/**
 * Background service worker module.
 * Orchestrates extension analysis requests from the popup, runs collectors
 * with timeout protection, and returns a normalized analysis payload.
 */
import {
  KNOWN_TRACKER_DOMAIN_PATTERNS,
  MESSAGE_TYPES,
  SUSPICIOUS_ENDPOINT_PATTERNS,
  isThirdPartyHost,
  createErrorPayload,
  createRequestId,
  validateIncomingMessage
} from "./messages.js";

const ANALYSIS_TIMEOUT_MS = 1500;
const NETWORK_WINDOW_MS = 60000;
const NETWORK_BURST_WINDOW_MS = 5000;
const MAX_TAB_NETWORK_EVENTS = 500;
const networkEventsByTab = new Map();
const networkCollectionState = {
  listenerReady: false,
  unavailableReason: null
};

function clearTabNetworkEvents(tabId) {
  if (typeof tabId !== "number" || tabId < 0) {
    return;
  }
  networkEventsByTab.delete(tabId);
}

chrome.runtime.onInstalled.addListener(() => {
  console.log("Privacy Assistant installed");
});

function isSupportedHttpUrl(url) {
  return typeof url === "string" && (url.startsWith("http://") || url.startsWith("https://"));
}

function parseHostnameFromUrl(rawUrl) {
  try {
    return new URL(rawUrl).hostname;
  } catch {
    return "";
  }
}

function getCollectorData(collectors, name) {
  const collector = collectors.find((item) => item.name === name) ?? null;
  if (!collector || collector.status !== "success") {
    return null;
  }
  return collector.data ?? null;
}

function getNestedCollectorData(contentCollectorData, nestedCollectorName) {
  if (!contentCollectorData || !Array.isArray(contentCollectorData.collectors)) {
    return null;
  }
  const nestedCollector = contentCollectorData.collectors.find(
    (collector) => collector.name === nestedCollectorName
  );
  if (!nestedCollector || nestedCollector.status !== "success") {
    return null;
  }
  return nestedCollector.data ?? null;
}

function calculateConfidence(collectors) {
  const failedCollectors = collectors.filter((collector) => collector.status === "failed").length;
  if (failedCollectors === 0) {
    return "high";
  }
  if (failedCollectors <= 2) {
    return "medium";
  }
  return "low";
}

function degradeConfidence(baseConfidence) {
  if (baseConfidence === "high") {
    return "medium";
  }
  return "low";
}

function toSafeNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function toSortedStringArray(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return [...value]
    .filter((item) => typeof item === "string" && item.length > 0)
    .sort((a, b) => a.localeCompare(b));
}

function sanitizeCountedItems(value, keyName) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((item) => item && typeof item === "object")
    .map((item) => {
      const key = typeof item[keyName] === "string" ? item[keyName] : "";
      const count = typeof item.count === "number" && Number.isFinite(item.count) ? item.count : 0;
      return { [keyName]: key, count };
    })
    .filter((item) => item[keyName].length > 0 && item.count > 0);
}

function buildNormalizedAnalysis({ requestId, tabContext, collectors, durationMs, requestedAt, completedAt }) {
  const contentPageSignals = getCollectorData(collectors, "contentPageSignals");
  const scriptSignals = getNestedCollectorData(contentPageSignals, "scriptSignals") ?? {};
  const storageSignals = getNestedCollectorData(contentPageSignals, "storageSignals") ?? {};
  const trackingHeuristics = getNestedCollectorData(contentPageSignals, "trackingHeuristics") ?? {};
  const pageContext = getNestedCollectorData(contentPageSignals, "pageContext") ?? {};
  const cookieSignals = getCollectorData(collectors, "cookieSignals") ?? {};
  const networkSignals = getCollectorData(collectors, "networkRequestSignals") ?? {};
  const networkSignalsAvailable = Boolean(networkSignals) && networkSignals.available !== false;
  const baseConfidence = calculateConfidence(collectors);

  const normalized = {
    requestId,
    schemaVersion: "1.0.0",
    timestamps: {
      requestedAt,
      completedAt,
      durationMs
    },
    page: {
      tabId: tabContext.tabId,
      url: tabContext.url,
      hostname: tabContext.hostname,
      title: pageContext.title ?? ""
    },
    sourceFlags: {
      contentReachable: Boolean(getCollectorData(collectors, "contentReachability")?.reachable),
      contentSignalsAvailable: Boolean(contentPageSignals),
      cookieSignalsAvailable: Boolean(getCollectorData(collectors, "cookieSignals")),
      networkSignalsAvailable
    },
    scriptSignals: {
      totalScriptTagsWithSrc: toSafeNumber(scriptSignals.totalScriptTagsWithSrc),
      externalScriptCount: toSafeNumber(scriptSignals.externalScriptCount),
      thirdPartyScriptDomainCount: toSafeNumber(scriptSignals.thirdPartyScriptDomainCount),
      thirdPartyScriptDomains: toSortedStringArray(scriptSignals.thirdPartyScriptDomains)
    },
    storageSignals: {
      localStorage: {
        keyCount: toSafeNumber(storageSignals.localStorage?.keyCount),
        approxBytes: toSafeNumber(storageSignals.localStorage?.approxBytes)
      },
      sessionStorage: {
        keyCount: toSafeNumber(storageSignals.sessionStorage?.keyCount),
        approxBytes: toSafeNumber(storageSignals.sessionStorage?.approxBytes)
      }
    },
    trackingHeuristics: {
      trackerDomainHitCount: toSafeNumber(trackingHeuristics.trackerDomainHitCount),
      endpointPatternHitCount: toSafeNumber(trackingHeuristics.endpointPatternHitCount),
      trackingQueryParamCount: toSafeNumber(trackingHeuristics.trackingQueryParamCount),
      trackerDomainHits: toSortedStringArray(trackingHeuristics.trackerDomainHits),
      trackingQueryParams: toSortedStringArray(trackingHeuristics.trackingQueryParams)
    },
    cookieSignals: {
      totalCookieCount: toSafeNumber(cookieSignals.totalCookieCount),
      firstPartyCookieCount: toSafeNumber(cookieSignals.firstPartyCookieCount),
      thirdPartyCookieEstimateCount: toSafeNumber(cookieSignals.thirdPartyCookieEstimateCount),
      thirdPartyCookieDomains: toSortedStringArray(cookieSignals.thirdPartyCookieDomains)
    },
    networkSignals: {
      available: networkSignalsAvailable,
      unavailableReason: networkSignalsAvailable ? null : networkSignals.unavailableReason ?? "UNKNOWN",
      observedWindowMs: toSafeNumber(networkSignals.observedWindowMs),
      totalObservedRequests: toSafeNumber(networkSignals.totalObservedRequests),
      thirdPartyRequestCount: toSafeNumber(networkSignals.thirdPartyRequestCount),
      thirdPartyTopHosts: sanitizeCountedItems(networkSignals.thirdPartyTopHosts, "host"),
      suspiciousEndpointHitCount: toSafeNumber(networkSignals.suspiciousEndpointHitCount),
      suspiciousEndpointPatternCounts: sanitizeCountedItems(
        networkSignals.suspiciousEndpointPatternCounts,
        "pattern"
      ),
      knownTrackerDomainHitCount: toSafeNumber(networkSignals.knownTrackerDomainHitCount),
      shortWindowBurstCount: toSafeNumber(networkSignals.shortWindowBurstCount),
      knownTrackerDomains: toSortedStringArray(networkSignals.knownTrackerDomains)
    },
    derived: {
      totalThirdPartySignals:
        toSafeNumber(scriptSignals.thirdPartyScriptDomainCount) +
        toSafeNumber(cookieSignals.thirdPartyCookieEstimateCount) +
        toSafeNumber(networkSignals.thirdPartyRequestCount),
      totalTrackingIndicators:
        toSafeNumber(trackingHeuristics.trackerDomainHitCount) +
        toSafeNumber(trackingHeuristics.endpointPatternHitCount) +
        toSafeNumber(trackingHeuristics.trackingQueryParamCount) +
        toSafeNumber(networkSignals.suspiciousEndpointHitCount) +
        toSafeNumber(networkSignals.knownTrackerDomainHitCount)
    },
    confidence: networkSignalsAvailable ? baseConfidence : degradeConfidence(baseConfidence)
  };

  return normalized;
}

function validateNormalizedAnalysis(normalized) {
  if (!normalized || typeof normalized !== "object") {
    throw new Error("Normalized analysis must be an object");
  }

  const requiredRootFields = ["schemaVersion", "page", "sourceFlags", "confidence"];
  for (const field of requiredRootFields) {
    if (!(field in normalized)) {
      throw new Error(`Normalized analysis is missing required field: ${field}`);
    }
  }

  if (!normalized.page || typeof normalized.page.url !== "string") {
    throw new Error("Normalized analysis page context is invalid");
  }

  if (!["high", "medium", "low"].includes(normalized.confidence)) {
    throw new Error("Normalized analysis confidence is invalid");
  }
}

function appendNetworkEvent(tabId, event) {
  const existing = networkEventsByTab.get(tabId) ?? [];
  existing.push(event);

  const cutoff = Date.now() - NETWORK_WINDOW_MS;
  const filtered = existing.filter((entry) => entry.timestampMs >= cutoff);

  while (filtered.length > MAX_TAB_NETWORK_EVENTS) {
    filtered.shift();
  }

  networkEventsByTab.set(tabId, filtered);
}

try {
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (typeof details.tabId !== "number" || details.tabId < 0) {
        return;
      }
      if (!isSupportedHttpUrl(details.url)) {
        return;
      }

      appendNetworkEvent(details.tabId, {
        timestampMs: Date.now(),
        url: details.url,
        requestHost: parseHostnameFromUrl(details.url),
        initiatorHost: details.initiator ? parseHostnameFromUrl(details.initiator) : "",
        type: details.type
      });
    },
    { urls: ["http://*/*", "https://*/*"] }
  );
  networkCollectionState.listenerReady = true;
  networkCollectionState.unavailableReason = null;
} catch (error) {
  networkCollectionState.listenerReady = false;
  networkCollectionState.unavailableReason =
    error instanceof Error ? error.message : "webRequest listener setup failed";
}

async function collectCookieSignals(tabContext) {
  const cookies = await chrome.cookies.getAll({ url: tabContext.url });
  const firstPartyHost = tabContext.hostname;

  let firstPartyCookieCount = 0;
  let thirdPartyCookieEstimateCount = 0;
  const thirdPartyDomains = new Set();

  for (const cookie of cookies) {
    const cookieDomain = (cookie.domain ?? "").replace(/^\./, "");
    const thirdParty = isThirdPartyHost(cookieDomain, firstPartyHost);
    if (thirdParty) {
      thirdPartyCookieEstimateCount += 1;
      if (cookieDomain) {
        thirdPartyDomains.add(cookieDomain);
      }
    } else {
      firstPartyCookieCount += 1;
    }
  }

  return {
    totalCookieCount: cookies.length,
    firstPartyCookieCount,
    thirdPartyCookieEstimateCount,
    thirdPartyCookieDomains: Array.from(thirdPartyDomains)
  };
}

async function collectNetworkRequestSignals(tabContext) {
  if (!networkCollectionState.listenerReady) {
    return {
      available: false,
      unavailableReason:
        networkCollectionState.unavailableReason ?? "WEBREQUEST_LISTENER_UNAVAILABLE",
      observedWindowMs: NETWORK_WINDOW_MS,
      totalObservedRequests: 0,
      thirdPartyRequestCount: 0,
      thirdPartyTopHosts: [],
      suspiciousEndpointHitCount: 0,
      suspiciousEndpointPatternCounts: [],
      knownTrackerDomainHitCount: 0,
      knownTrackerDomains: [],
      shortWindowBurstCount: 0
    };
  }

  const events = networkEventsByTab.get(tabContext.tabId) ?? [];
  const firstPartyHost = tabContext.hostname;
  const now = Date.now();
  const recentEvents = events.filter((event) => event.timestampMs >= now - NETWORK_WINDOW_MS);

  let thirdPartyRequestCount = 0;
  let suspiciousEndpointHitCount = 0;
  const thirdPartyHostCounts = new Map();
  const suspiciousPatternCounts = new Map();
  const trackerDomainMatches = new Set();

  for (const event of recentEvents) {
    if (isThirdPartyHost(event.requestHost, firstPartyHost)) {
      thirdPartyRequestCount += 1;
      const existingCount = thirdPartyHostCounts.get(event.requestHost) ?? 0;
      thirdPartyHostCounts.set(event.requestHost, existingCount + 1);
    }

    const urlLower = event.url.toLowerCase();
    for (const pattern of SUSPICIOUS_ENDPOINT_PATTERNS) {
      if (urlLower.includes(pattern)) {
        suspiciousEndpointHitCount += 1;
        const existingCount = suspiciousPatternCounts.get(pattern) ?? 0;
        suspiciousPatternCounts.set(pattern, existingCount + 1);
      }
    }

    const hostLower = event.requestHost.toLowerCase();
    for (const pattern of KNOWN_TRACKER_DOMAIN_PATTERNS) {
      if (hostLower.includes(pattern)) {
        trackerDomainMatches.add(event.requestHost);
      }
    }
  }

  const recentWindowStart = now - NETWORK_BURST_WINDOW_MS;
  const shortWindowCount = recentEvents.filter(
    (event) => event.timestampMs >= recentWindowStart
  ).length;

  const thirdPartyTopHosts = Array.from(thirdPartyHostCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([host, count]) => ({ host, count }));

  const suspiciousEndpointPatternCounts = Array.from(suspiciousPatternCounts.entries())
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([pattern, count]) => ({ pattern, count }));

  const payload = {
    available: true,
    unavailableReason: null,
    observedWindowMs: NETWORK_WINDOW_MS,
    totalObservedRequests: recentEvents.length,
    thirdPartyRequestCount,
    thirdPartyTopHosts,
    suspiciousEndpointHitCount,
    suspiciousEndpointPatternCounts,
    knownTrackerDomainHitCount: trackerDomainMatches.size,
    knownTrackerDomains: Array.from(trackerDomainMatches),
    shortWindowBurstCount: shortWindowCount
  };
  return payload;
}

/**
 * Resolves the currently active tab and extracts normalized context needed
 * by collectors (tab id, full URL, and hostname).
 * Throws when no supported tab is available.
 */
async function getActiveTabContext() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];

  if (!tab || typeof tab.id !== "number" || !isSupportedHttpUrl(tab.url)) {
    throw new Error("No supported active tab found");
  }

  const parsed = new URL(tab.url);
  return {
    tabId: tab.id,
    url: tab.url,
    hostname: parsed.hostname
  };
}

/**
 * Runs a collector with timeout and returns a standardized result envelope.
 * This prevents one slow/failing collector from breaking the whole pipeline.
 */
async function withTimeout(name, task, timeoutMs = ANALYSIS_TIMEOUT_MS) {
  const startedAt = Date.now();

  try {
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`${name} timed out`)), timeoutMs);
    });
    const data = await Promise.race([task(), timeoutPromise]);
    return {
      name,
      status: "success",
      durationMs: Date.now() - startedAt,
      data
    };
  } catch (error) {
    return {
      name,
      status: "failed",
      durationMs: Date.now() - startedAt,
      error: error instanceof Error ? error.message : "Unknown collector error"
    };
  }
}

/**
 * Verifies that the content script is reachable on the target tab.
 * Used as a baseline health/smoke signal for page-level collection.
 */
async function collectContentReachability(tabId, requestId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, { type: MESSAGE_TYPES.PING_CONTENT, requestId }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response || response.ok !== true) {
        reject(new Error("Content script reachability check returned invalid response"));
        return;
      }
      resolve({
        reachable: Boolean(response?.ok),
        source: response?.source ?? "unknown",
        requestId: response?.requestId ?? null
      });
    });
  });
}

async function collectPageSignalsFromContent(tabId, requestId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(
      tabId,
      { type: MESSAGE_TYPES.COLLECT_PAGE_SIGNALS, requestId },
      (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        if (!response || response.ok !== true) {
          reject(new Error(response?.error ?? "Content signal collection returned invalid response"));
          return;
        }
        resolve({
          requestId: response.requestId ?? null,
          status: response.status,
          summary: response.summary,
          collectors: response.collectors
        });
      }
    );
  });
}

/**
 * Temporary placeholder collector for runtime-level signals.
 */
async function collectPlaceholderRuntimeSignals() {
  return {
    runtimeReady: true,
    note: "Collector placeholders"
  };
}

/**
 * Main analysis coordinator.
 * Gets tab context, runs collectors in parallel with timeout guards, then
 * returns one normalized response object with summary stats.
 */
async function runAnalysisPipeline(requestId) {
  const requestedAt = new Date().toISOString();
  const startedAt = Date.now();

  let tabContext;
  try {
    tabContext = await getActiveTabContext();
  } catch (error) {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const fallbackTab = tabs[0];
    const fallbackUrl = typeof fallbackTab?.url === "string" ? fallbackTab.url : "";
    const fallbackHostname = isSupportedHttpUrl(fallbackUrl) ? new URL(fallbackUrl).hostname : "";
    const completedAt = new Date().toISOString();
    const durationMs = Date.now() - startedAt;

    const normalizedAnalysis = buildNormalizedAnalysis({
      requestId,
      tabContext: {
        tabId: typeof fallbackTab?.id === "number" ? fallbackTab.id : -1,
        url: fallbackUrl,
        hostname: fallbackHostname
      },
      collectors: [],
      durationMs,
      requestedAt,
      completedAt
    });
    validateNormalizedAnalysis(normalizedAnalysis);

    return {
      ok: true,
      source: "background",
      requestId,
      requestedAt,
      completedAt,
      durationMs,
      tab: {
        id: typeof fallbackTab?.id === "number" ? fallbackTab.id : null,
        url: fallbackUrl,
        hostname: fallbackHostname
      },
      status: "partial",
      collectors: [],
      summary: {
        total: 0,
        succeeded: 0,
        failed: 0
      },
      warnings: [
        {
          code: "UNSUPPORTED_ACTIVE_TAB",
          message: error instanceof Error ? error.message : "No supported active tab found"
        }
      ],
      normalizedAnalysis: {
        ...normalizedAnalysis,
        confidence: "low",
        sourceFlags: {
          contentReachable: false,
          contentSignalsAvailable: false,
          cookieSignalsAvailable: false,
          networkSignalsAvailable: false
        }
      }
    };
  }
  const collectors = await Promise.all([
    withTimeout("contentReachability", () => collectContentReachability(tabContext.tabId, requestId)),
    withTimeout("contentPageSignals", () => collectPageSignalsFromContent(tabContext.tabId, requestId)),
    withTimeout("cookieSignals", () => collectCookieSignals(tabContext)),
    withTimeout("networkRequestSignals", () => collectNetworkRequestSignals(tabContext)),
    withTimeout("runtimeSignals", () => collectPlaceholderRuntimeSignals())
  ]);

  const succeeded = collectors.filter((collector) => collector.status === "success").length;
  const failed = collectors.length - succeeded;
  const completedAt = new Date().toISOString();
  const durationMs = Date.now() - startedAt;
  const normalizedAnalysis = buildNormalizedAnalysis({
    requestId,
    tabContext,
    collectors,
    durationMs,
    requestedAt,
    completedAt
  });
  validateNormalizedAnalysis(normalizedAnalysis);
  const warnings = [];
  if (!normalizedAnalysis.sourceFlags.networkSignalsAvailable) {
    warnings.push({
      code: "NETWORK_SIGNALS_UNAVAILABLE",
      message:
        normalizedAnalysis.networkSignals.unavailableReason ??
        "Network signal collection is unavailable"
    });
  }

  return {
    ok: true,
    source: "background",
    requestId,
    requestedAt,
    completedAt,
    durationMs,
    tab: {
      id: tabContext.tabId,
      url: tabContext.url,
      hostname: tabContext.hostname
    },
    status: failed === 0 ? "success" : "partial",
    collectors,
    summary: {
      total: collectors.length,
      succeeded,
      failed
    },
    warnings,
    normalizedAnalysis
  };
}

function normalizeCookieDomain(domain) {
  if (typeof domain !== "string") {
    return "";
  }
  return domain.replace(/^\./, "").toLowerCase().trim();
}

function toCookieRemovalUrl(cookie) {
  const normalizedDomain = normalizeCookieDomain(cookie?.domain ?? "");
  if (!normalizedDomain) {
    return null;
  }
  const scheme = cookie?.secure ? "https" : "http";
  const path = typeof cookie?.path === "string" && cookie.path.startsWith("/") ? cookie.path : "/";
  return `${scheme}://${normalizedDomain}${path}`;
}

function openSettingsTabForAction(actionId, targetUrl) {
  return chrome.tabs.create({ url: targetUrl });
}

function toSettingsSiteDetailsUrl(tabContext) {
  const rawUrl = typeof tabContext?.url === "string" ? tabContext.url : "";
  if (!isSupportedHttpUrl(rawUrl)) {
    return null;
  }
  try {
    const parsed = new URL(rawUrl);
    return `chrome://settings/content/siteDetails?site=${encodeURIComponent(parsed.origin)}`;
  } catch {
    return null;
  }
}

async function clearCookiesForTabContext(tabContext, mode) {
  if (!tabContext || !tabContext.url || !tabContext.hostname) {
    return { eligibleCount: 0, removedCount: 0, failedCount: 0 };
  }

  const cookies = await chrome.cookies.getAll({ url: tabContext.url });
  let eligibleCount = 0;
  let removedCount = 0;
  let failedCount = 0;

  for (const cookie of cookies) {
    const cookieDomain = normalizeCookieDomain(cookie.domain ?? "");
    if (
      mode === "third_party_only" &&
      !isThirdPartyHost(cookieDomain, tabContext.hostname)
    ) {
      continue;
    }

    eligibleCount += 1;
    const removalUrl = toCookieRemovalUrl(cookie);
    if (!removalUrl) {
      failedCount += 1;
      continue;
    }

    try {
      const removed = await chrome.cookies.remove({
        url: removalUrl,
        name: cookie.name,
        storeId: cookie.storeId
      });
      if (removed) {
        removedCount += 1;
      } else {
        failedCount += 1;
      }
    } catch {
      failedCount += 1;
    }
  }

  return { eligibleCount, removedCount, failedCount };
}

async function executeImproveAction(actionId, tabContext) {
  if (actionId === "reduce_third_party_cookies") {
    const summary = await clearCookiesForTabContext(tabContext, "third_party_only");
    if (summary.eligibleCount === 0) {
      return {
        actionId,
        status: "skipped",
        message: "No third-party cookies were eligible for removal on this page."
      };
    }
    if (summary.removedCount > 0) {
      return {
        actionId,
        status: "success",
        message: `Removed ${summary.removedCount} third-party cookie(s).`
      };
    }
    await openSettingsTabForAction(actionId, "chrome://settings/cookies");
    return {
      actionId,
      status: "success",
      message:
        "Automatic cookie cleanup was limited. Opened Cookies settings. Steps: 1) Block third-party cookies, 2) Clear site data if needed."
    };
  }

  if (actionId === "clear_site_storage_data") {
    const summary = await clearCookiesForTabContext(tabContext, "all_current_site");
    if (summary.eligibleCount === 0) {
      await openSettingsTabForAction(actionId, "chrome://settings/siteData");
      return {
        actionId,
        status: "success",
        message:
          "No removable cookies were found automatically. Opened site-data settings. Steps: 1) Search this domain, 2) Remove stored data."
      };
    }
    if (summary.removedCount > 0) {
      return {
        actionId,
        status: "success",
        message:
          `Cleared ${summary.removedCount} site cookie(s). ` +
          "If needed, open site-data settings to remove remaining storage."
      };
    }
    await openSettingsTabForAction(actionId, "chrome://settings/siteData");
    return {
      actionId,
      status: "success",
      message:
        "Automatic site-data cleanup was limited. Opened site-data settings. Steps: 1) Search this domain, 2) Remove remaining data."
    };
  }

  if (actionId === "review_tracking_permissions") {
    const siteDetailsUrl = toSettingsSiteDetailsUrl(tabContext);
    await openSettingsTabForAction(
      actionId,
      siteDetailsUrl ?? "chrome://settings/content/all"
    );
    return {
      actionId,
      status: "success",
      message:
        "Opened this site's permission details. Steps: 1) Review this site permissions, 2) restrict tracking-related access."
    };
  }

  if (actionId === "harden_network_privacy") {
    await openSettingsTabForAction(actionId, "chrome://settings/security");
    return {
      actionId,
      status: "success",
      message:
        "Opened security settings. Steps: 1) Use Enhanced protection, 2) Review secure DNS and privacy controls."
    };
  }

  if (actionId === "limit_third_party_scripts") {
    await openSettingsTabForAction(actionId, "chrome://settings/content/javascript");
    return {
      actionId,
      status: "success",
      message:
        "Opened JavaScript settings. Steps: 1) Restrict JavaScript for high-risk sites, 2) Use per-site blocking for untrusted domains."
    };
  }

  if (actionId === "block_known_trackers") {
    await openSettingsTabForAction(actionId, "chrome://settings/cookies");
    return {
      actionId,
      status: "success",
      message:
        "Opened Cookies settings. Enable third-party cookie blocking to reduce tracker domains."
    };
  }

  await openSettingsTabForAction(actionId, "chrome://settings/privacy");
  return {
    actionId,
    status: "success",
    message:
      "Opened general privacy settings. Steps: 1) Review tracking-related controls, 2) tighten permissions for this site."
  };
}

async function executeImproveActionQueue(selectedActionIds, tabContext) {
  if (!Array.isArray(selectedActionIds)) {
    return [];
  }

  const seen = new Set();
  const orderedActionIds = [];
  for (const actionId of selectedActionIds) {
    if (typeof actionId !== "string" || seen.has(actionId)) {
      continue;
    }
    seen.add(actionId);
    orderedActionIds.push(actionId);
  }

  const results = [];
  for (const actionId of orderedActionIds) {
    try {
      const result = await executeImproveAction(actionId, tabContext);
      results.push(result);
    } catch (error) {
      results.push({
        actionId,
        status: "failed",
        message: error instanceof Error ? error.message : "Action failed unexpectedly."
      });
    }
  }
  const anyActionApplied = results.some((result) => result.status === "success");
  if (anyActionApplied && tabContext && typeof tabContext.tabId === "number") {
    // Drop pre-action network history so post-action scoring reflects fresh traffic sooner.
    clearTabNetworkEvents(tabContext.tabId);
  }
  return results;
}

/**
 * Runtime message router:
 * - PING: quick health response
 * - RUN_ANALYSIS: executes analysis pipeline asynchronously
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const validation = validateIncomingMessage(message);
  if (!validation.ok) {
    sendResponse(
      createErrorPayload({
        source: "background",
        requestId: null,
        code: "INVALID_MESSAGE",
        error: validation.error
      })
    );
    return;
  }

  if (message.type === MESSAGE_TYPES.PING) {
    sendResponse({
      ok: true,
      source: "background",
      requestId: message.requestId ?? null
    });
    return;
  }

  if (message.type === MESSAGE_TYPES.EXECUTE_IMPROVE_PRIVACY_ACTIONS) {
    const requestId = message.requestId ?? createRequestId("improve_privacy");
    const selectedActionIds = Array.isArray(message.selectedActionIds)
      ? message.selectedActionIds
      : [];

    (async () => {
      try {
        let tabContext = null;
        try {
          tabContext = await getActiveTabContext();
        } catch {
          tabContext = null;
        }

        const results = await executeImproveActionQueue(selectedActionIds, tabContext);
        const refreshedAnalysis = await runAnalysisPipeline(createRequestId("analysis_refresh"));

        sendResponse({
          ok: true,
          source: "background",
          requestId,
          payload: {
            results,
            refreshedAnalysis
          }
        });
      } catch (error) {
        sendResponse(
          createErrorPayload({
            source: "background",
            requestId,
            code: "EXECUTE_IMPROVE_PRIVACY_ACTIONS_FAILED",
            error:
              error instanceof Error
                ? error.message
                : "Failed to execute Improve Privacy actions"
          })
        );
      }
    })();

    return true;
  }

  if (message.type !== MESSAGE_TYPES.RUN_ANALYSIS) {
    return;
  }

  const requestId = message.requestId ?? createRequestId("analysis");

  (async () => {
    try {
      const analysisResult = await runAnalysisPipeline(requestId);
      sendResponse(analysisResult);
    } catch (error) {
      sendResponse(
        createErrorPayload({
          source: "background",
          requestId,
          code: "ANALYSIS_PIPELINE_FAILED",
          error: error instanceof Error ? error.message : "Analysis failed unexpectedly"
        })
      );
    }
  })();

  return true;
});
