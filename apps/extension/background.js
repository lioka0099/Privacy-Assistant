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
const NETWORK_WINDOW_MS = 30000;
const MAX_TAB_NETWORK_EVENTS = 500;
const networkEventsByTab = new Map();

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

function toSafeNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function buildNormalizedAnalysis({ requestId, tabContext, collectors, durationMs, requestedAt, completedAt }) {
  const contentPageSignals = getCollectorData(collectors, "contentPageSignals");
  const scriptSignals = getNestedCollectorData(contentPageSignals, "scriptSignals") ?? {};
  const storageSignals = getNestedCollectorData(contentPageSignals, "storageSignals") ?? {};
  const trackingHeuristics = getNestedCollectorData(contentPageSignals, "trackingHeuristics") ?? {};
  const pageContext = getNestedCollectorData(contentPageSignals, "pageContext") ?? {};
  const cookieSignals = getCollectorData(collectors, "cookieSignals") ?? {};
  const networkSignals = getCollectorData(collectors, "networkRequestSignals") ?? {};

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
      networkSignalsAvailable: Boolean(getCollectorData(collectors, "networkRequestSignals"))
    },
    scriptSignals: {
      totalScriptTagsWithSrc: toSafeNumber(scriptSignals.totalScriptTagsWithSrc),
      externalScriptCount: toSafeNumber(scriptSignals.externalScriptCount),
      thirdPartyScriptDomainCount: toSafeNumber(scriptSignals.thirdPartyScriptDomainCount),
      thirdPartyScriptDomains: Array.isArray(scriptSignals.thirdPartyScriptDomains)
        ? scriptSignals.thirdPartyScriptDomains
        : []
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
      trackerDomainHits: Array.isArray(trackingHeuristics.trackerDomainHits)
        ? trackingHeuristics.trackerDomainHits
        : [],
      trackingQueryParams: Array.isArray(trackingHeuristics.trackingQueryParams)
        ? trackingHeuristics.trackingQueryParams
        : []
    },
    cookieSignals: {
      totalCookieCount: toSafeNumber(cookieSignals.totalCookieCount),
      firstPartyCookieCount: toSafeNumber(cookieSignals.firstPartyCookieCount),
      thirdPartyCookieEstimateCount: toSafeNumber(cookieSignals.thirdPartyCookieEstimateCount),
      thirdPartyCookieDomains: Array.isArray(cookieSignals.thirdPartyCookieDomains)
        ? cookieSignals.thirdPartyCookieDomains
        : []
    },
    networkSignals: {
      observedWindowMs: toSafeNumber(networkSignals.observedWindowMs),
      totalObservedRequests: toSafeNumber(networkSignals.totalObservedRequests),
      thirdPartyRequestCount: toSafeNumber(networkSignals.thirdPartyRequestCount),
      suspiciousEndpointHitCount: toSafeNumber(networkSignals.suspiciousEndpointHitCount),
      knownTrackerDomainHitCount: toSafeNumber(networkSignals.knownTrackerDomainHitCount),
      shortWindowBurstCount: toSafeNumber(networkSignals.shortWindowBurstCount),
      knownTrackerDomains: Array.isArray(networkSignals.knownTrackerDomains)
        ? networkSignals.knownTrackerDomains
        : []
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
    confidence: calculateConfidence(collectors)
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
  const events = networkEventsByTab.get(tabContext.tabId) ?? [];
  const firstPartyHost = tabContext.hostname;
  const now = Date.now();
  const recentEvents = events.filter((event) => event.timestampMs >= now - NETWORK_WINDOW_MS);

  let thirdPartyRequestCount = 0;
  let suspiciousEndpointHitCount = 0;
  const trackerDomainMatches = new Set();

  for (const event of recentEvents) {
    if (isThirdPartyHost(event.requestHost, firstPartyHost)) {
      thirdPartyRequestCount += 1;
    }

    const urlLower = event.url.toLowerCase();
    if (SUSPICIOUS_ENDPOINT_PATTERNS.some((pattern) => urlLower.includes(pattern))) {
      suspiciousEndpointHitCount += 1;
    }

    const hostLower = event.requestHost.toLowerCase();
    for (const pattern of KNOWN_TRACKER_DOMAIN_PATTERNS) {
      if (hostLower.includes(pattern)) {
        trackerDomainMatches.add(event.requestHost);
      }
    }
  }

  const recentWindowStart = now - 5000;
  const shortWindowCount = recentEvents.filter(
    (event) => event.timestampMs >= recentWindowStart
  ).length;

  return {
    observedWindowMs: NETWORK_WINDOW_MS,
    totalObservedRequests: recentEvents.length,
    thirdPartyRequestCount,
    suspiciousEndpointHitCount,
    knownTrackerDomainHitCount: trackerDomainMatches.size,
    knownTrackerDomains: Array.from(trackerDomainMatches),
    shortWindowBurstCount: shortWindowCount
  };
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

  const tabContext = await getActiveTabContext();

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
    normalizedAnalysis
  };
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
