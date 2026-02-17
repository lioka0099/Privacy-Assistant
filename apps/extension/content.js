/**
 * Content script module.
 * Collects page-level signals (scripts and storage) in a defensive way so
 * failures in one collector do not crash the full analysis response.
 */
import {
  KNOWN_TRACKER_DOMAIN_PATTERNS,
  SUSPICIOUS_ENDPOINT_PATTERNS,
  TRACKING_QUERY_PARAM_PATTERNS,
  isThirdPartyHost
} from "./messages.js";

const MESSAGE_TYPES = Object.freeze({
  PING_CONTENT: "PING_CONTENT",
  COLLECT_PAGE_SIGNALS: "COLLECT_PAGE_SIGNALS"
});

function isValidRequestId(requestId) {
  return requestId === undefined || (typeof requestId === "string" && requestId.trim().length > 0);
}

function createCollectorSuccess(name, data, startedAt) {
  return {
    name,
    status: "success",
    durationMs: Date.now() - startedAt,
    data
  };
}

function createCollectorFailure(name, error, startedAt) {
  return {
    name,
    status: "failed",
    durationMs: Date.now() - startedAt,
    error: error instanceof Error ? error.message : "Unknown collector error"
  };
}

function runCollector(name, collector) {
  const startedAt = Date.now();
  try {
    const data = collector();
    return createCollectorSuccess(name, data, startedAt);
  } catch (error) {
    return createCollectorFailure(name, error, startedAt);
  }
}

function parseUrlSafely(rawUrl, baseUrl) {
  try {
    return new URL(rawUrl, baseUrl);
  } catch {
    return null;
  }
}

function collectScriptSignals() {
  const currentHost = window.location.hostname;
  const scriptElements = Array.from(document.querySelectorAll("script[src]"));

  const externalScripts = [];
  const thirdPartyDomains = new Set();

  for (const scriptElement of scriptElements) {
    const src = scriptElement.getAttribute("src");
    if (!src) {
      continue;
    }

    const parsed = parseUrlSafely(src, window.location.href);
    if (!parsed || !parsed.hostname) {
      continue;
    }

    const isThirdParty = isThirdPartyHost(parsed.hostname, currentHost);
    externalScripts.push({
      src: parsed.href,
      hostname: parsed.hostname,
      isThirdParty
    });

    if (isThirdParty) {
      thirdPartyDomains.add(parsed.hostname);
    }
  }

  return {
    totalScriptTagsWithSrc: scriptElements.length,
    externalScriptCount: externalScripts.length,
    thirdPartyScriptDomainCount: thirdPartyDomains.size,
    thirdPartyScriptDomains: Array.from(thirdPartyDomains),
    sampledExternalScripts: externalScripts.slice(0, 25)
  };
}

function estimateStorageBytes(storageArea) {
  let approxChars = 0;
  const keys = [];

  for (let index = 0; index < storageArea.length; index++) {
    const key = storageArea.key(index);
    if (!key) {
      continue;
    }
    keys.push(key);

    const value = storageArea.getItem(key) ?? "";
    approxChars += key.length + value.length;
  }

  return {
    keys,
    keyCount: keys.length,
    approxBytes: approxChars * 2
  };
}

function collectStorageSignals() {
  const local = estimateStorageBytes(window.localStorage);
  const session = estimateStorageBytes(window.sessionStorage);

  return {
    localStorage: local,
    sessionStorage: session
  };
}

function collectTrackingHeuristics() {
  const scriptSources = Array.from(document.querySelectorAll("script[src]"))
    .map((script) => script.getAttribute("src"))
    .filter(Boolean);

  const trackerDomainHits = new Set();
  const endpointHits = [];

  for (const src of scriptSources) {
    const parsed = parseUrlSafely(src, window.location.href);
    if (!parsed) {
      continue;
    }

    const hostname = parsed.hostname.toLowerCase();
    const hrefLower = parsed.href.toLowerCase();
    for (const pattern of KNOWN_TRACKER_DOMAIN_PATTERNS) {
      if (hostname.includes(pattern)) {
        trackerDomainHits.add(hostname);
      }
    }
    for (const pattern of SUSPICIOUS_ENDPOINT_PATTERNS) {
      if (hrefLower.includes(pattern)) {
        endpointHits.push({ pattern, url: parsed.href });
      }
    }
  }

  const activeQueryParams = [];
  const currentParams = new URLSearchParams(window.location.search);
  for (const [key] of currentParams.entries()) {
    const lowerKey = key.toLowerCase();
    if (TRACKING_QUERY_PARAM_PATTERNS.some((pattern) => lowerKey.includes(pattern))) {
      activeQueryParams.push(key);
    }
  }

  return {
    trackerDomainHits: Array.from(trackerDomainHits),
    trackerDomainHitCount: trackerDomainHits.size,
    endpointPatternHitCount: endpointHits.length,
    endpointPatternHits: endpointHits.slice(0, 25),
    trackingQueryParams: activeQueryParams,
    trackingQueryParamCount: activeQueryParams.length
  };
}

function collectPageContext() {
  return {
    url: window.location.href,
    hostname: window.location.hostname,
    title: document.title
  };
}

function collectPageSignals(requestId) {
  const requestedAt = new Date().toISOString();
  const startedAt = Date.now();

  const collectors = [
    runCollector("pageContext", () => collectPageContext()),
    runCollector("scriptSignals", () => collectScriptSignals()),
    runCollector("storageSignals", () => collectStorageSignals()),
    runCollector("trackingHeuristics", () => collectTrackingHeuristics())
  ];

  const succeeded = collectors.filter((collector) => collector.status === "success").length;
  const failed = collectors.length - succeeded;

  return {
    ok: true,
    source: "content",
    requestId: requestId ?? null,
    requestedAt,
    completedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    status: failed === 0 ? "success" : "partial",
    collectors,
    summary: {
      total: collectors.length,
      succeeded,
      failed
    }
  };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || typeof message !== "object" || typeof message.type !== "string") {
    sendResponse({
      ok: false,
      source: "content",
      requestId: null,
      status: "failed",
      code: "INVALID_MESSAGE",
      error: "Message must be an object with a string type"
    });
    return;
  }

  if (!isValidRequestId(message.requestId)) {
    sendResponse({
      ok: false,
      source: "content",
      requestId: null,
      status: "failed",
      code: "INVALID_MESSAGE",
      error: "requestId must be a non-empty string when provided"
    });
    return;
  }

  if (message.type === MESSAGE_TYPES.PING_CONTENT) {
    sendResponse({ ok: true, source: "content", requestId: message.requestId ?? null });
    return;
  }

  if (message.type !== MESSAGE_TYPES.COLLECT_PAGE_SIGNALS) {
    return;
  }

  try {
    const result = collectPageSignals(message.requestId);
    sendResponse(result);
  } catch (error) {
    sendResponse({
      ok: false,
      source: "content",
      requestId: message.requestId ?? null,
      status: "failed",
      code: "CONTENT_COLLECTION_FAILED",
      error: error instanceof Error ? error.message : "Content collection failed unexpectedly"
    });
  }
});
