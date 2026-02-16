/**
 * Content script module.
 * Collects page-level signals (scripts and storage) in a defensive way so
 * failures in one collector do not crash the full analysis response.
 */

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

    const isThirdParty = parsed.hostname !== currentHost;
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

function collectPageContext() {
  return {
    url: window.location.href,
    hostname: window.location.hostname,
    title: document.title
  };
}

function collectPageSignals() {
  const requestedAt = new Date().toISOString();
  const startedAt = Date.now();

  const collectors = [
    runCollector("pageContext", () => collectPageContext()),
    runCollector("scriptSignals", () => collectScriptSignals()),
    runCollector("storageSignals", () => collectStorageSignals())
  ];

  const succeeded = collectors.filter((collector) => collector.status === "success").length;
  const failed = collectors.length - succeeded;

  return {
    ok: true,
    source: "content",
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
  if (message?.type === "PING_CONTENT") {
    sendResponse({ ok: true, source: "content" });
    return;
  }

  if (message?.type !== "COLLECT_PAGE_SIGNALS") {
    return;
  }

  try {
    const result = collectPageSignals();
    sendResponse(result);
  } catch (error) {
    sendResponse({
      ok: false,
      source: "content",
      status: "failed",
      error: error instanceof Error ? error.message : "Content collection failed unexpectedly"
    });
  }
});
