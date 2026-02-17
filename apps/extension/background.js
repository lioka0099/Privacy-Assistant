/**
 * Background service worker module.
 * Orchestrates extension analysis requests from the popup, runs collectors
 * with timeout protection, and returns a normalized analysis payload.
 */
import {
  MESSAGE_TYPES,
  createErrorPayload,
  createRequestId,
  validateIncomingMessage
} from "./messages.js";

const ANALYSIS_TIMEOUT_MS = 1500;

chrome.runtime.onInstalled.addListener(() => {
  console.log("Privacy Assistant installed");
});

function isSupportedHttpUrl(url) {
  return typeof url === "string" && (url.startsWith("http://") || url.startsWith("https://"));
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
    withTimeout("runtimeSignals", () => collectPlaceholderRuntimeSignals())
  ]);

  const succeeded = collectors.filter((collector) => collector.status === "success").length;
  const failed = collectors.length - succeeded;

  return {
    ok: true,
    source: "background",
    requestId,
    requestedAt,
    completedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
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
    }
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
