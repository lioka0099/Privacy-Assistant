/**
 * Runtime message contracts for extension contexts.
 * Shared by popup/background (module scripts) to keep message handling consistent.
 */
export const MESSAGE_TYPES = Object.freeze({
  PING: "PING",
  RUN_ANALYSIS: "RUN_ANALYSIS",
  PING_CONTENT: "PING_CONTENT",
  COLLECT_PAGE_SIGNALS: "COLLECT_PAGE_SIGNALS"
});

function isObject(value) {
  return typeof value === "object" && value !== null;
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

export function createRequestId(prefix = "req") {
  const random = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${Date.now()}_${random}`;
}

export function validateIncomingMessage(message) {
  if (!isObject(message)) {
    return { ok: false, error: "Message must be an object" };
  }

  if (!isNonEmptyString(message.type)) {
    return { ok: false, error: "Message type is required" };
  }

  if (message.requestId !== undefined && !isNonEmptyString(message.requestId)) {
    return { ok: false, error: "requestId must be a non-empty string when provided" };
  }

  return { ok: true };
}

export function createErrorPayload({ source, requestId, code, error }) {
  return {
    ok: false,
    source,
    requestId: requestId ?? null,
    status: "failed",
    code: code ?? "UNEXPECTED_ERROR",
    error
  };
}
