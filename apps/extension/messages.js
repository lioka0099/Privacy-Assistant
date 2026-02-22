/**
 * Runtime message contracts for extension contexts.
 * Shared by popup/background (module scripts) to keep message handling consistent.
 */
export const MESSAGE_TYPES = Object.freeze({
  PING: "PING",
  RUN_ANALYSIS: "RUN_ANALYSIS",
  PING_CONTENT: "PING_CONTENT",
  COLLECT_PAGE_SIGNALS: "COLLECT_PAGE_SIGNALS",
  EXECUTE_IMPROVE_PRIVACY_ACTIONS: "EXECUTE_IMPROVE_PRIVACY_ACTIONS"
});

export const KNOWN_TRACKER_DOMAIN_PATTERNS = Object.freeze([
  "google-analytics.com",
  "doubleclick.net",
  "googletagmanager.com",
  "facebook.net",
  "connect.facebook.net",
  "hotjar.com",
  "segment.com",
  "mixpanel.com"
]);

export const SUSPICIOUS_ENDPOINT_PATTERNS = Object.freeze([
  "collect",
  "track",
  "pixel",
  "beacon",
  "events"
]);

export const TRACKING_QUERY_PARAM_PATTERNS = Object.freeze([
  "utm_",
  "fbclid",
  "gclid",
  "msclkid"
]);

const COMMON_MULTI_PART_PUBLIC_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "gov.uk",
  "ac.uk",
  "net.uk",
  "sch.uk",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "asn.au",
  "id.au",
  "co.nz",
  "org.nz",
  "govt.nz",
  "ac.nz",
  "co.jp",
  "ne.jp",
  "or.jp",
  "go.jp",
  "ac.jp",
  "com.br",
  "net.br",
  "org.br",
  "gov.br",
  "com.mx",
  "org.mx",
  "gob.mx",
  "co.kr",
  "or.kr",
  "go.kr",
  "ac.kr",
  "co.in",
  "firm.in",
  "net.in",
  "org.in",
  "gen.in",
  "ind.in",
  "gov.in",
  "edu.in",
  "res.in",
  "com.sg",
  "net.sg",
  "org.sg",
  "gov.sg",
  "edu.sg",
  "com.tr",
  "net.tr",
  "org.tr",
  "gov.tr",
  "edu.tr"
]);

export function getComparableDomain(hostname) {
  if (typeof hostname !== "string") {
    return "";
  }

  const clean = hostname.toLowerCase().trim().replace(/\.+$/, "").replace(/^\.+/, "");
  if (!clean) {
    return "";
  }

  const isIpv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(clean);
  if (isIpv4 || clean.includes(":")) {
    return clean;
  }

  const segments = clean.split(".").filter(Boolean);
  if (segments.length <= 2) {
    return clean;
  }

  const twoPartSuffix = segments.slice(-2).join(".");
  if (COMMON_MULTI_PART_PUBLIC_SUFFIXES.has(twoPartSuffix) && segments.length >= 3) {
    return segments.slice(-3).join(".");
  }

  return twoPartSuffix;
}

export function isThirdPartyHost(targetHost, firstPartyHost) {
  const target = getComparableDomain(targetHost);
  const firstParty = getComparableDomain(firstPartyHost);
  if (!target || !firstParty) {
    return false;
  }
  return target !== firstParty;
}

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
