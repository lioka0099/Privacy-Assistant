export const MESSAGE_TYPES = {
  PING: "PING",
  RUN_ANALYSIS: "RUN_ANALYSIS",
  PING_CONTENT: "PING_CONTENT",
  COLLECT_PAGE_SIGNALS: "COLLECT_PAGE_SIGNALS"
} as const;

export const KNOWN_TRACKER_DOMAIN_PATTERNS = [
  "google-analytics.com",
  "doubleclick.net",
  "googletagmanager.com",
  "facebook.net",
  "connect.facebook.net",
  "hotjar.com",
  "segment.com",
  "mixpanel.com"
] as const;

export const SUSPICIOUS_ENDPOINT_PATTERNS = [
  "collect",
  "track",
  "pixel",
  "beacon",
  "events"
] as const;

export const TRACKING_QUERY_PARAM_PATTERNS = [
  "utm_",
  "fbclid",
  "gclid",
  "msclkid"
] as const;

export type MessageType = (typeof MESSAGE_TYPES)[keyof typeof MESSAGE_TYPES];

export type ExtensionMessage = {
  type: MessageType;
  requestId?: string;
};

export type MessageErrorPayload = {
  ok: false;
  source: "background" | "content" | "popup";
  requestId: string | null;
  status: "failed";
  code: string;
  error: string;
};
