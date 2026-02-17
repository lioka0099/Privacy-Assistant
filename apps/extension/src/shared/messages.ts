export const MESSAGE_TYPES = {
  PING: "PING",
  RUN_ANALYSIS: "RUN_ANALYSIS",
  PING_CONTENT: "PING_CONTENT",
  COLLECT_PAGE_SIGNALS: "COLLECT_PAGE_SIGNALS"
} as const;

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
