import type {
  ConfidenceAssessment,
  PrivacyScoreComputation,
  Recommendation,
  RecommendationActionId,
  RiskDetectionOutput
} from "@shared/index";

export const MESSAGE_TYPES = {
  PING: "PING",
  RUN_ANALYSIS: "RUN_ANALYSIS",
  PING_CONTENT: "PING_CONTENT",
  COLLECT_PAGE_SIGNALS: "COLLECT_PAGE_SIGNALS",
  GET_POPUP_ANALYSIS: "GET_POPUP_ANALYSIS",
  EXECUTE_IMPROVE_PRIVACY_ACTIONS: "EXECUTE_IMPROVE_PRIVACY_ACTIONS"
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

export type MessageSuccessPayload<TPayload> = {
  ok: true;
  source: "background" | "content" | "popup";
  requestId: string | null;
  payload: TPayload;
};

export type MessageErrorPayload = {
  ok: false;
  source: "background" | "content" | "popup";
  requestId: string | null;
  status: "failed";
  code: string;
  error: string;
};

export type PopupAnalysisViewModel = {
  tabId: number;
  pageUrl: string;
  domain: string;
  generatedAtIso: string;
  score: PrivacyScoreComputation;
  confidence: ConfidenceAssessment;
  risks: RiskDetectionOutput;
  recommendations: readonly Recommendation[];
};

export type ImprovePrivacyActionStatus = "success" | "failed" | "skipped";

export type ImprovePrivacyActionResult = {
  actionId: RecommendationActionId;
  status: ImprovePrivacyActionStatus;
  message: string;
};

type RequestMessageBase = {
  requestId: string;
};

export type GetPopupAnalysisRequest = RequestMessageBase & {
  type: typeof MESSAGE_TYPES.GET_POPUP_ANALYSIS;
};

export type ExecuteImprovePrivacyActionsRequest = RequestMessageBase & {
  type: typeof MESSAGE_TYPES.EXECUTE_IMPROVE_PRIVACY_ACTIONS;
  selectedActionIds: readonly RecommendationActionId[];
};

export type PopupToBackgroundRequest =
  | GetPopupAnalysisRequest
  | ExecuteImprovePrivacyActionsRequest
  | (RequestMessageBase & {
    type: typeof MESSAGE_TYPES.RUN_ANALYSIS;
  });

export type GetPopupAnalysisResponse = MessageSuccessPayload<{
  analysis: PopupAnalysisViewModel;
}>;

export type ExecuteImprovePrivacyActionsResponse = MessageSuccessPayload<{
  results: readonly ImprovePrivacyActionResult[];
  refreshedAnalysis: PopupAnalysisViewModel;
}>;
