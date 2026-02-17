export type ScoreFactorId =
  | "third_party_scripts"
  | "third_party_cookies"
  | "storage_usage"
  | "tracking_indicators"
  | "network_suspiciousness";

export type ScoreUnit =
  | "count"
  | "domain_count"
  | "requests"
  | "bytes"
  | "composite_signals";

export type ConfidenceLevel = "low" | "medium" | "high";

export type ScoreBounds = {
  min: number;
  max: number;
};

export type ScoreFactorDefinition = {
  id: ScoreFactorId;
  label: string;
  // Dot path documents where raw value is read from normalized input.
  sourcePath: string;
  unit: ScoreUnit;
  // Positive values indicate max penalty points this factor may subtract.
  weight: number;
  // Hard cap for raw input to avoid one source dominating the score.
  hardCap: number;
  rationale: string;
};

export type NormalizedAnalysisInput = {
  scriptSignals: {
    thirdPartyScriptDomainCount: number;
    externalScriptCount: number;
  };
  cookieSignals: {
    thirdPartyCookieEstimateCount: number;
    totalCookieCount: number;
  };
  storageSignals: {
    localStorage: {
      approxBytes: number;
      keyCount: number;
    };
    sessionStorage: {
      approxBytes: number;
      keyCount: number;
    };
  };
  trackingHeuristics: {
    trackerDomainHitCount: number;
    endpointPatternHitCount: number;
    trackingQueryParamCount: number;
  };
  networkSignals: {
    available: boolean;
    thirdPartyRequestCount: number;
    suspiciousEndpointHitCount: number;
    knownTrackerDomainHitCount: number;
    shortWindowBurstCount: number;
  };
  confidence: ConfidenceLevel;
};

export const PRIVACY_SCORE_BOUNDS: ScoreBounds = Object.freeze({
  min: 0,
  max: 100
});

/**
 * Ordered factor list used as canonical scoring model definition.
 * Keep this order stable to preserve deterministic downstream behavior.
 */
export const SCORE_FACTOR_DEFINITIONS: readonly ScoreFactorDefinition[] = Object.freeze([
  {
    id: "third_party_scripts",
    label: "Third-party script domains",
    sourcePath: "scriptSignals.thirdPartyScriptDomainCount",
    unit: "domain_count",
    weight: 20,
    hardCap: 20,
    rationale: "Many external third-party script domains increase data-sharing and fingerprinting risk."
  },
  {
    id: "third_party_cookies",
    label: "Third-party cookies",
    sourcePath: "cookieSignals.thirdPartyCookieEstimateCount",
    unit: "count",
    weight: 20,
    hardCap: 40,
    rationale: "Third-party cookies are a strong indicator of cross-site tracking."
  },
  {
    id: "storage_usage",
    label: "Client storage footprint",
    sourcePath: "storageSignals.(localStorage+sessionStorage)",
    unit: "bytes",
    weight: 15,
    hardCap: 4000000,
    rationale: "Large persistent browser storage can support durable tracking identifiers."
  },
  {
    id: "tracking_indicators",
    label: "Tracking heuristics",
    sourcePath: "trackingHeuristics.(tracker+endpoint+query_hits)",
    unit: "composite_signals",
    weight: 25,
    hardCap: 30,
    rationale: "Tracker-domain hits and tracking patterns strongly correlate with surveillance behavior."
  },
  {
    id: "network_suspiciousness",
    label: "Suspicious network activity",
    sourcePath: "networkSignals.(third_party+suspicious+known_tracker+burst)",
    unit: "composite_signals",
    weight: 20,
    hardCap: 80,
    rationale: "Frequent third-party and suspicious endpoints indicate active telemetry and profiling."
  }
]);

export const SCORE_FACTOR_IDS_IN_ORDER: readonly ScoreFactorId[] = Object.freeze(
  SCORE_FACTOR_DEFINITIONS.map((factor) => factor.id)
);

export function clampPrivacyScore(value: number): number {
  if (!Number.isFinite(value)) {
    return PRIVACY_SCORE_BOUNDS.min;
  }
  if (value < PRIVACY_SCORE_BOUNDS.min) {
    return PRIVACY_SCORE_BOUNDS.min;
  }
  if (value > PRIVACY_SCORE_BOUNDS.max) {
    return PRIVACY_SCORE_BOUNDS.max;
  }
  return value;
}
