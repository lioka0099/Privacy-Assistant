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

export type ScoreFactorContribution = {
  factorId: ScoreFactorId;
  label: string;
  rawValue: number;
  cappedValue: number;
  hardCap: number;
  weight: number;
  penalty: number;
};

export type ScoreReason = {
  factorId: ScoreFactorId;
  label: string;
  penalty: number;
  reason: string;
};

export type PrivacyScoreComputation = {
  baseScore: number;
  totalPenalty: number;
  score: number;
  roundingStrategy: "stable_half_up_2dp";
  contributions: readonly ScoreFactorContribution[];
  strongestNegativeReasons: readonly ScoreReason[];
};

export type NormalizedAnalysisInput = {
  sourceFlags: {
    contentReachable: boolean;
    contentSignalsAvailable: boolean;
    cookieSignalsAvailable: boolean;
    networkSignalsAvailable: boolean;
  };
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
    unavailableReason?: string | null;
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
    hardCap: 4000000, //bytes
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

const MAX_REASON_COUNT = 3;
const BASE_PRIVACY_SCORE = 100;

function toFiniteNonNegative(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    return 0;
  }
  return value;
}

function roundStableHalfUp2dp(value: number): number {
  const safe = Number.isFinite(value) ? value : 0;
  return Math.round((safe + Number.EPSILON) * 100) / 100;
}

function computeRawFactorValue(
  factorId: ScoreFactorId,
  input: NormalizedAnalysisInput
): number {
  if (factorId === "third_party_scripts") {
    return toFiniteNonNegative(input.scriptSignals.thirdPartyScriptDomainCount);
  }
  if (factorId === "third_party_cookies") {
    return toFiniteNonNegative(input.cookieSignals.thirdPartyCookieEstimateCount);
  }
  if (factorId === "storage_usage") {
    return toFiniteNonNegative(
      input.storageSignals.localStorage.approxBytes + input.storageSignals.sessionStorage.approxBytes
    );
  }
  if (factorId === "tracking_indicators") {
    return toFiniteNonNegative(
      input.trackingHeuristics.trackerDomainHitCount +
      input.trackingHeuristics.endpointPatternHitCount +
      input.trackingHeuristics.trackingQueryParamCount
    );
  }
  if (!input.networkSignals.available) {
    return 0;
  }
  return toFiniteNonNegative(
    input.networkSignals.thirdPartyRequestCount +
    input.networkSignals.suspiciousEndpointHitCount +
    input.networkSignals.knownTrackerDomainHitCount +
    input.networkSignals.shortWindowBurstCount
  );
}

function buildReasonText(contribution: ScoreFactorContribution): string {
  if (contribution.factorId === "storage_usage") {
    return `${contribution.label} consumed ${Math.round(contribution.rawValue)} bytes`;
  }
  return `${contribution.label} triggered ${Math.round(contribution.rawValue)} signals`;
}

function compareContributions(
  a: ScoreFactorContribution,
  b: ScoreFactorContribution
): number {
  if (b.penalty !== a.penalty) {
    return b.penalty - a.penalty;
  }
  return SCORE_FACTOR_IDS_IN_ORDER.indexOf(a.factorId) - SCORE_FACTOR_IDS_IN_ORDER.indexOf(b.factorId);
}

export function computePrivacyScore(input: NormalizedAnalysisInput): PrivacyScoreComputation {
  const contributions = SCORE_FACTOR_DEFINITIONS.map((factor) => {
    const rawValue = computeRawFactorValue(factor.id, input);
    const cappedValue = Math.min(rawValue, factor.hardCap);
    const normalizedPenaltyRatio = factor.hardCap > 0 ? cappedValue / factor.hardCap : 0;
    const penalty = roundStableHalfUp2dp(factor.weight * normalizedPenaltyRatio);

    return {
      factorId: factor.id,
      label: factor.label,
      rawValue: roundStableHalfUp2dp(rawValue),
      cappedValue: roundStableHalfUp2dp(cappedValue),
      hardCap: factor.hardCap,
      weight: factor.weight,
      penalty
    } satisfies ScoreFactorContribution;
  });

  const totalPenalty = roundStableHalfUp2dp(
    contributions.reduce((sum, contribution) => sum + contribution.penalty, 0)
  );
  const unclampedScore = roundStableHalfUp2dp(BASE_PRIVACY_SCORE - totalPenalty);
  const score = roundStableHalfUp2dp(clampPrivacyScore(unclampedScore));

  const strongestNegativeReasons = [...contributions]
    .filter((contribution) => contribution.penalty > 0)
    .sort(compareContributions)
    .slice(0, MAX_REASON_COUNT)
    .map(
      (contribution) =>
        ({
          factorId: contribution.factorId,
          label: contribution.label,
          penalty: contribution.penalty,
          reason: buildReasonText(contribution)
        }) satisfies ScoreReason
    );

  return {
    baseScore: BASE_PRIVACY_SCORE,
    totalPenalty,
    score,
    roundingStrategy: "stable_half_up_2dp",
    contributions,
    strongestNegativeReasons
  };
}

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
