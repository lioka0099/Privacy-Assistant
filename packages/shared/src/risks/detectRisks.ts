import type { NormalizedAnalysisInput } from "../scoring/privacyScore";

export type OverallRiskLevel = "low" | "medium" | "high";
export type RiskSeverity = "low" | "medium" | "high";
export type MitigationPriority = "p1" | "p2" | "p3";

export type RiskMetricOperator = ">=" | ">" | "<=" | "<";

export type RiskRuleSource =
  | "overall_score"
  | "cookies"
  | "scripts"
  | "storage"
  | "tracking"
  | "network";

export type RiskItem = {
  id: string;
  title: string;
  explanation: string;
  severity: RiskSeverity;
  mitigationPriority: MitigationPriority;
  source: RiskRuleSource;
  metric: string;
  operator: RiskMetricOperator;
  threshold: number;
  actualValue: number;
};

export type RiskDetectionInput = {
  score: number;
  normalized: NormalizedAnalysisInput;
};

export type RiskDetectionOutput = {
  rulesetVersion: string;
  overallRisk: OverallRiskLevel;
  overallExplanation: string;
  mappingFallbackUsed: boolean;
  networkFallbackUsed: boolean;
  networkUnavailableReason: string | null;
  riskItems: readonly RiskItem[];
};

type ScoreBand = {
  level: OverallRiskLevel;
  minInclusive: number;
  maxInclusive: number;
  explanation: string;
};

type RiskRule = {
  id: string;
  title: string;
  severity: RiskSeverity;
  mitigationPriority: MitigationPriority;
  source: RiskRuleSource;
  metric: string;
  operator: RiskMetricOperator;
  threshold: number;
  explanation: string;
  getActualValue: (input: RiskDetectionInput) => number;
};

export const RISK_RULESET_VERSION = "1.0.0";
const OVERALL_RISK_FALLBACK: ScoreBand = Object.freeze({
  level: "medium",
  minInclusive: 0,
  maxInclusive: 100,
  explanation:
    "Overall privacy risk could not be determined reliably due to a risk mapping configuration issue."
});

// Bands are intentionally explicit to keep thresholds versioned and deterministic.
const OVERALL_SCORE_BANDS: readonly ScoreBand[] = Object.freeze([
  {
    level: "high",
    minInclusive: 0,
    maxInclusive: 39.99,
    explanation: "High privacy risk due to strong tracking and third-party activity signals."
  },
  {
    level: "medium",
    minInclusive: 40,
    maxInclusive: 69.99,
    explanation: "Medium privacy risk with notable tracking-related behaviors detected."
  },
  {
    level: "low",
    minInclusive: 70,
    maxInclusive: 100,
    explanation: "Lower privacy risk compared to common web tracking patterns."
  }
]);

const RISK_RULES: readonly RiskRule[] = Object.freeze([
  {
    id: "overall_score_high",
    title: "Overall privacy score is low",
    severity: "high",
    mitigationPriority: "p1",
    source: "overall_score",
    metric: "score",
    operator: "<",
    threshold: 40,
    explanation: "The total score indicates multiple significant privacy risk factors.",
    getActualValue: (input) => input.score
  },
  {
    id: "third_party_cookie_volume",
    title: "High third-party cookie volume",
    severity: "high",
    mitigationPriority: "p1",
    source: "cookies",
    metric: "cookieSignals.thirdPartyCookieEstimateCount",
    operator: ">=",
    threshold: 25,
    explanation: "A large number of third-party cookies can enable cross-site tracking.",
    getActualValue: (input) => input.normalized.cookieSignals.thirdPartyCookieEstimateCount
  },
  {
    id: "third_party_script_domains",
    title: "Many third-party script domains",
    severity: "medium",
    mitigationPriority: "p2",
    source: "scripts",
    metric: "scriptSignals.thirdPartyScriptDomainCount",
    operator: ">=",
    threshold: 10,
    explanation: "Numerous external script domains increase exposure to data-sharing and tracking.",
    getActualValue: (input) => input.normalized.scriptSignals.thirdPartyScriptDomainCount
  },
  {
    id: "persistent_storage_footprint",
    title: "Large persistent storage footprint",
    severity: "medium",
    mitigationPriority: "p2",
    source: "storage",
    metric: "storageSignals.totalApproxBytes",
    operator: ">=",
    threshold: 2000000,
    explanation: "Large local/session storage may indicate persistent identifiers for tracking.",
    getActualValue: (input) =>
      input.normalized.storageSignals.localStorage.approxBytes +
      input.normalized.storageSignals.sessionStorage.approxBytes
  },
  {
    id: "tracking_indicator_density",
    title: "Dense tracking indicators",
    severity: "high",
    mitigationPriority: "p1",
    source: "tracking",
    metric: "trackingHeuristics.totalIndicators",
    operator: ">=",
    threshold: 12,
    explanation: "Multiple tracker and endpoint patterns suggest active telemetry collection.",
    getActualValue: (input) =>
      input.normalized.trackingHeuristics.trackerDomainHitCount +
      input.normalized.trackingHeuristics.endpointPatternHitCount +
      input.normalized.trackingHeuristics.trackingQueryParamCount
  },
  {
    id: "network_heavy_third_party_requests",
    title: "Heavy third-party request volume",
    severity: "medium",
    mitigationPriority: "p2",
    source: "network",
    metric: "networkSignals.thirdPartyRequestCount",
    operator: ">=",
    threshold: 40,
    explanation: "Frequent third-party network requests increase passive data leakage risk.",
    getActualValue: (input) =>
      input.normalized.networkSignals.available
        ? input.normalized.networkSignals.thirdPartyRequestCount
        : 0
  },
  {
    id: "network_suspicious_endpoint_repetition",
    title: "Repeated suspicious tracking endpoints",
    severity: "high",
    mitigationPriority: "p1",
    source: "network",
    metric: "networkSignals.suspiciousEndpointHitCount",
    operator: ">=",
    threshold: 15,
    explanation: "Repeated calls to tracking-like endpoints suggest active behavior analytics.",
    getActualValue: (input) =>
      input.normalized.networkSignals.available
        ? input.normalized.networkSignals.suspiciousEndpointHitCount
        : 0
  },
  {
    id: "network_tracker_domain_concentration",
    title: "Concentrated known tracker-domain activity",
    severity: "high",
    mitigationPriority: "p1",
    source: "network",
    metric: "networkSignals.knownTrackerDomainHitCount",
    operator: ">=",
    threshold: 8,
    explanation: "High known-tracker domain frequency indicates sustained profiling behavior.",
    getActualValue: (input) =>
      input.normalized.networkSignals.available
        ? input.normalized.networkSignals.knownTrackerDomainHitCount
        : 0
  },
  {
    id: "network_short_window_burst",
    title: "Suspicious short-window traffic burst",
    severity: "medium",
    mitigationPriority: "p2",
    source: "network",
    metric: "networkSignals.shortWindowBurstCount",
    operator: ">=",
    threshold: 25,
    explanation: "Burst-like request behavior may indicate beaconing or batch telemetry uploads.",
    getActualValue: (input) =>
      input.normalized.networkSignals.available ? input.normalized.networkSignals.shortWindowBurstCount : 0
  }
]);

function clampToScoreRange(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  if (value < 0) {
    return 0;
  }
  if (value > 100) {
    return 100;
  }
  return value;
}

function compareThreshold(actualValue: number, operator: RiskMetricOperator, threshold: number): boolean {
  if (operator === ">=") {
    return actualValue >= threshold;
  }
  if (operator === ">") {
    return actualValue > threshold;
  }
  if (operator === "<=") {
    return actualValue <= threshold;
  }
  return actualValue < threshold;
}

function resolveOverallRisk(score: number): { band: ScoreBand; fallbackUsed: boolean } {
  const safeScore = clampToScoreRange(score);
  const matchedBand = OVERALL_SCORE_BANDS.find(
    (band) => safeScore >= band.minInclusive && safeScore <= band.maxInclusive
  );
  if (matchedBand) {
    return { band: matchedBand, fallbackUsed: false };
  }
  return { band: OVERALL_RISK_FALLBACK, fallbackUsed: true };
}

function createNetworkUnavailableRisk(input: RiskDetectionInput): RiskItem {
  return {
    id: "network_signals_unavailable",
    title: "Network signal analysis unavailable",
    explanation: input.normalized.networkSignals.unavailableReason
      ? `Network-based risk checks were skipped: ${input.normalized.networkSignals.unavailableReason}.`
      : "Network-based risk checks were skipped because network signals are unavailable.",
    severity: "low",
    mitigationPriority: "p3",
    source: "network",
    metric: "networkSignals.available",
    operator: "<",
    threshold: 1,
    actualValue: 0
  };
}

export function detectRisks(input: RiskDetectionInput): RiskDetectionOutput {
  const overall = resolveOverallRisk(input.score);
  const networkSignalsAvailable = input.normalized.networkSignals.available;

  const riskItems = RISK_RULES.flatMap((rule): RiskItem[] => {
    if (rule.source === "network" && !networkSignalsAvailable) {
      return [];
    }
    const actualValue = rule.getActualValue(input);
    if (!compareThreshold(actualValue, rule.operator, rule.threshold)) {
      return [];
    }
    return [
      {
        id: rule.id,
        title: rule.title,
        explanation: rule.explanation,
        severity: rule.severity,
        mitigationPriority: rule.mitigationPriority,
        source: rule.source,
        metric: rule.metric,
        operator: rule.operator,
        threshold: rule.threshold,
        actualValue
      }
    ];
  });
  if (!networkSignalsAvailable) {
    riskItems.push(createNetworkUnavailableRisk(input));
  }

  return {
    rulesetVersion: RISK_RULESET_VERSION,
    overallRisk: overall.band.level,
    overallExplanation: overall.band.explanation,
    mappingFallbackUsed: overall.fallbackUsed,
    networkFallbackUsed: !networkSignalsAvailable,
    networkUnavailableReason: networkSignalsAvailable
      ? null
      : input.normalized.networkSignals.unavailableReason ?? null,
    riskItems
  };
}
