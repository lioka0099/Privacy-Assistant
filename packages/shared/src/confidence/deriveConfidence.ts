import type {
  ConfidenceLevel,
  NormalizedAnalysisInput,
  PrivacyScoreComputation
} from "../scoring/privacyScore";

export type ConfidenceReasonCode =
  | "CONTENT_UNREACHABLE"
  | "CONTENT_SIGNALS_UNAVAILABLE"
  | "COOKIE_SIGNALS_UNAVAILABLE"
  | "NETWORK_SIGNALS_UNAVAILABLE";

export type ConfidenceReason = {
  code: ConfidenceReasonCode;
  message: string;
};

export type ConfidenceAssessment = {
  rulesetVersion: string;
  score: number;
  level: ConfidenceLevel;
  reasons: readonly ConfidenceReason[];
};

export type PrivacyScoredOutput = {
  score: PrivacyScoreComputation;
  confidence: ConfidenceAssessment;
};

export const CONFIDENCE_RULESET_VERSION = "1.0.0";

const MAX_CONFIDENCE_SCORE = 100;
const MIN_CONFIDENCE_SCORE = 0;

type ConfidencePenaltyRule = {
  code: ConfidenceReasonCode;
  penalty: number;
  message: (input: NormalizedAnalysisInput) => string;
  shouldApply: (input: NormalizedAnalysisInput) => boolean;
};

const CONFIDENCE_PENALTY_RULES: readonly ConfidencePenaltyRule[] = Object.freeze([
  {
    code: "CONTENT_UNREACHABLE",
    penalty: 20,
    message: () => "Content context was unreachable; page-level signals may be incomplete.",
    shouldApply: (input) => !input.sourceFlags.contentReachable
  },
  {
    code: "CONTENT_SIGNALS_UNAVAILABLE",
    penalty: 35,
    message: () => "Content signal collectors were unavailable for this analysis.",
    shouldApply: (input) => !input.sourceFlags.contentSignalsAvailable
  },
  {
    code: "COOKIE_SIGNALS_UNAVAILABLE",
    penalty: 20,
    message: () => "Cookie signal collector data is unavailable, reducing confidence.",
    shouldApply: (input) => !input.sourceFlags.cookieSignalsAvailable
  },
  {
    code: "NETWORK_SIGNALS_UNAVAILABLE",
    penalty: 25,
    message: (input) =>
      input.networkSignals.unavailableReason
        ? `Network signal collector unavailable: ${input.networkSignals.unavailableReason}.`
        : "Network signal collector is unavailable, reducing confidence in traffic-related results.",
    shouldApply: (input) => !input.sourceFlags.networkSignalsAvailable
  }
]);

function clampConfidenceScore(value: number): number {
  if (!Number.isFinite(value)) {
    return MIN_CONFIDENCE_SCORE;
  }
  if (value < MIN_CONFIDENCE_SCORE) {
    return MIN_CONFIDENCE_SCORE;
  }
  if (value > MAX_CONFIDENCE_SCORE) {
    return MAX_CONFIDENCE_SCORE;
  }
  return value;
}

function mapConfidenceLevel(score: number): ConfidenceLevel {
  if (score >= 80) {
    return "high";
  }
  if (score >= 50) {
    return "medium";
  }
  return "low";
}

export function deriveConfidence(input: NormalizedAnalysisInput): ConfidenceAssessment {
  let confidenceScore = MAX_CONFIDENCE_SCORE;
  const reasons: ConfidenceReason[] = [];

  for (const rule of CONFIDENCE_PENALTY_RULES) {
    if (!rule.shouldApply(input)) {
      continue;
    }
    confidenceScore -= rule.penalty;
    reasons.push({
      code: rule.code,
      message: rule.message(input)
    });
  }

  const boundedScore = clampConfidenceScore(confidenceScore);
  return {
    rulesetVersion: CONFIDENCE_RULESET_VERSION,
    score: boundedScore,
    level: mapConfidenceLevel(boundedScore),
    reasons
  };
}

export function createPrivacyScoredOutput(
  score: PrivacyScoreComputation,
  normalized: NormalizedAnalysisInput
): PrivacyScoredOutput {
  return {
    score,
    confidence: deriveConfidence(normalized)
  };
}
