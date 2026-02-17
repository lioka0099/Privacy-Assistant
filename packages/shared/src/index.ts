export const sharedPackageReady = true;

export {
  PRIVACY_SCORE_BOUNDS,
  SCORE_FACTOR_DEFINITIONS,
  SCORE_FACTOR_IDS_IN_ORDER,
  computePrivacyScore,
  clampPrivacyScore
} from "./scoring/privacyScore";
export type {
  ConfidenceLevel,
  NormalizedAnalysisInput,
  PrivacyScoreComputation,
  ScoreBounds,
  ScoreFactorContribution,
  ScoreFactorDefinition,
  ScoreFactorId,
  ScoreReason,
  ScoreUnit
} from "./scoring/privacyScore";
