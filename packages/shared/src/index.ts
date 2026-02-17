export const sharedPackageReady = true;

export {
  PRIVACY_SCORE_BOUNDS,
  SCORE_FACTOR_DEFINITIONS,
  SCORE_FACTOR_IDS_IN_ORDER,
  clampPrivacyScore
} from "./scoring/privacyScore";
export type {
  ConfidenceLevel,
  NormalizedAnalysisInput,
  ScoreBounds,
  ScoreFactorDefinition,
  ScoreFactorId,
  ScoreUnit
} from "./scoring/privacyScore";
