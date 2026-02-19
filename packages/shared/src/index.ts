export const sharedPackageReady = true;

export {
  PRIVACY_SCORE_BOUNDS,
  SCORE_FACTOR_DEFINITIONS,
  SCORE_FACTOR_IDS_IN_ORDER,
  computePrivacyScore,
  clampPrivacyScore
} from "./scoring/privacyScore";
export { RISK_RULESET_VERSION, detectRisks } from "./risks/detectRisks";
export {
  CONFIDENCE_RULESET_VERSION,
  createPrivacyScoredOutput,
  deriveConfidence
} from "./confidence/deriveConfidence";
export { generateRecommendations } from "./recommendations/generateRecommendations";
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
export type {
  ConfidenceAssessment,
  ConfidenceReason,
  ConfidenceReasonCode,
  PrivacyScoredOutput
} from "./confidence/deriveConfidence";
export type {
  MitigationPriority,
  OverallRiskLevel,
  RiskDetectionInput,
  RiskDetectionOutput,
  RiskItem,
  RiskMetricOperator,
  RiskRuleSource,
  RiskSeverity
} from "./risks/detectRisks";
export type {
  Recommendation,
  RecommendationActionId,
  RecommendationCatalogItem,
  RecommendationOutput
} from "./recommendations/generateRecommendations";
