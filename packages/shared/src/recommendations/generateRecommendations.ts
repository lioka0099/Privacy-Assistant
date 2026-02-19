import type { MitigationPriority, RiskDetectionOutput, RiskItem, RiskSeverity } from "../risks/detectRisks";

export type RecommendationActionId =
  | "reduce_third_party_cookies"
  | "limit_third_party_scripts"
  | "clear_site_storage_data"
  | "block_known_trackers"
  | "review_tracking_permissions"
  | "harden_network_privacy";

export type RecommendationCatalogItem = {
  actionId: RecommendationActionId;
  title: string;
  rationale: string;
  defaultPriority: MitigationPriority;
};

export type Recommendation = {
  actionId: RecommendationActionId;
  title: string;
  rationale: string;
  severity: RiskSeverity;
  priority: MitigationPriority;
  triggeredByRiskIds: readonly string[];
};

export type RecommendationOutput = {
  rulesetVersion: string;
  recommendations: readonly Recommendation[];
};

const RECOMMENDATION_RULESET_VERSION = "1.0.0";

const RECOMMENDATION_CATALOG: Record<RecommendationActionId, RecommendationCatalogItem> = Object.freeze({
  reduce_third_party_cookies: {
    actionId: "reduce_third_party_cookies",
    title: "Reduce third-party cookies",
    rationale: "Reducing third-party cookies lowers cross-site tracking across browsing sessions.",
    defaultPriority: "p1"
  },
  limit_third_party_scripts: {
    actionId: "limit_third_party_scripts",
    title: "Limit third-party scripts",
    rationale: "Limiting third-party script execution lowers data-sharing and fingerprinting exposure.",
    defaultPriority: "p2"
  },
  clear_site_storage_data: {
    actionId: "clear_site_storage_data",
    title: "Clear site storage data",
    rationale: "Removing persistent storage can invalidate long-lived tracking identifiers.",
    defaultPriority: "p2"
  },
  block_known_trackers: {
    actionId: "block_known_trackers",
    title: "Block known tracker domains",
    rationale: "Blocking known trackers reduces profiling and telemetry collection.",
    defaultPriority: "p1"
  },
  review_tracking_permissions: {
    actionId: "review_tracking_permissions",
    title: "Review tracking-related permissions",
    rationale: "Restricting site permissions can reduce silent data access and background tracking.",
    defaultPriority: "p2"
  },
  harden_network_privacy: {
    actionId: "harden_network_privacy",
    title: "Harden network privacy settings",
    rationale: "Network privacy controls can reduce beaconing, endpoint telemetry, and request leakage.",
    defaultPriority: "p1"
  }
});

function recommendationIds(...actionIds: RecommendationActionId[]): readonly RecommendationActionId[] {
  return actionIds;
}

const RISK_TO_RECOMMENDATION_MAP: Readonly<Record<string, readonly RecommendationActionId[]>> =
  Object.freeze({
    overall_score_high: recommendationIds(
      "block_known_trackers",
      "reduce_third_party_cookies",
      "harden_network_privacy"
    ),
    third_party_cookie_volume: recommendationIds("reduce_third_party_cookies"),
    third_party_script_domains: recommendationIds(
      "limit_third_party_scripts",
      "review_tracking_permissions"
    ),
    persistent_storage_footprint: recommendationIds("clear_site_storage_data"),
    tracking_indicator_density: recommendationIds("block_known_trackers", "harden_network_privacy"),
    network_heavy_third_party_requests: recommendationIds(
      "harden_network_privacy",
      "block_known_trackers"
    ),
    network_suspicious_endpoint_repetition: recommendationIds(
      "harden_network_privacy",
      "block_known_trackers"
    ),
    network_tracker_domain_concentration: recommendationIds(
      "block_known_trackers",
      "harden_network_privacy"
    ),
    network_short_window_burst: recommendationIds("harden_network_privacy")
  });

const RISK_SEVERITY_ORDER: Record<RiskSeverity, number> = Object.freeze({
  high: 0,
  medium: 1,
  low: 2
});

const PRIORITY_ORDER: Record<MitigationPriority, number> = Object.freeze({
  p1: 0,
  p2: 1,
  p3: 2
});

function chooseHigherSeverity(a: RiskSeverity, b: RiskSeverity): RiskSeverity {
  return RISK_SEVERITY_ORDER[a] <= RISK_SEVERITY_ORDER[b] ? a : b;
}

function chooseHigherPriority(a: MitigationPriority, b: MitigationPriority): MitigationPriority {
  return PRIORITY_ORDER[a] <= PRIORITY_ORDER[b] ? a : b;
}

function sortRiskIdsStable(riskIds: readonly string[]): string[] {
  return [...riskIds].sort((left, right) => left.localeCompare(right));
}

function compareRecommendations(left: Recommendation, right: Recommendation): number {
  const bySeverity = RISK_SEVERITY_ORDER[left.severity] - RISK_SEVERITY_ORDER[right.severity];
  if (bySeverity !== 0) {
    return bySeverity;
  }
  const byPriority = PRIORITY_ORDER[left.priority] - PRIORITY_ORDER[right.priority];
  if (byPriority !== 0) {
    return byPriority;
  }
  return left.actionId.localeCompare(right.actionId);
}

type RecommendationAccumulator = {
  actionId: RecommendationActionId;
  severity: RiskSeverity;
  priority: MitigationPriority;
  triggeredByRiskIds: Set<string>;
};

function applyRiskToAccumulator(
  accumulators: Map<RecommendationActionId, RecommendationAccumulator>,
  risk: RiskItem
): void {
  const actionIds = RISK_TO_RECOMMENDATION_MAP[risk.id] ?? [];
  for (const actionId of actionIds) {
    const existing = accumulators.get(actionId);
    if (!existing) {
      accumulators.set(actionId, {
        actionId,
        severity: risk.severity,
        priority: risk.mitigationPriority,
        triggeredByRiskIds: new Set([risk.id])
      });
      continue;
    }

    existing.severity = chooseHigherSeverity(existing.severity, risk.severity);
    existing.priority = chooseHigherPriority(existing.priority, risk.mitigationPriority);
    existing.triggeredByRiskIds.add(risk.id);
  }
}

export function generateRecommendations(input: RiskDetectionOutput): RecommendationOutput {
  const accumulators = new Map<RecommendationActionId, RecommendationAccumulator>();
  for (const risk of input.riskItems) {
    applyRiskToAccumulator(accumulators, risk);
  }

  const recommendations = Array.from(accumulators.values())
    .map((accumulator): Recommendation => {
      const catalog = RECOMMENDATION_CATALOG[accumulator.actionId];
      return {
        actionId: accumulator.actionId,
        title: catalog.title,
        rationale: catalog.rationale,
        severity: accumulator.severity,
        priority: chooseHigherPriority(catalog.defaultPriority, accumulator.priority),
        triggeredByRiskIds: sortRiskIdsStable(Array.from(accumulator.triggeredByRiskIds))
      };
    })
    .sort(compareRecommendations);

  return {
    rulesetVersion: RECOMMENDATION_RULESET_VERSION,
    recommendations
  };
}
