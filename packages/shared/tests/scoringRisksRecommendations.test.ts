import { describe, expect, it } from "vitest";
import { computePrivacyScore } from "../src/scoring/privacyScore";
import { detectRisks } from "../src/risks/detectRisks";
import { generateRecommendations } from "../src/recommendations/generateRecommendations";
import {
  cloneFixture,
  highRiskFixture,
  lowRiskFixture,
  mediumRiskFixture,
  partialDataFixture
} from "./fixtures/analysisFixtures.ts";

describe("score determinism and thresholds", () => {
  it("returns exactly the same scoring output for the same fixture", () => {
    const fixture = cloneFixture(mediumRiskFixture);
    const first = computePrivacyScore(fixture);
    const second = computePrivacyScore(fixture);
    expect(second).toEqual(first);
  });

  it("keeps low/medium/high fixtures in expected score ranges", () => {
    const low = computePrivacyScore(cloneFixture(lowRiskFixture));
    const medium = computePrivacyScore(cloneFixture(mediumRiskFixture));
    const high = computePrivacyScore(cloneFixture(highRiskFixture));

    expect(low.score).toBeGreaterThanOrEqual(70);
    expect(medium.score).toBeGreaterThanOrEqual(40);
    expect(medium.score).toBeLessThan(70);
    expect(high.score).toBeLessThan(40);
  });
});

describe("risk mapping", () => {
  it("maps overall risk boundaries deterministically", () => {
    const normalized = cloneFixture(lowRiskFixture);

    const boundaryLow = detectRisks({ score: 70, normalized });
    const boundaryMediumUpper = detectRisks({ score: 69.99, normalized });
    const boundaryMediumLower = detectRisks({ score: 40, normalized });
    const boundaryHigh = detectRisks({ score: 39.99, normalized });

    expect(boundaryLow.overallRisk).toBe("low");
    expect(boundaryMediumUpper.overallRisk).toBe("medium");
    expect(boundaryMediumLower.overallRisk).toBe("medium");
    expect(boundaryHigh.overallRisk).toBe("high");
  });

  it("triggers expected network fallback outputs when network is unavailable", () => {
    const result = detectRisks({
      score: computePrivacyScore(cloneFixture(partialDataFixture)).score,
      normalized: cloneFixture(partialDataFixture)
    });

    expect(result.networkFallbackUsed).toBe(true);
    expect(result.networkUnavailableReason).toBe("WEBREQUEST_LISTENER_UNAVAILABLE");
    expect(result.riskItems.some((risk) => risk.id === "network_signals_unavailable")).toBe(true);
    expect(
      result.riskItems.some(
        (risk) =>
          risk.id === "network_heavy_third_party_requests" ||
          risk.id === "network_suspicious_endpoint_repetition" ||
          risk.id === "network_tracker_domain_concentration" ||
          risk.id === "network_short_window_burst"
      )
    ).toBe(false);
  });
});

describe("recommendation mapping", () => {
  it("deduplicates recommendations while preserving risk coverage", () => {
    const normalized = cloneFixture(highRiskFixture);
    const score = computePrivacyScore(normalized);
    const risks = detectRisks({ score: score.score, normalized });
    const recommendations = generateRecommendations(risks);

    const recommendationIds = recommendations.recommendations.map((item) => item.actionId);
    const uniqueIds = new Set(recommendationIds);

    expect(uniqueIds.size).toBe(recommendationIds.length);
    expect(recommendationIds.length).toBeGreaterThan(0);
    expect(
      recommendations.recommendations.every((recommendation) => recommendation.triggeredByRiskIds.length > 0)
    ).toBe(true);
  });
});
