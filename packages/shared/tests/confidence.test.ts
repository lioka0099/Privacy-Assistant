import { describe, expect, it } from "vitest";
import { deriveConfidence } from "../src/confidence/deriveConfidence";
import { cloneFixture, lowRiskFixture, partialDataFixture } from "./fixtures/analysisFixtures.ts";

describe("confidence derivation", () => {
  it("returns high confidence with no missing sources", () => {
    const result = deriveConfidence(cloneFixture(lowRiskFixture));
    expect(result.level).toBe("high");
    expect(result.score).toBe(100);
    expect(result.reasons).toEqual([]);
  });

  it("downgrades confidence when only network signals are missing", () => {
    const fixture = cloneFixture(lowRiskFixture);
    fixture.sourceFlags.networkSignalsAvailable = false;
    fixture.networkSignals.available = false;
    fixture.networkSignals.unavailableReason = "NETWORK_PERMISSION_BLOCKED";

    const result = deriveConfidence(fixture);
    expect(result.level).toBe("medium");
    expect(result.score).toBe(75);
    expect(result.reasons.map((reason) => reason.code)).toEqual(["NETWORK_SIGNALS_UNAVAILABLE"]);
  });

  it("drops confidence to low when core collectors are unavailable", () => {
    const result = deriveConfidence(cloneFixture(partialDataFixture));
    expect(result.level).toBe("low");
    expect(result.score).toBe(20);
    expect(result.reasons.map((reason) => reason.code)).toEqual([
      "CONTENT_UNREACHABLE",
      "CONTENT_SIGNALS_UNAVAILABLE",
      "NETWORK_SIGNALS_UNAVAILABLE"
    ]);
  });
});
