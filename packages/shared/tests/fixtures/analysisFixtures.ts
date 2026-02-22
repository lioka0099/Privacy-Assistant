import type { NormalizedAnalysisInput } from "../../src/scoring/privacyScore";

function baseFixture(): NormalizedAnalysisInput {
  return {
    sourceFlags: {
      contentReachable: true,
      contentSignalsAvailable: true,
      cookieSignalsAvailable: true,
      networkSignalsAvailable: true
    },
    scriptSignals: {
      thirdPartyScriptDomainCount: 0,
      externalScriptCount: 0
    },
    cookieSignals: {
      thirdPartyCookieEstimateCount: 0,
      totalCookieCount: 0
    },
    storageSignals: {
      localStorage: { approxBytes: 0, keyCount: 0 },
      sessionStorage: { approxBytes: 0, keyCount: 0 }
    },
    trackingHeuristics: {
      trackerDomainHitCount: 0,
      endpointPatternHitCount: 0,
      trackingQueryParamCount: 0
    },
    networkSignals: {
      available: true,
      unavailableReason: null,
      thirdPartyRequestCount: 0,
      suspiciousEndpointHitCount: 0,
      knownTrackerDomainHitCount: 0,
      shortWindowBurstCount: 0
    },
    confidence: "high"
  };
}

export const lowRiskFixture: NormalizedAnalysisInput = {
  ...baseFixture(),
  scriptSignals: { thirdPartyScriptDomainCount: 2, externalScriptCount: 8 },
  cookieSignals: { thirdPartyCookieEstimateCount: 4, totalCookieCount: 12 },
  storageSignals: {
    localStorage: { approxBytes: 120000, keyCount: 8 },
    sessionStorage: { approxBytes: 80000, keyCount: 5 }
  },
  trackingHeuristics: { trackerDomainHitCount: 1, endpointPatternHitCount: 1, trackingQueryParamCount: 1 },
  networkSignals: {
    available: true,
    unavailableReason: null,
    thirdPartyRequestCount: 3,
    suspiciousEndpointHitCount: 1,
    knownTrackerDomainHitCount: 0,
    shortWindowBurstCount: 0
  }
};

export const mediumRiskFixture: NormalizedAnalysisInput = {
  ...baseFixture(),
  scriptSignals: { thirdPartyScriptDomainCount: 10, externalScriptCount: 25 },
  cookieSignals: { thirdPartyCookieEstimateCount: 20, totalCookieCount: 35 },
  storageSignals: {
    localStorage: { approxBytes: 1100000, keyCount: 24 },
    sessionStorage: { approxBytes: 400000, keyCount: 16 }
  },
  trackingHeuristics: { trackerDomainHitCount: 4, endpointPatternHitCount: 4, trackingQueryParamCount: 4 },
  networkSignals: {
    available: true,
    unavailableReason: null,
    thirdPartyRequestCount: 30,
    suspiciousEndpointHitCount: 5,
    knownTrackerDomainHitCount: 2,
    shortWindowBurstCount: 3
  }
};

export const highRiskFixture: NormalizedAnalysisInput = {
  ...baseFixture(),
  scriptSignals: { thirdPartyScriptDomainCount: 30, externalScriptCount: 80 },
  cookieSignals: { thirdPartyCookieEstimateCount: 80, totalCookieCount: 120 },
  storageSignals: {
    localStorage: { approxBytes: 5000000, keyCount: 80 },
    sessionStorage: { approxBytes: 2500000, keyCount: 45 }
  },
  trackingHeuristics: { trackerDomainHitCount: 16, endpointPatternHitCount: 14, trackingQueryParamCount: 12 },
  networkSignals: {
    available: true,
    unavailableReason: null,
    thirdPartyRequestCount: 80,
    suspiciousEndpointHitCount: 25,
    knownTrackerDomainHitCount: 12,
    shortWindowBurstCount: 30
  }
};

export const partialDataFixture: NormalizedAnalysisInput = {
  ...mediumRiskFixture,
  sourceFlags: {
    contentReachable: false,
    contentSignalsAvailable: false,
    cookieSignalsAvailable: true,
    networkSignalsAvailable: false
  },
  networkSignals: {
    available: false,
    unavailableReason: "WEBREQUEST_LISTENER_UNAVAILABLE",
    thirdPartyRequestCount: 0,
    suspiciousEndpointHitCount: 0,
    knownTrackerDomainHitCount: 0,
    shortWindowBurstCount: 0
  },
  confidence: "low"
};

export function cloneFixture(input: NormalizedAnalysisInput): NormalizedAnalysisInput {
  return structuredClone(input);
}
