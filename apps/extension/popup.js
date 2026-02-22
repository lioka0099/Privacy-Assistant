import { MESSAGE_TYPES, createRequestId } from "./messages.js";

const root = document.getElementById("app");

const state = {
  analysisResult: null,
  selectedActionIds: [],
  actionResults: [],
  isProcessing: false,
  loading: true,
  errorMessage: null,
  instructionsModal: {
    open: false,
    actionIds: []
  }
};
const COMPLETED_GUIDED_ACTIONS_STORAGE_KEY = "privacyAssistantCompletedGuidedActionsV1";

function toSafeNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function formatList(values, limit = 3) {
  if (!Array.isArray(values) || values.length === 0) {
    return "none";
  }
  return values.slice(0, limit).join(", ");
}

function formatCountedItems(values, key, limit = 3) {
  if (!Array.isArray(values) || values.length === 0) {
    return "none";
  }
  return values
    .slice(0, limit)
    .map((item) => `${item?.[key] ?? "unknown"} (${toSafeNumber(item?.count)})`)
    .join(", ");
}

function toCountedDetailLines(values, key, unitLabel, limit = 3) {
  if (!Array.isArray(values) || values.length === 0) {
    return [];
  }
  return values.slice(0, limit).map((item) => {
    const label = item?.[key] ?? "unknown";
    const count = toSafeNumber(item?.count);
    return `${label}: ${count} ${unitLabel}`;
  });
}

function buildRiskDetails(...lines) {
  return lines
    .flat()
    .filter((line) => typeof line === "string" && line.trim().length > 0)
    .slice(0, 6);
}

const GUIDED_ACTION_INSTRUCTIONS = Object.freeze({
  limit_third_party_scripts: {
    title: "Limit third-party scripts",
    steps: [
      "Chrome will open JavaScript settings.",
      "Set stricter JavaScript behavior for high-risk sites.",
      "Use site-specific blocking for untrusted domains."
    ]
  },
  block_known_trackers: {
    title: "Block known tracker domains",
    steps: [
      "Chrome will open cookie and tracking controls.",
      "Enable third-party cookie blocking.",
      "Clear existing site data if tracking persists."
    ]
  },
  review_tracking_permissions: {
    title: "Review tracking permissions",
    steps: [
      "Chrome will open cookie/permission settings.",
      "Review and restrict broad site permissions.",
      "Disable permissions that are not required."
    ]
  },
  harden_network_privacy: {
    title: "Harden network privacy",
    steps: [
      "Chrome will open security settings.",
      "Enable Enhanced protection.",
      "Review secure DNS and other privacy controls."
    ]
  }
});

function getGuidedActionIds(actionIds) {
  return actionIds.filter((actionId) => Boolean(GUIDED_ACTION_INSTRUCTIONS[actionId]));
}

function getDomainFromAnalysisResult(analysisResult) {
  return analysisResult?.tab?.hostname ?? analysisResult?.normalizedAnalysis?.page?.hostname ?? null;
}

function readCompletedGuidedActionsMap() {
  try {
    const raw = localStorage.getItem(COMPLETED_GUIDED_ACTIONS_STORAGE_KEY);
    if (!raw) {
      return {};
    }
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") {
      return {};
    }
    return parsed;
  } catch {
    return {};
  }
}

function writeCompletedGuidedActionsMap(map) {
  try {
    localStorage.setItem(COMPLETED_GUIDED_ACTIONS_STORAGE_KEY, JSON.stringify(map));
  } catch {
    // ignore storage write failures in popup context
  }
}

function getCompletedGuidedActionIdsForDomain(domain) {
  if (!domain || typeof domain !== "string") {
    return [];
  }
  const map = readCompletedGuidedActionsMap();
  const actionIds = map[domain];
  if (!Array.isArray(actionIds)) {
    return [];
  }
  return actionIds.filter((actionId) => typeof actionId === "string");
}

function persistCompletedGuidedActionsForDomain(domain, actionIds) {
  if (!domain || typeof domain !== "string" || !Array.isArray(actionIds) || actionIds.length === 0) {
    return;
  }
  const map = readCompletedGuidedActionsMap();
  const existingActionIds = Array.isArray(map[domain]) ? map[domain] : [];
  const merged = Array.from(new Set([...existingActionIds, ...actionIds]));
  map[domain] = merged;
  writeCompletedGuidedActionsMap(map);
}

function renderInstructionsModal() {
  if (!state.instructionsModal.open || state.instructionsModal.actionIds.length === 0) {
    return "";
  }

  const content = state.instructionsModal.actionIds
    .map((actionId) => {
      const instruction = GUIDED_ACTION_INSTRUCTIONS[actionId];
      if (!instruction) {
        return "";
      }
      return `
        <section class="instructions-item">
          <h3>${instruction.title}</h3>
          <ul>
            ${instruction.steps.map((step) => `<li>${step}</li>`).join("")}
          </ul>
        </section>
      `;
    })
    .join("");

  return `
    <section class="instructions-modal-overlay" aria-label="Action instructions confirmation">
      <div class="instructions-modal">
        <h2>Before we continue</h2>
        <p>Some selected actions need a quick manual confirmation in Chrome settings.</p>
        ${content}
        <div class="instructions-actions">
          <button id="instructions-cancel-button" type="button">Cancel</button>
          <button id="instructions-confirm-button" type="button">I read this, continue</button>
        </div>
      </div>
    </section>
  `;
}

function clampScore(score) {
  if (score < 0) {
    return 0;
  }
  if (score > 100) {
    return 100;
  }
  return score;
}

function scaleSignalToFiveSecondWindow(value, observedWindowMs) {
  const safeValue = toSafeNumber(value);
  const windowMs = toSafeNumber(observedWindowMs);
  if (windowMs <= 0) {
    return safeValue;
  }
  return (safeValue * 5000) / windowMs;
}

function computeScore(normalized) {
  if (!normalized) {
    return 0;
  }
  const thirdPartyScriptDomainCount = toSafeNumber(
    normalized.scriptSignals?.thirdPartyScriptDomainCount
  );
  const thirdPartyCookieEstimateCount = toSafeNumber(
    normalized.cookieSignals?.thirdPartyCookieEstimateCount
  );
  const storageBytes =
    toSafeNumber(normalized.storageSignals?.localStorage?.approxBytes) +
    toSafeNumber(normalized.storageSignals?.sessionStorage?.approxBytes);
  const trackingIndicators =
    toSafeNumber(normalized.trackingHeuristics?.trackerDomainHitCount) +
    toSafeNumber(normalized.trackingHeuristics?.endpointPatternHitCount) +
    toSafeNumber(normalized.trackingHeuristics?.trackingQueryParamCount);
  const networkAvailable = normalized.networkSignals?.available !== false;
  const networkObservedWindowMs = toSafeNumber(normalized.networkSignals?.observedWindowMs);
  const scaledThirdPartyRequests = scaleSignalToFiveSecondWindow(
    normalized.networkSignals?.thirdPartyRequestCount,
    networkObservedWindowMs
  );
  const scaledSuspiciousEndpoints = scaleSignalToFiveSecondWindow(
    normalized.networkSignals?.suspiciousEndpointHitCount,
    networkObservedWindowMs
  );
  const scaledKnownTrackerHits = scaleSignalToFiveSecondWindow(
    normalized.networkSignals?.knownTrackerDomainHitCount,
    networkObservedWindowMs
  );
  const burstPenaltyContribution =
    Math.min(toSafeNumber(normalized.networkSignals?.shortWindowBurstCount), 25) * 0.05;
  const networkSuspiciousness = networkAvailable
    ? scaledThirdPartyRequests +
    scaledSuspiciousEndpoints +
    scaledKnownTrackerHits +
    burstPenaltyContribution
    : 0;

  const penalties = [
    (Math.min(thirdPartyScriptDomainCount, 20) / 20) * 20,
    (Math.min(thirdPartyCookieEstimateCount, 40) / 40) * 20,
    (Math.min(storageBytes, 4000000) / 4000000) * 15,
    (Math.min(trackingIndicators, 30) / 30) * 25,
    (Math.min(networkSuspiciousness, 80) / 80) * 20
  ];
  const totalPenalty = penalties.reduce((sum, penalty) => sum + penalty, 0);
  return Math.round(clampScore(100 - totalPenalty) * 100) / 100;
}

function detectRisks(normalized, score) {
  if (!normalized) {
    return [];
  }
  const risks = [];
  const contentReachable = normalized.sourceFlags?.contentReachable !== false;
  const contentSignalsAvailable = normalized.sourceFlags?.contentSignalsAvailable !== false;
  if (!contentReachable || !contentSignalsAvailable) {
    risks.push({
      id: "content_signals_unavailable",
      title: "Page-level signals are partially unavailable",
      severity: "medium",
      explanation:
        "Some in-page privacy signals could not be collected, so this score may understate actual risk.",
      details: buildRiskDetails(
        `contentReachable: ${String(normalized.sourceFlags?.contentReachable)}`,
        `contentSignalsAvailable: ${String(normalized.sourceFlags?.contentSignalsAvailable)}`,
        "Try reloading the page and re-running analysis."
      )
    });
  }
  if (score < 70) {
    risks.push({
      id: "overall_score_medium_or_high",
      title: "Overall privacy score needs improvement",
      severity: score < 40 ? "high" : "medium",
      explanation: "Multiple tracking-related signals indicate privacy hardening opportunities.",
      details: buildRiskDetails(
        `Score: ${score.toFixed(2)} / 100`,
        `Third-party script domains: ${toSafeNumber(normalized.scriptSignals?.thirdPartyScriptDomainCount)}`,
        `Third-party cookies: ${toSafeNumber(normalized.cookieSignals?.thirdPartyCookieEstimateCount)}`,
        `Tracker indicators: ${toSafeNumber(normalized.trackingHeuristics?.trackerDomainHitCount) +
        toSafeNumber(normalized.trackingHeuristics?.endpointPatternHitCount) +
        toSafeNumber(normalized.trackingHeuristics?.trackingQueryParamCount)
        }`
      )
    });
  }
  if (score < 40) {
    risks.push({
      id: "overall_score_high",
      title: "Overall privacy score is low",
      severity: "high",
      explanation: "The total score indicates multiple significant privacy risk factors."
    });
  }
  if (toSafeNumber(normalized.cookieSignals?.thirdPartyCookieEstimateCount) >= 25) {
    risks.push({
      id: "third_party_cookie_volume",
      title: "High third-party cookie volume",
      severity: "high",
      explanation: "A large number of third-party cookies can enable cross-site tracking."
    });
  }
  if (toSafeNumber(normalized.scriptSignals?.thirdPartyScriptDomainCount) >= 10) {
    risks.push({
      id: "third_party_script_domains",
      title: "Many third-party script domains",
      severity: "medium",
      explanation: "Numerous external script domains increase data-sharing and tracking exposure.",
      evidence: `Domains: ${formatList(normalized.scriptSignals?.thirdPartyScriptDomains)}`,
      details: buildRiskDetails(
        `Total third-party script domains: ${toSafeNumber(
          normalized.scriptSignals?.thirdPartyScriptDomainCount
        )}`,
        `Sample domains: ${formatList(normalized.scriptSignals?.thirdPartyScriptDomains, 5)}`
      )
    });
  } else if (toSafeNumber(normalized.scriptSignals?.thirdPartyScriptDomainCount) >= 5) {
    risks.push({
      id: "third_party_script_domains_moderate",
      title: "Moderate third-party script activity",
      severity: "medium",
      explanation: "Several external script domains are active and may increase tracking exposure.",
      evidence: `Domains: ${formatList(normalized.scriptSignals?.thirdPartyScriptDomains)}`,
      details: buildRiskDetails(
        `Total third-party script domains: ${toSafeNumber(
          normalized.scriptSignals?.thirdPartyScriptDomainCount
        )}`,
        `Sample domains: ${formatList(normalized.scriptSignals?.thirdPartyScriptDomains, 5)}`
      )
    });
  }
  const storageBytes =
    toSafeNumber(normalized.storageSignals?.localStorage?.approxBytes) +
    toSafeNumber(normalized.storageSignals?.sessionStorage?.approxBytes);
  if (storageBytes >= 2000000) {
    risks.push({
      id: "persistent_storage_footprint",
      title: "Large persistent storage footprint",
      severity: "medium",
      explanation: "Large browser storage may indicate persistent identifiers for tracking."
    });
  }
  const trackingIndicators =
    toSafeNumber(normalized.trackingHeuristics?.trackerDomainHitCount) +
    toSafeNumber(normalized.trackingHeuristics?.endpointPatternHitCount) +
    toSafeNumber(normalized.trackingHeuristics?.trackingQueryParamCount);
  if (trackingIndicators >= 12) {
    risks.push({
      id: "tracking_indicator_density",
      title: "Dense tracking indicators",
      severity: "high",
      explanation: "Multiple tracker-like patterns suggest active telemetry collection.",
      evidence: `Tracker domains: ${formatList(normalized.trackingHeuristics?.trackerDomainHits)}`,
      details: buildRiskDetails(
        `Tracker-domain hits: ${toSafeNumber(normalized.trackingHeuristics?.trackerDomainHitCount)}`,
        `Suspicious endpoint hits: ${toSafeNumber(
          normalized.trackingHeuristics?.endpointPatternHitCount
        )}`,
        `Tracking query params: ${toSafeNumber(normalized.trackingHeuristics?.trackingQueryParamCount)}`,
        `Sample tracker domains: ${formatList(normalized.trackingHeuristics?.trackerDomainHits, 5)}`
      )
    });
  } else if (trackingIndicators >= 6) {
    risks.push({
      id: "tracking_indicator_density_moderate",
      title: "Moderate tracking indicators",
      severity: "medium",
      explanation: "Some tracker-like indicators were detected and may still affect privacy.",
      evidence: `Tracker domains: ${formatList(normalized.trackingHeuristics?.trackerDomainHits)}`,
      details: buildRiskDetails(
        `Tracker-domain hits: ${toSafeNumber(normalized.trackingHeuristics?.trackerDomainHitCount)}`,
        `Suspicious endpoint hits: ${toSafeNumber(
          normalized.trackingHeuristics?.endpointPatternHitCount
        )}`,
        `Tracking query params: ${toSafeNumber(normalized.trackingHeuristics?.trackingQueryParamCount)}`,
        `Sample tracker domains: ${formatList(normalized.trackingHeuristics?.trackerDomainHits, 5)}`
      )
    });
  }

  if (normalized.networkSignals?.available !== false) {
    const observedWindowMs = toSafeNumber(normalized.networkSignals?.observedWindowMs);
    const thirdPartyRequestCount = scaleSignalToFiveSecondWindow(
      normalized.networkSignals?.thirdPartyRequestCount,
      observedWindowMs
    );
    const suspiciousEndpointHitCount = scaleSignalToFiveSecondWindow(
      normalized.networkSignals?.suspiciousEndpointHitCount,
      observedWindowMs
    );
    const knownTrackerDomainHitCount = scaleSignalToFiveSecondWindow(
      normalized.networkSignals?.knownTrackerDomainHitCount,
      observedWindowMs
    );
    const shortWindowBurstCount = toSafeNumber(normalized.networkSignals?.shortWindowBurstCount);

    if (thirdPartyRequestCount >= 40) {
      risks.push({
        id: "network_heavy_third_party_requests",
        title: "Heavy third-party network traffic",
        severity: "medium",
        explanation: "Frequent third-party requests increase passive data leakage risk.",
        evidence:
          `Third-party requests (5s-equivalent): ${thirdPartyRequestCount.toFixed(1)}. ` +
          `Top hosts: ${formatCountedItems(normalized.networkSignals?.thirdPartyTopHosts, "host")}`,
        details: buildRiskDetails(
          `Observed window: ${toSafeNumber(normalized.networkSignals?.observedWindowMs) / 1000}s`,
          `Third-party requests (5s-equivalent): ${thirdPartyRequestCount.toFixed(1)}`,
          ...toCountedDetailLines(
            normalized.networkSignals?.thirdPartyTopHosts,
            "host",
            "requests"
          )
        )
      });
    } else if (thirdPartyRequestCount >= 20) {
      risks.push({
        id: "network_moderate_third_party_requests",
        title: "Moderate third-party network traffic",
        severity: "medium",
        explanation: "Noticeable third-party request volume may expose browsing activity.",
        evidence:
          `Third-party requests (5s-equivalent): ${thirdPartyRequestCount.toFixed(1)}. ` +
          `Top hosts: ${formatCountedItems(normalized.networkSignals?.thirdPartyTopHosts, "host")}`,
        details: buildRiskDetails(
          `Observed window: ${toSafeNumber(normalized.networkSignals?.observedWindowMs) / 1000}s`,
          `Third-party requests (5s-equivalent): ${thirdPartyRequestCount.toFixed(1)}`,
          ...toCountedDetailLines(
            normalized.networkSignals?.thirdPartyTopHosts,
            "host",
            "requests"
          )
        )
      });
    }

    if (suspiciousEndpointHitCount >= 15) {
      risks.push({
        id: "network_suspicious_endpoint_repetition",
        title: "Repeated suspicious tracking endpoints",
        severity: "high",
        explanation: "Repeated calls to tracking-like endpoints suggest active behavior analytics.",
        evidence:
          `Suspicious endpoint hits (5s-equivalent): ${suspiciousEndpointHitCount.toFixed(1)}. ` +
          `Top patterns: ${formatCountedItems(
            normalized.networkSignals?.suspiciousEndpointPatternCounts,
            "pattern"
          )}`,
        details: buildRiskDetails(
          `Suspicious endpoint hits (5s-equivalent): ${suspiciousEndpointHitCount.toFixed(1)}`,
          ...toCountedDetailLines(
            normalized.networkSignals?.suspiciousEndpointPatternCounts,
            "pattern",
            "matches"
          )
        )
      });
    }

    if (knownTrackerDomainHitCount >= 8) {
      risks.push({
        id: "network_tracker_domain_concentration",
        title: "Known tracker-domain concentration",
        severity: "high",
        explanation: "High known-tracker domain frequency indicates sustained profiling activity.",
        evidence: `Known tracker domains: ${formatList(normalized.networkSignals?.knownTrackerDomains)}`,
        details: buildRiskDetails(
          `Known tracker-domain hits (5s-equivalent): ${knownTrackerDomainHitCount.toFixed(1)}`,
          `Sample domains: ${formatList(normalized.networkSignals?.knownTrackerDomains, 6)}`
        )
      });
    }

    if (shortWindowBurstCount >= 25) {
      risks.push({
        id: "network_short_window_burst",
        title: "Suspicious short-window network burst",
        severity: "medium",
        explanation: "Burst-like traffic can indicate beaconing or telemetry uploads.",
        evidence: `Requests in last 5s: ${shortWindowBurstCount}`,
        details: buildRiskDetails(
          `Requests in last 5s: ${shortWindowBurstCount}`,
          `Total observed requests: ${toSafeNumber(normalized.networkSignals?.totalObservedRequests)}`
        )
      });
    }
  }

  if (normalized.networkSignals?.available === false) {
    risks.push({
      id: "network_signals_unavailable",
      title: "Network signal analysis unavailable",
      severity: "low",
      explanation:
        normalized.networkSignals?.unavailableReason ??
        "Network-based checks were skipped because network signals are unavailable.",
      evidence: "Network listener unavailable in current page/permission context.",
      details: buildRiskDetails(
        `Unavailable reason: ${normalized.networkSignals?.unavailableReason ?? "unknown"}`
      )
    });
  }
  return risks;
}

const RECOMMENDATION_CATALOG = Object.freeze({
  reduce_third_party_cookies: {
    title: "Reduce third-party cookies",
    rationale: "Reducing third-party cookies lowers cross-site tracking across browsing sessions."
  },
  limit_third_party_scripts: {
    title: "Limit third-party scripts",
    rationale: "Limiting third-party scripts lowers data-sharing and fingerprinting exposure."
  },
  clear_site_storage_data: {
    title: "Clear site storage data",
    rationale: "Removing persistent storage can invalidate long-lived tracking identifiers."
  },
  block_known_trackers: {
    title: "Block known tracker domains",
    rationale: "Blocking known trackers reduces profiling and telemetry collection."
  },
  review_tracking_permissions: {
    title: "Review tracking-related permissions",
    rationale: "Restricting site permissions can reduce silent data access."
  },
  harden_network_privacy: {
    title: "Harden network privacy settings",
    rationale: "Network privacy controls can reduce endpoint telemetry."
  }
});

const RISK_TO_ACTIONS = Object.freeze({
  content_signals_unavailable: ["review_tracking_permissions", "harden_network_privacy"],
  overall_score_medium_or_high: [
    "review_tracking_permissions",
    "harden_network_privacy",
    "limit_third_party_scripts"
  ],
  overall_score_high: ["block_known_trackers", "reduce_third_party_cookies", "harden_network_privacy"],
  third_party_cookie_volume: ["reduce_third_party_cookies"],
  third_party_script_domains: ["limit_third_party_scripts", "review_tracking_permissions"],
  third_party_script_domains_moderate: ["limit_third_party_scripts"],
  persistent_storage_footprint: ["clear_site_storage_data"],
  tracking_indicator_density: ["block_known_trackers", "harden_network_privacy"],
  tracking_indicator_density_moderate: ["harden_network_privacy"],
  network_heavy_third_party_requests: ["harden_network_privacy", "block_known_trackers"],
  network_moderate_third_party_requests: ["harden_network_privacy"],
  network_suspicious_endpoint_repetition: ["harden_network_privacy", "block_known_trackers"],
  network_tracker_domain_concentration: ["block_known_trackers", "harden_network_privacy"],
  network_short_window_burst: ["harden_network_privacy"]
});

function buildRecommendations(risks) {
  const actionIds = [];
  for (const risk of risks) {
    const mappedActions = RISK_TO_ACTIONS[risk.id] ?? [];
    for (const actionId of mappedActions) {
      if (!actionIds.includes(actionId)) {
        actionIds.push(actionId);
      }
    }
  }

  return actionIds.map((actionId) => ({
    actionId,
    title: RECOMMENDATION_CATALOG[actionId]?.title ?? actionId,
    rationale: RECOMMENDATION_CATALOG[actionId]?.rationale ?? "No rationale available."
  }));
}

function asViewModel(analysisResult) {
  const normalized = analysisResult?.normalizedAnalysis ?? null;
  const rawScore = computeScore(normalized);
  const contentSignalsUnavailable = Boolean(
    normalized &&
    (normalized.sourceFlags?.contentReachable === false ||
      normalized.sourceFlags?.contentSignalsAvailable === false)
  );
  const score = contentSignalsUnavailable ? Math.min(rawScore, 75) : rawScore;
  const risks = detectRisks(normalized, score);
  const fallbackRecommendations = [];
  if (risks.length === 0 && normalized) {
    if (toSafeNumber(normalized.scriptSignals?.thirdPartyScriptDomainCount) > 0) {
      fallbackRecommendations.push("limit_third_party_scripts");
    }
    if (toSafeNumber(normalized.cookieSignals?.thirdPartyCookieEstimateCount) > 0) {
      fallbackRecommendations.push("reduce_third_party_cookies");
    }
    if (fallbackRecommendations.length === 0 && score < 85) {
      fallbackRecommendations.push("review_tracking_permissions");
    }
  }
  const mappedRecommendations = buildRecommendations(risks);
  const domain = analysisResult?.tab?.hostname ?? normalized?.page?.hostname ?? null;
  const completedGuidedActionIds = getCompletedGuidedActionIdsForDomain(domain);
  const recommendationsBeforeFilter =
    mappedRecommendations.length > 0
      ? mappedRecommendations
      : fallbackRecommendations.map((actionId) => ({
        actionId,
        title: RECOMMENDATION_CATALOG[actionId]?.title ?? actionId,
        rationale: RECOMMENDATION_CATALOG[actionId]?.rationale ?? "No rationale available."
      }));
  const recommendations = recommendationsBeforeFilter.map((recommendation) => ({
    ...recommendation,
    previouslyAcknowledged: completedGuidedActionIds.includes(recommendation.actionId)
  }));
  const sourceFlags = normalized?.sourceFlags ?? {};
  let confidence = normalized?.confidence ?? "low";
  if (sourceFlags.contentSignalsAvailable && sourceFlags.cookieSignalsAvailable) {
    confidence = sourceFlags.networkSignalsAvailable ? "high" : "medium";
  } else if (sourceFlags.contentSignalsAvailable || sourceFlags.cookieSignalsAvailable) {
    confidence = "medium";
  }
  const viewModel = {
    domain: analysisResult?.tab?.hostname ?? normalized?.page?.hostname ?? "Unknown domain",
    score,
    confidence,
    risks,
    recommendations
  };
  return viewModel;
}

function render() {
  if (!root) {
    return;
  }

  if (state.loading) {
    root.innerHTML = "<p>Running privacy analysis...</p>";
    return;
  }

  if (state.errorMessage) {
    root.innerHTML = `<p class="error-text">${state.errorMessage}</p>`;
    return;
  }

  const model = asViewModel(state.analysisResult);
  const recommendationItems =
    model.recommendations.length === 0
      ? "<p>No recommendations available for this page.</p>"
      : `<ul>${model.recommendations
        .map(
          (recommendation) => `
          <li>
            <label>
              <input
                type="checkbox"
                data-action-id="${recommendation.actionId}"
                ${state.selectedActionIds.includes(recommendation.actionId) ? "checked" : ""}
              />
              ${recommendation.title}
            </label>
            ${recommendation.previouslyAcknowledged
              ? `<p><em>Previously acknowledged for this domain.</em></p>`
              : ""
            }
            <p>${recommendation.rationale}</p>
          </li>
        `
        )
        .join("")}</ul>`;

  const riskItems =
    model.risks.length === 0
      ? "<p>No active risk rules triggered.</p>"
      : `<ul>${model.risks
        .map(
          (risk) => `
          <li>
            <p><strong>${risk.title}</strong> (${risk.severity})</p>
            <p>${risk.explanation}</p>
            ${Array.isArray(risk.details) && risk.details.length > 0
              ? `<details class="risk-details"><summary>Show details</summary><ul>${risk.details
                .map((detail) => `<li>${detail}</li>`)
                .join("")}</ul></details>`
              : ""
            }
          </li>
        `
        )
        .join("")}</ul>`;

  const actionResultItems =
    state.actionResults.length === 0
      ? ""
      : `<section aria-label="Last action run">
          <h3>Last action run</h3>
          <ul>${state.actionResults
        .map(
          (result) => `
            <li>
              <p><strong>${result.actionId}</strong>: ${result.status}</p>
              <p>${result.message}</p>
            </li>
          `
        )
        .join("")}</ul>
        </section>`;

  root.innerHTML = `
    <section>
      <h1>Privacy Assistant</h1>
      <p>Domain: ${model.domain}</p>
    </section>
    <section>
      <h2>Privacy Score</h2>
      <p><strong>${model.score.toFixed(2)} / 100</strong></p>
      <p>Confidence: ${String(model.confidence).toUpperCase()}</p>
    </section>
    <section>
      <h2>Risks</h2>
      ${riskItems}
    </section>
    <section>
      <h2>Recommendations</h2>
      ${recommendationItems}
      <button id="improve-privacy-button" ${state.isProcessing || state.selectedActionIds.length === 0 ? "disabled" : ""
    }>
        ${state.isProcessing ? "Improving..." : "Improve Privacy"}
      </button>
      ${actionResultItems}
    </section>
    ${renderInstructionsModal()}
  `;

  const checkboxes = Array.from(root.querySelectorAll('input[data-action-id]'));
  for (const checkbox of checkboxes) {
    checkbox.addEventListener("change", () => {
      state.selectedActionIds = checkboxes
        .filter((element) => element.checked)
        .map((element) => element.getAttribute("data-action-id"))
        .filter((value) => typeof value === "string");
      render();
    });
  }

  const improveButton = root.querySelector("#improve-privacy-button");
  improveButton?.addEventListener("click", () => {
    void runImprovePrivacyFlow(false);
  });

  const instructionsCancelButton = root.querySelector("#instructions-cancel-button");
  instructionsCancelButton?.addEventListener("click", () => {
    state.instructionsModal = {
      open: false,
      actionIds: []
    };
    render();
  });

  const instructionsConfirmButton = root.querySelector("#instructions-confirm-button");
  instructionsConfirmButton?.addEventListener("click", () => {
    state.instructionsModal = {
      open: false,
      actionIds: []
    };
    void runImprovePrivacyFlow(true);
  });
}

function sendMessage(request) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(request, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(response);
    });
  });
}

async function loadAnalysis() {
  const requestId = createRequestId("popup_analysis");
  const response = await sendMessage({ type: MESSAGE_TYPES.RUN_ANALYSIS, requestId });
  if (!response || response.ok !== true) {
    throw new Error(response?.error ?? "Analysis request failed.");
  }
  state.analysisResult = response;
}

async function runImprovePrivacyFlow(instructionsConfirmed) {
  if (state.selectedActionIds.length === 0 || state.isProcessing) {
    return;
  }

  const guidedActionIds = getGuidedActionIds(state.selectedActionIds);
  if (!instructionsConfirmed && guidedActionIds.length > 0) {
    state.instructionsModal = {
      open: true,
      actionIds: guidedActionIds
    };
    render();
    return;
  }

  if (instructionsConfirmed && guidedActionIds.length > 0) {
    const currentDomain = getDomainFromAnalysisResult(state.analysisResult);
    persistCompletedGuidedActionsForDomain(currentDomain, guidedActionIds);
  }
  state.isProcessing = true;
  render();

  const requestId = createRequestId("popup_improve");
  try {
    const response = await sendMessage({
      type: MESSAGE_TYPES.EXECUTE_IMPROVE_PRIVACY_ACTIONS,
      requestId,
      selectedActionIds: state.selectedActionIds
    });
    if (!response || response.ok !== true) {
      throw new Error(response?.error ?? "Failed to execute Improve Privacy actions.");
    }

    state.actionResults = Array.isArray(response.payload?.results) ? response.payload.results : [];
    state.analysisResult = response.payload?.refreshedAnalysis ?? state.analysisResult;
    state.selectedActionIds = [];
  } catch (error) {
    state.actionResults = state.selectedActionIds.map((actionId) => ({
      actionId,
      status: "failed",
      message: error instanceof Error ? error.message : "Action execution failed."
    }));
  } finally {
    state.isProcessing = false;
    render();
  }
}

async function bootstrap() {
  try {
    await loadAnalysis();
  } catch (error) {
    state.errorMessage = error instanceof Error ? error.message : "Failed to load analysis.";
  } finally {
    state.loading = false;
    render();
  }
}

bootstrap();
