import type { ImprovePrivacyActionResult, PopupAnalysisViewModel } from "../../shared/messages";
import type { RecommendationActionId } from "@shared/index";
import { renderRecommendationList } from "./RecommendationList";

export type ImprovePrivacyPanelState = {
  selectedActionIds: readonly RecommendationActionId[];
  isProcessing: boolean;
  actionResults: readonly ImprovePrivacyActionResult[];
};

function renderActionResults(results: readonly ImprovePrivacyActionResult[]): string {
  if (results.length === 0) {
    return "";
  }

  const list = results
    .map(
      (result) => `
      <li class="action-result status-${result.status}">
        <p><strong>${result.actionId}</strong>: ${result.status}</p>
        <p>${result.message}</p>
      </li>
    `
    )
    .join("");

  return `
    <section aria-label="Action results" class="action-results">
      <h3>Last action run</h3>
      <ul>${list}</ul>
    </section>
  `;
}

export function renderImprovePrivacyPanel(
  analysis: PopupAnalysisViewModel,
  state: ImprovePrivacyPanelState
): string {
  const recommendationList = renderRecommendationList(analysis, state.selectedActionIds);
  const isDisabled = state.selectedActionIds.length === 0 || state.isProcessing;
  const buttonLabel = state.isProcessing ? "Improving..." : "Improve Privacy";
  return `
    <section aria-label="Improve privacy actions" class="improve-privacy-panel">
      ${recommendationList}
      <button type="button" id="improve-privacy-button" ${isDisabled ? "disabled" : ""}>
        ${buttonLabel}
      </button>
      ${renderActionResults(state.actionResults)}
    </section>
  `;
}
