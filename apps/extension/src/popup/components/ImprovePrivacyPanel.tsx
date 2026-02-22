import type { PopupAnalysisViewModel } from "../../shared/messages";
import type { RecommendationActionId } from "@shared/index";
import { renderRecommendationList } from "./RecommendationList";

export type ImprovePrivacyPanelState = {
  selectedActionIds: readonly RecommendationActionId[];
  isProcessing: boolean;
};

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
    </section>
  `;
}
