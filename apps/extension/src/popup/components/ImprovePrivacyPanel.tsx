import type { PopupAnalysisViewModel } from "../../shared/messages";
import { renderRecommendationList } from "./RecommendationList";

export function renderImprovePrivacyPanel(analysis: PopupAnalysisViewModel): string {
  const recommendationList = renderRecommendationList(analysis);
  return `
    <section aria-label="Improve privacy actions" class="improve-privacy-panel">
      ${recommendationList}
      <button type="button" id="improve-privacy-button" disabled>
        Improve Privacy
      </button>
    </section>
  `;
}
