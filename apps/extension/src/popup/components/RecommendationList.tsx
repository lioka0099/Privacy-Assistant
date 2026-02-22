import type { PopupAnalysisViewModel } from "../../shared/messages";
import type { RecommendationActionId } from "@shared/index";

export function renderRecommendationList(
  analysis: PopupAnalysisViewModel,
  selectedActionIds: readonly RecommendationActionId[]
): string {
  const recommendations = analysis.recommendations;
  if (recommendations.length === 0) {
    return `
      <section aria-label="Recommendations" class="recommendation-list">
        <h2>Recommendations</h2>
        <p>No recommendations are available for this page.</p>
      </section>
    `;
  }

  const listHtml = recommendations
    .map(
      (recommendation) => `
        <li class="recommendation-item">
          <label>
            <input
              type="checkbox"
              name="recommendation"
              value="${recommendation.actionId}"
              data-action-id="${recommendation.actionId}"
              ${selectedActionIds.includes(recommendation.actionId) ? "checked" : ""}
            />
            <span>${recommendation.title}</span>
          </label>
          <p>${recommendation.rationale}</p>
        </li>
      `
    )
    .join("");

  return `
    <section aria-label="Recommendations" class="recommendation-list">
      <h2>Recommendations</h2>
      <ul>${listHtml}</ul>
    </section>
  `;
}
