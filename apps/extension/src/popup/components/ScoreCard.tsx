import type { PopupAnalysisViewModel } from "../../shared/messages";

function formatConfidenceLabel(score: number, level: string): string {
  return `${level.toUpperCase()} (${Math.round(score)}%)`;
}

export function renderScoreCard(analysis: PopupAnalysisViewModel): string {
  const strongestReasons = analysis.score.strongestNegativeReasons
    .slice(0, 3)
    .map((reason) => `<li>${reason.reason}</li>`)
    .join("");

  return `
    <section aria-label="Privacy score card" class="score-card">
      <h2>Privacy Score</h2>
      <p class="score-value">${analysis.score.score.toFixed(2)} / 100</p>
      <p class="score-confidence">
        Confidence: ${formatConfidenceLabel(analysis.confidence.score, analysis.confidence.level)}
      </p>
      ${
        strongestReasons
          ? `<div><p>Top factors:</p><ul>${strongestReasons}</ul></div>`
          : "<p>No major negative factors detected.</p>"
      }
    </section>
  `;
}
