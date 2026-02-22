import type { PopupAnalysisViewModel } from "../../shared/messages";

function renderRiskItem(title: string, explanation: string, severity: string): string {
  return `
    <li class="risk-item severity-${severity}">
      <p><strong>${title}</strong> (${severity})</p>
      <p>${explanation}</p>
    </li>
  `;
}

export function renderRiskList(analysis: PopupAnalysisViewModel): string {
  const items = analysis.risks.riskItems;
  if (items.length === 0) {
    return `
      <section aria-label="Detected risks" class="risk-list">
        <h2>Risks</h2>
        <p>No active risk rules were triggered.</p>
      </section>
    `;
  }

  const listHtml = items
    .map((item) => renderRiskItem(item.title, item.explanation, item.severity))
    .join("");

  return `
    <section aria-label="Detected risks" class="risk-list">
      <h2>Risks</h2>
      <ul>${listHtml}</ul>
    </section>
  `;
}
