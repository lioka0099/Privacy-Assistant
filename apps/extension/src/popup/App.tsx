import type { PopupAnalysisViewModel } from "../shared/messages";
import type { ImprovePrivacyPanelState } from "./components/ImprovePrivacyPanel";
import { renderImprovePrivacyPanel } from "./components/ImprovePrivacyPanel";
import { renderRiskList } from "./components/RiskList";
import { renderScoreCard } from "./components/ScoreCard";

function renderDomainHeader(analysis: PopupAnalysisViewModel): string {
  return `
    <header class="domain-header">
      <h1>Privacy Assistant</h1>
      <p>Domain: ${analysis.domain}</p>
    </header>
  `;
}

export function renderPopupApp(
  analysis: PopupAnalysisViewModel,
  improvePrivacyPanelState: ImprovePrivacyPanelState
): string {
  const domainHeader = renderDomainHeader(analysis);
  const scoreCard = renderScoreCard(analysis);
  const riskList = renderRiskList(analysis);
  const improvePrivacyPanel = renderImprovePrivacyPanel(analysis, improvePrivacyPanelState);

  return `
    <main class="popup-app">
      ${domainHeader}
      ${scoreCard}
      ${riskList}
      ${improvePrivacyPanel}
    </main>
  `;
}
