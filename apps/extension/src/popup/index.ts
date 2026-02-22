import type { PopupAnalysisViewModel } from "../shared/messages";
import { renderPopupApp } from "./App";

export const popupPlaceholderReady = true;

export function renderPopupRoot(container: HTMLElement, analysis: PopupAnalysisViewModel): void {
  container.innerHTML = renderPopupApp(analysis);
}
