import type { PopupAnalysisViewModel } from "../shared/messages";
import type { RecommendationActionId } from "@shared/index";
import { renderPopupApp } from "./App";

export const popupPlaceholderReady = true;

export type PopupUiState = {
  selectedActionIds: readonly RecommendationActionId[];
  isProcessing: boolean;
};

const DEFAULT_POPUP_UI_STATE: PopupUiState = Object.freeze({
  selectedActionIds: [],
  isProcessing: false
});

export function renderPopupRoot(
  container: HTMLElement,
  analysis: PopupAnalysisViewModel,
  uiState: PopupUiState = DEFAULT_POPUP_UI_STATE
): void {
  container.innerHTML = renderPopupApp(analysis, uiState);
}

export function mountPopupSelectionState(
  container: HTMLElement,
  analysis: PopupAnalysisViewModel,
  initialState: PopupUiState = DEFAULT_POPUP_UI_STATE
): {
  getState: () => PopupUiState;
  setProcessing: (isProcessing: boolean) => void;
} {
  let uiState: PopupUiState = {
    selectedActionIds: [...initialState.selectedActionIds],
    isProcessing: initialState.isProcessing
  };

  const renderAndBind = (): void => {
    renderPopupRoot(container, analysis, uiState);
    const checkboxes = Array.from(
      container.querySelectorAll<HTMLInputElement>('input[name="recommendation"]')
    );
    for (const checkbox of checkboxes) {
      checkbox.addEventListener("change", () => {
        const selectedActionIds = checkboxes
          .filter((item) => item.checked)
          .map((item) => item.value as RecommendationActionId);
        uiState = {
          ...uiState,
          selectedActionIds
        };
        renderAndBind();
      });
    }
  };

  renderAndBind();

  return {
    getState: () => uiState,
    setProcessing: (isProcessing: boolean) => {
      uiState = {
        ...uiState,
        isProcessing
      };
      renderAndBind();
    }
  };
}
