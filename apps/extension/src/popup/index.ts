import type { ImprovePrivacyActionResult, PopupAnalysisViewModel } from "../shared/messages";
import type { RecommendationActionId } from "@shared/index";
import { renderPopupApp } from "./App";

export const popupPlaceholderReady = true;

export type PopupUiState = {
  selectedActionIds: readonly RecommendationActionId[];
  isProcessing: boolean;
  actionResults: readonly ImprovePrivacyActionResult[];
};

const DEFAULT_POPUP_UI_STATE: PopupUiState = Object.freeze({
  selectedActionIds: [],
  isProcessing: false,
  actionResults: []
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
  initialAnalysis: PopupAnalysisViewModel,
  executeSelectedActions: (
    selectedActionIds: readonly RecommendationActionId[]
  ) => Promise<{
    results: readonly ImprovePrivacyActionResult[];
    refreshedAnalysis: PopupAnalysisViewModel;
  }>,
  initialState: PopupUiState = DEFAULT_POPUP_UI_STATE
): {
  getState: () => PopupUiState;
  setProcessing: (isProcessing: boolean) => void;
  getAnalysis: () => PopupAnalysisViewModel;
} {
  let analysis = initialAnalysis;
  let uiState: PopupUiState = {
    selectedActionIds: [...initialState.selectedActionIds],
    isProcessing: initialState.isProcessing,
    actionResults: [...initialState.actionResults]
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

    const improveButton = container.querySelector<HTMLButtonElement>("#improve-privacy-button");
    improveButton?.addEventListener("click", async () => {
      if (uiState.selectedActionIds.length === 0 || uiState.isProcessing) {
        return;
      }
      uiState = {
        ...uiState,
        isProcessing: true
      };
      renderAndBind();

      try {
        const executionResult = await executeSelectedActions(uiState.selectedActionIds);
        analysis = executionResult.refreshedAnalysis;
        uiState = {
          ...uiState,
          isProcessing: false,
          selectedActionIds: [],
          actionResults: [...executionResult.results]
        };
      } catch (error) {
        const failedSelectedActionIds = [...uiState.selectedActionIds];
        uiState = {
          ...uiState,
          isProcessing: false,
          actionResults: failedSelectedActionIds.map((actionId) => ({
            actionId,
            status: "failed" as const,
            message: error instanceof Error ? error.message : "Action execution failed."
          }))
        };
      }
      renderAndBind();
    });
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
    },
    getAnalysis: () => analysis
  };
}
