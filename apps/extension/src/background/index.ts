import type { RecommendationActionId } from "@shared/index";
import type {
  ExecuteImprovePrivacyActionsResponse,
  ImprovePrivacyActionResult,
  PopupAnalysisViewModel
} from "../shared/messages";
import {
  executeImprovePrivacyActionQueue,
  type ActionExecutionContext,
  type ImprovePrivacyActionHandlerRegistry
} from "./improvePrivacy/actionQueue";
import { createDefaultImprovePrivacyActionRegistry } from "./improvePrivacy/handlers";

export const backgroundPlaceholderReady = true;

let improvePrivacyActionRegistry: ImprovePrivacyActionHandlerRegistry = {};
setImprovePrivacyActionRegistry(createDefaultImprovePrivacyActionRegistry());

export function setImprovePrivacyActionRegistry(
  registry: ImprovePrivacyActionHandlerRegistry
): void {
  improvePrivacyActionRegistry = { ...registry };
}

export async function executeSelectedImprovePrivacyActions(
  selectedActionIds: readonly RecommendationActionId[],
  context: ActionExecutionContext
): Promise<readonly ImprovePrivacyActionResult[]> {
  return executeImprovePrivacyActionQueue(selectedActionIds, improvePrivacyActionRegistry, context);
}

export async function executeImprovePrivacyActionsAndRefresh(
  requestId: string,
  selectedActionIds: readonly RecommendationActionId[],
  context: ActionExecutionContext,
  refreshAnalysis: () => Promise<PopupAnalysisViewModel>
): Promise<ExecuteImprovePrivacyActionsResponse> {
  const results = await executeSelectedImprovePrivacyActions(selectedActionIds, context);
  const refreshedAnalysis = await refreshAnalysis();
  return {
    ok: true,
    source: "background",
    requestId,
    payload: {
      results,
      refreshedAnalysis
    }
  };
}
