import type { RecommendationActionId } from "@shared/index";
import type { ImprovePrivacyActionResult } from "../shared/messages";
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
