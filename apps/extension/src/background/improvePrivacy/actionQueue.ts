import type { RecommendationActionId } from "@shared/index";
import type { ImprovePrivacyActionResult } from "../../shared/messages";

export type ActionExecutionContext = {
  tabId: number | null;
  pageUrl: string | null;
  domain: string | null;
};

export type ActionHandlerResult = {
  status: "success" | "failed" | "skipped";
  message: string;
};

export type ImprovePrivacyActionHandler = (
  context: ActionExecutionContext
) => Promise<ActionHandlerResult> | ActionHandlerResult;

export type ImprovePrivacyActionHandlerRegistry = Partial<
  Record<RecommendationActionId, ImprovePrivacyActionHandler>
>;

function dedupeActionIdsInStableOrder(
  selectedActionIds: readonly RecommendationActionId[]
): RecommendationActionId[] {
  const seen = new Set<RecommendationActionId>();
  const ordered: RecommendationActionId[] = [];
  for (const actionId of selectedActionIds) {
    if (seen.has(actionId)) {
      continue;
    }
    seen.add(actionId);
    ordered.push(actionId);
  }
  return ordered;
}

function asFailedResult(actionId: RecommendationActionId, message: string): ImprovePrivacyActionResult {
  return {
    actionId,
    status: "failed",
    message
  };
}

export async function executeImprovePrivacyActionQueue(
  selectedActionIds: readonly RecommendationActionId[],
  registry: ImprovePrivacyActionHandlerRegistry,
  context: ActionExecutionContext
): Promise<readonly ImprovePrivacyActionResult[]> {
  const orderedActionIds = dedupeActionIdsInStableOrder(selectedActionIds);
  const results: ImprovePrivacyActionResult[] = [];

  for (const actionId of orderedActionIds) {
    const handler = registry[actionId];
    if (!handler) {
      results.push({
        actionId,
        status: "skipped",
        message: "No action handler is registered for this recommendation."
      });
      continue;
    }

    try {
      const outcome = await handler(context);
      results.push({
        actionId,
        status: outcome.status,
        message: outcome.message
      });
    } catch (error) {
      results.push(
        asFailedResult(
          actionId,
          error instanceof Error ? error.message : "Action failed unexpectedly."
        )
      );
    }
  }

  return results;
}
