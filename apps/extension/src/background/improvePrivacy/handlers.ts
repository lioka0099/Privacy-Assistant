import type { RecommendationActionId } from "@shared/index";
import type {
  ActionExecutionContext,
  ActionHandlerResult,
  ImprovePrivacyActionHandlerRegistry
} from "./actionQueue";

declare const chrome: any;

type CookieRecord = {
  name: string;
  domain?: string;
  path?: string;
  secure?: boolean;
  storeId?: string;
};

function normalizeDomain(domain: string | null): string {
  if (!domain) {
    return "";
  }
  return domain.replace(/^\./, "").toLowerCase().trim();
}

function isThirdPartyCookieDomain(cookieDomain: string | null, pageDomain: string | null): boolean {
  const normalizedCookieDomain = normalizeDomain(cookieDomain);
  const normalizedPageDomain = normalizeDomain(pageDomain);
  if (!normalizedCookieDomain || !normalizedPageDomain) {
    return false;
  }

  if (normalizedCookieDomain === normalizedPageDomain) {
    return false;
  }
  return !normalizedCookieDomain.endsWith(`.${normalizedPageDomain}`);
}

function toCookieRemovalUrl(cookie: CookieRecord): string | null {
  const normalizedDomain = normalizeDomain(cookie.domain ?? null);
  if (!normalizedDomain) {
    return null;
  }
  const scheme = cookie.secure ? "https" : "http";
  const path = cookie.path && cookie.path.startsWith("/") ? cookie.path : "/";
  return `${scheme}://${normalizedDomain}${path}`;
}

async function clearCookiesForCurrentSite(
  context: ActionExecutionContext,
  mode: "all_current_site" | "third_party_only"
): Promise<{ removedCount: number; eligibleCount: number; failedCount: number }> {
  if (!context.pageUrl || !context.domain) {
    return { removedCount: 0, eligibleCount: 0, failedCount: 0 };
  }

  const cookies = await chrome.cookies.getAll({ url: context.pageUrl });
  let eligibleCount = 0;
  let removedCount = 0;
  let failedCount = 0;

  for (const cookie of cookies) {
    const cookieDomain = cookie.domain ?? null;
    if (mode === "third_party_only" && !isThirdPartyCookieDomain(cookieDomain, context.domain)) {
      continue;
    }

    eligibleCount += 1;
    const removalUrl = toCookieRemovalUrl(cookie);
    if (!removalUrl) {
      failedCount += 1;
      continue;
    }

    try {
      const removed = await chrome.cookies.remove({
        url: removalUrl,
        name: cookie.name,
        storeId: cookie.storeId
      });
      if (removed) {
        removedCount += 1;
      } else {
        failedCount += 1;
      }
    } catch {
      failedCount += 1;
    }
  }

  return { removedCount, eligibleCount, failedCount };
}

async function openSettingsPage(url: string): Promise<void> {
  await chrome.tabs.create({ url });
}

async function reduceThirdPartyCookies(
  context: ActionExecutionContext
): Promise<ActionHandlerResult> {
  if (!context.pageUrl || !context.domain) {
    return {
      status: "skipped",
      message: "No supported page context is available for cookie cleanup."
    };
  }

  const summary = await clearCookiesForCurrentSite(context, "third_party_only");
  if (summary.eligibleCount === 0) {
    return {
      status: "skipped",
      message: "No third-party cookies were eligible for removal on this page."
    };
  }

  if (summary.removedCount > 0) {
    return {
      status: "success",
      message: `Removed ${summary.removedCount} third-party cookie(s) for this site.`
    };
  }

  return {
    status: "failed",
    message: "Could not remove third-party cookies for this site."
  };
}

async function clearSiteStorageData(
  context: ActionExecutionContext
): Promise<ActionHandlerResult> {
  if (!context.pageUrl || !context.domain) {
    return {
      status: "skipped",
      message: "No supported page context is available for site data cleanup."
    };
  }

  const summary = await clearCookiesForCurrentSite(context, "all_current_site");
  if (summary.eligibleCount === 0) {
    return {
      status: "skipped",
      message: "No site cookies were found to clear for this page."
    };
  }

  if (summary.removedCount > 0) {
    return {
      status: "success",
      message:
        `Cleared ${summary.removedCount} site cookie(s). ` +
        "Local/session storage cleanup requires in-page permission handling and will be added next."
    };
  }

  return {
    status: "failed",
    message: "Could not clear current-site cookies."
  };
}

async function reviewTrackingPermissions(): Promise<ActionHandlerResult> {
  await openSettingsPage("chrome://settings/content/cookies");
  return {
    status: "success",
    message: "Opened cookie and tracking permissions settings."
  };
}

async function hardenNetworkPrivacy(): Promise<ActionHandlerResult> {
  await openSettingsPage("chrome://settings/security");
  return {
    status: "success",
    message: "Opened browser security settings for network privacy hardening."
  };
}

function manualGuidanceResult(title: string): ActionHandlerResult {
  return {
    status: "skipped",
    message: `${title} currently requires manual user action. Guided prompts will be added in the next step.`
  };
}

export const improvePrivacyActionHandlers: Record<
  RecommendationActionId,
  (context: ActionExecutionContext) => Promise<ActionHandlerResult> | ActionHandlerResult
> = {
  reduce_third_party_cookies: reduceThirdPartyCookies,
  limit_third_party_scripts: () => manualGuidanceResult("Limiting third-party scripts"),
  clear_site_storage_data: clearSiteStorageData,
  block_known_trackers: () => manualGuidanceResult("Blocking known trackers"),
  review_tracking_permissions: reviewTrackingPermissions,
  harden_network_privacy: hardenNetworkPrivacy
};

export function createDefaultImprovePrivacyActionRegistry(): ImprovePrivacyActionHandlerRegistry {
  return improvePrivacyActionHandlers;
}
