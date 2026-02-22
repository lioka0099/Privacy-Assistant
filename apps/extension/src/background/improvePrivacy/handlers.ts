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

  await openSettingsPage("chrome://settings/content/cookies");
  return {
    status: "success",
    message:
      "Automatic cookie cleanup was limited. Opened cookie settings. Steps: 1) Block third-party cookies, 2) Clear site data if needed."
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
    await openSettingsPage("chrome://settings/siteData");
    return {
      status: "success",
      message:
        "No removable cookies were found automatically. Opened site-data settings. Steps: 1) Search this domain, 2) Remove stored data."
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

  await openSettingsPage("chrome://settings/siteData");
  return {
    status: "success",
    message:
      "Automatic site-data cleanup was limited. Opened site-data settings. Steps: 1) Search this domain, 2) Remove remaining data."
  };
}

async function reviewTrackingPermissions(): Promise<ActionHandlerResult> {
  await openSettingsPage("chrome://settings/content/cookies");
  return {
    status: "success",
    message:
      "Opened cookie and tracking permission settings. Steps: 1) Block third-party cookies, 2) Review site permissions for this domain."
  };
}

async function hardenNetworkPrivacy(): Promise<ActionHandlerResult> {
  await openSettingsPage("chrome://settings/security");
  return {
    status: "success",
    message:
      "Opened security settings. Steps: 1) Use Enhanced protection, 2) Review secure DNS and privacy controls."
  };
}

async function limitThirdPartyScriptsGuided(): Promise<ActionHandlerResult> {
  await openSettingsPage("chrome://settings/content/javascript");
  return {
    status: "success",
    message:
      "Opened JavaScript settings. Steps: 1) Restrict JavaScript for high-risk sites, 2) Use per-site blocking for untrusted domains."
  };
}

async function blockKnownTrackersGuided(): Promise<ActionHandlerResult> {
  await openSettingsPage("chrome://settings/content/cookies");
  return {
    status: "success",
    message:
      "Opened Chrome cookie/tracking controls. Steps: 1) Block third-party cookies, 2) clear existing site data if needed."
  };
}

export const improvePrivacyActionHandlers: Record<
  RecommendationActionId,
  (context: ActionExecutionContext) => Promise<ActionHandlerResult> | ActionHandlerResult
> = {
  reduce_third_party_cookies: reduceThirdPartyCookies,
  limit_third_party_scripts: limitThirdPartyScriptsGuided,
  clear_site_storage_data: clearSiteStorageData,
  block_known_trackers: blockKnownTrackersGuided,
  review_tracking_permissions: reviewTrackingPermissions,
  harden_network_privacy: hardenNetworkPrivacy
};

export function createDefaultImprovePrivacyActionRegistry(): ImprovePrivacyActionHandlerRegistry {
  return improvePrivacyActionHandlers;
}
