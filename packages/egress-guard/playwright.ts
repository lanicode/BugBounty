import type {
  Browser,
  BrowserContext,
  BrowserContextOptions,
} from "playwright";
import type { EgressPolicy } from "./types.js";
import { decideEgress } from "./guard.js";
import { normalizeUrl } from "./normalize.js";

export function secureContextOptions(
  base: BrowserContextOptions = {},
): BrowserContextOptions {
  return { ...base, serviceWorkers: "block", acceptDownloads: false };
}

export async function createGuardedContext(
  browser: Browser,
  policy: EgressPolicy,
  options: BrowserContextOptions = {},
): Promise<BrowserContext> {
  const context = await browser.newContext(secureContextOptions(options));
  await context.route("**/*", async (route) => {
    const request = route.request();
    const decision = decideEgress(policy, {
      url: request.url(),
      method: request.method(),
      captureMode: captureModeFor(policy, request.url()),
      resourceKind:
        request.resourceType() === "xhr"
          ? "xhr"
          : request.resourceType() === "fetch"
            ? "fetch"
            : request.isNavigationRequest()
              ? "navigation"
              : "other",
      isRedirect: request.redirectedFrom() !== null,
    });
    if (decision.allow) await route.continue();
    else await route.abort("blockedbyclient");
  });
  await context.routeWebSocket(/.*/u, (websocket) =>
    websocket.close({ code: 1008, reason: "BLOCK_WEBSOCKET" }),
  );
  return context;
}

function captureModeFor(
  policy: EgressPolicy,
  url: string,
): "metadata_only" | "none" | "redacted" {
  try {
    const normalized = normalizeUrl(url);
    return (
      policy.config.network.supporting_hosts.find(
        (entry) =>
          entry.host === normalized.host && entry.scheme === normalized.scheme,
      )?.capture ?? "redacted"
    );
  } catch {
    return "redacted";
  }
}
