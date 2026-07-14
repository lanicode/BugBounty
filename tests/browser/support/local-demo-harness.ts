import { once } from "node:events";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Browser, BrowserContext, Page, Response } from "playwright";
import type { ProgramConfig } from "../../../packages/config/types.js";
import { DemoSaas } from "../../../packages/demo-saas/domain.js";
import {
  startDemoSaasServer,
  type RunningDemoSaasServer,
} from "../../../packages/demo-saas/server.js";
import { createGuardedContext } from "../../../packages/egress-guard/playwright.js";
import { canonicalJson, sha256 } from "../../../packages/shared/canonical.js";
import { validateDemoResponse } from "./demo-response.js";
import {
  assertLoopbackOrigin,
  finalizeJourneyEvidence,
  isAllowedJourneyRequest,
  journeyPlan,
  type JourneyEvidence,
  type JourneyPath,
  type JourneyRole,
  type JourneyStepEvidence,
} from "./journey-model.js";
import {
  buildOpaqueScreenshotOverlay,
  digestRedactedScreenshot,
  REDACTED_SCREENSHOT_HEIGHT,
  REDACTED_SCREENSHOT_WIDTH,
  type JourneyState as ScreenshotJourneyState,
  type RedactedScreenshotDigest,
} from "./redacted-screenshot.js";

const FIXED_TIME = "2026-07-13T12:00:00.000Z";
const MAX_JOURNEY_MILLISECONDS = 15_000;
const MAX_RESPONSE_BYTES = 65_536;
const EXPECTED_CONTENT_TYPE = "application/json; charset=utf-8";
const EXPECTED_CSP =
  "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const EXPECTED_PERMISSIONS_POLICY = "camera=(), geolocation=(), microphone=()";

const SCREENSHOT_STATE: Readonly<Record<JourneyPath, ScreenshotJourneyState>> =
  Object.freeze({
    "/": "service",
    "/api/v1/organization": "organization",
    "/api/v1/projects": "projects",
    "/api/v1/documents": "documents",
    "/api/v1/invitations": "invitations",
    "/api/v1/test-objects": "test_objects",
    "/api/v1/policy": "policy",
    "/api/v1/state": "state",
  });

export interface BlockedLoopbackProbe {
  readonly blockedRequestCount: 1;
  readonly blockedServerHits: 0;
}

export async function runLocalDemoJourney(
  browser: Browser,
  role: JourneyRole,
): Promise<JourneyEvidence> {
  const demo = new DemoSaas(() => new Date(FIXED_TIME));
  const initialSnapshotDigest = sha256(canonicalJson(demo.snapshot()));
  const initialRevision = demo.snapshot().revision;
  const server = await startDemoSaasServer(demo, 0);
  let context: BrowserContext | undefined;
  try {
    const origin = assertLoopbackOrigin(server.origin);
    const plan = journeyPlan(role);
    context = await createGuardedContext(
      browser,
      localJourneyPolicy(server),
      fixedContextOptions(),
    );
    let currentIndex = -1;
    let blockedRequestCount = 0;
    let observedRequestCount = 0;
    await context.route("**/*", async (route) => {
      const request = route.request();
      if (
        !isAllowedJourneyRequest(
          role,
          currentIndex,
          request.url(),
          request.method(),
          origin,
        )
      ) {
        blockedRequestCount += 1;
        await route.abort("blockedbyclient");
        return;
      }
      await route.fallback();
    });

    const page = await context.newPage();
    const failures: string[] = [];
    context.on("page", (candidate) => {
      if (candidate !== page) failures.push("UNEXPECTED_PAGE");
    });
    page.on("request", () => {
      observedRequestCount += 1;
      if (observedRequestCount > plan.length)
        failures.push("REQUEST_LIMIT_EXCEEDED");
    });
    page.on("console", (message) => {
      if (message.type() === "error") failures.push("CONSOLE_ERROR");
    });
    page.on("pageerror", () => failures.push("PAGE_ERROR"));
    page.on("dialog", (dialog) => {
      failures.push("UNEXPECTED_DIALOG");
      void dialog.dismiss().catch(() => undefined);
    });
    page.on("download", (download) => {
      failures.push("UNEXPECTED_DOWNLOAD");
      void download.cancel().catch(() => undefined);
    });
    page.setDefaultNavigationTimeout(3_000);
    page.setDefaultTimeout(3_000);

    const startedAt = Date.now();
    const stepEvidence: JourneyStepEvidence[] = [];
    for (const step of plan) {
      currentIndex = step.index;
      const response = await page.goto(`${origin}${step.path}`, {
        waitUntil: "domcontentloaded",
      });
      if (response === null) throw new Error("LOCAL_JOURNEY_RESPONSE_MISSING");
      const validated = await validateBrowserResponse(response, step.path);
      if (
        (step.path === "/" || step.path === "/api/v1/state") &&
        (!validated.simulationMode || !validated.externalIntegrationsDisabled)
      )
        throw new Error("LOCAL_JOURNEY_SAFETY_STATE_INVALID");
      if (
        step.path === "/api/v1/state" &&
        validated.revision !== initialRevision
      )
        throw new Error("LOCAL_JOURNEY_REVISION_CHANGED");

      assertPageRemainsClosed(page, context, failures);
      const screenshot = await captureOpaqueScreenshot(
        page,
        role,
        SCREENSHOT_STATE[step.path],
      );
      stepEvidence.push({
        outcome: "success",
        recordCount: validated.recordCount,
        redactedScreenshotByteLength: screenshot.byteLength,
        redactedScreenshotDigestSha256: screenshot.sha256,
        responseDigestSha256: validated.responseDigestSha256,
        statusCode: response.status(),
      });
      if (observedRequestCount !== step.index + 1)
        throw new Error("LOCAL_JOURNEY_REQUEST_SEQUENCE_INVALID");
      if (Date.now() - startedAt > MAX_JOURNEY_MILLISECONDS)
        throw new Error("LOCAL_JOURNEY_RUNTIME_LIMIT_EXCEEDED");
    }

    const finalStep = plan.at(-1);
    const finalScreenshot = stepEvidence.at(-1);
    if (finalStep === undefined || finalScreenshot === undefined)
      throw new Error("LOCAL_JOURNEY_PLAN_EMPTY");
    await page.evaluate(() => {
      document.body.textContent = "PHASE7_RAW_SCREENSHOT_SECRET_MARKER";
    });
    const redactionProbe = await captureOpaqueScreenshot(
      page,
      role,
      SCREENSHOT_STATE[finalStep.path],
    );
    if (
      redactionProbe.sha256 !==
        finalScreenshot.redactedScreenshotDigestSha256 ||
      redactionProbe.byteLength !== finalScreenshot.redactedScreenshotByteLength
    )
      throw new Error("LOCAL_JOURNEY_REDACTION_INVARIANCE_FAILED");

    assertPageRemainsClosed(page, context, failures);
    if (blockedRequestCount !== 0)
      throw new Error("LOCAL_JOURNEY_UNEXPECTED_BLOCKED_REQUEST");
    if (observedRequestCount !== plan.length)
      throw new Error("LOCAL_JOURNEY_REQUEST_COUNT_INVALID");
    if ((await context.cookies()).length !== 0)
      throw new Error("LOCAL_JOURNEY_COOKIE_STATE_INVALID");
    const storage = await page.evaluate(() => ({
      local: localStorage.length,
      session: sessionStorage.length,
    }));
    if (storage.local !== 0 || storage.session !== 0)
      throw new Error("LOCAL_JOURNEY_STORAGE_STATE_INVALID");
    if (sha256(canonicalJson(demo.snapshot())) !== initialSnapshotDigest)
      throw new Error("LOCAL_JOURNEY_DEMO_MUTATED");

    return finalizeJourneyEvidence({
      role,
      status: "completed",
      blockedRequestCount: 0,
      steps: stepEvidence,
    });
  } finally {
    const resources: (() => Promise<void>)[] = [() => server.close()];
    if (context !== undefined) {
      const guardedContext = context;
      resources.unshift(() => guardedContext.close());
    }
    await closeAll(resources);
  }
}

export async function proveForeignLoopbackPortBlocked(
  browser: Browser,
): Promise<BlockedLoopbackProbe> {
  const demo = new DemoSaas(() => new Date(FIXED_TIME));
  const allowedServer = await startDemoSaasServer(demo, 0);
  let blockedServer:
    Awaited<ReturnType<typeof startHitCounterServer>> | undefined;
  let context: BrowserContext | undefined;
  try {
    blockedServer = await startHitCounterServer();
    const origin = assertLoopbackOrigin(allowedServer.origin);
    const blockedOrigin = assertLoopbackOrigin(blockedServer.origin);
    context = await createGuardedContext(
      browser,
      localJourneyPolicy(allowedServer),
      fixedContextOptions(),
    );
    let blockedRequestCount = 0;
    await context.route("**/*", async (route) => {
      const request = route.request();
      if (
        !isAllowedJourneyRequest(
          "External",
          0,
          request.url(),
          request.method(),
          origin,
        )
      ) {
        blockedRequestCount += 1;
        await route.abort("blockedbyclient");
        return;
      }
      await route.fallback();
    });
    const page = await context.newPage();
    await page.goto(`${origin}/`, { waitUntil: "domcontentloaded" });
    let navigationWasBlocked = false;
    try {
      await page.goto(`${blockedOrigin}/`, { waitUntil: "domcontentloaded" });
    } catch {
      navigationWasBlocked = true;
    }
    if (!navigationWasBlocked || blockedRequestCount !== 1)
      throw new Error("LOCAL_JOURNEY_FOREIGN_PORT_NOT_BLOCKED");
    if (blockedServer.hits() !== 0)
      throw new Error("LOCAL_JOURNEY_FOREIGN_PORT_REACHED");
    return Object.freeze({ blockedRequestCount: 1, blockedServerHits: 0 });
  } finally {
    const resources: (() => Promise<void>)[] = [() => allowedServer.close()];
    if (context !== undefined) {
      const guardedContext = context;
      resources.unshift(() => guardedContext.close());
    }
    if (blockedServer !== undefined) {
      const counterServer = blockedServer;
      resources.push(() => counterServer.close());
    }
    await closeAll(resources);
  }
}

async function validateBrowserResponse(
  response: Response,
  path: JourneyPath,
): Promise<ReturnType<typeof validateDemoResponse>> {
  if (response.status() !== 200)
    throw new Error("LOCAL_JOURNEY_HTTP_STATUS_INVALID");
  if (response.request().redirectedFrom() !== null)
    throw new Error("LOCAL_JOURNEY_REDIRECT_INVALID");
  const headers = response.headers();
  if (
    headers["content-type"] !== EXPECTED_CONTENT_TYPE ||
    headers["cache-control"] !== "no-store" ||
    headers["cross-origin-resource-policy"] !== "same-origin" ||
    headers["referrer-policy"] !== "no-referrer" ||
    headers["x-content-type-options"] !== "nosniff" ||
    headers["x-frame-options"] !== "DENY" ||
    headers["set-cookie"] !== undefined ||
    headers["location"] !== undefined ||
    headers["content-disposition"] !== undefined ||
    headers["content-security-policy"] !== EXPECTED_CSP ||
    headers["permissions-policy"] !== EXPECTED_PERMISSIONS_POLICY
  )
    throw new Error("LOCAL_JOURNEY_RESPONSE_HEADERS_INVALID");
  const contentLength = Number(headers["content-length"]);
  if (
    !Number.isSafeInteger(contentLength) ||
    contentLength < 2 ||
    contentLength > MAX_RESPONSE_BYTES
  )
    throw new Error("LOCAL_JOURNEY_CONTENT_LENGTH_INVALID");
  const body = await response.body();
  try {
    if (body.byteLength !== contentLength)
      throw new Error("LOCAL_JOURNEY_CONTENT_LENGTH_MISMATCH");
    return validateDemoResponse(path, body);
  } finally {
    body.fill(0);
  }
}

async function captureOpaqueScreenshot(
  page: Page,
  role: JourneyRole,
  state: ScreenshotJourneyState,
): Promise<RedactedScreenshotDigest> {
  const overlay = buildOpaqueScreenshotOverlay(role, state);
  if (overlay.role !== role || overlay.state !== state)
    throw new Error("LOCAL_JOURNEY_REDACTION_LABEL_INVALID");
  const created = await page.evaluate((label) => {
    if (
      document.querySelector('[data-local-redaction-overlay="true"]') !== null
    )
      return false;
    const section = document.createElement("section");
    section.dataset["localRedactionOverlay"] = "true";
    section.setAttribute("role", "img");
    section.setAttribute("aria-label", label);
    section.textContent = label;
    const styles: readonly (readonly [string, string])[] = [
      ["position", "fixed"],
      ["inset", "0"],
      ["z-index", "2147483647"],
      ["display", "block"],
      ["box-sizing", "border-box"],
      ["width", "100vw"],
      ["height", "100vh"],
      ["margin", "0"],
      ["padding", "0"],
      ["overflow", "hidden"],
      ["opacity", "1"],
      ["background", "rgb(16 24 32)"],
      ["color", "rgb(255 255 255)"],
      ["pointer-events", "none"],
    ];
    for (const [name, value] of styles)
      section.style.setProperty(name, value, "important");
    document.documentElement.append(section);
    return true;
  }, overlay.label);
  if (!created) throw new Error("LOCAL_JOURNEY_REDACTION_MASK_INVALID");
  const mask = page.locator('[data-local-redaction-overlay="true"]');
  try {
    if ((await mask.count()) !== 1)
      throw new Error("LOCAL_JOURNEY_REDACTION_MASK_INVALID");
    const [box, viewport, computed] = await Promise.all([
      mask.boundingBox(),
      page.evaluate(() => ({
        width: window.innerWidth,
        height: window.innerHeight,
        deviceScaleFactor: window.devicePixelRatio,
        scrollX: window.scrollX,
        scrollY: window.scrollY,
      })),
      mask.evaluate((element) => {
        const style = getComputedStyle(element);
        return {
          position: style.position,
          opacity: style.opacity,
          visibility: style.visibility,
          zIndex: style.zIndex,
        };
      }),
    ]);
    if (
      box === null ||
      viewport.width !== REDACTED_SCREENSHOT_WIDTH ||
      viewport.height !== REDACTED_SCREENSHOT_HEIGHT ||
      viewport.deviceScaleFactor !== 1 ||
      viewport.scrollX !== 0 ||
      viewport.scrollY !== 0 ||
      box.x !== 0 ||
      box.y !== 0 ||
      box.width !== REDACTED_SCREENSHOT_WIDTH ||
      box.height !== REDACTED_SCREENSHOT_HEIGHT ||
      computed.position !== "fixed" ||
      computed.opacity !== "1" ||
      computed.visibility !== "visible" ||
      computed.zIndex !== "2147483647"
    )
      throw new Error("LOCAL_JOURNEY_REDACTION_MASK_INVALID");
    const png = await page.screenshot({
      type: "png",
      animations: "disabled",
      caret: "hide",
      fullPage: false,
      scale: "css",
      mask: [mask],
      maskColor: overlay.maskColor,
    });
    return digestRedactedScreenshot(png);
  } finally {
    await page.evaluate(() => {
      document.querySelector('[data-local-redaction-overlay="true"]')?.remove();
    });
  }
}

function assertPageRemainsClosed(
  page: Page,
  context: BrowserContext,
  failures: readonly string[],
): void {
  if (
    failures.length !== 0 ||
    context.pages().length !== 1 ||
    context.pages()[0] !== page ||
    page.frames().length !== 1
  )
    throw new Error("LOCAL_JOURNEY_BROWSER_BOUNDARY_VIOLATION");
}

function fixedContextOptions(): Parameters<typeof createGuardedContext>[2] {
  return {
    viewport: {
      width: REDACTED_SCREENSHOT_WIDTH,
      height: REDACTED_SCREENSHOT_HEIGHT,
    },
    deviceScaleFactor: 1,
    locale: "de-DE",
    timezoneId: "UTC",
    colorScheme: "light",
    reducedMotion: "reduce",
    javaScriptEnabled: true,
    acceptDownloads: false,
    serviceWorkers: "block",
  };
}

function localJourneyPolicy(server: RunningDemoSaasServer): {
  readonly config: ProgramConfig;
  readonly localTestMode: true;
} {
  return {
    localTestMode: true,
    config: {
      version: 2,
      program: {
        platform: "local_fixture",
        handle: "phase7-demo-saas",
        display_name: "Phase 7 local Demo SaaS",
        policy_source: "compiled-test-harness",
        policy_hash_sha256: "0".repeat(64),
        policy_accepted_at: null,
        policy_accepted_by: null,
      },
      network: {
        targets: [],
        supporting_hosts: [
          {
            scheme: "http",
            host: "127.0.0.1",
            ports: [server.port],
            allowed_methods: ["GET"],
            capture: "metadata_only",
          },
        ],
        blocked_hosts: [],
        deny_by_default: true,
        allow_plain_http: true,
        follow_redirects: false,
        block_service_workers_during_capture: true,
      },
      capture: {
        persist_unredacted_traffic: false,
        persist_response_bodies: "selective",
        allowed_body_content_types: ["application/json"],
        max_body_bytes: MAX_RESPONSE_BYTES,
        binary_handling: "hash_only",
        websocket_capture: "disabled",
        stable_pseudonyms: true,
        local_hmac_key_ref: "keychain://phase7/not-used",
        quarantine_unknown_identity_data: true,
      },
      accounts: [],
      budgets: {
        global_requests_per_minute: 8,
        max_concurrency: 1,
        max_requests_per_candidate: 8,
        max_state_changes_per_candidate: 0,
        stop_after_first_positive_signal: true,
        cool_down_seconds_after_error: 30,
        stop_statuses: [429, 503],
      },
      forbidden: ["active_testing", "external_targets"],
      policy_drift: {
        block_campaign_when_policy_hash_changes: true,
        require_new_acceptance: true,
      },
    },
  };
}

async function startHitCounterServer(): Promise<{
  readonly origin: string;
  readonly hits: () => number;
  close(): Promise<void>;
}> {
  let hitCount = 0;
  const server = createServer((_request, response) => {
    hitCount += 1;
    response.writeHead(200, {
      "cache-control": "no-store",
      "content-type": "text/plain; charset=utf-8",
    });
    response.end("loopback-only-block-probe");
  });
  server.on("upgrade", (_request, socket) => socket.destroy());
  server.listen({ host: "127.0.0.1", port: 0, exclusive: true });
  await once(server, "listening");
  const address = server.address();
  if (!isLoopbackAddress(address)) {
    await closeServer(server);
    throw new Error("LOCAL_JOURNEY_PROBE_BIND_INVALID");
  }
  return Object.freeze({
    origin: `http://127.0.0.1:${address.port}`,
    hits: () => hitCount,
    close: () => closeServer(server),
  });
}

function isLoopbackAddress(
  address: string | AddressInfo | null,
): address is AddressInfo {
  return (
    address !== null &&
    typeof address !== "string" &&
    address.address === "127.0.0.1" &&
    address.family === "IPv4"
  );
}

function closeServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
    server.closeIdleConnections();
  });
}

async function closeAll(
  resources: readonly (() => Promise<void>)[],
): Promise<void> {
  let firstFailure: unknown;
  let failed = false;
  for (const close of resources) {
    try {
      await close();
    } catch (error) {
      if (!failed) firstFailure = error;
      failed = true;
    }
  }
  if (failed) throw firstFailure;
}
