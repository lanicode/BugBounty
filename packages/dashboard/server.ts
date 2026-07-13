import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { parseDocument } from "yaml";
import { diffPolicies } from "../control-plane/policy.js";
import { parseProgramImport } from "../control-plane/program-import.js";
import type {
  ControlPlaneStore,
  StoredPolicyVersion,
} from "../control-plane/store.js";
import type { DemoSaas } from "../demo-saas/domain.js";
import type {
  HumanSimulationEvidence,
  SimulationOrchestrator,
  SimulationSummary,
} from "../simulation/orchestrator.js";
import { errorCode, SecurityError } from "../shared/errors.js";
import {
  DASHBOARD_CSS,
  DASHBOARD_HTML,
  DASHBOARD_JAVASCRIPT,
} from "./assets.js";

const LOOPBACK_HOST = "127.0.0.1";
const MAX_BODY_BYTES = 65_536;
const ACTOR = /^[A-Za-z0-9._@-]{1,128}$/u;
const SECURITY_HEADERS = Object.freeze({
  "cache-control": "no-store",
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; worker-src 'none'",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy":
    "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
});

const CONFIRMATION_KEYS = Object.freeze([
  "acceptPolicyV1",
  "acceptPolicyV2",
  "approveCampaignV1",
  "approveCampaignV2",
  "clearKillSwitch",
  "queueReportReview",
]);

export interface DashboardDependencies {
  readonly store: ControlPlaneStore;
  readonly demo: DemoSaas;
  readonly simulation: SimulationOrchestrator;
  readonly now?: () => Date;
}

export interface RunningDashboardServer {
  readonly host: "127.0.0.1";
  readonly port: number;
  readonly origin: string;
  close(): Promise<void>;
}

export async function startDashboardServer(
  dependencies: DashboardDependencies,
  port = 0,
): Promise<RunningDashboardServer> {
  if (!Number.isInteger(port) || port < 0 || port > 65_535)
    throw new Error("DASHBOARD_PORT_INVALID");
  const now = dependencies.now ?? (() => new Date());
  const csrfToken = randomBytes(32).toString("base64url");
  const binding: { expectedHost?: string; origin?: string } = {};
  let lastSimulation: SimulationSummary | undefined;
  let simulationRunning = false;

  const server = createServer(
    {
      headersTimeout: 5_000,
      keepAliveTimeout: 1_000,
      maxHeaderSize: 16_384,
      requestTimeout: 10_000,
    },
    (request, response) => {
      void handleRequest(request, response).catch((error: unknown) => {
        if (response.headersSent) {
          response.destroy();
          return;
        }
        sendError(response, error);
      });
    },
  );

  async function handleRequest(
    request: IncomingMessage,
    response: ServerResponse,
  ): Promise<void> {
    applySecurityHeaders(response);
    const expectedHost = binding.expectedHost;
    const origin = binding.origin;
    if (request.socket.remoteAddress !== LOOPBACK_HOST)
      throw new DashboardHttpError(403, "DASHBOARD_REMOTE_ADDRESS_BLOCKED");
    if (expectedHost === undefined || request.headers.host !== expectedHost)
      throw new DashboardHttpError(403, "DASHBOARD_HOST_BLOCKED");
    if (origin === undefined)
      throw new DashboardHttpError(503, "DASHBOARD_BINDING_UNAVAILABLE");
    const pathname = parseCanonicalPath(request.url, expectedHost);

    if (request.method === "GET") {
      serveGet(response, pathname, () =>
        buildDashboardState(
          dependencies,
          csrfToken,
          timestamp(now),
          simulationRunning,
          lastSimulation,
        ),
      );
      return;
    }
    if (request.method !== "POST") {
      response.setHeader("allow", "GET, POST");
      throw new DashboardHttpError(405, "DASHBOARD_METHOD_BLOCKED");
    }
    assertMutationHeaders(request, origin, csrfToken);
    if (!isPostRoute(pathname))
      throw new DashboardHttpError(404, "DASHBOARD_ROUTE_NOT_FOUND");
    const body = await readJsonBody(request);

    switch (pathname) {
      case "/api/programs/import": {
        const imported = parseImportRequest(body);
        const program = dependencies.store.createProgram(
          parseProgramImport(imported.source, imported.format),
          timestamp(now),
        );
        sendJson(response, 201, { program });
        return;
      }
      case "/api/simulation/run": {
        if (simulationRunning)
          throw new DashboardHttpError(409, "SIMULATION_ALREADY_RUNNING");
        const evidence = parseSimulationRequest(body, timestamp(now));
        simulationRunning = true;
        try {
          lastSimulation = await dependencies.simulation.run(evidence);
          sendJson(response, 200, lastSimulation);
        } finally {
          simulationRunning = false;
        }
        return;
      }
      case "/api/kill-switch/engage":
      case "/api/kill-switch/clear": {
        const input = parseKillSwitchRequest(body);
        const result = dependencies.store.setKillSwitch(
          pathname.endsWith("/engage"),
          input.actor,
          timestamp(now),
        );
        sendJson(response, 200, result);
        return;
      }
    }
  }

  server.on("upgrade", (_request, socket) => {
    socket.destroy();
  });
  server.on("clientError", (_error, socket) => {
    socket.destroy();
  });

  await listen(server, port);
  const address = server.address();
  if (!isLoopbackAddress(address)) {
    await closeServer(server);
    throw new Error("DASHBOARD_BIND_INVALID");
  }
  binding.expectedHost = `${LOOPBACK_HOST}:${address.port}`;
  binding.origin = `http://${binding.expectedHost}`;
  let closePromise: Promise<void> | undefined;

  return Object.freeze({
    host: LOOPBACK_HOST,
    port: address.port,
    origin: binding.origin,
    close: () => {
      closePromise ??= closeServer(server);
      return closePromise;
    },
  });
}

function serveGet(
  response: ServerResponse,
  pathname: string,
  state: () => unknown,
): void {
  switch (pathname) {
    case "/":
      sendText(response, 200, "text/html; charset=utf-8", DASHBOARD_HTML);
      return;
    case "/app.js":
      sendText(
        response,
        200,
        "text/javascript; charset=utf-8",
        DASHBOARD_JAVASCRIPT,
      );
      return;
    case "/styles.css":
      sendText(response, 200, "text/css; charset=utf-8", DASHBOARD_CSS);
      return;
    case "/api/state":
      sendJson(response, 200, state());
      return;
    case "/health":
      sendJson(response, 200, {
        status: "ok",
        mode: "simulation",
        externalIntegrationsEnabled: false,
      });
      return;
    default:
      throw new DashboardHttpError(404, "DASHBOARD_ROUTE_NOT_FOUND");
  }
}

function buildDashboardState(
  dependencies: DashboardDependencies,
  csrfToken: string,
  generatedAt: string,
  simulationRunning: boolean,
  lastSimulation: SimulationSummary | undefined,
): unknown {
  const programs = dependencies.store.listPrograms();
  const storedPolicies = programs.flatMap((program) =>
    dependencies.store.listPolicies(program.id),
  );
  const campaigns = dependencies.store.listCampaigns();
  const approvals = dependencies.store.listApprovals();
  const identities = dependencies.store.listIdentities();
  const ownedObjects = dependencies.store.listOwnedObjects();
  const reports = dependencies.store.listReportDrafts();
  const killSwitchActive = dependencies.store.isKillSwitchActive();
  const demo = dependencies.demo.snapshot();
  const policyDiffs = makePolicyDiffs(
    programs.map(({ id }) => id),
    dependencies.store,
  );
  const completed = lastSimulation !== undefined || reports.length > 0;

  return {
    version: 1,
    mode: "simulation",
    externalIntegrationsEnabled: false,
    phase1SecurityStatus: "enforced",
    simulationStatus: simulationRunning
      ? "running"
      : completed
        ? "completed"
        : "ready",
    generatedAt,
    csrfToken,
    killSwitch: { active: killSwitchActive },
    counts: {
      programs: programs.length,
      activeCampaigns: campaigns.filter(
        ({ state }) => state === "running_simulation",
      ).length,
      pausedCampaigns: campaigns.filter(({ state }) => state === "paused")
        .length,
      openApprovals: approvals.filter(({ status }) => status === "open").length,
      privacyAlerts: approvals.filter(
        ({ kind, status }) => kind === "privacy_alert" && status === "open",
      ).length,
      reportDrafts: reports.length,
      identities: identities.length,
      ownedObjects: ownedObjects.length,
      policyVersions: storedPolicies.length,
    },
    programs,
    policies: storedPolicies.map((stored) => ({
      programId: stored.programId,
      version: stored.version,
      policyHash: stored.policy.policyHash,
      acceptedBy: stored.acceptance?.acceptedBy ?? null,
      requestLimits: stored.policy.requestLimits,
      forbiddenTestClasses: stored.policy.forbiddenTestClasses,
      unclearRules: stored.policy.unclearRules,
    })),
    policyDiffs,
    campaigns: campaigns.map((campaign) => ({
      id: campaign.id,
      programId: campaign.programId,
      policyVersion: campaign.policyVersion,
      policyHash: campaign.policyHash,
      state: campaign.state,
      revision: campaign.revision,
      humanApprovedBy: campaign.humanApprovedBy,
      maxRequests: campaign.contract.maxRequests,
      requestsPerMinute: campaign.contract.requestsPerMinute,
      maxConcurrency: campaign.contract.maxConcurrency,
      killSwitchStatus: campaign.killSwitchStatus,
    })),
    approvals: approvals.map((approval) => ({
      id: approval.id,
      kind: approval.kind,
      summary: approval.summary,
      impact: approval.impact,
      status: approval.status,
      auditReference: approval.auditReference,
    })),
    identities: identities.map((identity) => ({
      id: identity.id,
      programId: identity.programId,
      role: identity.role,
      status: identity.status,
      humanActionRequired: identity.humanActionRequired,
      organizationRef: identity.organizationRef,
    })),
    ownedObjects: ownedObjects.map((object) => ({
      objectRef: object.objectRef,
      programId: object.programId,
      campaignId: object.campaignId,
      accountId: object.accountId,
      tenantRef: object.tenantRef,
      objectType: object.objectType,
      status: object.status,
      allowedActions: object.allowedActions,
      expiresAt: object.expiresAt,
    })),
    reports: reports.map((report) => ({
      id: report.id,
      campaignId: report.campaignId,
      title: report.title,
      summary: report.summary,
      status: report.status,
      externalSubmissionPerformed: false,
    })),
    expert: {
      policyDecisions:
        programs.length === 0
          ? ["Keine Policy-Entscheidungen vorhanden."]
          : programs.map(
              (program) =>
                `${program.id}: ${program.ruleAcceptanceStatus}; Hash ${program.currentPolicyHash ?? "nicht gesetzt"}`,
            ),
      auditLog:
        approvals.length === 0
          ? ["Bodyfreies Control-Plane-Audit aktiv; noch keine Freigaben."]
          : approvals.map(
              (approval) =>
                `${approval.auditReference}: ${approval.kind} / ${approval.status}`,
            ),
      requestBudgets:
        campaigns.length === 0
          ? ["Keine Kampagnenbudgets vorhanden."]
          : campaigns.map(
              (campaign) =>
                `${campaign.id}: ${String(campaign.contract.maxRequests)} gesamt, ${String(campaign.contract.requestsPerMinute)}/min, Parallelität ${String(campaign.contract.maxConcurrency)}`,
            ),
      ownershipLedger: [
        `${String(ownedObjects.length)} kontrollierte Objektreferenzen`,
        "Unbekannte Objekt-IDs werden blockiert.",
        "Canaries erscheinen im Dashboard ausschließlich als geschützte Ledger-Metadaten.",
      ],
      adapterStatus: [
        "MockPlatformAdapter: lokal verfügbar",
        "Demo-SaaS: " + demo.organization.organizationRef,
        "HackerOne/Bugcrowd: deaktiviert und nicht implementiert",
      ],
      eventStore: [
        "Eventdaten: ausschließlich AES-256-GCM-verschlüsselt",
        "Roh-HAR und unredigierte Responses: deaktiviert",
      ],
      configurationDiagnosis: [
        "external_integrations_enabled: false",
        "Netzwerkzielklasse: ausschließlich 127.0.0.1",
        `Globaler Kill Switch: ${killSwitchActive ? "aktiv" : "freigegeben"}`,
        "Fehlerzustände werden fail-closed behandelt.",
      ],
    },
  };
}

function makePolicyDiffs(
  programIds: readonly string[],
  store: ControlPlaneStore,
): readonly unknown[] {
  return programIds.flatMap((programId) => {
    const policies = store.listPolicies(programId);
    const records: unknown[] = [];
    for (let index = 1; index < policies.length; index += 1) {
      const before = requirePolicy(policies[index - 1]);
      const after = requirePolicy(policies[index]);
      const diff = diffPolicies(before.policy, after.policy);
      records.push({
        programId,
        fromVersion: before.version,
        toVersion: after.version,
        addedAssets: diff.addedAssets,
        removedAssets: diff.removedAssets,
        newlyForbiddenTestClasses: diff.newlyForbiddenTestClasses,
        newlyAllowedTestClasses: diff.newlyAllowedTestClasses,
        changedRequestLimits: diff.changedRequestLimits.map(
          ({ field, before: previous, after: next }) =>
            `${field}: ${String(previous)} → ${String(next)}`,
        ),
        unclearRules: diff.unclearRules.current,
      });
    }
    return records;
  });
}

function requirePolicy(
  value: StoredPolicyVersion | undefined,
): StoredPolicyVersion {
  if (value === undefined) throw new SecurityError("DASHBOARD_POLICY_MISSING");
  return value;
}

function parseCanonicalPath(rawUrl: string | undefined, host: string): string {
  if (
    rawUrl === undefined ||
    !rawUrl.startsWith("/") ||
    rawUrl.startsWith("//")
  )
    throw new DashboardHttpError(400, "DASHBOARD_URL_INVALID");
  let url: URL;
  try {
    url = new URL(rawUrl, `http://${host}`);
  } catch {
    throw new DashboardHttpError(400, "DASHBOARD_URL_INVALID");
  }
  if (url.search !== "" || url.hash !== "" || url.pathname !== rawUrl)
    throw new DashboardHttpError(404, "DASHBOARD_ROUTE_NOT_FOUND");
  return url.pathname;
}

function isPostRoute(pathname: string): boolean {
  return (
    pathname === "/api/programs/import" ||
    pathname === "/api/simulation/run" ||
    pathname === "/api/kill-switch/engage" ||
    pathname === "/api/kill-switch/clear"
  );
}

function assertMutationHeaders(
  request: IncomingMessage,
  origin: string,
  csrfToken: string,
): void {
  if (request.headers.origin !== origin)
    throw new DashboardHttpError(403, "DASHBOARD_ORIGIN_BLOCKED");
  const supplied = request.headers["x-csrf-token"];
  if (typeof supplied !== "string" || !safeEqual(supplied, csrfToken))
    throw new DashboardHttpError(403, "DASHBOARD_CSRF_BLOCKED");
  const contentType = request.headers["content-type"];
  if (
    typeof contentType !== "string" ||
    contentType.split(";", 1)[0]?.trim().toLowerCase() !== "application/json"
  )
    throw new DashboardHttpError(415, "DASHBOARD_CONTENT_TYPE_BLOCKED");
  const length = request.headers["content-length"];
  if (length !== undefined) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(length))
      throw new DashboardHttpError(400, "DASHBOARD_CONTENT_LENGTH_INVALID");
    if (Number(length) > MAX_BODY_BYTES)
      throw new DashboardHttpError(413, "DASHBOARD_BODY_TOO_LARGE");
  }
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.byteLength === rightBytes.byteLength &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function readJsonBody(request: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    const cleanup = (): void => {
      request.off("data", onData);
      request.off("end", onEnd);
      request.off("error", onError);
      request.off("aborted", onAborted);
    };
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onData = (chunk: unknown): void => {
      if (settled) return;
      if (!Buffer.isBuffer(chunk)) {
        fail(new DashboardHttpError(400, "DASHBOARD_BODY_INVALID"));
        return;
      }
      bytes += chunk.byteLength;
      if (bytes > MAX_BODY_BYTES) {
        fail(new DashboardHttpError(413, "DASHBOARD_BODY_TOO_LARGE"));
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      try {
        const source = new TextDecoder("utf-8", { fatal: true }).decode(
          Buffer.concat(chunks),
        );
        const document = parseDocument(source, {
          merge: false,
          uniqueKeys: true,
          version: "1.2",
        });
        if (document.errors.length > 0 || document.warnings.length > 0)
          throw new Error("DASHBOARD_JSON_AMBIGUOUS");
        resolve(JSON.parse(source) as unknown);
      } catch {
        reject(new DashboardHttpError(400, "DASHBOARD_JSON_INVALID"));
      }
    };
    const onError = (): void => {
      fail(new DashboardHttpError(400, "DASHBOARD_BODY_READ_FAILED"));
    };
    const onAborted = (): void => {
      fail(new DashboardHttpError(400, "DASHBOARD_BODY_ABORTED"));
    };
    request.on("data", onData);
    request.once("end", onEnd);
    request.once("error", onError);
    request.once("aborted", onAborted);
  });
}

function parseImportRequest(value: unknown): {
  readonly format: "json" | "yaml";
  readonly source: string;
} {
  assertExactObject(value, ["format", "source"], "DASHBOARD_IMPORT_INVALID");
  const format = value["format"];
  const source = value["source"];
  if ((format !== "json" && format !== "yaml") || typeof source !== "string")
    throw new SecurityError("DASHBOARD_IMPORT_INVALID");
  return Object.freeze({ format, source });
}

function parseSimulationRequest(
  value: unknown,
  confirmedAt: string,
): HumanSimulationEvidence {
  assertExactObject(
    value,
    ["actor", "confirmations"],
    "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
  );
  const actor = value["actor"];
  const confirmations = value["confirmations"];
  if (typeof actor !== "string" || !ACTOR.test(actor))
    throw new SecurityError("DASHBOARD_SIMULATION_ACTOR_INVALID");
  assertExactObject(
    confirmations,
    CONFIRMATION_KEYS,
    "DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID",
  );
  if (CONFIRMATION_KEYS.some((key) => confirmations[key] !== true))
    throw new SecurityError("DASHBOARD_SIMULATION_CONFIRMATIONS_INVALID");
  return Object.freeze({
    version: 1,
    actor,
    confirmedAt,
    confirmations: Object.freeze({
      clearKillSwitch: true,
      acceptPolicyV1: true,
      approveCampaignV1: true,
      acceptPolicyV2: true,
      approveCampaignV2: true,
      queueReportReview: true,
    }),
  });
}

function parseKillSwitchRequest(value: unknown): { readonly actor: string } {
  assertExactObject(
    value,
    ["actor", "confirmed"],
    "DASHBOARD_KILL_SWITCH_CONFIRMATION_INVALID",
  );
  const actor = value["actor"];
  if (
    value["confirmed"] !== true ||
    typeof actor !== "string" ||
    !ACTOR.test(actor)
  )
    throw new SecurityError("DASHBOARD_KILL_SWITCH_CONFIRMATION_INVALID");
  return Object.freeze({ actor });
}

function assertExactObject(
  value: unknown,
  expectedKeys: readonly string[],
  code: string,
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new SecurityError(code);
  const keys = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  )
    throw new SecurityError(code);
}

function timestamp(now: () => Date): string {
  const value = now();
  if (!Number.isFinite(value.getTime()))
    throw new SecurityError("DASHBOARD_CLOCK_INVALID");
  return value.toISOString();
}

function applySecurityHeaders(response: ServerResponse): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS))
    response.setHeader(name, value);
}

function sendJson(
  response: ServerResponse,
  statusCode: number,
  value: unknown,
): void {
  sendText(
    response,
    statusCode,
    "application/json; charset=utf-8",
    JSON.stringify(value),
  );
}

function sendError(response: ServerResponse, error: unknown): void {
  if (error instanceof DashboardHttpError) {
    sendJson(response, error.statusCode, { error: error.code });
    return;
  }
  if (error instanceof SecurityError) {
    sendJson(response, 409, { error: error.code });
    return;
  }
  sendJson(response, 500, { error: errorCode(error) });
}

function sendText(
  response: ServerResponse,
  statusCode: number,
  contentType: string,
  body: string,
): void {
  response.statusCode = statusCode;
  response.setHeader("connection", "close");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.setHeader("content-type", contentType);
  response.end(body);
}

function isLoopbackAddress(
  address: string | AddressInfo | null,
): address is AddressInfo {
  return (
    address !== null &&
    typeof address !== "string" &&
    address.address === LOOPBACK_HOST &&
    address.family === "IPv4"
  );
}

function listen(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ exclusive: true, host: LOOPBACK_HOST, port });
  });
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

class DashboardHttpError extends Error {
  public constructor(
    public readonly statusCode: number,
    public readonly code: string,
  ) {
    super(code);
    this.name = "DashboardHttpError";
  }
}
