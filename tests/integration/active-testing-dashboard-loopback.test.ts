import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock(
  "../../packages/active-testing/transport.js",
  () => import("../support/active-testing-loopback-transport.js"),
);

import {
  ActiveTestingActionGate,
  ActiveTestingService,
  resolveActiveTestingRuntime,
} from "../../packages/active-testing/index.js";
import {
  ControlPlaneDatabase,
  type ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  LocalActiveTestingController,
  startDashboardServer,
  type RunningDashboardServer,
} from "../../packages/dashboard/index.js";
import { DemoSaas } from "../../packages/demo-saas/index.js";
import { HackerOneMetadataActionGate } from "../../packages/external-actions/hackerone-metadata.js";
import {
  HACKERONE_METADATA_READ_CAPABILITY,
  createHackerOnePolicySnapshot,
  resolveHackerOneMetadataReadRuntime,
} from "../../packages/hackerone-readonly/index.js";
import { HackerOneMetadataStore } from "../../packages/hackerone-readonly/store.js";
import { deriveRuntimeReadiness } from "../../packages/local-runtime/index.js";
import {
  activeTestExclusion,
  activeTestProgram,
  activeTestScope,
} from "../fixtures/active-testing.factory.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
  decideTestApproval,
  setTestControlPlaneTime,
  TEST_OPERATOR_ID,
  TEST_OPERATOR_SIGNER,
} from "../fixtures/operator-auth.factory.js";
import { LoopbackActiveTestMockTransport } from "../support/active-testing-loopback-transport.js";

const RAW_COOKIE_CANARY = "dashboard-active-raw-cookie-must-not-persist";
const databases = new Set<ControlPlaneDatabase>();
const targetServers = new Set<Server>();
const dashboardServers = new Set<RunningDashboardServer>();

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
  await Promise.all([...dashboardServers].map((server) => server.close()));
  dashboardServers.clear();
  await Promise.all([...targetServers].map(closeServer));
  targetServers.clear();
  for (const database of databases) database.close();
  databases.clear();
});

describe("dashboard active-testing loopback boundary", () => {
  it("requires prepare, signed approval and explicit start for exactly one redacted local request", async () => {
    vi.stubEnv("NODE_ENV", "test");
    let targetRequests = 0;
    const target = await listenLoopback((request, response) => {
      targetRequests += 1;
      expect(request.method).toBe("HEAD");
      expect(request.url).toBe("/");
      expect(request.headers.host).toMatch(/^127\.0\.0\.1:[0-9]+$/u);
      response.statusCode = 200;
      response.setHeader("content-type", "text/html; charset=utf-8");
      response.setHeader("content-security-policy", "default-src 'none'");
      response.setHeader("strict-transport-security", "max-age=31536000");
      response.setHeader("x-content-type-options", "nosniff");
      response.setHeader(
        "set-cookie",
        `session=${RAW_COOKIE_CANARY}; Secure; HttpOnly; SameSite=Strict`,
      );
      response.end();
    });
    const harness = await startHarness(
      new LoopbackActiveTestMockTransport({ origin: loopbackOrigin(target) }),
    );
    const initial = await state(harness.server);

    expect(initial.activeTesting.capability).toMatchObject({
      available: true,
      configured: true,
      enabled: true,
      secureCoreReady: true,
      killSwitchActive: false,
      reasonCodes: [],
    });
    expect(initial.activeTesting.assetCandidates).toEqual([
      expect.objectContaining({
        programRef: harness.programRef,
        snapshotDigest: harness.snapshotDigest,
        scopeId: harness.scopeId,
        assetIdentifierDigest: harness.assetIdentifierDigest,
        supported: true,
      }),
    ]);
    expect(targetRequests).toBe(0);

    const exactPreparation = {
      programRef: harness.programRef,
      snapshotDigest: harness.snapshotDigest,
      scopeId: harness.scopeId,
      assetIdentifierDigest: harness.assetIdentifierDigest,
      testClass: "http_headers",
      confirmations: confirmations(),
    } as const;
    const freeTargetBlocked = await postJson(
      harness.server,
      "/api/active-testing/plan/prepare",
      initial.csrfToken,
      {
        ...exactPreparation,
        targetUrl: "https://caller-controlled.invalid/",
      },
    );
    expect(freeTargetBlocked.status).toBe(409);
    expect(await freeTargetBlocked.json()).toEqual({
      error: "ACTIVE_TESTING_DASHBOARD_PLAN_INVALID",
    });
    const missingConfirmationBlocked = await postJson(
      harness.server,
      "/api/active-testing/plan/prepare",
      initial.csrfToken,
      {
        ...exactPreparation,
        confirmations: {
          ...confirmations(),
          noSideEffectsConfirmed: false,
        },
      },
    );
    expect(missingConfirmationBlocked.status).toBe(409);
    expect(await missingConfirmationBlocked.json()).toEqual({
      error: "ACTIVE_TESTING_DASHBOARD_PLAN_INVALID",
    });
    expect(harness.gate.listPlans()).toEqual([]);
    expect(targetRequests).toBe(0);

    const preparedResponse = await postJson(
      harness.server,
      "/api/active-testing/plan/prepare",
      initial.csrfToken,
      exactPreparation,
    );
    expect(preparedResponse.status, await preparedResponse.clone().text()).toBe(
      201,
    );
    const prepared = (await preparedResponse.json()) as PreparedResponse;
    expect(prepared).toMatchObject({
      requestPerformed: false,
    });
    expect(prepared.planId).toMatch(/^active-plan-[a-f0-9]{32}$/u);
    expect(prepared.approvalId).toMatch(/^active-approval-[a-f0-9]{32}$/u);
    expect(prepared.planDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(targetRequests).toBe(0);

    const prematureStart = await postJson(
      harness.server,
      "/api/active-testing/execution/start",
      initial.csrfToken,
      planAction(prepared),
    );
    expect(prematureStart.status).toBe(409);
    expect(await prematureStart.json()).toEqual({
      error: "ACTIVE_TESTING_APPROVAL_NOT_CURRENT",
    });
    const malformedApproval = await postJson(
      harness.server,
      "/api/active-testing/plan/approve",
      initial.csrfToken,
      { ...planAction(prepared), confirmed: false },
    );
    expect(malformedApproval.status).toBe(409);
    expect(await malformedApproval.json()).toEqual({
      error: "ACTIVE_TESTING_DASHBOARD_ACTION_INVALID",
    });
    expect(targetRequests).toBe(0);

    const approvalResponse = await postJson(
      harness.server,
      "/api/active-testing/plan/approve",
      initial.csrfToken,
      planAction(prepared),
    );
    expect(approvalResponse.status, await approvalResponse.clone().text()).toBe(
      200,
    );
    expect(await approvalResponse.json()).toEqual({
      planId: prepared.planId,
      approvalId: prepared.approvalId,
      approved: true,
      requestPerformed: false,
    });
    const activeApproval = harness.store
      .listApprovals()
      .find(({ id }) => id === prepared.approvalId);
    expect(activeApproval).toMatchObject({
      id: prepared.approvalId,
      status: "accepted",
      decidedBy: TEST_OPERATOR_ID,
      userAction: `explicit_active_test_plan_approval:${prepared.planId}`,
      revision: 1,
    });
    expect(
      harness.database.get(
        `SELECT count(*) AS count FROM signed_approval_decisions
         WHERE approval_id=?`,
        prepared.approvalId,
      ),
    ).toEqual({ count: 1 });
    expect(targetRequests).toBe(0);

    const approvalReplay = await postJson(
      harness.server,
      "/api/active-testing/plan/approve",
      initial.csrfToken,
      planAction(prepared),
    );
    expect(approvalReplay.status).toBe(409);
    expect(await approvalReplay.json()).toEqual({
      error: "ACTIVE_TESTING_APPROVAL_NOT_CURRENT",
    });
    expect(targetRequests).toBe(0);

    const startResponse = await postJson(
      harness.server,
      "/api/active-testing/execution/start",
      initial.csrfToken,
      planAction(prepared),
    );
    expect(startResponse.status, await startResponse.clone().text()).toBe(200);
    const completed = (await startResponse.json()) as CompletionResponse;
    expect(completed).toMatchObject({
      completed: true,
      planId: prepared.planId,
      reviewStatus: "local_draft_unsubmitted",
      externalSubmissionPerformed: false,
    });
    expect(completed.observationDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(completed.reportId).toMatch(/^active-report-[a-f0-9]{64}$/u);
    expect(targetRequests).toBe(1);

    expect(harness.gate.listAttempts()).toEqual([
      expect.objectContaining({
        approvalId: prepared.approvalId,
        planId: prepared.planId,
        method: "HEAD",
        status: "succeeded",
        revision: 2,
      }),
    ]);
    expect(harness.gate.listReportSummaries()).toEqual([
      expect.objectContaining({
        reportId: completed.reportId,
        planId: prepared.planId,
        observationDigest: completed.observationDigest,
        reviewStatus: "local_draft_unsubmitted",
        externalSubmissionPerformed: false,
      }),
    ]);

    const observationRow = harness.database.get(
      `SELECT observation_json FROM active_test_observations
       WHERE plan_id=?`,
      prepared.planId,
    );
    const reportRow = harness.database.get(
      `SELECT report_json,review_status,external_submission_performed
       FROM active_test_reports WHERE plan_id=?`,
      prepared.planId,
    );
    expect(observationRow).toBeDefined();
    expect(reportRow).toMatchObject({
      review_status: "local_draft_unsubmitted",
      external_submission_performed: 0,
    });
    const observationJson = requiredText(observationRow, "observation_json");
    const reportJson = requiredText(reportRow, "report_json");
    expect(observationJson).not.toContain(RAW_COOKIE_CANARY);
    expect(reportJson).not.toContain(RAW_COOKIE_CANARY);
    expect(JSON.parse(observationJson)).toMatchObject({
      planId: prepared.planId,
      rawBodyStored: false,
      rawHeadersStored: false,
      cookiesStored: false,
      redirectLocationPresent: false,
      transportKind: "loopback_test",
    });
    const persistedReport = JSON.parse(reportJson) as {
      readonly json: string;
      readonly markdown: string;
      readonly reviewStatus: string;
      readonly externalSubmissionPerformed: boolean;
      readonly transportKind: string;
    };
    expect(persistedReport).toMatchObject({
      reviewStatus: "local_draft_unsubmitted",
      externalSubmissionPerformed: false,
      transportKind: "loopback_test",
    });
    expect(persistedReport.markdown).not.toContain(RAW_COOKIE_CANARY);
    expect(JSON.parse(persistedReport.json)).toMatchObject({
      reviewStatus: "local_draft_unsubmitted",
      externalSubmissionPerformed: false,
      retention: {
        rawBodyStored: false,
        rawHeadersStored: false,
        cookiesStored: false,
      },
    });

    const afterCompletion = await state(harness.server);
    expect(afterCompletion.activeTesting.currentPlan).toBeNull();
    expect(afterCompletion.activeTesting.attempts).toEqual([
      expect.objectContaining({
        planId: prepared.planId,
        method: "HEAD",
        status: "succeeded",
      }),
    ]);
    expect(afterCompletion.activeTesting.reports).toEqual([
      expect.objectContaining({
        reportId: completed.reportId,
        planId: prepared.planId,
        reviewStatus: "local_draft_unsubmitted",
        externalSubmissionPerformed: false,
      }),
    ]);
    expect(JSON.stringify(afterCompletion)).not.toContain(RAW_COOKIE_CANARY);

    const startReplay = await postJson(
      harness.server,
      "/api/active-testing/execution/start",
      initial.csrfToken,
      planAction(prepared),
    );
    expect(startReplay.status).toBe(409);
    expect(await startReplay.json()).toEqual({
      error: "ACTIVE_TESTING_APPROVAL_NOT_CURRENT",
    });
    expect(targetRequests).toBe(1);
    expect(harness.gate.listAttempts()).toHaveLength(1);
    expect(harness.gate.listReportSummaries()).toHaveLength(1);
  });
});

interface Harness {
  readonly database: ControlPlaneDatabase;
  readonly store: ControlPlaneStore;
  readonly gate: ActiveTestingActionGate;
  readonly server: RunningDashboardServer;
  readonly programRef: string;
  readonly snapshotDigest: string;
  readonly scopeId: string;
  readonly assetIdentifierDigest: string;
}

interface DashboardState {
  readonly csrfToken: string;
  readonly activeTesting: {
    readonly capability: Readonly<Record<string, unknown>>;
    readonly assetCandidates: readonly Readonly<Record<string, unknown>>[];
    readonly currentPlan: unknown;
    readonly attempts: readonly Readonly<Record<string, unknown>>[];
    readonly reports: readonly Readonly<Record<string, unknown>>[];
  };
}

interface PreparedResponse {
  readonly planId: string;
  readonly planDigest: string;
  readonly approvalId: string;
  readonly requestPerformed: false;
}

interface CompletionResponse {
  readonly completed: true;
  readonly planId: string;
  readonly observationDigest: string;
  readonly reportId: string;
  readonly reviewStatus: "local_draft_unsubmitted";
  readonly externalSubmissionPerformed: false;
}

async function startHarness(
  transport: LoopbackActiveTestMockTransport,
): Promise<Harness> {
  const nowValue = new Date().toISOString();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(nowValue));
  const activationAt = new Date(Date.parse(nowValue) - 1).toISOString();
  const now = (): Date => new Date(nowValue);
  const database = ControlPlaneDatabase.memory();
  databases.add(database);
  const store = createTestControlPlaneStore(database, activationAt);
  clearTestKillSwitch(store, activationAt, "dashboard_active_test_clear");

  const metadata = new HackerOneMetadataStore(database);
  const metadataGate = new HackerOneMetadataActionGate(
    database,
    store,
    resolveHackerOneMetadataReadRuntime({
      version: 1,
      capability: HACKERONE_METADATA_READ_CAPABILITY,
      external_integrations_enabled: true,
      enabled: true,
      request_budget: {
        max_requests_total: 1,
        requests_per_minute: 1,
        max_concurrency: 1,
      },
    }),
  );
  const activation = metadataGate.prepareActivationApproval({
    approvalId: "h1-dashboard-active-adapter-activation",
    operatorId: TEST_OPERATOR_ID,
    credentialFingerprint: "a3".repeat(32),
    createdAt: activationAt,
  });
  decideTestApproval(store, {
    approvalId: activation.id,
    decision: "accepted",
    userAction: "explicit_dashboard_active_adapter_activation",
    issuedAt: activationAt,
  });
  setTestControlPlaneTime(store, nowValue);
  const program = activeTestProgram({
    synchronizedAt: nowValue,
    updatedAt: nowValue,
  });
  const scope = activeTestScope({ createdAt: nowValue, updatedAt: nowValue });
  const snapshot = createHackerOnePolicySnapshot({
    program,
    structuredScopes: [scope],
    scopeExclusions: [
      activeTestExclusion({ createdAt: nowValue, updatedAt: nowValue }),
    ],
    fetchedAt: nowValue,
    previousSnapshotDigest: null,
  });
  const stored = metadata.replaceAuthenticatedApiCatalog(
    [program],
    nowValue,
  )[0];
  if (stored === undefined) throw new Error("TEST_PROGRAM_REQUIRED");
  metadata.commitSelectedProgramSynchronization(stored.localRef, snapshot, {
    expectedRevision: metadata.getIntegrationState().revision,
    occurredAt: nowValue,
    result: "succeeded",
    errorCode: null,
  });

  const acceptance = metadataGate.preparePolicyAcceptanceApproval({
    approvalId: "h1-policy-dashboard-active-loopback",
    operatorId: TEST_OPERATOR_ID,
    programLocalRef: stored.localRef,
    snapshotDigest: snapshot.snapshotDigest,
    createdAt: nowValue,
  });
  decideTestApproval(store, {
    approvalId: acceptance.id,
    decision: "accepted",
    userAction: "explicit_dashboard_active_loopback_policy_acceptance",
    issuedAt: nowValue,
  });

  const runtime = resolveActiveTestingRuntime({
    version: 1,
    capability: "HACKERONE_ACTIVE_TEST",
    external_integrations_enabled: true,
    enabled: true,
    request_budget: {
      max_requests_total: 5,
      requests_per_minute: 2,
      max_concurrency: 1,
    },
    request_timeout_ms: 5_000,
    max_response_bytes: 16_384,
  });
  const gate = new ActiveTestingActionGate(database, store, runtime);
  const service = new ActiveTestingService(metadata, gate, transport);
  const activeTesting = new LocalActiveTestingController({
    service,
    gate,
    runtime,
  });
  try {
    const server = await startDashboardServer(
      {
        store,
        demo: new DemoSaas(now),
        readiness: deriveRuntimeReadiness({
          platform: "darwin",
          eventKeyMinimumVersion: "1",
          operatorKeyReference: "keychain://test/local-operator-ed25519-v1",
          operatorId: TEST_OPERATOR_ID,
          operatorKeyRevision: "1",
          secretStoreProbe: "available",
          demoSaasReady: true,
          databaseReady: true,
        }),
        operatorSigner: TEST_OPERATOR_SIGNER,
        activeTesting,
        now,
      },
      0,
    );
    dashboardServers.add(server);
    return Object.freeze({
      database,
      store,
      gate,
      server,
      programRef: stored.localRef,
      snapshotDigest: snapshot.snapshotDigest,
      scopeId: scope.id,
      assetIdentifierDigest: scope.assetIdentifierDigest,
    });
  } catch (error) {
    database.close();
    databases.delete(database);
    throw error;
  }
}

function confirmations() {
  return Object.freeze({
    automationPermissionReviewed: true as const,
    scopeInstructionReviewed: true as const,
    scopeExclusionsReviewed: true as const,
    noSideEffectsConfirmed: true as const,
  });
}

function planAction(prepared: PreparedResponse): {
  readonly approvalId: string;
  readonly confirmed: true;
  readonly planId: string;
} {
  return Object.freeze({
    approvalId: prepared.approvalId,
    confirmed: true as const,
    planId: prepared.planId,
  });
}

async function state(server: RunningDashboardServer): Promise<DashboardState> {
  const response = await fetch(`${server.origin}/api/state`);
  expect(response.status, await response.clone().text()).toBe(200);
  return (await response.json()) as DashboardState;
}

function postJson(
  server: RunningDashboardServer,
  path: string,
  csrfToken: string,
  body: unknown,
): Promise<Response> {
  return fetch(`${server.origin}${path}`, {
    method: "POST",
    headers: {
      origin: server.origin,
      "content-type": "application/json",
      "x-csrf-token": csrfToken,
    },
    body: JSON.stringify(body),
  });
}

async function listenLoopback(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<Server> {
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  targetServers.add(server);
  return server;
}

function loopbackOrigin(server: Server): string {
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("TEST_LOOPBACK_ADDRESS_REQUIRED");
  const info: AddressInfo = address;
  return `http://127.0.0.1:${info.port}`;
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
  });
}

function requiredText(
  row: Readonly<Record<string, unknown>> | undefined,
  key: string,
): string {
  const value = row?.[key];
  if (typeof value !== "string") throw new Error("TEST_DATABASE_TEXT_REQUIRED");
  return value;
}
