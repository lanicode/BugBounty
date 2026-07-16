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
  isTrustedActiveTestTransport,
  resolveActiveTestingRuntime,
} from "../../packages/active-testing/index.js";
import {
  ControlPlaneDatabase,
  type ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import { HackerOneMetadataActionGate } from "../../packages/external-actions/hackerone-metadata.js";
import {
  HACKERONE_METADATA_READ_CAPABILITY,
  createHackerOnePolicySnapshot,
  resolveHackerOneMetadataReadRuntime,
} from "../../packages/hackerone-readonly/index.js";
import { HackerOneMetadataStore } from "../../packages/hackerone-readonly/store.js";
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
} from "../fixtures/operator-auth.factory.js";
import { LoopbackActiveTestMockTransport } from "../support/active-testing-loopback-transport.js";

const databases = new Set<ControlPlaneDatabase>();
const servers = new Set<Server>();

afterEach(async () => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
  await Promise.all([...servers].map(closeServer));
  servers.clear();
  for (const database of databases) database.close();
  databases.clear();
});

describe("ActiveTestingService loopback integration", () => {
  it("prepares from the current store snapshot and completes one local unsubmitted report", async () => {
    vi.stubEnv("NODE_ENV", "test");
    let requests = 0;
    const server = await listenLoopback((request, response) => {
      requests += 1;
      expect(request.method).toBe("HEAD");
      expect(request.url).toBe("/");
      response.statusCode = 200;
      response.setHeader("content-type", "text/html; charset=utf-8");
      response.setHeader("content-security-policy", "default-src 'none'");
      response.setHeader("strict-transport-security", "max-age=31536000");
      response.setHeader("x-content-type-options", "nosniff");
      response.end();
    });
    const harness = readyHarness(
      new LoopbackActiveTestMockTransport({ origin: loopbackOrigin(server) }),
    );
    const preparedAt = new Date().toISOString();
    setTestControlPlaneTime(harness.controlPlane, preparedAt);
    const prepared = harness.service.preparePlanApproval({
      planId: "active-service-plan-success",
      approvalId: "active-service-approval-success",
      operatorId: TEST_OPERATOR_ID,
      programRef: harness.programRef,
      snapshotDigest: harness.snapshotDigest,
      scopeId: harness.scopeId,
      assetIdentifierDigest: harness.assetIdentifierDigest,
      testClass: "http_headers",
      createdAt: preparedAt,
      confirmations: confirmations(),
    });

    expect(prepared.plan.snapshot_digest).toBe(harness.snapshotDigest);
    expect(prepared.plan.asset_identifier_digest).toBe(
      harness.assetIdentifierDigest,
    );
    expect(requests).toBe(0);
    decideTestApproval(harness.controlPlane, {
      approvalId: prepared.approval.id,
      decision: "accepted",
      userAction: "explicit_active_service_success",
      issuedAt: preparedAt,
    });

    const completed = await harness.service.executeConfirmed({
      proposalId: "active-service-proposal-success",
      approvalId: prepared.approval.id,
      planId: prepared.plan.plan_id,
      confirmed: true,
    });

    expect(requests).toBe(1);
    expect(completed.observation.signals).toEqual([]);
    expect(completed.report).toMatchObject({
      reviewStatus: "local_draft_unsubmitted",
      externalSubmissionPerformed: false,
    });
    expect(harness.gate.listAttempts()).toEqual([
      expect.objectContaining({ status: "succeeded", revision: 2 }),
    ]);
    expect(harness.gate.listPlans()).toEqual([
      expect.objectContaining({
        approvalId: prepared.approval.id,
        planId: prepared.plan.plan_id,
        attemptStatus: "succeeded",
      }),
    ]);
    expect(harness.gate.listReportSummaries()).toEqual([
      expect.objectContaining({
        reportId: completed.report.reportId,
        planId: completed.report.planId,
        reviewStatus: "local_draft_unsubmitted",
        externalSubmissionPerformed: false,
      }),
    ]);
    expect(() =>
      harness.database.run(
        `UPDATE active_test_reports SET review_status='submitted'
         WHERE report_id=?`,
        completed.report.reportId,
      ),
    ).toThrow("ACTIVE_TEST_REPORT_IMMUTABLE");

    const trigger = requiredTriggerSql(
      harness.database,
      "active_test_reports_no_update",
    );
    const storedReport = harness.database.get(
      "SELECT report_json FROM active_test_reports WHERE report_id=?",
      completed.report.reportId,
    );
    if (typeof storedReport?.["report_json"] !== "string")
      throw new Error("TEST_REPORT_JSON_REQUIRED");
    const tamperedReport = `{"snapshotDigest":"RAW_REPORT_CANARY",${storedReport["report_json"].slice(1)}`;
    harness.database.run("DROP TRIGGER active_test_reports_no_update");
    harness.database.run(
      "UPDATE active_test_reports SET report_json=? WHERE report_id=?",
      tamperedReport,
      completed.report.reportId,
    );
    harness.database.run(trigger);
    expect(
      () =>
        new ActiveTestingActionGate(
          harness.database,
          harness.controlPlane,
          harness.runtime,
        ),
    ).toThrow("ACTIVE_TEST_REPORT_EVIDENCE_INVALID");
  });

  it("does not follow or retry a redirect and settles the reserved attempt as failed", async () => {
    vi.stubEnv("NODE_ENV", "test");
    let requests = 0;
    const server = await listenLoopback((_request, response) => {
      requests += 1;
      response.statusCode = 302;
      response.setHeader("location", "/second-request-must-not-happen");
      response.end();
    });
    const harness = readyHarness(
      new LoopbackActiveTestMockTransport({ origin: loopbackOrigin(server) }),
    );
    const preparedAt = new Date().toISOString();
    setTestControlPlaneTime(harness.controlPlane, preparedAt);
    const prepared = harness.service.preparePlanApproval({
      planId: "active-service-plan-redirect",
      approvalId: "active-service-approval-redirect",
      operatorId: TEST_OPERATOR_ID,
      programRef: harness.programRef,
      snapshotDigest: harness.snapshotDigest,
      scopeId: harness.scopeId,
      assetIdentifierDigest: harness.assetIdentifierDigest,
      testClass: "http_headers",
      createdAt: preparedAt,
      confirmations: confirmations(),
    });
    decideTestApproval(harness.controlPlane, {
      approvalId: prepared.approval.id,
      decision: "accepted",
      userAction: "explicit_active_service_redirect",
      issuedAt: preparedAt,
    });

    await expect(
      harness.service.executeConfirmed({
        proposalId: "active-service-proposal-redirect",
        approvalId: prepared.approval.id,
        planId: prepared.plan.plan_id,
        confirmed: true,
      }),
    ).rejects.toThrow("ACTIVE_TEST_REDIRECT_BLOCKED");

    expect(requests).toBe(1);
    expect(harness.gate.listAttempts()).toEqual([
      expect.objectContaining({ status: "failed", revision: 2 }),
    ]);
    expect(
      harness.database.get("SELECT count(*) AS count FROM active_test_reports"),
    ).toEqual({ count: 0 });
  });

  it("rejects transport evidence whose completion time predates request start", async () => {
    vi.stubEnv("NODE_ENV", "test");
    let rollbackAt = "";
    let requests = 0;
    const server = await listenLoopback((_request, response) => {
      requests += 1;
      vi.setSystemTime(new Date(rollbackAt));
      response.statusCode = 200;
      response.end();
    });
    const harness = readyHarness(
      new LoopbackActiveTestMockTransport({ origin: loopbackOrigin(server) }),
    );
    const preparedAt = new Date().toISOString();
    rollbackAt = new Date(Date.parse(preparedAt) - 1).toISOString();
    setTestControlPlaneTime(harness.controlPlane, preparedAt);
    const prepared = harness.service.preparePlanApproval({
      planId: "active-service-plan-chronology",
      approvalId: "active-service-approval-chronology",
      operatorId: TEST_OPERATOR_ID,
      programRef: harness.programRef,
      snapshotDigest: harness.snapshotDigest,
      scopeId: harness.scopeId,
      assetIdentifierDigest: harness.assetIdentifierDigest,
      testClass: "http_headers",
      createdAt: preparedAt,
      confirmations: confirmations(),
    });
    decideTestApproval(harness.controlPlane, {
      approvalId: prepared.approval.id,
      decision: "accepted",
      userAction: "explicit_active_service_chronology",
      issuedAt: preparedAt,
    });

    await expect(
      harness.service.executeConfirmed({
        proposalId: "active-service-proposal-chronology",
        approvalId: prepared.approval.id,
        planId: prepared.plan.plan_id,
        confirmed: true,
      }),
    ).rejects.toThrow("ACTIVE_TEST_EVIDENCE_TIME_INVALID");
    expect(requests).toBe(1);
    expect(harness.gate.listAttempts()).toEqual([
      expect.objectContaining({ status: "failed", revision: 2 }),
    ]);
    expect(
      harness.database.get(
        "SELECT count(*) AS count FROM active_test_observations",
      ),
    ).toEqual({ count: 0 });
  });

  it("brands only Vitest-owned transports with canonical literal loopback origins", () => {
    const ipv4 = new LoopbackActiveTestMockTransport({
      origin: "http://127.0.0.1:43123",
    });
    const ipv6 = new LoopbackActiveTestMockTransport({
      origin: "http://[::1]:43123",
    });
    expect(isTrustedActiveTestTransport(ipv4)).toBe(true);
    expect(isTrustedActiveTestTransport(ipv6)).toBe(true);
    for (const origin of [
      "http://localhost:43123",
      "http://127.0.0.2:43123",
      "http://[::ffff:127.0.0.1]:43123",
      "http://127.0.0.1:43123/",
      "https://127.0.0.1:43123",
      "http://127.0.0.1",
    ]) {
      expect(() => new LoopbackActiveTestMockTransport({ origin })).toThrow(
        "ACTIVE_TEST_LOOPBACK_ENDPOINT_INVALID",
      );
    }
    expect(isTrustedActiveTestTransport(ipv4)).toBe(true);
  });

  it("rejects stale browser-selected snapshot and asset digests before approval persistence", () => {
    vi.stubEnv("NODE_ENV", "test");
    const transport = new LoopbackActiveTestMockTransport({
      origin: "http://127.0.0.1:43123",
    });
    const harness = readyHarness(transport);
    const base = {
      planId: "active-service-plan-stale",
      approvalId: "active-service-approval-stale",
      operatorId: TEST_OPERATOR_ID,
      programRef: harness.programRef,
      snapshotDigest: harness.snapshotDigest,
      scopeId: harness.scopeId,
      assetIdentifierDigest: harness.assetIdentifierDigest,
      testClass: "http_headers" as const,
      createdAt: new Date().toISOString(),
      confirmations: confirmations(),
    };
    setTestControlPlaneTime(harness.controlPlane, base.createdAt);

    expect(() =>
      harness.service.preparePlanApproval({
        ...base,
        snapshotDigest: "f".repeat(64),
      }),
    ).toThrow("ACTIVE_TEST_SNAPSHOT_SELECTION_STALE");
    expect(() =>
      harness.service.preparePlanApproval({
        ...base,
        assetIdentifierDigest: "e".repeat(64),
      }),
    ).toThrow("ACTIVE_TEST_ASSET_SELECTION_STALE");
    expect(harness.controlPlane.listApprovals()).toHaveLength(2);
  });

  it.each([
    "https://synthetic-target.bounty-safe.dev/a%2Fb",
    "https://synthetic-target.bounty-safe.dev/a//b",
    "https://foo/",
    "https://foo_bar.example/",
  ])(
    "blocks unsafe exact scope %s before approval persistence or a request",
    async (assetIdentifier) => {
      vi.stubEnv("NODE_ENV", "test");
      let requests = 0;
      const server = await listenLoopback((_request, response) => {
        requests += 1;
        response.end();
      });
      const harness = readyHarness(
        new LoopbackActiveTestMockTransport({ origin: loopbackOrigin(server) }),
        assetIdentifier,
      );
      const createdAt = new Date().toISOString();
      setTestControlPlaneTime(harness.controlPlane, createdAt);

      expect(() =>
        harness.service.preparePlanApproval({
          planId: "active-service-plan-unsafe-scope",
          approvalId: "active-service-approval-unsafe-scope",
          operatorId: TEST_OPERATOR_ID,
          programRef: harness.programRef,
          snapshotDigest: harness.snapshotDigest,
          scopeId: harness.scopeId,
          assetIdentifierDigest: harness.assetIdentifierDigest,
          testClass: "http_headers",
          createdAt,
          confirmations: confirmations(),
        }),
      ).toThrow();
      expect(requests).toBe(0);
      expect(harness.gate.listAttempts()).toEqual([]);
      expect(harness.gate.listPlans()).toEqual([]);
      expect(harness.controlPlane.listApprovals()).toHaveLength(2);
    },
  );
});

interface Harness {
  readonly database: ControlPlaneDatabase;
  readonly controlPlane: ControlPlaneStore;
  readonly gate: ActiveTestingActionGate;
  readonly runtime: ReturnType<typeof resolveActiveTestingRuntime>;
  readonly service: ActiveTestingService;
  readonly programRef: string;
  readonly scopeId: string;
  readonly assetIdentifierDigest: string;
  readonly snapshotDigest: string;
}

function readyHarness(
  transport: LoopbackActiveTestMockTransport,
  assetIdentifier?: string,
): Harness {
  const initializedAt = new Date().toISOString();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(initializedAt));
  const activationAt = new Date(Date.parse(initializedAt) - 1).toISOString();
  const database = ControlPlaneDatabase.memory();
  databases.add(database);
  const controlPlane = createTestControlPlaneStore(database, activationAt);
  const metadata = new HackerOneMetadataStore(database);
  const metadataGate = new HackerOneMetadataActionGate(
    database,
    controlPlane,
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
  clearTestKillSwitch(controlPlane, activationAt);
  const activation = metadataGate.prepareActivationApproval({
    approvalId: "h1-active-service-adapter-activation",
    operatorId: TEST_OPERATOR_ID,
    credentialFingerprint: "a2".repeat(32),
    createdAt: activationAt,
  });
  decideTestApproval(controlPlane, {
    approvalId: activation.id,
    decision: "accepted",
    userAction: "explicit_active_service_adapter_activation",
    issuedAt: activationAt,
  });
  setTestControlPlaneTime(controlPlane, initializedAt);
  const scope = activeTestScope({
    ...(assetIdentifier === undefined ? {} : { assetIdentifier }),
    createdAt: initializedAt,
    updatedAt: initializedAt,
  });
  const program = activeTestProgram({
    synchronizedAt: initializedAt,
    updatedAt: initializedAt,
  });
  const snapshot = createHackerOnePolicySnapshot({
    program,
    structuredScopes: [scope],
    scopeExclusions: [
      activeTestExclusion({
        createdAt: initializedAt,
        updatedAt: initializedAt,
      }),
    ],
    fetchedAt: initializedAt,
    previousSnapshotDigest: null,
  });
  const stored = metadata.replaceAuthenticatedApiCatalog(
    [program],
    initializedAt,
  )[0];
  if (stored === undefined) throw new Error("TEST_PROGRAM_REQUIRED");
  metadata.commitSelectedProgramSynchronization(stored.localRef, snapshot, {
    expectedRevision: metadata.getIntegrationState().revision,
    occurredAt: initializedAt,
    result: "succeeded",
    errorCode: null,
  });
  const acceptance = metadataGate.preparePolicyAcceptanceApproval({
    approvalId: "h1-policy-active-service",
    operatorId: TEST_OPERATOR_ID,
    programLocalRef: stored.localRef,
    snapshotDigest: snapshot.snapshotDigest,
    createdAt: initializedAt,
  });
  decideTestApproval(controlPlane, {
    approvalId: acceptance.id,
    decision: "accepted",
    userAction: "explicit_active_service_policy_acceptance",
    issuedAt: initializedAt,
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
  const gate = new ActiveTestingActionGate(database, controlPlane, runtime);
  return Object.freeze({
    database,
    controlPlane,
    gate,
    runtime,
    service: new ActiveTestingService(metadata, gate, transport),
    programRef: stored.localRef,
    scopeId: scope.id,
    assetIdentifierDigest: scope.assetIdentifierDigest,
    snapshotDigest: snapshot.snapshotDigest,
  });
}

function requiredTriggerSql(
  database: ControlPlaneDatabase,
  name: string,
): string {
  const row = database.get(
    "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?",
    name,
  );
  if (typeof row?.["sql"] !== "string")
    throw new Error("TEST_TRIGGER_SQL_REQUIRED");
  return row["sql"];
}

function confirmations(): {
  readonly automationPermissionReviewed: true;
  readonly scopeInstructionReviewed: true;
  readonly scopeExclusionsReviewed: true;
  readonly noSideEffectsConfirmed: true;
} {
  return Object.freeze({
    automationPermissionReviewed: true,
    scopeInstructionReviewed: true,
    scopeExclusionsReviewed: true,
    noSideEffectsConfirmed: true,
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
  servers.add(server);
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
