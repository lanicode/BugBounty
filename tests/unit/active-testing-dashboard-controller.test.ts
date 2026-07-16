import { afterEach, describe, expect, it } from "vitest";
import {
  ActiveTestingActionGate,
  ActiveTestingService,
  ProductionActiveTestTransport,
  resolveActiveTestingRuntime,
} from "../../packages/active-testing/index.js";
import {
  ControlPlaneDatabase,
  type ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  LocalActiveTestingController,
  isTrustedLocalActiveTestingController,
} from "../../packages/dashboard/active-testing.js";
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

const databases = new Set<ControlPlaneDatabase>();

afterEach(() => {
  for (const database of databases) database.close();
  databases.clear();
});

describe("LocalActiveTestingController", () => {
  it("projects only the selected accepted API snapshot and separates prepare from approval", () => {
    const harness = readyHarness(true);
    const initial = projection(harness.controller, harness.now);
    expect(initial.capability).toEqual({
      available: true,
      configured: true,
      enabled: true,
      secureCoreReady: true,
      killSwitchActive: false,
      reasonCodes: [],
    });
    expect(initial.programs).toHaveLength(1);
    expect(initial.snapshots).toEqual([
      expect.objectContaining({ accepted: true, current: true }),
    ]);
    expect(initial.assetCandidates).toEqual([
      expect.objectContaining({
        supported: true,
        scopeId: harness.scopeId,
        assetIdentifierDigest: harness.assetIdentifierDigest,
      }),
    ]);
    expect(initial.currentPlan).toBeNull();

    const prepared = harness.controller.preparePlanApproval({
      planId: "dashboard-active-plan-one",
      approvalId: "dashboard-active-approval-one",
      operatorId: TEST_OPERATOR_ID,
      programRef: harness.programRef,
      snapshotDigest: harness.snapshotDigest,
      scopeId: harness.scopeId,
      assetIdentifierDigest: harness.assetIdentifierDigest,
      testClass: "http_headers",
      createdAt: harness.now,
      confirmations: confirmations(),
    });
    const awaitingApproval = projection(harness.controller, harness.now);
    expect(awaitingApproval.currentPlan).toEqual(
      expect.objectContaining({
        planId: prepared.plan.plan_id,
        status: "prepared",
      }),
    );
    expect(awaitingApproval.currentApproval).toEqual({
      approvalId: prepared.approval.id,
      planId: prepared.plan.plan_id,
      status: "open",
    });
    harness.controller.assertApprovalState(
      prepared.plan.plan_id,
      prepared.approval.id,
      "open",
    );

    decideTestApproval(harness.controlPlane, {
      approvalId: prepared.approval.id,
      decision: "accepted",
      userAction: "explicit_dashboard_active_plan_approval",
      issuedAt: harness.now,
    });
    const approved = projection(harness.controller, harness.now);
    expect(approved.currentPlan).toEqual(
      expect.objectContaining({ status: "approved" }),
    );
    expect(approved.currentApproval).toEqual(
      expect.objectContaining({ status: "accepted" }),
    );
    harness.controller.assertApprovalState(
      prepared.plan.plan_id,
      prepared.approval.id,
      "accepted",
    );
  });

  it("keeps missing runtime, core, signer and kill-switch evidence fail-closed", () => {
    const harness = readyHarness(false);
    const state = harness.controller.project({
      secureCoreReady: false,
      operatorSignerAvailable: false,
      killSwitchActive: true,
      now: harness.now,
    }) as Projection;
    expect(state.capability).toMatchObject({
      available: true,
      configured: false,
      enabled: false,
      secureCoreReady: false,
      killSwitchActive: true,
    });
    expect(state.capability.reasonCodes).toEqual(
      expect.arrayContaining([
        "ACTIVE_TESTING_EXTERNAL_INTEGRATIONS_DISABLED",
        "ACTIVE_TESTING_CAPABILITY_DISABLED",
        "ACTIVE_TESTING_SECURE_CORE_REQUIRED",
        "ACTIVE_TESTING_OPERATOR_SIGNER_REQUIRED",
        "ACTIVE_TESTING_KILL_SWITCH_ACTIVE",
      ]),
    );
  });

  it("rejects controller construction across separately trusted gate/runtime bindings", () => {
    const first = readyHarness(true);
    const second = readyHarness(true);
    expect(isTrustedLocalActiveTestingController(first.controller)).toBe(true);
    expect(
      () =>
        new LocalActiveTestingController({
          service: first.service,
          gate: second.gate,
          runtime: second.runtime,
        }),
    ).toThrow("ACTIVE_TESTING_CONTROLLER_UNTRUSTED");
  });
});

interface Harness {
  readonly now: string;
  readonly controlPlane: ControlPlaneStore;
  readonly gate: ActiveTestingActionGate;
  readonly service: ActiveTestingService;
  readonly runtime: ReturnType<typeof resolveActiveTestingRuntime>;
  readonly controller: LocalActiveTestingController;
  readonly programRef: string;
  readonly snapshotDigest: string;
  readonly scopeId: string;
  readonly assetIdentifierDigest: string;
}

interface Projection {
  readonly capability: {
    readonly available: boolean;
    readonly configured: boolean;
    readonly enabled: boolean;
    readonly secureCoreReady: boolean;
    readonly killSwitchActive: boolean;
    readonly reasonCodes: readonly string[];
  };
  readonly programs: readonly unknown[];
  readonly snapshots: readonly unknown[];
  readonly assetCandidates: readonly unknown[];
  readonly currentPlan: unknown;
  readonly currentApproval: unknown;
}

function readyHarness(enabled: boolean): Harness {
  const now = new Date().toISOString();
  const activationAt = new Date(Date.parse(now) - 1).toISOString();
  const database = ControlPlaneDatabase.memory();
  databases.add(database);
  const controlPlane = createTestControlPlaneStore(database, activationAt);
  clearTestKillSwitch(controlPlane, activationAt);
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
  const activation = metadataGate.prepareActivationApproval({
    approvalId: `dashboard-h1-adapter-${enabled ? "enabled" : "disabled"}`,
    operatorId: TEST_OPERATOR_ID,
    credentialFingerprint: "a4".repeat(32),
    createdAt: activationAt,
  });
  decideTestApproval(controlPlane, {
    approvalId: activation.id,
    decision: "accepted",
    userAction: "explicit_dashboard_active_adapter_activation",
    issuedAt: activationAt,
  });
  setTestControlPlaneTime(controlPlane, now);
  const program = activeTestProgram({ synchronizedAt: now, updatedAt: now });
  const scope = activeTestScope({ createdAt: now, updatedAt: now });
  const snapshot = createHackerOnePolicySnapshot({
    program,
    structuredScopes: [scope],
    scopeExclusions: [activeTestExclusion({ createdAt: now, updatedAt: now })],
    fetchedAt: now,
    previousSnapshotDigest: null,
  });
  const stored = metadata.replaceAuthenticatedApiCatalog([program], now)[0];
  if (stored === undefined) throw new Error("TEST_PROGRAM_REQUIRED");
  metadata.commitSelectedProgramSynchronization(stored.localRef, snapshot, {
    expectedRevision: metadata.getIntegrationState().revision,
    occurredAt: now,
    result: "succeeded",
    errorCode: null,
  });
  const acceptance = metadataGate.preparePolicyAcceptanceApproval({
    approvalId: `dashboard-h1-policy-${enabled ? "enabled" : "disabled"}`,
    operatorId: TEST_OPERATOR_ID,
    programLocalRef: stored.localRef,
    snapshotDigest: snapshot.snapshotDigest,
    createdAt: now,
  });
  decideTestApproval(controlPlane, {
    approvalId: acceptance.id,
    decision: "accepted",
    userAction: "explicit_dashboard_active_policy_acceptance",
    issuedAt: now,
  });
  const runtime = resolveActiveTestingRuntime({
    version: 1,
    capability: "HACKERONE_ACTIVE_TEST",
    external_integrations_enabled: enabled,
    enabled,
    request_budget: {
      max_requests_total: 5,
      requests_per_minute: 2,
      max_concurrency: 1,
    },
    request_timeout_ms: 5_000,
    max_response_bytes: 16_384,
  });
  const gate = new ActiveTestingActionGate(database, controlPlane, runtime);
  const service = new ActiveTestingService(
    metadata,
    gate,
    new ProductionActiveTestTransport(controlPlane),
  );
  const controller = new LocalActiveTestingController({
    service,
    gate,
    runtime,
  });
  return Object.freeze({
    now,
    controlPlane,
    gate,
    service,
    runtime,
    controller,
    programRef: stored.localRef,
    snapshotDigest: snapshot.snapshotDigest,
    scopeId: scope.id,
    assetIdentifierDigest: scope.assetIdentifierDigest,
  });
}

function projection(
  controller: LocalActiveTestingController,
  now: string,
): Projection {
  return controller.project({
    secureCoreReady: true,
    operatorSignerAvailable: true,
    killSwitchActive: false,
    now,
  }) as Projection;
}

function confirmations() {
  return Object.freeze({
    automationPermissionReviewed: true as const,
    scopeInstructionReviewed: true as const,
    scopeExclusionsReviewed: true as const,
    noSideEffectsConfirmed: true as const,
  });
}
