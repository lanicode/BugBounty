import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ActiveTestingActionGate,
  captureAuthorizedActiveTestTransportPlan,
  createActiveTestPlan,
  resolveActiveTestingRuntime,
} from "../../../packages/active-testing/index.js";
import {
  ControlPlaneDatabase,
  type ControlPlaneStore,
} from "../../../packages/control-plane/index.js";
import { HackerOneMetadataActionGate } from "../../../packages/external-actions/hackerone-metadata.js";
import { hackerOneActiveTestRegistryDefinitionDigest } from "../../../packages/external-actions/registry.js";
import {
  HACKERONE_METADATA_READ_CAPABILITY,
  resolveHackerOneMetadataReadRuntime,
} from "../../../packages/hackerone-readonly/runtime.js";
import { HackerOneMetadataStore } from "../../../packages/hackerone-readonly/store.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
  decideTestApproval,
  setTestControlPlaneTime,
  TEST_OPERATOR_ID,
} from "../../fixtures/operator-auth.factory.js";
import {
  ACTIVE_TEST_TIME,
  activeTestProgram,
  activeTestScope,
  activeTestSnapshot,
} from "../../fixtures/active-testing.factory.js";

const databases = new Set<ControlPlaneDatabase>();

afterEach(() => {
  vi.useRealTimers();
  for (const database of databases) database.close();
  databases.clear();
});

describe("ActiveTestingActionGate", () => {
  it("requires a signed plan-bound approval and consumes a one-shot transport plan", () => {
    const harness = readyHarness();
    const prepared = prepareAcceptedPlan(harness, "active-approval-one");

    const authorization = harness.gate.authorizeAndReserve({
      proposalId: "active-proposal-one",
      approvalId: prepared.approvalId,
      planId: prepared.planId,
      confirmed: true,
    });
    const opaque = harness.gate.start(authorization);
    const transport = captureAuthorizedActiveTestTransportPlan(opaque);
    expect(transport).toMatchObject({
      authorizationId: authorization.authorizationId,
      registryDefinitionDigest: hackerOneActiveTestRegistryDefinitionDigest(),
      target: { scheme: "https", port: 443, path: "/" },
      request: {
        method: "HEAD",
        follow_redirects: false,
        retries: 0,
      },
      timeoutMs: 5_000,
      maxResponseBytes: 16_384,
    });
    expect(() => captureAuthorizedActiveTestTransportPlan(opaque)).toThrow(
      "ACTIVE_TEST_TRANSPORT_AUTHORIZATION_REQUIRED",
    );

    expect(() => {
      harness.gate.complete(
        authorization,
        responseMetadata(transport) as never,
      );
    }).toThrow("ACTIVE_TEST_TRANSPORT_EVIDENCE_REQUIRED");
    harness.gate.settle(authorization, "failed");
    expect(harness.gate.listAttempts()).toEqual([
      expect.objectContaining({
        approvalId: prepared.approvalId,
        planId: prepared.planId,
        status: "failed",
        revision: 2,
      }),
    ]);
    expect(harness.gate.listReportSummaries()).toEqual([]);
  });

  it("does not reserve without the second explicit start confirmation", () => {
    const harness = readyHarness();
    const prepared = prepareAcceptedPlan(harness, "active-approval-confirm");
    const before = harness.gate.listAttempts();
    expect(() =>
      harness.gate.authorizeAndReserve({
        proposalId: "active-proposal-confirm",
        approvalId: prepared.approvalId,
        planId: prepared.planId,
        confirmed: false as true,
      }),
    ).toThrow("ACTIVE_TEST_START_CONFIRMATION_REQUIRED");
    expect(harness.gate.listAttempts()).toEqual(before);
  });

  it("binds the trusted Pilot-C registry digest and blocks durable drift before reservation", () => {
    const harness = readyHarness();
    const prepared = prepareAcceptedPlan(
      harness,
      "active-approval-registry-binding",
    );
    expect(
      harness.database.get(
        `SELECT registry_definition_digest FROM active_test_approval_bindings
         WHERE approval_id=?`,
        prepared.approvalId,
      ),
    ).toEqual({
      registry_definition_digest: hackerOneActiveTestRegistryDefinitionDigest(),
    });

    tamperRegistryDefinitionDigest(harness, prepared.approvalId);

    expect(() =>
      harness.gate.authorizeAndReserve({
        proposalId: "active-proposal-registry-drift",
        approvalId: prepared.approvalId,
        planId: prepared.planId,
        confirmed: true,
      }),
    ).toThrow("ACTIVE_TEST_APPROVAL_EVIDENCE_INVALID");
    expect(harness.gate.listAttempts()).toEqual([]);
  });

  it("rechecks the registry binding after reservation and before transport authorization", () => {
    const harness = readyHarness();
    const prepared = prepareAcceptedPlan(
      harness,
      "active-approval-registry-start",
    );
    const authorization = harness.gate.authorizeAndReserve({
      proposalId: "active-proposal-registry-start",
      approvalId: prepared.approvalId,
      planId: prepared.planId,
      confirmed: true,
    });
    tamperRegistryDefinitionDigest(harness, prepared.approvalId);

    expect(() => harness.gate.start(authorization)).toThrow(
      "ACTIVE_TEST_APPROVAL_EVIDENCE_INVALID",
    );
    expect(harness.gate.listAttempts()).toEqual([
      expect.objectContaining({ status: "reserved", revision: 0 }),
    ]);
    harness.gate.abortReservation(authorization);
  });

  it("rechecks the registry binding before completion evidence is persisted", () => {
    const harness = readyHarness();
    const prepared = prepareAcceptedPlan(
      harness,
      "active-approval-registry-complete",
    );
    const authorization = harness.gate.authorizeAndReserve({
      proposalId: "active-proposal-registry-complete",
      approvalId: prepared.approvalId,
      planId: prepared.planId,
      confirmed: true,
    });
    const transport = captureAuthorizedActiveTestTransportPlan(
      harness.gate.start(authorization),
    );
    tamperRegistryDefinitionDigest(harness, prepared.approvalId);

    expect(() =>
      harness.gate.complete(
        authorization,
        responseMetadata(transport) as never,
      ),
    ).toThrow("ACTIVE_TEST_APPROVAL_EVIDENCE_INVALID");
    expect(
      harness.database.get(
        "SELECT count(*) AS count FROM active_test_observations",
      ),
    ).toEqual({ count: 0 });
    expect(harness.gate.listAttempts()).toEqual([
      expect.objectContaining({ status: "running", revision: 1 }),
    ]);
    harness.gate.settle(authorization, "failed");
  });

  it("keeps a rejected approval unusable and records no request", () => {
    const harness = readyHarness();
    const plan = planFor(harness, "active-plan-rejected");
    const approval = harness.gate.preparePlanApproval({
      approvalId: "active-approval-rejected",
      operatorId: TEST_OPERATOR_ID,
      plan,
      createdAt: ACTIVE_TEST_TIME,
    });
    decideTestApproval(harness.controlPlane, {
      approvalId: approval.id,
      decision: "rejected",
      userAction: "explicit_active_test_rejection",
      issuedAt: ACTIVE_TEST_TIME,
    });

    expect(() =>
      harness.gate.authorizeAndReserve({
        proposalId: "active-proposal-rejected",
        approvalId: approval.id,
        planId: plan.plan_id,
        confirmed: true,
      }),
    ).toThrow("ACTIVE_TEST_APPROVAL_EVIDENCE_INVALID");
    expect(harness.gate.listAttempts()).toEqual([]);
  });

  it("fails closed when the snapshot drifts after approval", () => {
    const harness = readyHarness();
    const prepared = prepareAcceptedPlan(harness, "active-approval-drift");
    const changedProgram = activeTestProgram({
      policy:
        "Automated testing is explicitly allowed for low-risk read-only HTTPS checks. Changed.",
      synchronizedAt: "2026-07-15T12:00:01.000Z",
      updatedAt: "2026-07-15T12:00:01.000Z",
    });
    harness.metadata.replaceAuthenticatedApiCatalog(
      [changedProgram],
      "2026-07-15T12:00:01.000Z",
    );
    const changed = activeTestSnapshot({
      program: changedProgram,
      previousSnapshotDigest: harness.snapshot.snapshotDigest,
    });
    harness.metadata.commitSnapshotWithPolicyDrift(
      harness.programRef,
      changed,
      "2026-07-15T12:00:01.000Z",
    );

    expect(() =>
      harness.gate.authorizeAndReserve({
        proposalId: "active-proposal-drift",
        approvalId: prepared.approvalId,
        planId: prepared.planId,
        confirmed: true,
      }),
    ).toThrow("ACTIVE_TEST_SNAPSHOT_NOT_CURRENT_ACCEPTED");
    expect(harness.gate.listAttempts()).toEqual([]);
  });

  it("blocks selection drift and a failed synchronization after approval", () => {
    const selection = readyHarness();
    const selectedPlan = prepareAcceptedPlan(
      selection,
      "active-approval-selection-drift",
    );
    selection.metadata.selectProgram(
      selection.metadata.getIntegrationState().revision,
      null,
    );
    expect(() =>
      selection.gate.authorizeAndReserve({
        proposalId: "active-proposal-selection-drift",
        approvalId: selectedPlan.approvalId,
        planId: selectedPlan.planId,
        confirmed: true,
      }),
    ).toThrow("ACTIVE_TEST_SNAPSHOT_NOT_CURRENT_ACCEPTED");

    const failedSync = readyHarness();
    const synchronizedPlan = prepareAcceptedPlan(
      failedSync,
      "active-approval-failed-sync",
    );
    failedSync.metadata.recordSynchronization({
      expectedRevision: failedSync.metadata.getIntegrationState().revision,
      occurredAt: ACTIVE_TEST_TIME,
      result: "failed",
      errorCode: "SYNTHETIC_SYNC_FAILURE",
    });
    expect(() =>
      failedSync.gate.authorizeAndReserve({
        proposalId: "active-proposal-failed-sync",
        approvalId: synchronizedPlan.approvalId,
        planId: synchronizedPlan.planId,
        confirmed: true,
      }),
    ).toThrow("ACTIVE_TEST_SNAPSHOT_NOT_CURRENT_ACCEPTED");

    const disabledAdapter = readyHarness();
    const adapterPlan = prepareAcceptedPlan(
      disabledAdapter,
      "active-approval-adapter-disabled",
    );
    const integration = disabledAdapter.metadata.getIntegrationState();
    disabledAdapter.metadata.setAdapterEnabled(integration.revision, false);
    expect(() =>
      disabledAdapter.gate.authorizeAndReserve({
        proposalId: "active-proposal-adapter-disabled",
        approvalId: adapterPlan.approvalId,
        planId: adapterPlan.planId,
        confirmed: true,
      }),
    ).toThrow("ACTIVE_TEST_SNAPSHOT_NOT_CURRENT_ACCEPTED");
    expect(disabledAdapter.gate.listAttempts()).toEqual([]);

    const reactivatedAt = "2026-07-15T12:00:01.000Z";
    vi.setSystemTime(new Date(reactivatedAt));
    setTestControlPlaneTime(disabledAdapter.controlPlane, reactivatedAt);
    const reactivation = disabledAdapter.metadataGate.prepareActivationApproval(
      {
        approvalId: "h1-active-testing-adapter-reactivation",
        operatorId: TEST_OPERATOR_ID,
        credentialFingerprint: "b2".repeat(32),
        createdAt: reactivatedAt,
      },
    );
    decideTestApproval(disabledAdapter.controlPlane, {
      approvalId: reactivation.id,
      decision: "accepted",
      userAction: "explicit_test_hackerone_adapter_reactivation",
      issuedAt: reactivatedAt,
    });
    expect(disabledAdapter.metadata.getIntegrationState()).toMatchObject({
      adapterEnabled: true,
      lastSynchronizationAt: null,
      lastSynchronizationResult: null,
      selectedProgramRef: null,
      selectedProgramSource: null,
    });
    expect(() =>
      disabledAdapter.gate.authorizeAndReserve({
        proposalId: "active-proposal-after-credential-generation-change",
        approvalId: adapterPlan.approvalId,
        planId: adapterPlan.planId,
        confirmed: true,
      }),
    ).toThrow("ACTIVE_TEST_SNAPSHOT_NOT_CURRENT_ACCEPTED");
    expect(disabledAdapter.gate.listAttempts()).toEqual([]);
  });

  it("rejects a snapshot older than the live freshness window before approval", () => {
    const harness = readyHarness(undefined, true, "2026-07-15T11:44:59.999Z");
    const plan = planFor(harness, "active-plan-stale-snapshot");
    expect(() =>
      harness.gate.preparePlanApproval({
        approvalId: "active-approval-stale-snapshot",
        operatorId: TEST_OPERATOR_ID,
        plan,
        createdAt: ACTIVE_TEST_TIME,
      }),
    ).toThrow("ACTIVE_TEST_SNAPSHOT_NOT_CURRENT_ACCEPTED");
    expect(harness.gate.listPlans()).toEqual([]);
  });

  it("reserves budget before execution and never refunds failed attempts", () => {
    const harness = readyHarness({ max_requests_total: 1 });
    const first = prepareAcceptedPlan(harness, "active-approval-budget-one");
    const authorization = harness.gate.authorizeAndReserve({
      proposalId: "active-proposal-budget-one",
      approvalId: first.approvalId,
      planId: first.planId,
      confirmed: true,
    });
    harness.gate.start(authorization);
    harness.gate.settle(authorization, "failed");

    const second = prepareAcceptedPlan(
      harness,
      "active-approval-budget-two",
      "security_txt",
    );
    expect(() =>
      harness.gate.authorizeAndReserve({
        proposalId: "active-proposal-budget-two",
        approvalId: second.approvalId,
        planId: second.planId,
        confirmed: true,
      }),
    ).toThrow("ACTIVE_TEST_REQUEST_BUDGET_EXCEEDED");
  });

  it("blocks approval, reserve and start whenever runtime or kill switch is closed", () => {
    const disabled = readyHarness(undefined, false);
    expect(() => planFor(disabled, "active-plan-disabled")).not.toThrow();
    expect(() =>
      disabled.gate.preparePlanApproval({
        approvalId: "active-approval-disabled",
        operatorId: TEST_OPERATOR_ID,
        plan: planFor(disabled, "active-plan-disabled-two"),
        createdAt: ACTIVE_TEST_TIME,
      }),
    ).toThrow("EXTERNAL_INTEGRATIONS_DISABLED");

    const harness = readyHarness();
    const prepared = prepareAcceptedPlan(harness, "active-approval-kill");
    harness.controlPlane.setKillSwitch(
      true,
      TEST_OPERATOR_ID,
      ACTIVE_TEST_TIME,
    );
    expect(() =>
      harness.gate.authorizeAndReserve({
        proposalId: "active-proposal-kill",
        approvalId: prepared.approvalId,
        planId: prepared.planId,
        confirmed: true,
      }),
    ).toThrow("ACTIVE_TEST_KILL_SWITCH");
  });

  it("rejects forged authorizations and immutable evidence mutation", () => {
    const harness = readyHarness();
    const prepared = prepareAcceptedPlan(harness, "active-approval-forge");
    const authorization = harness.gate.authorizeAndReserve({
      proposalId: "active-proposal-forge",
      approvalId: prepared.approvalId,
      planId: prepared.planId,
      confirmed: true,
    });
    expect(() => harness.gate.start({ ...authorization })).toThrow(
      "ACTIVE_TEST_AUTHORIZATION_REQUIRED",
    );
    expect(() =>
      harness.database.run(
        "UPDATE active_test_plans SET plan_digest=? WHERE plan_id=?",
        "f".repeat(64),
        prepared.planId,
      ),
    ).toThrow("ACTIVE_TEST_PLAN_IMMUTABLE");
    harness.gate.abortReservation(authorization);
  });

  it("fails closed on duplicate-key plan JSON retained in durable storage", () => {
    const harness = readyHarness();
    const prepared = prepareAcceptedPlan(
      harness,
      "active-approval-noncanonical-plan",
    );
    const trigger = requiredTriggerSql(
      harness.database,
      "active_test_plans_no_update",
    );
    const row = harness.database.get(
      "SELECT plan_json FROM active_test_plans WHERE plan_id=?",
      prepared.planId,
    );
    if (typeof row?.["plan_json"] !== "string")
      throw new Error("TEST_PLAN_JSON_REQUIRED");
    const tampered = `{"plan_id":"RAW_SECRET_CANARY",${row["plan_json"].slice(1)}`;
    harness.database.run("DROP TRIGGER active_test_plans_no_update");
    harness.database.run(
      "UPDATE active_test_plans SET plan_json=? WHERE plan_id=?",
      tampered,
      prepared.planId,
    );
    harness.database.run(trigger);

    expect(
      () =>
        new ActiveTestingActionGate(
          harness.database,
          harness.controlPlane,
          harness.runtime,
        ),
    ).toThrow("ACTIVE_TEST_PLAN_EVIDENCE_INVALID");
  });

  it("detects a durable plan whose approval binding was removed offline", () => {
    const harness = readyHarness();
    prepareAcceptedPlan(harness, "active-approval-orphan-plan");
    const trigger = requiredTriggerSql(
      harness.database,
      "active_test_binding_no_delete",
    );
    harness.database.run("DROP TRIGGER active_test_binding_no_delete");
    harness.database.run(
      "DELETE FROM active_test_approval_bindings WHERE approval_id=?",
      "active-approval-orphan-plan",
    );
    harness.database.run(trigger);

    expect(
      () =>
        new ActiveTestingActionGate(
          harness.database,
          harness.controlPlane,
          harness.runtime,
        ),
    ).toThrow("ACTIVE_TEST_PERSISTED_EVIDENCE_INVALID");
  });

  it("rejects direct attempt transitions and unbound immutable observation inserts", () => {
    const harness = readyHarness();
    const prepared = prepareAcceptedPlan(harness, "active-approval-transition");
    const authorization = harness.gate.authorizeAndReserve({
      proposalId: "active-proposal-transition",
      approvalId: prepared.approvalId,
      planId: prepared.planId,
      confirmed: true,
    });
    harness.gate.start(authorization);
    expect(() =>
      harness.database.run(
        `UPDATE active_test_attempts
         SET status='failed',finished_at=started_at,revision=2,
           settlement_audit_id=reservation_audit_id
         WHERE authorization_id=?`,
        authorization.authorizationId,
      ),
    ).toThrow("ACTIVE_TEST_ATTEMPT_TRANSITION_INVALID");
    expect(() =>
      harness.database.run(
        `INSERT INTO active_test_observations(
          authorization_id,plan_id,plan_digest,observation_digest,
          observation_json,created_at
        ) VALUES(?,?,?,?,?,?)`,
        authorization.authorizationId,
        authorization.planId,
        authorization.planDigest,
        "f".repeat(64),
        JSON.stringify({ version: 1 }),
        ACTIVE_TEST_TIME,
      ),
    ).toThrow("ACTIVE_TEST_OBSERVATION_EVIDENCE_INVALID");
    harness.gate.settle(authorization, "failed");
  });

  it("uses the store-owned clock and blocks rollback before reserve and settlement", () => {
    const harness = readyHarness();
    const first = prepareAcceptedPlan(harness, "active-approval-clock-one");
    setTestControlPlaneTime(harness.controlPlane, "2026-07-15T11:59:59.000Z");
    expect(() =>
      harness.gate.authorizeAndReserve({
        proposalId: "active-proposal-clock-one",
        approvalId: first.approvalId,
        planId: first.planId,
        confirmed: true,
      }),
    ).toThrow("OPERATOR_CLOCK_ROLLBACK");

    setTestControlPlaneTime(harness.controlPlane, ACTIVE_TEST_TIME);
    const authorization = harness.gate.authorizeAndReserve({
      proposalId: "active-proposal-clock-two",
      approvalId: first.approvalId,
      planId: first.planId,
      confirmed: true,
    });
    setTestControlPlaneTime(harness.controlPlane, "2026-07-15T12:00:01.000Z");
    harness.gate.start(authorization);
    setTestControlPlaneTime(harness.controlPlane, ACTIVE_TEST_TIME);
    expect(() => {
      harness.gate.settle(authorization, "failed");
    }).toThrow("ACTIVE_TEST_CLOCK_ROLLBACK");
    setTestControlPlaneTime(harness.controlPlane, "2026-07-15T12:00:01.000Z");
    harness.gate.settle(authorization, "failed");
  });
});

interface Harness {
  readonly database: ControlPlaneDatabase;
  readonly controlPlane: ControlPlaneStore;
  readonly metadata: HackerOneMetadataStore;
  readonly metadataGate: HackerOneMetadataActionGate;
  readonly gate: ActiveTestingActionGate;
  readonly runtime: ReturnType<typeof resolveActiveTestingRuntime>;
  readonly programRef: string;
  readonly snapshot: ReturnType<typeof activeTestSnapshot>;
}

function readyHarness(
  budget?: { readonly max_requests_total: number },
  enabled = true,
  metadataAt = ACTIVE_TEST_TIME,
): Harness {
  vi.useFakeTimers();
  vi.setSystemTime(new Date(ACTIVE_TEST_TIME));
  const database = ControlPlaneDatabase.memory();
  databases.add(database);
  const activationAt = new Date(Date.parse(metadataAt) - 1).toISOString();
  const controlPlane = createTestControlPlaneStore(database, activationAt);
  const metadata = new HackerOneMetadataStore(database);
  const h1Gate = new HackerOneMetadataActionGate(
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
  const activation = h1Gate.prepareActivationApproval({
    approvalId: "h1-active-testing-adapter-activation",
    operatorId: TEST_OPERATOR_ID,
    credentialFingerprint: "a1".repeat(32),
    createdAt: activationAt,
  });
  decideTestApproval(controlPlane, {
    approvalId: activation.id,
    decision: "accepted",
    userAction: "explicit_test_hackerone_adapter_activation",
    issuedAt: activationAt,
  });
  setTestControlPlaneTime(controlPlane, ACTIVE_TEST_TIME);
  const program = activeTestProgram({
    synchronizedAt: metadataAt,
    updatedAt: metadataAt,
  });
  const stored = metadata.replaceAuthenticatedApiCatalog(
    [program],
    metadataAt,
  )[0];
  if (stored === undefined) throw new Error("TEST_PROGRAM_REQUIRED");
  const snapshot = activeTestSnapshot({ program, fetchedAt: metadataAt });
  metadata.commitSelectedProgramSynchronization(stored.localRef, snapshot, {
    expectedRevision: metadata.getIntegrationState().revision,
    occurredAt: metadataAt,
    result: "succeeded",
    errorCode: null,
  });
  const acceptance = h1Gate.preparePolicyAcceptanceApproval({
    approvalId: "h1-policy-active-test",
    operatorId: TEST_OPERATOR_ID,
    programLocalRef: stored.localRef,
    snapshotDigest: snapshot.snapshotDigest,
    createdAt: ACTIVE_TEST_TIME,
  });
  decideTestApproval(controlPlane, {
    approvalId: acceptance.id,
    decision: "accepted",
    userAction: "explicit_active_test_policy_acceptance",
    issuedAt: ACTIVE_TEST_TIME,
  });
  const runtime = resolveActiveTestingRuntime({
    version: 1,
    capability: "HACKERONE_ACTIVE_TEST",
    external_integrations_enabled: enabled,
    enabled,
    request_budget: {
      max_requests_total: budget?.max_requests_total ?? 5,
      requests_per_minute: 2,
      max_concurrency: 1,
    },
    request_timeout_ms: 5_000,
    max_response_bytes: 16_384,
  });
  const gate = new ActiveTestingActionGate(database, controlPlane, runtime);
  return {
    database,
    controlPlane,
    metadata,
    metadataGate: h1Gate,
    gate,
    runtime,
    programRef: stored.localRef,
    snapshot,
  };
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

function tamperRegistryDefinitionDigest(
  harness: Harness,
  approvalId: string,
): void {
  const trigger = requiredTriggerSql(
    harness.database,
    "active_test_binding_immutable",
  );
  harness.database.run("DROP TRIGGER active_test_binding_immutable");
  harness.database.run(
    `UPDATE active_test_approval_bindings
     SET registry_definition_digest=? WHERE approval_id=?`,
    "f".repeat(64),
    approvalId,
  );
  harness.database.run(trigger);
}

function planFor(
  harness: Harness,
  planId: string,
  testClass:
    "cors_preflight" | "http_headers" | "security_txt" = "http_headers",
) {
  const scope = activeTestScope();
  return createActiveTestPlan({
    planId,
    programRef: harness.programRef,
    snapshot: harness.snapshot,
    scopeId: scope.id,
    assetIdentifierDigest: scope.assetIdentifierDigest,
    testClass,
    createdAt: ACTIVE_TEST_TIME,
    confirmations: {
      automationPermissionReviewed: true,
      scopeInstructionReviewed: true,
      scopeExclusionsReviewed: true,
      noSideEffectsConfirmed: true,
    },
  });
}

function prepareAcceptedPlan(
  harness: Harness,
  approvalId: string,
  testClass:
    "cors_preflight" | "http_headers" | "security_txt" = "http_headers",
): { readonly approvalId: string; readonly planId: string } {
  const planId = approvalId.replace("approval", "plan");
  const plan = planFor(harness, planId, testClass);
  const approval = harness.gate.preparePlanApproval({
    approvalId,
    operatorId: TEST_OPERATOR_ID,
    plan,
    createdAt: ACTIVE_TEST_TIME,
  });
  decideTestApproval(harness.controlPlane, {
    approvalId: approval.id,
    decision: "accepted",
    userAction: `explicit_${approvalId}`,
    issuedAt: ACTIVE_TEST_TIME,
  });
  return Object.freeze({ approvalId, planId });
}

function responseMetadata(
  transport: ReturnType<typeof captureAuthorizedActiveTestTransportPlan>,
) {
  return Object.freeze({
    version: 1 as const,
    planId: transport.planId,
    planDigest: transport.planDigest,
    testClass: "http_headers" as const,
    statusCode: 200,
    durationMs: 25,
    responseBytesObserved: 0,
    contentType: "text/html" as const,
    redirectLocationPresent: false as const,
    tls: Object.freeze({
      authorized: true as const,
      protocol: "TLSv1.3" as const,
      cipher: "modern" as const,
    }),
    transport: Object.freeze({
      kind: "production_https" as const,
      resolutionDigest: "d".repeat(64),
    }),
    facts: Object.freeze({
      kind: "http_headers" as const,
      contentSecurityPolicyPresent: true,
      strictTransportSecurityPresent: true,
      xContentTypeOptionsNosniff: true,
      insecureCookieFlagsObserved: false,
    }),
    responseDigest: null,
    redaction: Object.freeze({
      status: "complete" as const,
      rawBodyStored: false as const,
      rawHeadersStored: false as const,
      cookiesStored: false as const,
    }),
    completedAt: ACTIVE_TEST_TIME,
  });
}
