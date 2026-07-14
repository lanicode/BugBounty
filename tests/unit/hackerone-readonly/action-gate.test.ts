import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ControlPlaneDatabase,
  type ControlPlaneDatabase as ControlPlaneDatabaseType,
  type ControlPlaneStore,
} from "../../../packages/control-plane/index.js";
import {
  captureAuthorizedHackerOneMetadataTransportPlan,
  HackerOneMetadataActionGate,
  type StoreBoundHackerOneMetadataAuthorization,
} from "../../../packages/external-actions/hackerone-metadata.js";
import {
  createInitialHackerOneMetadataRequestPlan,
  type HackerOneMetadataRequestPlan,
} from "../../../packages/hackerone-readonly/request-policy.js";
import {
  HACKERONE_METADATA_READ_CAPABILITY,
  resolveHackerOneMetadataReadRuntime,
  type HackerOneMetadataReadRuntimeState,
} from "../../../packages/hackerone-readonly/runtime.js";
import { createHackerOnePolicySnapshot } from "../../../packages/hackerone-readonly/snapshot.js";
import { HackerOneMetadataStore } from "../../../packages/hackerone-readonly/store.js";
import type { HackerOneProgram } from "../../../packages/hackerone-readonly/types.js";
import { createActivatedHackerOneActionHarness } from "../../fixtures/hackerone-action.factory.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
  decideTestApproval,
  signTestApprovalDecision,
  TEST_OPERATOR_ID,
} from "../../fixtures/operator-auth.factory.js";

const AT = "2026-07-14T12:00:00.000Z";
const LATER = "2026-07-14T12:00:01.000Z";
const FINGERPRINT = "a1".repeat(32);

interface ClearedHarness {
  readonly database: ControlPlaneDatabaseType;
  readonly controlPlane: ControlPlaneStore;
  readonly metadata: HackerOneMetadataStore;
  readonly actionGate: HackerOneMetadataActionGate;
  close(): void;
}

const databases = new Set<ControlPlaneDatabaseType>();

afterEach(() => {
  vi.useRealTimers();
  for (const database of databases) database.close();
  databases.clear();
});

describe("HackerOneMetadataActionGate", () => {
  it("activates only through an accepted signed decision and commits all evidence atomically", () => {
    const harness = createClearedHarness(runtime());
    expect(() =>
      harness.actionGate.prepareActivationApproval({
        approvalId: "h1activation-short-display-fingerprint",
        operatorId: TEST_OPERATOR_ID,
        credentialFingerprint: FINGERPRINT.slice(0, 12),
        createdAt: AT,
      }),
    ).toThrow("HACKERONE_CREDENTIAL_FINGERPRINT_INVALID");
    const approval = harness.actionGate.prepareActivationApproval({
      approvalId: "h1activation-accepted",
      operatorId: TEST_OPERATOR_ID,
      credentialFingerprint: FINGERPRINT,
      createdAt: AT,
    });

    const accepted = decideTestApproval(harness.controlPlane, {
      approvalId: approval.id,
      decision: "accepted",
      userAction: "explicit_test_hackerone_activation_accept",
      issuedAt: AT,
    });

    expect(accepted).toMatchObject({
      status: "accepted",
      revision: 1,
      decidedBy: TEST_OPERATOR_ID,
    });
    expect(harness.metadata.getIntegrationState()).toMatchObject({
      adapterEnabled: true,
      adapterGeneration: 1,
      revision: 1,
    });
    const binding = harness.database.get(
      `SELECT decision_audit_id,activated_generation
       FROM hackerone_metadata_activation_bindings WHERE approval_id=?`,
      approval.id,
    );
    const decisionAuditId = binding?.["decision_audit_id"];
    expect(typeof decisionAuditId).toBe("string");
    expect(binding?.["activated_generation"]).toBe(1);
    expect(
      harness.database.get(
        `SELECT credential_fingerprint
         FROM hackerone_metadata_activation_bindings WHERE approval_id=?`,
        approval.id,
      ),
    ).toEqual({ credential_fingerprint: FINGERPRINT });
    if (typeof decisionAuditId !== "string")
      throw new Error("TEST_ACTIVATION_AUDIT_ID_REQUIRED");
    expect(
      harness.database.get(
        `SELECT decision,object_reference FROM control_plane_audit
         WHERE id=?`,
        decisionAuditId,
      ),
    ).toMatchObject({ decision: "accepted", object_reference: approval.id });
  });

  it("keeps activation disabled after signed rejection or an invalid signature", () => {
    const rejectedHarness = createClearedHarness(runtime());
    const rejectedApproval =
      rejectedHarness.actionGate.prepareActivationApproval({
        approvalId: "h1activation-rejected",
        operatorId: TEST_OPERATOR_ID,
        credentialFingerprint: FINGERPRINT,
        createdAt: AT,
      });
    decideTestApproval(rejectedHarness.controlPlane, {
      approvalId: rejectedApproval.id,
      decision: "rejected",
      userAction: "explicit_test_hackerone_activation_reject",
      issuedAt: AT,
    });

    expect(rejectedHarness.metadata.getIntegrationState()).toMatchObject({
      adapterEnabled: false,
      adapterGeneration: 0,
      revision: 0,
    });
    const rejectedBinding = rejectedHarness.database.get(
      `SELECT decision_audit_id,activated_generation
       FROM hackerone_metadata_activation_bindings WHERE approval_id=?`,
      rejectedApproval.id,
    );
    expect(typeof rejectedBinding?.["decision_audit_id"]).toBe("string");
    expect(rejectedBinding?.["activated_generation"]).toBeNull();

    const invalidHarness = createClearedHarness(runtime());
    const invalidApproval = invalidHarness.actionGate.prepareActivationApproval(
      {
        approvalId: "h1activation-invalid-signature",
        operatorId: TEST_OPERATOR_ID,
        credentialFingerprint: FINGERPRINT,
        createdAt: AT,
      },
    );
    const signed = signTestApprovalDecision(invalidHarness.controlPlane, {
      approvalId: invalidApproval.id,
      decision: "accepted",
      userAction: "explicit_test_hackerone_activation_invalid_signature",
      issuedAt: AT,
    });

    expect(() =>
      invalidHarness.controlPlane.decideApproval({
        ...signed,
        signature_base64url: mutateSignature(signed.signature_base64url),
      }),
    ).toThrow();
    expect(invalidHarness.metadata.getIntegrationState()).toMatchObject({
      adapterEnabled: false,
      adapterGeneration: 0,
      revision: 0,
    });
    expect(
      invalidHarness.controlPlane
        .listApprovals()
        .find(({ id }) => id === invalidApproval.id),
    ).toMatchObject({ status: "open", revision: 0 });
    expect(
      invalidHarness.database.get(
        `SELECT decision_audit_id,activated_generation
         FROM hackerone_metadata_activation_bindings WHERE approval_id=?`,
        invalidApproval.id,
      ),
    ).toEqual({ decision_audit_id: null, activated_generation: null });
  });

  it("rolls an accepted activation decision back at and after expiry", () => {
    const expiry = new Date(Date.parse(AT) + 5 * 60_000).toISOString();
    const afterExpiry = new Date(Date.parse(expiry) + 1).toISOString();
    for (const [suffix, decisionAt] of [
      ["at-expiry", expiry],
      ["after-expiry", afterExpiry],
    ] as const) {
      const harness = createClearedHarness(runtime());
      const approval = harness.actionGate.prepareActivationApproval({
        approvalId: `h1activation-${suffix}`,
        operatorId: TEST_OPERATOR_ID,
        credentialFingerprint: FINGERPRINT,
        createdAt: AT,
      });

      expect(() =>
        decideTestApproval(harness.controlPlane, {
          approvalId: approval.id,
          decision: "accepted",
          userAction: `explicit_test_hackerone_activation_${suffix}`,
          issuedAt: decisionAt,
        }),
      ).toThrow("HACKERONE_ACTIVATION_EXPIRED");
      expect(harness.metadata.getIntegrationState()).toMatchObject({
        adapterEnabled: false,
        adapterGeneration: 0,
        revision: 0,
      });
      expect(
        harness.controlPlane
          .listApprovals()
          .find(({ id }) => id === approval.id),
      ).toMatchObject({ status: "open", revision: 0 });
      expect(
        harness.database.get(
          `SELECT decision_audit_id,activated_generation
           FROM hackerone_metadata_activation_bindings WHERE approval_id=?`,
          approval.id,
        ),
      ).toEqual({ decision_audit_id: null, activated_generation: null });
    }
  });

  it("accepts only the exact current snapshot through signed evidence", () => {
    const harness = activatedHarness(runtime());
    const first = persistSnapshot(harness.metadata, program(), AT, null);
    const second = persistSnapshot(
      harness.metadata,
      program({ policy: "Changed synthetic local policy." }),
      LATER,
      first.snapshotDigest,
    );

    const approvalsBefore = harness.controlPlane.listApprovals().length;
    expect(() =>
      harness.actionGate.preparePolicyAcceptanceApproval({
        approvalId: "h1policy-stale",
        operatorId: TEST_OPERATOR_ID,
        programLocalRef: first.programLocalRef,
        snapshotDigest: first.snapshotDigest,
        createdAt: LATER,
      }),
    ).toThrow("HACKERONE_SNAPSHOT_ACCEPTANCE_REQUIRES_CURRENT");
    expect(harness.controlPlane.listApprovals()).toHaveLength(approvalsBefore);

    const approval = harness.actionGate.preparePolicyAcceptanceApproval({
      approvalId: "h1policy-current",
      operatorId: TEST_OPERATOR_ID,
      programLocalRef: second.programLocalRef,
      snapshotDigest: second.snapshotDigest,
      createdAt: LATER,
    });
    decideTestApproval(harness.controlPlane, {
      approvalId: approval.id,
      decision: "accepted",
      userAction: "explicit_test_current_hackerone_policy_acceptance",
      issuedAt: LATER,
    });

    expect(
      harness.metadata.getSnapshot(second.snapshotDigest)?.acceptancePending,
    ).toBe(false);
    expect(
      harness.metadata.getSnapshot(first.snapshotDigest)?.acceptancePending,
    ).toBe(true);
    const acceptance = harness.database.get(
      `SELECT program_local_ref,approval_id,accepted_by,decision_audit_id,
         statement_digest FROM hackerone_policy_acceptances
       WHERE snapshot_digest=?`,
      second.snapshotDigest,
    );
    expect(acceptance?.["program_local_ref"]).toBe(second.programLocalRef);
    expect(acceptance?.["approval_id"]).toBe(approval.id);
    expect(acceptance?.["accepted_by"]).toBe(TEST_OPERATOR_ID);
    expect(typeof acceptance?.["decision_audit_id"]).toBe("string");
    expect(acceptance?.["statement_digest"]).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("records a signed policy rejection without creating acceptance", () => {
    const harness = activatedHarness(runtime());
    const current = persistSnapshot(harness.metadata, program(), AT, null);
    const approval = harness.actionGate.preparePolicyAcceptanceApproval({
      approvalId: "h1policy-rejected",
      operatorId: TEST_OPERATOR_ID,
      programLocalRef: current.programLocalRef,
      snapshotDigest: current.snapshotDigest,
      createdAt: AT,
    });

    decideTestApproval(harness.controlPlane, {
      approvalId: approval.id,
      decision: "rejected",
      userAction: "explicit_test_hackerone_policy_rejection",
      issuedAt: AT,
    });

    expect(
      harness.metadata.getSnapshot(current.snapshotDigest)?.acceptancePending,
    ).toBe(true);
    expect(
      harness.database.get(
        "SELECT snapshot_digest FROM hackerone_policy_acceptances WHERE snapshot_digest=?",
        current.snapshotDigest,
      ),
    ).toBeUndefined();
    const rejection = harness.database.get(
      `SELECT decision_audit_id FROM hackerone_policy_acceptance_bindings
       WHERE approval_id=?`,
      approval.id,
    );
    expect(typeof rejection?.["decision_audit_id"]).toBe("string");
  });

  it("blocks acceptance during catalog drift until an exact detail snapshot is committed", () => {
    const harness = activatedHarness(runtime());
    const initialProgram = program();
    const initial = persistSnapshot(harness.metadata, initialProgram, AT, null);
    const changedProgram = program({
      policy: "Catalog policy changed and requires detail synchronization.",
      synchronizedAt: LATER,
      updatedAt: LATER,
    });
    harness.metadata.replaceAuthenticatedApiCatalog([changedProgram], LATER);
    expect(harness.metadata.getProgram(initial.programLocalRef)).toMatchObject({
      catalogActive: true,
      catalogDriftPending: true,
    });
    expect(() =>
      harness.actionGate.preparePolicyAcceptanceApproval({
        approvalId: "h1policy-catalog-drift",
        operatorId: TEST_OPERATOR_ID,
        programLocalRef: initial.programLocalRef,
        snapshotDigest: initial.snapshotDigest,
        createdAt: LATER,
      }),
    ).toThrow("HACKERONE_SNAPSHOT_ACCEPTANCE_REQUIRES_CURRENT");

    const detail = createHackerOnePolicySnapshot({
      program: changedProgram,
      structuredScopes: [],
      scopeExclusions: [],
      fetchedAt: LATER,
      previousSnapshotDigest: initial.snapshotDigest,
    });
    const committed = harness.metadata.commitSnapshotWithPolicyDrift(
      initial.programLocalRef,
      detail,
      LATER,
    ).stored;
    expect(harness.metadata.getProgram(initial.programLocalRef)).toMatchObject({
      catalogActive: true,
      catalogDriftPending: false,
    });
    expect(() =>
      harness.actionGate.preparePolicyAcceptanceApproval({
        approvalId: "h1policy-detail-current",
        operatorId: TEST_OPERATOR_ID,
        programLocalRef: initial.programLocalRef,
        snapshotDigest: committed.snapshot.snapshotDigest,
        createdAt: LATER,
      }),
    ).not.toThrow();

    harness.metadata.replaceAuthenticatedApiCatalog([], LATER);
    expect(harness.metadata.getProgram(initial.programLocalRef)).toMatchObject({
      catalogActive: false,
      catalogDriftPending: true,
    });
    expect(() =>
      harness.actionGate.preparePolicyAcceptanceApproval({
        approvalId: "h1policy-program-missing",
        operatorId: TEST_OPERATOR_ID,
        programLocalRef: initial.programLocalRef,
        snapshotDigest: committed.snapshot.snapshotDigest,
        createdAt: LATER,
      }),
    ).toThrow("HACKERONE_SNAPSHOT_ACCEPTANCE_REQUIRES_CURRENT");

    harness.metadata.replaceAuthenticatedApiCatalog([changedProgram], LATER);
    expect(harness.metadata.getProgram(initial.programLocalRef)).toMatchObject({
      catalogActive: true,
      catalogDriftPending: true,
      currentSnapshotDigest: committed.snapshot.snapshotDigest,
    });
    expect(() =>
      harness.actionGate.preparePolicyAcceptanceApproval({
        approvalId: "h1policy-program-returned-without-detail-sync",
        operatorId: TEST_OPERATOR_ID,
        programLocalRef: initial.programLocalRef,
        snapshotDigest: committed.snapshot.snapshotDigest,
        createdAt: LATER,
      }),
    ).toThrow("HACKERONE_SNAPSHOT_ACCEPTANCE_REQUIRES_CURRENT");
  });

  it("persists and consumes the per-operation total and per-minute budgets", () => {
    vi.useFakeTimers();
    vi.setSystemTime(AT);
    const totalHarness = activatedHarness(runtime(2, 100));
    consume(
      totalHarness.actionGate,
      totalHarness.runtime,
      "operation-total",
      "proposal-total-1",
    );
    consume(
      totalHarness.actionGate,
      totalHarness.runtime,
      "operation-total",
      "proposal-total-2",
    );

    expect(() =>
      reserve(
        totalHarness.actionGate,
        totalHarness.runtime,
        "operation-total",
        "proposal-total-3",
      ),
    ).toThrow("HACKERONE_REQUEST_BUDGET_EXCEEDED");
    expect(totalHarness.actionGate.listAttempts()).toHaveLength(2);

    const minuteHarness = activatedHarness(runtime(10, 2));
    consume(
      minuteHarness.actionGate,
      minuteHarness.runtime,
      "operation-minute-1",
      "proposal-minute-1",
    );
    consume(
      minuteHarness.actionGate,
      minuteHarness.runtime,
      "operation-minute-2",
      "proposal-minute-2",
    );
    expect(() =>
      reserve(
        minuteHarness.actionGate,
        minuteHarness.runtime,
        "operation-minute-3",
        "proposal-minute-3",
      ),
    ).toThrow("HACKERONE_REQUEST_BUDGET_EXCEEDED");

    vi.setSystemTime(Date.parse(AT) + 60_001);
    expect(
      reserve(
        minuteHarness.actionGate,
        minuteHarness.runtime,
        "operation-minute-3",
        "proposal-minute-3",
      ).attemptIndex,
    ).toBe(1);
  });

  it("binds signed activation evidence to the exact request-budget runtime", () => {
    vi.useFakeTimers();
    vi.setSystemTime(AT);
    const activated = activatedHarness(runtime(10, 10));
    const changedRuntime = runtime(11, 10);
    const changedGate = new HackerOneMetadataActionGate(
      activated.database,
      activated.controlPlane,
      changedRuntime,
    );

    expect(() =>
      reserve(
        changedGate,
        changedRuntime,
        "operation-runtime-budget-drift",
        "proposal-runtime-budget-drift",
      ),
    ).toThrow("HACKERONE_ACTIVATION_EVIDENCE_INVALID");
    expect(changedGate.listAttempts()).toEqual([]);
  });

  it("keeps the per-minute budget consumed across disable and reactivation", () => {
    vi.useFakeTimers();
    vi.setSystemTime(AT);
    const state = runtime(10, 1);
    const harness = activatedHarness(state);
    consume(
      harness.actionGate,
      state,
      "operation-before-reactivation",
      "proposal-before-reactivation",
    );
    const enabled = harness.metadata.getIntegrationState();
    harness.metadata.setAdapterEnabled(enabled.revision, false);

    vi.setSystemTime(LATER);
    const approval = harness.actionGate.prepareActivationApproval({
      approvalId: "h1activation-reactivated",
      operatorId: TEST_OPERATOR_ID,
      credentialFingerprint: FINGERPRINT,
      createdAt: LATER,
    });
    decideTestApproval(harness.controlPlane, {
      approvalId: approval.id,
      decision: "accepted",
      userAction: "explicit_test_hackerone_reactivation",
      issuedAt: LATER,
    });

    expect(() =>
      reserve(
        harness.actionGate,
        state,
        "operation-after-reactivation",
        "proposal-after-reactivation",
      ),
    ).toThrow("HACKERONE_REQUEST_BUDGET_EXCEEDED");
    expect(harness.actionGate.listAttempts()).toHaveLength(1);
  });

  it("keeps per-operation and crash-active budgets consumed across reactivation", () => {
    vi.useFakeTimers();
    vi.setSystemTime(AT);
    const totalState = runtime(1, 100);
    const totalHarness = activatedHarness(totalState);
    consume(
      totalHarness.actionGate,
      totalState,
      "operation-global-total",
      "proposal-global-total-before",
    );
    reactivate(totalHarness, LATER, "h1activation-global-total");
    vi.setSystemTime(LATER);
    expect(() =>
      reserve(
        totalHarness.actionGate,
        totalState,
        "operation-global-total",
        "proposal-global-total-after",
      ),
    ).toThrow("HACKERONE_REQUEST_BUDGET_EXCEEDED");

    vi.setSystemTime(AT);
    const activeState = runtime(10, 100);
    const activeHarness = activatedHarness(activeState);
    reserve(
      activeHarness.actionGate,
      activeState,
      "operation-crash-before-reactivation",
      "proposal-crash-before-reactivation",
    );
    reactivate(activeHarness, LATER, "h1activation-crash-reactivated");
    vi.setSystemTime(LATER);
    expect(() =>
      reserve(
        activeHarness.actionGate,
        activeState,
        "operation-after-crash-reactivation",
        "proposal-after-crash-reactivation",
      ),
    ).toThrow("HACKERONE_REQUEST_BUDGET_EXCEEDED");
    expect(activeHarness.actionGate.listAttempts()).toMatchObject([
      { status: "reserved", attemptIndex: 1 },
    ]);
  });

  it("keeps crash reservations blocking and never refunds an aborted unit", () => {
    vi.useFakeTimers();
    vi.setSystemTime(AT);
    const harness = activatedHarness(runtime(1, 100));
    const stranded = reserve(
      harness.actionGate,
      harness.runtime,
      "operation-crash",
      "proposal-crash-1",
    );
    const restartedGate = new HackerOneMetadataActionGate(
      harness.database,
      harness.controlPlane,
      harness.runtime,
    );

    expect(() =>
      reserve(
        restartedGate,
        harness.runtime,
        "operation-other",
        "proposal-other-1",
      ),
    ).toThrow("HACKERONE_REQUEST_BUDGET_EXCEEDED");
    restartedGate.abortReservation(stranded);
    expect(() =>
      reserve(
        restartedGate,
        harness.runtime,
        "operation-crash",
        "proposal-crash-2",
      ),
    ).toThrow("HACKERONE_REQUEST_BUDGET_EXCEEDED");
    expect(
      reserve(
        restartedGate,
        harness.runtime,
        "operation-other",
        "proposal-other-1",
      ).attemptIndex,
    ).toBe(1);
    expect(
      restartedGate
        .listAttempts()
        .map(({ status }) => status)
        .sort(),
    ).toEqual(["aborted", "reserved"]);
  });

  it("blocks disabled runtime, disabled adapter, and an engaged kill switch", () => {
    const disabledHarness = createClearedHarness(
      resolveHackerOneMetadataReadRuntime(undefined),
    );
    expect(() =>
      disabledHarness.actionGate.prepareActivationApproval({
        approvalId: "h1activation-disabled-runtime",
        operatorId: TEST_OPERATOR_ID,
        credentialFingerprint: FINGERPRINT,
        createdAt: AT,
      }),
    ).toThrow("EXTERNAL_INTEGRATIONS_DISABLED");

    const rejectedHarness = createClearedHarness(runtime());
    expect(() =>
      reserve(
        rejectedHarness.actionGate,
        runtime(),
        "operation-disabled-adapter",
        "proposal-disabled-adapter",
      ),
    ).toThrow("HACKERONE_ADAPTER_DISABLED");

    const activeHarness = activatedHarness(runtime());
    activeHarness.controlPlane.setKillSwitch(true, TEST_OPERATOR_ID, LATER);
    expect(() =>
      reserve(
        activeHarness.actionGate,
        activeHarness.runtime,
        "operation-killed",
        "proposal-killed",
      ),
    ).toThrow("HACKERONE_KILL_SWITCH");
    expect(activeHarness.actionGate.listAttempts()).toEqual([]);
  });

  it("binds every handle-based authorization to the authenticated synchronized catalog", () => {
    vi.useFakeTimers();
    vi.setSystemTime(AT);
    const harness = activatedHarness(runtime());
    const detailPlan = createInitialHackerOneMetadataRequestPlan(
      {
        version: 1,
        capability: HACKERONE_METADATA_READ_CAPABILITY,
        operation: "program",
        handle: "action_gate_synthetic_program",
        page: null,
      },
      harness.runtime,
      {
        consumedRequests: 0,
        activeRequests: 0,
        requestsInCurrentMinute: 0,
      },
    );

    expect(() =>
      harness.actionGate.authorizeAndReserve({
        operationId: "operation-unsynchronized-handle",
        proposalId: "proposal-unsynchronized-handle",
        plan: detailPlan,
        credentialFingerprint: FINGERPRINT,
      }),
    ).toThrow("HACKERONE_ACTION_SCOPE_BLOCKED");
    expect(harness.actionGate.listAttempts()).toEqual([]);

    harness.metadata.replaceAuthenticatedApiCatalog([program()]);
    const authorization = harness.actionGate.authorizeAndReserve({
      operationId: "operation-synchronized-handle",
      proposalId: "proposal-synchronized-handle",
      plan: detailPlan,
      credentialFingerprint: FINGERPRINT,
    });
    expect(authorization.plan.handle).toBe("action_gate_synthetic_program");
    harness.actionGate.abortReservation(authorization);
  });

  it("rejects forged and proxy request plans, authorizations, and transport plans", () => {
    vi.useFakeTimers();
    vi.setSystemTime(AT);
    const harness = activatedHarness(runtime());
    const plan = requestPlan(harness.runtime);

    expect(() =>
      harness.actionGate.authorizeAndReserve({
        operationId: "operation-forged-plan",
        proposalId: "proposal-forged-plan",
        plan: { ...plan },
        credentialFingerprint: FINGERPRINT,
      }),
    ).toThrow();
    expect(() =>
      harness.actionGate.authorizeAndReserve({
        operationId: "operation-proxy-plan",
        proposalId: "proposal-proxy-plan",
        plan: new Proxy(plan, {}),
        credentialFingerprint: FINGERPRINT,
      }),
    ).toThrow();
    expect(harness.actionGate.listAttempts()).toEqual([]);

    const authorization = reserve(
      harness.actionGate,
      harness.runtime,
      "operation-authentic",
      "proposal-authentic",
    );
    expect(() =>
      harness.actionGate.start({
        ...authorization,
      }),
    ).toThrow("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
    expect(() =>
      harness.actionGate.start(new Proxy(authorization, {})),
    ).toThrow("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");

    const transportPlan = harness.actionGate.start(authorization);
    expect(
      captureAuthorizedHackerOneMetadataTransportPlan(transportPlan),
    ).toEqual({
      authorizationId: authorization.authorizationId,
      proposalDigest: authorization.proposalDigest,
      credentialFingerprint: FINGERPRINT,
      endpointClass: "programs",
      requestTarget: "/v1/hackers/programs?page[number]=1&page[size]=10",
    });
    expect(() =>
      captureAuthorizedHackerOneMetadataTransportPlan(transportPlan),
    ).toThrow("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
    expect(() =>
      captureAuthorizedHackerOneMetadataTransportPlan({ ...transportPlan }),
    ).toThrow("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
    expect(() =>
      captureAuthorizedHackerOneMetadataTransportPlan(
        new Proxy(transportPlan, {}),
      ),
    ).toThrow("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
  });

  it("makes activation, acceptance, and action-attempt evidence immutable", () => {
    vi.useFakeTimers();
    vi.setSystemTime(AT);
    const harness = activatedHarness(runtime());
    const current = persistSnapshot(harness.metadata, program(), AT, null);
    const approval = harness.actionGate.preparePolicyAcceptanceApproval({
      approvalId: "h1policy-immutable",
      operatorId: TEST_OPERATOR_ID,
      programLocalRef: current.programLocalRef,
      snapshotDigest: current.snapshotDigest,
      createdAt: AT,
    });
    decideTestApproval(harness.controlPlane, {
      approvalId: approval.id,
      decision: "accepted",
      userAction: "explicit_test_immutable_hackerone_policy_acceptance",
      issuedAt: AT,
    });
    consume(
      harness.actionGate,
      harness.runtime,
      "operation-immutable",
      "proposal-immutable",
      "succeeded",
    );
    const attempt = harness.actionGate.listAttempts()[0]!;

    expect(() =>
      harness.database.run(
        `UPDATE hackerone_metadata_action_attempts SET proposal_id='forged'
         WHERE authorization_id=?`,
        attempt.authorizationId,
      ),
    ).toThrow("HACKERONE_ACTION_ATTEMPT_IMMUTABLE");
    expect(() =>
      harness.database.run(
        `UPDATE hackerone_metadata_action_attempts SET status='failed'
         WHERE authorization_id=?`,
        attempt.authorizationId,
      ),
    ).toThrow("HACKERONE_ACTION_ATTEMPT_TRANSITION_INVALID");
    expect(() =>
      harness.database.run(
        "DELETE FROM hackerone_metadata_action_attempts WHERE authorization_id=?",
        attempt.authorizationId,
      ),
    ).toThrow("HACKERONE_ACTION_ATTEMPT_IMMUTABLE");
    expect(() =>
      harness.database.run(
        `UPDATE hackerone_metadata_activation_bindings
         SET credential_fingerprint='${"0".repeat(64)}'`,
      ),
    ).toThrow("HACKERONE_ACTIVATION_IMMUTABLE");
    expect(() =>
      harness.database.run(
        "DELETE FROM hackerone_metadata_activation_bindings",
      ),
    ).toThrow("HACKERONE_ACTIVATION_IMMUTABLE");
    expect(() =>
      harness.database.run(
        `UPDATE hackerone_policy_acceptances SET accepted_by='forged'
         WHERE snapshot_digest=?`,
        current.snapshotDigest,
      ),
    ).toThrow("HACKERONE_POLICY_ACCEPTANCE_IMMUTABLE");
    expect(() =>
      harness.database.run(
        "DELETE FROM hackerone_policy_acceptances WHERE snapshot_digest=?",
        current.snapshotDigest,
      ),
    ).toThrow("HACKERONE_POLICY_ACCEPTANCE_IMMUTABLE");
  });
});

function runtime(
  maximum = 10,
  perMinute = 10,
): HackerOneMetadataReadRuntimeState {
  return resolveHackerOneMetadataReadRuntime({
    version: 1,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    external_integrations_enabled: true,
    enabled: true,
    request_budget: {
      max_requests_total: maximum,
      requests_per_minute: perMinute,
      max_concurrency: 1,
    },
  });
}

function createClearedHarness(
  state: HackerOneMetadataReadRuntimeState,
): ClearedHarness {
  const database = track(ControlPlaneDatabase.memory());
  const controlPlane = createTestControlPlaneStore(database, AT);
  const metadata = new HackerOneMetadataStore(database);
  const actionGate = new HackerOneMetadataActionGate(
    database,
    controlPlane,
    state,
  );
  clearTestKillSwitch(controlPlane, AT);
  return Object.freeze({
    database,
    controlPlane,
    metadata,
    actionGate,
    close: () => {
      database.close();
    },
  });
}

function activatedHarness(state: HackerOneMetadataReadRuntimeState) {
  const harness = createActivatedHackerOneActionHarness(state, FINGERPRINT, AT);
  databases.add(harness.database);
  return Object.freeze({ ...harness, runtime: state });
}

function reactivate(
  harness: Pick<ClearedHarness, "actionGate" | "controlPlane" | "metadata">,
  at: string,
  approvalId: string,
): void {
  const enabled = harness.metadata.getIntegrationState();
  harness.metadata.setAdapterEnabled(enabled.revision, false);
  const approval = harness.actionGate.prepareActivationApproval({
    approvalId,
    operatorId: TEST_OPERATOR_ID,
    credentialFingerprint: FINGERPRINT,
    createdAt: at,
  });
  decideTestApproval(harness.controlPlane, {
    approvalId: approval.id,
    decision: "accepted",
    userAction: `explicit_test_${approvalId}`,
    issuedAt: at,
  });
}

function requestPlan(
  state: HackerOneMetadataReadRuntimeState,
): HackerOneMetadataRequestPlan {
  return createInitialHackerOneMetadataRequestPlan(
    {
      version: 1,
      capability: HACKERONE_METADATA_READ_CAPABILITY,
      operation: "programs",
      handle: null,
      page: { number: 1, size: 10 },
    },
    state,
    {
      consumedRequests: 0,
      activeRequests: 0,
      requestsInCurrentMinute: 0,
    },
  );
}

function reserve(
  gate: HackerOneMetadataActionGate,
  state: HackerOneMetadataReadRuntimeState,
  operationId: string,
  proposalId: string,
): StoreBoundHackerOneMetadataAuthorization {
  return gate.authorizeAndReserve({
    operationId,
    proposalId,
    plan: requestPlan(state),
    credentialFingerprint: FINGERPRINT,
  });
}

function consume(
  gate: HackerOneMetadataActionGate,
  state: HackerOneMetadataReadRuntimeState,
  operationId: string,
  proposalId: string,
  outcome: "aborted" | "failed" | "succeeded" = "failed",
): void {
  const authorization = reserve(gate, state, operationId, proposalId);
  gate.start(authorization);
  gate.settle(authorization, outcome);
}

function program(overrides: Partial<HackerOneProgram> = {}): HackerOneProgram {
  return Object.freeze({
    hackerOneId: "action-gate-synthetic-program",
    handle: "action_gate_synthetic_program",
    name: "Action Gate Synthetic Program",
    currency: "USD",
    policy: "Synthetic local policy requiring explicit human review.",
    submissionState: "open",
    programState: "public_mode",
    offersBounties: true,
    openScope: false,
    goldStandardSafeHarbor: true,
    bookmarked: false,
    ownReportCount: 0,
    ownValidReportCount: 0,
    startedAcceptingAt: "2026-01-01T00:00:00.000Z",
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: AT,
    synchronizedAt: AT,
    source: "hackerone_api_authenticated",
    ...overrides,
  });
}

function persistSnapshot(
  metadata: HackerOneMetadataStore,
  value: HackerOneProgram,
  fetchedAt: string,
  previousSnapshotDigest: string | null,
) {
  const stored = metadata.replaceAuthenticatedApiCatalog([value])[0]!;
  const snapshot = createHackerOnePolicySnapshot({
    program: value,
    structuredScopes: [],
    scopeExclusions: [],
    fetchedAt,
    previousSnapshotDigest,
  });
  const committed = metadata.commitSnapshot(stored.localRef, snapshot);
  return Object.freeze({
    programLocalRef: committed.programLocalRef,
    snapshotDigest: committed.snapshot.snapshotDigest,
  });
}

function mutateSignature(value: string): string {
  return `${value.startsWith("A") ? "B" : "A"}${value.slice(1)}`;
}

function track(database: ControlPlaneDatabaseType): ControlPlaneDatabaseType {
  databases.add(database);
  return database;
}
