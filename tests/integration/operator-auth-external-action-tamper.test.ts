import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ControlPlaneDatabase,
  type ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  DeterministicMockActionRunner,
  ExternalActionPipeline,
  Phase2KillSwitch,
  StoreBoundExternalActionEvaluator,
  enqueueStoreBoundExternalActionApproval,
  prepareStoreBoundExternalActionProposal,
  type ExternalActionProposal,
} from "../../packages/external-actions/index.js";
import {
  resolvePhase2Runtime,
  SAFE_PHASE2_CONFIG,
} from "../../packages/phase2-config/index.js";
import { sha256 } from "../../packages/shared/canonical.js";
import {
  ACTION_DECISION_TIME,
  ACTION_EXECUTION_TIME,
  ACTION_OPERATOR,
  ACTION_TIME,
  seedStoreBoundAction,
} from "../fixtures/store-bound-action.factory.js";

describe("operator-authenticated external-action evidence tampering", () => {
  let database: ControlPlaneDatabase;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(ACTION_TIME);
    database = ControlPlaneDatabase.memory();
  });

  afterEach(() => {
    database.close();
    vi.useRealTimers();
  });

  it("blocks a manipulated signature before reservation and runner invocation", async () => {
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    tamperApprovalSignature(database, seeded.approvalId);
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });

    await expect(
      pipeline(seeded.store, runner).execute(seeded.proposal),
    ).rejects.toThrow("OPERATOR_SIGNATURE_INVALID");
    expect(seeded.store.listExternalActionAttempts()).toEqual([]);
    expect(runner.recordedExecutions()).toEqual([]);
  });

  it("blocks missing signed-decision evidence before reservation and runner invocation", async () => {
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    database.run("DROP TRIGGER signed_approval_decisions_delete_guard");
    expect(
      database.run(
        "DELETE FROM signed_approval_decisions WHERE approval_id=?",
        seeded.approvalId,
      ).changes,
    ).toBe(1);
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });

    await expect(
      pipeline(seeded.store, runner).execute(seeded.proposal),
    ).rejects.toThrow("SIGNED_APPROVAL_DECISION_REQUIRED");
    expect(seeded.store.listExternalActionAttempts()).toEqual([]);
    expect(runner.recordedExecutions()).toEqual([]);
  });

  it("revalidates a manipulated signature after reservation and before runner start", async () => {
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    let tamperedAfterReservation = false;
    const killSwitch = new Phase2KillSwitch({
      readActive: () => {
        if (
          !tamperedAfterReservation &&
          seeded.store
            .listExternalActionAttempts()
            .some(({ status }) => status === "reserved")
        ) {
          tamperApprovalSignature(database, seeded.approvalId);
          tamperedAfterReservation = true;
        }
        return seeded.store.isKillSwitchActive();
      },
    });

    await expect(
      pipeline(seeded.store, runner, killSwitch).execute(seeded.proposal),
    ).rejects.toThrow("OPERATOR_SIGNATURE_INVALID");
    expect(tamperedAfterReservation).toBe(true);
    expect(runner.recordedExecutions()).toEqual([]);
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "aborted", revision: 1 },
    ]);
  });

  it("aborts settlement when signature evidence changes after reservation and start", async () => {
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner(
      { "proposal-1": { mustNotSettleAsSuccess: true } },
      { deferredProposalIds: ["proposal-1"] },
    );

    const pending = pipeline(seeded.store, runner).execute(seeded.proposal);
    expect(runner.recordedExecutions()).toHaveLength(1);
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "running", revision: 1 },
    ]);

    tamperApprovalSignature(database, seeded.approvalId);
    runner.release("proposal-1");

    await expect(pending).rejects.toThrow("OPERATOR_SIGNATURE_INVALID");
    expect(runner.recordedExecutions()).toHaveLength(1);
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "aborted", revision: 2 },
    ]);
    expect(
      seeded.store
        .listAuditEntries()
        .find(
          (entry) =>
            entry.action === "external_action_settlement" &&
            entry.objectReference === "proposal-1",
        ),
    ).toMatchObject({
      decision: "aborted",
      reasonCode: "OPERATOR_SIGNATURE_INVALID",
    });
  });

  it("does not authorize a relationally complete legacy accepted row without a signature", async () => {
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    const { proposal, approvalId } = createUnsignedLegacyApproval(
      database,
      seeded.store,
      seeded.campaign.id,
    );
    expect(
      seeded.store
        .listApprovals()
        .find((approval) => approval.id === approvalId),
    ).toMatchObject({ status: "accepted", revision: 1 });
    expect(
      database.get(
        "SELECT approval_id FROM signed_approval_decisions WHERE approval_id=?",
        approvalId,
      ),
    ).toBeUndefined();
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-legacy": { unexpected: true },
    });

    await expect(
      pipeline(seeded.store, runner).execute(proposal),
    ).rejects.toThrow("SIGNED_APPROVAL_DECISION_REQUIRED");
    expect(seeded.store.listExternalActionAttempts()).toEqual([]);
    expect(runner.recordedExecutions()).toEqual([]);
  });
});

function pipeline(
  store: ControlPlaneStore,
  runner: DeterministicMockActionRunner,
  killSwitch = new Phase2KillSwitch({
    readActive: () => store.isKillSwitchActive(),
  }),
): ExternalActionPipeline {
  return new ExternalActionPipeline(
    resolvePhase2Runtime(SAFE_PHASE2_CONFIG, {
      secretsAvailable: false,
      externalAdapterAvailable: false,
    }),
    runner,
    killSwitch,
    new StoreBoundExternalActionEvaluator(store),
  );
}

function tamperApprovalSignature(
  database: ControlPlaneDatabase,
  approvalId: string,
): void {
  const row = database.get(
    `SELECT s.statement_digest,s.signature_base64url
     FROM signed_approval_decisions d
     JOIN operator_signed_statements s
       ON s.statement_digest=d.statement_digest
     WHERE d.approval_id=?`,
    approvalId,
  );
  const digest = row?.["statement_digest"];
  const signature = row?.["signature_base64url"];
  if (typeof digest !== "string" || typeof signature !== "string")
    throw new Error("TEST_SIGNED_APPROVAL_EVIDENCE_MISSING");
  const replacement = `${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;
  database.run("DROP TRIGGER operator_signed_statements_update_guard");
  expect(
    database.run(
      `UPDATE operator_signed_statements SET signature_base64url=?
       WHERE statement_digest=?`,
      replacement,
      digest,
    ).changes,
  ).toBe(1);
}

function createUnsignedLegacyApproval(
  database: ControlPlaneDatabase,
  store: ControlPlaneStore,
  campaignId: string,
): { readonly proposal: ExternalActionProposal; readonly approvalId: string } {
  const proposal = prepareStoreBoundExternalActionProposal(store, {
    proposalId: "proposal-legacy",
    actionId: "platform_api_read",
    campaignRef: campaignId,
    accountRef: null,
    objectRef: null,
    payloadRef: null,
    approvalRef: "action-approval-legacy",
    operatorRef: ACTION_OPERATOR,
  });
  const approval = enqueueStoreBoundExternalActionApproval(store, proposal);
  const auditId = `approval-${sha256(
    `${approval.id}\u0000${ACTION_DECISION_TIME}\u0000accepted`,
  ).slice(0, 32)}`;

  database.run("DROP TRIGGER approvals_signed_decision_guard");
  database.run("DROP TRIGGER external_action_approval_binding_decision_guard");
  expect(
    database.run(
      `UPDATE approvals SET status='accepted',decided_at=?,decided_by=?,
       user_action='approve_store_bound_external_action',revision=1
       WHERE id=? AND status='open' AND revision=0`,
      ACTION_DECISION_TIME,
      ACTION_OPERATOR,
      approval.id,
    ).changes,
  ).toBe(1);
  database.run(
    `INSERT INTO control_plane_audit(
      id,occurred_at,action,decision,reason_code,object_reference,payload_hash
    ) VALUES(?,?,'approval_decision','accepted','HUMAN_APPROVAL_DECISION',?,?)`,
    auditId,
    ACTION_DECISION_TIME,
    approval.id,
    approval.payloadHash,
  );
  expect(
    database.run(
      `UPDATE external_action_approval_bindings SET decision_audit_id=?
       WHERE approval_id=? AND decision_audit_id IS NULL`,
      auditId,
      approval.id,
    ).changes,
  ).toBe(1);
  return Object.freeze({ proposal, approvalId: approval.id });
}
