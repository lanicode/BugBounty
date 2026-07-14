import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ApprovalQueue,
  ControlPlaneDatabase,
  ControlPlaneStore,
  type ApprovalDecisionSigningContext,
  type ApprovalRecord,
} from "../../packages/control-plane/index.js";
import type { SignedApprovalDecision } from "../../packages/operator-auth/index.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
  decideTestApproval,
  enrollTestOperator,
  setTestControlPlaneTime,
  signTestApprovalDecision,
  signTestOperatorEnrollment,
  TEST_OPERATOR_SIGNER,
} from "../fixtures/operator-auth.factory.js";

const ENROLLED_AT = "2026-07-14T12:00:00.000Z";
const FIRST_DECISION_AT = "2026-07-14T12:00:10.000Z";
const SECOND_DECISION_AT = "2026-07-14T12:00:20.000Z";
const UNSIGNED_CLEAR_AT = "2026-07-14T12:00:40.000Z";
const REPLAYED_NONCE = Buffer.alloc(32, 0x5a).toString("base64url");

describe("file-backed operator authentication evidence", () => {
  it("reopens credentials, signed approval and kill-clear evidence and keeps the nonce consumed", async () => {
    await withDatabaseFile(async (path) => {
      let database: ControlPlaneDatabase | undefined =
        await ControlPlaneDatabase.file(path);
      try {
        let store = createTestControlPlaneStore(database, ENROLLED_AT);
        enrollTestOperator(store, ENROLLED_AT);
        clearTestKillSwitch(store, ENROLLED_AT);
        const controlPlaneId = store.getControlPlaneId();
        const credential = store.getLocalOperatorCredential();
        expect(credential).toEqual(TEST_OPERATOR_SIGNER.credential);

        const approval = persistApproval(store, "persisted-signed-approval");
        const sessionId = enrolledSessionId(database);
        const signed = signApprovalDecision(
          store.describeApprovalDecision(approval.id),
          sessionId,
          REPLAYED_NONCE,
          FIRST_DECISION_AT,
        );
        setTestControlPlaneTime(store, FIRST_DECISION_AT);
        const decided = store.decideApproval(signed);
        const decisionEvidence = store.requireAuthenticatedApprovalDecision(
          decided,
          decided.payloadHash,
        );
        expect(store.isKillSwitchActive()).toBe(false);
        expect(count(database, "signed_approval_decisions")).toBe(1);
        expect(count(database, "signed_kill_switch_clears")).toBe(1);

        database.close();
        database = undefined;

        database = await ControlPlaneDatabase.file(path);
        store = createTestControlPlaneStore(database, SECOND_DECISION_AT);
        expect(store.getControlPlaneId()).toBe(controlPlaneId);
        expect(store.getLocalOperatorCredential()).toEqual(credential);
        expect(store.isKillSwitchActive()).toBe(false);
        const reopenedApproval = requiredApproval(
          store,
          "persisted-signed-approval",
        );
        expect(reopenedApproval).toMatchObject({
          status: "accepted",
          revision: 1,
        });
        expect(
          store.requireAuthenticatedApprovalDecision(
            reopenedApproval,
            reopenedApproval.payloadHash,
          ),
        ).toEqual(decisionEvidence);
        expect(count(database, "local_operator_credentials")).toBe(1);
        expect(count(database, "signed_approval_decisions")).toBe(1);
        expect(count(database, "signed_kill_switch_clears")).toBe(1);

        const replayTarget = persistApproval(store, "nonce-replay-target");
        const replay = signApprovalDecision(
          store.describeApprovalDecision(replayTarget.id),
          sessionId,
          REPLAYED_NONCE,
          SECOND_DECISION_AT,
        );
        expect(() => store.decideApproval(replay)).toThrow(
          /operator_signed_statements\.nonce/u,
        );
        expect(requiredApproval(store, replayTarget.id)).toMatchObject({
          status: "open",
          revision: 0,
        });
        expect(
          database.get(
            "SELECT count(*) AS value FROM operator_signed_statements WHERE nonce=?",
            REPLAYED_NONCE,
          )?.["value"],
        ).toBe(1);
      } finally {
        close(database);
      }
    });
  });

  it("blocks UPDATE and DELETE for every persisted credential and signature-evidence table", async () => {
    await withDatabaseFile(async (path) => {
      const database = await ControlPlaneDatabase.file(path);
      try {
        const store = createTestControlPlaneStore(database, ENROLLED_AT);
        enrollTestOperator(store, ENROLLED_AT);
        clearTestKillSwitch(store, ENROLLED_AT);
        const approval = persistApproval(store, "immutable-signed-approval");
        const decided = decideTestApproval(store, {
          approvalId: approval.id,
          decision: "accepted",
          userAction: "explicit_local_immutability_test",
          issuedAt: FIRST_DECISION_AT,
        });

        const guards = [
          {
            table: "operator_signed_statements",
            column: "signature_base64url",
            code: "OPERATOR_STATEMENT_IMMUTABLE",
          },
          {
            table: "local_operator_credentials",
            column: "operator_id",
            code: "OPERATOR_CREDENTIAL_IMMUTABLE",
          },
          {
            table: "signed_approval_decisions",
            column: "user_action",
            code: "SIGNED_APPROVAL_DECISION_IMMUTABLE",
          },
          {
            table: "signed_kill_switch_clears",
            column: "user_action",
            code: "SIGNED_KILL_SWITCH_CLEAR_IMMUTABLE",
          },
        ] as const;

        for (const guard of guards) {
          const before = count(database, guard.table);
          expect(() =>
            database.run(
              `UPDATE ${guard.table} SET ${guard.column}=${guard.column}`,
            ),
          ).toThrow(guard.code);
          expect(() => database.run(`DELETE FROM ${guard.table}`)).toThrow(
            guard.code,
          );
          expect(count(database, guard.table)).toBe(before);
        }

        expect(() =>
          database.run(
            "UPDATE control_plane_identity SET control_plane_id=?",
            "f".repeat(64),
          ),
        ).toThrow("CONTROL_PLANE_IDENTITY_IMMUTABLE");
        expect(() =>
          database.run("DELETE FROM control_plane_identity"),
        ).toThrow("CONTROL_PLANE_IDENTITY_IMMUTABLE");

        expect(store.getLocalOperatorCredential()).toEqual(
          TEST_OPERATOR_SIGNER.credential,
        );
        expect(store.isKillSwitchActive()).toBe(false);
        expect(
          store.requireAuthenticatedApprovalDecision(
            decided,
            decided.payloadHash,
          ),
        ).toMatchObject({ keyRevision: 1 });
      } finally {
        database.close();
      }
    });
  });

  it("rejects raw unsigned approval and kill-clear transitions", async () => {
    await withDatabaseFile(async (path) => {
      const database = await ControlPlaneDatabase.file(path);
      try {
        const store = createTestControlPlaneStore(database, ENROLLED_AT);
        enrollTestOperator(store, ENROLLED_AT);
        const approval = persistApproval(store, "unsigned-transition");

        expect(() =>
          database.run(
            `INSERT INTO approvals(
              id,kind,summary,technical_details,impact,policy_version,
              policy_hash,created_at,status,decided_at,decided_by,user_action,
              audit_reference,payload_hash,revision
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            "unsigned-decided-insert",
            "privacy_alert",
            "Unsigned decided insert",
            "Must be blocked by the v5 trigger.",
            "No external action is available.",
            null,
            null,
            ENROLLED_AT,
            "accepted",
            FIRST_DECISION_AT,
            TEST_OPERATOR_SIGNER.credential.operator_id,
            "unsigned_direct_insert",
            "audit:unsigned-decided-insert",
            "a".repeat(64),
            1,
          ),
        ).toThrow("SIGNED_APPROVAL_DECISION_REQUIRED");

        expect(() =>
          database.run(
            `UPDATE approvals SET status='accepted',decided_at=?,decided_by=?,
             user_action=?,revision=1 WHERE id=?`,
            FIRST_DECISION_AT,
            TEST_OPERATOR_SIGNER.credential.operator_id,
            "unsigned_direct_approval",
            approval.id,
          ),
        ).toThrow("SIGNED_APPROVAL_DECISION_REQUIRED");
        expect(requiredApproval(store, approval.id)).toMatchObject({
          status: "open",
          revision: 0,
        });
        expect(count(database, "signed_approval_decisions")).toBe(0);

        const currentRevision = requiredInteger(
          database.get(
            "SELECT revision FROM system_state WHERE key='global_kill_switch'",
          )?.["revision"],
        );
        database.run(
          `INSERT INTO control_plane_audit(
            id,occurred_at,action,decision,reason_code,object_reference,payload_hash
          ) VALUES(?,?,?,?,?,?,?)`,
          "unsigned-kill-clear-audit",
          UNSIGNED_CLEAR_AT,
          "kill_switch_change",
          "clear",
          "HUMAN_KILL_SWITCH_CLEARED",
          TEST_OPERATOR_SIGNER.credential.operator_id,
          "0".repeat(64),
        );
        expect(() =>
          database.run(
            `UPDATE system_state SET value='clear',revision=?,updated_at=?,
             audit_reference=? WHERE key='global_kill_switch'`,
            currentRevision + 1,
            UNSIGNED_CLEAR_AT,
            "unsigned-kill-clear-audit",
          ),
        ).toThrow("SIGNED_KILL_SWITCH_CLEAR_REQUIRED");
        expect(
          database.get(
            "SELECT value,revision FROM system_state WHERE key='global_kill_switch'",
          ),
        ).toMatchObject({ value: "engaged", revision: currentRevision });
        expect(store.isKillSwitchActive()).toBe(true);
        expect(count(database, "signed_kill_switch_clears")).toBe(0);
      } finally {
        database.close();
      }
    });
  });

  it("blocks clock rollback in the store and SQLite trigger and fails closed on clock errors", async () => {
    await withDatabaseFile(async (path) => {
      const database = await ControlPlaneDatabase.file(path);
      try {
        const store = createTestControlPlaneStore(database, ENROLLED_AT);
        enrollTestOperator(store, ENROLLED_AT);
        clearTestKillSwitch(store, ENROLLED_AT);
        const accepted = persistApproval(store, "clock-high-water");
        decideTestApproval(store, {
          approvalId: accepted.id,
          decision: "accepted",
          userAction: "establish_operator_clock_high_water",
          issuedAt: SECOND_DECISION_AT,
        });

        const rollbackTarget = persistApproval(store, "clock-rollback-target");
        const rollbackDecision = signTestApprovalDecision(store, {
          approvalId: rollbackTarget.id,
          decision: "accepted",
          userAction: "must_not_accept_rolled_back_clock",
          issuedAt: FIRST_DECISION_AT,
        });
        const statementCount = count(database, "operator_signed_statements");
        setTestControlPlaneTime(store, FIRST_DECISION_AT);
        expect(() => store.decideApproval(rollbackDecision)).toThrow(
          "OPERATOR_CLOCK_ROLLBACK",
        );
        expect(requiredApproval(store, rollbackTarget.id)).toMatchObject({
          status: "open",
          revision: 0,
        });
        expect(count(database, "operator_signed_statements")).toBe(
          statementCount,
        );

        const credential = store.getLocalOperatorCredential();
        if (credential === undefined)
          throw new Error("TEST_OPERATOR_CREDENTIAL_MISSING");
        expect(() =>
          database.run(
            `INSERT INTO operator_signed_statements(
              statement_digest,purpose,control_plane_id,operator_id,
              key_fingerprint_sha256,key_revision,session_id,nonce,issued_at,
              expires_at,verified_at,signature_base64url
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
            "e".repeat(64),
            "operator_enrollment",
            store.getControlPlaneId(),
            credential.operator_id,
            credential.key_fingerprint_sha256,
            credential.key_revision,
            Buffer.alloc(32, 0x31).toString("base64url"),
            Buffer.alloc(32, 0x32).toString("base64url"),
            FIRST_DECISION_AT,
            new Date(Date.parse(FIRST_DECISION_AT) + 30_000).toISOString(),
            FIRST_DECISION_AT,
            "A".repeat(86),
          ),
        ).toThrow("OPERATOR_CLOCK_ROLLBACK");
      } finally {
        database.close();
      }
    });

    for (const clock of [
      () => {
        throw new Error("CLOCK_UNAVAILABLE");
      },
      () => new Date(Number.NaN),
    ]) {
      const database = ControlPlaneDatabase.memory();
      try {
        const store = new ControlPlaneStore(database, clock);
        const proof = signTestOperatorEnrollment(store, ENROLLED_AT);
        expect(() => store.enrollLocalOperator(proof)).toThrow(
          /OPERATOR_CLOCK_(?:UNAVAILABLE|INVALID)/u,
        );
        expect(store.getLocalOperatorCredential()).toBeUndefined();
      } finally {
        database.close();
      }
    }
  });
});

function persistApproval(store: ControlPlaneStore, id: string): ApprovalRecord {
  const approval = new ApprovalQueue().enqueue({
    id,
    kind: "privacy_alert",
    summary: `Review ${id}`,
    technicalDetails: "Local persistence-test evidence only.",
    impact: "No external action is available.",
    policyVersion: null,
    policyHash: null,
    createdAt: ENROLLED_AT,
    auditReference: `audit:${id}`,
  });
  store.persistApproval(approval);
  return approval;
}

function signApprovalDecision(
  context: ApprovalDecisionSigningContext,
  sessionId: string,
  nonce: string,
  issuedAt: string,
): SignedApprovalDecision {
  return TEST_OPERATOR_SIGNER.signApprovalDecision({
    controlPlaneId: context.controlPlaneId,
    approvalId: context.approvalId,
    approvalKind: context.approvalKind,
    approvalPayloadHashSha256: context.approvalPayloadHashSha256,
    expectedRevision: context.expectedRevision,
    decision: "accepted",
    userAction: "explicit_local_persistence_test_approval",
    contextDigestSha256: context.contextDigestSha256,
    sessionId,
    nonce,
    issuedAt,
    expiresAt: new Date(Date.parse(issuedAt) + 30_000).toISOString(),
  });
}

function enrolledSessionId(database: ControlPlaneDatabase): string {
  const value = database.get(
    `SELECT session_id FROM operator_signed_statements
     WHERE purpose='operator_enrollment'
     ORDER BY verified_at DESC,statement_digest DESC LIMIT 1`,
  )?.["session_id"];
  if (typeof value !== "string") throw new Error("TEST_SESSION_NOT_FOUND");
  return value;
}

function requiredApproval(
  store: ControlPlaneStore,
  id: string,
): ApprovalRecord {
  const approval = store
    .listApprovals()
    .find((candidate) => candidate.id === id);
  if (approval === undefined) throw new Error("TEST_APPROVAL_NOT_FOUND");
  return approval;
}

function count(database: ControlPlaneDatabase, table: string): number {
  const value = database.get(`SELECT count(*) AS value FROM ${table}`)?.[
    "value"
  ];
  return requiredInteger(value);
}

function requiredInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value))
    throw new Error("TEST_INTEGER_REQUIRED");
  return value;
}

async function withDatabaseFile(
  operation: (path: string) => Promise<void>,
): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "bbc-operator-auth-persistence-"));
  try {
    await operation(join(root, "control-plane.sqlite"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function close(database: ControlPlaneDatabase | undefined): void {
  if (database === undefined) return;
  try {
    database.close();
  } catch {
    // The first close already completed; cleanup must not mask assertions.
  }
}
