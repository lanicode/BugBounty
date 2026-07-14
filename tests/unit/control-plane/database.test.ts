import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CONTROL_PLANE_SCHEMA_VERSION,
  ControlPlaneDatabase,
  isTrustedControlPlaneDatabase,
} from "../../../packages/control-plane/database.js";
import { ApprovalQueue } from "../../../packages/control-plane/approval-queue.js";
import { ControlPlaneStore } from "../../../packages/control-plane/store.js";
import {
  campaign,
  controlPlanePolicy,
  LATER,
  NOW,
  programInput,
} from "../../fixtures/control-plane.factory.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const RESERVED_AT = "2026-07-13T12:30:00.000Z";
const STARTED_AT = "2026-07-13T12:31:00.000Z";
const FINISHED_AT = "2026-07-13T12:32:00.000Z";

describe("ControlPlaneDatabase migrations", () => {
  it("migrates a fresh in-memory database and enforces foreign keys", () => {
    const database = ControlPlaneDatabase.memory();
    expect(database.migrationVersion()).toBe(CONTROL_PLANE_SCHEMA_VERSION);
    expect(() =>
      database.run(
        `INSERT INTO policy_versions(
          program_id,version,normalized_json,policy_text,policy_hash,created_at
        ) VALUES(1,1,'{}','x',?,?)`,
        "a".repeat(64),
        "2026-07-13T00:00:00.000Z",
      ),
    ).toThrow();
    database.close();
  });

  it("rolls back failed transactions", () => {
    const database = ControlPlaneDatabase.memory();
    expect(() =>
      database.transaction(() => {
        database.run(
          "INSERT INTO control_plane_audit VALUES(?,?,?,?,?,?,?)",
          "event-1",
          "2026-07-13T00:00:00.000Z",
          "test",
          "allow",
          "TEST",
          null,
          "a".repeat(64),
        );
        throw new Error("forced");
      }),
    ).toThrow("forced");
    expect(
      database.get("SELECT id FROM control_plane_audit WHERE id='event-1'"),
    ).toBeUndefined();
    database.close();
  });

  it("brands only genuine databases and rejects async transaction callbacks", () => {
    const database = ControlPlaneDatabase.memory();
    expect(isTrustedControlPlaneDatabase(database)).toBe(true);
    expect(isTrustedControlPlaneDatabase({})).toBe(false);
    expect(
      isTrustedControlPlaneDatabase(
        Object.create(ControlPlaneDatabase.prototype) as unknown,
      ),
    ).toBe(false);
    expect(isTrustedControlPlaneDatabase(new Proxy(database, {}))).toBe(false);

    expect(() =>
      database.transaction(() => {
        database.run(
          "INSERT INTO control_plane_audit VALUES(?,?,?,?,?,?,?)",
          "async-event",
          NOW,
          "test",
          "deny",
          "TEST_ASYNC_TRANSACTION",
          null,
          HASH_A,
        );
        return Promise.resolve("unsafe");
      }),
    ).toThrow("CONTROL_PLANE_TRANSACTION_ASYNC");
    expect(
      database.get("SELECT id FROM control_plane_audit WHERE id='async-event'"),
    ).toBeUndefined();
    database.close();
  });

  it("exposes only the structured phase-3 evidence columns", () => {
    const database = ControlPlaneDatabase.memory();
    expect(columnNames(database, "external_action_approval_bindings")).toEqual(
      [...BINDING_COLUMNS].sort(),
    );
    expect(columnNames(database, "external_action_attempts")).toEqual(
      [...ATTEMPT_COLUMNS].sort(),
    );
    database.close();
  });

  it("enforces immutable proposal bindings and single-use attempt transitions", () => {
    const database = ControlPlaneDatabase.memory();
    const store = new ControlPlaneStore(database);
    store.createProgram(programInput(), NOW);
    const policy = controlPlanePolicy();
    store.addPolicyVersion({
      programId: "program-local",
      version: 1,
      policy,
      createdAt: NOW,
    });
    store.insertCampaign(campaign({ policyHash: policy.policyHash }));

    const approval = new ApprovalQueue().enqueue({
      id: "external-action-approval",
      kind: "external_action",
      summary: "Approve one exact local action proposal",
      technicalDetails: `Proposal digest ${HASH_A}`,
      impact: "Allows one deterministic loopback-only mock action.",
      policyVersion: 1,
      policyHash: policy.policyHash,
      createdAt: NOW,
      auditReference: "audit:external-action-approval",
    });
    store.persistApproval(approval);

    expect(() => {
      insertBinding(database, policy.policyHash, {
        proposalDigest: "a".repeat(63),
      });
    }).toThrow();
    insertBinding(database, policy.policyHash);
    const duplicateApproval = new ApprovalQueue().enqueue({
      id: "duplicate-external-action-approval",
      kind: "external_action",
      summary: "Duplicate proposal fixture",
      technicalDetails: `Proposal digest ${HASH_A}`,
      impact: "Must be rejected by the unique proposal binding.",
      policyVersion: 1,
      policyHash: policy.policyHash,
      createdAt: NOW,
      auditReference: "audit:duplicate-external-action-approval",
    });
    store.persistApproval(duplicateApproval);
    expect(() => {
      insertBinding(database, policy.policyHash, {
        approvalId: duplicateApproval.id,
      });
    }).toThrow();
    expect(() =>
      database.run(
        "UPDATE external_action_approval_bindings SET binding_digest=? WHERE approval_id=?",
        HASH_A,
        approval.id,
      ),
    ).toThrow("EXTERNAL_ACTION_APPROVAL_BINDING_IMMUTABLE");
    expect(() =>
      database.run(
        "DELETE FROM external_action_approval_bindings WHERE approval_id=?",
        approval.id,
      ),
    ).toThrow("EXTERNAL_ACTION_APPROVAL_BINDING_IMMUTABLE");

    database.run(
      `UPDATE approvals SET status='accepted',decided_at=?,decided_by=?,
       user_action=?,revision=1 WHERE id=?`,
      LATER,
      "local-reviewer",
      "explicit_external_action_approval",
      approval.id,
    );
    database.run(
      `INSERT INTO control_plane_audit(
        id,occurred_at,action,decision,reason_code,object_reference,payload_hash
      ) VALUES(?,?,?,?,?,?,?)`,
      "decision-audit",
      LATER,
      "approval_decision",
      "accepted",
      "HUMAN_APPROVAL_DECISION",
      approval.id,
      approval.payloadHash,
    );
    database.run(
      `UPDATE external_action_approval_bindings
       SET decision_audit_id=? WHERE approval_id=?`,
      "decision-audit",
      approval.id,
    );
    expect(() =>
      database.run(
        `UPDATE external_action_approval_bindings
         SET decision_audit_id=? WHERE approval_id=?`,
        "decision-audit",
        approval.id,
      ),
    ).toThrow("EXTERNAL_ACTION_APPROVAL_EVIDENCE_INVALID");

    database.run(
      `INSERT INTO control_plane_audit(
        id,occurred_at,action,decision,reason_code,object_reference,payload_hash
      ) VALUES(?,?,?,?,?,?,?)`,
      "reservation-audit",
      RESERVED_AT,
      "external_action_authorization",
      "reserved",
      "EXTERNAL_ACTION_RESERVED",
      "authorization-1",
      HASH_B,
    );
    expect(() => {
      insertAttempt(database, policy.policyHash, { scopeRef: "wrong-scope" });
    }).toThrow("EXTERNAL_ACTION_ATTEMPT_BINDING_INVALID");
    insertAttempt(database, policy.policyHash);

    expect(() =>
      database.run(
        "UPDATE control_plane_audit SET decision='tampered' WHERE id='reservation-audit'",
      ),
    ).toThrow("CONTROL_PLANE_AUDIT_IMMUTABLE");
    expect(() =>
      database.run(
        "DELETE FROM control_plane_audit WHERE id='reservation-audit'",
      ),
    ).toThrow("CONTROL_PLANE_AUDIT_IMMUTABLE");

    expect(() =>
      database.run(
        `UPDATE external_action_attempts
         SET status='succeeded',revision=2,started_at=?,finished_at=?
         WHERE authorization_id='authorization-1'`,
        STARTED_AT,
        FINISHED_AT,
      ),
    ).toThrow("EXTERNAL_ACTION_ATTEMPT_TRANSITION_INVALID");
    database.run(
      `UPDATE external_action_attempts
       SET status='running',revision=1,started_at=?
       WHERE authorization_id='authorization-1'`,
      STARTED_AT,
    );
    database.run(
      `UPDATE external_action_attempts
       SET status='succeeded',revision=2,finished_at=?
       WHERE authorization_id='authorization-1'`,
      FINISHED_AT,
    );
    expect(() =>
      database.run(
        `UPDATE external_action_attempts SET scope_ref='other-scope'
         WHERE authorization_id='authorization-1'`,
      ),
    ).toThrow("EXTERNAL_ACTION_ATTEMPT_BINDING_IMMUTABLE");
    expect(() =>
      database.run(
        "DELETE FROM external_action_attempts WHERE authorization_id='authorization-1'",
      ),
    ).toThrow("EXTERNAL_ACTION_ATTEMPT_IMMUTABLE");
    expect(
      database.get(
        "SELECT status,revision FROM external_action_attempts WHERE authorization_id='authorization-1'",
      ),
    ).toMatchObject({ status: "succeeded", revision: 2 });
    database.close();
  });

  it("binds policy acceptances to the exact persisted hash", () => {
    const database = ControlPlaneDatabase.memory();
    const store = new ControlPlaneStore(database);
    store.createProgram(programInput(), NOW);
    const policy = controlPlanePolicy();
    store.addPolicyVersion({
      programId: "program-local",
      version: 1,
      policy,
      createdAt: NOW,
    });
    expect(() =>
      database.run(
        `INSERT INTO policy_acceptances(
          program_id,version,policy_hash,accepted_by,accepted_at,audit_reference
        ) VALUES(?,?,?,?,?,?)`,
        "program-local",
        1,
        "f".repeat(64),
        "local-reviewer",
        NOW,
        "audit:raw-mismatch",
      ),
    ).toThrow();
    expect(store.getPolicy("program-local", 1)?.acceptance).toBeNull();
    database.close();
  });

  it("reopens idempotently, sets restrictive permissions, and blocks a changed checksum", async () => {
    const root = await mkdtemp(join(tmpdir(), "bbc-control-plane-"));
    const path = join(root, "state.sqlite");
    const first = await ControlPlaneDatabase.file(path);
    first.close();
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    const second = await ControlPlaneDatabase.file(path);
    expect(second.migrationVersion()).toBe(CONTROL_PLANE_SCHEMA_VERSION);
    second.run(
      "UPDATE schema_migrations SET checksum=? WHERE version=1",
      "0".repeat(64),
    );
    second.close();
    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow(
      "CONTROL_PLANE_MIGRATION_INTEGRITY",
    );
    expect((await readFile(path)).byteLength).toBeGreaterThan(0);
  });

  it("blocks unknown future migration versions", async () => {
    const root = await mkdtemp(join(tmpdir(), "bbc-control-plane-future-"));
    const path = join(root, "state.sqlite");
    const database = await ControlPlaneDatabase.file(path);
    database.run(
      "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(?,?,?)",
      CONTROL_PLANE_SCHEMA_VERSION + 1,
      "f".repeat(64),
      "2026-07-13T00:00:00.000Z",
    );
    database.close();
    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow(
      "CONTROL_PLANE_MIGRATION_INTEGRITY",
    );
  });

  it("rejects a legacy acceptance backed by another program's approval", async () => {
    const root = await mkdtemp(join(tmpdir(), "bbc-control-plane-cross-"));
    const path = join(root, "state.sqlite");
    const database = await ControlPlaneDatabase.file(path);
    const store = new ControlPlaneStore(database);
    const policy = controlPlanePolicy();
    for (const [id, name] of [
      ["program-a", "Program A"],
      ["program-b", "Program B"],
    ] as const) {
      store.createProgram({ ...programInput(), id, name }, NOW);
      store.addPolicyVersion({
        programId: id,
        version: 1,
        policy,
        createdAt: NOW,
      });
    }
    database.run(
      `INSERT INTO approvals(
        id,kind,summary,technical_details,impact,policy_version,policy_hash,
        created_at,status,decided_at,decided_by,user_action,audit_reference,
        payload_hash,revision
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      "approval-program-a",
      "program_policy_acceptance",
      "Accept program-a policy version 1",
      "Cross-program migration fixture",
      "Local fixture only",
      1,
      policy.policyHash,
      NOW,
      "accepted",
      NOW,
      "local-reviewer",
      "explicit_local_acceptance",
      "audit:cross-program",
      "b".repeat(64),
      1,
    );
    database.run(
      `INSERT INTO policy_acceptances(
        program_id,version,policy_hash,accepted_by,accepted_at,audit_reference
      ) VALUES(?,?,?,?,?,?)`,
      "program-b",
      1,
      policy.policyHash,
      "local-reviewer",
      NOW,
      "audit:cross-program",
    );

    for (const trigger of [
      "campaigns_exact_policy_insert",
      "campaigns_exact_policy_update",
      "owned_objects_exact_bindings_insert",
      "owned_objects_exact_bindings_update",
      "system_state_kill_switch_insert_guard",
      "system_state_kill_switch_update_guard",
    ])
      database.run(`DROP TRIGGER ${trigger}`);
    for (const index of [
      "policy_versions_exact_binding",
      "campaigns_program_binding",
      "identities_program_binding",
    ])
      database.run(`DROP INDEX ${index}`);
    database.run(`CREATE TABLE system_state_v1 (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      revision INTEGER NOT NULL CHECK (revision >= 0),
      updated_at TEXT NOT NULL
    ) STRICT`);
    database.run(
      `INSERT INTO system_state_v1(key,value,revision,updated_at)
       SELECT key,value,revision,updated_at FROM system_state`,
    );
    database.run("DROP TABLE system_state");
    database.run("ALTER TABLE system_state_v1 RENAME TO system_state");
    database.run("DELETE FROM schema_migrations WHERE version>=2");
    database.close();

    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow();
  });

  it("migrates a phase-2-shaped database fail-closed into phase 3", async () => {
    const root = await mkdtemp(join(tmpdir(), "bbc-control-plane-v4-"));
    const path = join(root, "state.sqlite");
    const database = await ControlPlaneDatabase.file(path);
    const store = new ControlPlaneStore(database);
    store.createProgram(programInput(), NOW);
    const policy = controlPlanePolicy();
    store.addPolicyVersion({
      programId: "program-local",
      version: 1,
      policy,
      createdAt: NOW,
    });
    store.setKillSwitch(false, "local-reviewer", NOW);
    store.insertCampaign(campaign({ policyHash: policy.policyHash }));
    database.run(
      `UPDATE campaigns SET state='running_simulation',revision=3,
       human_approved_by='local-reviewer',human_approved_at=?,
       last_policy_check_at=?,kill_switch_status='clear' WHERE id=?`,
      NOW,
      NOW,
      "campaign-local",
    );
    const legacyApproval = new ApprovalQueue().enqueue({
      id: "legacy-campaign-approval",
      kind: "campaign_contract",
      summary: "Legacy phase-2 approval",
      technicalDetails: "Migration preservation fixture",
      impact: "Local fixture only",
      policyVersion: 1,
      policyHash: policy.policyHash,
      createdAt: NOW,
      auditReference: "audit:legacy-campaign-approval",
    });
    store.persistApproval(legacyApproval);

    database.run("DROP TABLE external_action_attempts");
    database.run("DROP TABLE external_action_approval_bindings");
    database.run("DROP INDEX owned_objects_external_action_binding");
    database.run("DROP TRIGGER control_plane_audit_update_guard");
    database.run("DROP TRIGGER control_plane_audit_delete_guard");
    database.run(`CREATE TABLE approvals_v3 (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL CHECK (kind IN ('program_policy_acceptance','campaign_contract','account_manual_action','tier_3_action','privacy_alert','report_bundle','triage_response')),
      summary TEXT NOT NULL,
      technical_details TEXT NOT NULL,
      impact TEXT NOT NULL,
      policy_version INTEGER,
      policy_hash TEXT,
      created_at TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('open','accepted','rejected')),
      decided_at TEXT,
      decided_by TEXT,
      user_action TEXT,
      audit_reference TEXT NOT NULL UNIQUE,
      payload_hash TEXT NOT NULL,
      revision INTEGER NOT NULL CHECK (revision >= 0)
    ) STRICT`);
    database.run(
      `INSERT INTO approvals_v3 SELECT id,kind,summary,technical_details,impact,
       policy_version,policy_hash,created_at,status,decided_at,decided_by,
       user_action,audit_reference,payload_hash,revision FROM approvals`,
    );
    database.run("DROP TABLE approvals");
    database.run("ALTER TABLE approvals_v3 RENAME TO approvals");
    database.run("DELETE FROM schema_migrations WHERE version=4");
    database.close();

    const migrated = await ControlPlaneDatabase.file(path);
    expect(migrated.migrationVersion()).toBe(4);
    expect(
      migrated.get(
        "SELECT kind FROM approvals WHERE id='legacy-campaign-approval'",
      ),
    ).toMatchObject({ kind: "campaign_contract" });
    expect(
      migrated.get(
        "SELECT state,revision,human_approved_by,kill_switch_status FROM campaigns WHERE id='campaign-local'",
      ),
    ).toMatchObject({
      state: "paused",
      revision: 4,
      human_approved_by: null,
      kill_switch_status: "engaged",
    });
    expect(
      migrated.get(
        "SELECT value,audit_reference FROM system_state WHERE key='global_kill_switch'",
      ),
    ).toMatchObject({ value: "engaged", audit_reference: null });
    expect(
      migrated.get(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name='external_action_attempts'",
      ),
    ).toMatchObject({ name: "external_action_attempts" });
    migrated.close();
  });
});

function insertBinding(
  database: ControlPlaneDatabase,
  policyHash: string,
  options: {
    readonly approvalId?: string;
    readonly proposalDigest?: string;
  } = {},
): void {
  database.run(
    `INSERT INTO external_action_approval_bindings(
      approval_id,proposal_id,proposal_digest,action_id,program_id,campaign_id,
      campaign_revision,campaign_digest,policy_version,policy_hash,scope_ref,
      account_id,account_role,identity_digest,object_ref,ownership_digest,
      payload_ref,operator_id,created_at,expires_at,binding_digest,
      decision_audit_id
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    options.approvalId ?? "external-action-approval",
    "proposal-1",
    options.proposalDigest ?? HASH_A,
    "platform_api_read",
    "program-local",
    "campaign-local",
    0,
    HASH_B,
    1,
    policyHash,
    "scope-1",
    null,
    null,
    null,
    null,
    null,
    null,
    "local-reviewer",
    NOW,
    LATER,
    HASH_C,
    null,
  );
}

function insertAttempt(
  database: ControlPlaneDatabase,
  policyHash: string,
  options: { readonly scopeRef?: string } = {},
): void {
  database.run(
    `INSERT INTO external_action_attempts(
      authorization_id,proposal_id,proposal_digest,action_id,program_id,
      campaign_id,campaign_revision,campaign_digest,policy_version,policy_hash,
      scope_ref,account_id,account_role,identity_digest,object_ref,
      ownership_digest,payload_ref,approval_id,operator_id,evidence_digest,
      units,status,reserved_at,started_at,finished_at,revision,
      reservation_audit_id
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    "authorization-1",
    "proposal-1",
    HASH_A,
    "platform_api_read",
    "program-local",
    "campaign-local",
    0,
    HASH_B,
    1,
    policyHash,
    options.scopeRef ?? "scope-1",
    null,
    null,
    null,
    null,
    null,
    null,
    "external-action-approval",
    "local-reviewer",
    HASH_B,
    1,
    "reserved",
    RESERVED_AT,
    null,
    null,
    0,
    "reservation-audit",
  );
}

function columnNames(
  database: ControlPlaneDatabase,
  table: "external_action_approval_bindings" | "external_action_attempts",
): readonly string[] {
  return database
    .all(`PRAGMA table_info(${table})`)
    .map((row) => row["name"])
    .filter((name): name is string => typeof name === "string")
    .sort();
}

const BINDING_COLUMNS = Object.freeze([
  "account_id",
  "account_role",
  "action_id",
  "approval_id",
  "binding_digest",
  "campaign_digest",
  "campaign_id",
  "campaign_revision",
  "created_at",
  "decision_audit_id",
  "expires_at",
  "identity_digest",
  "object_ref",
  "operator_id",
  "ownership_digest",
  "payload_ref",
  "policy_hash",
  "policy_version",
  "program_id",
  "proposal_digest",
  "proposal_id",
  "scope_ref",
] as const);

const ATTEMPT_COLUMNS = Object.freeze([
  "account_id",
  "account_role",
  "action_id",
  "approval_id",
  "authorization_id",
  "campaign_digest",
  "campaign_id",
  "campaign_revision",
  "evidence_digest",
  "finished_at",
  "identity_digest",
  "object_ref",
  "operator_id",
  "ownership_digest",
  "payload_ref",
  "policy_hash",
  "policy_version",
  "program_id",
  "proposal_digest",
  "proposal_id",
  "reservation_audit_id",
  "reserved_at",
  "revision",
  "scope_ref",
  "started_at",
  "status",
  "units",
] as const);
