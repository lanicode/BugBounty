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
import { externalActionApprovalBindingDigest } from "../../../packages/control-plane/external-action-evidence.js";
import {
  campaign,
  controlPlanePolicy,
  LATER,
  NOW,
  programInput,
} from "../../fixtures/control-plane.factory.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
  decideTestApproval,
  enrollTestOperator,
} from "../../fixtures/operator-auth.factory.js";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
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
    const store = createTestControlPlaneStore(database, NOW);
    enrollTestOperator(store, NOW);
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

    expect(() =>
      database.run(
        `UPDATE approvals SET status='accepted',decided_at=?,decided_by=?,
         user_action=?,revision=1 WHERE id=?`,
        LATER,
        "local-reviewer",
        "explicit_external_action_approval",
        approval.id,
      ),
    ).toThrow("SIGNED_APPROVAL_DECISION_REQUIRED");
    clearTestKillSwitch(store, NOW);
    decideTestApproval(store, {
      approvalId: approval.id,
      decision: "accepted",
      userAction: "explicit_external_action_approval",
      issuedAt: LATER,
    });
    const decisionAuditId = database.get(
      `SELECT decision_audit_id FROM external_action_approval_bindings
       WHERE approval_id=?`,
      approval.id,
    )?.["decision_audit_id"];
    expect(typeof decisionAuditId).toBe("string");
    expect(() =>
      database.run(
        `UPDATE external_action_approval_bindings
         SET decision_audit_id=? WHERE approval_id=?`,
        decisionAuditId as string,
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
    const store = createTestControlPlaneStore(database, NOW);
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
    const store = createTestControlPlaneStore(database, NOW);
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
    database.run("DROP TRIGGER approvals_signed_insert_guard");
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

  it("migrates a phase-3-shaped database fail-closed into phase 4", async () => {
    const root = await mkdtemp(join(tmpdir(), "bbc-control-plane-v5-"));
    const path = join(root, "state.sqlite");
    const database = await ControlPlaneDatabase.file(path);
    const store = createTestControlPlaneStore(database, NOW);
    enrollTestOperator(store, NOW);
    clearTestKillSwitch(store, NOW);
    store.createProgram(programInput(), NOW);
    const policy = controlPlanePolicy();
    store.addPolicyVersion({
      programId: "program-local",
      version: 1,
      policy,
      createdAt: NOW,
    });
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
      id: "legacy-policy-approval",
      kind: "program_policy_acceptance",
      summary: "Accept program-local policy version 1",
      technicalDetails: "Unsigned Phase-3 migration fixture",
      impact: "Local fixture only",
      policyVersion: 1,
      policyHash: policy.policyHash,
      createdAt: NOW,
      auditReference: "audit:legacy-policy-approval",
    });
    store.persistApproval(legacyApproval);

    for (const trigger of [
      "operator_signed_statements_update_guard",
      "operator_signed_statements_delete_guard",
      "local_operator_credentials_insert_guard",
      "local_operator_credentials_update_guard",
      "local_operator_credentials_delete_guard",
      "signed_approval_decisions_insert_guard",
      "signed_approval_decisions_update_guard",
      "signed_approval_decisions_delete_guard",
      "approvals_signed_insert_guard",
      "approvals_signed_decision_guard",
      "signed_kill_switch_clears_insert_guard",
      "signed_kill_switch_clears_update_guard",
      "signed_kill_switch_clears_delete_guard",
      "system_state_signed_kill_clear_guard",
    ])
      database.run(`DROP TRIGGER ${trigger}`);
    database.run("DROP TABLE signed_kill_switch_clears");
    database.run("DROP TABLE signed_approval_decisions");
    database.run("DROP TABLE local_operator_credentials");
    database.run("DROP TABLE operator_signed_statements");
    database.run("DROP TABLE control_plane_identity");
    database.run("DELETE FROM schema_migrations WHERE version=5");
    database.run(
      `UPDATE approvals SET status='accepted',decided_at=?,decided_by=?,
       user_action='legacy_unsigned_acceptance',revision=1 WHERE id=?`,
      LATER,
      "local-reviewer",
      legacyApproval.id,
    );
    database.run(
      `INSERT INTO policy_acceptances(
        program_id,version,policy_hash,accepted_by,accepted_at,audit_reference
      ) VALUES(?,?,?,?,?,?)`,
      "program-local",
      1,
      policy.policyHash,
      "local-reviewer",
      LATER,
      legacyApproval.auditReference,
    );
    database.run(
      `UPDATE programs SET rule_acceptance_status='accepted'
       WHERE id='program-local'`,
    );
    database.close();

    const migrated = await ControlPlaneDatabase.file(path);
    expect(migrated.migrationVersion()).toBe(5);
    expect(
      migrated.get(
        "SELECT kind,status FROM approvals WHERE id='legacy-policy-approval'",
      ),
    ).toMatchObject({
      kind: "program_policy_acceptance",
      status: "accepted",
    });
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
        "SELECT rule_acceptance_status FROM programs WHERE id='program-local'",
      ),
    ).toMatchObject({ rule_acceptance_status: "pending" });
    expect(
      migrated.get("SELECT count(*) AS value FROM policy_acceptances"),
    ).toMatchObject({ value: 0 });
    const migratedStore = createTestControlPlaneStore(migrated, NOW);
    const unsigned = migratedStore
      .listApprovals()
      .find((approval) => approval.id === legacyApproval.id);
    expect(unsigned).toBeDefined();
    expect(() =>
      migratedStore.requireAuthenticatedApprovalDecision(
        unsigned!,
        legacyApproval.payloadHash,
      ),
    ).toThrow("SIGNED_APPROVAL_DECISION_REQUIRED");
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
  const proposalDigest = options.proposalDigest ?? HASH_A;
  const bindingDigest = externalActionApprovalBindingDigest({
    approvalId: options.approvalId ?? "external-action-approval",
    proposalId: "proposal-1",
    proposalDigest,
    actionId: "platform_api_read",
    programId: "program-local",
    campaignId: "campaign-local",
    campaignRevision: 0,
    campaignDigest: HASH_B,
    policyVersion: 1,
    policyHash,
    scopeRef: "scope-1",
    accountId: null,
    accountRole: null,
    identityDigest: null,
    objectRef: null,
    ownershipDigest: null,
    payloadRef: null,
    operatorId: "local-reviewer",
    createdAt: NOW,
    expiresAt: LATER,
    decisionAuditId: null,
  });
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
    proposalDigest,
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
    bindingDigest,
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
