import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CONTROL_PLANE_SCHEMA_VERSION,
  ControlPlaneDatabase,
} from "../../../packages/control-plane/database.js";
import { ControlPlaneStore } from "../../../packages/control-plane/store.js";
import {
  controlPlanePolicy,
  NOW,
  programInput,
} from "../../fixtures/control-plane.factory.js";

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
    ])
      database.run(`DROP TRIGGER ${trigger}`);
    for (const index of [
      "policy_versions_exact_binding",
      "campaigns_program_binding",
      "identities_program_binding",
    ])
      database.run(`DROP INDEX ${index}`);
    database.run("DELETE FROM schema_migrations WHERE version=2");
    database.close();

    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow();
  });
});
