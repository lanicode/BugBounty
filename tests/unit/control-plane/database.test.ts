import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CONTROL_PLANE_SCHEMA_VERSION,
  ControlPlaneDatabase,
} from "../../../packages/control-plane/database.js";

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
      "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(2,?,?)",
      "f".repeat(64),
      "2026-07-13T00:00:00.000Z",
    );
    database.close();
    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow(
      "CONTROL_PLANE_MIGRATION_INTEGRITY",
    );
  });
});
