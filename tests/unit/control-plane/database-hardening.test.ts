import { DatabaseSync } from "node:sqlite";
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  mkdir,
  open,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ControlPlaneDatabase } from "../../../packages/control-plane/database.js";

const HASH = "a".repeat(64);
const NOW = "2026-07-14T12:00:00.000Z";
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("ControlPlaneDatabase hardening", () => {
  it("pins and verifies the local durability contract", async () => {
    const { root, path } = await databasePath("durability");
    const database = await ControlPlaneDatabase.file(path);
    try {
      expect(pragmaValue(database, "PRAGMA foreign_keys")).toBe(1);
      expect(pragmaValue(database, "PRAGMA trusted_schema")).toBe(0);
      expect(pragmaValue(database, "PRAGMA recursive_triggers")).toBe(1);
      expect(pragmaValue(database, "PRAGMA journal_mode")).toBe("delete");
      expect(pragmaValue(database, "PRAGMA synchronous")).toBe(2);
      expect(pragmaValue(database, "PRAGMA fullfsync")).toBe(1);
      expect(pragmaValue(database, "PRAGMA locking_mode")).toBe("normal");
      expect(pragmaValue(database, "PRAGMA busy_timeout")).toBe(1_000);
      expect(pragmaValue(database, "PRAGMA temp_store")).toBe(2);
      expect((await lstat(await realpath(root))).mode & 0o7777).toBe(0o700);
      expect((await lstat(path)).mode & 0o7777).toBe(0o600);
    } finally {
      database.close();
    }
  });

  it("keeps delete guards effective for INSERT OR REPLACE conflict deletes", () => {
    const database = ControlPlaneDatabase.memory();
    try {
      database.run(
        "CREATE TABLE append_only_guard(id TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT",
      );
      database.run(
        `CREATE TRIGGER append_only_guard_no_delete
         BEFORE DELETE ON append_only_guard
         BEGIN SELECT RAISE(ABORT,'APPEND_ONLY_DELETE_BLOCKED'); END`,
      );
      database.run(
        "INSERT INTO append_only_guard(id,value) VALUES('row','original')",
      );

      expect(() =>
        database.run(
          "INSERT OR REPLACE INTO append_only_guard(id,value) VALUES('row','forged')",
        ),
      ).toThrow("APPEND_ONLY_DELETE_BLOCKED");
      expect(
        database.get("SELECT id,value FROM append_only_guard WHERE id='row'"),
      ).toEqual({ id: "row", value: "original" });
    } finally {
      database.close();
    }
  });

  it("uses nested savepoints and preserves the original nested failure", () => {
    const database = ControlPlaneDatabase.memory();
    const original = new Error("EXPECTED_NESTED_FAILURE");
    try {
      database.transaction(() => {
        insertAudit(database, "outer-before");
        try {
          database.transaction(() => {
            insertAudit(database, "nested-rolled-back");
            throw original;
          });
        } catch (error) {
          expect(error).toBe(original);
        }
        database.transaction(() => {
          insertAudit(database, "nested-committed");
        });
        insertAudit(database, "outer-after");
      });
      expect(
        database
          .all("SELECT id FROM control_plane_audit ORDER BY id")
          .map((row) => row["id"]),
      ).toEqual(["nested-committed", "outer-after", "outer-before"]);
    } finally {
      database.close();
    }
  });

  it("rejects non-canonical paths and user-owned ancestor symlinks", async () => {
    await expect(ControlPlaneDatabase.file("relative.sqlite")).rejects.toThrow(
      "CONTROL_PLANE_PATH_INVALID",
    );
    const root = await trackedRoot("ancestor");
    const realDirectory = join(root, "real");
    const linkedDirectory = join(root, "linked");
    await mkdir(realDirectory, { mode: 0o700 });
    await symlink(realDirectory, linkedDirectory);
    await expect(
      ControlPlaneDatabase.file(join(linkedDirectory, "state.sqlite")),
    ).rejects.toThrow("CONTROL_PLANE_DIRECTORY_SYMLINK");

    const nested = join(realDirectory, "nested");
    await mkdir(nested, { mode: 0o700 });
    const ancestor = join(root, "ancestor-link");
    await symlink(realDirectory, ancestor);
    await expect(
      ControlPlaneDatabase.file(join(ancestor, "nested", "state.sqlite")),
    ).rejects.toThrow("CONTROL_PLANE_ANCESTOR_SYMLINK");
  });

  it("rejects symlink, hardlink, and permissive database files", async () => {
    const { root, path } = await databasePath("file-boundary");
    const database = await ControlPlaneDatabase.file(path);
    database.close();

    await chmod(path, 0o644);
    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow(
      "CONTROL_PLANE_FILE_PERMISSIONS_INVALID",
    );
    await chmod(path, 0o600);

    const hardlink = join(root, "hardlink.sqlite");
    await link(path, hardlink);
    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow(
      "CONTROL_PLANE_FILE_HARDLINK_INVALID",
    );
    await unlink(hardlink);

    const alias = join(root, "alias.sqlite");
    await symlink(path, alias);
    await expect(ControlPlaneDatabase.file(alias)).rejects.toThrow(
      "CONTROL_PLANE_PATH_SYMLINK",
    );
  });

  it("rejects unsafe SQLite sidecars before opening the database", async () => {
    const { root, path } = await databasePath("sidecars");
    const database = await ControlPlaneDatabase.file(path);
    database.close();
    const target = join(root, "sidecar-target");
    await writeFile(target, "local", { mode: 0o600 });

    for (const suffix of ["-journal", "-wal", "-shm"] as const) {
      const sidecar = `${path}${suffix}`;
      await symlink(target, sidecar);
      await expect(ControlPlaneDatabase.file(path)).rejects.toThrow(
        "CONTROL_PLANE_SIDECAR_SYMLINK",
      );
      await unlink(sidecar);
    }

    await writeFile(`${path}-wal`, "", { mode: 0o600 });
    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow(
      "CONTROL_PLANE_SIDECAR_UNEXPECTED",
    );
    await unlink(`${path}-wal`);

    await writeFile(`${path}-journal`, "", { mode: 0o600 });
    await chmod(`${path}-journal`, 0o644);
    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow(
      "CONTROL_PLANE_SIDECAR_PERMISSIONS_INVALID",
    );
  });

  it("fails closed on foreign-key corruption during reopen", async () => {
    const { path } = await databasePath("foreign-key-corruption");
    const database = await ControlPlaneDatabase.file(path);
    database.close();

    const raw = new DatabaseSync(path, {
      enableForeignKeyConstraints: false,
      allowExtension: false,
    });
    try {
      raw.exec("PRAGMA foreign_keys=OFF");
      raw
        .prepare(
          `INSERT INTO report_drafts(
            id,campaign_id,title,summary,created_at,status,
            external_submission_performed
          ) VALUES(?,?,?,?,?,'draft',0)`,
        )
        .run("orphan-report", "missing-campaign", "Local", "Local", NOW);
    } finally {
      raw.close();
    }

    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow(
      "CONTROL_PLANE_FOREIGN_KEY_INTEGRITY_INVALID",
    );
  });

  it("fails closed when integrity_check cannot validate a corrupted page", async () => {
    const { path } = await databasePath("page-corruption");
    const database = await ControlPlaneDatabase.file(path);
    database.close();
    const handle = await open(path, "r+");
    try {
      await handle.write(new Uint8Array([0]), 0, 1, 100);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await expect(ControlPlaneDatabase.file(path)).rejects.toThrow(
      "CONTROL_PLANE_INTEGRITY_INVALID",
    );
  });
});

async function databasePath(label: string): Promise<{
  readonly root: string;
  readonly path: string;
}> {
  const root = await trackedRoot(label);
  return { root, path: join(root, "state.sqlite") };
}

async function trackedRoot(label: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `bbc-control-plane-${label}-`));
  roots.push(root);
  return root;
}

function pragmaValue(database: ControlPlaneDatabase, pragma: string): unknown {
  const row = database.get(pragma);
  const values = row === undefined ? [] : Object.values(row);
  expect(values).toHaveLength(1);
  return values[0];
}

function insertAudit(database: ControlPlaneDatabase, id: string): void {
  database.run(
    "INSERT INTO control_plane_audit VALUES(?,?,?,?,?,?,?)",
    id,
    NOW,
    "database_hardening_test",
    "deny",
    "LOCAL_TEST_ONLY",
    null,
    HASH,
  );
}
