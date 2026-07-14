import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { lstat, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { ControlPlaneDatabase } from "../../packages/control-plane/database.js";

const CHILD_PATH = fileURLToPath(
  new URL("../fixtures/control-plane-transaction-child.ts", import.meta.url),
);
const roots: string[] = [];
const children = new Set<ChildProcessWithoutNullStreams>();

afterEach(async () => {
  await Promise.all([...children].map(killAndWait));
  children.clear();
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("ControlPlaneDatabase process crash boundary", () => {
  it("rolls back a SIGKILLed open transaction and preserves prior commits", async () => {
    const path = await seededDatabasePath("rollback");
    const child = spawnChild(path, "hold");
    await waitForMarker(child, "TRANSACTION_OPEN\n");
    expect((await lstat(`${path}-journal`)).mode & 0o7777).toBe(0o600);

    child.kill("SIGKILL");
    expect(await waitForClose(child)).toEqual({
      code: null,
      signal: "SIGKILL",
    });
    children.delete(child);

    const reopened = await ControlPlaneDatabase.file(path);
    try {
      expect(auditExists(reopened, "baseline-committed")).toBe(true);
      expect(auditExists(reopened, "child-uncommitted")).toBe(false);
      // SQLite may retain a non-hot rollback journal after recovery. The
      // boundary requires it to remain a private regular file, not to vanish.
      expect((await lstat(`${path}-journal`)).mode & 0o7777).toBe(0o600);
    } finally {
      reopened.close();
    }
  });

  it("keeps a child-process commit durable across process exit and reopen", async () => {
    const path = await seededDatabasePath("commit");
    const child = spawnChild(path, "commit");
    const output = await collectChild(child);
    children.delete(child);
    expect(output).toEqual({
      code: 0,
      signal: null,
      stdout: "COMMITTED\n",
      stderr: "",
    });

    const reopened = await ControlPlaneDatabase.file(path);
    try {
      expect(auditExists(reopened, "child-committed")).toBe(true);
    } finally {
      reopened.close();
    }
  });

  it("maps independent-writer contention to CONTROL_PLANE_BUSY without writes", async () => {
    const path = await seededDatabasePath("busy");
    const contender = await ControlPlaneDatabase.file(path);
    const child = spawnChild(path, "hold");
    await waitForMarker(child, "TRANSACTION_OPEN\n");
    try {
      expect(() => {
        contender.transaction(() => {
          insertAudit(contender, "busy-loser");
        });
      }).toThrow("CONTROL_PLANE_BUSY");
      expect(auditExists(contender, "busy-loser")).toBe(false);
      expect(auditExists(contender, "child-uncommitted")).toBe(false);
    } finally {
      contender.close();
      child.kill("SIGKILL");
      await waitForClose(child);
      children.delete(child);
    }

    const reopened = await ControlPlaneDatabase.file(path);
    try {
      expect(auditExists(reopened, "child-uncommitted")).toBe(false);
      expect(auditExists(reopened, "busy-loser")).toBe(false);
    } finally {
      reopened.close();
    }
  });
});

async function seededDatabasePath(label: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `bbc-control-plane-${label}-`));
  roots.push(root);
  const path = join(root, "state.sqlite");
  const database = await ControlPlaneDatabase.file(path);
  try {
    insertAudit(database, "baseline-committed");
  } finally {
    database.close();
  }
  return path;
}

function spawnChild(
  path: string,
  mode: "commit" | "hold",
): ChildProcessWithoutNullStreams {
  const child = spawn(
    process.execPath,
    [
      "--no-warnings",
      "--import",
      import.meta.resolve("tsx"),
      CHILD_PATH,
      path,
      mode,
    ],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  children.add(child);
  return child;
}

async function waitForMarker(
  child: ChildProcessWithoutNullStreams,
  marker: string,
): Promise<void> {
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  let stdout = "";
  let stderr = "";
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`CHILD_MARKER_TIMEOUT:${stdout}:${stderr}`));
    }, 10_000);
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
      if (!stdout.includes(marker)) return;
      clearTimeout(timeout);
      resolve();
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      reject(
        new Error(`CHILD_EXITED:${String(code)}:${String(signal)}:${stderr}`),
      );
    });
  });
  expect(stderr).toBe("");
}

async function collectChild(child: ChildProcessWithoutNullStreams): Promise<{
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
}> {
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });
  const { code, signal } = await waitForClose(child);
  return { code, signal, stdout, stderr };
}

async function waitForClose(child: ChildProcessWithoutNullStreams): Promise<{
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
}> {
  const [code, signal] = (await once(child, "close")) as [
    number | null,
    NodeJS.Signals | null,
  ];
  return { code, signal };
}

async function killAndWait(
  child: ChildProcessWithoutNullStreams,
): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGKILL");
  await once(child, "close");
}

function auditExists(database: ControlPlaneDatabase, id: string): boolean {
  return (
    database.get("SELECT id FROM control_plane_audit WHERE id=?", id)?.[
      "id"
    ] === id
  );
}

function insertAudit(database: ControlPlaneDatabase, id: string): void {
  database.run(
    "INSERT INTO control_plane_audit VALUES(?,?,?,?,?,?,?)",
    id,
    "2026-07-14T12:00:00.000Z",
    "child_process_database_test",
    "deny",
    "LOCAL_TEST_ONLY",
    null,
    "a".repeat(64),
  );
}
