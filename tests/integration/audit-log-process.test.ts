import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  realpath,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION,
  AuditLog,
  recoverStaleAuditMutation,
  verifyAuditLog,
} from "../../packages/audit-log/audit.js";
import { canonicalJson } from "../../packages/shared/canonical.js";

const APPENDER_PATH = fileURLToPath(
  new URL("../fixtures/audit-log-appender.ts", import.meta.url),
);
const LOCK_HOLDER_PATH = fileURLToPath(
  new URL("../fixtures/audit-log-lock-holder.ts", import.meta.url),
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

describe("audit log process boundary", () => {
  it("serializes independent local processes into one restart-safe chain", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "audit-process-")),
    );
    roots.push(root);
    await chmod(root, 0o700);
    const path = join(root, "audit.jsonl");
    const workers = 8;
    const perWorker = 8;

    const results = await Promise.all(
      Array.from({ length: workers }, (_, index) =>
        runAppender(path, `p${String(index)}`, perWorker),
      ),
    );
    for (const result of results) {
      expect(result.code).toBe(0);
      expect(result.signal).toBeNull();
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toMatchObject({ count: perWorker });
    }

    const entries = workers * perWorker;
    await expect(verifyAuditLog(path)).resolves.toEqual({
      valid: true,
      entries,
    });
    const source = await readFile(path, "utf8");
    const lines = source.slice(0, -1).split("\n");
    expect(lines).toHaveLength(entries);
    expect(
      lines.map((line) => (JSON.parse(line) as { sequence: number }).sequence),
    ).toEqual(Array.from({ length: entries }, (_, index) => index));
    for (const line of lines)
      expect(line).toBe(canonicalJson(JSON.parse(line)));
    expect((await lstat(path)).mode & 0o777).toBe(0o600);
    await expect(lstat(`${path}.mutation.lock`)).rejects.toMatchObject({
      code: "ENOENT",
    });
  }, 20_000);

  it("recovers an exact lease after SIGKILL but never steals it from a live owner", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "audit-process-crash-")),
    );
    roots.push(root);
    await chmod(root, 0o700);
    const path = join(root, "audit.jsonl");
    await new AuditLog(path).append({
      timestamp: "2026-07-14T12:00:00.000Z",
      action: "before-crash",
      decision: "allow",
      reasonCode: "LOCAL_SIGKILL_TEST",
      policyHash: "d".repeat(64),
    });

    const child = spawn(
      process.execPath,
      ["--import", import.meta.resolve("tsx"), LOCK_HOLDER_PATH, path],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    children.add(child);
    const output = await waitForMarker(child, "LOCKED\n");
    expect(output.stderr).toBe("");
    await expect(
      recoverStaleAuditMutation(
        path,
        AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION,
      ),
    ).rejects.toThrow("AUDIT_MUTATION_LOCK_ACTIVE");
    expect((await lstat(`${path}.mutation.lock`)).isFile()).toBe(true);

    child.kill("SIGKILL");
    const [code, signal] = (await once(child, "close")) as [
      number | null,
      NodeJS.Signals | null,
    ];
    children.delete(child);
    expect({ code, signal }).toEqual({ code: null, signal: "SIGKILL" });

    await expect(
      recoverStaleAuditMutation(
        path,
        AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION,
      ),
    ).resolves.toEqual({ recovered: true, valid: true, entries: 1 });
    await expect(lstat(`${path}.mutation.lock`)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await new AuditLog(path).append({
      timestamp: "2026-07-14T12:00:01.000Z",
      action: "after-recovery",
      decision: "allow",
      reasonCode: "LOCAL_SIGKILL_TEST",
      policyHash: "d".repeat(64),
    });
    await expect(verifyAuditLog(path)).resolves.toEqual({
      valid: true,
      entries: 2,
    });
  }, 20_000);
});

async function runAppender(
  path: string,
  worker: string,
  count: number,
): Promise<{
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const child = spawn(
    process.execPath,
    [
      "--import",
      import.meta.resolve("tsx"),
      APPENDER_PATH,
      path,
      worker,
      String(count),
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
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
  const [code, signal] = (await once(child, "close")) as [
    number | null,
    NodeJS.Signals | null,
  ];
  return { code, signal, stdout, stderr };
}

async function waitForMarker(
  child: ChildProcessWithoutNullStreams,
  marker: string,
): Promise<{ readonly stdout: string; readonly stderr: string }> {
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  let stdout = "";
  let stderr = "";
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`AUDIT_CHILD_MARKER_TIMEOUT:${stdout}:${stderr}`));
    }, 10_000);
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
      if (stdout.includes(marker)) {
        clearTimeout(timeout);
        resolve({ stdout, stderr });
      }
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      reject(
        new Error(
          `AUDIT_CHILD_EXITED:${String(code)}:${String(signal)}:${stderr}`,
        ),
      );
    });
  });
}

async function killAndWait(
  child: ChildProcessWithoutNullStreams,
): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGKILL");
  await once(child, "close");
}
