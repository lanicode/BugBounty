import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { EventKeyLifecycle } from "../../packages/event-key-lifecycle/index.js";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";

const HOLDER_PATH = fileURLToPath(
  new URL("../fixtures/event-key-mutation-lease-holder.ts", import.meta.url),
);
const roots: string[] = [];
const children = new Set<ChildProcessWithoutNullStreams>();
const KEY_REFERENCE = (version: number): string =>
  `secret://event-key/v${String(version)}`;

afterEach(async () => {
  for (const child of children) child.kill("SIGKILL");
  children.clear();
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("event key mutation lease process boundary", () => {
  it("blocks an independent process for the full refresh-and-write section", async () => {
    const root = await mkdtemp(join(tmpdir(), "event-key-process-lease-"));
    roots.push(root);
    const directory = join(root, "events");
    const secrets = new InMemorySecretStore();
    secrets.set(KEY_REFERENCE(1), new Uint8Array(32).fill(1));
    await EventKeyLifecycle.initializeFresh({
      directory,
      secrets,
      keyReference: KEY_REFERENCE,
      minimumActiveKeyVersion: 1,
    });

    const child = spawn(
      process.execPath,
      ["--import", import.meta.resolve("tsx"), HOLDER_PATH, directory],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    children.add(child);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    let stdout = "";
    let stderr = "";
    let lockedResolve: (() => void) | undefined;
    const locked = new Promise<void>((resolve) => {
      lockedResolve = resolve;
    });
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
      if (stdout.includes("LOCKED\n")) lockedResolve?.();
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    await Promise.race([
      locked,
      once(child, "close").then(([code, signal]) => {
        throw new Error(
          `LEASE_HOLDER_EXITED:${String(code)}:${String(signal)}`,
        );
      }),
    ]);

    const lockPath = join(directory, ".event-key-mutation.lock");
    expect((await lstat(lockPath)).mode & 0o777).toBe(0o600);
    await expect(
      EventKeyLifecycle.open({
        directory,
        secrets,
        keyReference: KEY_REFERENCE,
        minimumActiveKeyVersion: 1,
      }),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCKED");

    child.stdin.end("continue\n");
    const [code] = (await once(child, "close")) as [number, NodeJS.Signals];
    children.delete(child);
    expect({ code, stderr }).toEqual({ code: 0, stderr: "" });
    expect(stdout).toContain("DONE\n");
    await expect(lstat(lockPath)).rejects.toThrow();

    const eventPath = join(directory, "child-process.events.enc");
    const envelope = JSON.parse(await readFile(eventPath, "utf8")) as {
      keyVersion: number;
    };
    expect(envelope.keyVersion).toBe(1);
  });
});
