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
const keyReference = (version: number): string =>
  `secret://event-key/v${String(version)}`;

afterEach(async () => {
  await Promise.all([...children].map(killAndWait));
  children.clear();
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("event key mutation crash boundary", () => {
  it.each([
    ["rotate-pre-link", 1, false],
    ["rotate-post-link", 2, true],
  ] as const)(
    "recovers deterministically after SIGKILL at %s",
    async (mode, expectedVersion, recordTwoExists) => {
      const root = await mkdtemp(join(tmpdir(), `event-key-${mode}-`));
      roots.push(root);
      const directory = join(root, "events");
      const secrets = new InMemorySecretStore();
      secrets.set(keyReference(1), new Uint8Array(32).fill(1));
      secrets.set(keyReference(2), new Uint8Array(32).fill(2));
      await EventKeyLifecycle.initializeFresh({
        directory,
        secrets,
        keyReference,
        minimumActiveKeyVersion: 1,
      });

      const child = spawn(
        process.execPath,
        ["--import", import.meta.resolve("tsx"), HOLDER_PATH, directory, mode],
        { stdio: ["pipe", "pipe", "pipe"] },
      );
      children.add(child);
      const output = await waitForMarker(child, "LOCKED\n");
      expect(output.stderr).toBe("");

      const lockPath = join(directory, ".event-key-mutation.lock");
      const lockBeforeRecovery = await readFile(lockPath, "utf8");
      await expect(
        EventKeyLifecycle.recoverStaleMutation({
          directory,
          secrets,
          keyReference,
          minimumActiveKeyVersion: expectedVersion,
        }),
      ).rejects.toThrow("EVENT_KEY_MUTATION_LOCK_ACTIVE");
      expect(await readFile(lockPath, "utf8")).toBe(lockBeforeRecovery);

      child.kill("SIGKILL");
      const [code, signal] = (await once(child, "close")) as [
        number | null,
        NodeJS.Signals | null,
      ];
      children.delete(child);
      expect({ code, signal }).toEqual({ code: null, signal: "SIGKILL" });

      await expect(
        EventKeyLifecycle.open({
          directory,
          secrets,
          keyReference,
          minimumActiveKeyVersion: expectedVersion,
        }),
      ).rejects.toThrow("EVENT_KEY_MUTATION_LOCKED");
      const recordTwoPath = join(
        directory,
        ".event-key-state",
        "state-0000000002.json",
      );
      await expect(pathExists(recordTwoPath)).resolves.toBe(recordTwoExists);

      await expect(
        EventKeyLifecycle.recoverStaleMutation({
          directory,
          secrets,
          keyReference,
          minimumActiveKeyVersion: expectedVersion,
        }),
      ).resolves.toMatchObject({
        activeKeyVersion: expectedVersion,
        revision: expectedVersion,
        recoveredExistingLock: true,
      });
      await expect(lstat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(
        EventKeyLifecycle.open({
          directory,
          secrets,
          keyReference,
          minimumActiveKeyVersion: expectedVersion,
        }),
      ).resolves.toMatchObject({});
    },
  );
});

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
      reject(new Error(`CHILD_MARKER_TIMEOUT:${stdout}:${stderr}`));
    }, 10_000);
    const finish = (): void => {
      clearTimeout(timeout);
      resolve({ stdout, stderr });
    };
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
      if (stdout.includes(marker)) finish();
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
}

async function killAndWait(
  child: ChildProcessWithoutNullStreams,
): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGKILL");
  await once(child, "close");
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT")
      return false;
    throw error;
  }
}
