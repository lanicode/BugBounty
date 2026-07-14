import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { ControlPlaneDatabase } from "../../packages/control-plane/database.js";
import { seedRunningCampaign } from "../fixtures/store-bound-action.factory.js";
import { createTestControlPlaneStore } from "../fixtures/operator-auth.factory.js";

const CHILD_PATH = fileURLToPath(
  new URL("../fixtures/kill-switch-engagement-child.ts", import.meta.url),
);
const roots: string[] = [];
const children = new Set<ChildProcessWithoutNullStreams>();

afterEach(async () => {
  await Promise.all([...children].map(killAndWait));
  children.clear();
  await Promise.all(
    roots.splice(0).map((root) => {
      return rm(root, { recursive: true, force: true });
    }),
  );
});

describe("kill-switch crash recovery", () => {
  it("pauses a committed running campaign after SIGKILL and file reopen", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "bbc-kill-recovery-")),
    );
    roots.push(root);
    const path = join(root, "state.sqlite");
    const database = await ControlPlaneDatabase.file(path);
    seedRunningCampaign(createTestControlPlaneStore(database));
    database.close();

    const child = spawnChild(path);
    await waitForMarker(child, "ENGAGEMENT_COMMITTED\n");
    child.kill("SIGKILL");
    const [code, signal] = (await once(child, "close")) as [
      number | null,
      NodeJS.Signals | null,
    ];
    children.delete(child);
    expect({ code, signal }).toEqual({ code: null, signal: "SIGKILL" });

    const reopened = await ControlPlaneDatabase.file(path);
    try {
      expect(
        reopened.get(
          "SELECT value FROM system_state WHERE key='global_kill_switch'",
        ),
      ).toMatchObject({ value: "engaged" });
      expect(
        reopened.get("SELECT state FROM campaigns WHERE id='campaign-local'"),
      ).toMatchObject({ state: "running_simulation" });

      const recovered = createTestControlPlaneStore(reopened);
      expect(recovered.isKillSwitchActive()).toBe(true);
      expect(recovered.getCampaign("campaign-local")).toMatchObject({
        state: "paused",
        humanApprovedBy: null,
        humanApprovedAt: null,
        killSwitchStatus: "engaged",
      });
    } finally {
      reopened.close();
    }
  });
});

function spawnChild(path: string): ChildProcessWithoutNullStreams {
  const child = spawn(
    process.execPath,
    ["--no-warnings", "--import", import.meta.resolve("tsx"), CHILD_PATH, path],
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

async function killAndWait(
  child: ChildProcessWithoutNullStreams,
): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGKILL");
  await once(child, "close");
}
