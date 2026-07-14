import { spawn } from "node:child_process";
import { once } from "node:events";
import { lstat, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const APP_PATH = fileURLToPath(
  new URL("../../apps/event-key-cli/index.ts", import.meta.url),
);
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("event key local admin CLI boundary", () => {
  it.each([undefined, "", "0", "01", "10001"])(
    "fails before filesystem or Keychain access for minimum version %j",
    async (minimum) => {
      const root = await mkdtemp(join(tmpdir(), "event-key-admin-config-"));
      roots.push(root);
      const result = await runAdmin(root, ["status"], minimum);
      expect(result).toEqual({
        code: 1,
        signal: null,
        stdout: "",
        stderr: "EVENT_KEY_MIN_VERSION_CONFIG_INVALID\n",
      });
      await expect(lstat(join(root, ".local"))).rejects.toMatchObject({
        code: "ENOENT",
      });
    },
  );

  it("requires the exact stale-recovery confirmation flag", async () => {
    const root = await mkdtemp(join(tmpdir(), "event-key-admin-recovery-"));
    roots.push(root);
    await expect(
      runAdmin(root, ["recover-stale-mutation"], undefined),
    ).resolves.toMatchObject({
      code: 1,
      stdout: "",
      stderr: "EVENT_KEY_ADMIN_USAGE_INVALID\n",
    });
    await expect(
      runAdmin(
        root,
        ["recover-stale-mutation", "--confirm-local-stale-event-key-recovery"],
        undefined,
      ),
    ).resolves.toMatchObject({
      code: 1,
      stdout: "",
      stderr: "EVENT_KEY_MIN_VERSION_CONFIG_INVALID\n",
    });
    await expect(lstat(join(root, ".local"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });
});

async function runAdmin(
  cwd: string,
  args: readonly string[],
  minimumActiveKeyVersion: string | undefined,
): Promise<{
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const env: NodeJS.ProcessEnv = { ...process.env };
  if (minimumActiveKeyVersion === undefined)
    delete env["BUGBOUNTY_EVENT_KEY_MIN_VERSION"];
  else env["BUGBOUNTY_EVENT_KEY_MIN_VERSION"] = minimumActiveKeyVersion;
  const child = spawn(
    process.execPath,
    ["--import", import.meta.resolve("tsx"), APP_PATH, ...args],
    { cwd, env, stdio: ["ignore", "pipe", "pipe"] },
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
  const timeout = setTimeout(() => child.kill("SIGKILL"), 10_000);
  const [code, signal] = (await once(child, "close")) as [
    number | null,
    NodeJS.Signals | null,
  ];
  clearTimeout(timeout);
  return { code, signal, stdout, stderr };
}
