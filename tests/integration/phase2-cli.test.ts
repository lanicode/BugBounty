import { spawn } from "node:child_process";
import { once } from "node:events";
import { lstat, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const CLI_PATH = fileURLToPath(
  new URL("../../apps/phase2-cli/index.ts", import.meta.url),
);

describe("phase 2 simulation CLI", () => {
  it("fails before creating runtime state when no interactive TTY is present", async () => {
    const root = await mkdtemp(join(tmpdir(), "bbc-phase2-cli-"));
    const child = spawn(
      process.execPath,
      [
        "--import",
        import.meta.resolve("tsx"),
        CLI_PATH,
        "simulate",
        "--confirm-local-simulation",
      ],
      {
        cwd: root,
        env: { ...process.env },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    child.stdin.end();
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });

    const [code] = (await once(child, "close")) as [number, NodeJS.Signals];
    expect(code).toBe(1);
    expect(stderr).toContain("SIMULATION_INTERACTIVE_TTY_REQUIRED");
    await expect(lstat(join(root, ".local"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });
});
