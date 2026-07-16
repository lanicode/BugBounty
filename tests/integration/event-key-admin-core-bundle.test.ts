import { lstat, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runEventKeyAdminCommand } from "../../apps/event-key-cli/command.js";
import {
  CORE_EVENT_KEY_REFERENCE,
  InMemorySecretStore,
  MacOSCoreKeychainBackend,
  resolveMacOSEventKeyAdminSecretStore,
} from "../../packages/secret-store/index.js";
import { TestCoreKeychainRunner } from "../fixtures/core-keychain.factory.js";

const EVENT_V2 = "keychain://bugbounty-copilot/event-store-v2";
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("event-key admin CLI with Core provisioning layouts", () => {
  it("initializes, reports and rotates a fresh bundle while keeping v2 generic", async () => {
    const harness = await harnessFor("fresh_bundle", true);

    const initialized = await harness.run([
      "initialize",
      "--confirm-local-event-key-initialize",
    ]);
    const status = await harness.run(["status"]);
    const rotated = await harness.run([
      "rotate",
      "--expected",
      "1",
      "--next",
      "2",
      "--confirm-local-event-key-rotation",
    ]);

    expect(initialized).toMatchObject({
      revision: 1,
      activeKeyVersion: 1,
      readableKeyVersions: [1],
    });
    expect(status).toEqual(initialized);
    expect(rotated).toMatchObject({
      revision: 2,
      previousActiveKeyVersion: 1,
      activeKeyVersion: 2,
      readableKeyVersions: [1, 2],
      requiredMinimumVersionAfterRestart: 2,
    });
    expect(harness.runner.operations).toContain("read-event");
    expect(JSON.stringify([initialized, status, rotated])).not.toContain(
      "eventKey",
    );
  });

  it.each(["legacy_ready", "legacy_direct_complete"] as const)(
    "keeps Phase-5 event admin functional in explicit %s mode without Core-role reads",
    async (status) => {
      const harness = await harnessFor(status, true);
      await harness.run(["initialize", "--confirm-local-event-key-initialize"]);
      const rotated = await harness.run([
        "rotate",
        "--expected",
        "1",
        "--next",
        "2",
        "--confirm-local-event-key-rotation",
      ]);

      expect(rotated).toMatchObject({
        activeKeyVersion: 2,
        readableKeyVersions: [1, 2],
      });
      expect(harness.runner.operations).not.toContain("read-event");
      expect(harness.runner.operations).not.toContain("read-operator");
    },
  );

  it.each(["absent", "conflict"] as const)(
    "blocks %s before creating event-key state even when generic keys exist",
    async (status) => {
      const harness = await harnessFor(status, true);
      await expect(
        harness.run(["initialize", "--confirm-local-event-key-initialize"]),
      ).rejects.toThrow("CORE_AWARE_KEYCHAIN_STATE_INVALID");
      await expect(lstat(harness.directory)).rejects.toMatchObject({
        code: "ENOENT",
      });
    },
  );

  it("does not commit a rotation when the exact generic v2 key is absent", async () => {
    const harness = await harnessFor("fresh_bundle", false);
    await harness.run(["initialize", "--confirm-local-event-key-initialize"]);
    await expect(
      harness.run([
        "rotate",
        "--expected",
        "1",
        "--next",
        "2",
        "--confirm-local-event-key-rotation",
      ]),
    ).rejects.toThrow("EVENT_KEY_UNAVAILABLE");
    expect(await harness.run(["status"])).toMatchObject({
      revision: 1,
      activeKeyVersion: 1,
      readableKeyVersions: [1],
    });
  });
});

async function harnessFor(
  status: ConstructorParameters<typeof TestCoreKeychainRunner>[0],
  includeV2: boolean,
): Promise<{
  readonly directory: string;
  readonly runner: TestCoreKeychainRunner;
  run(args: readonly string[]): Promise<object>;
}> {
  const root = await mkdtemp(join(tmpdir(), "event-key-core-admin-"));
  roots.push(root);
  const directory = join(root, "event-store");
  const runner = new TestCoreKeychainRunner(status);
  const core = new MacOSCoreKeychainBackend("darwin", runner);
  const generic = new InMemorySecretStore();
  generic.set(CORE_EVENT_KEY_REFERENCE, new Uint8Array(32).fill(0x51));
  if (includeV2) generic.set(EVENT_V2, new Uint8Array(32).fill(0x52));
  return {
    directory,
    runner,
    run: (args) =>
      runEventKeyAdminCommand({
        args,
        minimumActiveKeyVersion: "1",
        eventDirectory: directory,
        secrets: () => resolveMacOSEventKeyAdminSecretStore(core, generic),
      }),
  };
}
