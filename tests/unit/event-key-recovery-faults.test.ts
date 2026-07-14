import { lstat, mkdtemp, rm, writeFile } from "node:fs/promises";
import type * as FsPromises from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";

const roots: string[] = [];
const TEMP_NAME = ".tmp-88-0123456789abcdef";
const LOCK_NAME = ".event-key-mutation.lock";
const keyReference = (): string => "secret://recovery-fault/event-key-v1";

afterEach(async () => {
  vi.doUnmock("node:fs/promises");
  vi.resetModules();
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("event key recovery fault boundary", () => {
  it("keeps the recovery lock and temporary when unlink fails", async () => {
    const fixture = await initializedFixture();
    vi.resetModules();
    vi.doMock("node:fs/promises", async (importOriginal) => {
      const actual = await importOriginal<typeof FsPromises>();
      return {
        ...actual,
        unlink: async (...args: Parameters<typeof actual.unlink>) => {
          if (basename(String(args[0])) === TEMP_NAME)
            throw new Error("INJECTED_EVENT_TEMP_UNLINK_FAILURE");
          await actual.unlink(...args);
        },
      };
    });
    const { EventKeyLifecycle } =
      await import("../../packages/event-key-lifecycle/lifecycle.js");

    await expect(
      EventKeyLifecycle.recoverStaleMutation(fixture.options),
    ).rejects.toThrow("EVENT_KEY_MUTATION_RECOVERY_FAILED");
    await expect(lstat(fixture.temporary)).resolves.toMatchObject({});
    await expect(
      lstat(join(fixture.directory, LOCK_NAME)),
    ).resolves.toMatchObject({});
    await expect(EventKeyLifecycle.open(fixture.options)).rejects.toThrow(
      "EVENT_KEY_MUTATION_LOCKED",
    );
  });

  it("keeps the recovery lock when directory fsync fails after unlink", async () => {
    const fixture = await initializedFixture();
    let temporaryRemoved = false;
    let syncFailureInjected = false;
    vi.resetModules();
    vi.doMock("node:fs/promises", async (importOriginal) => {
      const actual = await importOriginal<typeof FsPromises>();
      return {
        ...actual,
        unlink: async (...args: Parameters<typeof actual.unlink>) => {
          await actual.unlink(...args);
          if (basename(String(args[0])) === TEMP_NAME) temporaryRemoved = true;
        },
        open: async (...args: Parameters<typeof actual.open>) => {
          const handle = await actual.open(...args);
          if (
            temporaryRemoved &&
            !syncFailureInjected &&
            resolve(String(args[0])) === fixture.directory
          ) {
            Object.defineProperty(handle, "sync", {
              configurable: true,
              value: () => {
                syncFailureInjected = true;
                return Promise.reject(
                  new Error("INJECTED_RECOVERY_DIRECTORY_SYNC_FAILURE"),
                );
              },
            });
          }
          return handle;
        },
      };
    });
    const { EventKeyLifecycle } =
      await import("../../packages/event-key-lifecycle/lifecycle.js");

    await expect(
      EventKeyLifecycle.recoverStaleMutation(fixture.options),
    ).rejects.toThrow("EVENT_KEY_MUTATION_RECOVERY_FAILED");
    await expect(lstat(fixture.temporary)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(
      lstat(join(fixture.directory, LOCK_NAME)),
    ).resolves.toMatchObject({});
    await expect(EventKeyLifecycle.open(fixture.options)).rejects.toThrow(
      "EVENT_KEY_MUTATION_LOCKED",
    );
  });
});

async function initializedFixture() {
  vi.doUnmock("node:fs/promises");
  vi.resetModules();
  const { EventKeyLifecycle } =
    await import("../../packages/event-key-lifecycle/lifecycle.js");
  const root = await mkdtemp(join(tmpdir(), "event-key-recovery-fault-"));
  roots.push(root);
  const directory = resolve(join(root, "events"));
  const secrets = new InMemorySecretStore();
  secrets.set(keyReference(), new Uint8Array(32).fill(1));
  const options = {
    directory,
    secrets,
    keyReference,
    minimumActiveKeyVersion: 1,
  };
  await EventKeyLifecycle.initializeFresh(options);
  const temporary = join(directory, TEMP_NAME);
  await writeFile(temporary, "partial", { mode: 0o600 });
  return { directory, options, temporary };
}
