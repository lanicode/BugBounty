import { mkdtemp, readdir, rm } from "node:fs/promises";
import type * as FsPromises from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";

const roots: string[] = [];
const keyReference = (version: number): string =>
  `secret://fault/event-key-v${String(version)}`;

afterEach(async () => {
  vi.doUnmock("node:fs/promises");
  vi.resetModules();
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("event key state commit fault boundary", () => {
  it("keeps v1 active when the final hardlink fails", async () => {
    const fixture = await faultFixture();
    fixture.setFault("before-link");

    await expect(
      fixture.lifecycle.rotate({
        expectedActiveKeyVersion: 1,
        nextKeyVersion: 2,
      }),
    ).rejects.toThrow("INJECTED_STATE_LINK_FAILURE");
    expect(await readdir(fixture.stateDirectory)).toEqual([
      "state-0000000001.json",
    ]);
    expect(await readdir(fixture.directory)).toEqual([".event-key-state"]);
    await expect(
      fixture.EventKeyLifecycle.open(fixture.options(1)),
    ).resolves.toMatchObject({});
  });

  it("loads v2 after restart when the final link succeeded before fsync reported failure", async () => {
    const fixture = await faultFixture();
    fixture.setFault("after-link");

    await expect(
      fixture.lifecycle.rotate({
        expectedActiveKeyVersion: 1,
        nextKeyVersion: 2,
      }),
    ).rejects.toThrow("EVENT_KEY_STATE_IO_FAILED");
    expect(await readdir(fixture.stateDirectory)).toEqual([
      "state-0000000001.json",
      "state-0000000002.json",
    ]);
    expect(await readdir(fixture.directory)).toEqual([".event-key-state"]);
    const reopened = await fixture.EventKeyLifecycle.open(fixture.options(2));
    expect(reopened.status()).toMatchObject({
      revision: 2,
      activeKeyVersion: 2,
      readableKeyVersions: [1, 2],
    });
  });
});

type FaultMode = "none" | "before-link" | "after-link";

async function faultFixture() {
  const root = await mkdtemp(join(tmpdir(), "event-key-state-fault-"));
  roots.push(root);
  const directory = resolve(join(root, "events"));
  const stateDirectory = join(directory, ".event-key-state");
  let fault: FaultMode = "none";

  vi.resetModules();
  vi.doMock("node:fs/promises", async (importOriginal) => {
    const actual = await importOriginal<typeof FsPromises>();
    return {
      ...actual,
      link: async (...args: Parameters<typeof actual.link>) => {
        if (
          fault === "before-link" &&
          basename(String(args[1])) === "state-0000000002.json"
        ) {
          fault = "none";
          throw new Error("INJECTED_STATE_LINK_FAILURE");
        }
        await actual.link(...args);
      },
      open: async (...args: Parameters<typeof actual.open>) => {
        const handle = await actual.open(...args);
        if (
          fault === "after-link" &&
          resolve(String(args[0])) === stateDirectory
        ) {
          Object.defineProperty(handle, "sync", {
            configurable: true,
            value: () => {
              fault = "none";
              return Promise.reject(
                new Error("INJECTED_STATE_DIRECTORY_SYNC_FAILURE"),
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
  const secrets = new InMemorySecretStore();
  secrets.set(keyReference(1), new Uint8Array(32).fill(1));
  secrets.set(keyReference(2), new Uint8Array(32).fill(2));
  const options = (minimumActiveKeyVersion: number) => ({
    directory,
    secrets,
    keyReference,
    minimumActiveKeyVersion,
  });
  const lifecycle = await EventKeyLifecycle.initializeFresh(options(1));
  return {
    EventKeyLifecycle,
    directory,
    stateDirectory,
    lifecycle,
    options,
    setFault(next: FaultMode) {
      fault = next;
    },
  };
}
