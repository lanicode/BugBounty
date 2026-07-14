import { chmod, copyFile, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EventKeyLifecycle } from "../../packages/event-key-lifecycle/index.js";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";

const roots: string[] = [];
const keyReference = (version: number): string =>
  `keychain://integration/event-store-v${String(version)}`;

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function directory(label: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `event-key-restart-${label}-`));
  roots.push(root);
  return join(root, "events");
}

function keys(...versions: number[]): InMemorySecretStore {
  const secrets = new InMemorySecretStore();
  for (const version of versions) {
    const key = new Uint8Array(32).fill(version);
    key[0] = version;
    secrets.set(keyReference(version), key);
  }
  return secrets;
}

describe("event key lifecycle restart", () => {
  it("persists the rotated head and reads old and new ciphertext after reopen", async () => {
    const eventDirectory = await directory("roundtrip");
    const secrets = keys(1, 2);
    let lifecycle = await EventKeyLifecycle.initializeFresh({
      directory: eventDirectory,
      secrets,
      keyReference,
      minimumActiveKeyVersion: 1,
    });
    const oldPath = await lifecycle.write("old", { generation: 1 });
    await lifecycle.rotate({
      expectedActiveKeyVersion: 1,
      nextKeyVersion: 2,
    });
    const newPath = await lifecycle.write("new", { generation: 2 });

    lifecycle = await EventKeyLifecycle.open({
      directory: eventDirectory,
      secrets,
      keyReference,
      minimumActiveKeyVersion: 2,
    });
    expect(lifecycle.status()).toMatchObject({
      revision: 2,
      activeKeyVersion: 2,
      readableKeyVersions: [1, 2],
    });
    await expect(lifecycle.read(oldPath)).resolves.toEqual({ generation: 1 });
    await expect(lifecycle.read(newPath)).resolves.toEqual({ generation: 2 });
    const newEnvelope = JSON.parse(await readFile(newPath, "utf8")) as {
      keyVersion: number;
    };
    expect(newEnvelope.keyVersion).toBe(2);
  });

  it("blocks restart when any activated key is unavailable", async () => {
    const eventDirectory = await directory("missing");
    const complete = keys(1, 2);
    const lifecycle = await EventKeyLifecycle.initializeFresh({
      directory: eventDirectory,
      secrets: complete,
      keyReference,
      minimumActiveKeyVersion: 1,
    });
    await lifecycle.rotate({
      expectedActiveKeyVersion: 1,
      nextKeyVersion: 2,
    });

    await expect(
      EventKeyLifecycle.open({
        directory: eventDirectory,
        secrets: keys(2),
        keyReference,
        minimumActiveKeyVersion: 2,
      }),
    ).rejects.toThrow("EVENT_KEY_UNAVAILABLE");
    await expect(
      EventKeyLifecycle.open({
        directory: eventDirectory,
        secrets: keys(1),
        keyReference,
        minimumActiveKeyVersion: 2,
      }),
    ).rejects.toThrow("EVENT_KEY_UNAVAILABLE");
  });

  it("rejects a valid record copied from another store domain", async () => {
    const leftDirectory = await directory("left");
    const rightDirectory = await directory("right");
    const secrets = keys(1, 2);
    const left = await EventKeyLifecycle.initializeFresh({
      directory: leftDirectory,
      secrets,
      keyReference,
      minimumActiveKeyVersion: 1,
    });
    await left.rotate({
      expectedActiveKeyVersion: 1,
      nextKeyVersion: 2,
    });
    await EventKeyLifecycle.initializeFresh({
      directory: rightDirectory,
      secrets,
      keyReference,
      minimumActiveKeyVersion: 1,
    });

    const copied = join(
      rightDirectory,
      ".event-key-state",
      "state-0000000002.json",
    );
    await copyFile(
      join(leftDirectory, ".event-key-state", "state-0000000002.json"),
      copied,
    );
    await chmod(copied, 0o600);
    await expect(
      EventKeyLifecycle.open({
        directory: rightDirectory,
        secrets,
        keyReference,
        minimumActiveKeyVersion: 1,
      }),
    ).rejects.toThrow("EVENT_KEY_STATE_CHAIN_INVALID");
  });

  it("rejects a chain gap instead of selecting a lower or higher partial head", async () => {
    const eventDirectory = await directory("gap");
    const secrets = keys(1, 2, 3);
    const lifecycle = await EventKeyLifecycle.initializeFresh({
      directory: eventDirectory,
      secrets,
      keyReference,
      minimumActiveKeyVersion: 1,
    });
    await lifecycle.rotate({
      expectedActiveKeyVersion: 1,
      nextKeyVersion: 2,
    });
    await lifecycle.rotate({
      expectedActiveKeyVersion: 2,
      nextKeyVersion: 3,
    });
    await rm(join(eventDirectory, ".event-key-state", "state-0000000002.json"));
    await expect(
      EventKeyLifecycle.open({
        directory: eventDirectory,
        secrets,
        keyReference,
        minimumActiveKeyVersion: 3,
      }),
    ).rejects.toThrow("EVENT_KEY_STATE_CHAIN_INVALID");
  });

  it("requires an external minimum anchor and rejects a truncated valid prefix", async () => {
    const eventDirectory = await directory("truncated-tail");
    const secrets = keys(1, 2);
    const lifecycle = await EventKeyLifecycle.initializeFresh({
      directory: eventDirectory,
      secrets,
      keyReference,
      minimumActiveKeyVersion: 1,
    });
    await lifecycle.rotate({
      expectedActiveKeyVersion: 1,
      nextKeyVersion: 2,
    });
    await rm(join(eventDirectory, ".event-key-state", "state-0000000002.json"));

    await expect(
      EventKeyLifecycle.open({
        directory: eventDirectory,
        secrets,
        keyReference,
      } as never),
    ).rejects.toThrow("EVENT_KEY_LIFECYCLE_OPTIONS_INVALID");
    await expect(
      EventKeyLifecycle.open({
        directory: eventDirectory,
        secrets,
        keyReference,
        minimumActiveKeyVersion: 2,
      }),
    ).rejects.toThrow("EVENT_KEY_ACTIVE_VERSION_BELOW_MINIMUM");
  });
});
