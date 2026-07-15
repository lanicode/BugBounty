import { randomBytes } from "node:crypto";
import {
  chmod,
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EventKeyLifecycle } from "../../packages/event-key-lifecycle/index.js";
import { EncryptedEventStore } from "../../packages/event-store/index.js";
import {
  InMemorySecretStore,
  type SecretStore,
} from "../../packages/secret-store/index.js";
import { canonicalJson } from "../../packages/shared/canonical.js";

const roots: string[] = [];
const KEY_REFERENCE = (version: number): string =>
  `secret://event-key/v${String(version)}`;

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function testDirectory(label: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `event-key-${label}-`));
  roots.push(root);
  return join(root, "events");
}

function secretStore(versions: readonly number[]): InMemorySecretStore {
  const secrets = new InMemorySecretStore();
  for (const version of versions) {
    const key = new Uint8Array(32).fill(version);
    key[0] = version;
    secrets.set(KEY_REFERENCE(version), key);
  }
  return secrets;
}

function options(
  directory: string,
  secrets: SecretStore,
  minimumActiveKeyVersion = 1,
) {
  return {
    directory,
    secrets,
    keyReference: KEY_REFERENCE,
    minimumActiveKeyVersion,
  };
}

describe("event key lifecycle", () => {
  it("rejects accessor and extra lifecycle options without invoking accessors", async () => {
    let getterCalls = 0;
    const accessorOptions = {
      get directory() {
        getterCalls += 1;
        return "/tmp/should-not-be-read";
      },
      secrets: secretStore([1]),
      keyReference: KEY_REFERENCE,
      minimumActiveKeyVersion: 1,
    };
    await expect(EventKeyLifecycle.open(accessorOptions)).rejects.toThrow(
      "EVENT_KEY_LIFECYCLE_OPTIONS_INVALID",
    );
    expect(getterCalls).toBe(0);
    await expect(
      EventKeyLifecycle.open({
        directory: "/tmp/event-key-extra",
        secrets: secretStore([1]),
        keyReference: KEY_REFERENCE,
        minimumActiveKeyVersion: 1,
        unexpected: true,
      } as never),
    ).rejects.toThrow("EVENT_KEY_LIFECYCLE_OPTIONS_INVALID");
  });

  it("initializes canonical v1 state, writes, and reopens without secrets in metadata", async () => {
    const directory = await testDirectory("fresh");
    const secrets = secretStore([1]);
    const lifecycle = await EventKeyLifecycle.initializeFresh(
      options(directory, secrets),
    );

    expect(lifecycle.status()).toMatchObject({
      schemaVersion: 1,
      revision: 1,
      activeKeyVersion: 1,
      readableKeyVersions: [1],
    });
    const eventPath = await lifecycle.write("event-v1", {
      marker: "encrypted-only",
    });
    expect(await lifecycle.read(eventPath)).toEqual({
      marker: "encrypted-only",
    });

    const statePath = join(
      directory,
      ".event-key-state",
      "state-0000000001.json",
    );
    const stateSource = await readFile(statePath, "utf8");
    const state = JSON.parse(stateSource) as Record<string, unknown>;
    expect(stateSource).toBe(canonicalJson(state));
    expect(state).toMatchObject({
      schemaVersion: 1,
      revision: 1,
      operation: "initialize",
      activeKeyVersion: 1,
      readableKeyVersions: [1],
      previousRecordDigest: "0".repeat(64),
    });
    expect(stateSource).not.toContain("secret://");
    expect(stateSource).not.toContain("encrypted-only");
    expect((await lstat(directory)).mode & 0o777).toBe(0o700);
    expect((await lstat(statePath)).mode & 0o777).toBe(0o600);

    const reopened = await EventKeyLifecycle.open(options(directory, secrets));
    expect(reopened.status()).toEqual(lifecycle.status());
    await expect(reopened.read(eventPath)).resolves.toEqual({
      marker: "encrypted-only",
    });
  });

  it("rotates monotonically, survives restart, writes new, and reads explicitly activated old", async () => {
    const directory = await testDirectory("rotate");
    const secrets = secretStore([1, 2]);
    const lifecycle = await EventKeyLifecycle.initializeFresh(
      options(directory, secrets),
    );
    const oldPath = await lifecycle.write("before-rotation", { version: 1 });

    await expect(
      lifecycle.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 2 }),
    ).resolves.toMatchObject({
      revision: 2,
      previousActiveKeyVersion: 1,
      activeKeyVersion: 2,
      readableKeyVersions: [1, 2],
    });
    const newPath = await lifecycle.write("after-rotation", { version: 2 });
    const newEnvelope = JSON.parse(await readFile(newPath, "utf8")) as {
      keyVersion: number;
    };
    expect(newEnvelope.keyVersion).toBe(2);

    const reopened = await EventKeyLifecycle.open(
      options(directory, secrets, 2),
    );
    await expect(reopened.read(oldPath)).resolves.toEqual({ version: 1 });
    await expect(reopened.read(newPath)).resolves.toEqual({ version: 2 });
    expect(reopened.status()).toMatchObject({
      revision: 2,
      activeKeyVersion: 2,
      readableKeyVersions: [1, 2],
    });
    expect(await readdir(join(directory, ".event-key-state"))).toEqual([
      "state-0000000001.json",
      "state-0000000002.json",
    ]);
  });

  it("fails closed without new or historical keys and never advances on failed rotation", async () => {
    const directory = await testDirectory("missing-keys");
    const initialSecrets = secretStore([1]);
    const lifecycle = await EventKeyLifecycle.initializeFresh(
      options(directory, initialSecrets),
    );
    await expect(
      lifecycle.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 2 }),
    ).rejects.toThrow("EVENT_KEY_UNAVAILABLE");
    expect(lifecycle.status().activeKeyVersion).toBe(1);
    expect(await readdir(join(directory, ".event-key-state"))).toEqual([
      "state-0000000001.json",
    ]);

    const bothSecrets = secretStore([1, 2]);
    const reopened = await EventKeyLifecycle.open(
      options(directory, bothSecrets),
    );
    await reopened.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 2 });
    await expect(
      EventKeyLifecycle.open(options(directory, secretStore([2]))),
    ).rejects.toThrow("EVENT_KEY_UNAVAILABLE");
  });

  it("rejects duplicate keys, stale versions, skips, rollback, and low minimum heads", async () => {
    const directory = await testDirectory("versions");
    const duplicateSecrets = new InMemorySecretStore();
    const duplicate = randomBytes(32);
    duplicateSecrets.set(KEY_REFERENCE(1), duplicate);
    duplicateSecrets.set(KEY_REFERENCE(2), duplicate);
    const lifecycle = await EventKeyLifecycle.initializeFresh(
      options(directory, duplicateSecrets),
    );

    await expect(
      lifecycle.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 2 }),
    ).rejects.toThrow("EVENT_KEY_DUPLICATE");
    await expect(
      lifecycle.rotate({ expectedActiveKeyVersion: 2, nextKeyVersion: 3 }),
    ).rejects.toThrow("EVENT_KEY_ROTATION_STALE");
    await expect(
      lifecycle.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 3 }),
    ).rejects.toThrow("EVENT_KEY_ROTATION_NON_MONOTONIC");
    await expect(
      lifecycle.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 1 }),
    ).rejects.toThrow("EVENT_KEY_ROTATION_NON_MONOTONIC");
    await expect(
      EventKeyLifecycle.open(options(directory, duplicateSecrets, 2)),
    ).rejects.toThrow("EVENT_KEY_ACTIVE_VERSION_BELOW_MINIMUM");
    await expect(
      EventKeyLifecycle.initializeFresh(
        options(await testDirectory("minimum"), secretStore([1]), 2),
      ),
    ).rejects.toThrow("EVENT_KEY_ACTIVE_VERSION_BELOW_MINIMUM");
  });

  it("adopts only authenticated legacy v1 events and never silently adopts v2", async () => {
    const directory = await testDirectory("legacy");
    const secrets = secretStore([1, 2]);
    const legacy = new EncryptedEventStore(
      directory,
      secrets,
      KEY_REFERENCE,
      1,
      [1],
    );
    const legacyPath = await legacy.write("legacy-event", { legacy: true });

    await expect(
      EventKeyLifecycle.openOrInitializeFresh(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_LEGACY_ADOPTION_REQUIRED");
    await expect(
      lstat(join(directory, ".event-key-state")),
    ).rejects.toMatchObject({ code: "ENOENT" });

    const adopted = await EventKeyLifecycle.adoptLegacyV1(
      options(directory, secrets),
    );
    await expect(adopted.read(legacyPath)).resolves.toEqual({ legacy: true });
    const state = JSON.parse(
      await readFile(
        join(directory, ".event-key-state", "state-0000000001.json"),
        "utf8",
      ),
    ) as { operation: string };
    expect(state.operation).toBe("adopt_legacy_v1");

    const v2Directory = await testDirectory("legacy-v2");
    const legacyV2 = new EncryptedEventStore(
      v2Directory,
      secrets,
      KEY_REFERENCE,
      2,
      [2],
    );
    await legacyV2.write("legacy-v2", { legacy: 2 });
    await expect(
      EventKeyLifecycle.adoptLegacyV1(options(v2Directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_LEGACY_INVALID");
  });

  it("opens, initializes, and safely retries a key failure with an otherwise empty state", async () => {
    const directory = await testDirectory("open-or-init");
    const secrets = secretStore([1]);
    const initialized = await EventKeyLifecycle.openOrInitializeFresh(
      options(directory, secrets),
    );
    expect(initialized.status().activeKeyVersion).toBe(1);
    const reopened = await EventKeyLifecycle.openOrInitializeFresh(
      options(directory, secrets),
    );
    expect(reopened.status()).toEqual(initialized.status());

    const emptyStateDirectory = await testDirectory("empty-state");
    const initiallyMissing = new InMemorySecretStore();
    await expect(
      EventKeyLifecycle.openOrInitializeFresh(
        options(emptyStateDirectory, initiallyMissing),
      ),
    ).rejects.toThrow("EVENT_KEY_UNAVAILABLE");
    expect(
      await readdir(join(emptyStateDirectory, ".event-key-state")),
    ).toEqual([]);
    initiallyMissing.set(KEY_REFERENCE(1), new Uint8Array(32).fill(1));
    await expect(
      EventKeyLifecycle.openOrInitializeFresh(
        options(emptyStateDirectory, initiallyMissing),
      ),
    ).resolves.toMatchObject({});
  });

  it("authenticates canonical state and blocks tampering, unknown files, and symlinks", async () => {
    const tamperedDirectory = await testDirectory("tamper");
    const secrets = secretStore([1]);
    await EventKeyLifecycle.initializeFresh(
      options(tamperedDirectory, secrets),
    );
    const statePath = join(
      tamperedDirectory,
      ".event-key-state",
      "state-0000000001.json",
    );
    const state = JSON.parse(await readFile(statePath, "utf8")) as {
      authenticationTag: string;
    };
    state.authenticationTag = `${state.authenticationTag.startsWith("f") ? "e" : "f"}${state.authenticationTag.slice(1)}`;
    await writeFile(statePath, canonicalJson(state), "utf8");
    await chmod(statePath, 0o600);
    await expect(
      EventKeyLifecycle.open(options(tamperedDirectory, secrets)),
    ).rejects.toThrow("EVENT_KEY_STATE_AUTHENTICATION_FAILED");

    const unknownDirectory = await testDirectory("unknown");
    await EventKeyLifecycle.initializeFresh(options(unknownDirectory, secrets));
    await writeFile(
      join(unknownDirectory, ".event-key-state", "unexpected"),
      "x",
      { mode: 0o600 },
    );
    await expect(
      EventKeyLifecycle.open(options(unknownDirectory, secrets)),
    ).rejects.toThrow("EVENT_KEY_STATE_UNKNOWN_FILE");

    const unknownRootDirectory = await testDirectory("unknown-root");
    await EventKeyLifecycle.initializeFresh(
      options(unknownRootDirectory, secrets),
    );
    await writeFile(join(unknownRootDirectory, "raw-event.json"), "{}", {
      mode: 0o600,
    });
    await expect(
      EventKeyLifecycle.open(options(unknownRootDirectory, secrets)),
    ).rejects.toThrow("EVENT_KEY_DIRECTORY_UNKNOWN_FILE");

    const symlinkDirectory = await testDirectory("symlink");
    await EventKeyLifecycle.initializeFresh(options(symlinkDirectory, secrets));
    const target = `${symlinkDirectory}-target`;
    await writeFile(target, "x", { mode: 0o600 });
    await symlink(
      target,
      join(symlinkDirectory, ".event-key-state", "state-0000000002.json"),
    );
    await expect(
      EventKeyLifecycle.open(options(symlinkDirectory, secrets)),
    ).rejects.toThrow("EVENT_KEY_STATE_SYMLINK");
  });

  it("allows only tightly named private temporary files", async () => {
    const directory = await testDirectory("temporary");
    const secrets = secretStore([1]);
    const lifecycle = await EventKeyLifecycle.initializeFresh(
      options(directory, secrets),
    );
    const temporary = join(
      directory,
      ".event-key-state",
      `.tmp-state-${String(process.pid)}-aaaaaaaaaaaaaaaa`,
    );
    await writeFile(temporary, "incomplete", { mode: 0o600 });
    await chmod(temporary, 0o600);
    await expect(
      EventKeyLifecycle.open(options(directory, secrets)),
    ).resolves.toMatchObject({});
    expect(lifecycle.status().activeKeyVersion).toBe(1);
  });

  it("requires exact 0700 directories and exact 0600 state and event files", async () => {
    const secrets = secretStore([1]);

    for (const mode of [0o640, 0o700]) {
      const directory = await testDirectory(`state-mode-${String(mode)}`);
      await EventKeyLifecycle.initializeFresh(options(directory, secrets));
      const statePath = join(
        directory,
        ".event-key-state",
        "state-0000000001.json",
      );
      await chmod(statePath, mode);
      await expect(
        EventKeyLifecycle.open(options(directory, secrets)),
      ).rejects.toThrow("EVENT_KEY_STATE_FILE_INVALID");
    }

    const eventDirectory = await testDirectory("event-mode");
    const lifecycle = await EventKeyLifecycle.initializeFresh(
      options(eventDirectory, secrets),
    );
    const eventPath = await lifecycle.write("event-mode", { value: true });
    await chmod(eventPath, 0o700);
    await expect(
      EventKeyLifecycle.open(options(eventDirectory, secrets)),
    ).rejects.toThrow("EVENT_KEY_LEGACY_INVALID");

    const rootDirectory = await testDirectory("root-mode");
    await EventKeyLifecycle.initializeFresh(options(rootDirectory, secrets));
    await chmod(rootDirectory, 0o1700);
    await expect(
      EventKeyLifecycle.open(options(rootDirectory, secrets)),
    ).rejects.toThrow("EVENT_KEY_DIRECTORY_PERMISSIONS");
  });

  it("rejects accessor, symbol, non-enumerable extra, and ordinary extra rotation fields without invoking accessors", async () => {
    const directory = await testDirectory("input");
    const secrets = secretStore([1, 2]);
    const lifecycle = await EventKeyLifecycle.initializeFresh(
      options(directory, secrets),
    );
    let getterCalls = 0;
    const accessor = {
      get expectedActiveKeyVersion() {
        getterCalls += 1;
        return 1;
      },
      nextKeyVersion: 2,
    };
    await expect(lifecycle.rotate(accessor as never)).rejects.toThrow(
      "EVENT_KEY_ROTATION_INPUT_INVALID",
    );
    expect(getterCalls).toBe(0);

    const withSymbol = {
      expectedActiveKeyVersion: 1,
      nextKeyVersion: 2,
      [Symbol("extra")]: true,
    };
    await expect(lifecycle.rotate(withSymbol)).rejects.toThrow(
      "EVENT_KEY_ROTATION_INPUT_INVALID",
    );

    const withHidden = {
      expectedActiveKeyVersion: 1,
      nextKeyVersion: 2,
    };
    Object.defineProperty(withHidden, "hidden", { value: true });
    await expect(lifecycle.rotate(withHidden)).rejects.toThrow(
      "EVENT_KEY_ROTATION_INPUT_INVALID",
    );
    await expect(
      lifecycle.rotate({
        expectedActiveKeyVersion: 1,
        nextKeyVersion: 2,
        extra: true,
      } as never),
    ).rejects.toThrow("EVENT_KEY_ROTATION_INPUT_INVALID");
  });

  it("serializes competing rotations so exactly one immutable next record wins", async () => {
    const directory = await testDirectory("conflict");
    const secrets = secretStore([1, 2]);
    await EventKeyLifecycle.initializeFresh(options(directory, secrets));
    const left = await EventKeyLifecycle.open(options(directory, secrets));
    const right = await EventKeyLifecycle.open(options(directory, secrets));
    const results = await Promise.allSettled([
      left.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 2 }),
      right.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 2 }),
    ]);
    expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(
      1,
    );
    expect(results.filter(({ status }) => status === "rejected")).toHaveLength(
      1,
    );
    const reopened = await EventKeyLifecycle.open(options(directory, secrets));
    expect(reopened.status()).toMatchObject({
      revision: 2,
      activeKeyVersion: 2,
    });
  });

  it("zeroizes every lifecycle-owned key copy on success and failure", async () => {
    const directory = await testDirectory("zeroize");
    const tracking = new TrackingSecretStore();
    tracking.set(KEY_REFERENCE(1), new Uint8Array(32).fill(1));
    tracking.set(KEY_REFERENCE(2), new Uint8Array(32).fill(2));
    const lifecycle = await EventKeyLifecycle.initializeFresh(
      options(directory, tracking),
    );
    await lifecycle.rotate({
      expectedActiveKeyVersion: 1,
      nextKeyVersion: 2,
    });
    await expect(
      lifecycle.rotate({ expectedActiveKeyVersion: 2, nextKeyVersion: 3 }),
    ).rejects.toThrow("EVENT_KEY_UNAVAILABLE");
    expect(tracking.returned.length).toBeGreaterThan(0);
    expect(
      tracking.returned.every((key) => key.every((value) => value === 0)),
    ).toBe(true);
  });
});

class TrackingSecretStore implements SecretStore {
  readonly #values = new Map<string, Uint8Array>();
  readonly returned: Uint8Array[] = [];

  public set(reference: string, value: Uint8Array): void {
    this.#values.set(reference, Uint8Array.from(value));
  }

  public get(reference: string): Promise<Uint8Array> {
    const stored = this.#values.get(reference);
    if (stored === undefined)
      return Promise.reject(new Error("SECRET_NOT_FOUND"));
    const copy = Uint8Array.from(stored);
    this.returned.push(copy);
    return Promise.resolve(copy);
  }
}
