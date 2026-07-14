import { randomBytes } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EventKeyLifecycle } from "../../packages/event-key-lifecycle/index.js";
import { MAX_EVENT_ENVELOPE_BYTES } from "../../packages/event-store/index.js";
import {
  InMemorySecretStore,
  type SecretStore,
} from "../../packages/secret-store/index.js";
import { canonicalJson } from "../../packages/shared/canonical.js";

const roots: string[] = [];
const LOCK_NAME = ".event-key-mutation.lock";
const KEY_REFERENCE = (version: number): string =>
  `secret://event-key/v${String(version)}`;

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function testDirectory(label: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `event-key-lease-${label}-`));
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

function options(directory: string, secrets: SecretStore) {
  return {
    directory,
    secrets,
    keyReference: KEY_REFERENCE,
    minimumActiveKeyVersion: 1,
  };
}

function lockSource(token = "a".repeat(32), ownerPid = 2_147_483_647): string {
  return canonicalJson({ ownerPid, schemaVersion: 1, token });
}

async function createLock(directory: string, source = lockSource()) {
  const path = join(directory, LOCK_NAME);
  await writeFile(path, source, { flag: "wx", mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

describe("event key directory mutation lease", () => {
  it("keeps a valid foreign or stale lock fail-closed until explicit recovery", async () => {
    const directory = await testDirectory("stale");
    const secrets = secretStore([1, 2]);
    const lifecycle = await EventKeyLifecycle.initializeFresh(
      options(directory, secrets),
    );
    const existingEvent = await lifecycle.write("existing", { value: 1 });
    const lockPath = await createLock(directory);

    await expect(
      EventKeyLifecycle.open(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCKED");
    await expect(lifecycle.write("blocked", { blocked: true })).rejects.toThrow(
      "EVENT_KEY_MUTATION_LOCKED",
    );
    await expect(lifecycle.read(existingEvent)).rejects.toThrow(
      "EVENT_KEY_MUTATION_LOCKED",
    );
    await expect(
      lifecycle.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 2 }),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCKED");

    expect(await readFile(lockPath, "utf8")).toBe(lockSource());
    expect((await lstat(lockPath)).mode & 0o777).toBe(0o600);
    await expect(
      lstat(join(directory, "blocked.events.enc")),
    ).rejects.toThrow();
    await expect(
      lstat(join(directory, ".event-key-state", "state-0000000002.json")),
    ).rejects.toThrow();
  });

  it("holds one exact private canonical lock across refresh and write", async () => {
    const directory = await testDirectory("held");
    const backing = secretStore([1, 2]);
    await EventKeyLifecycle.initializeFresh(options(directory, backing));
    const gate = new GatedSecretStore(backing);
    const writer = await EventKeyLifecycle.open(options(directory, gate));
    const rotator = await EventKeyLifecycle.open(options(directory, backing));

    gate.blockNextGet();
    const pendingWrite = writer.write("serialized", { version: 1 });
    await gate.waitUntilBlocked();

    const lockPath = join(directory, LOCK_NAME);
    const source = await readFile(lockPath, "utf8");
    const parsed = JSON.parse(source) as Record<string, unknown>;
    expect(source).toBe(canonicalJson(parsed));
    expect(Object.keys(parsed).sort()).toEqual([
      "ownerPid",
      "schemaVersion",
      "token",
    ]);
    expect(parsed).toMatchObject({ schemaVersion: 1, ownerPid: process.pid });
    expect(parsed["token"]).toMatch(/^[a-f0-9]{32}$/u);
    expect((await lstat(lockPath)).mode & 0o777).toBe(0o600);

    await expect(
      rotator.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 2 }),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCKED");
    gate.release();
    const eventPath = await pendingWrite;
    await expect(lstat(lockPath)).rejects.toThrow();
    const envelope = JSON.parse(await readFile(eventPath, "utf8")) as {
      keyVersion: number;
    };
    expect(envelope.keyVersion).toBe(1);

    await expect(
      rotator.rotate({ expectedActiveKeyVersion: 1, nextKeyVersion: 2 }),
    ).resolves.toMatchObject({ activeKeyVersion: 2, revision: 2 });
  });

  it("returns the exact lock reason to a competing rotation", async () => {
    const directory = await testDirectory("rotation-reason");
    const backing = secretStore([1, 2]);
    await EventKeyLifecycle.initializeFresh(options(directory, backing));
    const gate = new GatedSecretStore(backing);
    const winner = await EventKeyLifecycle.open(options(directory, gate));
    const contender = await EventKeyLifecycle.open(options(directory, backing));

    gate.blockNextGet();
    const pending = winner.rotate({
      expectedActiveKeyVersion: 1,
      nextKeyVersion: 2,
    });
    await gate.waitUntilBlocked();
    await expect(
      contender.rotate({
        expectedActiveKeyVersion: 1,
        nextKeyVersion: 2,
      }),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCKED");
    gate.release();
    await expect(pending).resolves.toMatchObject({
      revision: 2,
      activeKeyVersion: 2,
    });
  });

  it("recovers only explicitly and removes only strictly named private event temporaries", async () => {
    const directory = await testDirectory("recover");
    const secrets = secretStore([1]);
    const lifecycle = await EventKeyLifecycle.initializeFresh(
      options(directory, secrets),
    );
    const eventPath = await lifecycle.write("preserved", { value: "kept" });
    const lockPath = await createLock(directory);
    const temporary = join(directory, ".tmp-4242-0123456789abcdef");
    await writeFile(temporary, "partial", { mode: 0o600 });
    await chmod(temporary, 0o600);

    await expect(
      EventKeyLifecycle.open(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCKED");
    await expect(
      EventKeyLifecycle.recoverStaleMutation(options(directory, secrets)),
    ).resolves.toMatchObject({
      revision: 1,
      activeKeyVersion: 1,
      recoveredExistingLock: true,
      removedEventTemporaryFiles: 1,
    });

    await expect(lstat(lockPath)).rejects.toThrow();
    await expect(lstat(temporary)).rejects.toThrow();
    const reopened = await EventKeyLifecycle.open(options(directory, secrets));
    await expect(reopened.read(eventPath)).resolves.toEqual({ value: "kept" });
  });

  it("refuses explicit recovery while the exact lock owner PID is alive", async () => {
    const directory = await testDirectory("active-owner");
    const secrets = secretStore([1]);
    await EventKeyLifecycle.initializeFresh(options(directory, secrets));
    const source = lockSource("b".repeat(32), process.pid);
    const lockPath = await createLock(directory, source);

    await expect(
      EventKeyLifecycle.recoverStaleMutation(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCK_ACTIVE");
    expect(await readFile(lockPath, "utf8")).toBe(source);
  });

  it("requires explicit recovery for an orphan event temporary even without a lock", async () => {
    const directory = await testDirectory("orphan");
    const secrets = secretStore([1]);
    await EventKeyLifecycle.initializeFresh(options(directory, secrets));
    const temporary = join(directory, ".tmp-7-fedcba9876543210");
    await writeFile(temporary, "", { mode: 0o600 });
    await chmod(temporary, 0o600);

    await expect(
      EventKeyLifecycle.open(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_MUTATION_RECOVERY_REQUIRED");
    const receipt = await EventKeyLifecycle.recoverStaleMutation(
      options(directory, secrets),
    );
    expect(receipt).toMatchObject({
      recoveredExistingLock: false,
      removedEventTemporaryFiles: 1,
    });
    await expect(lstat(temporary)).rejects.toThrow();
  });

  it.each([
    ["noncanonical", `${lockSource()}\n`, 0o600],
    ["unknown-field", canonicalJson({ extra: true }), 0o600],
    [
      "zero-pid",
      canonicalJson({ ownerPid: 0, schemaVersion: 1, token: "a".repeat(32) }),
      0o600,
    ],
    [
      "fractional-pid",
      canonicalJson({
        ownerPid: 1.5,
        schemaVersion: 1,
        token: "a".repeat(32),
      }),
      0o600,
    ],
    [
      "out-of-range-pid",
      canonicalJson({
        ownerPid: 2_147_483_648,
        schemaVersion: 1,
        token: "a".repeat(32),
      }),
      0o600,
    ],
    ["wrong-mode", lockSource(), 0o640],
  ] as const)(
    "rejects an invalid %s lock without deleting it",
    async (_label, source, mode) => {
      const directory = await testDirectory(`invalid-${_label}`);
      const secrets = secretStore([1]);
      await EventKeyLifecycle.initializeFresh(options(directory, secrets));
      const lockPath = await createLock(directory, source);
      await chmod(lockPath, mode);

      await expect(
        EventKeyLifecycle.open(options(directory, secrets)),
      ).rejects.toThrow("EVENT_KEY_MUTATION_LOCK_INVALID");
      await expect(
        EventKeyLifecycle.recoverStaleMutation(options(directory, secrets)),
      ).rejects.toThrow("EVENT_KEY_MUTATION_LOCK_INVALID");
      expect(await readFile(lockPath, "utf8")).toBe(source);
    },
  );

  it("rejects a symlink lock and does not follow or remove its target", async () => {
    const directory = await testDirectory("symlink");
    const secrets = secretStore([1]);
    await EventKeyLifecycle.initializeFresh(options(directory, secrets));
    const target = join(
      directory,
      "..",
      `lock-target-${randomBytes(4).toString("hex")}`,
    );
    await writeFile(target, lockSource(), { mode: 0o600 });
    await symlink(target, join(directory, LOCK_NAME));

    await expect(
      EventKeyLifecycle.open(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCK_INVALID");
    await expect(
      EventKeyLifecycle.recoverStaleMutation(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCK_INVALID");
    expect(await readFile(target, "utf8")).toBe(lockSource());
  });

  it("never removes malformed, public, or unknown files during recovery", async () => {
    const directory = await testDirectory("strict-recovery");
    const secrets = secretStore([1]);
    await EventKeyLifecycle.initializeFresh(options(directory, secrets));
    await createLock(directory);
    const publicTemporary = join(directory, ".tmp-9-0123456789abcdef");
    await writeFile(publicTemporary, "partial", { mode: 0o600 });
    await chmod(publicTemporary, 0o644);
    const unknown = join(directory, ".tmp-event-arbitrary");
    await writeFile(unknown, "do-not-delete", { mode: 0o600 });

    await expect(
      EventKeyLifecycle.recoverStaleMutation(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_EVENT_TEMP_INVALID");
    expect(await readFile(publicTemporary, "utf8")).toBe("partial");
    expect(await readFile(unknown, "utf8")).toBe("do-not-delete");
  });

  it("prevalidates the whole directory before removing a recoverable temporary", async () => {
    const directory = await testDirectory("unknown-recovery");
    const secrets = secretStore([1]);
    await EventKeyLifecycle.initializeFresh(options(directory, secrets));
    await createLock(directory);
    const recoverable = join(directory, ".tmp-8-0123456789abcdef");
    await writeFile(recoverable, "partial", { mode: 0o600 });
    await chmod(recoverable, 0o600);
    const unknown = join(directory, ".tmp-x-0123456789abcdef");
    await writeFile(unknown, "unknown", { mode: 0o600 });

    await expect(
      EventKeyLifecycle.recoverStaleMutation(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_DIRECTORY_UNKNOWN_FILE");
    expect(await readFile(recoverable, "utf8")).toBe("partial");
    expect(await readFile(unknown, "utf8")).toBe("unknown");
  });

  it.each(["symlink", "directory", "oversize"] as const)(
    "never removes an exact-name %s event temporary during recovery",
    async (kind) => {
      const directory = await testDirectory(`temp-${kind}`);
      const secrets = secretStore([1]);
      await EventKeyLifecycle.initializeFresh(options(directory, secrets));
      await createLock(directory);
      const temporary = join(directory, ".tmp-77-0123456789abcdef");
      let target: string | undefined;
      if (kind === "symlink") {
        target = join(directory, "..", "event-temp-target");
        await writeFile(target, "preserve-target", { mode: 0o600 });
        await symlink(target, temporary);
      } else if (kind === "directory") {
        await mkdir(temporary, { mode: 0o700 });
      } else {
        await writeFile(temporary, "x".repeat(MAX_EVENT_ENVELOPE_BYTES + 1), {
          mode: 0o600,
        });
        await chmod(temporary, 0o600);
      }

      await expect(
        EventKeyLifecycle.recoverStaleMutation(options(directory, secrets)),
      ).rejects.toThrow();
      await expect(lstat(temporary)).resolves.toMatchObject({});
      if (target !== undefined)
        await expect(readFile(target, "utf8")).resolves.toBe("preserve-target");
      await expect(
        EventKeyLifecycle.open(options(directory, secrets)),
      ).rejects.toThrow();
    },
  );

  it("blocks fresh initialization and legacy adoption behind a foreign lock", async () => {
    const directory = await testDirectory("bootstrap");
    await mkdir(directory, { mode: 0o700 });
    await chmod(directory, 0o700);
    await createLock(directory);
    const secrets = secretStore([1]);

    await expect(
      EventKeyLifecycle.initializeFresh(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCKED");
    await expect(
      EventKeyLifecycle.adoptLegacyV1(options(directory, secrets)),
    ).rejects.toThrow("EVENT_KEY_MUTATION_LOCKED");
    await expect(lstat(join(directory, ".event-key-state"))).rejects.toThrow();
  });
});

class GatedSecretStore implements SecretStore {
  #block = false;
  #blockedResolve: (() => void) | undefined;
  #releaseResolve: (() => void) | undefined;
  #blocked = new Promise<void>((resolve) => {
    this.#blockedResolve = resolve;
  });
  #released = new Promise<void>((resolve) => {
    this.#releaseResolve = resolve;
  });

  public constructor(private readonly backing: SecretStore) {}

  public blockNextGet(): void {
    this.#block = true;
  }

  public waitUntilBlocked(): Promise<void> {
    return this.#blocked;
  }

  public release(): void {
    this.#releaseResolve?.();
  }

  public async get(reference: string): Promise<Uint8Array> {
    if (this.#block) {
      this.#block = false;
      this.#blockedResolve?.();
      await this.#released;
    }
    return this.backing.get(reference);
  }
}
