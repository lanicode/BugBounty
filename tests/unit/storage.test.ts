import { randomBytes } from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  readdir,
  realpath,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import type * as FsPromises from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { AuditLog, verifyAuditLog } from "../../packages/audit-log/audit.js";
import {
  EncryptedEventStore,
  MAX_EVENT_ENVELOPE_BYTES,
} from "../../packages/event-store/store.js";
import {
  InMemorySecretStore,
  type SecretStore,
} from "../../packages/secret-store/store.js";

describe("encrypted event store", () => {
  it("round-trips ciphertext and detects tampering", async ({ task }) => {
    const directory = join("/tmp", `bbc-${process.pid}-${task.id}`);
    const secrets = new InMemorySecretStore();
    secrets.set("keychain://test/event-v1", randomBytes(32));
    const store = new EncryptedEventStore(
      directory,
      secrets,
      (version) => `keychain://test/event-v${version}`,
    );
    const path = await store.write("event-1", { safe: "redacted" });
    await expect(
      store.write("event-1", { safe: "replacement" }),
    ).rejects.toThrow();
    expect(await readdir(directory)).toEqual(["event-1.events.enc"]);
    expect(await readFile(path, "utf8")).not.toContain("redacted");
    expect(await store.read(path)).toEqual({ safe: "redacted" });
    const envelope = JSON.parse(await readFile(path, "utf8")) as {
      ciphertext: string;
    };
    envelope.ciphertext = `${envelope.ciphertext.slice(0, -2)}AA`;
    await writeFile(path, JSON.stringify(envelope));
    await chmod(path, 0o600);
    await expect(store.read(path)).rejects.toThrow("EVENT_INTEGRITY_FAILED");
  });
  it("has no plaintext fallback when the key is absent", async ({ task }) => {
    const store = new EncryptedEventStore(
      join("/tmp", `bbc-missing-${process.pid}-${task.id}`),
      new InMemorySecretStore(),
      () => "keychain://test/missing",
    );
    await expect(store.write("event", { safe: true })).rejects.toThrow(
      "SECRET_NOT_FOUND",
    );
  });

  it("enforces an explicit positive and ordered readable key set", () => {
    const secrets = new InMemorySecretStore();
    expect(
      () => new EncryptedEventStore("/tmp/events", secrets, () => "ref", 0),
    ).toThrow("EVENT_KEY_VERSION_INVALID");
    expect(
      () =>
        new EncryptedEventStore("/tmp/events", secrets, () => "ref", 1, [1, 1]),
    ).toThrow("EVENT_READABLE_KEY_VERSIONS_INVALID");
    expect(
      () =>
        new EncryptedEventStore("/tmp/events", secrets, () => "ref", 1, [2]),
    ).toThrow("EVENT_READABLE_KEY_VERSIONS_INVALID");

    let getterCalls = 0;
    const accessorVersions = [1];
    Object.defineProperty(accessorVersions, "0", {
      configurable: true,
      enumerable: true,
      get() {
        getterCalls += 1;
        return 1;
      },
    });
    expect(
      () =>
        new EncryptedEventStore(
          "/tmp/events",
          secrets,
          () => "ref",
          1,
          accessorVersions,
        ),
    ).toThrow("EVENT_READABLE_KEY_VERSIONS_INVALID");
    expect(getterCalls).toBe(0);
  });

  it("rejects an unactivated envelope version before resolving a secret", async ({
    task,
  }) => {
    const directory = join("/tmp", `bbc-version-${process.pid}-${task.id}`);
    const secrets = new InMemorySecretStore();
    secrets.set("keychain://test/event-v1", randomBytes(32));
    const writer = new EncryptedEventStore(
      directory,
      secrets,
      (version) => `keychain://test/event-v${String(version)}`,
    );
    const path = await writer.write("event", { safe: true });
    const envelope = JSON.parse(await readFile(path, "utf8")) as {
      keyVersion: number;
    };
    envelope.keyVersion = 2;
    await writeFile(path, JSON.stringify(envelope), "utf8");
    let secretCalls = 0;
    let referenceCalls = 0;
    const neverSecrets: SecretStore = {
      get() {
        secretCalls += 1;
        return Promise.reject(new Error("SHOULD_NOT_BE_CALLED"));
      },
    };
    const reader = new EncryptedEventStore(
      directory,
      neverSecrets,
      () => {
        referenceCalls += 1;
        return "keychain://test/event-v1";
      },
      1,
      [1],
    );
    await expect(reader.read(path)).rejects.toThrow(
      "EVENT_KEY_VERSION_NOT_READABLE",
    );
    expect(referenceCalls).toBe(0);
    expect(secretCalls).toBe(0);
  });

  it("strictly validates envelope encoding, sizes, and regular files", async ({
    task,
  }) => {
    const directory = join("/tmp", `bbc-envelope-${process.pid}-${task.id}`);
    const secrets = new InMemorySecretStore();
    secrets.set("keychain://test/event-v1", randomBytes(32));
    const store = new EncryptedEventStore(
      directory,
      secrets,
      () => "keychain://test/event-v1",
    );
    const path = await store.write("event", { safe: true });
    const valid = JSON.parse(await readFile(path, "utf8")) as Record<
      string,
      unknown
    >;
    for (const mutation of [
      { ...valid, nonce: "***" },
      { ...valid, nonce: Buffer.alloc(11).toString("base64") },
      { ...valid, tag: Buffer.alloc(15).toString("base64") },
      { ...valid, ciphertext: "A===" },
      { ...valid, extra: true },
    ]) {
      await writeFile(path, JSON.stringify(mutation), "utf8");
      await expect(store.read(path)).rejects.toThrow("EVENT_ENVELOPE_INVALID");
    }
    await writeFile(path, "x".repeat(MAX_EVENT_ENVELOPE_BYTES + 1), "utf8");
    await expect(store.read(path)).rejects.toThrow("EVENT_ENVELOPE_INVALID");

    const target = join(directory, "outside.txt");
    await writeFile(target, JSON.stringify(valid), "utf8");
    const linked = join(directory, "linked.events.enc");
    await symlink(target, linked);
    await expect(store.read(linked)).rejects.toThrow("EVENT_ENVELOPE_INVALID");
  });

  it("rejects an oversized serialized envelope before creating any file", async ({
    task,
  }) => {
    const directory = join("/tmp", `bbc-oversized-${process.pid}-${task.id}`);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const secrets = new InMemorySecretStore();
    secrets.set("keychain://test/event-v1", randomBytes(32));
    const store = new EncryptedEventStore(
      directory,
      secrets,
      () => "keychain://test/event-v1",
    );

    await expect(
      store.write("oversized", {
        safe: "x".repeat(MAX_EVENT_ENVELOPE_BYTES),
      }),
    ).rejects.toThrow("EVENT_ENVELOPE_TOO_LARGE");
    expect(await readdir(directory)).toEqual([]);
  });

  it("fsyncs the parent directory after publish and temporary cleanup", async ({
    task,
  }) => {
    const directory = resolve(
      join("/tmp", `bbc-directory-sync-${process.pid}-${task.id}`),
    );
    const directorySyncs: string[] = [];
    vi.resetModules();
    vi.doMock("node:fs/promises", async (importOriginal) => {
      const actual = await importOriginal<typeof FsPromises>();
      return {
        ...actual,
        open: async (...args: Parameters<typeof actual.open>) => {
          const handle = await actual.open(...args);
          if (resolve(String(args[0])) === directory) {
            const sync = handle.sync.bind(handle);
            Object.defineProperty(handle, "sync", {
              configurable: true,
              value: async () => {
                directorySyncs.push(directory);
                await sync();
              },
            });
          }
          return handle;
        },
      };
    });
    try {
      const { EncryptedEventStore: IsolatedEventStore } =
        await import("../../packages/event-store/store.js");
      const secrets = new InMemorySecretStore();
      secrets.set("keychain://test/event-v1", randomBytes(32));
      const store = new IsolatedEventStore(
        directory,
        secrets,
        () => "keychain://test/event-v1",
      );
      await store.write("event", { safe: true });
      expect(directorySyncs).toEqual([directory, directory]);
    } finally {
      vi.doUnmock("node:fs/promises");
      vi.resetModules();
    }
  });

  it("fails closed when temporary cleanup fails", async ({ task }) => {
    const directory = resolve(
      join("/tmp", `bbc-cleanup-failure-${process.pid}-${task.id}`),
    );
    vi.resetModules();
    vi.doMock("node:fs/promises", async (importOriginal) => {
      const actual = await importOriginal<typeof FsPromises>();
      return {
        ...actual,
        unlink: async (...args: Parameters<typeof actual.unlink>) => {
          if (basename(String(args[0])).startsWith(".tmp-"))
            throw new Error("INJECTED_TEMP_CLEANUP_FAILURE");
          await actual.unlink(...args);
        },
      };
    });
    try {
      const { EncryptedEventStore: IsolatedEventStore } =
        await import("../../packages/event-store/store.js");
      const secrets = new InMemorySecretStore();
      secrets.set("keychain://test/event-v1", randomBytes(32));
      const store = new IsolatedEventStore(
        directory,
        secrets,
        () => "keychain://test/event-v1",
      );
      await expect(store.write("event", { safe: true })).rejects.toThrow(
        "INJECTED_TEMP_CLEANUP_FAILURE",
      );
      const names = await readdir(directory);
      expect(names).toContain("event.events.enc");
      expect(names.some((name) => name.startsWith(".tmp-"))).toBe(true);
      await Promise.all(names.map((name) => unlink(join(directory, name))));
    } finally {
      vi.doUnmock("node:fs/promises");
      vi.resetModules();
    }
  });

  it("zeroizes every key buffer returned by the secret store", async ({
    task,
  }) => {
    const directory = join("/tmp", `bbc-zeroize-${process.pid}-${task.id}`);
    const original = Uint8Array.from(randomBytes(32));
    const supplied: Uint8Array[] = [];
    const secrets: SecretStore = {
      get() {
        const copy = Uint8Array.from(original);
        supplied.push(copy);
        return Promise.resolve(copy);
      },
    };
    const store = new EncryptedEventStore(
      directory,
      secrets,
      () => "keychain://test/event-v1",
    );
    const path = await store.write("event", { safe: true });
    await expect(store.read(path)).resolves.toEqual({ safe: true });
    expect(supplied).toHaveLength(2);
    for (const key of supplied) expect(key).toEqual(new Uint8Array(32));

    await mkdir(join(directory, "nested"), { recursive: true });
    await expect(
      store.read(join(directory, "nested", "event.events.enc")),
    ).rejects.toThrow("EVENT_PATH_INVALID");
  });
});

describe("audit chain", () => {
  it("verifies and detects manipulation", async ({ task }) => {
    const directory = join("/tmp", `audit-${process.pid}-${task.id}`);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);
    const path = join(await realpath(directory), "audit.jsonl");
    const log = new AuditLog(path);
    await log.append({
      timestamp: "2026-01-01T00:00:00Z",
      action: "capture",
      decision: "allow",
      reasonCode: "ALLOW_TARGET",
      policyHash: "a".repeat(64),
    });
    await log.append({
      timestamp: "2026-01-01T00:00:01Z",
      action: "capture",
      decision: "block",
      reasonCode: "BLOCK_HOST",
      policyHash: "a".repeat(64),
    });
    await expect(verifyAuditLog(path)).resolves.toEqual({
      valid: true,
      entries: 2,
    });
    const source = await readFile(path, "utf8");
    await writeFile(path, source.replace("BLOCK_HOST", "BLOCK_PORT"));
    await expect(verifyAuditLog(path)).rejects.toThrow("AUDIT_CHAIN_INVALID");
  });
  it("rejects body-like or unsafe audit values", async ({ task }) => {
    const directory = join("/tmp", `audit-unsafe-${process.pid}-${task.id}`);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);
    const log = new AuditLog(join(await realpath(directory), "audit.jsonl"));
    await expect(
      log.append({
        timestamp: "2026-01-01T00:00:00Z",
        action: "{body}",
        decision: "allow",
        reasonCode: "ALLOW",
        policyHash: "a".repeat(64),
      }),
    ).rejects.toThrow("AUDIT_VALUE_INVALID");
  });
});
