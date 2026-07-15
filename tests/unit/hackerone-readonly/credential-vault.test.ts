import { appendFile, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import type { SecretStore } from "../../../packages/secret-store/index.js";
import { sha256 } from "../../../packages/shared/canonical.js";
import {
  consumeHackerOneCredentialLease,
  HackerOneCredentialVault,
  MacOSHackerOneKeychainMutationBackend,
  prepareMacOSHackerOneKeychainHelper,
  SpawnHackerOneKeychainHelperRunner,
  type HackerOneKeychainMutationBackend,
  type HackerOneKeychainHelperOperation,
  type HackerOneKeychainHelperProcess,
  type HackerOneKeychainHelperRunner,
} from "../../../packages/hackerone-readonly/credential-vault.js";
import {
  HACKERONE_IDENTIFIER_REFERENCE,
  HACKERONE_TOKEN_REFERENCE,
} from "../../../packages/hackerone-readonly/types.js";

const encoder = new TextEncoder();
const HELPER_SOURCE_PATH = fileURLToPath(
  new URL(
    "../../../packages/hackerone-readonly/native/macos-keychain-helper.c",
    import.meta.url,
  ),
);
const SYNTHETIC_IDENTIFIER = "synthetic-identifier-value";
const SYNTHETIC_TOKEN = "synthetic-token-value";

function syntheticCredentialEnvelope(
  role: "identifier" | "token",
  value = "printable-secret",
): Uint8Array {
  const generation = Buffer.alloc(16, 1).toString("base64url");
  const encodedSecret = Buffer.from(value, "utf8").toString("base64url");
  return encoder.encode(
    `BBC-H1-CRED-V1.${role === "identifier" ? "i" : "t"}.${generation}.${encodedSecret}`,
  );
}

class RecordingSecretStore implements SecretStore {
  public readonly calls: string[] = [];
  public readonly returned: Uint8Array[] = [];
  public readonly values = new Map<string, Uint8Array>();
  public readonly failures = new Set<string>();

  public get(reference: string): Promise<Uint8Array> {
    this.calls.push(reference);
    if (this.failures.has(reference))
      return Promise.reject(new Error("SYNTHETIC_SECRET_BACKEND_DETAIL"));
    const stored = this.values.get(reference);
    if (stored === undefined)
      return Promise.reject(new Error("SYNTHETIC_SECRET_MISSING_DETAIL"));
    const result = Uint8Array.from(stored);
    this.returned.push(result);
    return Promise.resolve(result);
  }
}

type MutationName =
  "deleteIdentifier" | "deleteToken" | "storeIdentifier" | "storeToken";

class RecordingMutationBackend implements HackerOneKeychainMutationBackend {
  public readonly calls: MutationName[] = [];
  public readonly copies: Uint8Array[] = [];
  public readonly references: Uint8Array[] = [];
  public readonly failures = new Set<MutationName>();
  public readonly synchronousFailures = new Set<MutationName>();

  public constructor(private readonly persisted?: RecordingSecretStore) {}

  public storeIdentifier(value: Uint8Array): Promise<void> {
    return this.store("storeIdentifier", HACKERONE_IDENTIFIER_REFERENCE, value);
  }

  public storeToken(value: Uint8Array): Promise<void> {
    return this.store("storeToken", HACKERONE_TOKEN_REFERENCE, value);
  }

  public deleteIdentifier(): Promise<void> {
    return this.remove("deleteIdentifier", HACKERONE_IDENTIFIER_REFERENCE);
  }

  public deleteToken(): Promise<void> {
    return this.remove("deleteToken", HACKERONE_TOKEN_REFERENCE);
  }

  private async store(
    name: MutationName,
    reference: string,
    value: Uint8Array,
  ): Promise<void> {
    this.copies.push(Uint8Array.from(value));
    this.references.push(value);
    await this.invoke(name);
    this.persisted?.values.set(reference, Uint8Array.from(value));
  }

  private async remove(name: MutationName, reference: string): Promise<void> {
    await this.invoke(name);
    this.persisted?.values.delete(reference);
  }

  private invoke(name: MutationName): Promise<void> {
    this.calls.push(name);
    if (this.synchronousFailures.has(name))
      throw new Error("SYNTHETIC_SYNCHRONOUS_KEYCHAIN_DETAIL");
    return this.failures.has(name)
      ? Promise.reject(new Error("SYNTHETIC_KEYCHAIN_INTERNAL_DETAIL"))
      : Promise.resolve();
  }
}

class RecordingKeychainHelperRunner implements HackerOneKeychainHelperRunner {
  public readonly calls: {
    readonly operation: HackerOneKeychainHelperOperation;
    readonly secretCopy: Uint8Array | null;
    readonly secretReference: Uint8Array | undefined;
  }[] = [];

  public constructor(private readonly persisted?: RecordingSecretStore) {}

  public execute(
    operation: HackerOneKeychainHelperOperation,
    secret?: Uint8Array,
  ): Promise<Uint8Array | undefined> {
    this.calls.push({
      operation,
      secretCopy: secret === undefined ? null : Uint8Array.from(secret),
      secretReference: secret,
    });
    const reference = operation.endsWith("-identifier")
      ? HACKERONE_IDENTIFIER_REFERENCE
      : operation.endsWith("-token")
        ? HACKERONE_TOKEN_REFERENCE
        : undefined;
    if (reference !== undefined && operation.startsWith("read-")) {
      const value = this.persisted?.values.get(reference);
      return value === undefined
        ? Promise.reject(new Error("SYNTHETIC_HELPER_SECRET_MISSING"))
        : Promise.resolve(Uint8Array.from(value));
    }
    if (reference !== undefined && secret !== undefined)
      this.persisted?.values.set(reference, Uint8Array.from(secret));
    else if (reference !== undefined && operation.startsWith("delete-"))
      this.persisted?.values.delete(reference);
    return Promise.resolve(undefined);
  }
}

class FailingKeychainHelperProcess implements HackerOneKeychainHelperProcess {
  public input: Uint8Array | undefined;
  public killCount = 0;
  public listenersRemoved = false;
  private stdinError: (() => void) | undefined;
  private childError: (() => void) | undefined;

  public constructor(
    private readonly failure: "child-error" | "stdin-error" | "sync-throw",
  ) {}

  public onStdoutData(listener: (chunk: unknown) => void): void {
    void listener;
  }

  public onStderrData(listener: (chunk: unknown) => void): void {
    void listener;
  }

  public onStdinError(listener: () => void): void {
    this.stdinError = listener;
  }

  public onError(listener: () => void): void {
    this.childError = listener;
  }

  public onClose(
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): void {
    void listener;
  }

  public writeInput(input: Uint8Array | undefined): void {
    this.input = input;
    if (this.failure === "sync-throw")
      throw new Error("SYNTHETIC_STDIN_END_FAILURE");
    if (this.failure === "stdin-error") this.stdinError?.();
    else this.childError?.();
  }

  public removeAllListeners(): void {
    this.listenersRemoved = true;
    this.stdinError = undefined;
    this.childError = undefined;
  }

  public kill(): void {
    this.killCount += 1;
  }
}

class SuccessfulKeychainHelperProcess implements HackerOneKeychainHelperProcess {
  public inputReference: Uint8Array | undefined;
  public inputSnapshot: Uint8Array | undefined;
  public listenersRemoved = false;
  private closeListener:
    ((code: number | null, signal: NodeJS.Signals | null) => void) | undefined;
  private stdoutListener: ((chunk: unknown) => void) | undefined;

  public constructor(private readonly stdout?: Buffer) {}

  public onStdoutData(listener: (chunk: unknown) => void): void {
    this.stdoutListener = listener;
  }

  public onStderrData(listener: (chunk: unknown) => void): void {
    void listener;
  }

  public onStdinError(listener: () => void): void {
    void listener;
  }

  public onError(listener: () => void): void {
    void listener;
  }

  public onClose(
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): void {
    this.closeListener = listener;
  }

  public writeInput(input: Uint8Array | undefined): void {
    this.inputReference = input;
    this.inputSnapshot =
      input === undefined ? undefined : Uint8Array.from(input);
    if (this.stdout !== undefined) this.stdoutListener?.(this.stdout);
    this.closeListener?.(0, null);
  }

  public removeAllListeners(): void {
    this.listenersRemoved = true;
    this.closeListener = undefined;
    this.stdoutListener = undefined;
  }

  public kill(): void {
    throw new Error("SYNTHETIC_SUCCESS_PROCESS_MUST_NOT_BE_KILLED");
  }
}

async function configuredSecretStore(): Promise<RecordingSecretStore> {
  const store = new RecordingSecretStore();
  const mutations = new RecordingMutationBackend(store);
  await new HackerOneCredentialVault(store, mutations).store(
    SYNTHETIC_IDENTIFIER,
    SYNTHETIC_TOKEN,
  );
  store.calls.length = 0;
  store.returned.length = 0;
  return store;
}

describe("HackerOne credential presence and loading", () => {
  it("probes only the two fixed references, publishes a digest, and zeroes reads", async () => {
    const secrets = await configuredSecretStore();
    const vault = new HackerOneCredentialVault(
      secrets,
      new RecordingMutationBackend(),
    );

    const presence = await vault.probe();

    expect(secrets.calls).toEqual([
      HACKERONE_IDENTIFIER_REFERENCE,
      HACKERONE_TOKEN_REFERENCE,
    ]);
    expect(presence).toEqual({
      identifierPresent: true,
      tokenPresent: true,
      tokenFingerprint: sha256(encoder.encode(SYNTHETIC_TOKEN)).slice(0, 12),
      tokenBindingDigest: sha256(encoder.encode(SYNTHETIC_TOKEN)),
      secretStoreAvailable: true,
    });
    expect(Object.isFrozen(presence)).toBe(true);
    expect(presence.tokenFingerprint).toHaveLength(12);
    expect(presence.tokenBindingDigest).toHaveLength(64);
    expect(secrets.returned).toHaveLength(2);
    for (const value of secrets.returned)
      expect(value.every((byte) => byte === 0)).toBe(true);
    expect(JSON.stringify(presence)).not.toContain(SYNTHETIC_IDENTIFIER);
    expect(JSON.stringify(presence)).not.toContain(SYNTHETIC_TOKEN);
  });

  it("reports partial and total keychain failure without exposing backend errors", async () => {
    const partial = await configuredSecretStore();
    partial.failures.add(HACKERONE_TOKEN_REFERENCE);
    await expect(
      new HackerOneCredentialVault(
        partial,
        new RecordingMutationBackend(),
      ).probe(),
    ).resolves.toEqual({
      identifierPresent: false,
      tokenPresent: false,
      tokenFingerprint: null,
      tokenBindingDigest: null,
      secretStoreAvailable: true,
    });
    expect(partial.returned[0]?.every((byte) => byte === 0)).toBe(true);

    const failed = await configuredSecretStore();
    failed.failures.add(HACKERONE_IDENTIFIER_REFERENCE);
    failed.failures.add(HACKERONE_TOKEN_REFERENCE);
    await expect(
      new HackerOneCredentialVault(
        failed,
        new RecordingMutationBackend(),
      ).probe(),
    ).resolves.toEqual({
      identifierPresent: false,
      tokenPresent: false,
      tokenFingerprint: null,
      tokenBindingDigest: null,
      secretStoreAvailable: false,
    });
  });

  it("loads the exact pair and leaves zeroization to the immediate caller", async () => {
    const secrets = await configuredSecretStore();
    const pair = await new HackerOneCredentialVault(
      secrets,
      new RecordingMutationBackend(),
    ).load();

    expect(secrets.calls).toEqual([
      HACKERONE_IDENTIFIER_REFERENCE,
      HACKERONE_TOKEN_REFERENCE,
    ]);
    expect(pair.identifier).toEqual(encoder.encode(SYNTHETIC_IDENTIFIER));
    expect(pair.token).toEqual(encoder.encode(SYNTHETIC_TOKEN));
    expect(Object.isFrozen(pair)).toBe(true);
    pair.identifier.fill(0);
    pair.token.fill(0);
  });

  it("issues one-shot trusted leases and rejects arbitrary structural or replayed pairs", async () => {
    const secrets = await configuredSecretStore();
    const vault = new HackerOneCredentialVault(
      secrets,
      new RecordingMutationBackend(),
    );
    const presence = await vault.probe();
    const bindingDigest = presence.tokenBindingDigest;
    if (bindingDigest === null) throw new Error("TEST_BINDING_DIGEST_MISSING");
    const expectedBindingDigest: string = bindingDigest;
    const leased = await vault.load();

    expect(() => {
      consumeHackerOneCredentialLease(
        Object.freeze({
          identifier: encoder.encode(SYNTHETIC_IDENTIFIER),
          token: encoder.encode(SYNTHETIC_TOKEN),
        }),
        expectedBindingDigest,
      );
    }).toThrow("HACKERONE_CREDENTIAL_LEASE_INVALID");
    expect(() => {
      consumeHackerOneCredentialLease(leased, expectedBindingDigest);
    }).not.toThrow();
    expect(() => {
      consumeHackerOneCredentialLease(leased, expectedBindingDigest);
    }).toThrow("HACKERONE_CREDENTIAL_LEASE_INVALID");
    leased.identifier.fill(0);
    leased.token.fill(0);
  });

  it("binds a lease to the full digest rather than the display prefix", async () => {
    const secrets = await configuredSecretStore();
    const vault = new HackerOneCredentialVault(
      secrets,
      new RecordingMutationBackend(),
    );
    const presence = await vault.probe();
    if (
      presence.tokenBindingDigest === null ||
      presence.tokenFingerprint === null
    )
      throw new Error("TEST_BINDING_DIGEST_MISSING");
    const wrongFullDigest = `${presence.tokenBindingDigest.slice(0, -1)}${
      presence.tokenBindingDigest.endsWith("0") ? "1" : "0"
    }`;
    expect(wrongFullDigest.slice(0, 12)).toBe(presence.tokenFingerprint);
    const leased = await vault.load();

    expect(() => {
      consumeHackerOneCredentialLease(leased, wrongFullDigest);
    }).toThrow("HACKERONE_CREDENTIAL_LEASE_INVALID");
    expect(leased.identifier.every((byte) => byte === 0)).toBe(true);
    expect(leased.token.every((byte) => byte === 0)).toBe(true);
  });

  it("rejects generation-mismatched entries left by interleaved writers", async () => {
    const firstSecrets = new RecordingSecretStore();
    const secondSecrets = new RecordingSecretStore();
    const firstWriter = new RecordingMutationBackend(firstSecrets);
    const secondWriter = new RecordingMutationBackend(secondSecrets);
    await new HackerOneCredentialVault(firstSecrets, firstWriter).store(
      "first-identifier",
      "first-token",
    );
    await new HackerOneCredentialVault(secondSecrets, secondWriter).store(
      "second-identifier",
      "second-token",
    );
    const mixed = new RecordingSecretStore();
    const firstIdentifier = firstWriter.copies[0];
    const secondToken = secondWriter.copies[1];
    if (firstIdentifier === undefined || secondToken === undefined)
      throw new Error("TEST_PAIR_SETUP_FAILED");
    mixed.values.set(HACKERONE_IDENTIFIER_REFERENCE, firstIdentifier);
    mixed.values.set(HACKERONE_TOKEN_REFERENCE, secondToken);
    const vault = new HackerOneCredentialVault(
      mixed,
      new RecordingMutationBackend(),
    );

    await expect(vault.load()).rejects.toThrow(
      "HACKERONE_SECRET_STORE_UNAVAILABLE",
    );
    await expect(vault.probe()).resolves.toEqual({
      identifierPresent: false,
      tokenPresent: false,
      tokenFingerprint: null,
      tokenBindingDigest: null,
      secretStoreAvailable: true,
    });
    for (const value of mixed.returned)
      expect(value.every((byte) => byte === 0)).toBe(true);
  });

  it("zeroes a partial read and returns only the redacted load error", async () => {
    const secrets = await configuredSecretStore();
    secrets.failures.add(HACKERONE_TOKEN_REFERENCE);
    let thrown: unknown;
    try {
      await new HackerOneCredentialVault(
        secrets,
        new RecordingMutationBackend(),
      ).load();
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect((thrown as Error).message).toBe(
      "HACKERONE_SECRET_STORE_UNAVAILABLE",
    );
    expect((thrown as Error).message).not.toContain(
      "SYNTHETIC_SECRET_BACKEND_DETAIL",
    );
    expect(secrets.returned[0]?.every((byte) => byte === 0)).toBe(true);
  });
});

describe("HackerOne credential mutation", () => {
  it("writes identifier then token, returns only a fingerprint, and zeroes both buffers", async () => {
    const secrets = await configuredSecretStore();
    const mutations = new RecordingMutationBackend(secrets);
    const vault = new HackerOneCredentialVault(secrets, mutations);

    const fingerprint = await vault.store(
      SYNTHETIC_IDENTIFIER,
      SYNTHETIC_TOKEN,
    );

    expect(fingerprint).toBe(
      sha256(encoder.encode(SYNTHETIC_TOKEN)).slice(0, 12),
    );
    expect(fingerprint).not.toContain(SYNTHETIC_TOKEN);
    expect(mutations.calls).toEqual(["storeIdentifier", "storeToken"]);
    expect(mutations.copies).toHaveLength(2);
    for (const envelope of mutations.copies) {
      expect(envelope.byteLength).toBeLessThanOrEqual(4_095);
      expect(envelope.every((byte) => byte >= 0x21 && byte <= 0x7e)).toBe(true);
      expect(envelope).not.toContain(0x00);
      expect(envelope).not.toContain(0x0a);
      expect(envelope).not.toContain(0x0d);
      expect(new TextDecoder().decode(envelope)).toMatch(
        /^BBC-H1-CRED-V1\.[it]\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]+$/u,
      );
    }
    expect(mutations.copies[0]).not.toEqual(
      encoder.encode(SYNTHETIC_IDENTIFIER),
    );
    expect(mutations.copies[1]).not.toEqual(encoder.encode(SYNTHETIC_TOKEN));
    const stored = new RecordingSecretStore();
    const identifierEnvelope = mutations.copies[0];
    const tokenEnvelope = mutations.copies[1];
    if (identifierEnvelope === undefined || tokenEnvelope === undefined)
      throw new Error("TEST_PAIR_SETUP_FAILED");
    stored.values.set(HACKERONE_IDENTIFIER_REFERENCE, identifierEnvelope);
    stored.values.set(HACKERONE_TOKEN_REFERENCE, tokenEnvelope);
    const loaded = await new HackerOneCredentialVault(
      stored,
      new RecordingMutationBackend(),
    ).load();
    expect(loaded.identifier).toEqual(encoder.encode(SYNTHETIC_IDENTIFIER));
    expect(loaded.token).toEqual(encoder.encode(SYNTHETIC_TOKEN));
    loaded.identifier.fill(0);
    loaded.token.fill(0);
    for (const value of mutations.references)
      expect(value.every((byte) => byte === 0)).toBe(true);
  });

  it("fails closed and removes both entries when persisted readback does not match the new pair", async () => {
    const stalePair = await configuredSecretStore();
    const mutations = new RecordingMutationBackend();
    const vault = new HackerOneCredentialVault(stalePair, mutations);

    await expect(
      vault.store("replacement-identifier", "replacement-token"),
    ).rejects.toThrow("HACKERONE_KEYCHAIN_WRITE_FAILED");
    expect(mutations.calls).toEqual([
      "storeIdentifier",
      "storeToken",
      "deleteIdentifier",
      "deleteToken",
    ]);
    for (const value of stalePair.returned)
      expect(value.every((byte) => byte === 0)).toBe(true);
  });

  it("accepts printable ASCII TTY buffers without mutating the caller copies", async () => {
    const secrets = await configuredSecretStore();
    const mutations = new RecordingMutationBackend(secrets);
    const vault = new HackerOneCredentialVault(secrets, mutations);
    const identifier = encoder.encode(SYNTHETIC_IDENTIFIER);
    const token = encoder.encode(SYNTHETIC_TOKEN);
    const expectedIdentifier = Uint8Array.from(identifier);
    const expectedToken = Uint8Array.from(token);

    await expect(vault.storeBytes(identifier, token)).resolves.toBe(
      sha256(token).slice(0, 12),
    );

    expect(identifier).toEqual(expectedIdentifier);
    expect(token).toEqual(expectedToken);
    expect(mutations.calls).toEqual(["storeIdentifier", "storeToken"]);
  });

  it("uses the exact printable envelope boundary and rejects one byte beyond it", async () => {
    const secrets = await configuredSecretStore();
    const mutations = new RecordingMutationBackend(secrets);
    const vault = new HackerOneCredentialVault(secrets, mutations);
    const maximum = new Uint8Array(3_041).fill(0x41);
    const oversized = new Uint8Array(3_042).fill(0x41);

    await expect(vault.storeBytes(maximum, maximum)).resolves.toMatch(
      /^[0-9a-f]{12}$/u,
    );
    expect(mutations.copies).toHaveLength(2);
    expect(mutations.copies[0]).toHaveLength(4_095);
    expect(mutations.copies[1]).toHaveLength(4_095);
    await expect(vault.storeBytes(maximum, oversized)).rejects.toThrow(
      "HACKERONE_CREDENTIAL_INPUT_INVALID",
    );
    maximum.fill(0);
    oversized.fill(0);
  });

  it("rejects non-canonical, role-confused, and newline-bearing envelopes", async () => {
    const cases: Uint8Array[] = [];
    const configured = await configuredSecretStore();
    const identifier = configured.values.get(HACKERONE_IDENTIFIER_REFERENCE);
    const token = configured.values.get(HACKERONE_TOKEN_REFERENCE);
    if (identifier === undefined || token === undefined)
      throw new Error("TEST_PAIR_SETUP_FAILED");
    const invalidAlphabet = Uint8Array.from(token);
    invalidAlphabet[invalidAlphabet.length - 1] = 0x3d;
    cases.push(invalidAlphabet);
    const newline = Uint8Array.from(token);
    newline[newline.length - 1] = 0x0a;
    cases.push(newline);
    const wrongRole = Uint8Array.from(token);
    wrongRole[15] = 0x69;
    cases.push(wrongRole);

    for (const malformed of cases) {
      const secrets = new RecordingSecretStore();
      secrets.values.set(HACKERONE_IDENTIFIER_REFERENCE, identifier);
      secrets.values.set(HACKERONE_TOKEN_REFERENCE, malformed);
      const vault = new HackerOneCredentialVault(
        secrets,
        new RecordingMutationBackend(),
      );
      await expect(vault.load()).rejects.toThrow(
        "HACKERONE_SECRET_STORE_UNAVAILABLE",
      );
      await expect(vault.probe()).resolves.toMatchObject({
        identifierPresent: false,
        tokenPresent: false,
        tokenFingerprint: null,
        tokenBindingDigest: null,
      });
      for (const returned of secrets.returned)
        expect(returned.every((byte) => byte === 0)).toBe(true);
    }
  });

  it("rejects whitespace and non-ASCII TTY buffers before keychain mutation", async () => {
    const mutations = new RecordingMutationBackend();
    const vault = new HackerOneCredentialVault(
      await configuredSecretStore(),
      mutations,
    );

    await expect(
      vault.storeBytes(
        encoder.encode("identifier with space"),
        encoder.encode(SYNTHETIC_TOKEN),
      ),
    ).rejects.toThrow("HACKERONE_CREDENTIAL_INPUT_INVALID");
    await expect(
      vault.storeBytes(
        encoder.encode(SYNTHETIC_IDENTIFIER),
        encoder.encode("töken"),
      ),
    ).rejects.toThrow("HACKERONE_CREDENTIAL_INPUT_INVALID");
    expect(mutations.calls).toEqual([]);
  });

  it("zeroes the first encoded input when normalization of the second input fails", async () => {
    const OriginalTextEncoder = TextEncoder;
    const encoded: Uint8Array[] = [];
    class InspectableTextEncoder extends OriginalTextEncoder {
      public override encode(input?: string) {
        const value = super.encode(input);
        encoded.push(value);
        return value;
      }
    }
    vi.stubGlobal("TextEncoder", InspectableTextEncoder);
    try {
      const mutations = new RecordingMutationBackend();
      await expect(
        new HackerOneCredentialVault(
          await configuredSecretStore(),
          mutations,
        ).store(SYNTHETIC_IDENTIFIER, "invalid\ntoken"),
      ).rejects.toThrow("HACKERONE_CREDENTIAL_INPUT_INVALID");
      expect(mutations.calls).toEqual([]);
      expect(encoded).not.toHaveLength(0);
      expect(encoded.every((value) => value.every((byte) => byte === 0))).toBe(
        true,
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it.each([
    ["empty identifier", "", SYNTHETIC_TOKEN],
    ["empty token", SYNTHETIC_IDENTIFIER, ""],
    ["identifier control byte", "synthetic\nidentifier", SYNTHETIC_TOKEN],
    ["token control byte", SYNTHETIC_IDENTIFIER, "synthetic\u0000token"],
    ["oversized identifier bytes", "é".repeat(3_000), SYNTHETIC_TOKEN],
    ["oversized token bytes", SYNTHETIC_IDENTIFIER, "é".repeat(3_000)],
  ])(
    "rejects %s before a keychain mutation",
    async (_label, identifier, token) => {
      const mutations = new RecordingMutationBackend();
      const vault = new HackerOneCredentialVault(
        await configuredSecretStore(),
        mutations,
      );
      await expect(vault.store(identifier, token)).rejects.toThrow(
        "HACKERONE_CREDENTIAL_INPUT_INVALID",
      );
      expect(mutations.calls).toEqual([]);
    },
  );

  it.each(["storeIdentifier", "storeToken"] as const)(
    "cleans both fixed entries after a %s failure and redacts the cause",
    async (failedMutation) => {
      const mutations = new RecordingMutationBackend();
      mutations.failures.add(failedMutation);
      const vault = new HackerOneCredentialVault(
        await configuredSecretStore(),
        mutations,
      );

      let thrown: unknown;
      try {
        await vault.store(SYNTHETIC_IDENTIFIER, SYNTHETIC_TOKEN);
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(Error);
      expect((thrown as Error).message).toBe("HACKERONE_KEYCHAIN_WRITE_FAILED");
      expect((thrown as Error).message).not.toContain(
        "SYNTHETIC_KEYCHAIN_INTERNAL_DETAIL",
      );
      expect(mutations.calls).toContain("deleteIdentifier");
      expect(mutations.calls).toContain("deleteToken");
      for (const value of mutations.references)
        expect(value.every((byte) => byte === 0)).toBe(true);
    },
  );

  it("attempts both removals and fails closed if either removal fails", async () => {
    const mutations = new RecordingMutationBackend();
    mutations.failures.add("deleteIdentifier");
    const vault = new HackerOneCredentialVault(
      await configuredSecretStore(),
      mutations,
    );

    await expect(vault.remove()).rejects.toThrow(
      "HACKERONE_KEYCHAIN_DELETE_FAILED",
    );
    expect(mutations.calls).toEqual(["deleteIdentifier", "deleteToken"]);
  });

  it("attempts both removals when the first backend call throws synchronously", async () => {
    const mutations = new RecordingMutationBackend();
    mutations.synchronousFailures.add("deleteIdentifier");
    const vault = new HackerOneCredentialVault(
      await configuredSecretStore(),
      mutations,
    );

    await expect(vault.remove()).rejects.toThrow(
      "HACKERONE_KEYCHAIN_DELETE_FAILED",
    );
    expect(mutations.calls).toEqual(["deleteIdentifier", "deleteToken"]);
  });
});

describe("fixed macOS HackerOne Keychain boundary", () => {
  it("uses only fixed helper operations and passes synthetic envelopes outside argv", async () => {
    const persisted = new RecordingSecretStore();
    const runner = new RecordingKeychainHelperRunner(persisted);
    const backend = new MacOSHackerOneKeychainMutationBackend("darwin", runner);
    await new HackerOneCredentialVault(backend, backend).store(
      SYNTHETIC_IDENTIFIER,
      SYNTHETIC_TOKEN,
    );
    await backend.deleteIdentifier();
    await backend.deleteToken();

    expect(runner.calls.map(({ operation }) => operation)).toEqual([
      "store-identifier",
      "store-token",
      "read-identifier",
      "read-token",
      "delete-identifier",
      "delete-token",
    ]);
    expect(runner.calls[0]?.secretCopy).not.toEqual(
      encoder.encode(SYNTHETIC_IDENTIFIER),
    );
    expect(runner.calls[1]?.secretCopy).not.toEqual(
      encoder.encode(SYNTHETIC_TOKEN),
    );
    for (const call of runner.calls.slice(0, 2)) {
      const envelope = call.secretCopy;
      if (envelope === null) throw new Error("TEST_ENVELOPE_MISSING");
      expect(envelope.every((byte) => byte >= 0x21 && byte <= 0x7e)).toBe(true);
      expect(envelope).not.toContain(0x00);
      expect(envelope).not.toContain(0x0a);
    }
    for (const call of runner.calls.slice(2))
      expect(call.secretCopy).toBeNull();
    for (const { operation } of runner.calls) {
      const serialized = JSON.stringify(operation);
      expect(serialized).not.toContain(SYNTHETIC_IDENTIFIER);
      expect(serialized).not.toContain(SYNTHETIC_TOKEN);
    }
  });

  it("fails before runner invocation on non-macOS platforms", async () => {
    const runner = new RecordingKeychainHelperRunner();
    const backend = new MacOSHackerOneKeychainMutationBackend("linux", runner);
    await expect(
      backend.storeToken(encoder.encode(SYNTHETIC_TOKEN)),
    ).rejects.toThrow("HACKERONE_SECRET_STORE_UNAVAILABLE");
    await expect(backend.deleteToken()).rejects.toThrow(
      "HACKERONE_SECRET_STORE_UNAVAILABLE",
    );
    await expect(backend.get(HACKERONE_TOKEN_REFERENCE)).rejects.toThrow(
      "HACKERONE_SECRET_STORE_UNAVAILABLE",
    );
    await expect(prepareMacOSHackerOneKeychainHelper("linux")).rejects.toThrow(
      "HACKERONE_KEYCHAIN_HELPER_FAILED",
    );
    expect(runner.calls).toEqual([]);
  });

  it("rejects malformed envelopes with the native-helper error before invocation", async () => {
    const runner = new RecordingKeychainHelperRunner();
    const backend = new MacOSHackerOneKeychainMutationBackend("darwin", runner);

    await expect(
      backend.storeToken(encoder.encode("printable-but-not-an-envelope")),
    ).rejects.toThrow("HACKERONE_KEYCHAIN_HELPER_FAILED");
    expect(runner.calls).toEqual([]);
  });

  it.runIf(process.platform === "darwin")(
    "binds an isolated native helper build to source and binary digests",
    async () => {
      const directoryPath = await realpath(
        await mkdtemp(join(tmpdir(), "bugbounty-helper-build-test-")),
      );
      const binaryPath = join(directoryPath, "hackerone-keychain-helper");
      const digestPath = `${binaryPath}.sha256`;
      const layout = {
        sourcePath: HELPER_SOURCE_PATH,
        directoryPath,
        binaryPath,
        digestPath,
      } as const;
      try {
        await prepareMacOSHackerOneKeychainHelper("darwin", layout);
        const trustedBinary = await readFile(binaryPath);
        try {
          const digestLines = (await readFile(digestPath, "utf8"))
            .trimEnd()
            .split("\n");
          expect(digestLines).toHaveLength(2);
          expect(digestLines[1]).toBe(sha256(trustedBinary));

          await appendFile(binaryPath, Buffer.from([0]));
          await prepareMacOSHackerOneKeychainHelper("darwin", layout);
          const rebuiltBinary = await readFile(binaryPath);
          try {
            expect(rebuiltBinary.byteLength).toBe(trustedBinary.byteLength);
            const rebuiltDigestLines = (await readFile(digestPath, "utf8"))
              .trimEnd()
              .split("\n");
            expect(rebuiltDigestLines).toHaveLength(2);
            expect(rebuiltDigestLines[1]).toBe(sha256(rebuiltBinary));
            const helperSource = await readFile(HELPER_SOURCE_PATH);
            try {
              expect(rebuiltDigestLines[0]).toBe(sha256(helperSource));
            } finally {
              helperSource.fill(0);
            }
          } finally {
            rebuiltBinary.fill(0);
          }
        } finally {
          trustedBinary.fill(0);
        }
      } finally {
        await rm(directoryPath, { recursive: true, force: true });
      }
    },
  );

  it.runIf(process.platform === "darwin")(
    "rejects isolated build paths outside their canonical private fixture",
    async () => {
      const directoryPath = await realpath(
        await mkdtemp(join(tmpdir(), "bugbounty-helper-build-test-")),
      );
      try {
        await expect(
          prepareMacOSHackerOneKeychainHelper("darwin", {
            sourcePath: HELPER_SOURCE_PATH,
            directoryPath,
            binaryPath: join(tmpdir(), "outside-helper"),
            digestPath: join(tmpdir(), "outside-helper.sha256"),
          }),
        ).rejects.toThrow("HACKERONE_KEYCHAIN_HELPER_FAILED");
      } finally {
        await rm(directoryPath, { recursive: true, force: true });
      }
    },
  );

  it.each(["stdin-error", "child-error", "sync-throw"] as const)(
    "kills the native helper and zeroes stdin on %s",
    async (failure) => {
      const child = new FailingKeychainHelperProcess(failure);
      const runner = new SpawnHackerOneKeychainHelperRunner(
        () => Promise.resolve("/synthetic/fixed-helper"),
        () => child,
      );

      await expect(
        runner.execute("store-token", syntheticCredentialEnvelope("token")),
      ).rejects.toThrow("HACKERONE_KEYCHAIN_HELPER_FAILED");
      expect(child.killCount).toBe(1);
      expect(child.listenersRemoved).toBe(true);
      expect(child.input).toBeDefined();
      expect(child.input?.every((byte) => byte === 0)).toBe(true);
    },
  );

  it("starts only the fixed native helper operation and supplies one bounded raw stdin value", async () => {
    const child = new SuccessfulKeychainHelperProcess();
    let capturedBinary: string | undefined;
    let capturedOperation: HackerOneKeychainHelperOperation | undefined;
    const runner = new SpawnHackerOneKeychainHelperRunner(
      () => Promise.resolve("/synthetic/fixed-helper"),
      (binary, operation) => {
        capturedBinary = binary;
        capturedOperation = operation;
        return child;
      },
    );

    await expect(
      runner.execute("store-token", syntheticCredentialEnvelope("token")),
    ).resolves.toBeUndefined();

    expect(capturedBinary).toBe("/synthetic/fixed-helper");
    expect(capturedOperation).toBe("store-token");
    expect(new TextDecoder().decode(child.inputSnapshot)).toMatch(
      /^BBC-H1-CRED-V1\.t\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]+$/u,
    );
    expect(child.inputReference?.every((byte) => byte === 0)).toBe(true);
    expect(child.listenersRemoved).toBe(true);
  });

  it("returns bounded helper read output while erasing the process chunk", async () => {
    const processChunk = Buffer.from("synthetic-envelope");
    const child = new SuccessfulKeychainHelperProcess(processChunk);
    const runner = new SpawnHackerOneKeychainHelperRunner(
      () => Promise.resolve("/synthetic/fixed-helper"),
      () => child,
    );

    const result = await runner.execute("read-identifier");

    expect(new TextDecoder().decode(result)).toBe("synthetic-envelope");
    expect(processChunk.every((byte) => byte === 0)).toBe(true);
    result?.fill(0);
  });

  it("rejects arbitrary printable material before the native helper starts", async () => {
    const processFactory = vi.fn(() => new SuccessfulKeychainHelperProcess());
    const runner = new SpawnHackerOneKeychainHelperRunner(
      () => Promise.resolve("/synthetic/fixed-helper"),
      processFactory,
    );

    await expect(
      runner.execute("store-token", encoder.encode("printable-secret")),
    ).rejects.toThrow("HACKERONE_KEYCHAIN_HELPER_FAILED");
    expect(processFactory).not.toHaveBeenCalled();
  });
});
