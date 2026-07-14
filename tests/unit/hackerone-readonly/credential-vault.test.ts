import { describe, expect, it, vi } from "vitest";
import type { SecretStore } from "../../../packages/secret-store/index.js";
import { sha256 } from "../../../packages/shared/canonical.js";
import {
  consumeHackerOneCredentialLease,
  HackerOneCredentialVault,
  MacOSHackerOneKeychainMutationBackend,
  SpawnHackerOneSecurityCliRunner,
  type HackerOneKeychainMutationBackend,
  type HackerOneSecurityCliProcess,
  type HackerOneSecurityCliRunner,
} from "../../../packages/hackerone-readonly/credential-vault.js";
import {
  HACKERONE_IDENTIFIER_REFERENCE,
  HACKERONE_TOKEN_REFERENCE,
} from "../../../packages/hackerone-readonly/types.js";

const encoder = new TextEncoder();
const SYNTHETIC_IDENTIFIER = "synthetic-identifier-value";
const SYNTHETIC_TOKEN = "synthetic-token-value";

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

  public storeIdentifier(value: Uint8Array): Promise<void> {
    return this.store("storeIdentifier", value);
  }

  public storeToken(value: Uint8Array): Promise<void> {
    return this.store("storeToken", value);
  }

  public deleteIdentifier(): Promise<void> {
    return this.invoke("deleteIdentifier");
  }

  public deleteToken(): Promise<void> {
    return this.invoke("deleteToken");
  }

  private store(name: MutationName, value: Uint8Array): Promise<void> {
    this.copies.push(Uint8Array.from(value));
    this.references.push(value);
    return this.invoke(name);
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

class RecordingSecurityCliRunner implements HackerOneSecurityCliRunner {
  public readonly calls: {
    readonly args: readonly string[];
    readonly secretCopy: Uint8Array | null;
    readonly secretReference: Uint8Array | undefined;
  }[] = [];

  public run(args: readonly string[], secret?: Uint8Array): Promise<void> {
    this.calls.push({
      args: [...args],
      secretCopy: secret === undefined ? null : Uint8Array.from(secret),
      secretReference: secret,
    });
    return Promise.resolve();
  }
}

class FailingSecurityCliProcess implements HackerOneSecurityCliProcess {
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

async function configuredSecretStore(): Promise<RecordingSecretStore> {
  const store = new RecordingSecretStore();
  const mutations = new RecordingMutationBackend();
  await new HackerOneCredentialVault(store, mutations).store(
    SYNTHETIC_IDENTIFIER,
    SYNTHETIC_TOKEN,
  );
  const identifierEnvelope = mutations.copies[0];
  const tokenEnvelope = mutations.copies[1];
  if (identifierEnvelope === undefined || tokenEnvelope === undefined)
    throw new Error("TEST_PAIR_SETUP_FAILED");
  store.values.set(HACKERONE_IDENTIFIER_REFERENCE, identifierEnvelope);
  store.values.set(HACKERONE_TOKEN_REFERENCE, tokenEnvelope);
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
    const firstWriter = new RecordingMutationBackend();
    const secondWriter = new RecordingMutationBackend();
    const unusedSecrets = new RecordingSecretStore();
    await new HackerOneCredentialVault(unusedSecrets, firstWriter).store(
      "first-identifier",
      "first-token",
    );
    await new HackerOneCredentialVault(unusedSecrets, secondWriter).store(
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
    const mutations = new RecordingMutationBackend();
    const vault = new HackerOneCredentialVault(
      await configuredSecretStore(),
      mutations,
    );

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

  it("accepts printable ASCII TTY buffers without mutating the caller copies", async () => {
    const mutations = new RecordingMutationBackend();
    const vault = new HackerOneCredentialVault(
      await configuredSecretStore(),
      mutations,
    );
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
    const mutations = new RecordingMutationBackend();
    const vault = new HackerOneCredentialVault(
      await configuredSecretStore(),
      mutations,
    );
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
  it("uses fixed service/accounts and passes synthetic secrets outside argv", async () => {
    const runner = new RecordingSecurityCliRunner();
    const backend = new MacOSHackerOneKeychainMutationBackend("darwin", runner);
    await new HackerOneCredentialVault(
      new RecordingSecretStore(),
      backend,
    ).store(SYNTHETIC_IDENTIFIER, SYNTHETIC_TOKEN);
    await backend.deleteIdentifier();
    await backend.deleteToken();

    expect(runner.calls.map(({ args }) => args)).toEqual([
      [
        "add-generic-password",
        "-U",
        "-s",
        "bugbounty-copilot",
        "-a",
        "hackerone-api-identifier",
        "-w",
      ],
      [
        "add-generic-password",
        "-U",
        "-s",
        "bugbounty-copilot",
        "-a",
        "hackerone-api-token",
        "-w",
      ],
      [
        "delete-generic-password",
        "-s",
        "bugbounty-copilot",
        "-a",
        "hackerone-api-identifier",
      ],
      [
        "delete-generic-password",
        "-s",
        "bugbounty-copilot",
        "-a",
        "hackerone-api-token",
      ],
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
    expect(runner.calls[2]?.secretCopy).toBeNull();
    expect(runner.calls[3]?.secretCopy).toBeNull();
    for (const { args } of runner.calls) {
      const serialized = JSON.stringify(args);
      expect(serialized).not.toContain(SYNTHETIC_IDENTIFIER);
      expect(serialized).not.toContain(SYNTHETIC_TOKEN);
    }
  });

  it("fails before runner invocation on non-macOS platforms", () => {
    const runner = new RecordingSecurityCliRunner();
    const backend = new MacOSHackerOneKeychainMutationBackend("linux", runner);
    expect(() => backend.storeToken(encoder.encode(SYNTHETIC_TOKEN))).toThrow(
      "HACKERONE_SECRET_STORE_UNAVAILABLE",
    );
    expect(() => backend.deleteToken()).toThrow(
      "HACKERONE_SECRET_STORE_UNAVAILABLE",
    );
    expect(runner.calls).toEqual([]);
  });

  it.each(["stdin-error", "child-error", "sync-throw"] as const)(
    "kills the security process and zeroes stdin on %s",
    async (failure) => {
      const child = new FailingSecurityCliProcess(failure);
      const runner = new SpawnHackerOneSecurityCliRunner(() => child);

      await expect(
        runner.run(["synthetic-operation"], encoder.encode("printable-secret")),
      ).rejects.toThrow("HACKERONE_KEYCHAIN_CLI_FAILED");
      expect(child.killCount).toBe(1);
      expect(child.listenersRemoved).toBe(true);
      expect(child.input).toBeDefined();
      expect(child.input?.every((byte) => byte === 0)).toBe(true);
    },
  );
});
