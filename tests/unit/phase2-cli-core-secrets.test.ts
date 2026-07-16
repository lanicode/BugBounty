import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createPhase2CoreSecretContext } from "../../apps/phase2-cli/core-secrets.js";
import {
  CORE_EVENT_KEY_REFERENCE,
  CORE_OPERATOR_KEY_REFERENCE,
  MacOSCoreKeychainBackend,
  type SecretStore,
} from "../../packages/secret-store/index.js";
import { TestCoreKeychainRunner } from "../fixtures/core-keychain.factory.js";

const EVENT_V2 = "keychain://bugbounty-copilot/event-store-v2";

class TrackingSecretStore implements SecretStore {
  public readonly calls: string[] = [];
  readonly #values = new Map<string, Uint8Array>();

  public set(reference: string, value: Uint8Array): void {
    this.#values.set(reference, Uint8Array.from(value));
  }

  public get(reference: string): Promise<Uint8Array> {
    this.calls.push(reference);
    const value = this.#values.get(reference);
    return value === undefined
      ? Promise.reject(new Error("missing"))
      : Promise.resolve(Uint8Array.from(value));
  }
}

describe("Phase-2 CLI Core secret composition", () => {
  it("derives the operator identity from a fresh bundle and keeps v2 on the generic route", async () => {
    const runner = new TestCoreKeychainRunner(
      "fresh_bundle",
      "bundle-operator",
    );
    const generic = new TrackingSecretStore();
    generic.set(EVENT_V2, new Uint8Array(32).fill(0x52));

    const context = await createPhase2CoreSecretContext(
      {},
      {
        core: new MacOSCoreKeychainBackend("darwin", runner),
        generic,
      },
    );

    expect(context.storageMode).toBe("bundled");
    expect(context.operatorSigner.credential).toMatchObject({
      operator_id: "bundle-operator",
      key_revision: 1,
    });
    const eventV1 = await context.secretStore.get(CORE_EVENT_KEY_REFERENCE);
    const eventV2 = await context.secretStore.get(EVENT_V2);
    expect(eventV1).toEqual(new Uint8Array(32).fill(0x51));
    expect(eventV2).toEqual(new Uint8Array(32).fill(0x52));
    expect(runner.operations).toContain("read-operator");
    expect(runner.operations).toContain("read-event");
    expect(generic.calls).toEqual([EVENT_V2]);
    eventV1.fill(0);
    eventV2.fill(0);
  });

  it("accepts canonical legacy-direct keys only with complete exact operator configuration", async () => {
    const runner = new TestCoreKeychainRunner("legacy_direct_complete");
    const generic = new TrackingSecretStore();
    generic.set(CORE_OPERATOR_KEY_REFERENCE, operatorDer());
    generic.set(CORE_EVENT_KEY_REFERENCE, new Uint8Array(32).fill(0x53));

    const context = await createPhase2CoreSecretContext(
      {
        BUGBOUNTY_OPERATOR_KEY_REFERENCE: CORE_OPERATOR_KEY_REFERENCE,
        BUGBOUNTY_OPERATOR_ID: "legacy-operator",
        BUGBOUNTY_OPERATOR_KEY_REVISION: "1",
      },
      {
        core: new MacOSCoreKeychainBackend("darwin", runner),
        generic,
      },
    );

    expect(context.storageMode).toBe("legacy_direct");
    expect(context.operatorSigner.credential.operator_id).toBe(
      "legacy-operator",
    );
    const event = await context.secretStore.get(CORE_EVENT_KEY_REFERENCE);
    expect(event).toEqual(new Uint8Array(32).fill(0x53));
    expect(generic.calls).toEqual([
      CORE_OPERATOR_KEY_REFERENCE,
      CORE_EVENT_KEY_REFERENCE,
    ]);
    expect(runner.operations).not.toContain("read-operator");
    expect(runner.operations).not.toContain("read-event");
    event.fill(0);
  });

  it("rejects bundle metadata mismatch before reading an operator secret", async () => {
    const runner = new TestCoreKeychainRunner(
      "fresh_bundle",
      "bundle-operator",
    );
    const generic = new TrackingSecretStore();
    await expect(
      createPhase2CoreSecretContext(
        {
          BUGBOUNTY_OPERATOR_KEY_REFERENCE: CORE_OPERATOR_KEY_REFERENCE,
          BUGBOUNTY_OPERATOR_ID: "different-operator",
          BUGBOUNTY_OPERATOR_KEY_REVISION: "1",
        },
        {
          core: new MacOSCoreKeychainBackend("darwin", runner),
          generic,
        },
      ),
    ).rejects.toThrow("OPERATOR_SIGNER_CONFIG_INVALID");
    expect(runner.operations).not.toContain("read-operator");
    expect(generic.calls).toEqual([]);
  });

  it("blocks missing legacy-direct metadata and every incomplete Core state without a generic fallback", async () => {
    const directRunner = new TestCoreKeychainRunner("legacy_direct_complete");
    const directGeneric = new TrackingSecretStore();
    directGeneric.set(CORE_OPERATOR_KEY_REFERENCE, operatorDer());
    await expect(
      createPhase2CoreSecretContext(
        {},
        {
          core: new MacOSCoreKeychainBackend("darwin", directRunner),
          generic: directGeneric,
        },
      ),
    ).rejects.toThrow("OPERATOR_SIGNER_CONFIG_INVALID");
    expect(directGeneric.calls).toEqual([]);

    for (const status of ["absent", "conflict", "legacy_ready"] as const) {
      const runner = new TestCoreKeychainRunner(status);
      const generic = new TrackingSecretStore();
      generic.set(CORE_OPERATOR_KEY_REFERENCE, operatorDer());
      await expect(
        createPhase2CoreSecretContext(
          {
            BUGBOUNTY_OPERATOR_KEY_REFERENCE: CORE_OPERATOR_KEY_REFERENCE,
            BUGBOUNTY_OPERATOR_ID: "legacy-operator",
            BUGBOUNTY_OPERATOR_KEY_REVISION: "1",
          },
          {
            core: new MacOSCoreKeychainBackend("darwin", runner),
            generic,
          },
        ),
      ).rejects.toThrow("CORE_AWARE_KEYCHAIN_STATE_INVALID");
      expect(generic.calls).toEqual([]);
    }
  });
});

function operatorDer(): Uint8Array {
  const { privateKey } = generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  try {
    return Uint8Array.from(der);
  } finally {
    der.fill(0);
  }
}
