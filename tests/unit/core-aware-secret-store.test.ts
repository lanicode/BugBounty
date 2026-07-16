import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CORE_EVENT_KEY_REFERENCE,
  CORE_OPERATOR_KEY_REFERENCE,
  CoreAwareKeychainSecretStore,
  MacOSCoreKeychainBackend,
  resolveMacOSCoreRuntimeSecretStore,
  resolveMacOSEventKeyAdminSecretStore,
  type CoreKeychainInspection,
  type CoreKeychainReadBackend,
  type CoreKeychainStatus,
  type SecretStore,
} from "../../packages/secret-store/index.js";
import { TestCoreKeychainRunner } from "../fixtures/core-keychain.factory.js";

const EVENT_V2 = "keychain://bugbounty-copilot/event-store-v2";

class TrackingSecretStore implements SecretStore {
  public readonly calls: string[] = [];
  public readonly returned: Uint8Array[] = [];
  readonly #values = new Map<string, Uint8Array>();

  public set(reference: string, value: Uint8Array): void {
    this.#values.set(reference, Uint8Array.from(value));
  }

  public get(reference: string): Promise<Uint8Array> {
    this.calls.push(reference);
    const value = this.#values.get(reference);
    if (value === undefined) return Promise.reject(new Error("missing"));
    const result = Uint8Array.from(value);
    this.returned.push(result);
    return Promise.resolve(result);
  }
}

class SyntheticCore implements CoreKeychainReadBackend {
  public status: CoreKeychainStatus = "fresh_bundle";
  public generationByte = 1;
  public readonly getCalls: string[] = [];
  public readonly returned: Uint8Array[] = [];
  public failRead = false;
  public changeGenerationAfterRead = false;

  public inspect(): Promise<CoreKeychainInspection> {
    return Promise.resolve(inspection(this.status, this.generationByte));
  }

  public get(reference: string): Promise<Uint8Array> {
    this.getCalls.push(reference);
    if (this.failRead) return Promise.reject(new Error("sensitive"));
    const bytes =
      reference === CORE_OPERATOR_KEY_REFERENCE
        ? new Uint8Array(48).fill(0x62)
        : new Uint8Array(32).fill(0x51);
    this.returned.push(bytes);
    if (this.changeGenerationAfterRead) this.generationByte += 1;
    return Promise.resolve(bytes);
  }
}

describe("Core-aware Keychain SecretStore", () => {
  it("reads exact v1 roles from a stable bundle and rotated v2 only from the generic Keychain", async () => {
    const runner = new TestCoreKeychainRunner(
      "fresh_bundle",
      "bundle-operator",
    );
    const generic = new TrackingSecretStore();
    generic.set(EVENT_V2, new Uint8Array(32).fill(0x52));
    const store = new CoreAwareKeychainSecretStore(
      new MacOSCoreKeychainBackend("darwin", runner),
      generic,
    );

    const eventV1 = await store.get(CORE_EVENT_KEY_REFERENCE);
    const operator = await store.get(CORE_OPERATOR_KEY_REFERENCE);
    const eventV2 = await store.get(EVENT_V2);

    expect(eventV1).toEqual(new Uint8Array(32).fill(0x51));
    expect(operator).toHaveLength(48);
    expect(eventV2).toEqual(new Uint8Array(32).fill(0x52));
    expect(generic.calls).toEqual([EVENT_V2]);
    expect(runner.operations).toContain("read-event");
    expect(runner.operations).toContain("read-operator");
    expect(generic.returned[0]?.every((byte) => byte === 0)).toBe(true);
    eventV1.fill(0);
    operator.fill(0);
    eventV2.fill(0);
  });

  it("never falls back across backends and rejects unknown references", async () => {
    const core = new SyntheticCore();
    const generic = new TrackingSecretStore();
    generic.set(CORE_EVENT_KEY_REFERENCE, new Uint8Array(32).fill(0x70));
    generic.set(EVENT_V2, new Uint8Array(32).fill(0x71));
    const store = new CoreAwareKeychainSecretStore(core, generic);

    core.failRead = true;
    await expect(store.get(CORE_EVENT_KEY_REFERENCE)).rejects.toThrow(
      "CORE_AWARE_KEYCHAIN_READ_FAILED",
    );
    expect(generic.calls).toEqual([]);

    core.failRead = false;
    generic.set(EVENT_V2, new Uint8Array(31).fill(0x71));
    await expect(store.get(EVENT_V2)).rejects.toThrow(
      "CORE_AWARE_KEYCHAIN_READ_FAILED",
    );
    expect(core.getCalls).toEqual([CORE_EVENT_KEY_REFERENCE]);
    expect(generic.returned.at(-1)?.every((byte) => byte === 0)).toBe(true);

    await expect(
      store.get("keychain://bugbounty-copilot/unexpected"),
    ).rejects.toThrow("CORE_AWARE_KEYCHAIN_REFERENCE_INVALID");
  });

  it("zeroes a read and fails closed when the bundle identity changes", async () => {
    const core = new SyntheticCore();
    core.changeGenerationAfterRead = true;
    const store = new CoreAwareKeychainSecretStore(
      core,
      new TrackingSecretStore(),
    );

    await expect(store.get(CORE_EVENT_KEY_REFERENCE)).rejects.toThrow(
      "CORE_AWARE_KEYCHAIN_STATE_CHANGED",
    );
    expect(core.returned[0]?.every((byte) => byte === 0)).toBe(true);
  });

  it.each(["absent", "conflict", "legacy_ready"] as const)(
    "blocks strict bundle reads in %s without touching either secret route",
    async (status) => {
      const runner = new TestCoreKeychainRunner(status);
      const generic = new TrackingSecretStore();
      const store = new CoreAwareKeychainSecretStore(
        new MacOSCoreKeychainBackend("darwin", runner),
        generic,
      );

      await expect(store.get(CORE_EVENT_KEY_REFERENCE)).rejects.toThrow(
        "CORE_AWARE_KEYCHAIN_STATE_INVALID",
      );
      expect(runner.operations).not.toContain("read-event");
      expect(generic.calls).toEqual([]);
    },
  );

  it("selects status-bound generic event keys only for the two explicit legacy admin states", async () => {
    for (const status of ["legacy_ready", "legacy_direct_complete"] as const) {
      const runner = new TestCoreKeychainRunner(status);
      const generic = new TrackingSecretStore();
      generic.set(CORE_EVENT_KEY_REFERENCE, new Uint8Array(32).fill(0x55));
      const store = await resolveMacOSEventKeyAdminSecretStore(
        new MacOSCoreKeychainBackend("darwin", runner),
        generic,
      );

      const value = await store.get(CORE_EVENT_KEY_REFERENCE);
      expect(value).toEqual(new Uint8Array(32).fill(0x55));
      expect(runner.operations).not.toContain("read-event");
      expect(generic.calls).toEqual([CORE_EVENT_KEY_REFERENCE]);
      value.fill(0);
    }
  });

  it.each(["absent", "conflict"] as const)(
    "does not turn %s into a legacy event-admin fallback",
    async (status) => {
      const runner = new TestCoreKeychainRunner(status);
      const generic = new TrackingSecretStore();
      generic.set(CORE_EVENT_KEY_REFERENCE, new Uint8Array(32).fill(0x55));
      await expect(
        resolveMacOSEventKeyAdminSecretStore(
          new MacOSCoreKeychainBackend("darwin", runner),
          generic,
        ),
      ).rejects.toThrow("CORE_AWARE_KEYCHAIN_STATE_INVALID");
      expect(generic.calls).toEqual([]);
    },
  );

  it("uses status-bound generic operator and event keys for canonical legacy-direct runtime only", async () => {
    const runner = new TestCoreKeychainRunner("legacy_direct_complete");
    const generic = new TrackingSecretStore();
    generic.set(CORE_EVENT_KEY_REFERENCE, new Uint8Array(32).fill(0x57));
    generic.set(CORE_OPERATOR_KEY_REFERENCE, operatorDer());
    const resolution = await resolveMacOSCoreRuntimeSecretStore(
      new MacOSCoreKeychainBackend("darwin", runner),
      generic,
    );

    expect(resolution.mode).toBe("legacy_direct");
    const eventKey = await resolution.secrets.get(CORE_EVENT_KEY_REFERENCE);
    const operatorKey = await resolution.secrets.get(
      CORE_OPERATOR_KEY_REFERENCE,
    );
    expect(eventKey).toHaveLength(32);
    expect(operatorKey).toHaveLength(48);
    expect(runner.operations).not.toContain("read-event");
    expect(runner.operations).not.toContain("read-operator");
    expect(generic.calls).toEqual([
      CORE_EVENT_KEY_REFERENCE,
      CORE_OPERATOR_KEY_REFERENCE,
    ]);
    eventKey.fill(0);
    operatorKey.fill(0);
  });

  it("zeroes a legacy-direct read when the inspected state changes during generic access", async () => {
    const core = new SyntheticCore();
    core.status = "legacy_direct_complete";
    let returned: Uint8Array | undefined;
    const changingGeneric: SecretStore = {
      get: () => {
        returned = new Uint8Array(32).fill(0x59);
        core.status = "conflict";
        return Promise.resolve(returned);
      },
    };
    const resolution = await resolveMacOSCoreRuntimeSecretStore(
      core,
      changingGeneric,
    );

    await expect(
      resolution.secrets.get(CORE_EVENT_KEY_REFERENCE),
    ).rejects.toThrow("CORE_AWARE_KEYCHAIN_STATE_INVALID");
    expect(returned?.every((byte) => byte === 0)).toBe(true);
    expect(core.getCalls).toEqual([]);
  });
});

function inspection(
  status: CoreKeychainStatus,
  generationByte: number,
): CoreKeychainInspection {
  if (status !== "fresh_bundle" && status !== "legacy_complete")
    return Object.freeze({ status, receipt: null });
  return Object.freeze({
    status,
    receipt: Object.freeze({
      version: 1 as const,
      mode: status,
      operatorId: "local-operator",
      initialEventKeyVersion: 1 as const,
      operatorKeyRevision: 1 as const,
      generation: Buffer.alloc(16, generationByte).toString("base64url"),
    }),
  });
}

function operatorDer(): Uint8Array {
  const { privateKey } = generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  try {
    return Uint8Array.from(der);
  } finally {
    der.fill(0);
  }
}
