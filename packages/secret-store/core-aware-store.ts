import { types } from "node:util";
import {
  CORE_EVENT_KEY_REFERENCE,
  CORE_OPERATOR_KEY_REFERENCE,
  MacOSCoreKeychainBackend,
  type CoreKeychainInspection,
  type CoreKeychainReceipt,
} from "./core-keychain.js";
import { MacOSKeychainSecretStore, type SecretStore } from "./store.js";
import { SecurityError } from "../shared/errors.js";

const EVENT_KEY_REFERENCE =
  /^keychain:\/\/bugbounty-copilot\/event-store-v([1-9][0-9]{0,4})$/u;
const MAX_EVENT_KEY_VERSION = 10_000;
const EVENT_KEY_BYTES = 32;
const OPERATOR_KEY_BYTES = 48;
const SAFE_OPERATOR_ID = /^[A-Za-z0-9._@-]{1,128}$/u;
const BASE64URL_GENERATION = /^[A-Za-z0-9_-]{22}$/u;

export interface CoreKeychainReadBackend extends SecretStore {
  inspect(): Promise<CoreKeychainInspection>;
}

export interface CompletedCoreKeychainIdentity {
  readonly status: "fresh_bundle" | "legacy_complete";
  readonly receipt: CoreKeychainReceipt;
}

export type CoreRuntimeSecretStoreResolution =
  | {
      readonly mode: "bundled";
      readonly identity: CompletedCoreKeychainIdentity;
      readonly secrets: CoreAwareKeychainSecretStore;
    }
  | {
      readonly mode: "legacy_direct";
      readonly identity: null;
      readonly secrets: SecretStore;
    };

/**
 * Routes the two logical version-1 core references through the native bundle
 * reader and only rotated event keys through their fixed generic Keychain
 * references. A failed route is never retried through the other backend.
 */
export class CoreAwareKeychainSecretStore implements SecretStore {
  readonly #core: CoreKeychainReadBackend;
  readonly #rotatedEventKeys: SecretStore;

  public constructor(
    core: CoreKeychainReadBackend,
    rotatedEventKeys: SecretStore,
  ) {
    if (
      types.isProxy(core) ||
      types.isProxy(rotatedEventKeys) ||
      typeof core.inspect !== "function" ||
      typeof core.get !== "function" ||
      typeof rotatedEventKeys.get !== "function"
    )
      throw new SecurityError("CORE_AWARE_KEYCHAIN_STORE_INVALID");
    this.#core = core;
    this.#rotatedEventKeys = rotatedEventKeys;
    Object.freeze(this);
  }

  public async inspectCompletedCore(): Promise<CompletedCoreKeychainIdentity> {
    return completedIdentity(await this.inspectCore());
  }

  public async get(reference: string): Promise<Uint8Array> {
    const route = parseRoute(reference);
    const before = await this.inspectCompletedCore();
    let source: Uint8Array | undefined;
    let result: Uint8Array | undefined;
    let failure: unknown;
    try {
      source = await (route.backend === "core"
        ? this.#core.get(reference)
        : this.#rotatedEventKeys.get(reference));
      if (!isExactSecret(source, route.expectedBytes))
        throw new SecurityError("CORE_AWARE_KEYCHAIN_READ_FAILED");
      const after = await this.inspectCompletedCore();
      if (!sameIdentity(before, after))
        throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_CHANGED");
      result = Uint8Array.from(source);
    } catch (error) {
      failure = error;
    }
    if (source !== undefined && !zeroize(source)) {
      if (result !== undefined) zeroize(result);
      throw new SecurityError("CORE_AWARE_KEYCHAIN_ZEROIZATION_FAILED");
    }
    if (failure instanceof SecurityError) throw failure;
    if (failure !== undefined || result === undefined)
      throw new SecurityError("CORE_AWARE_KEYCHAIN_READ_FAILED");
    return result;
  }

  private async inspectCore(): Promise<CoreKeychainInspection> {
    try {
      return await this.#core.inspect();
    } catch {
      throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
    }
  }
}

export function createMacOSCoreAwareSecretStore(
  platform: NodeJS.Platform = process.platform,
): CoreAwareKeychainSecretStore {
  return new CoreAwareKeychainSecretStore(
    new MacOSCoreKeychainBackend(platform),
    new MacOSKeychainSecretStore(undefined, platform),
  );
}

/**
 * Resolves the offline event-key admin boundary from the native inspection.
 * The receiptless `legacy_ready` and `legacy_direct_complete` modes are
 * explicit Phase-4/5 compatibility states, never error fallbacks.
 */
export async function resolveMacOSEventKeyAdminSecretStore(
  core: CoreKeychainReadBackend = new MacOSCoreKeychainBackend(),
  generic: SecretStore = new MacOSKeychainSecretStore(),
): Promise<SecretStore> {
  let inspection: CoreKeychainInspection;
  try {
    inspection = await core.inspect();
  } catch {
    throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
  }
  if (
    inspection.status === "fresh_bundle" ||
    inspection.status === "legacy_complete"
  ) {
    completedIdentity(inspection);
    return new CoreAwareKeychainSecretStore(core, generic);
  }
  if (
    inspection.status === "legacy_ready" ||
    inspection.status === "legacy_direct_complete"
  ) {
    assertReceiptlessInspection(inspection);
    return new StableLegacyKeychainSecretStore(
      core,
      generic,
      inspection.status,
      false,
    );
  }
  throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
}

export async function resolveMacOSCoreRuntimeSecretStore(
  core: CoreKeychainReadBackend = new MacOSCoreKeychainBackend(),
  generic: SecretStore = new MacOSKeychainSecretStore(),
): Promise<CoreRuntimeSecretStoreResolution> {
  let inspection: CoreKeychainInspection;
  try {
    inspection = await core.inspect();
  } catch {
    throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
  }
  if (
    inspection.status === "fresh_bundle" ||
    inspection.status === "legacy_complete"
  ) {
    const identity = completedIdentity(inspection);
    return Object.freeze({
      mode: "bundled" as const,
      identity,
      secrets: new CoreAwareKeychainSecretStore(core, generic),
    });
  }
  if (inspection.status === "legacy_direct_complete") {
    assertReceiptlessInspection(inspection);
    return Object.freeze({
      mode: "legacy_direct" as const,
      identity: null,
      secrets: new StableLegacyKeychainSecretStore(
        core,
        generic,
        "legacy_direct_complete",
        true,
      ),
    });
  }
  throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
}

class StableLegacyKeychainSecretStore implements SecretStore {
  public constructor(
    private readonly core: CoreKeychainReadBackend,
    private readonly generic: SecretStore,
    private readonly expectedStatus: "legacy_direct_complete" | "legacy_ready",
    private readonly allowOperator: boolean,
  ) {
    Object.freeze(this);
  }

  public async get(reference: string): Promise<Uint8Array> {
    const route = parseRoute(reference);
    if (route.expectedBytes !== EVENT_KEY_BYTES && !this.allowOperator)
      throw new SecurityError("CORE_AWARE_KEYCHAIN_REFERENCE_INVALID");
    await this.assertStableState();
    let source: Uint8Array | undefined;
    let result: Uint8Array | undefined;
    let failure: unknown;
    try {
      source = await this.generic.get(reference);
      if (!isExactSecret(source, route.expectedBytes))
        throw new SecurityError("CORE_AWARE_KEYCHAIN_READ_FAILED");
      await this.assertStableState();
      result = Uint8Array.from(source);
    } catch (error) {
      failure = error;
    }
    if (source !== undefined && !zeroize(source)) {
      if (result !== undefined) zeroize(result);
      throw new SecurityError("CORE_AWARE_KEYCHAIN_ZEROIZATION_FAILED");
    }
    if (failure instanceof SecurityError) throw failure;
    if (failure !== undefined || result === undefined)
      throw new SecurityError("CORE_AWARE_KEYCHAIN_READ_FAILED");
    return result;
  }

  private async assertStableState(): Promise<void> {
    let inspection: CoreKeychainInspection;
    try {
      inspection = await this.core.inspect();
    } catch {
      throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
    }
    assertReceiptlessInspection(inspection);
    if (inspection.status !== this.expectedStatus)
      throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_CHANGED");
  }
}

function parseRoute(reference: unknown): {
  readonly backend: "core" | "rotated";
  readonly expectedBytes: number;
} {
  if (reference === CORE_OPERATOR_KEY_REFERENCE)
    return Object.freeze({
      backend: "core" as const,
      expectedBytes: OPERATOR_KEY_BYTES,
    });
  if (typeof reference !== "string")
    throw new SecurityError("CORE_AWARE_KEYCHAIN_REFERENCE_INVALID");
  const match = EVENT_KEY_REFERENCE.exec(reference);
  const versionText = match?.[1];
  if (versionText === undefined)
    throw new SecurityError("CORE_AWARE_KEYCHAIN_REFERENCE_INVALID");
  const version = Number(versionText);
  if (
    !Number.isSafeInteger(version) ||
    version < 1 ||
    version > MAX_EVENT_KEY_VERSION
  )
    throw new SecurityError("CORE_AWARE_KEYCHAIN_REFERENCE_INVALID");
  return Object.freeze({
    backend: reference === CORE_EVENT_KEY_REFERENCE ? "core" : "rotated",
    expectedBytes: EVENT_KEY_BYTES,
  });
}

function completedIdentity(value: unknown): CompletedCoreKeychainIdentity {
  if (
    typeof value !== "object" ||
    value === null ||
    types.isProxy(value) ||
    !Object.isFrozen(value) ||
    !exactKeys(value, ["receipt", "status"])
  )
    throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
  const status: unknown = Reflect.get(value, "status");
  const receipt: unknown = Reflect.get(value, "receipt");
  if (
    (status !== "fresh_bundle" && status !== "legacy_complete") ||
    typeof receipt !== "object" ||
    receipt === null ||
    types.isProxy(receipt) ||
    !Object.isFrozen(receipt) ||
    !exactKeys(receipt, [
      "generation",
      "initialEventKeyVersion",
      "mode",
      "operatorId",
      "operatorKeyRevision",
      "version",
    ]) ||
    Reflect.get(receipt, "version") !== 1 ||
    Reflect.get(receipt, "mode") !== status ||
    Reflect.get(receipt, "initialEventKeyVersion") !== 1 ||
    Reflect.get(receipt, "operatorKeyRevision") !== 1
  )
    throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
  const operatorId: unknown = Reflect.get(receipt, "operatorId");
  const generation: unknown = Reflect.get(receipt, "generation");
  if (
    typeof operatorId !== "string" ||
    !SAFE_OPERATOR_ID.test(operatorId) ||
    typeof generation !== "string" ||
    !validGeneration(generation)
  )
    throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
  return Object.freeze({
    status,
    receipt: Object.freeze({
      version: 1 as const,
      mode: status,
      operatorId,
      initialEventKeyVersion: 1 as const,
      operatorKeyRevision: 1 as const,
      generation,
    }),
  });
}

function assertReceiptlessInspection(value: unknown): asserts value is {
  readonly status: "legacy_direct_complete" | "legacy_ready";
  readonly receipt: null;
} {
  if (
    typeof value !== "object" ||
    value === null ||
    types.isProxy(value) ||
    !Object.isFrozen(value) ||
    !exactKeys(value, ["receipt", "status"])
  )
    throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
  const status: unknown = Reflect.get(value, "status");
  if (
    (status !== "legacy_direct_complete" && status !== "legacy_ready") ||
    Reflect.get(value, "receipt") !== null
  )
    throw new SecurityError("CORE_AWARE_KEYCHAIN_STATE_INVALID");
}

function validGeneration(value: string): boolean {
  if (!BASE64URL_GENERATION.test(value)) return false;
  let decoded: Buffer | undefined;
  try {
    decoded = Buffer.from(value, "base64url");
    return (
      decoded.byteLength === 16 &&
      decoded.toString("base64url") === value &&
      decoded.some((byte) => byte !== 0)
    );
  } finally {
    decoded?.fill(0);
  }
}

function exactKeys(value: object, expected: readonly string[]): boolean {
  try {
    const keys = Object.keys(value).sort();
    return (
      keys.length === expected.length &&
      expected.every((key, index) => keys[index] === key)
    );
  } catch {
    return false;
  }
}

function sameIdentity(
  left: CompletedCoreKeychainIdentity,
  right: CompletedCoreKeychainIdentity,
): boolean {
  return (
    left.status === right.status &&
    left.receipt.mode === right.receipt.mode &&
    left.receipt.operatorId === right.receipt.operatorId &&
    left.receipt.generation === right.receipt.generation
  );
}

function isExactSecret(
  value: unknown,
  expectedBytes: number,
): value is Uint8Array {
  return (
    types.isUint8Array(value) &&
    Object.getPrototypeOf(value) === Uint8Array.prototype &&
    !Object.hasOwn(value, "fill") &&
    value.byteLength === expectedBytes
  );
}

function zeroize(value: Uint8Array): boolean {
  try {
    Uint8Array.prototype.fill.call(value, 0);
    return value.every((byte) => byte === 0);
  } catch {
    return false;
  }
}
