import {
  createHmac,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import {
  constants,
  chmod,
  link,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  unlink,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  EncryptedEventStore,
  MAX_EVENT_ENVELOPE_BYTES,
  MAX_EVENT_KEY_VERSION,
} from "../event-store/store.js";
import { canonicalJson, sha256, type JsonValue } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import type {
  EventKeyLifecycleOptions,
  EventKeyMutationRecoveryReceipt,
  EventKeyRotationInput,
  EventKeyRotationReceipt,
  EventKeyState,
  EventKeyStateOperation,
  EventKeyStateRecord,
} from "./types.js";

const STATE_DIRECTORY_NAME = ".event-key-state";
const MUTATION_LOCK_NAME = ".event-key-mutation.lock";
const STATE_FILE_PATTERN = /^state-([0-9]{10})\.json$/u;
const TEMP_FILE_PATTERN = /^\.tmp-state-[1-9][0-9]{0,19}-[a-f0-9]{16}$/u;
const EVENT_TEMP_FILE_PATTERN = /^\.tmp-[1-9][0-9]{0,19}-[a-f0-9]{16}$/u;
const EVENT_FILE_PATTERN = /^[A-Za-z0-9_-]{1,80}\.events\.enc$/u;
const STORE_ID_PATTERN = /^[a-f0-9]{64}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const GENESIS_DIGEST = "0".repeat(64);
const STATE_SCHEMA_VERSION = 1 as const;
const MAX_STATE_RECORD_BYTES = 16 * 1024;
const MAX_MUTATION_LOCK_BYTES = 512;
const MAX_PROCESS_ID = 2_147_483_647;
const KEY_BYTES = 32;
const HKDF_INFO = Buffer.from("event-key-state:v1", "utf8");
const RECORD_KEYS = Object.freeze([
  "activeKeyVersion",
  "authenticationTag",
  "operation",
  "previousRecordDigest",
  "readableKeyVersions",
  "revision",
  "schemaVersion",
  "storeId",
] as const);

interface NormalizedOptions {
  readonly directory: string;
  readonly stateDirectory: string;
  readonly secrets: EventKeyLifecycleOptions["secrets"];
  readonly keyReference: EventKeyLifecycleOptions["keyReference"];
  readonly minimumActiveKeyVersion: number;
}

interface ParsedChain {
  readonly records: readonly EventKeyStateRecord[];
  readonly digests: readonly string[];
}

interface VerifiedState {
  readonly state: EventKeyState;
  readonly keys: ReadonlyMap<number, Uint8Array>;
}

interface MutationLockRecord {
  readonly schemaVersion: 1;
  readonly ownerPid: number;
  readonly token: string;
}

interface MutationLease {
  readonly token: string;
}

interface EventDirectoryScan {
  readonly eventPaths: readonly string[];
  readonly temporaryPaths: readonly string[];
}

const MUTATION_LOCK_KEYS = Object.freeze([
  "ownerPid",
  "schemaVersion",
  "token",
] as const);
const MUTATION_TOKEN_PATTERN = /^[a-f0-9]{32}$/u;

export class EventKeyLifecycle {
  #state: EventKeyState;
  #operationTail: Promise<void> = Promise.resolve();

  private constructor(
    private readonly options: NormalizedOptions,
    state: EventKeyState,
  ) {
    this.#state = state;
  }

  public static async initializeFresh(
    options: EventKeyLifecycleOptions,
  ): Promise<EventKeyLifecycle> {
    const normalized = normalizeOptions(options);
    return EventKeyLifecycle.initializeFreshNormalized(normalized);
  }

  public static async openOrInitializeFresh(
    options: EventKeyLifecycleOptions,
  ): Promise<EventKeyLifecycle> {
    const normalized = normalizeOptions(options);
    const rootMissing = await pathIsMissing(normalized.directory);
    if (!rootMissing) {
      await assertDirectory(normalized.directory, false);
      const stateMissing = await pathIsMissing(normalized.stateDirectory);
      if (!stateMissing) {
        await assertDirectory(normalized.stateDirectory, false);
        const stateRecords = await listStateRecordPaths(normalized);
        if (stateRecords.length > 0)
          return EventKeyLifecycle.openNormalized(normalized);
        const events = await listEventFiles(normalized);
        if (events.length > 0)
          throw new SecurityError("EVENT_KEY_LEGACY_ADOPTION_REQUIRED");
      }
    }
    try {
      return await EventKeyLifecycle.initializeFreshNormalized(normalized);
    } catch (error) {
      if (
        !hasSecurityCode(error, "EVENT_KEY_STATE_EXISTS") &&
        !hasSecurityCode(error, "EVENT_KEY_ROTATION_CONFLICT")
      )
        throw error;
      await prepareDirectories(normalized, false);
      return EventKeyLifecycle.openNormalized(normalized);
    }
  }

  private static async initializeFreshNormalized(
    normalized: NormalizedOptions,
  ): Promise<EventKeyLifecycle> {
    assertV1MeetsMinimum(normalized);
    await prepareRootDirectory(normalized, true);
    return withMutationLease(normalized, async (lease) => {
      const stateMissing = await pathIsMissing(normalized.stateDirectory);
      if (!stateMissing) {
        await assertDirectory(normalized.stateDirectory, false);
        await assertNoStateRecords(normalized);
      }
      const events = await listEventFiles(normalized, lease.token);
      if (events.length > 0)
        throw new SecurityError("EVENT_KEY_LEGACY_ADOPTION_REQUIRED");
      await mkdir(normalized.stateDirectory, { recursive: true, mode: 0o700 });
      await assertDirectory(normalized.stateDirectory, true);
      await assertNoStateRecords(normalized);

      const key = await loadKey(normalized, 1);
      try {
        const record = createRecord(
          {
            schemaVersion: STATE_SCHEMA_VERSION,
            storeId: randomBytes(32).toString("hex"),
            revision: 1,
            operation: "initialize",
            activeKeyVersion: 1,
            readableKeyVersions: Object.freeze([1]),
            previousRecordDigest: GENESIS_DIGEST,
          },
          key,
        );
        await commitRecord(normalized, record, lease.token);
      } finally {
        zeroize(key);
      }
      return EventKeyLifecycle.openNormalized(normalized, lease.token);
    });
  }

  public static async adoptLegacyV1(
    options: EventKeyLifecycleOptions,
  ): Promise<EventKeyLifecycle> {
    const normalized = normalizeOptions(options);
    assertV1MeetsMinimum(normalized);
    await prepareRootDirectory(normalized, true);
    return withMutationLease(normalized, async (lease) => {
      await mkdir(normalized.stateDirectory, { recursive: true, mode: 0o700 });
      await assertDirectory(normalized.stateDirectory, true);
      await assertNoStateRecords(normalized);
      const before = await listEventFiles(normalized, lease.token);
      if (before.length === 0)
        throw new SecurityError("EVENT_KEY_LEGACY_EVENTS_REQUIRED");

      const legacy = new EncryptedEventStore(
        normalized.directory,
        normalized.secrets,
        normalized.keyReference,
        1,
        [1],
      );
      for (const path of before) {
        let inspected: {
          readonly envelopeVersion: number;
          readonly keyVersion: number;
        };
        try {
          inspected = await legacy.inspect(path);
        } catch {
          throw new SecurityError("EVENT_KEY_LEGACY_INVALID");
        }
        if (inspected.envelopeVersion !== 1 || inspected.keyVersion !== 1)
          throw new SecurityError("EVENT_KEY_LEGACY_INVALID");
        try {
          await legacy.read(path);
        } catch {
          throw new SecurityError("EVENT_KEY_LEGACY_INVALID");
        }
      }
      const after = await listEventFiles(normalized, lease.token);
      if (!sameStrings(before, after))
        throw new SecurityError("EVENT_KEY_LEGACY_CHANGED");

      const key = await loadKey(normalized, 1);
      try {
        const record = createRecord(
          {
            schemaVersion: STATE_SCHEMA_VERSION,
            storeId: randomBytes(32).toString("hex"),
            revision: 1,
            operation: "adopt_legacy_v1",
            activeKeyVersion: 1,
            readableKeyVersions: Object.freeze([1]),
            previousRecordDigest: GENESIS_DIGEST,
          },
          key,
        );
        await commitRecord(normalized, record, lease.token);
      } finally {
        zeroize(key);
      }
      return EventKeyLifecycle.openNormalized(normalized, lease.token);
    });
  }

  public static async open(
    options: EventKeyLifecycleOptions,
  ): Promise<EventKeyLifecycle> {
    const normalized = normalizeOptions(options);
    await prepareDirectories(normalized, false);
    return EventKeyLifecycle.openNormalized(normalized);
  }

  private static async openNormalized(
    options: NormalizedOptions,
    leaseToken?: string,
  ): Promise<EventKeyLifecycle> {
    const verified = await verifyState(options, leaseToken);
    zeroizeKeys(verified.keys);
    return new EventKeyLifecycle(options, verified.state);
  }

  public static async recoverStaleMutation(
    options: EventKeyLifecycleOptions,
  ): Promise<EventKeyMutationRecoveryReceipt> {
    const normalized = normalizeOptions(options);
    await prepareDirectories(normalized, false);
    const existing = await readMutationLockIfPresent(normalized);
    const recoveredExistingLock = existing !== undefined;
    if (existing !== undefined) assertMutationOwnerIsStale(existing.ownerPid);
    const lease = existing ?? (await acquireMutationLease(normalized));
    let recoveryCompleted = false;
    try {
      const temporaryPaths = await listRecoverableEventTemporaryFiles(
        normalized,
        lease.token,
      );
      await removeEventTemporaryFiles(normalized, temporaryPaths, lease.token);
      const verified = await verifyState(normalized, lease.token);
      try {
        recoveryCompleted = true;
        return Object.freeze({
          ...copyState(verified.state),
          recoveredExistingLock,
          removedEventTemporaryFiles: temporaryPaths.length,
        });
      } finally {
        zeroizeKeys(verified.keys);
      }
    } finally {
      if (recoveryCompleted) await releaseMutationLease(normalized, lease);
    }
  }

  public status(): EventKeyState {
    return copyState(this.#state);
  }

  public read(path: string): Promise<JsonValue> {
    return this.serialize(async () => {
      await this.refresh();
      return this.eventStore().read(path);
    });
  }

  public write(id: string, event: JsonValue): Promise<string> {
    return this.serialize(async () => {
      return withMutationLease(this.options, async (lease) => {
        await this.refresh(lease.token);
        const path = await this.eventStore().write(id, event);
        await assertOwnedMutationLease(this.options, lease.token);
        return path;
      });
    });
  }

  public rotate(
    input: EventKeyRotationInput,
  ): Promise<EventKeyRotationReceipt> {
    return this.serialize(async () => {
      const rotation = validateRotationInput(input);
      return withMutationLease(this.options, async (lease) => {
        const verified = await verifyState(this.options, lease.token);
        this.#state = verified.state;
        const keys = new Map(verified.keys);
        try {
          if (
            rotation.expectedActiveKeyVersion !==
            verified.state.activeKeyVersion
          )
            throw new SecurityError("EVENT_KEY_ROTATION_STALE");
          if (
            rotation.nextKeyVersion !== rotation.expectedActiveKeyVersion + 1 ||
            rotation.nextKeyVersion > MAX_EVENT_KEY_VERSION
          )
            throw new SecurityError("EVENT_KEY_ROTATION_NON_MONOTONIC");

          const nextKey = await loadKey(this.options, rotation.nextKeyVersion);
          keys.set(rotation.nextKeyVersion, nextKey);
          assertDistinctKeys(keys);

          const nextRecord = createRecord(
            {
              schemaVersion: STATE_SCHEMA_VERSION,
              storeId: verified.state.storeId,
              revision: verified.state.revision + 1,
              operation: "rotate",
              activeKeyVersion: rotation.nextKeyVersion,
              readableKeyVersions: Object.freeze([
                ...verified.state.readableKeyVersions,
                rotation.nextKeyVersion,
              ]),
              previousRecordDigest: verified.state.headRecordDigest,
            },
            nextKey,
          );
          await commitRecord(this.options, nextRecord, lease.token);
          await this.refresh(lease.token);
          if (
            this.#state.revision !== nextRecord.revision ||
            this.#state.activeKeyVersion !== nextRecord.activeKeyVersion
          )
            throw new SecurityError("EVENT_KEY_ROTATION_COMMIT_INVALID");
          return Object.freeze({
            ...copyState(this.#state),
            previousActiveKeyVersion: rotation.expectedActiveKeyVersion,
          });
        } finally {
          zeroizeKeys(keys);
        }
      });
    });
  }

  private async refresh(leaseToken?: string): Promise<void> {
    const verified = await verifyState(this.options, leaseToken);
    try {
      this.#state = verified.state;
    } finally {
      zeroizeKeys(verified.keys);
    }
  }

  private eventStore(): EncryptedEventStore {
    return new EncryptedEventStore(
      this.options.directory,
      this.options.secrets,
      this.options.keyReference,
      this.#state.activeKeyVersion,
      this.#state.readableKeyVersions,
    );
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#operationTail.then(operation, operation);
    this.#operationTail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}

async function withMutationLease<T>(
  options: NormalizedOptions,
  operation: (lease: MutationLease) => Promise<T>,
): Promise<T> {
  const lease = await acquireMutationLease(options);
  try {
    return await operation(lease);
  } finally {
    await releaseMutationLease(options, lease);
  }
}

async function acquireMutationLease(
  options: NormalizedOptions,
): Promise<MutationLease> {
  const record: MutationLockRecord = Object.freeze({
    schemaVersion: 1,
    ownerPid: process.pid,
    token: randomBytes(16).toString("hex"),
  });
  const path = mutationLockPath(options);
  let handle;
  try {
    handle = await open(path, "wx", 0o600);
  } catch (error) {
    if (isNodeError(error) && error.code === "EEXIST") {
      const existing = await readMutationLockIfPresent(options);
      if (existing === undefined)
        throw new SecurityError("EVENT_KEY_MUTATION_LOCK_INVALID");
      throw new SecurityError("EVENT_KEY_MUTATION_LOCKED");
    }
    throw new SecurityError("EVENT_KEY_MUTATION_LOCK_IO_FAILED");
  }
  try {
    await handle.chmod(0o600);
    await handle.writeFile(canonicalJson(record), "utf8");
    await handle.sync();
  } catch {
    throw new SecurityError("EVENT_KEY_MUTATION_LOCK_IO_FAILED");
  } finally {
    try {
      await handle.close();
    } catch {
      // The lock remains fail-closed when its durability cannot be proven.
    }
  }
  await syncDirectory(options.directory, "EVENT_KEY_MUTATION_LOCK_IO_FAILED");
  await assertOwnedMutationLease(options, record.token);
  return Object.freeze({ token: record.token });
}

async function releaseMutationLease(
  options: NormalizedOptions,
  lease: MutationLease,
): Promise<void> {
  await assertOwnedMutationLease(options, lease.token);
  try {
    await unlink(mutationLockPath(options));
  } catch {
    throw new SecurityError("EVENT_KEY_MUTATION_LEASE_LOST");
  }
  await syncDirectory(options.directory, "EVENT_KEY_MUTATION_LOCK_IO_FAILED");
}

async function assertOwnedMutationLease(
  options: NormalizedOptions,
  expectedToken: string,
): Promise<void> {
  const record = await readMutationLockIfPresent(options);
  if (record?.token !== expectedToken)
    throw new SecurityError("EVENT_KEY_MUTATION_LEASE_LOST");
}

async function readMutationLockIfPresent(
  options: NormalizedOptions,
): Promise<MutationLockRecord | undefined> {
  let handle;
  try {
    handle = await open(
      mutationLockPath(options),
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return undefined;
    throw new SecurityError("EVENT_KEY_MUTATION_LOCK_INVALID");
  }
  try {
    const stats = await handle.stat();
    if (
      !stats.isFile() ||
      stats.size <= 0 ||
      stats.size > MAX_MUTATION_LOCK_BYTES ||
      !hasExactPrivateFileMode(stats.mode)
    )
      throw new SecurityError("EVENT_KEY_MUTATION_LOCK_INVALID");
    const source = await handle.readFile("utf8");
    let value: unknown;
    try {
      value = JSON.parse(source) as unknown;
    } catch {
      throw new SecurityError("EVENT_KEY_MUTATION_LOCK_INVALID");
    }
    if (!isMutationLockRecord(value) || source !== canonicalJson(value))
      throw new SecurityError("EVENT_KEY_MUTATION_LOCK_INVALID");
    return Object.freeze({ ...value });
  } catch (error) {
    if (error instanceof SecurityError) throw error;
    throw new SecurityError("EVENT_KEY_MUTATION_LOCK_INVALID");
  } finally {
    try {
      await handle.close();
    } catch {
      // A close failure cannot make an invalid or foreign lock usable.
    }
  }
}

function isMutationLockRecord(value: unknown): value is MutationLockRecord {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    !sameStrings(Object.keys(value).sort(), [...MUTATION_LOCK_KEYS].sort())
  )
    return false;
  const candidate = value as Partial<MutationLockRecord>;
  return (
    candidate.schemaVersion === 1 &&
    isProcessId(candidate.ownerPid) &&
    typeof candidate.token === "string" &&
    MUTATION_TOKEN_PATTERN.test(candidate.token)
  );
}

function assertMutationOwnerIsStale(ownerPid: number): void {
  try {
    process.kill(ownerPid, 0);
  } catch (error) {
    if (isNodeError(error) && error.code === "ESRCH") return;
  }
  throw new SecurityError("EVENT_KEY_MUTATION_LOCK_ACTIVE");
}

function isProcessId(value: unknown): value is number {
  return isPositiveSafeInteger(value) && value <= MAX_PROCESS_ID;
}

function mutationLockPath(options: NormalizedOptions): string {
  return join(options.directory, MUTATION_LOCK_NAME);
}

async function syncDirectory(path: string, errorCode: string): Promise<void> {
  let handle;
  try {
    handle = await open(
      path,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    const stats = await handle.stat();
    if (!stats.isDirectory()) throw new Error("NOT_A_DIRECTORY");
    await handle.sync();
  } catch {
    throw new SecurityError(errorCode);
  } finally {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        // The caller receives a failure only when acquisition or sync failed.
      }
    }
  }
}

function normalizeOptions(options: unknown): NormalizedOptions {
  if (
    options === null ||
    typeof options !== "object" ||
    Array.isArray(options) ||
    Object.getPrototypeOf(options) !== Object.prototype
  )
    throw new SecurityError("EVENT_KEY_LIFECYCLE_OPTIONS_INVALID");
  const allowedKeys = [
    "directory",
    "keyReference",
    "minimumActiveKeyVersion",
    "secrets",
  ];
  const keys = Reflect.ownKeys(options);
  if (
    keys.some((key) => typeof key !== "string" || !allowedKeys.includes(key)) ||
    !keys.includes("directory") ||
    !keys.includes("keyReference") ||
    !keys.includes("minimumActiveKeyVersion") ||
    !keys.includes("secrets")
  )
    throw new SecurityError("EVENT_KEY_LIFECYCLE_OPTIONS_INVALID");
  const descriptors = Object.getOwnPropertyDescriptors(options);
  const directoryValue = dataDescriptorValue(descriptors["directory"]);
  const keyReferenceValue = dataDescriptorValue(descriptors["keyReference"]);
  const secretsValue = dataDescriptorValue(descriptors["secrets"]);
  if (
    typeof directoryValue !== "string" ||
    directoryValue.length === 0 ||
    directoryValue.includes("\u0000") ||
    !isKeyReference(keyReferenceValue) ||
    !isSecretStore(secretsValue)
  )
    throw new SecurityError("EVENT_KEY_LIFECYCLE_OPTIONS_INVALID");
  const minimum = dataDescriptorValue(descriptors["minimumActiveKeyVersion"]);
  if (!isKeyVersion(minimum))
    throw new SecurityError("EVENT_KEY_LIFECYCLE_OPTIONS_INVALID");
  const directory = resolve(directoryValue);
  return Object.freeze({
    directory,
    stateDirectory: join(directory, STATE_DIRECTORY_NAME),
    secrets: secretsValue,
    keyReference: keyReferenceValue,
    minimumActiveKeyVersion: minimum,
  });
}

function assertV1MeetsMinimum(options: NormalizedOptions): void {
  if (options.minimumActiveKeyVersion > 1)
    throw new SecurityError("EVENT_KEY_ACTIVE_VERSION_BELOW_MINIMUM");
}

async function prepareDirectories(
  options: NormalizedOptions,
  create: boolean,
): Promise<void> {
  await prepareRootDirectory(options, create);
  if (create) {
    await mkdir(options.stateDirectory, { recursive: true, mode: 0o700 });
    await assertDirectory(options.stateDirectory, true);
    return;
  }
  await assertDirectory(options.directory, false);
  await assertDirectory(options.stateDirectory, false);
}

async function prepareRootDirectory(
  options: NormalizedOptions,
  create: boolean,
): Promise<void> {
  if (create) await mkdir(options.directory, { recursive: true, mode: 0o700 });
  await assertDirectory(options.directory, create);
}

async function assertDirectory(
  path: string,
  repairMode: boolean,
): Promise<void> {
  let stats;
  try {
    stats = await lstat(path);
  } catch {
    throw new SecurityError("EVENT_KEY_STATE_MISSING");
  }
  if (stats.isSymbolicLink() || !stats.isDirectory())
    throw new SecurityError("EVENT_KEY_DIRECTORY_INVALID");
  if (repairMode) await chmod(path, 0o700);
  const current = repairMode ? await lstat(path) : stats;
  if ((current.mode & 0o7777) !== 0o700)
    throw new SecurityError("EVENT_KEY_DIRECTORY_PERMISSIONS");
}

async function assertNoStateRecords(options: NormalizedOptions): Promise<void> {
  if ((await listStateRecordPaths(options)).length !== 0)
    throw new SecurityError("EVENT_KEY_STATE_EXISTS");
}

async function listStateRecordPaths(
  options: NormalizedOptions,
): Promise<readonly string[]> {
  let names: string[];
  try {
    names = await readdir(options.stateDirectory);
  } catch {
    throw new SecurityError("EVENT_KEY_STATE_MISSING");
  }
  const records: { readonly revision: number; readonly path: string }[] = [];
  for (const name of names) {
    const path = join(options.stateDirectory, name);
    const stats = await secureEntryStats(path);
    const recordMatch = STATE_FILE_PATTERN.exec(name);
    if (recordMatch?.[1] !== undefined) {
      if (!stats.isFile() || !hasPrivateFileMode(stats.mode))
        throw new SecurityError("EVENT_KEY_STATE_FILE_INVALID");
      const revision = Number(recordMatch[1]);
      if (!isPositiveSafeInteger(revision))
        throw new SecurityError("EVENT_KEY_STATE_FILE_INVALID");
      records.push({ revision, path });
      continue;
    }
    if (TEMP_FILE_PATTERN.test(name)) {
      if (
        !stats.isFile() ||
        !hasPrivateFileMode(stats.mode) ||
        stats.size > MAX_STATE_RECORD_BYTES
      )
        throw new SecurityError("EVENT_KEY_STATE_TEMP_INVALID");
      continue;
    }
    throw new SecurityError("EVENT_KEY_STATE_UNKNOWN_FILE");
  }
  records.sort((left, right) => left.revision - right.revision);
  for (let index = 0; index < records.length; index += 1) {
    const expected = index + 1;
    const record = records[index];
    if (
      record?.revision !== expected ||
      record.path !== join(options.stateDirectory, stateFileName(expected))
    )
      throw new SecurityError("EVENT_KEY_STATE_CHAIN_INVALID");
  }
  return Object.freeze(records.map(({ path }) => path));
}

async function secureEntryStats(path: string) {
  let stats;
  try {
    stats = await lstat(path);
  } catch {
    throw new SecurityError("EVENT_KEY_STATE_FILE_INVALID");
  }
  if (stats.isSymbolicLink())
    throw new SecurityError("EVENT_KEY_STATE_SYMLINK");
  return stats;
}

function hasPrivateFileMode(mode: number): boolean {
  return (mode & 0o7777) === 0o600;
}

function hasExactPrivateFileMode(mode: number): boolean {
  return hasPrivateFileMode(mode);
}

async function listEventFiles(
  options: NormalizedOptions,
  leaseToken?: string,
): Promise<readonly string[]> {
  return (await scanEventDirectory(options, leaseToken, false)).eventPaths;
}

async function listRecoverableEventTemporaryFiles(
  options: NormalizedOptions,
  leaseToken: string,
): Promise<readonly string[]> {
  return (await scanEventDirectory(options, leaseToken, true)).temporaryPaths;
}

async function scanEventDirectory(
  options: NormalizedOptions,
  leaseToken: string | undefined,
  allowEventTemporaryFiles: boolean,
): Promise<EventDirectoryScan> {
  const names = await readdir(options.directory);
  names.sort();
  const eventPaths: string[] = [];
  const temporaryPaths: string[] = [];
  let ownedLockFound = false;
  for (const name of names) {
    if (name === STATE_DIRECTORY_NAME) continue;
    if (name === MUTATION_LOCK_NAME) {
      const lock = await readMutationLockIfPresent(options);
      if (lock === undefined)
        throw new SecurityError("EVENT_KEY_MUTATION_LOCK_INVALID");
      if (leaseToken === undefined || lock.token !== leaseToken)
        throw new SecurityError("EVENT_KEY_MUTATION_LOCKED");
      ownedLockFound = true;
      continue;
    }
    const path = join(options.directory, name);
    const stats = await secureEntryStats(path);
    if (EVENT_TEMP_FILE_PATTERN.test(name)) {
      if (
        !stats.isFile() ||
        !hasExactPrivateFileMode(stats.mode) ||
        stats.size > MAX_EVENT_ENVELOPE_BYTES
      )
        throw new SecurityError("EVENT_KEY_EVENT_TEMP_INVALID");
      if (!allowEventTemporaryFiles)
        throw new SecurityError("EVENT_KEY_MUTATION_RECOVERY_REQUIRED");
      temporaryPaths.push(path);
      continue;
    }
    if (EVENT_FILE_PATTERN.test(name)) {
      if (!stats.isFile() || !hasPrivateFileMode(stats.mode))
        throw new SecurityError("EVENT_KEY_LEGACY_INVALID");
      eventPaths.push(path);
      continue;
    }
    throw new SecurityError("EVENT_KEY_DIRECTORY_UNKNOWN_FILE");
  }
  if (leaseToken !== undefined) {
    if (!ownedLockFound)
      throw new SecurityError("EVENT_KEY_MUTATION_LEASE_LOST");
    await assertOwnedMutationLease(options, leaseToken);
  }
  eventPaths.sort();
  temporaryPaths.sort();
  return Object.freeze({
    eventPaths: Object.freeze(eventPaths),
    temporaryPaths: Object.freeze(temporaryPaths),
  });
}

async function removeEventTemporaryFiles(
  options: NormalizedOptions,
  paths: readonly string[],
  leaseToken: string,
): Promise<void> {
  await assertOwnedMutationLease(options, leaseToken);
  for (const path of paths) await assertRecoverableEventTemporaryFile(path);
  for (const path of paths) {
    try {
      await unlink(path);
    } catch {
      throw new SecurityError("EVENT_KEY_MUTATION_RECOVERY_FAILED");
    }
  }
  if (paths.length > 0)
    await syncDirectory(
      options.directory,
      "EVENT_KEY_MUTATION_RECOVERY_FAILED",
    );
  await assertOwnedMutationLease(options, leaseToken);
}

async function assertRecoverableEventTemporaryFile(
  path: string,
): Promise<void> {
  const name = path.slice(path.lastIndexOf("/") + 1);
  if (!EVENT_TEMP_FILE_PATTERN.test(name))
    throw new SecurityError("EVENT_KEY_EVENT_TEMP_INVALID");
  const stats = await secureEntryStats(path);
  if (
    !stats.isFile() ||
    !hasExactPrivateFileMode(stats.mode) ||
    stats.size > MAX_EVENT_ENVELOPE_BYTES
  )
    throw new SecurityError("EVENT_KEY_EVENT_TEMP_INVALID");
}

async function verifyState(
  options: NormalizedOptions,
  leaseToken?: string,
): Promise<VerifiedState> {
  await listEventFiles(options, leaseToken);
  const chain = await parseChain(options);
  const keys = new Map<number, Uint8Array>();
  try {
    for (const record of chain.records)
      keys.set(
        record.activeKeyVersion,
        await loadKey(options, record.activeKeyVersion),
      );
    assertDistinctKeys(keys);
    for (const record of chain.records) {
      const key = keys.get(record.activeKeyVersion);
      if (key === undefined || !authenticationMatches(record, key))
        throw new SecurityError("EVENT_KEY_STATE_AUTHENTICATION_FAILED");
    }
    const head = chain.records.at(-1);
    const headDigest = chain.digests.at(-1);
    if (head === undefined || headDigest === undefined)
      throw new SecurityError("EVENT_KEY_STATE_MISSING");
    if (head.activeKeyVersion < options.minimumActiveKeyVersion)
      throw new SecurityError("EVENT_KEY_ACTIVE_VERSION_BELOW_MINIMUM");
    return {
      state: freezeState({
        schemaVersion: STATE_SCHEMA_VERSION,
        storeId: head.storeId,
        revision: head.revision,
        activeKeyVersion: head.activeKeyVersion,
        readableKeyVersions: head.readableKeyVersions,
        headRecordDigest: headDigest,
      }),
      keys,
    };
  } catch (error) {
    zeroizeKeys(keys);
    throw error;
  }
}

async function parseChain(options: NormalizedOptions): Promise<ParsedChain> {
  const paths = await listStateRecordPaths(options);
  if (paths.length === 0) throw new SecurityError("EVENT_KEY_STATE_MISSING");
  const records: EventKeyStateRecord[] = [];
  const digests: string[] = [];
  let expectedPrevious = GENESIS_DIGEST;
  let expectedStoreId: string | undefined;
  for (let index = 0; index < paths.length; index += 1) {
    const path = paths[index];
    if (path === undefined)
      throw new SecurityError("EVENT_KEY_STATE_CHAIN_INVALID");
    const stats = await secureEntryStats(path);
    if (
      !stats.isFile() ||
      stats.size <= 0 ||
      stats.size > MAX_STATE_RECORD_BYTES ||
      !hasPrivateFileMode(stats.mode)
    )
      throw new SecurityError("EVENT_KEY_STATE_FILE_INVALID");
    const source = await readFile(path, "utf8");
    let value: unknown;
    try {
      value = JSON.parse(source) as unknown;
    } catch {
      throw new SecurityError("EVENT_KEY_STATE_JSON_INVALID");
    }
    if (!isStateRecord(value) || source !== canonicalJson(value))
      throw new SecurityError("EVENT_KEY_STATE_RECORD_INVALID");
    const expectedRevision = index + 1;
    if (
      value.revision !== expectedRevision ||
      value.activeKeyVersion !== expectedRevision ||
      value.previousRecordDigest !== expectedPrevious ||
      (index === 0
        ? value.operation !== "initialize" &&
          value.operation !== "adopt_legacy_v1"
        : value.operation !== "rotate") ||
      (expectedStoreId !== undefined && value.storeId !== expectedStoreId)
    )
      throw new SecurityError("EVENT_KEY_STATE_CHAIN_INVALID");
    expectedStoreId ??= value.storeId;
    const digest = sha256(source);
    records.push(freezeRecord(value));
    digests.push(digest);
    expectedPrevious = digest;
  }
  return {
    records: Object.freeze(records),
    digests: Object.freeze(digests),
  };
}

function isStateRecord(value: unknown): value is EventKeyStateRecord {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    !sameStrings(Object.keys(value).sort(), [...RECORD_KEYS].sort())
  )
    return false;
  const candidate = value as Partial<EventKeyStateRecord>;
  if (
    candidate.schemaVersion !== STATE_SCHEMA_VERSION ||
    typeof candidate.storeId !== "string" ||
    !STORE_ID_PATTERN.test(candidate.storeId) ||
    !isPositiveSafeInteger(candidate.revision) ||
    !isOperation(candidate.operation) ||
    !isKeyVersion(candidate.activeKeyVersion) ||
    !Array.isArray(candidate.readableKeyVersions) ||
    typeof candidate.previousRecordDigest !== "string" ||
    !DIGEST_PATTERN.test(candidate.previousRecordDigest) ||
    typeof candidate.authenticationTag !== "string" ||
    !DIGEST_PATTERN.test(candidate.authenticationTag)
  )
    return false;
  const readable = candidate.readableKeyVersions;
  if (readable.length !== candidate.activeKeyVersion) return false;
  for (let index = 0; index < readable.length; index += 1)
    if (readable[index] !== index + 1) return false;
  return true;
}

function isOperation(value: unknown): value is EventKeyStateOperation {
  return (
    value === "initialize" || value === "adopt_legacy_v1" || value === "rotate"
  );
}

function createRecord(
  unsigned: Omit<EventKeyStateRecord, "authenticationTag">,
  key: Uint8Array,
): EventKeyStateRecord {
  const authenticationTag = calculateAuthenticationTag(unsigned, key);
  return freezeRecord({ ...unsigned, authenticationTag });
}

function calculateAuthenticationTag(
  unsigned: Omit<EventKeyStateRecord, "authenticationTag">,
  key: Uint8Array,
): string {
  const derived = Buffer.from(
    hkdfSync(
      "sha256",
      key,
      Buffer.from(unsigned.storeId, "hex"),
      HKDF_INFO,
      KEY_BYTES,
    ),
  );
  try {
    return createHmac("sha256", derived)
      .update(canonicalJson(unsigned), "utf8")
      .digest("hex");
  } finally {
    zeroize(derived);
  }
}

function authenticationMatches(
  record: EventKeyStateRecord,
  key: Uint8Array,
): boolean {
  const { authenticationTag, ...unsigned } = record;
  const expected = Buffer.from(
    calculateAuthenticationTag(unsigned, key),
    "hex",
  );
  const actual = Buffer.from(authenticationTag, "hex");
  try {
    return timingSafeEqual(expected, actual);
  } finally {
    zeroize(expected);
    zeroize(actual);
  }
}

async function commitRecord(
  options: NormalizedOptions,
  record: EventKeyStateRecord,
  leaseToken: string,
): Promise<void> {
  await assertOwnedMutationLease(options, leaseToken);
  const destination = join(
    options.stateDirectory,
    stateFileName(record.revision),
  );
  const temporary = join(
    options.stateDirectory,
    `.tmp-state-${String(process.pid)}-${randomBytes(8).toString("hex")}`,
  );
  const source = canonicalJson(record);
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(source, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(temporary, 0o600);
  let commitFailed = false;
  let commitError: unknown;
  try {
    try {
      await link(temporary, destination);
    } catch (error) {
      if (isNodeError(error) && error.code === "EEXIST")
        throw new SecurityError("EVENT_KEY_ROTATION_CONFLICT");
      throw error;
    }
    await assertOwnedMutationLease(options, leaseToken);
    await syncDirectory(options.stateDirectory, "EVENT_KEY_STATE_IO_FAILED");
  } catch (error) {
    commitFailed = true;
    commitError = error;
  }
  try {
    await unlink(temporary);
    await syncDirectory(
      options.stateDirectory,
      "EVENT_KEY_STATE_TEMP_CLEANUP_FAILED",
    );
  } catch {
    throw new SecurityError("EVENT_KEY_STATE_TEMP_CLEANUP_FAILED");
  }
  if (commitFailed) throw commitError;
  await assertOwnedMutationLease(options, leaseToken);
}

async function loadKey(
  options: NormalizedOptions,
  version: number,
): Promise<Uint8Array> {
  let reference: string;
  try {
    reference = options.keyReference(version);
  } catch {
    throw new SecurityError("EVENT_KEY_REFERENCE_INVALID");
  }
  if (
    typeof reference !== "string" ||
    reference.length === 0 ||
    reference.length > 512 ||
    reference.includes("\u0000")
  )
    throw new SecurityError("EVENT_KEY_REFERENCE_INVALID");
  let value: unknown;
  try {
    value = await options.secrets.get(reference);
  } catch {
    throw new SecurityError("EVENT_KEY_UNAVAILABLE");
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype ||
    Object.hasOwn(value, "fill") ||
    !(value instanceof Uint8Array) ||
    value.byteLength !== KEY_BYTES
  ) {
    if (value instanceof Uint8Array) zeroize(value);
    throw new SecurityError("EVENT_KEY_INVALID");
  }
  return value;
}

function assertDistinctKeys(keys: ReadonlyMap<number, Uint8Array>): void {
  const entries = [...keys.entries()];
  for (let leftIndex = 0; leftIndex < entries.length; leftIndex += 1) {
    const left = entries[leftIndex];
    if (left === undefined) continue;
    for (
      let rightIndex = leftIndex + 1;
      rightIndex < entries.length;
      rightIndex += 1
    ) {
      const right = entries[rightIndex];
      if (
        right !== undefined &&
        timingSafeEqual(
          Buffer.from(left[1].buffer, left[1].byteOffset, left[1].byteLength),
          Buffer.from(
            right[1].buffer,
            right[1].byteOffset,
            right[1].byteLength,
          ),
        )
      )
        throw new SecurityError("EVENT_KEY_DUPLICATE");
    }
  }
}

function validateRotationInput(input: unknown): EventKeyRotationInput {
  let expected: unknown;
  let next: unknown;
  try {
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input) ||
      Object.getPrototypeOf(input) !== Object.prototype
    )
      throw new Error("invalid");
    const keys = Reflect.ownKeys(input);
    if (
      keys.length !== 2 ||
      !keys.includes("expectedActiveKeyVersion") ||
      !keys.includes("nextKeyVersion")
    )
      throw new Error("invalid");
    const expectedDescriptor = Object.getOwnPropertyDescriptor(
      input,
      "expectedActiveKeyVersion",
    );
    const nextDescriptor = Object.getOwnPropertyDescriptor(
      input,
      "nextKeyVersion",
    );
    if (
      expectedDescriptor === undefined ||
      !("value" in expectedDescriptor) ||
      nextDescriptor === undefined ||
      !("value" in nextDescriptor)
    )
      throw new Error("invalid");
    expected = expectedDescriptor.value;
    next = nextDescriptor.value;
  } catch {
    throw new SecurityError("EVENT_KEY_ROTATION_INPUT_INVALID");
  }
  if (!isKeyVersion(expected) || !isKeyVersion(next))
    throw new SecurityError("EVENT_KEY_ROTATION_INPUT_INVALID");
  return Object.freeze({
    expectedActiveKeyVersion: expected,
    nextKeyVersion: next,
  });
}

function isKeyVersion(value: unknown): value is number {
  return isPositiveSafeInteger(value) && value <= MAX_EVENT_KEY_VERSION;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function stateFileName(revision: number): string {
  return `state-${String(revision).padStart(10, "0")}.json`;
}

function freezeRecord(record: EventKeyStateRecord): EventKeyStateRecord {
  return Object.freeze({
    ...record,
    readableKeyVersions: Object.freeze([...record.readableKeyVersions]),
  });
}

function freezeState(state: EventKeyState): EventKeyState {
  return Object.freeze({
    ...state,
    readableKeyVersions: Object.freeze([...state.readableKeyVersions]),
  });
}

function copyState(state: EventKeyState): EventKeyState {
  return freezeState(state);
}

function sameStrings(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function zeroizeKeys(keys: ReadonlyMap<number, Uint8Array>): void {
  for (const key of keys.values()) zeroize(key);
}

function zeroize(value: Uint8Array): void {
  for (let index = 0; index < value.byteLength; index += 1) value[index] = 0;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function isSecretStore(
  value: unknown,
): value is EventKeyLifecycleOptions["secrets"] {
  if (value === null || typeof value !== "object") return false;
  try {
    const own = Object.getOwnPropertyDescriptor(value, "get");
    if (own !== undefined)
      return "value" in own && typeof own.value === "function";
    const prototype = Reflect.getPrototypeOf(value);
    if (prototype === null) return false;
    const inherited = Object.getOwnPropertyDescriptor(prototype, "get");
    return (
      inherited !== undefined &&
      "value" in inherited &&
      typeof inherited.value === "function"
    );
  } catch {
    return false;
  }
}

function isKeyReference(
  value: unknown,
): value is EventKeyLifecycleOptions["keyReference"] {
  return typeof value === "function";
}

async function pathIsMissing(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return false;
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return true;
    throw new SecurityError("EVENT_KEY_STATE_IO_FAILED");
  }
}

function hasSecurityCode(error: unknown, code: string): boolean {
  return error instanceof SecurityError && error.code === code;
}

function dataDescriptorValue(
  descriptor: PropertyDescriptor | undefined,
): unknown {
  if (descriptor === undefined || !("value" in descriptor))
    throw new SecurityError("EVENT_KEY_LIFECYCLE_OPTIONS_INVALID");
  return descriptor.value;
}
