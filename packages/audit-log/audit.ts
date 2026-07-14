import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  open,
  realpath,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { isAbsolute, basename, dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { types } from "node:util";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

export interface AuditPayload {
  readonly timestamp: string;
  readonly action: string;
  readonly decision: string;
  readonly reasonCode: string;
  readonly policyHash: string;
  readonly assetRef?: string;
  readonly accountRef?: string;
}

export interface AuditRecord extends AuditPayload {
  readonly sequence: number;
  readonly previousHash: string;
  readonly hash: string;
}

export const MAX_AUDIT_RECORD_BYTES = 4 * 1024;
export const MAX_AUDIT_LOG_BYTES = 16 * 1024 * 1024;
export const MAX_AUDIT_LOG_ENTRIES = 50_000;
export const AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION =
  "confirm-local-offline-audit-recovery";

const GENESIS = "0".repeat(64);
const SAFE_REQUIRED = /^[A-Za-z0-9_.:/-]{1,256}$/u;
const SHA256_HEX = /^[a-f0-9]{64}$/u;
const TIMESTAMP =
  /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{3})?Z$/u;
const REQUIRED_PAYLOAD_KEYS = Object.freeze([
  "action",
  "decision",
  "policyHash",
  "reasonCode",
  "timestamp",
] as const);
const OPTIONAL_PAYLOAD_KEYS = Object.freeze([
  "accountRef",
  "assetRef",
] as const);
const LOCK_WAIT_MS = 5_000;
const LOCK_POLL_MS = 5;
const LOCK_SCHEMA_VERSION = 1;
const MAX_AUDIT_LOCK_BYTES = 512;
const PATH_MAX_BYTES = 4 * 1024;
const decoder = new TextDecoder("utf-8", { fatal: true });

interface AuditPath {
  readonly path: string;
  readonly parent: string;
  readonly lockPath: string;
  readonly parentDevice: number;
  readonly parentInode: number;
}

interface AuditHead {
  readonly entries: number;
  readonly lastHash: string;
  readonly bytes: number;
}

interface MutationLease {
  readonly handle: FileHandle;
  readonly device: number;
  readonly inode: number;
}

interface MutationLockRecord {
  readonly schemaVersion: 1;
  readonly pid: number;
  readonly token: string;
}

export class AuditLog {
  readonly #path: string;

  public constructor(path: string) {
    this.#path = path;
    Object.freeze(this);
  }

  public async append(payload: AuditPayload): Promise<AuditRecord> {
    const normalized = normalizePayload(payload);
    const auditPath = await validateAuditPath(this.#path);
    return withMutationLease(auditPath, async () => {
      const handle = await openAuditFile(auditPath, true);
      try {
        const head = await readAndVerify(handle);
        if (head.entries >= MAX_AUDIT_LOG_ENTRIES)
          throw new SecurityError("AUDIT_ENTRY_LIMIT_EXCEEDED");
        const base = freezeAuditBase(normalized, head.entries, head.lastHash);
        const record = Object.freeze({
          ...base,
          hash: sha256(canonicalJson(base)),
        });
        const encoded = Buffer.from(`${canonicalJson(record)}\n`, "utf8");
        if (encoded.byteLength > MAX_AUDIT_RECORD_BYTES)
          throw new SecurityError("AUDIT_RECORD_TOO_LARGE");
        if (head.bytes + encoded.byteLength > MAX_AUDIT_LOG_BYTES)
          throw new SecurityError("AUDIT_LOG_TOO_LARGE");
        await appendFully(handle, encoded);
        await handle.sync();
        const after = await handle.stat();
        assertAuditFileMetadata(after);
        if (after.size !== head.bytes + encoded.byteLength)
          throw new SecurityError("AUDIT_CONCURRENT_MUTATION");
        await assertPathMatchesHandle(auditPath.path, after.dev, after.ino);
        await assertParentUnchanged(auditPath);
        await syncDirectory(auditPath.parent);
        return record;
      } finally {
        await handle.close();
      }
    });
  }
}

export async function verifyAuditLog(
  path: string,
): Promise<{ valid: true; entries: number }> {
  const auditPath = await validateAuditPath(path);
  return withMutationLease(auditPath, async () => {
    let handle: FileHandle;
    try {
      handle = await openAuditFile(auditPath, false);
    } catch (error) {
      if (isNodeError(error) && error.code === "ENOENT")
        throw new SecurityError("AUDIT_READ_FAILED");
      throw error;
    }
    try {
      const head = await readAndVerify(handle);
      await assertPathMatchesHandle(
        auditPath.path,
        undefined,
        undefined,
        handle,
      );
      await assertParentUnchanged(auditPath);
      return Object.freeze({ valid: true as const, entries: head.entries });
    } finally {
      await handle.close();
    }
  });
}

export async function recoverStaleAuditMutation(
  path: string,
  confirmation: string,
): Promise<{
  readonly recovered: true;
  readonly valid: true;
  readonly entries: number;
}> {
  if (confirmation !== AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION)
    throw new SecurityError("AUDIT_RECOVERY_CONFIRMATION_REQUIRED");
  const auditPath = await validateAuditPath(path);
  const lock = await openMutationLockForRecovery(auditPath);
  let auditHandle: FileHandle | undefined;
  let head: AuditHead;
  try {
    assertMutationOwnerStale(lock.record.pid);
    try {
      auditHandle = await openAuditFile(auditPath, false);
      head = await readAndVerify(auditHandle);
      await assertPathMatchesHandle(
        auditPath.path,
        undefined,
        undefined,
        auditHandle,
      );
    } catch (error) {
      if (!isNodeError(error) || error.code !== "ENOENT") throw error;
      head = Object.freeze({ entries: 0, lastHash: GENESIS, bytes: 0 });
    }
    assertMutationOwnerStale(lock.record.pid);
    assertLockMetadata(await lock.handle.stat(), false);
    await assertPathMatchesHandle(auditPath.lockPath, lock.device, lock.inode);
    await assertParentUnchanged(auditPath);
    await unlink(auditPath.lockPath);
  } finally {
    if (auditHandle !== undefined) await auditHandle.close();
    await lock.handle.close();
  }
  await syncDirectory(auditPath.parent);
  await assertParentUnchanged(auditPath);
  return Object.freeze({
    recovered: true as const,
    valid: true as const,
    entries: head.entries,
  });
}

async function validateAuditPath(value: unknown): Promise<AuditPath> {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > PATH_MAX_BYTES ||
    !isAbsolute(value) ||
    resolve(value) !== value
  )
    throw new SecurityError("AUDIT_PATH_INVALID");
  const name = basename(value);
  if (name.length === 0 || name === "." || name === "..")
    throw new SecurityError("AUDIT_PATH_INVALID");
  const parent = dirname(value);
  let metadata;
  try {
    metadata = await lstat(parent);
  } catch {
    throw new SecurityError("AUDIT_PARENT_INVALID");
  }
  if (
    metadata.isSymbolicLink() ||
    !metadata.isDirectory() ||
    (metadata.mode & 0o777) !== 0o700 ||
    !ownedByCurrentUser(metadata.uid)
  )
    throw new SecurityError("AUDIT_PARENT_INVALID");
  let canonicalParent: string;
  try {
    canonicalParent = await realpath(parent);
  } catch {
    throw new SecurityError("AUDIT_PARENT_INVALID");
  }
  if (canonicalParent !== parent)
    throw new SecurityError("AUDIT_PARENT_INVALID");
  return Object.freeze({
    path: value,
    parent,
    lockPath: `${value}.mutation.lock`,
    parentDevice: metadata.dev,
    parentInode: metadata.ino,
  });
}

async function withMutationLease<T>(
  auditPath: AuditPath,
  operation: () => Promise<T>,
): Promise<T> {
  const lease = await acquireMutationLease(auditPath);
  let outcome:
    | { readonly succeeded: true; readonly value: T }
    | { readonly succeeded: false; readonly error: Error };
  try {
    outcome = { succeeded: true, value: await operation() };
  } catch (error) {
    outcome = {
      succeeded: false,
      error:
        error instanceof Error
          ? error
          : new SecurityError("AUDIT_OPERATION_FAILED"),
    };
  }
  try {
    await releaseMutationLease(auditPath, lease);
  } catch {
    throw new SecurityError("AUDIT_MUTATION_LEASE_RELEASE_FAILED");
  }
  if (!outcome.succeeded) throw outcome.error;
  return outcome.value;
}

async function acquireMutationLease(
  auditPath: AuditPath,
): Promise<MutationLease> {
  const deadline = performance.now() + LOCK_WAIT_MS;
  for (;;) {
    let handle: FileHandle;
    try {
      handle = await open(
        auditPath.lockPath,
        constants.O_CREAT |
          constants.O_EXCL |
          constants.O_RDWR |
          constants.O_NOFOLLOW,
        0o600,
      );
    } catch (error) {
      if (!isNodeError(error) || error.code !== "EEXIST")
        throw new SecurityError("AUDIT_MUTATION_LEASE_FAILED");
      if (performance.now() >= deadline)
        throw new SecurityError("AUDIT_MUTATION_LOCKED");
      await delay(LOCK_POLL_MS);
      continue;
    }
    try {
      await handle.chmod(0o600);
      const metadata = await handle.stat();
      assertLockMetadata(metadata, true);
      const leaseRecord = Buffer.from(
        `${canonicalJson({
          schemaVersion: LOCK_SCHEMA_VERSION,
          pid: process.pid,
          token: randomBytes(16).toString("hex"),
        })}\n`,
        "utf8",
      );
      await appendFully(handle, leaseRecord);
      await handle.sync();
      assertLockMetadata(await handle.stat(), false);
      await assertPathMatchesHandle(
        auditPath.lockPath,
        metadata.dev,
        metadata.ino,
      );
      await assertParentUnchanged(auditPath);
      await syncDirectory(auditPath.parent);
      return Object.freeze({
        handle,
        device: metadata.dev,
        inode: metadata.ino,
      });
    } catch (error) {
      try {
        await handle.close();
      } catch {
        // The durable lock remains fail closed when its creation is uncertain.
      }
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("AUDIT_MUTATION_LEASE_FAILED");
    }
  }
}

async function openMutationLockForRecovery(auditPath: AuditPath): Promise<{
  readonly handle: FileHandle;
  readonly device: number;
  readonly inode: number;
  readonly record: MutationLockRecord;
}> {
  let expected;
  try {
    expected = await lstat(auditPath.lockPath);
  } catch {
    throw new SecurityError("AUDIT_RECOVERY_LOCK_REQUIRED");
  }
  assertLockMetadata(expected, false);
  let handle: FileHandle;
  try {
    handle = await open(
      auditPath.lockPath,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
  } catch {
    throw new SecurityError("AUDIT_MUTATION_LEASE_INVALID");
  }
  try {
    const actual = await handle.stat();
    assertLockMetadata(actual, false);
    if (actual.dev !== expected.dev || actual.ino !== expected.ino)
      throw new SecurityError("AUDIT_MUTATION_LEASE_INVALID");
    const encoded = await handle.readFile();
    const after = await handle.stat();
    assertLockMetadata(after, false);
    if (
      after.size !== actual.size ||
      encoded.byteLength !== actual.size ||
      after.dev !== actual.dev ||
      after.ino !== actual.ino
    )
      throw new SecurityError("AUDIT_MUTATION_LEASE_INVALID");
    const record = parseMutationLockRecord(encoded);
    return Object.freeze({
      handle,
      device: actual.dev,
      inode: actual.ino,
      record,
    });
  } catch (error) {
    await handle.close();
    throw error;
  }
}

function parseMutationLockRecord(encoded: Uint8Array): MutationLockRecord {
  let source: string;
  try {
    source = decoder.decode(encoded);
  } catch {
    throw new SecurityError("AUDIT_MUTATION_LEASE_INVALID");
  }
  if (!source.endsWith("\n") || source.slice(0, -1).includes("\n"))
    throw new SecurityError("AUDIT_MUTATION_LEASE_INVALID");
  const line = source.slice(0, -1);
  let value: unknown;
  try {
    value = JSON.parse(line) as unknown;
  } catch {
    throw new SecurityError("AUDIT_MUTATION_LEASE_INVALID");
  }
  const descriptors = exactDataDescriptors(
    value,
    ["pid", "schemaVersion", "token"],
    [],
    "AUDIT_MUTATION_LEASE_INVALID",
  );
  const schemaVersion = mutationDescriptorNumber(descriptors, "schemaVersion");
  const pid = mutationDescriptorNumber(descriptors, "pid");
  const token = mutationDescriptorString(descriptors, "token");
  const candidate = Object.freeze({ schemaVersion, pid, token });
  if (
    schemaVersion !== LOCK_SCHEMA_VERSION ||
    !Number.isSafeInteger(pid) ||
    pid < 1 ||
    pid > 2_147_483_647 ||
    !/^[a-f0-9]{32}$/u.test(token) ||
    canonicalJson(candidate) !== line
  )
    throw new SecurityError("AUDIT_MUTATION_LEASE_INVALID");
  return Object.freeze({ schemaVersion, pid, token });
}

function mutationDescriptorNumber(
  descriptors: Readonly<Record<string, PropertyDescriptor>>,
  key: string,
): number {
  const descriptor = descriptors[key];
  if (descriptor === undefined || typeof descriptor.value !== "number")
    throw new SecurityError("AUDIT_MUTATION_LEASE_INVALID");
  return descriptor.value;
}

function mutationDescriptorString(
  descriptors: Readonly<Record<string, PropertyDescriptor>>,
  key: string,
): string {
  const descriptor = descriptors[key];
  if (descriptor === undefined || typeof descriptor.value !== "string")
    throw new SecurityError("AUDIT_MUTATION_LEASE_INVALID");
  return descriptor.value;
}

function assertMutationOwnerStale(pid: number): void {
  try {
    process.kill(pid, 0);
  } catch (error) {
    if (isNodeError(error) && error.code === "ESRCH") return;
    if (isNodeError(error) && error.code === "EPERM")
      throw new SecurityError("AUDIT_MUTATION_LOCK_ACTIVE");
    throw new SecurityError("AUDIT_MUTATION_OWNER_CHECK_FAILED");
  }
  throw new SecurityError("AUDIT_MUTATION_LOCK_ACTIVE");
}

async function releaseMutationLease(
  auditPath: AuditPath,
  lease: MutationLease,
): Promise<void> {
  try {
    await assertPathMatchesHandle(
      auditPath.lockPath,
      lease.device,
      lease.inode,
    );
    await assertParentUnchanged(auditPath);
    await unlink(auditPath.lockPath);
  } finally {
    await lease.handle.close();
  }
  await syncDirectory(auditPath.parent);
  await assertParentUnchanged(auditPath);
}

async function openAuditFile(
  auditPath: AuditPath,
  create: boolean,
): Promise<FileHandle> {
  let expected;
  try {
    expected = await lstat(auditPath.path);
  } catch (error) {
    if (!isNodeError(error) || error.code !== "ENOENT" || !create) throw error;
    const handle = await open(
      auditPath.path,
      constants.O_CREAT |
        constants.O_EXCL |
        constants.O_RDWR |
        constants.O_APPEND |
        constants.O_NOFOLLOW,
      0o600,
    );
    try {
      await handle.chmod(0o600);
      assertAuditFileMetadata(await handle.stat());
      return handle;
    } catch (error) {
      await handle.close();
      throw error;
    }
  }
  assertAuditFileMetadata(expected);
  const flags = create
    ? constants.O_RDWR | constants.O_APPEND | constants.O_NOFOLLOW
    : constants.O_RDONLY | constants.O_NOFOLLOW;
  const handle = await open(auditPath.path, flags);
  try {
    const actual = await handle.stat();
    assertAuditFileMetadata(actual);
    if (actual.dev !== expected.dev || actual.ino !== expected.ino)
      throw new SecurityError("AUDIT_PATH_CHANGED");
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function readAndVerify(handle: FileHandle): Promise<AuditHead> {
  const before = await handle.stat();
  assertAuditFileMetadata(before);
  if (!Number.isSafeInteger(before.size) || before.size > MAX_AUDIT_LOG_BYTES)
    throw new SecurityError("AUDIT_LOG_TOO_LARGE");
  const bytes = await handle.readFile();
  const after = await handle.stat();
  assertAuditFileMetadata(after);
  if (
    after.size !== before.size ||
    bytes.byteLength !== before.size ||
    bytes.byteLength > MAX_AUDIT_LOG_BYTES
  )
    throw new SecurityError("AUDIT_CONCURRENT_MUTATION");
  let source: string;
  try {
    source = decoder.decode(bytes);
  } catch {
    throw new SecurityError("AUDIT_ENCODING_INVALID");
  }
  if (source.length === 0)
    return Object.freeze({ entries: 0, lastHash: GENESIS, bytes: 0 });
  if (!source.endsWith("\n")) throw new SecurityError("AUDIT_PARTIAL_RECORD");
  const lines = source.slice(0, -1).split("\n");
  if (
    lines.length > MAX_AUDIT_LOG_ENTRIES ||
    lines.some(
      (line) =>
        line.length === 0 ||
        line.includes("\r") ||
        Buffer.byteLength(line, "utf8") + 1 > MAX_AUDIT_RECORD_BYTES,
    )
  )
    throw new SecurityError("AUDIT_FORMAT_INVALID");
  let previousHash = GENESIS;
  for (let sequence = 0; sequence < lines.length; sequence += 1) {
    const line = lines[sequence];
    if (line === undefined) throw new SecurityError("AUDIT_CHAIN_INVALID");
    let value: unknown;
    try {
      value = JSON.parse(line) as unknown;
    } catch {
      throw new SecurityError("AUDIT_JSON_INVALID");
    }
    const record = normalizeRecord(value);
    if (canonicalJson(record) !== line)
      throw new SecurityError("AUDIT_CANONICAL_JSON_REQUIRED");
    if (record.sequence !== sequence || record.previousHash !== previousHash)
      throw new SecurityError("AUDIT_CHAIN_INVALID");
    const base = freezeAuditBase(record, record.sequence, record.previousHash);
    if (sha256(canonicalJson(base)) !== record.hash)
      throw new SecurityError("AUDIT_CHAIN_INVALID");
    previousHash = record.hash;
  }
  return Object.freeze({
    entries: lines.length,
    lastHash: previousHash,
    bytes: bytes.byteLength,
  });
}

function normalizePayload(value: unknown): Readonly<AuditPayload> {
  const descriptors = exactDataDescriptors(
    value,
    REQUIRED_PAYLOAD_KEYS,
    OPTIONAL_PAYLOAD_KEYS,
    "AUDIT_PAYLOAD_INVALID",
  );
  const timestamp = descriptorString(
    descriptors,
    "timestamp",
    "AUDIT_PAYLOAD_INVALID",
  );
  const action = descriptorString(
    descriptors,
    "action",
    "AUDIT_PAYLOAD_INVALID",
  );
  const decision = descriptorString(
    descriptors,
    "decision",
    "AUDIT_PAYLOAD_INVALID",
  );
  const reasonCode = descriptorString(
    descriptors,
    "reasonCode",
    "AUDIT_PAYLOAD_INVALID",
  );
  const policyHash = descriptorString(
    descriptors,
    "policyHash",
    "AUDIT_PAYLOAD_INVALID",
  );
  validateTimestamp(timestamp);
  for (const item of [action, decision, reasonCode])
    if (!SAFE_REQUIRED.test(item))
      throw new SecurityError("AUDIT_VALUE_INVALID");
  if (!SHA256_HEX.test(policyHash))
    throw new SecurityError("AUDIT_POLICY_HASH_INVALID");
  const assetRef = optionalDescriptorString(descriptors, "assetRef");
  const accountRef = optionalDescriptorString(descriptors, "accountRef");
  for (const item of [assetRef, accountRef])
    if (item !== undefined && !SAFE_REQUIRED.test(item))
      throw new SecurityError("AUDIT_VALUE_INVALID");
  return Object.freeze({
    timestamp,
    action,
    decision,
    reasonCode,
    policyHash,
    ...(assetRef === undefined ? {} : { assetRef }),
    ...(accountRef === undefined ? {} : { accountRef }),
  });
}

function normalizeRecord(value: unknown): Readonly<AuditRecord> {
  const descriptors = exactDataDescriptors(
    value,
    [...REQUIRED_PAYLOAD_KEYS, "hash", "previousHash", "sequence"],
    OPTIONAL_PAYLOAD_KEYS,
    "AUDIT_RECORD_INVALID",
  );
  const payload = normalizePayload(
    Object.freeze({
      timestamp: descriptorString(descriptors, "timestamp"),
      action: descriptorString(descriptors, "action"),
      decision: descriptorString(descriptors, "decision"),
      reasonCode: descriptorString(descriptors, "reasonCode"),
      policyHash: descriptorString(descriptors, "policyHash"),
      ...(descriptors["assetRef"] === undefined
        ? {}
        : { assetRef: descriptorString(descriptors, "assetRef") }),
      ...(descriptors["accountRef"] === undefined
        ? {}
        : { accountRef: descriptorString(descriptors, "accountRef") }),
    }),
  );
  const sequence = descriptorNumber(descriptors, "sequence");
  const previousHash = descriptorString(descriptors, "previousHash");
  const hash = descriptorString(descriptors, "hash");
  if (
    !Number.isSafeInteger(sequence) ||
    sequence < 0 ||
    !SHA256_HEX.test(previousHash) ||
    !SHA256_HEX.test(hash)
  )
    throw new SecurityError("AUDIT_RECORD_INVALID");
  return Object.freeze({ ...payload, sequence, previousHash, hash });
}

function freezeAuditBase(
  payload: Readonly<AuditPayload>,
  sequence: number,
  previousHash: string,
): Readonly<
  AuditPayload & { readonly sequence: number; readonly previousHash: string }
> {
  return Object.freeze({
    timestamp: payload.timestamp,
    action: payload.action,
    decision: payload.decision,
    reasonCode: payload.reasonCode,
    policyHash: payload.policyHash,
    ...(payload.assetRef === undefined ? {} : { assetRef: payload.assetRef }),
    ...(payload.accountRef === undefined
      ? {}
      : { accountRef: payload.accountRef }),
    sequence,
    previousHash,
  });
}

function exactDataDescriptors(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  code: string,
): Readonly<Record<string, PropertyDescriptor>> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype
  )
    throw new SecurityError(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some((key) => typeof key !== "string") ||
    required.some((key) => descriptors[key] === undefined) ||
    keys.some(
      (key) =>
        typeof key !== "string" ||
        (!required.includes(key) && !optional.includes(key)),
    ) ||
    keys.length < required.length ||
    keys.length > required.length + optional.length
  )
    throw new SecurityError(code);
  for (const descriptor of Object.values(descriptors))
    if (!("value" in descriptor) || descriptor.enumerable !== true)
      throw new SecurityError(code);
  return descriptors;
}

function descriptorString(
  descriptors: Readonly<Record<string, PropertyDescriptor>>,
  key: string,
  code = "AUDIT_RECORD_INVALID",
): string {
  const descriptor = descriptors[key];
  if (descriptor === undefined || typeof descriptor.value !== "string")
    throw new SecurityError(code);
  return descriptor.value;
}

function optionalDescriptorString(
  descriptors: Readonly<Record<string, PropertyDescriptor>>,
  key: string,
): string | undefined {
  const descriptor = descriptors[key];
  if (descriptor === undefined) return undefined;
  if (typeof descriptor.value !== "string")
    throw new SecurityError("AUDIT_PAYLOAD_INVALID");
  return descriptor.value;
}

function descriptorNumber(
  descriptors: Readonly<Record<string, PropertyDescriptor>>,
  key: string,
): number {
  const descriptor = descriptors[key];
  if (descriptor === undefined || typeof descriptor.value !== "number")
    throw new SecurityError("AUDIT_RECORD_INVALID");
  return descriptor.value;
}

function validateTimestamp(value: string): void {
  if (!TIMESTAMP.test(value))
    throw new SecurityError("AUDIT_TIMESTAMP_INVALID");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds))
    throw new SecurityError("AUDIT_TIMESTAMP_INVALID");
  const canonical = new Date(milliseconds).toISOString();
  if (canonical !== value && canonical.replace(/\.000Z$/u, "Z") !== value)
    throw new SecurityError("AUDIT_TIMESTAMP_INVALID");
}

async function appendFully(
  handle: FileHandle,
  value: Uint8Array,
): Promise<void> {
  let offset = 0;
  while (offset < value.byteLength) {
    const result = await handle.write(
      value,
      offset,
      value.byteLength - offset,
      null,
    );
    if (result.bytesWritten <= 0) throw new SecurityError("AUDIT_WRITE_FAILED");
    offset += result.bytesWritten;
  }
}

function assertAuditFileMetadata(metadata: {
  readonly mode: number;
  readonly nlink: number;
  readonly uid: number;
  readonly size: number;
  isFile(): boolean;
  isSymbolicLink(): boolean;
}): void {
  if (
    metadata.isSymbolicLink() ||
    !metadata.isFile() ||
    metadata.nlink !== 1 ||
    (metadata.mode & 0o777) !== 0o600 ||
    !ownedByCurrentUser(metadata.uid) ||
    !Number.isSafeInteger(metadata.size) ||
    metadata.size < 0
  )
    throw new SecurityError("AUDIT_FILE_INVALID");
}

function assertLockMetadata(
  metadata: {
    readonly mode: number;
    readonly nlink: number;
    readonly uid: number;
    readonly size: number;
    isFile(): boolean;
    isSymbolicLink(): boolean;
  },
  allowEmpty: boolean,
): void {
  if (
    metadata.isSymbolicLink() ||
    !metadata.isFile() ||
    metadata.nlink !== 1 ||
    (metadata.mode & 0o777) !== 0o600 ||
    !ownedByCurrentUser(metadata.uid) ||
    !Number.isSafeInteger(metadata.size) ||
    metadata.size < (allowEmpty ? 0 : 1) ||
    metadata.size > MAX_AUDIT_LOCK_BYTES
  )
    throw new SecurityError("AUDIT_MUTATION_LEASE_INVALID");
}

async function assertPathMatchesHandle(
  path: string,
  expectedDevice?: number,
  expectedInode?: number,
  handle?: FileHandle,
): Promise<void> {
  let device = expectedDevice;
  let inode = expectedInode;
  if (handle !== undefined) {
    const metadata = await handle.stat();
    assertAuditFileMetadata(metadata);
    device = metadata.dev;
    inode = metadata.ino;
  }
  const pathMetadata = await lstat(path);
  if (
    pathMetadata.isSymbolicLink() ||
    device === undefined ||
    inode === undefined ||
    pathMetadata.dev !== device ||
    pathMetadata.ino !== inode
  )
    throw new SecurityError("AUDIT_PATH_CHANGED");
}

async function assertParentUnchanged(auditPath: AuditPath): Promise<void> {
  const metadata = await lstat(auditPath.parent);
  let canonicalParent: string;
  try {
    canonicalParent = await realpath(auditPath.parent);
  } catch {
    throw new SecurityError("AUDIT_PARENT_CHANGED");
  }
  if (
    metadata.isSymbolicLink() ||
    !metadata.isDirectory() ||
    canonicalParent !== auditPath.parent ||
    (metadata.mode & 0o777) !== 0o700 ||
    !ownedByCurrentUser(metadata.uid) ||
    metadata.dev !== auditPath.parentDevice ||
    metadata.ino !== auditPath.parentInode
  )
    throw new SecurityError("AUDIT_PARENT_CHANGED");
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function ownedByCurrentUser(uid: number): boolean {
  if (typeof process.getuid !== "function")
    throw new SecurityError("AUDIT_OWNER_CHECK_UNAVAILABLE");
  return uid === process.getuid();
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

Object.freeze(AuditLog.prototype);
Object.freeze(AuditLog);
