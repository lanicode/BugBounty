import { execFile, spawn } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  realpath,
  rename,
  unlink,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { types } from "node:util";
import { sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import type { SecretStore } from "./store.js";

export const CORE_EVENT_KEY_REFERENCE =
  "keychain://bugbounty-copilot/event-store-v1";
export const CORE_OPERATOR_KEY_REFERENCE =
  "keychain://bugbounty-copilot/operator-ed25519-v1";

const EVENT_KEY_BYTES = 32;
const OPERATOR_KEY_BYTES = 48;
const MAX_OPERATOR_ID_BYTES = 128;
const MAX_HELPER_OUTPUT_BYTES = 256;
const HELPER_TIMEOUT_MS = 10_000;
const HELPER_SOURCE_MAX_BYTES = 1_048_576;
const HELPER_BINARY_MAX_BYTES = 4_194_304;
const HELPER_DIGEST_MAX_BYTES = 256;
const SAFE_OPERATOR_ID = /^[A-Za-z0-9._@-]{1,128}$/u;
const RECEIPT_MAGIC = Object.freeze([
  0x42, 0x42, 0x43, 0x4f, 0x52, 0x45, 0x52, 0x31,
]);
const INPUT_MAGIC = Object.freeze([
  0x42, 0x42, 0x43, 0x4f, 0x52, 0x45, 0x50, 0x31,
]);

export type CoreKeychainStatus =
  | "absent"
  | "conflict"
  | "fresh_bundle"
  | "legacy_complete"
  | "legacy_direct_complete"
  | "legacy_ready";

export interface CoreKeychainReceipt {
  readonly version: 1;
  readonly mode: "fresh_bundle" | "legacy_complete";
  readonly operatorId: string;
  readonly initialEventKeyVersion: 1;
  readonly operatorKeyRevision: 1;
  readonly generation: string;
}

export interface CoreKeychainInspection {
  readonly status: CoreKeychainStatus;
  readonly receipt: CoreKeychainReceipt | null;
}

/**
 * The integration layer must bind this probe to the real dashboard event
 * directory and the current ControlPlaneStore. Booleans supplied in a request
 * are deliberately not accepted by the provisioning API.
 */
export interface CoreProvisioningStateProbe {
  readonly eventStoreDirectory: string;
  hasOperatorCredential(): Promise<boolean> | boolean;
}

export type CoreKeychainHelperOperation =
  | "complete-legacy"
  | "inspect"
  | "provision-fresh"
  | "read-event"
  | "read-operator";

export interface CoreKeychainHelperRunner {
  execute(
    operation: CoreKeychainHelperOperation,
    input?: Uint8Array,
  ): Promise<Uint8Array>;
}

export class MacOSCoreKeychainBackend implements SecretStore {
  public constructor(
    private readonly platform: NodeJS.Platform = process.platform,
    private readonly runner: CoreKeychainHelperRunner = new SpawnCoreKeychainHelperRunner(),
  ) {
    Object.freeze(this);
  }

  public async inspect(): Promise<CoreKeychainInspection> {
    this.assertAvailable();
    let output: Uint8Array | undefined;
    try {
      output = await this.runner.execute("inspect");
      return parseInspection(output);
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("CORE_KEYCHAIN_INSPECTION_FAILED");
    } finally {
      output?.fill(0);
    }
  }

  public async provisionFresh(
    operatorId: string,
    state: CoreProvisioningStateProbe,
  ): Promise<CoreKeychainReceipt> {
    return this.provision("provision-fresh", "absent", operatorId, state);
  }

  public async completeLegacy(
    operatorId: string,
    state: CoreProvisioningStateProbe,
  ): Promise<CoreKeychainReceipt> {
    return this.provision("complete-legacy", "legacy_ready", operatorId, state);
  }

  /**
   * Performs the same non-mutating filesystem and control-plane checks used
   * immediately before and after provisioning. Dashboard projections use this
   * to avoid advertising an action that the mutation boundary would reject.
   */
  public async assertProvisioningPreconditions(
    state: CoreProvisioningStateProbe,
  ): Promise<void> {
    this.assertAvailable();
    await assertProvisioningState(state);
  }

  public async get(reference: string): Promise<Uint8Array> {
    this.assertAvailable();
    const operation =
      reference === CORE_EVENT_KEY_REFERENCE
        ? ("read-event" as const)
        : reference === CORE_OPERATOR_KEY_REFERENCE
          ? ("read-operator" as const)
          : undefined;
    if (operation === undefined)
      throw new SecurityError("CORE_KEYCHAIN_REFERENCE_INVALID");
    let output: Uint8Array | undefined;
    try {
      output = await this.runner.execute(operation);
      const expectedBytes =
        operation === "read-event" ? EVENT_KEY_BYTES : OPERATOR_KEY_BYTES;
      if (
        types.isProxy(output) ||
        Object.getPrototypeOf(output) !== Uint8Array.prototype ||
        Object.hasOwn(output, "fill") ||
        output.byteLength !== expectedBytes
      )
        throw new Error("invalid");
      const result = Uint8Array.from(output);
      output.fill(0);
      output = undefined;
      return result;
    } catch {
      throw new SecurityError("CORE_KEYCHAIN_READ_FAILED");
    } finally {
      output?.fill(0);
    }
  }

  private async provision(
    operation: "complete-legacy" | "provision-fresh",
    expectedBefore: "absent" | "legacy_ready",
    operatorId: string,
    state: CoreProvisioningStateProbe,
  ): Promise<CoreKeychainReceipt> {
    this.assertAvailable();
    const normalizedOperatorId = validateOperatorId(operatorId);
    await assertProvisioningState(state);
    const before = await this.inspect();
    if (before.status !== expectedBefore)
      throw new SecurityError("CORE_KEYCHAIN_PROVISIONING_CONFLICT");

    let frame: Uint8Array | undefined;
    let output: Uint8Array | undefined;
    try {
      frame = createProvisioningFrame(normalizedOperatorId);
      output = await this.runner.execute(operation, frame);
      const inspection = parseInspection(output);
      const expectedAfter =
        operation === "provision-fresh" ? "fresh_bundle" : "legacy_complete";
      const receipt = inspection.receipt;
      if (
        inspection.status !== expectedAfter ||
        receipt?.operatorId !== normalizedOperatorId
      )
        throw new SecurityError("CORE_KEYCHAIN_PROVISIONING_FAILED");
      await assertProvisioningState(state);
      return receipt;
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("CORE_KEYCHAIN_PROVISIONING_FAILED");
    } finally {
      frame?.fill(0);
      output?.fill(0);
    }
  }

  private assertAvailable(): void {
    if (this.platform !== "darwin")
      throw new SecurityError("CORE_KEYCHAIN_UNAVAILABLE");
  }
}

export interface CoreKeychainHelperProcess {
  onStdoutData(listener: (chunk: unknown) => void): void;
  onStderrData(listener: (chunk: unknown) => void): void;
  onStdinError(listener: () => void): void;
  onError(listener: () => void): void;
  onClose(
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): void;
  writeInput(input: Uint8Array | undefined): void;
  removeAllListeners(): void;
  kill(): void;
}

export type CoreKeychainHelperProcessFactory = (
  binaryPath: string,
  operation: CoreKeychainHelperOperation,
) => CoreKeychainHelperProcess;

export type CoreKeychainHelperBinaryProvider = () => Promise<string>;

export class SpawnCoreKeychainHelperRunner implements CoreKeychainHelperRunner {
  public constructor(
    private readonly binaryProvider: CoreKeychainHelperBinaryProvider = ensureCoreKeychainHelper,
    private readonly processFactory: CoreKeychainHelperProcessFactory = spawnCoreKeychainHelperProcess,
  ) {
    Object.freeze(this);
  }

  public async execute(
    operation: CoreKeychainHelperOperation,
    input?: Uint8Array,
  ): Promise<Uint8Array> {
    const expectsInput =
      operation === "provision-fresh" || operation === "complete-legacy";
    if (
      !isHelperOperation(operation) ||
      (expectsInput && (input === undefined || !validInputFrame(input))) ||
      (!expectsInput && input !== undefined)
    )
      throw new SecurityError("CORE_KEYCHAIN_HELPER_FAILED");
    let binaryPath: string;
    try {
      binaryPath = await this.binaryProvider();
    } catch {
      throw new SecurityError("CORE_KEYCHAIN_HELPER_FAILED");
    }
    return runCoreKeychainHelper(
      binaryPath,
      operation,
      input,
      this.processFactory,
    );
  }
}

function runCoreKeychainHelper(
  binaryPath: string,
  operation: CoreKeychainHelperOperation,
  sourceInput: Uint8Array | undefined,
  processFactory: CoreKeychainHelperProcessFactory,
): Promise<Uint8Array> {
  return new Promise((resolvePromise, rejectPromise) => {
    const input =
      sourceInput === undefined ? undefined : Buffer.from(sourceInput);
    let child: CoreKeychainHelperProcess;
    try {
      child = processFactory(binaryPath, operation);
    } catch {
      input?.fill(0);
      rejectPromise(new SecurityError("CORE_KEYCHAIN_HELPER_FAILED"));
      return;
    }
    const stdoutChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let settled = false;
    const finish = (error?: SecurityError): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.removeAllListeners();
      } catch {
        error = new SecurityError("CORE_KEYCHAIN_HELPER_FAILED");
      } finally {
        input?.fill(0);
      }
      let output: Uint8Array | undefined;
      try {
        if (
          error === undefined &&
          (stdoutBytes === 0 || stdoutBytes > MAX_HELPER_OUTPUT_BYTES)
        )
          error = new SecurityError("CORE_KEYCHAIN_HELPER_FAILED");
        if (error === undefined) {
          const joined = Buffer.concat(stdoutChunks, stdoutBytes);
          output = Uint8Array.from(joined);
          joined.fill(0);
        }
      } finally {
        for (const chunk of stdoutChunks) chunk.fill(0);
      }
      if (error === undefined && output !== undefined) resolvePromise(output);
      else {
        output?.fill(0);
        rejectPromise(
          error ?? new SecurityError("CORE_KEYCHAIN_HELPER_FAILED"),
        );
      }
    };
    const fail = (): void => {
      killCoreKeychainHelper(child);
      finish(new SecurityError("CORE_KEYCHAIN_HELPER_FAILED"));
    };
    const timer = setTimeout(() => {
      killCoreKeychainHelper(child);
      finish(new SecurityError("CORE_KEYCHAIN_HELPER_TIMEOUT"));
    }, HELPER_TIMEOUT_MS);
    timer.unref();
    child.onStdoutData((chunk: unknown) => {
      if (!Buffer.isBuffer(chunk)) {
        fail();
        return;
      }
      stdoutBytes += chunk.byteLength;
      stdoutChunks.push(chunk);
      if (stdoutBytes > MAX_HELPER_OUTPUT_BYTES) fail();
    });
    child.onStderrData((chunk: unknown) => {
      if (Buffer.isBuffer(chunk)) chunk.fill(0);
      fail();
    });
    child.onStdinError(fail);
    child.onError(fail);
    child.onClose((code, signal) => {
      if (code === 0 && signal === null) finish();
      else finish(new SecurityError("CORE_KEYCHAIN_HELPER_FAILED"));
    });
    try {
      child.writeInput(input);
    } catch {
      fail();
    }
  });
}

function spawnCoreKeychainHelperProcess(
  binaryPath: string,
  operation: CoreKeychainHelperOperation,
): CoreKeychainHelperProcess {
  const args = helperArguments(operation);
  const child = spawn(binaryPath, args, {
    env: {},
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  return Object.freeze({
    onStdoutData: (listener: (chunk: unknown) => void) => {
      child.stdout.on("data", listener);
    },
    onStderrData: (listener: (chunk: unknown) => void) => {
      child.stderr.on("data", listener);
    },
    onStdinError: (listener: () => void) => {
      child.stdin.once("error", listener);
    },
    onError: (listener: () => void) => {
      child.once("error", listener);
    },
    onClose: (
      listener: (code: number | null, signal: NodeJS.Signals | null) => void,
    ) => {
      child.once("close", listener);
    },
    writeInput: (input: Uint8Array | undefined) => {
      child.stdin.end(input);
    },
    removeAllListeners: () => {
      child.stdout.removeAllListeners();
      child.stderr.removeAllListeners();
      child.stdin.removeAllListeners();
      child.removeAllListeners();
    },
    kill: () => {
      child.kill("SIGKILL");
    },
  });
}

function helperArguments(
  operation: CoreKeychainHelperOperation,
): readonly string[] {
  switch (operation) {
    case "inspect":
      return Object.freeze(["inspect"]);
    case "provision-fresh":
      return Object.freeze(["provision", "fresh"]);
    case "complete-legacy":
      return Object.freeze(["provision", "complete-legacy"]);
    case "read-event":
      return Object.freeze(["read", "event"]);
    case "read-operator":
      return Object.freeze(["read", "operator"]);
  }
}

function isHelperOperation(
  value: unknown,
): value is CoreKeychainHelperOperation {
  return (
    value === "complete-legacy" ||
    value === "inspect" ||
    value === "provision-fresh" ||
    value === "read-event" ||
    value === "read-operator"
  );
}

function killCoreKeychainHelper(child: CoreKeychainHelperProcess): void {
  try {
    child.kill();
  } catch {
    // A concurrently reaped helper is already fail-closed.
  }
}

function createProvisioningFrame(operatorId: string): Uint8Array {
  const encoded = Buffer.from(operatorId, "ascii");
  const frame = new Uint8Array(INPUT_MAGIC.length + 2 + encoded.byteLength);
  try {
    frame.set(INPUT_MAGIC, 0);
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    view.setUint16(INPUT_MAGIC.length, encoded.byteLength, false);
    frame.set(encoded, INPUT_MAGIC.length + 2);
    return frame;
  } finally {
    encoded.fill(0);
  }
}

function validInputFrame(value: Uint8Array): boolean {
  if (
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype ||
    value.byteLength < INPUT_MAGIC.length + 3 ||
    value.byteLength > INPUT_MAGIC.length + 2 + MAX_OPERATOR_ID_BYTES
  )
    return false;
  for (let index = 0; index < INPUT_MAGIC.length; index += 1)
    if (value[index] !== INPUT_MAGIC[index]) return false;
  const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
  const length = view.getUint16(INPUT_MAGIC.length, false);
  if (value.byteLength !== INPUT_MAGIC.length + 2 + length) return false;
  return validOperatorIdBytes(value.subarray(INPUT_MAGIC.length + 2));
}

function parseInspection(value: Uint8Array): CoreKeychainInspection {
  if (
    types.isProxy(value) ||
    Object.getPrototypeOf(value) !== Uint8Array.prototype ||
    value.byteLength < RECEIPT_MAGIC.length + 1 ||
    value.byteLength > MAX_HELPER_OUTPUT_BYTES
  )
    throw new SecurityError("CORE_KEYCHAIN_RECEIPT_INVALID");
  for (let index = 0; index < RECEIPT_MAGIC.length; index += 1)
    if (value[index] !== RECEIPT_MAGIC[index])
      throw new SecurityError("CORE_KEYCHAIN_RECEIPT_INVALID");
  const statusByte = value[RECEIPT_MAGIC.length];
  const status = receiptStatus(statusByte);
  if (status !== "fresh_bundle" && status !== "legacy_complete") {
    if (value.byteLength !== RECEIPT_MAGIC.length + 1)
      throw new SecurityError("CORE_KEYCHAIN_RECEIPT_INVALID");
    return Object.freeze({ status, receipt: null });
  }
  const metadataOffset = RECEIPT_MAGIC.length + 1;
  const operatorLengthOffset = metadataOffset + 16;
  const operatorIdOffset = operatorLengthOffset + 1;
  if (value.byteLength < operatorIdOffset + 1)
    throw new SecurityError("CORE_KEYCHAIN_RECEIPT_INVALID");
  const operatorIdLength = value[operatorLengthOffset];
  if (
    operatorIdLength === undefined ||
    value.byteLength !== operatorIdOffset + operatorIdLength
  )
    throw new SecurityError("CORE_KEYCHAIN_RECEIPT_INVALID");
  const operatorBytes = value.subarray(operatorIdOffset);
  if (!validOperatorIdBytes(operatorBytes))
    throw new SecurityError("CORE_KEYCHAIN_RECEIPT_INVALID");
  const operatorId = Buffer.from(operatorBytes).toString("ascii");
  const generation = Buffer.from(
    value.subarray(metadataOffset, operatorLengthOffset),
  ).toString("base64url");
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

function receiptStatus(value: number | undefined): CoreKeychainStatus {
  switch (value) {
    case 0:
      return "absent";
    case 1:
      return "fresh_bundle";
    case 2:
      return "legacy_complete";
    case 3:
      return "legacy_ready";
    case 4:
      return "conflict";
    case 5:
      return "legacy_direct_complete";
    default:
      throw new SecurityError("CORE_KEYCHAIN_RECEIPT_INVALID");
  }
}

function validateOperatorId(value: unknown): string {
  if (
    typeof value !== "string" ||
    !SAFE_OPERATOR_ID.test(value) ||
    Buffer.byteLength(value, "utf8") > MAX_OPERATOR_ID_BYTES
  )
    throw new SecurityError("CORE_KEYCHAIN_OPERATOR_ID_INVALID");
  return value;
}

function validOperatorIdBytes(value: Uint8Array): boolean {
  if (value.byteLength < 1 || value.byteLength > MAX_OPERATOR_ID_BYTES)
    return false;
  for (const byte of value) {
    const valid =
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2e ||
      byte === 0x5f ||
      byte === 0x40 ||
      byte === 0x2d;
    if (!valid) return false;
  }
  return true;
}

async function assertProvisioningState(state: unknown): Promise<void> {
  try {
    if (typeof state !== "object" || state === null || types.isProxy(state))
      throw new Error("invalid");
    const eventStoreDirectory: unknown = Reflect.get(
      state,
      "eventStoreDirectory",
    );
    const credentialProbe: unknown = Reflect.get(
      state,
      "hasOperatorCredential",
    );
    if (
      typeof eventStoreDirectory !== "string" ||
      !isAbsolute(eventStoreDirectory) ||
      resolve(eventStoreDirectory) !== eventStoreDirectory ||
      typeof credentialProbe !== "function"
    )
      throw new Error("invalid");
    const parent = dirname(eventStoreDirectory);
    const [parentMetadata, canonicalParent] = await Promise.all([
      lstat(parent),
      realpath(parent),
    ]);
    if (
      !parentMetadata.isDirectory() ||
      parentMetadata.isSymbolicLink() ||
      canonicalParent !== parent ||
      (parentMetadata.mode & 0o7777) !== 0o700 ||
      typeof process.getuid !== "function" ||
      parentMetadata.uid !== process.getuid()
    )
      throw new Error("invalid");
    try {
      await lstat(eventStoreDirectory);
      throw new Error("exists");
    } catch (error) {
      if (!isNodeError(error) || error.code !== "ENOENT") throw error;
    }
    const hasCredential: unknown = await Reflect.apply(
      credentialProbe,
      state,
      [],
    );
    if (hasCredential !== false) throw new Error("credential");
  } catch {
    throw new SecurityError("CORE_KEYCHAIN_PROVISIONING_PRECONDITION_FAILED");
  }
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

const HELPER_SOURCE_PATH = fileURLToPath(
  new URL("./native/macos-core-keychain-helper.c", import.meta.url),
);
const HELPER_DIRECTORY_PATH = fileURLToPath(
  new URL("../../.local/native/", import.meta.url),
);
const HELPER_BINARY_PATH = fileURLToPath(
  new URL("../../.local/native/core-keychain-helper-v1", import.meta.url),
);
const HELPER_DIGEST_PATH = `${HELPER_BINARY_PATH}.sha256`;
let helperBuild: Promise<string> | undefined;

export async function prepareMacOSCoreKeychainHelper(
  platform: NodeJS.Platform = process.platform,
): Promise<void> {
  if (platform !== "darwin")
    throw new SecurityError("CORE_KEYCHAIN_HELPER_FAILED");
  await ensureCoreKeychainHelper();
}

function ensureCoreKeychainHelper(): Promise<string> {
  if (helperBuild !== undefined) return helperBuild;
  const current = buildCoreKeychainHelper();
  helperBuild = current;
  return current.finally(() => {
    if (helperBuild === current) helperBuild = undefined;
  });
}

async function buildCoreKeychainHelper(): Promise<string> {
  if (process.platform !== "darwin" || typeof process.getuid !== "function")
    throw new SecurityError("CORE_KEYCHAIN_HELPER_FAILED");
  const source = await readPrivateFile(
    HELPER_SOURCE_PATH,
    undefined,
    HELPER_SOURCE_MAX_BYTES,
  );
  const sourceDigest = sha256(source);
  const suffix = `${String(process.pid)}-${cryptoRandomSuffix()}`;
  const temporarySource = `${HELPER_BINARY_PATH}.${suffix}.c`;
  const temporaryBinary = `${HELPER_BINARY_PATH}.${suffix}.tmp`;
  const temporaryDigest = `${HELPER_DIGEST_PATH}.${suffix}.tmp`;
  try {
    await preparePrivateHelperDirectory();
    if (await trustedHelperBinary(sourceDigest)) return HELPER_BINARY_PATH;
    await writeFile(temporarySource, source, { flag: "wx", mode: 0o600 });
    await compileCoreKeychainHelper(temporarySource, temporaryBinary);
    await chmod(temporaryBinary, 0o700);
    const binary = await readPrivateFile(
      temporaryBinary,
      0o700,
      HELPER_BINARY_MAX_BYTES,
    );
    const binaryDigest = sha256(binary);
    binary.fill(0);
    await writeFile(temporaryDigest, `${sourceDigest}\n${binaryDigest}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await rename(temporaryBinary, HELPER_BINARY_PATH);
    await rename(temporaryDigest, HELPER_DIGEST_PATH);
    if (!(await trustedHelperBinary(sourceDigest)))
      throw new Error("untrusted");
    return HELPER_BINARY_PATH;
  } catch {
    throw new SecurityError("CORE_KEYCHAIN_HELPER_FAILED");
  } finally {
    source.fill(0);
    await Promise.allSettled([
      unlink(temporarySource),
      unlink(temporaryBinary),
      unlink(temporaryDigest),
    ]);
  }
}

function cryptoRandomSuffix(): string {
  const values = new Uint32Array(2);
  globalThis.crypto.getRandomValues(values);
  return [...values]
    .map((value) => value.toString(16).padStart(8, "0"))
    .join("");
}

async function preparePrivateHelperDirectory(): Promise<void> {
  await mkdir(HELPER_DIRECTORY_PATH, { recursive: true, mode: 0o700 });
  const metadata = await lstat(HELPER_DIRECTORY_PATH);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== process.getuid?.() ||
    (metadata.mode & 0o7777) !== 0o700
  )
    throw new SecurityError("CORE_KEYCHAIN_HELPER_FAILED");
}

async function trustedHelperBinary(sourceDigest: string): Promise<boolean> {
  let binary: Buffer | undefined;
  let digest: Buffer | undefined;
  try {
    [binary, digest] = await Promise.all([
      readPrivateFile(HELPER_BINARY_PATH, 0o700, HELPER_BINARY_MAX_BYTES),
      readPrivateFile(HELPER_DIGEST_PATH, 0o600, HELPER_DIGEST_MAX_BYTES),
    ]);
    return digest.toString("utf8") === `${sourceDigest}\n${sha256(binary)}\n`;
  } catch {
    return false;
  } finally {
    binary?.fill(0);
    digest?.fill(0);
  }
}

async function readPrivateFile(
  path: string,
  expectedMode: number | undefined,
  maximumBytes: number,
): Promise<Buffer> {
  const handle = await open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  try {
    const metadata = await handle.stat();
    if (
      !metadata.isFile() ||
      metadata.nlink !== 1 ||
      metadata.uid !== process.getuid?.() ||
      (metadata.mode & 0o022) !== 0 ||
      (expectedMode !== undefined &&
        (metadata.mode & 0o777) !== expectedMode) ||
      metadata.size < 1 ||
      metadata.size > maximumBytes
    )
      throw new SecurityError("CORE_KEYCHAIN_HELPER_FAILED");
    const contents = await handle.readFile();
    if (contents.byteLength !== metadata.size) {
      contents.fill(0);
      throw new SecurityError("CORE_KEYCHAIN_HELPER_FAILED");
    }
    return contents;
  } finally {
    await handle.close();
  }
}

function compileCoreKeychainHelper(
  sourcePath: string,
  outputPath: string,
): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    execFile(
      "/usr/bin/xcrun",
      [
        "clang",
        "-std=c17",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-deprecated-declarations",
        sourcePath,
        "-framework",
        "Security",
        "-framework",
        "CoreFoundation",
        "-o",
        outputPath,
      ],
      {
        encoding: "buffer",
        env: { PATH: "/usr/bin:/bin", TMPDIR: HELPER_DIRECTORY_PATH },
        maxBuffer: 4_096,
        timeout: 30_000,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        if (Buffer.isBuffer(stdout)) stdout.fill(0);
        if (Buffer.isBuffer(stderr)) stderr.fill(0);
        if (error === null) resolvePromise();
        else rejectPromise(new SecurityError("CORE_KEYCHAIN_HELPER_FAILED"));
      },
    );
  });
}
