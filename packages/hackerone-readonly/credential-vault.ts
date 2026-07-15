import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
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
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import type { SecretStore } from "../secret-store/index.js";
import {
  HACKERONE_IDENTIFIER_REFERENCE,
  HACKERONE_TOKEN_REFERENCE,
} from "./types.js";

const MAX_KEYCHAIN_ENVELOPE_BYTES = 4_095;
const MAX_KEYCHAIN_HELPER_OUTPUT_BYTES = MAX_KEYCHAIN_ENVELOPE_BYTES;
const KEYCHAIN_HELPER_TIMEOUT_MS = 10_000;
const MAX_KEYCHAIN_HELPER_BINARY_BYTES = 4 * 1_024 * 1_024;
const MAX_KEYCHAIN_HELPER_DIGEST_BYTES = 256;
const MAX_KEYCHAIN_HELPER_SOURCE_BYTES = 1 * 1_024 * 1_024;
const ISOLATED_HELPER_DIRECTORY =
  /^bugbounty-helper-build-test-[A-Za-z0-9]{6}$/u;
const PAIR_ENVELOPE_PREFIX = Object.freeze([
  0x42, 0x42, 0x43, 0x2d, 0x48, 0x31, 0x2d, 0x43, 0x52, 0x45, 0x44, 0x2d, 0x56,
  0x31, 0x2e,
]);
const PAIR_GENERATION_BYTES = 16;
const PAIR_GENERATION_BASE64URL_BYTES = 22;
const PAIR_ENVELOPE_ROLE_OFFSET = PAIR_ENVELOPE_PREFIX.length;
const PAIR_ENVELOPE_ROLE_SEPARATOR_OFFSET = PAIR_ENVELOPE_ROLE_OFFSET + 1;
const PAIR_ENVELOPE_GENERATION_OFFSET = PAIR_ENVELOPE_ROLE_SEPARATOR_OFFSET + 1;
const PAIR_ENVELOPE_SECRET_SEPARATOR_OFFSET =
  PAIR_ENVELOPE_GENERATION_OFFSET + PAIR_GENERATION_BASE64URL_BYTES;
const PAIR_ENVELOPE_SECRET_OFFSET = PAIR_ENVELOPE_SECRET_SEPARATOR_OFFSET + 1;
const MAX_SECRET_BYTES = Math.floor(
  ((MAX_KEYCHAIN_ENVELOPE_BYTES - PAIR_ENVELOPE_SECRET_OFFSET) * 3) / 4,
);
const FULL_DIGEST = /^[0-9a-f]{64}$/u;

type CredentialRole = "identifier" | "token";

interface ParsedCredentialEnvelope {
  readonly generation: Uint8Array;
  readonly secret: Uint8Array;
}

interface TrustedCredentialLease {
  readonly identifier: Uint8Array;
  readonly identifierDigest: string;
  readonly token: Uint8Array;
  readonly tokenBindingDigest: string;
}

const trustedCredentialLeases = new WeakMap<object, TrustedCredentialLease>();

export interface HackerOneCredentialPair {
  readonly identifier: Uint8Array;
  readonly token: Uint8Array;
}

export interface HackerOneCredentialPresence {
  readonly identifierPresent: boolean;
  readonly tokenPresent: boolean;
  readonly tokenFingerprint: string | null;
  readonly tokenBindingDigest: string | null;
  readonly secretStoreAvailable: boolean;
}

export interface HackerOneKeychainMutationBackend {
  storeIdentifier(value: Uint8Array): Promise<void>;
  storeToken(value: Uint8Array): Promise<void>;
  deleteIdentifier(): Promise<void>;
  deleteToken(): Promise<void>;
}

export interface HackerOneCredentialAccess {
  probe(): Promise<HackerOneCredentialPresence>;
  load(): Promise<HackerOneCredentialPair>;
  store(identifier: string, token: string): Promise<string>;
  storeBytes(identifier: Uint8Array, token: Uint8Array): Promise<string>;
  remove(): Promise<void>;
}

export function consumeHackerOneCredentialLease(
  pair: HackerOneCredentialPair,
  expectedTokenBindingDigest: string,
): void {
  const lease = trustedCredentialLeases.get(pair);
  trustedCredentialLeases.delete(pair);
  try {
    if (
      lease === undefined ||
      !FULL_DIGEST.test(expectedTokenBindingDigest) ||
      pair.identifier !== lease.identifier ||
      pair.token !== lease.token ||
      !validCredentialBytes(pair.identifier) ||
      !validCredentialBytes(pair.token) ||
      !sameDigest(
        credentialBindingDigest(pair.identifier),
        lease.identifierDigest,
      ) ||
      !sameDigest(
        credentialBindingDigest(pair.token),
        lease.tokenBindingDigest,
      ) ||
      !sameDigest(lease.tokenBindingDigest, expectedTokenBindingDigest)
    )
      throw new Error("invalid");
  } catch {
    if (lease !== undefined) {
      lease.identifier.fill(0);
      lease.token.fill(0);
    }
    throw new SecurityError("HACKERONE_CREDENTIAL_LEASE_INVALID");
  }
}

export class HackerOneCredentialVault implements HackerOneCredentialAccess {
  public constructor(
    private readonly secrets: SecretStore,
    private readonly mutations: HackerOneKeychainMutationBackend,
  ) {
    Object.freeze(this);
  }

  public async probe(): Promise<HackerOneCredentialPresence> {
    let identifierEnvelope: Uint8Array | undefined;
    let tokenEnvelope: Uint8Array | undefined;
    let identifier: ParsedCredentialEnvelope | undefined;
    let token: ParsedCredentialEnvelope | undefined;
    let tokenFingerprint: string | null = null;
    let tokenBindingDigest: string | null = null;
    let successfulReads = 0;
    try {
      identifierEnvelope = await this.secrets.get(
        HACKERONE_IDENTIFIER_REFERENCE,
      );
      successfulReads += 1;
    } catch {
      // A partial pair is deliberately indistinguishable from no credentials.
    }
    try {
      tokenEnvelope = await this.secrets.get(HACKERONE_TOKEN_REFERENCE);
      successfulReads += 1;
    } catch {
      // A partial pair is deliberately indistinguishable from no credentials.
    }

    let pairPresent = false;
    try {
      if (identifierEnvelope !== undefined && tokenEnvelope !== undefined) {
        identifier = parseCredentialEnvelope(identifierEnvelope, "identifier");
        token = parseCredentialEnvelope(tokenEnvelope, "token");
        if (sameGeneration(identifier.generation, token.generation)) {
          pairPresent = true;
          tokenBindingDigest = credentialBindingDigest(token.secret);
          tokenFingerprint = tokenBindingDigest.slice(0, 12);
        }
      }
    } catch {
      pairPresent = false;
      tokenFingerprint = null;
      tokenBindingDigest = null;
    } finally {
      identifierEnvelope?.fill(0);
      tokenEnvelope?.fill(0);
      identifier?.generation.fill(0);
      identifier?.secret.fill(0);
      token?.generation.fill(0);
      token?.secret.fill(0);
    }
    return Object.freeze({
      identifierPresent: pairPresent,
      tokenPresent: pairPresent,
      tokenFingerprint,
      tokenBindingDigest,
      secretStoreAvailable: successfulReads > 0,
    });
  }

  public async load(): Promise<HackerOneCredentialPair> {
    let identifierEnvelope: Uint8Array | undefined;
    let tokenEnvelope: Uint8Array | undefined;
    let identifier: ParsedCredentialEnvelope | undefined;
    let token: ParsedCredentialEnvelope | undefined;
    let loaded = false;
    try {
      identifierEnvelope = await this.secrets.get(
        HACKERONE_IDENTIFIER_REFERENCE,
      );
      tokenEnvelope = await this.secrets.get(HACKERONE_TOKEN_REFERENCE);
      identifier = parseCredentialEnvelope(identifierEnvelope, "identifier");
      token = parseCredentialEnvelope(tokenEnvelope, "token");
      if (!sameGeneration(identifier.generation, token.generation))
        throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
      const pair = Object.freeze({
        identifier: identifier.secret,
        token: token.secret,
      });
      trustedCredentialLeases.set(pair, {
        identifier: pair.identifier,
        identifierDigest: credentialBindingDigest(pair.identifier),
        token: pair.token,
        tokenBindingDigest: credentialBindingDigest(pair.token),
      });
      loaded = true;
      return pair;
    } catch {
      throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
    } finally {
      identifierEnvelope?.fill(0);
      tokenEnvelope?.fill(0);
      identifier?.generation.fill(0);
      token?.generation.fill(0);
      if (!loaded) {
        identifier?.secret.fill(0);
        token?.secret.fill(0);
      }
    }
  }

  public async store(
    identifierValue: string,
    tokenValue: string,
  ): Promise<string> {
    const encoder = new TextEncoder();
    let identifier: Uint8Array | undefined;
    let token: Uint8Array | undefined;
    try {
      identifier = encoder.encode(normalizeCredential(identifierValue));
      token = encoder.encode(normalizeCredential(tokenValue));
      return await this.storeCredentialBytes(identifier, token);
    } finally {
      identifier?.fill(0);
      token?.fill(0);
    }
  }

  /**
   * TTY-only administration can keep credentials out of JavaScript strings.
   * The caller retains ownership of its buffers and must erase them itself.
   */
  public async storeBytes(
    identifierValue: Uint8Array,
    tokenValue: Uint8Array,
  ): Promise<string> {
    let identifier: Uint8Array | undefined;
    let token: Uint8Array | undefined;
    try {
      identifier = Uint8Array.from(identifierValue);
      token = Uint8Array.from(tokenValue);
      if (!validCredentialBytes(identifier) || !validCredentialBytes(token))
        throw new SecurityError("HACKERONE_CREDENTIAL_INPUT_INVALID");
      return await this.storeCredentialBytes(identifier, token);
    } finally {
      identifier?.fill(0);
      token?.fill(0);
    }
  }

  private async storeCredentialBytes(
    identifier: Uint8Array,
    token: Uint8Array,
  ): Promise<string> {
    let generation: Uint8Array | undefined;
    let identifierEnvelope: Uint8Array | undefined;
    let tokenEnvelope: Uint8Array | undefined;
    let mutationStarted = false;
    try {
      if (!validSecret(identifier) || !validSecret(token))
        throw new SecurityError("HACKERONE_CREDENTIAL_INPUT_INVALID");

      generation = randomBytes(PAIR_GENERATION_BYTES);
      identifierEnvelope = createCredentialEnvelope(
        "identifier",
        generation,
        identifier,
      );
      tokenEnvelope = createCredentialEnvelope("token", generation, token);
      mutationStarted = true;
      await this.mutations.storeIdentifier(identifierEnvelope);
      await this.mutations.storeToken(tokenEnvelope);
      return await this.verifyPersistedPair(identifier, token, generation);
    } catch (error) {
      if (
        error instanceof SecurityError &&
        error.code === "HACKERONE_CREDENTIAL_INPUT_INVALID"
      )
        throw error;
      if (mutationStarted) await this.deletePair();
      throw new SecurityError("HACKERONE_KEYCHAIN_WRITE_FAILED");
    } finally {
      generation?.fill(0);
      identifierEnvelope?.fill(0);
      tokenEnvelope?.fill(0);
    }
  }

  public async remove(): Promise<void> {
    const results = await this.deletePair();
    if (results.some((result) => result.status === "rejected"))
      throw new SecurityError("HACKERONE_KEYCHAIN_DELETE_FAILED");
  }

  private deletePair(): Promise<readonly PromiseSettledResult<void>[]> {
    return Promise.allSettled([
      Promise.resolve().then(() => this.mutations.deleteIdentifier()),
      Promise.resolve().then(() => this.mutations.deleteToken()),
    ]);
  }

  private async verifyPersistedPair(
    expectedIdentifier: Uint8Array,
    expectedToken: Uint8Array,
    expectedGeneration: Uint8Array,
  ): Promise<string> {
    let identifierEnvelope: Uint8Array | undefined;
    let tokenEnvelope: Uint8Array | undefined;
    let identifier: ParsedCredentialEnvelope | undefined;
    let token: ParsedCredentialEnvelope | undefined;
    try {
      identifierEnvelope = await this.secrets.get(
        HACKERONE_IDENTIFIER_REFERENCE,
      );
      tokenEnvelope = await this.secrets.get(HACKERONE_TOKEN_REFERENCE);
      identifier = parseCredentialEnvelope(identifierEnvelope, "identifier");
      token = parseCredentialEnvelope(tokenEnvelope, "token");
      const identifierDigest = credentialBindingDigest(identifier.secret);
      const expectedIdentifierDigest =
        credentialBindingDigest(expectedIdentifier);
      const tokenDigest = credentialBindingDigest(token.secret);
      const expectedTokenDigest = credentialBindingDigest(expectedToken);
      if (
        !sameGeneration(identifier.generation, expectedGeneration) ||
        !sameGeneration(token.generation, expectedGeneration) ||
        !sameDigest(identifierDigest, expectedIdentifierDigest) ||
        !sameDigest(tokenDigest, expectedTokenDigest)
      )
        throw new Error("invalid");
      return tokenDigest.slice(0, 12);
    } catch {
      throw new SecurityError("HACKERONE_KEYCHAIN_WRITE_FAILED");
    } finally {
      identifierEnvelope?.fill(0);
      tokenEnvelope?.fill(0);
      identifier?.generation.fill(0);
      identifier?.secret.fill(0);
      token?.generation.fill(0);
      token?.secret.fill(0);
    }
  }
}

export type HackerOneKeychainHelperOperation =
  | "delete-identifier"
  | "delete-token"
  | "read-identifier"
  | "read-token"
  | "store-identifier"
  | "store-token";

export interface HackerOneKeychainHelperRunner {
  execute(
    operation: HackerOneKeychainHelperOperation,
    secret?: Uint8Array,
  ): Promise<Uint8Array | undefined>;
}

export class MacOSHackerOneKeychainMutationBackend
  implements HackerOneKeychainMutationBackend, SecretStore
{
  public constructor(
    private readonly platform: NodeJS.Platform = process.platform,
    private readonly runner: HackerOneKeychainHelperRunner = new SpawnHackerOneKeychainHelperRunner(),
  ) {
    Object.freeze(this);
  }

  public async get(reference: string): Promise<Uint8Array> {
    this.assertAvailable();
    const operation =
      reference === HACKERONE_IDENTIFIER_REFERENCE
        ? "read-identifier"
        : reference === HACKERONE_TOKEN_REFERENCE
          ? "read-token"
          : undefined;
    if (operation === undefined)
      throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
    const value = await this.runner.execute(operation);
    if (
      value === undefined ||
      value.byteLength === 0 ||
      value.byteLength > MAX_KEYCHAIN_ENVELOPE_BYTES
    ) {
      value?.fill(0);
      throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
    }
    return value;
  }

  public storeIdentifier(value: Uint8Array): Promise<void> {
    return this.store("store-identifier", "identifier", value);
  }

  public storeToken(value: Uint8Array): Promise<void> {
    return this.store("store-token", "token", value);
  }

  public async deleteIdentifier(): Promise<void> {
    this.assertAvailable();
    await this.runner.execute("delete-identifier");
  }

  public async deleteToken(): Promise<void> {
    this.assertAvailable();
    await this.runner.execute("delete-token");
  }

  private async store(
    operation: "store-identifier" | "store-token",
    role: CredentialRole,
    value: Uint8Array,
  ): Promise<void> {
    this.assertAvailable();
    assertCredentialEnvelope(value, role);
    await this.runner.execute(operation, value);
  }

  private assertAvailable(): void {
    if (this.platform !== "darwin")
      throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
  }
}

export interface HackerOneKeychainHelperProcess {
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

export type HackerOneKeychainHelperProcessFactory = (
  binaryPath: string,
  operation: HackerOneKeychainHelperOperation,
) => HackerOneKeychainHelperProcess;

export type HackerOneKeychainHelperBinaryProvider = () => Promise<string>;

export class SpawnHackerOneKeychainHelperRunner implements HackerOneKeychainHelperRunner {
  public constructor(
    private readonly binaryProvider: HackerOneKeychainHelperBinaryProvider = ensureHackerOneKeychainHelper,
    private readonly processFactory: HackerOneKeychainHelperProcessFactory = spawnKeychainHelperProcess,
  ) {
    Object.freeze(this);
  }

  public async execute(
    operation: HackerOneKeychainHelperOperation,
    secret?: Uint8Array,
  ): Promise<Uint8Array | undefined> {
    const isStore = operation.startsWith("store-");
    const role: CredentialRole = operation.endsWith("-identifier")
      ? "identifier"
      : "token";
    if (
      (isStore &&
        (secret === undefined ||
          secret.byteLength === 0 ||
          secret.byteLength > MAX_KEYCHAIN_ENVELOPE_BYTES ||
          !printableAscii(secret))) ||
      (!isStore && secret !== undefined)
    )
      throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
    if (isStore) {
      try {
        if (secret === undefined) throw new Error("missing");
        assertCredentialEnvelope(secret, role);
      } catch {
        throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
      }
    }
    let binaryPath: string;
    try {
      binaryPath = await this.binaryProvider();
    } catch {
      throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
    }
    return runKeychainHelper(
      binaryPath,
      operation,
      secret,
      this.processFactory,
    );
  }
}

function runKeychainHelper(
  binaryPath: string,
  operation: HackerOneKeychainHelperOperation,
  secret: Uint8Array | undefined,
  processFactory: HackerOneKeychainHelperProcessFactory,
): Promise<Uint8Array | undefined> {
  return new Promise((resolve, reject) => {
    const input = secret === undefined ? undefined : Buffer.from(secret);
    let child: HackerOneKeychainHelperProcess;
    try {
      child = processFactory(binaryPath, operation);
    } catch {
      input?.fill(0);
      reject(new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED"));
      return;
    }
    const stdoutChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let settled = false;
    const expectsOutput = operation.startsWith("read-");
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.removeAllListeners();
      input?.fill(0);
      let output: Uint8Array | undefined;
      try {
        if (error === undefined && expectsOutput) {
          if (
            stdoutBytes === 0 ||
            stdoutBytes > MAX_KEYCHAIN_HELPER_OUTPUT_BYTES
          )
            error = new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
          else {
            const joined = Buffer.concat(stdoutChunks, stdoutBytes);
            output = Uint8Array.from(joined);
            joined.fill(0);
          }
        } else if (error === undefined && stdoutBytes !== 0) {
          error = new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
        }
      } finally {
        for (const chunk of stdoutChunks) chunk.fill(0);
      }
      if (error === undefined) resolve(output);
      else {
        output?.fill(0);
        reject(error);
      }
    };
    const fail = (): void => {
      killHelperChild(child);
      finish(new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED"));
    };
    const timer = setTimeout(() => {
      killHelperChild(child);
      finish(new SecurityError("HACKERONE_KEYCHAIN_HELPER_TIMEOUT"));
    }, KEYCHAIN_HELPER_TIMEOUT_MS);
    timer.unref();
    child.onStdoutData((chunk: unknown) => {
      if (!Buffer.isBuffer(chunk)) {
        fail();
        return;
      }
      stdoutBytes += chunk.byteLength;
      stdoutChunks.push(chunk);
      if (stdoutBytes > MAX_KEYCHAIN_HELPER_OUTPUT_BYTES) fail();
    });
    child.onStderrData((chunk: unknown) => {
      if (Buffer.isBuffer(chunk)) chunk.fill(0);
      fail();
    });
    child.onStdinError(fail);
    child.onError(fail);
    child.onClose((code, signal) => {
      if (code === 0 && signal === null) finish();
      else finish(new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED"));
    });
    try {
      child.writeInput(input);
    } catch {
      fail();
    }
  });
}

function spawnKeychainHelperProcess(
  binaryPath: string,
  operation: HackerOneKeychainHelperOperation,
): HackerOneKeychainHelperProcess {
  const separator = operation.indexOf("-");
  const command = operation.slice(0, separator);
  const role = operation.slice(separator + 1);
  const child = spawn(binaryPath, [command, role], {
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

const KEYCHAIN_HELPER_SOURCE_PATH = fileURLToPath(
  new URL("./native/macos-keychain-helper.c", import.meta.url),
);
const KEYCHAIN_HELPER_DIRECTORY_PATH = fileURLToPath(
  new URL("../../.local/native/", import.meta.url),
);
const KEYCHAIN_HELPER_BINARY_PATH = fileURLToPath(
  new URL("../../.local/native/hackerone-keychain-helper", import.meta.url),
);
const KEYCHAIN_HELPER_DIGEST_PATH = `${KEYCHAIN_HELPER_BINARY_PATH}.sha256`;
export interface HackerOneKeychainHelperBuildLayout {
  readonly sourcePath: string;
  readonly directoryPath: string;
  readonly binaryPath: string;
  readonly digestPath: string;
}

const PRODUCTION_KEYCHAIN_HELPER_LAYOUT: HackerOneKeychainHelperBuildLayout =
  Object.freeze({
    sourcePath: KEYCHAIN_HELPER_SOURCE_PATH,
    directoryPath: KEYCHAIN_HELPER_DIRECTORY_PATH,
    binaryPath: KEYCHAIN_HELPER_BINARY_PATH,
    digestPath: KEYCHAIN_HELPER_DIGEST_PATH,
  });
let keychainHelperBuild: Promise<string> | undefined;

export async function prepareMacOSHackerOneKeychainHelper(
  platform: NodeJS.Platform = process.platform,
  isolatedTestLayout?: HackerOneKeychainHelperBuildLayout,
): Promise<void> {
  if (platform !== "darwin")
    throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
  if (isolatedTestLayout === undefined) await ensureHackerOneKeychainHelper();
  else {
    await assertIsolatedTestBuildLayout(isolatedTestLayout);
    await buildHackerOneKeychainHelper(isolatedTestLayout);
  }
}

async function assertIsolatedTestBuildLayout(
  layout: HackerOneKeychainHelperBuildLayout,
): Promise<void> {
  try {
    if (
      process.env["NODE_ENV"] !== "test" ||
      layout.sourcePath !== KEYCHAIN_HELPER_SOURCE_PATH ||
      !isAbsolute(layout.directoryPath) ||
      resolve(layout.directoryPath) !== layout.directoryPath ||
      layout.binaryPath !==
        join(layout.directoryPath, "hackerone-keychain-helper") ||
      layout.digestPath !== `${layout.binaryPath}.sha256` ||
      !ISOLATED_HELPER_DIRECTORY.test(basename(layout.directoryPath))
    )
      throw new Error("invalid");
    const [canonicalDirectory, canonicalTemporaryRoot] = await Promise.all([
      realpath(layout.directoryPath),
      realpath(tmpdir()),
    ]);
    if (
      canonicalDirectory !== layout.directoryPath ||
      dirname(canonicalDirectory) !== canonicalTemporaryRoot
    )
      throw new Error("invalid");
  } catch {
    throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
  }
}

function ensureHackerOneKeychainHelper(): Promise<string> {
  if (keychainHelperBuild !== undefined) return keychainHelperBuild;
  const currentBuild = buildHackerOneKeychainHelper(
    PRODUCTION_KEYCHAIN_HELPER_LAYOUT,
  );
  keychainHelperBuild = currentBuild;
  return currentBuild.finally(() => {
    if (keychainHelperBuild === currentBuild) keychainHelperBuild = undefined;
  });
}

async function buildHackerOneKeychainHelper(
  layout: HackerOneKeychainHelperBuildLayout,
): Promise<string> {
  if (process.platform !== "darwin" || typeof process.getuid !== "function")
    throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
  const source = await readFixedHelperSource(layout.sourcePath);
  const sourceDigest = sha256(source);
  const suffix = `${String(process.pid)}-${randomBytes(8).toString("hex")}`;
  const temporarySource = `${layout.binaryPath}.${suffix}.c`;
  const temporaryBinary = `${layout.binaryPath}.${suffix}.tmp`;
  const temporaryDigest = `${layout.digestPath}.${suffix}.tmp`;
  try {
    await preparePrivateHelperDirectory(layout.directoryPath);
    if (await trustedHelperBinary(sourceDigest, layout))
      return layout.binaryPath;
    await writeFile(temporarySource, source, { flag: "wx", mode: 0o600 });
    await compileHackerOneKeychainHelper(
      temporarySource,
      temporaryBinary,
      layout.directoryPath,
    );
    await chmod(temporaryBinary, 0o700);
    const binaryDigest = await privateFileDigest(
      temporaryBinary,
      0o700,
      MAX_KEYCHAIN_HELPER_BINARY_BYTES,
    );
    await writeFile(temporaryDigest, `${sourceDigest}\n${binaryDigest}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await rename(temporaryBinary, layout.binaryPath);
    await rename(temporaryDigest, layout.digestPath);
    if (!(await trustedHelperBinary(sourceDigest, layout)))
      throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
    return layout.binaryPath;
  } catch {
    throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
  } finally {
    source.fill(0);
    await Promise.allSettled([
      unlink(temporarySource),
      unlink(temporaryBinary),
      unlink(temporaryDigest),
    ]);
  }
}

async function readFixedHelperSource(sourcePath: string): Promise<Buffer> {
  const handle = await open(
    sourcePath,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  try {
    const status = await handle.stat();
    if (
      !status.isFile() ||
      status.nlink !== 1 ||
      status.uid !== process.getuid?.() ||
      status.size < 1 ||
      status.size > MAX_KEYCHAIN_HELPER_SOURCE_BYTES
    )
      throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
    const source = await handle.readFile();
    if (source.byteLength !== status.size) {
      source.fill(0);
      throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
    }
    return source;
  } catch {
    throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
  } finally {
    await handle.close();
  }
}

async function preparePrivateHelperDirectory(
  directoryPath: string,
): Promise<void> {
  await mkdir(directoryPath, {
    recursive: true,
    mode: 0o700,
  });
  const status = await lstat(directoryPath);
  if (
    !status.isDirectory() ||
    status.isSymbolicLink() ||
    status.uid !== process.getuid?.() ||
    (status.mode & 0o077) !== 0
  )
    throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
}

async function trustedHelperBinary(
  sourceDigest: string,
  layout: HackerOneKeychainHelperBuildLayout,
): Promise<boolean> {
  let digestFile: Buffer | undefined;
  try {
    const binaryDigest = await privateFileDigest(
      layout.binaryPath,
      0o700,
      MAX_KEYCHAIN_HELPER_BINARY_BYTES,
    );
    digestFile = await readPrivateFile(
      layout.digestPath,
      0o600,
      MAX_KEYCHAIN_HELPER_DIGEST_BYTES,
    );
    return digestFile.toString("utf8") === `${sourceDigest}\n${binaryDigest}\n`;
  } catch {
    return false;
  } finally {
    digestFile?.fill(0);
  }
}

async function privateFileDigest(
  path: string,
  expectedMode: number,
  maximumBytes: number,
): Promise<string> {
  const contents = await readPrivateFile(path, expectedMode, maximumBytes);
  try {
    return sha256(contents);
  } finally {
    contents.fill(0);
  }
}

async function readPrivateFile(
  path: string,
  expectedMode: number,
  maximumBytes: number,
): Promise<Buffer> {
  const handle = await open(
    path,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  try {
    const status = await handle.stat();
    const uid = process.getuid?.();
    if (
      uid === undefined ||
      !status.isFile() ||
      status.nlink !== 1 ||
      status.uid !== uid ||
      (status.mode & 0o777) !== expectedMode ||
      status.size < 1 ||
      status.size > maximumBytes
    )
      throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
    const contents = await handle.readFile();
    if (contents.byteLength !== status.size) {
      contents.fill(0);
      throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
    }
    return contents;
  } finally {
    await handle.close();
  }
}

function compileHackerOneKeychainHelper(
  sourcePath: string,
  outputPath: string,
  temporaryDirectoryPath: string,
): Promise<void> {
  return new Promise((resolve, reject) => {
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
        "-framework",
        "Security",
        "-framework",
        "CoreFoundation",
        sourcePath,
        "-o",
        outputPath,
      ],
      {
        encoding: "buffer",
        env: {
          PATH: "/usr/bin:/bin",
          TMPDIR: temporaryDirectoryPath,
        },
        maxBuffer: 4_096,
        timeout: 30_000,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        if (Buffer.isBuffer(stdout)) stdout.fill(0);
        if (Buffer.isBuffer(stderr)) stderr.fill(0);
        if (error === null) resolve();
        else reject(new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED"));
      },
    );
  });
}

function killHelperChild(child: HackerOneKeychainHelperProcess): void {
  try {
    child.kill();
  } catch {
    // Failure remains closed if the OS has already reaped the helper.
  }
}

function validSecret(value: Uint8Array): boolean {
  return value.byteLength > 0 && value.byteLength <= MAX_SECRET_BYTES;
}

function createCredentialEnvelope(
  role: CredentialRole,
  generation: Uint8Array,
  secret: Uint8Array,
): Uint8Array {
  if (generation.byteLength !== PAIR_GENERATION_BYTES || !validSecret(secret))
    throw new SecurityError("HACKERONE_CREDENTIAL_INPUT_INVALID");
  const envelope = new Uint8Array(
    PAIR_ENVELOPE_SECRET_OFFSET + base64UrlEncodedLength(secret.byteLength),
  );
  try {
    if (envelope.byteLength > MAX_KEYCHAIN_ENVELOPE_BYTES)
      throw new SecurityError("HACKERONE_CREDENTIAL_INPUT_INVALID");
    envelope.set(PAIR_ENVELOPE_PREFIX, 0);
    envelope[PAIR_ENVELOPE_ROLE_OFFSET] = role === "identifier" ? 0x69 : 0x74;
    envelope[PAIR_ENVELOPE_ROLE_SEPARATOR_OFFSET] = 0x2e;
    if (
      encodeBase64Url(generation, envelope, PAIR_ENVELOPE_GENERATION_OFFSET) !==
      PAIR_GENERATION_BASE64URL_BYTES
    )
      throw new SecurityError("HACKERONE_CREDENTIAL_INPUT_INVALID");
    envelope[PAIR_ENVELOPE_SECRET_SEPARATOR_OFFSET] = 0x2e;
    encodeBase64Url(secret, envelope, PAIR_ENVELOPE_SECRET_OFFSET);
    return envelope;
  } catch (error) {
    envelope.fill(0);
    throw error;
  }
}

function parseCredentialEnvelope(
  envelope: Uint8Array,
  expectedRole: CredentialRole,
): ParsedCredentialEnvelope {
  let generation: Uint8Array | undefined;
  let secret: Uint8Array | undefined;
  try {
    if (
      !(envelope instanceof Uint8Array) ||
      envelope.byteLength <= PAIR_ENVELOPE_SECRET_OFFSET ||
      envelope.byteLength > MAX_KEYCHAIN_ENVELOPE_BYTES ||
      !printableAscii(envelope)
    )
      throw new Error("invalid");
    for (let index = 0; index < PAIR_ENVELOPE_PREFIX.length; index += 1) {
      if (envelope[index] !== PAIR_ENVELOPE_PREFIX[index])
        throw new Error("invalid");
    }
    if (
      envelope[PAIR_ENVELOPE_ROLE_OFFSET] !==
        (expectedRole === "identifier" ? 0x69 : 0x74) ||
      envelope[PAIR_ENVELOPE_ROLE_SEPARATOR_OFFSET] !== 0x2e ||
      envelope[PAIR_ENVELOPE_SECRET_SEPARATOR_OFFSET] !== 0x2e
    )
      throw new Error("invalid");
    generation = decodeBase64Url(
      envelope,
      PAIR_ENVELOPE_GENERATION_OFFSET,
      PAIR_GENERATION_BASE64URL_BYTES,
    );
    secret = decodeBase64Url(
      envelope,
      PAIR_ENVELOPE_SECRET_OFFSET,
      envelope.byteLength - PAIR_ENVELOPE_SECRET_OFFSET,
    );
    if (
      generation.byteLength !== PAIR_GENERATION_BYTES ||
      !validCredentialBytes(secret)
    )
      throw new Error("invalid");
    return { generation, secret };
  } catch {
    generation?.fill(0);
    secret?.fill(0);
    throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
  }
}

function assertCredentialEnvelope(
  envelope: Uint8Array,
  expectedRole: CredentialRole,
): void {
  let parsed: ParsedCredentialEnvelope | undefined;
  try {
    parsed = parseCredentialEnvelope(envelope, expectedRole);
  } catch {
    throw new SecurityError("HACKERONE_KEYCHAIN_HELPER_FAILED");
  } finally {
    parsed?.generation.fill(0);
    parsed?.secret.fill(0);
  }
}

function base64UrlEncodedLength(byteLength: number): number {
  return Math.ceil((byteLength * 4) / 3);
}

function encodeBase64Url(
  source: Uint8Array,
  destination: Uint8Array,
  offset: number,
): number {
  const required = base64UrlEncodedLength(source.byteLength);
  if (
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    offset + required > destination.byteLength
  )
    throw new SecurityError("HACKERONE_CREDENTIAL_INPUT_INVALID");
  let output = offset;
  for (let index = 0; index < source.byteLength; index += 3) {
    const first = source[index] ?? 0;
    const secondPresent = index + 1 < source.byteLength;
    const thirdPresent = index + 2 < source.byteLength;
    const second = source[index + 1] ?? 0;
    const third = source[index + 2] ?? 0;
    destination[output] = base64UrlByte(first >>> 2);
    output += 1;
    destination[output] = base64UrlByte(((first & 0x03) << 4) | (second >>> 4));
    output += 1;
    if (secondPresent) {
      destination[output] = base64UrlByte(
        ((second & 0x0f) << 2) | (third >>> 6),
      );
      output += 1;
    }
    if (thirdPresent) {
      destination[output] = base64UrlByte(third & 0x3f);
      output += 1;
    }
  }
  return output - offset;
}

function decodeBase64Url(
  source: Uint8Array,
  offset: number,
  length: number,
): Uint8Array {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length <= 0 ||
    offset + length > source.byteLength ||
    length % 4 === 1
  )
    throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
  const output = new Uint8Array(Math.floor((length * 6) / 8));
  try {
    let input = offset;
    let written = 0;
    const end = offset + length;
    while (end - input >= 4) {
      const first = base64UrlValue(source[input] ?? -1);
      const second = base64UrlValue(source[input + 1] ?? -1);
      const third = base64UrlValue(source[input + 2] ?? -1);
      const fourth = base64UrlValue(source[input + 3] ?? -1);
      output[written] = (first << 2) | (second >>> 4);
      output[written + 1] = ((second & 0x0f) << 4) | (third >>> 2);
      output[written + 2] = ((third & 0x03) << 6) | fourth;
      input += 4;
      written += 3;
    }
    const remaining = end - input;
    if (remaining === 2) {
      const first = base64UrlValue(source[input] ?? -1);
      const second = base64UrlValue(source[input + 1] ?? -1);
      if ((second & 0x0f) !== 0) throw new Error("non-canonical");
      output[written] = (first << 2) | (second >>> 4);
      written += 1;
    } else if (remaining === 3) {
      const first = base64UrlValue(source[input] ?? -1);
      const second = base64UrlValue(source[input + 1] ?? -1);
      const third = base64UrlValue(source[input + 2] ?? -1);
      if ((third & 0x03) !== 0) throw new Error("non-canonical");
      output[written] = (first << 2) | (second >>> 4);
      output[written + 1] = ((second & 0x0f) << 4) | (third >>> 2);
      written += 2;
    } else if (remaining !== 0) {
      throw new Error("invalid");
    }
    if (written !== output.byteLength) throw new Error("invalid");
    return output;
  } catch {
    output.fill(0);
    throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
  }
}

function base64UrlByte(value: number): number {
  if (value < 26) return 0x41 + value;
  if (value < 52) return 0x61 + value - 26;
  if (value < 62) return 0x30 + value - 52;
  return value === 62 ? 0x2d : 0x5f;
}

function base64UrlValue(value: number): number {
  if (value >= 0x41 && value <= 0x5a) return value - 0x41;
  if (value >= 0x61 && value <= 0x7a) return value - 0x61 + 26;
  if (value >= 0x30 && value <= 0x39) return value - 0x30 + 52;
  if (value === 0x2d) return 62;
  if (value === 0x5f) return 63;
  throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
}

function sameGeneration(left: Uint8Array, right: Uint8Array): boolean {
  if (
    left.byteLength !== PAIR_GENERATION_BYTES ||
    right.byteLength !== PAIR_GENERATION_BYTES
  )
    return false;
  let difference = 0;
  for (let index = 0; index < PAIR_GENERATION_BYTES; index += 1)
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  return difference === 0;
}

function normalizeCredential(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_SECRET_BYTES ||
    /[^\u0021-\u007e]/u.test(value)
  )
    throw new SecurityError("HACKERONE_CREDENTIAL_INPUT_INVALID");
  return value;
}

function validCredentialBytes(value: Uint8Array): boolean {
  if (!validSecret(value)) return false;
  for (const byte of value) if (byte < 0x21 || byte > 0x7e) return false;
  return true;
}

function printableAscii(value: Uint8Array): boolean {
  for (const byte of value) if (byte < 0x21 || byte > 0x7e) return false;
  return true;
}

function credentialBindingDigest(value: Uint8Array): string {
  return sha256(value);
}

function sameDigest(left: string, right: string): boolean {
  if (!FULL_DIGEST.test(left) || !FULL_DIGEST.test(right)) return false;
  let difference = 0;
  for (let index = 0; index < 64; index += 1)
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}
