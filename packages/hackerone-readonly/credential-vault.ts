import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import type { SecretStore } from "../secret-store/index.js";
import {
  HACKERONE_IDENTIFIER_REFERENCE,
  HACKERONE_TOKEN_REFERENCE,
} from "./types.js";

const KEYCHAIN_SERVICE = "bugbounty-copilot";
const IDENTIFIER_ACCOUNT = "hackerone-api-identifier";
const TOKEN_ACCOUNT = "hackerone-api-token";
const MAX_KEYCHAIN_STDIN_BYTES = 4_096;
const MAX_KEYCHAIN_ENVELOPE_BYTES = MAX_KEYCHAIN_STDIN_BYTES - 1;
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

      const fingerprint = shortFingerprint(token);
      generation = randomBytes(PAIR_GENERATION_BYTES);
      identifierEnvelope = createCredentialEnvelope(
        "identifier",
        generation,
        identifier,
      );
      tokenEnvelope = createCredentialEnvelope("token", generation, token);
      mutationStarted = true;
      try {
        await this.mutations.storeIdentifier(identifierEnvelope);
        await this.mutations.storeToken(tokenEnvelope);
      } catch {
        await this.deletePair();
        throw new SecurityError("HACKERONE_KEYCHAIN_WRITE_FAILED");
      }
      return fingerprint;
    } catch (error) {
      if (
        error instanceof SecurityError &&
        (error.code === "HACKERONE_CREDENTIAL_INPUT_INVALID" ||
          error.code === "HACKERONE_KEYCHAIN_WRITE_FAILED")
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
}

export class MacOSHackerOneKeychainMutationBackend implements HackerOneKeychainMutationBackend {
  public constructor(
    private readonly platform: NodeJS.Platform = process.platform,
    private readonly runner: HackerOneSecurityCliRunner = new SpawnHackerOneSecurityCliRunner(),
  ) {
    Object.freeze(this);
  }

  public storeIdentifier(value: Uint8Array): Promise<void> {
    return this.store(IDENTIFIER_ACCOUNT, "identifier", value);
  }

  public storeToken(value: Uint8Array): Promise<void> {
    return this.store(TOKEN_ACCOUNT, "token", value);
  }

  public deleteIdentifier(): Promise<void> {
    return this.delete(IDENTIFIER_ACCOUNT);
  }

  public deleteToken(): Promise<void> {
    return this.delete(TOKEN_ACCOUNT);
  }

  private store(
    account: string,
    role: CredentialRole,
    value: Uint8Array,
  ): Promise<void> {
    this.assertAvailable();
    assertCredentialEnvelope(value, role);
    return this.runner.run(
      [
        "add-generic-password",
        "-U",
        "-s",
        KEYCHAIN_SERVICE,
        "-a",
        account,
        "-w",
      ],
      value,
    );
  }

  private delete(account: string): Promise<void> {
    this.assertAvailable();
    return this.runner.run([
      "delete-generic-password",
      "-s",
      KEYCHAIN_SERVICE,
      "-a",
      account,
    ]);
  }

  private assertAvailable(): void {
    if (this.platform !== "darwin")
      throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
  }
}

export interface HackerOneSecurityCliRunner {
  run(args: readonly string[], secret?: Uint8Array): Promise<void>;
}

export interface HackerOneSecurityCliProcess {
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

export type HackerOneSecurityCliProcessFactory = (
  args: readonly string[],
) => HackerOneSecurityCliProcess;

export class SpawnHackerOneSecurityCliRunner implements HackerOneSecurityCliRunner {
  public constructor(
    private readonly processFactory: HackerOneSecurityCliProcessFactory = spawnSecurityCliProcess,
  ) {
    Object.freeze(this);
  }

  public run(args: readonly string[], secret?: Uint8Array): Promise<void> {
    return runSecurityCli(args, secret, this.processFactory);
  }
}

function runSecurityCli(
  args: readonly string[],
  secret?: Uint8Array,
  processFactory: HackerOneSecurityCliProcessFactory = spawnSecurityCliProcess,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const input =
      secret === undefined ? undefined : secretInput(Uint8Array.from(secret));
    let child: HackerOneSecurityCliProcess;
    try {
      child = processFactory(args);
    } catch {
      input?.fill(0);
      reject(new SecurityError("HACKERONE_KEYCHAIN_CLI_FAILED"));
      return;
    }
    let outputBytes = 0;
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      input?.fill(0);
      child.removeAllListeners();
      if (error === undefined) resolve();
      else reject(error);
    };
    const timer = setTimeout(() => {
      killChild(child);
      finish(new SecurityError("HACKERONE_KEYCHAIN_CLI_TIMEOUT"));
    }, 5_000);
    timer.unref();
    const countOutput = (chunk: unknown): void => {
      if (!Buffer.isBuffer(chunk)) {
        killChild(child);
        finish(new SecurityError("HACKERONE_KEYCHAIN_CLI_FAILED"));
        return;
      }
      outputBytes += chunk.byteLength;
      chunk.fill(0);
      if (outputBytes > MAX_KEYCHAIN_STDIN_BYTES) {
        killChild(child);
        finish(new SecurityError("HACKERONE_KEYCHAIN_CLI_FAILED"));
      }
    };
    child.onStdoutData(countOutput);
    child.onStderrData(countOutput);
    child.onStdinError(() => {
      killChild(child);
      finish(new SecurityError("HACKERONE_KEYCHAIN_CLI_FAILED"));
    });
    child.onError(() => {
      killChild(child);
      finish(new SecurityError("HACKERONE_KEYCHAIN_CLI_FAILED"));
    });
    child.onClose((code, signal) => {
      if (code === 0 && signal === null) finish();
      else finish(new SecurityError("HACKERONE_KEYCHAIN_CLI_FAILED"));
    });
    try {
      child.writeInput(input);
    } catch {
      killChild(child);
      finish(new SecurityError("HACKERONE_KEYCHAIN_CLI_FAILED"));
    }
  });
}

function spawnSecurityCliProcess(
  args: readonly string[],
): HackerOneSecurityCliProcess {
  const child = spawn("/usr/bin/security", [...args], {
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

function secretInput(secret: Uint8Array): Buffer {
  try {
    if (
      secret.byteLength === 0 ||
      secret.byteLength > MAX_KEYCHAIN_ENVELOPE_BYTES ||
      !printableAscii(secret)
    )
      throw new SecurityError("HACKERONE_KEYCHAIN_CLI_FAILED");
    const input = Buffer.alloc(secret.byteLength + 1);
    input.set(secret);
    input[input.byteLength - 1] = 0x0a;
    return input;
  } finally {
    secret.fill(0);
  }
}

function killChild(child: HackerOneSecurityCliProcess): void {
  try {
    child.kill();
  } catch {
    // The operation remains failed closed even if the OS already reaped it.
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
    throw new SecurityError("HACKERONE_KEYCHAIN_CLI_FAILED");
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

function shortFingerprint(value: Uint8Array): string {
  return credentialBindingDigest(value).slice(0, 12);
}
