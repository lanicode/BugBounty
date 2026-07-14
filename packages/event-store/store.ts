import { constants, chmod, link, mkdir, open, unlink } from "node:fs/promises";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { basename, dirname, join, resolve } from "node:path";
import type { SecretStore } from "../secret-store/store.js";
import { canonicalJson, type JsonValue } from "../shared/canonical.js";

interface Envelope {
  readonly version: 1;
  readonly keyVersion: number;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}

interface ParsedEnvelope {
  readonly envelope: Envelope;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
}

export interface EventEnvelopeMetadata {
  readonly envelopeVersion: 1;
  readonly keyVersion: number;
}

export const MAX_EVENT_KEY_VERSION = 10_000;
export const MAX_EVENT_ENVELOPE_BYTES = 4 * 1024 * 1024;

const EVENT_FILE = /^[a-zA-Z0-9_-]{1,80}\.events\.enc$/u;
const BASE64 =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;

export class EncryptedEventStore {
  readonly #directory: string;
  readonly #secrets: SecretStore;
  readonly #keyReference: (version: number) => string;
  readonly #keyVersion: number;
  readonly #readableKeyVersions: ReadonlySet<number>;

  public constructor(
    directory: string,
    secrets: SecretStore,
    keyReference: (version: number) => string,
    keyVersion = 1,
    readableKeyVersions: readonly number[] = [keyVersion],
  ) {
    if (typeof directory !== "string" || directory.length === 0)
      throw new Error("EVENT_DIRECTORY_INVALID");
    if (typeof keyReference !== "function")
      throw new Error("EVENT_KEY_REFERENCE_INVALID");
    assertKeyVersion(keyVersion);
    const readable = validateReadableKeyVersions(
      readableKeyVersions,
      keyVersion,
    );
    this.#directory = resolve(directory);
    this.#secrets = secrets;
    this.#keyReference = keyReference;
    this.#keyVersion = keyVersion;
    this.#readableKeyVersions = readable;
  }

  async #withKey<T>(version: number, use: (key: Uint8Array) => T): Promise<T> {
    this.#assertReadable(version);
    const reference = this.#keyReference(version);
    if (typeof reference !== "string" || reference.length === 0)
      throw new Error("EVENT_KEY_REFERENCE_INVALID");
    let key: Uint8Array | undefined;
    try {
      key = await this.#secrets.get(reference);
      if (
        Object.getPrototypeOf(key) !== Uint8Array.prototype ||
        Object.hasOwn(key, "fill") ||
        key.byteLength !== 32
      )
        throw new Error("EVENT_KEY_INVALID");
      return use(key);
    } finally {
      if (key !== undefined) zeroizeKey(key);
    }
  }

  #assertReadable(version: number): void {
    assertKeyVersion(version);
    if (!this.#readableKeyVersions.has(version))
      throw new Error("EVENT_KEY_VERSION_NOT_READABLE");
  }

  public async write(id: string, event: JsonValue): Promise<string> {
    if (!/^[a-zA-Z0-9_-]{1,80}$/u.test(id)) throw new Error("EVENT_ID_INVALID");
    const nonce = randomBytes(12);
    const encrypted = await this.#withKey(this.#keyVersion, (key) => {
      const cipher = createCipheriv("aes-256-gcm", key, nonce);
      cipher.setAAD(Buffer.from(`event-store:v1:key:${this.#keyVersion}`));
      const ciphertext = Buffer.concat([
        cipher.update(canonicalJson(event), "utf8"),
        cipher.final(),
      ]);
      return {
        ciphertext: ciphertext.toString("base64"),
        tag: cipher.getAuthTag().toString("base64"),
      };
    });
    const envelope: Envelope = {
      version: 1,
      keyVersion: this.#keyVersion,
      nonce: nonce.toString("base64"),
      ciphertext: encrypted.ciphertext,
      tag: encrypted.tag,
    };
    const serializedEnvelope = JSON.stringify(envelope);
    if (
      Buffer.byteLength(serializedEnvelope, "utf8") > MAX_EVENT_ENVELOPE_BYTES
    )
      throw new Error("EVENT_ENVELOPE_TOO_LARGE");
    await mkdir(this.#directory, { recursive: true, mode: 0o700 });
    await chmod(this.#directory, 0o700);
    const destination = join(this.#directory, `${id}.events.enc`);
    const temporary = join(
      this.#directory,
      `.tmp-${process.pid}-${randomBytes(8).toString("hex")}`,
    );
    const handle = await open(temporary, "wx", 0o600);
    try {
      try {
        await handle.writeFile(serializedEnvelope, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      await chmod(temporary, 0o600);
      await link(temporary, destination);
      await syncDirectory(this.#directory);
    } finally {
      await unlink(temporary);
      await syncDirectory(this.#directory);
    }
    return destination;
  }

  public async inspect(path: string): Promise<EventEnvelopeMetadata> {
    const parsed = await this.#readEnvelope(path);
    return Object.freeze({
      envelopeVersion: parsed.envelope.version,
      keyVersion: parsed.envelope.keyVersion,
    });
  }

  public async read(path: string): Promise<JsonValue> {
    const parsed = await this.#readEnvelope(path);
    this.#assertReadable(parsed.envelope.keyVersion);
    return this.#withKey(parsed.envelope.keyVersion, (key) => {
      try {
        const decipher = createDecipheriv("aes-256-gcm", key, parsed.nonce);
        decipher.setAAD(
          Buffer.from(`event-store:v1:key:${parsed.envelope.keyVersion}`),
        );
        decipher.setAuthTag(parsed.tag);
        const plaintext = Buffer.concat([
          decipher.update(parsed.ciphertext),
          decipher.final(),
        ]).toString("utf8");
        const value: unknown = JSON.parse(plaintext);
        if (!isJsonValue(value)) throw new Error("EVENT_PLAINTEXT_INVALID");
        return value;
      } catch {
        throw new Error("EVENT_INTEGRITY_FAILED");
      }
    });
  }

  async #readEnvelope(path: string): Promise<ParsedEnvelope> {
    const resolvedPath = resolve(path);
    if (
      dirname(resolvedPath) !== this.#directory ||
      !EVENT_FILE.test(basename(resolvedPath))
    )
      throw new Error("EVENT_PATH_INVALID");
    let source: string;
    try {
      const handle = await open(
        resolvedPath,
        constants.O_RDONLY | constants.O_NOFOLLOW,
      );
      try {
        const stat = await handle.stat();
        if (
          !stat.isFile() ||
          stat.size <= 0 ||
          stat.size > MAX_EVENT_ENVELOPE_BYTES
        )
          throw new Error("EVENT_ENVELOPE_INVALID");
        source = await handle.readFile("utf8");
      } finally {
        await handle.close();
      }
    } catch {
      throw new Error("EVENT_ENVELOPE_INVALID");
    }
    let value: unknown;
    try {
      value = JSON.parse(source);
    } catch {
      throw new Error("EVENT_ENVELOPE_INVALID");
    }
    return parseEnvelope(value);
  }
}

async function syncDirectory(directory: string): Promise<void> {
  const handle = await open(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    const stat = await handle.stat();
    if (!stat.isDirectory()) throw new Error("EVENT_DIRECTORY_INVALID");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function zeroizeKey(key: Uint8Array): void {
  for (let index = 0; index < key.byteLength; index += 1) key[index] = 0;
}

function validateReadableKeyVersions(
  value: unknown,
  activeVersion: number,
): ReadonlySet<number> {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length < 1 ||
    value.length > MAX_EVENT_KEY_VERSION
  )
    throw new Error("EVENT_READABLE_KEY_VERSIONS_INVALID");
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== value.length + 1 ||
    keys.some(
      (key) =>
        key !== "length" &&
        (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/u.test(key)),
    )
  )
    throw new Error("EVENT_READABLE_KEY_VERSIONS_INVALID");
  const versions = new Set<number>();
  let previous = 0;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor))
      throw new Error("EVENT_READABLE_KEY_VERSIONS_INVALID");
    const candidate: unknown = descriptor.value;
    assertKeyVersion(candidate);
    const version = candidate;
    if (version <= previous)
      throw new Error("EVENT_READABLE_KEY_VERSIONS_INVALID");
    versions.add(version);
    previous = version;
  }
  if (!versions.has(activeVersion))
    throw new Error("EVENT_READABLE_KEY_VERSIONS_INVALID");
  return versions;
}

function assertKeyVersion(value: unknown): asserts value is number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > MAX_EVENT_KEY_VERSION
  )
    throw new Error("EVENT_KEY_VERSION_INVALID");
}

function parseEnvelope(value: unknown): ParsedEnvelope {
  if (
    !isExactObject(value, [
      "version",
      "keyVersion",
      "nonce",
      "ciphertext",
      "tag",
    ])
  )
    throw new Error("EVENT_ENVELOPE_INVALID");
  const fields = value;
  if (fields["version"] !== 1) throw new Error("EVENT_ENVELOPE_INVALID");
  const keyVersion = fields["keyVersion"];
  if (typeof keyVersion !== "number") throw new Error("EVENT_ENVELOPE_INVALID");
  assertKeyVersion(keyVersion);
  const nonceText = fields["nonce"];
  const ciphertextText = fields["ciphertext"];
  const tagText = fields["tag"];
  if (
    typeof nonceText !== "string" ||
    typeof ciphertextText !== "string" ||
    typeof tagText !== "string"
  )
    throw new Error("EVENT_ENVELOPE_INVALID");
  const nonce = decodeCanonicalBase64(nonceText, 12);
  const ciphertext = decodeCanonicalBase64(ciphertextText);
  const tag = decodeCanonicalBase64(tagText, 16);
  if (ciphertext.byteLength === 0) throw new Error("EVENT_ENVELOPE_INVALID");
  return {
    envelope: {
      version: 1,
      keyVersion,
      nonce: nonceText,
      ciphertext: ciphertextText,
      tag: tagText,
    },
    nonce,
    ciphertext,
    tag,
  };
}

function decodeCanonicalBase64(value: string, length?: number): Uint8Array {
  if (!BASE64.test(value)) throw new Error("EVENT_ENVELOPE_INVALID");
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.toString("base64") !== value ||
    (length !== undefined && bytes.byteLength !== length)
  )
    throw new Error("EVENT_ENVELOPE_INVALID");
  return bytes;
}

function isExactObject(
  value: unknown,
  expectedKeys: readonly string[],
): value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    return false;
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string" || !expectedKeys.includes(key))
  )
    return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return expectedKeys.every((key) => {
    const descriptor = descriptors[key];
    return (
      descriptor !== undefined &&
      "value" in descriptor &&
      descriptor.enumerable &&
      descriptor.configurable &&
      descriptor.writable
    );
  });
}

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (
    typeof value === "object" &&
    Object.getPrototypeOf(value) === Object.prototype
  )
    return Object.values(value).every(isJsonValue);
  return false;
}
