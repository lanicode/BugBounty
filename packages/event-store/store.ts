import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { chmod, link, mkdir, open, readFile, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { SecretStore } from "../secret-store/store.js";
import { canonicalJson, type JsonValue } from "../shared/canonical.js";

interface Envelope {
  readonly version: 1;
  readonly keyVersion: number;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}

export class EncryptedEventStore {
  public constructor(
    private readonly directory: string,
    private readonly secrets: SecretStore,
    private readonly keyReference: (version: number) => string,
    private readonly keyVersion = 1,
  ) {}

  async #key(version: number): Promise<Uint8Array> {
    const key = await this.secrets.get(this.keyReference(version));
    if (key.byteLength !== 32) throw new Error("EVENT_KEY_INVALID");
    return key;
  }

  public async write(id: string, event: JsonValue): Promise<string> {
    if (!/^[a-zA-Z0-9_-]{1,80}$/u.test(id)) throw new Error("EVENT_ID_INVALID");
    const key = await this.#key(this.keyVersion);
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(Buffer.from(`event-store:v1:key:${this.keyVersion}`));
    const ciphertext = Buffer.concat([
      cipher.update(canonicalJson(event), "utf8"),
      cipher.final(),
    ]);
    const envelope: Envelope = {
      version: 1,
      keyVersion: this.keyVersion,
      nonce: nonce.toString("base64"),
      ciphertext: ciphertext.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
    };
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await chmod(this.directory, 0o700);
    const destination = join(this.directory, `${id}.events.enc`);
    const temporary = join(
      this.directory,
      `.tmp-${process.pid}-${randomBytes(8).toString("hex")}`,
    );
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(JSON.stringify(envelope), "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await link(temporary, destination);
    } finally {
      await unlink(temporary).catch(() => undefined);
    }
    await chmod(destination, 0o600);
    return destination;
  }

  public async read(path: string): Promise<JsonValue> {
    if (dirname(path) !== this.directory) throw new Error("EVENT_PATH_INVALID");
    let value: unknown;
    try {
      value = JSON.parse(await readFile(path, "utf8")) as unknown;
    } catch {
      throw new Error("EVENT_ENVELOPE_INVALID");
    }
    if (!isEnvelope(value)) throw new Error("EVENT_ENVELOPE_INVALID");
    const key = await this.#key(value.keyVersion);
    try {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        key,
        Buffer.from(value.nonce, "base64"),
      );
      decipher.setAAD(Buffer.from(`event-store:v1:key:${value.keyVersion}`));
      decipher.setAuthTag(Buffer.from(value.tag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(value.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
      const parsed: unknown = JSON.parse(plaintext);
      if (!isJsonValue(parsed)) throw new Error("EVENT_PLAINTEXT_INVALID");
      return parsed;
    } catch {
      throw new Error("EVENT_INTEGRITY_FAILED");
    }
  }
}

function isEnvelope(value: unknown): value is Envelope {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  return (
    Object.keys(value).length === 5 &&
    "version" in value &&
    value.version === 1 &&
    "keyVersion" in value &&
    Number.isInteger(value.keyVersion) &&
    "nonce" in value &&
    typeof value.nonce === "string" &&
    "ciphertext" in value &&
    typeof value.ciphertext === "string" &&
    "tag" in value &&
    typeof value.tag === "string"
  );
}

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (typeof value === "object") return Object.values(value).every(isJsonValue);
  return false;
}
