import { execFile as execFileCallback } from "node:child_process";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);

export interface KeychainReader {
  read(service: string, account: string): Promise<Uint8Array>;
}

export interface SecretStore {
  get(reference: string): Promise<Uint8Array>;
}

export class InMemorySecretStore implements SecretStore {
  readonly #secrets = new Map<string, Uint8Array>();

  public set(reference: string, value: Uint8Array): void {
    this.#secrets.set(reference, Uint8Array.from(value));
  }

  public get(reference: string): Promise<Uint8Array> {
    const value = this.#secrets.get(reference);
    if (value === undefined)
      return Promise.reject(new Error("SECRET_NOT_FOUND"));
    return Promise.resolve(Uint8Array.from(value));
  }
}

function parseReference(reference: string): {
  service: string;
  account: string;
} {
  const match = /^keychain:\/\/([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._/-]+)$/u.exec(
    reference,
  );
  if (
    match?.[1] === undefined ||
    match[2] === undefined ||
    match[2].includes("..")
  )
    throw new Error("SECRET_REFERENCE_INVALID");
  return { service: match[1], account: match[2] };
}

export class MacOSKeychainSecretStore implements SecretStore {
  public constructor(
    private readonly reader: KeychainReader = new SecurityCliKeychainReader(),
    private readonly platform: NodeJS.Platform = process.platform,
  ) {}

  public async get(reference: string): Promise<Uint8Array> {
    if (this.platform !== "darwin") throw new Error("KEYCHAIN_UNAVAILABLE");
    const { service, account } = parseReference(reference);
    try {
      const value = await this.reader.read(service, account);
      if (value.byteLength === 0 || value.byteLength > 4096)
        throw new Error("KEYCHAIN_READ_FAILED");
      return Uint8Array.from(value);
    } catch {
      throw new Error("KEYCHAIN_READ_FAILED");
    }
  }
}

export class SecurityCliKeychainReader implements KeychainReader {
  public async read(service: string, account: string): Promise<Uint8Array> {
    const { stdout, stderr } = await execFile(
      "/usr/bin/security",
      ["find-generic-password", "-s", service, "-a", account, "-w"],
      { encoding: "buffer", maxBuffer: 4096, timeout: 5000 },
    );
    if (stderr.byteLength > 0) {
      stdout.fill(0);
      throw new Error("KEYCHAIN_READ_FAILED");
    }
    const value = Uint8Array.from(
      stdout.subarray(0, stdout.at(-1) === 10 ? -1 : undefined),
    );
    stdout.fill(0);
    return value;
  }
}
