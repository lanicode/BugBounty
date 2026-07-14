import { execFile as execFileCallback } from "node:child_process";

const MAX_KEYCHAIN_SECRET_BYTES = 4_096;
const MAX_SECURITY_OUTPUT_BYTES = MAX_KEYCHAIN_SECRET_BYTES + 1;

export interface SecurityCliExecutionResult {
  readonly stdout: Uint8Array;
  readonly stderr: Uint8Array;
}

export type SecurityCliExecutor = (
  file: string,
  args: readonly string[],
  options: {
    readonly encoding: "buffer";
    readonly maxBuffer: number;
    readonly timeout: number;
    readonly windowsHide: true;
  },
) => Promise<SecurityCliExecutionResult>;

class SecurityCliExecutionFailure extends Error {
  public constructor(
    public readonly stdout: Uint8Array,
    public readonly stderr: Uint8Array,
  ) {
    super("KEYCHAIN_READ_FAILED");
  }
}

const execFile: SecurityCliExecutor = (file, args, options) =>
  new Promise((resolve, reject) => {
    execFileCallback(file, [...args], options, (error, stdout, stderr) => {
      if (error !== null) {
        reject(new SecurityCliExecutionFailure(stdout, stderr));
        return;
      }
      resolve({ stdout, stderr });
    });
  });

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
    let value: Uint8Array | undefined;
    try {
      value = await this.reader.read(service, account);
      if (
        !(value instanceof Uint8Array) ||
        value.byteLength === 0 ||
        value.byteLength > MAX_KEYCHAIN_SECRET_BYTES
      )
        throw new Error("KEYCHAIN_READ_FAILED");
      return Uint8Array.from(value);
    } catch {
      throw new Error("KEYCHAIN_READ_FAILED");
    } finally {
      value?.fill(0);
    }
  }
}

export class SecurityCliKeychainReader implements KeychainReader {
  public constructor(
    private readonly executor: SecurityCliExecutor = execFile,
  ) {}

  public async read(service: string, account: string): Promise<Uint8Array> {
    let stdout: Uint8Array | undefined;
    let stderr: Uint8Array | undefined;
    let value: Uint8Array | undefined;
    let failed = false;
    try {
      const result = await this.executor(
        "/usr/bin/security",
        ["find-generic-password", "-s", service, "-a", account, "-w"],
        {
          encoding: "buffer",
          maxBuffer: MAX_SECURITY_OUTPUT_BYTES,
          timeout: 5_000,
          windowsHide: true,
        },
      );
      stdout = result.stdout;
      stderr = result.stderr;
      if (
        !(stdout instanceof Uint8Array) ||
        !(stderr instanceof Uint8Array) ||
        stdout.byteLength === 0 ||
        stdout.byteLength > MAX_SECURITY_OUTPUT_BYTES ||
        stderr.byteLength > 0
      )
        throw new Error("KEYCHAIN_READ_FAILED");
      const secretLength = stdout.byteLength - (stdout.at(-1) === 0x0a ? 1 : 0);
      if (secretLength === 0 || secretLength > MAX_KEYCHAIN_SECRET_BYTES)
        throw new Error("KEYCHAIN_READ_FAILED");
      value = Uint8Array.from(stdout.subarray(0, secretLength));
    } catch (error) {
      stdout ??= errorOutput(error, "stdout");
      stderr ??= errorOutput(error, "stderr");
      failed = true;
    } finally {
      stdout?.fill(0);
      stderr?.fill(0);
    }
    if (failed || value === undefined) throw new Error("KEYCHAIN_READ_FAILED");
    return value;
  }
}

function errorOutput(
  error: unknown,
  field: "stderr" | "stdout",
): Uint8Array | undefined {
  if (typeof error !== "object" || error === null || !(field in error))
    return undefined;
  const value: unknown = Reflect.get(error, field);
  return value instanceof Uint8Array ? value : undefined;
}
