import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ControlPlaneDatabase } from "../../packages/control-plane/index.js";
import {
  HackerOneCredentialVault,
  HackerOneMetadataStore,
  MacOSHackerOneKeychainMutationBackend,
} from "../../packages/hackerone-readonly/index.js";
import { errorCode, SecurityError } from "../../packages/shared/errors.js";

const MAX_TTY_CREDENTIAL_BYTES = 4_000;
type Command = "remove" | "status" | "store";

async function main(): Promise<void> {
  const command = parseCommand(process.argv.slice(2));
  if (process.platform !== "darwin")
    throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
  requireInteractiveTerminal();
  const keychain = new MacOSHackerOneKeychainMutationBackend();
  const vault = new HackerOneCredentialVault(keychain, keychain);

  if (command === "status") {
    const status = await vault.probe();
    process.stdout.write(
      [
        `Identifier vorhanden: ${status.identifierPresent ? "ja" : "nein"}`,
        `Token vorhanden: ${status.tokenPresent ? "ja" : "nein"}`,
        `Token-Fingerprint: ${status.tokenFingerprint ?? "nicht verfügbar"}`,
      ].join("\n") + "\n",
    );
    return;
  }

  if (command === "remove") {
    await disablePersistedAdapter();
    await vault.remove();
    process.stdout.write("Credentials entfernt; Adapter deaktiviert.\n");
    return;
  }

  let identifier: Uint8Array | undefined;
  let token: Uint8Array | undefined;
  try {
    identifier = await readHiddenCredential("HackerOne API-Identifier: ");
    token = await readHiddenCredential("HackerOne API-Token: ");
    await disablePersistedAdapter();
    const fingerprint = await vault.storeBytes(identifier, token);
    process.stdout.write(
      `Credentials im macOS-Schlüsselbund gespeichert; Adapter deaktiviert; Token-Fingerprint: ${fingerprint}\n`,
    );
  } finally {
    identifier?.fill(0);
    token?.fill(0);
  }
}

function parseCommand(args: readonly string[]): Command {
  if (args.length !== 1)
    throw new SecurityError("HACKERONE_CREDENTIAL_COMMAND_INVALID");
  const command = args[0];
  if (command !== "remove" && command !== "status" && command !== "store")
    throw new SecurityError("HACKERONE_CREDENTIAL_COMMAND_INVALID");
  return command;
}

function requireInteractiveTerminal(): void {
  if (
    !process.stdin.isTTY ||
    !process.stdout.isTTY ||
    typeof process.stdin.setRawMode !== "function"
  )
    throw new SecurityError("HACKERONE_MANUAL_TTY_REQUIRED");
}

async function disablePersistedAdapter(): Promise<void> {
  const database = await ControlPlaneDatabase.file(
    resolve(".local", "dashboard", "control-plane.sqlite"),
  );
  try {
    const store = new HackerOneMetadataStore(database);
    const state = store.getIntegrationState();
    if (state.adapterEnabled) store.setAdapterEnabled(state.revision, false);
  } finally {
    database.close();
  }
}

export interface HiddenCredentialInput {
  isRaw: boolean;
  on(event: "data", listener: (chunk: unknown) => void): unknown;
  pause(): unknown;
  removeListener(event: "data", listener: (chunk: unknown) => void): unknown;
  resume(): unknown;
  setRawMode(mode: boolean): unknown;
}

export interface HiddenCredentialOutput {
  write(value: string | Uint8Array): unknown;
}

export function readHiddenCredential(
  prompt: string,
  input: HiddenCredentialInput = process.stdin,
  output: HiddenCredentialOutput = process.stdout,
): Promise<Uint8Array> {
  return new Promise((resolveInput, rejectInput) => {
    const scratch = Buffer.alloc(MAX_TTY_CREDENTIAL_BYTES);
    const wasRaw = input.isRaw;
    let length = 0;
    let settled = false;

    const cleanup = (): Error | undefined => {
      let failed = false;
      try {
        input.removeListener("data", onData);
      } catch {
        failed = true;
      }
      try {
        input.setRawMode(wasRaw);
      } catch {
        failed = true;
      }
      try {
        input.pause();
      } catch {
        failed = true;
      }
      scratch.fill(0);
      try {
        output.write("\n");
      } catch {
        failed = true;
      }
      return failed
        ? new SecurityError("HACKERONE_TTY_INPUT_INVALID")
        : undefined;
    };
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      const value =
        error === undefined && length > 0
          ? Uint8Array.from(scratch.subarray(0, length))
          : undefined;
      const cleanupError = cleanup();
      const failure = error ?? cleanupError;
      if (failure !== undefined) {
        value?.fill(0);
        rejectInput(failure);
      } else if (value !== undefined) resolveInput(value);
      else rejectInput(new SecurityError("HACKERONE_CREDENTIAL_INPUT_INVALID"));
    };
    const onData = (chunk: unknown): void => {
      if (!(chunk instanceof Uint8Array)) {
        finish(new SecurityError("HACKERONE_TTY_INPUT_INVALID"));
        return;
      }
      for (let index = 0; index < chunk.byteLength; index += 1) {
        const byte = chunk[index];
        if (byte === 0x03) {
          finish(new SecurityError("HACKERONE_TTY_INPUT_ABORTED"));
          return;
        }
        if (byte === 0x0a || byte === 0x0d) {
          const trailing = chunk.subarray(index + 1);
          if ([...trailing].some((value) => value !== 0x0a && value !== 0x0d))
            finish(new SecurityError("HACKERONE_TTY_INPUT_INVALID"));
          else finish();
          return;
        }
        if (byte === 0x08 || byte === 0x7f) {
          if (length > 0) {
            length -= 1;
            scratch[length] = 0;
          }
          continue;
        }
        if (byte === undefined || byte < 0x21 || byte > 0x7e) {
          finish(new SecurityError("HACKERONE_CREDENTIAL_INPUT_INVALID"));
          return;
        }
        if (length >= scratch.byteLength) {
          finish(new SecurityError("HACKERONE_CREDENTIAL_INPUT_INVALID"));
          return;
        }
        scratch[length] = byte;
        length += 1;
      }
    };

    try {
      output.write(prompt);
      input.setRawMode(true);
      input.on("data", onData);
      input.resume();
    } catch {
      finish(new SecurityError("HACKERONE_TTY_INPUT_INVALID"));
    }
  });
}

export function hackerOneCredentialCliExitCode(error: unknown): 1 | 130 {
  return errorCode(error) === "HACKERONE_TTY_INPUT_ABORTED" ? 130 : 1;
}

const invokedPath = process.argv[1];
if (
  invokedPath !== undefined &&
  resolve(invokedPath) === resolve(fileURLToPath(import.meta.url))
)
  void main().catch((error: unknown) => {
    const code = errorCode(error);
    process.stderr.write(`${code}\n`);
    process.exitCode = hackerOneCredentialCliExitCode(error);
  });
