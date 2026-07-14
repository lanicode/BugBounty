import { resolve } from "node:path";
import { ControlPlaneDatabase } from "../../packages/control-plane/index.js";
import {
  HackerOneCredentialVault,
  HackerOneMetadataStore,
  MacOSHackerOneKeychainMutationBackend,
} from "../../packages/hackerone-readonly/index.js";
import { MacOSKeychainSecretStore } from "../../packages/secret-store/index.js";
import { errorCode, SecurityError } from "../../packages/shared/errors.js";

const MAX_TTY_CREDENTIAL_BYTES = 4_000;
type Command = "remove" | "status" | "store";

async function main(): Promise<void> {
  const command = parseCommand(process.argv.slice(2));
  if (process.platform !== "darwin")
    throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
  requireInteractiveTerminal();
  const vault = new HackerOneCredentialVault(
    new MacOSKeychainSecretStore(),
    new MacOSHackerOneKeychainMutationBackend(),
  );

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

  await disablePersistedAdapter();
  if (command === "remove") {
    await vault.remove();
    process.stdout.write("Credentials entfernt; Adapter deaktiviert.\n");
    return;
  }

  let identifier: Uint8Array | undefined;
  let token: Uint8Array | undefined;
  try {
    identifier = await readHiddenCredential("HackerOne API-Identifier: ");
    token = await readHiddenCredential("HackerOne API-Token: ");
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

function readHiddenCredential(prompt: string): Promise<Uint8Array> {
  return new Promise((resolveInput, rejectInput) => {
    const input = process.stdin;
    const output = process.stdout;
    const scratch = Buffer.alloc(MAX_TTY_CREDENTIAL_BYTES);
    const wasRaw = input.isRaw;
    let length = 0;
    let settled = false;

    const cleanup = (): void => {
      input.removeListener("data", onData);
      input.setRawMode(wasRaw);
      scratch.fill(0);
      output.write("\n");
    };
    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      const value =
        error === undefined && length > 0
          ? Uint8Array.from(scratch.subarray(0, length))
          : undefined;
      cleanup();
      if (error !== undefined) rejectInput(error);
      else if (value !== undefined) resolveInput(value);
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

    output.write(prompt);
    input.setRawMode(true);
    input.resume();
    input.on("data", onData);
  });
}

main().catch((error: unknown) => {
  process.stderr.write(`${errorCode(error)}\n`);
  process.exitCode = 1;
});
