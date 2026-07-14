import { resolve } from "node:path";
import {
  EventKeyLifecycle,
  parseEventKeyMinimumVersion,
} from "../../packages/event-key-lifecycle/index.js";
import { MAX_EVENT_KEY_VERSION } from "../../packages/event-store/index.js";
import { MacOSKeychainSecretStore } from "../../packages/secret-store/index.js";
import { errorCode, SecurityError } from "../../packages/shared/errors.js";

const EVENT_DIRECTORY = resolve(".local", "dashboard", "event-store");

async function main(): Promise<void> {
  const command = parseCommand(process.argv.slice(2));
  const minimumActiveKeyVersion = configuredMinimumVersion();
  const options = {
    directory: EVENT_DIRECTORY,
    secrets: new MacOSKeychainSecretStore(),
    keyReference: (version: number) =>
      `keychain://bugbounty-copilot/event-store-v${String(version)}`,
    minimumActiveKeyVersion,
  };

  if (command.kind === "initialize") {
    const lifecycle = await EventKeyLifecycle.initializeFresh(options);
    writeState(lifecycle.status());
    return;
  }
  if (command.kind === "adopt_legacy_v1") {
    const lifecycle = await EventKeyLifecycle.adoptLegacyV1(options);
    writeState(lifecycle.status());
    return;
  }
  if (command.kind === "recover_stale_mutation") {
    const receipt = await EventKeyLifecycle.recoverStaleMutation(options);
    writeState(receipt);
    return;
  }

  const lifecycle = await EventKeyLifecycle.open(options);
  if (command.kind === "status") {
    writeState(lifecycle.status());
    return;
  }
  const receipt = await lifecycle.rotate({
    expectedActiveKeyVersion: command.expectedActiveKeyVersion,
    nextKeyVersion: command.nextKeyVersion,
  });
  writeState({
    ...receipt,
    requiredMinimumVersionAfterRestart: receipt.activeKeyVersion,
  });
}

type AdminCommand =
  | { readonly kind: "status" }
  | { readonly kind: "initialize" }
  | { readonly kind: "adopt_legacy_v1" }
  | { readonly kind: "recover_stale_mutation" }
  | {
      readonly kind: "rotate";
      readonly expectedActiveKeyVersion: number;
      readonly nextKeyVersion: number;
    };

function parseCommand(args: readonly string[]): AdminCommand {
  if (args.length === 1 && args[0] === "status")
    return Object.freeze({ kind: "status" });
  if (
    args.length === 2 &&
    args[0] === "initialize" &&
    args[1] === "--confirm-local-event-key-initialize"
  )
    return Object.freeze({ kind: "initialize" });
  if (
    args.length === 2 &&
    args[0] === "adopt-legacy-v1" &&
    args[1] === "--confirm-local-legacy-adoption"
  )
    return Object.freeze({ kind: "adopt_legacy_v1" });
  if (
    args.length === 2 &&
    args[0] === "recover-stale-mutation" &&
    args[1] === "--confirm-local-stale-event-key-recovery"
  )
    return Object.freeze({ kind: "recover_stale_mutation" });
  if (
    args.length === 6 &&
    args[0] === "rotate" &&
    args[1] === "--expected" &&
    args[3] === "--next" &&
    args[5] === "--confirm-local-event-key-rotation"
  ) {
    const expectedActiveKeyVersion = parseVersion(args[2]);
    const nextKeyVersion = parseVersion(args[4]);
    return Object.freeze({
      kind: "rotate",
      expectedActiveKeyVersion,
      nextKeyVersion,
    });
  }
  throw new SecurityError("EVENT_KEY_ADMIN_USAGE_INVALID");
}

function configuredMinimumVersion(): number {
  return parseEventKeyMinimumVersion(
    process.env["BUGBOUNTY_EVENT_KEY_MIN_VERSION"],
  );
}

function parseVersion(value: string | undefined): number {
  if (value === undefined || !/^[1-9][0-9]{0,4}$/u.test(value))
    throw new SecurityError("EVENT_KEY_VERSION_INVALID");
  const version = Number(value);
  if (!Number.isSafeInteger(version) || version > MAX_EVENT_KEY_VERSION)
    throw new SecurityError("EVENT_KEY_VERSION_INVALID");
  return version;
}

function writeState(state: object): void {
  process.stdout.write(`${JSON.stringify(state, null, 2)}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${errorCode(error)}\n`);
  process.exitCode = 1;
});
