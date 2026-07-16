import { resolve } from "node:path";
import { resolveMacOSEventKeyAdminSecretStore } from "../../packages/secret-store/index.js";
import { errorCode } from "../../packages/shared/errors.js";
import { runEventKeyAdminCommand } from "./command.js";

const EVENT_DIRECTORY = resolve(".local", "dashboard", "event-store");

async function main(): Promise<void> {
  writeState(
    await runEventKeyAdminCommand({
      args: process.argv.slice(2),
      minimumActiveKeyVersion: process.env["BUGBOUNTY_EVENT_KEY_MIN_VERSION"],
      eventDirectory: EVENT_DIRECTORY,
      secrets: resolveMacOSEventKeyAdminSecretStore,
    }),
  );
}

function writeState(state: object): void {
  process.stdout.write(`${JSON.stringify(state, null, 2)}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${errorCode(error)}\n`);
  process.exitCode = 1;
});
