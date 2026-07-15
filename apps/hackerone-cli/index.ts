import { resolve } from "node:path";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  HackerOneCredentialVault,
  HackerOneHttpsTransport,
  HackerOneMetadataStore,
  HackerOneReadOnlyClient,
  MacOSHackerOneKeychainMutationBackend,
  resolveHackerOneMetadataReadRuntime,
} from "../../packages/hackerone-readonly/index.js";
import { HackerOneMetadataActionGate } from "../../packages/external-actions/index.js";
import { errorCode, SecurityError } from "../../packages/shared/errors.js";

async function main(): Promise<void> {
  if (!process.stdin.isTTY || !process.stdout.isTTY)
    throw new SecurityError("HACKERONE_MANUAL_TTY_REQUIRED");
  const runtime = resolveHackerOneMetadataReadRuntime({
    version: 1,
    capability: "HACKERONE_METADATA_READ",
    external_integrations_enabled:
      process.env["BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED"] === "true",
    enabled: process.env["BUGBOUNTY_HACKERONE_READONLY_ENABLED"] === "true",
    request_budget: {
      max_requests_total: 1,
      requests_per_minute: 1,
      max_concurrency: 1,
    },
  });
  if (!runtime.enabled)
    throw new SecurityError("HACKERONE_METADATA_CAPABILITY_DISABLED");

  const database = await ControlPlaneDatabase.file(
    resolve(".local", "dashboard", "control-plane.sqlite"),
  );
  try {
    const controlPlane = new ControlPlaneStore(database);
    const metadata = new HackerOneMetadataStore(database);
    const actionGate = new HackerOneMetadataActionGate(
      database,
      controlPlane,
      runtime,
    );
    const keychain = new MacOSHackerOneKeychainMutationBackend();
    const credentials = new HackerOneCredentialVault(keychain, keychain);
    const client = new HackerOneReadOnlyClient({
      runtime,
      credentials,
      transport: new HackerOneHttpsTransport(),
      actionGate,
      audit: (event) => {
        metadata.recordRequestAudit(event);
      },
    });
    const result = await client.connectionTest(new AbortController().signal);
    process.stdout.write(
      [
        result.result === "connected"
          ? "Verbindung erfolgreich"
          : "Verbindung blockiert oder fehlgeschlagen",
        `Anzahl empfangener Datensätze: ${String(result.recordCount)}`,
        `Schema gültig: ${result.schemaValid ? "ja" : "nein"}`,
        `Dauer: ${String(result.durationMs)} ms`,
        `Redigierter Status: ${result.redactedStatus}`,
      ].join("\n") + "\n",
    );
    if (result.result !== "connected") process.exitCode = 1;
  } finally {
    database.close();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${errorCode(error)}\n`);
  process.exitCode = 1;
});
