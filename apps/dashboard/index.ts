import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  startDashboardServer,
  type RunningDashboardServer,
} from "../../packages/dashboard/index.js";
import {
  DemoSaas,
  startDemoSaasServer,
  type RunningDemoSaasServer,
} from "../../packages/demo-saas/index.js";
import { SimulationOrchestrator } from "../../packages/simulation/index.js";
import {
  createKeychainOperatorSigner,
  type OperatorSigner,
} from "../../packages/operator-auth/index.js";
import {
  MacOSKeychainSecretStore,
  type SecretStore,
} from "../../packages/secret-store/index.js";
import { errorCode } from "../../packages/shared/errors.js";

async function main(): Promise<void> {
  const runtimeRoot = resolve(".local", "dashboard");
  await mkdir(runtimeRoot, { recursive: true, mode: 0o700 });
  const database = await ControlPlaneDatabase.file(
    resolve(runtimeRoot, "control-plane.sqlite"),
  );
  const clock = (): Date => new Date();
  const store = new ControlPlaneStore(database, clock);
  store.setKillSwitch(
    true,
    `system-startup-${String(process.pid)}`,
    new Date().toISOString(),
  );
  const demo = new DemoSaas(clock);
  let demoServer: RunningDemoSaasServer | undefined;
  let dashboardServer: RunningDashboardServer | undefined;
  let closing = false;

  const close = async (): Promise<void> => {
    if (closing) return;
    closing = true;
    await Promise.all([
      dashboardServer?.close() ?? Promise.resolve(),
      demoServer?.close() ?? Promise.resolve(),
    ]);
    database.close();
  };

  try {
    demoServer = await startDemoSaasServer(demo, 0);
    const secretStore = new MacOSKeychainSecretStore();
    const operatorSigner = await configuredOperatorSigner(secretStore);
    const simulation = new SimulationOrchestrator(
      store,
      demo,
      resolve(runtimeRoot, "event-store"),
      secretStore,
      (version) =>
        `keychain://bugbounty-copilot/event-store-v${String(version)}`,
      clock,
      operatorSigner,
    );
    dashboardServer = await startDashboardServer(
      {
        store,
        demo,
        simulation,
        ...(operatorSigner === undefined ? {} : { operatorSigner }),
        now: clock,
      },
      4173,
    );
    process.stdout.write(
      [
        "Bug Bounty Copilot läuft ausschließlich lokal.",
        `Dashboard: ${dashboardServer.origin}`,
        `Demo-SaaS: ${demoServer.origin}`,
        "SIMULATIONSMODUS · EXTERNE INTEGRATIONEN DEAKTIVIERT",
      ].join("\n") + "\n",
    );
    const shutdown = (): void => {
      void close()
        .then(() => {
          process.exitCode = 0;
        })
        .catch(() => {
          process.exitCode = 1;
        });
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  } catch (error) {
    await close().catch(() => undefined);
    throw error;
  }
}

async function configuredOperatorSigner(
  secretStore: SecretStore,
): Promise<OperatorSigner | undefined> {
  const keyReference = process.env["BUGBOUNTY_OPERATOR_KEY_REFERENCE"];
  const operatorId = process.env["BUGBOUNTY_OPERATOR_ID"];
  const revisionText = process.env["BUGBOUNTY_OPERATOR_KEY_REVISION"];
  if (
    keyReference === undefined &&
    operatorId === undefined &&
    revisionText === undefined
  )
    return undefined;
  if (
    keyReference === undefined ||
    operatorId === undefined ||
    revisionText === undefined ||
    !/^[1-9][0-9]*$/u.test(revisionText)
  )
    throw new Error("OPERATOR_SIGNER_CONFIG_INVALID");
  const keyRevision = Number(revisionText);
  if (!Number.isSafeInteger(keyRevision))
    throw new Error("OPERATOR_SIGNER_CONFIG_INVALID");
  return createKeychainOperatorSigner(secretStore, {
    keyReference,
    operatorId,
    keyRevision,
  });
}

main().catch((error: unknown) => {
  process.stderr.write(`${errorCode(error)}\n`);
  process.exitCode = 1;
});
