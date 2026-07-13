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
import { MacOSKeychainSecretStore } from "../../packages/secret-store/index.js";
import { errorCode } from "../../packages/shared/errors.js";

async function main(): Promise<void> {
  const runtimeRoot = resolve(".local", "dashboard");
  await mkdir(runtimeRoot, { recursive: true, mode: 0o700 });
  const database = await ControlPlaneDatabase.file(
    resolve(runtimeRoot, "control-plane.sqlite"),
  );
  const store = new ControlPlaneStore(database);
  store.setKillSwitch(
    true,
    `system-startup-${String(process.pid)}`,
    new Date().toISOString(),
  );
  const demo = new DemoSaas(() => new Date());
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
    const simulation = new SimulationOrchestrator(
      store,
      demo,
      resolve(runtimeRoot, "event-store"),
      new MacOSKeychainSecretStore(),
      (version) =>
        `keychain://bugbounty-copilot/event-store-v${String(version)}`,
      () => new Date(),
    );
    dashboardServer = await startDashboardServer(
      { store, demo, simulation, now: () => new Date() },
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

main().catch((error: unknown) => {
  process.stderr.write(`${errorCode(error)}\n`);
  process.exitCode = 1;
});
