import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import { DemoSaas } from "../../packages/demo-saas/index.js";
import { SimulationOrchestrator } from "../../packages/simulation/index.js";
import { errorCode } from "../../packages/shared/errors.js";

async function main(): Promise<void> {
  const [command, confirmation, ...rest] = process.argv.slice(2);
  if (
    command !== "simulate" ||
    confirmation !== "--confirm-local-simulation" ||
    rest.length !== 0
  ) {
    process.stderr.write(
      "Usage: phase2-cli simulate --confirm-local-simulation\n",
    );
    process.exitCode = 2;
    return;
  }
  const now = new Date();
  const runtimeRoot = resolve(".local", "phase2-simulation");
  await mkdir(runtimeRoot, { recursive: true, mode: 0o700 });
  const database = ControlPlaneDatabase.memory();
  try {
    const summary = await new SimulationOrchestrator(
      new ControlPlaneStore(database),
      new DemoSaas(() => now),
      resolve(runtimeRoot, "event-store"),
      () => now,
    ).run({
      version: 1,
      actor: "local-cli-user",
      confirmedAt: now.toISOString(),
      confirmations: {
        clearKillSwitch: true,
        acceptPolicyV1: true,
        approveCampaignV1: true,
        acceptPolicyV2: true,
        approveCampaignV2: true,
        queueReportReview: true,
      },
    });
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  } finally {
    database.close();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${errorCode(error)}\n`);
  process.exitCode = 1;
});
