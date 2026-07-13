import { randomUUID } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import { DemoSaas } from "../../packages/demo-saas/index.js";
import {
  collectInteractiveSimulationEvidence,
  SimulationOrchestrator,
  type HumanSimulationEvidence,
} from "../../packages/simulation/index.js";
import { MacOSKeychainSecretStore } from "../../packages/secret-store/index.js";
import { errorCode, SecurityError } from "../../packages/shared/errors.js";

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
  if (!stdin.isTTY || !stdout.isTTY)
    throw new SecurityError("SIMULATION_INTERACTIVE_TTY_REQUIRED");
  const runtimeRoot = resolve(".local", "phase2-simulation", randomUUID());
  await mkdir(runtimeRoot, { recursive: true, mode: 0o700 });
  const database = ControlPlaneDatabase.memory();
  try {
    const orchestrator = new SimulationOrchestrator(
      new ControlPlaneStore(database),
      new DemoSaas(() => new Date()),
      resolve(runtimeRoot, "event-store"),
      new MacOSKeychainSecretStore(),
      (version) =>
        `keychain://bugbounty-copilot/event-store-v${String(version)}`,
      () => new Date(),
    );
    const review = orchestrator.preview();
    process.stdout.write(`Review-Paket:\n${JSON.stringify(review, null, 2)}\n`);
    const terminal = createInterface({ input: stdin, output: stdout });
    let evidence: HumanSimulationEvidence;
    try {
      evidence = await collectInteractiveSimulationEvidence({
        reviewDigest: review.reviewDigest,
        prompt: (message) => terminal.question(message),
        now: () => new Date(),
      });
    } finally {
      terminal.close();
    }
    const summary = await orchestrator.run(evidence);
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  } finally {
    database.close();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${errorCode(error)}\n`);
  process.exitCode = 1;
});
