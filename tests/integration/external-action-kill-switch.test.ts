import { afterEach, describe, expect, it } from "vitest";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  DeterministicSimulationGateEvaluator,
  DeterministicMockActionRunner,
  ExternalActionPipeline,
  Phase2KillSwitch,
} from "../../packages/external-actions/index.js";
import {
  resolvePhase2Runtime,
  SAFE_PHASE2_CONFIG,
} from "../../packages/phase2-config/index.js";

const databases: ControlPlaneDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
});

describe("persistent global kill switch composition", () => {
  it("blocks the action pipeline before clear, after dashboard-equivalent engage, and on read failure", async () => {
    const database = ControlPlaneDatabase.memory();
    databases.push(database);
    const store = new ControlPlaneStore(database);
    const runner = new DeterministicMockActionRunner({
      "proposal-persistent-kill": { ok: true },
    });
    const runtime = resolvePhase2Runtime(SAFE_PHASE2_CONFIG, {
      secretsAvailable: false,
      externalAdapterAvailable: false,
    });
    const proposal = {
      version: 1 as const,
      proposal_id: "proposal-persistent-kill",
      action_id: "platform_api_read",
      mode: "simulation" as const,
      parameters: {
        campaign_ref: "campaign-local",
        policy_hash_sha256: "a".repeat(64),
        scope_ref: "scope-local",
        account_ref: null,
        object_ref: null,
        payload_ref: null,
      },
    };
    const gates = new DeterministicSimulationGateEvaluator(proposal, {
      policy: true,
      scope: true,
      ownership: true,
      humanCheckpoint: true,
    });
    const pipeline = () =>
      new ExternalActionPipeline(
        runtime,
        runner,
        new Phase2KillSwitch({
          readActive: () => store.isKillSwitchActive(),
        }),
        gates,
      );

    await expect(pipeline().execute(proposal)).rejects.toThrow(
      "ACTION_KILL_SWITCH",
    );
    store.setKillSwitch(false, "local-reviewer", "2026-07-13T12:00:00.000Z");
    await expect(pipeline().execute(proposal)).resolves.toMatchObject({
      actionId: "platform_api_read",
    });
    store.setKillSwitch(true, "local-reviewer", "2026-07-13T12:01:00.000Z");
    await expect(pipeline().execute(proposal)).rejects.toThrow(
      "ACTION_KILL_SWITCH",
    );

    database.close();
    databases.splice(databases.indexOf(database), 1);
    await expect(pipeline().execute(proposal)).rejects.toThrow(
      "ACTION_KILL_SWITCH",
    );
  });
});
