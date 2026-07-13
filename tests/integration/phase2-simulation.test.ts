import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import { DemoSaas } from "../../packages/demo-saas/index.js";
import {
  SimulationOrchestrator,
  type HumanSimulationEvidence,
} from "../../packages/simulation/index.js";

const NOW = "2026-07-13T12:00:00.000Z";
const databases: ControlPlaneDatabase[] = [];

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  vi.restoreAllMocks();
});

function evidence(): HumanSimulationEvidence {
  return {
    version: 1,
    actor: "local-e2e-reviewer",
    confirmedAt: NOW,
    confirmations: {
      clearKillSwitch: true,
      acceptPolicyV1: true,
      approveCampaignV1: true,
      acceptPolicyV2: true,
      approveCampaignV2: true,
      queueReportReview: true,
    },
  };
}

async function setup() {
  const database = ControlPlaneDatabase.memory();
  databases.push(database);
  const store = new ControlPlaneStore(database);
  const directory = await mkdtemp(join(tmpdir(), "bbc-simulation-"));
  const orchestrator = new SimulationOrchestrator(
    store,
    new DemoSaas(() => new Date(NOW)),
    directory,
    () => new Date(NOW),
  );
  return { store, directory, orchestrator };
}

describe("Phase 2 complete local simulation", () => {
  it("executes the reproducible 18-step flow with zero external actions", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const { store, directory, orchestrator } = await setup();
    const summary = await orchestrator.run(evidence());

    expect(summary).toMatchObject({
      mode: "simulation",
      externalIntegrationsEnabled: false,
      networkConnections: 0,
      externalSubmissions: 0,
      campaignState: "running_simulation",
      policyVersions: 2,
      identities: 3,
      ownedObjects: 1,
      encryptedEvents: 3,
      openApprovals: 1,
      reportDrafts: 1,
    });
    expect(summary.steps).toEqual([
      "mock_program_imported",
      "policy_v1_displayed",
      "policy_v1_human_accepted",
      "campaign_contract_created",
      "campaign_human_approved",
      "mock_identities_created",
      "mock_organization_ready",
      "mock_objects_created",
      "ownership_ledger_updated",
      "encrypted_events_recorded",
      "policy_drift_simulated",
      "campaign_auto_paused",
      "policy_v2_diff_displayed",
      "policy_v2_human_accepted",
      "simulation_resumed",
      "report_draft_created",
      "report_approval_queued",
      "external_submission_not_performed",
    ]);
    expect(store.listPolicies("program-local-demo")).toHaveLength(2);
    expect(
      store
        .listPolicies("program-local-demo")
        .every((policy) => policy.acceptance !== null),
    ).toBe(true);
    expect(store.listCampaigns()).toMatchObject([
      { state: "running_simulation", policyVersion: 2 },
    ]);
    expect(store.listIdentities().map((identity) => identity.role)).toEqual([
      "External",
      "Member",
      "Owner",
    ]);
    expect(
      store.listApprovals().filter(({ status }) => status === "open"),
    ).toMatchObject([{ kind: "report_bundle", id: "report-review-approval" }]);
    expect(store.listReportDrafts()).toMatchObject([
      { externalSubmissionPerformed: false },
    ]);
    expect(fetchSpy).not.toHaveBeenCalled();

    const eventFiles = (await readdir(directory)).sort();
    expect(eventFiles).toHaveLength(3);
    for (const file of eventFiles) {
      const envelope = await readFile(join(directory, file), "utf8");
      expect(envelope).toContain('"ciphertext"');
      expect(envelope).not.toContain("PROGRAM_IMPORTED");
      expect(envelope).not.toContain("owned-object-001");
    }
  });

  it("fails closed before changing state when human evidence is missing or manipulated", async () => {
    const { store, orchestrator } = await setup();
    await expect(orchestrator.run(undefined)).rejects.toThrow(
      "SIMULATION_EVIDENCE_INVALID",
    );
    await expect(
      orchestrator.run({
        ...evidence(),
        confirmations: {
          ...evidence().confirmations,
          approveCampaignV2: false,
        },
      }),
    ).rejects.toThrow("SIMULATION_EVIDENCE_INVALID");
    await expect(
      orchestrator.run({ ...evidence(), unexpected: "field" }),
    ).rejects.toThrow("SIMULATION_EVIDENCE_INVALID");
    expect(store.listPrograms()).toHaveLength(0);
    expect(store.isKillSwitchActive()).toBe(true);
  });

  it("does not replay a completed simulation into existing state", async () => {
    const { orchestrator } = await setup();
    await orchestrator.run(evidence());
    await expect(orchestrator.run(evidence())).rejects.toThrow(
      "SIMULATION_REQUIRES_FRESH_STATE",
    );
  });

  it("stops before the next step when the persistent kill switch engages", async () => {
    const database = ControlPlaneDatabase.memory();
    databases.push(database);
    const store = new ControlPlaneStore(database);
    const directory = await mkdtemp(join(tmpdir(), "bbc-simulation-kill-"));
    let demoClockCalls = 0;
    const demo = new DemoSaas(() => {
      demoClockCalls += 1;
      if (demoClockCalls === 1)
        store.setKillSwitch(
          true,
          "local-kill-reviewer",
          "2026-07-13T12:01:00.000Z",
        );
      return new Date(NOW);
    });
    const orchestrator = new SimulationOrchestrator(
      store,
      demo,
      directory,
      () => new Date(NOW),
    );

    await expect(orchestrator.run(evidence())).rejects.toThrow(
      "SIMULATION_KILL_SWITCH",
    );
    expect(store.isKillSwitchActive()).toBe(true);
    expect(store.listOwnedObjects()).toHaveLength(0);
    expect(store.listReportDrafts()).toHaveLength(0);
  });
});
