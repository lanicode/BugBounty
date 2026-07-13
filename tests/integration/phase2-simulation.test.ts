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
import { canonicalJson, sha256 } from "../../packages/shared/canonical.js";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";

const NOW = "2026-07-13T12:00:00.000Z";
const databases: ControlPlaneDatabase[] = [];
const EVENT_KEY_REFERENCE = "secret://simulation/event-key";

function eventSecrets(): InMemorySecretStore {
  const secrets = new InMemorySecretStore();
  secrets.set(EVENT_KEY_REFERENCE, new Uint8Array(32).fill(7));
  return secrets;
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  vi.restoreAllMocks();
});

function evidence(
  orchestrator: SimulationOrchestrator,
): HumanSimulationEvidence {
  return {
    version: 2,
    actor: "local-e2e-reviewer",
    confirmedAt: NOW,
    reviewDigest: orchestrator.preview().reviewDigest,
    confirmations: {
      clearKillSwitch: true,
      acceptPolicyV1: true,
      approveCampaignV1: true,
      acceptPolicyV2: true,
      approveCampaignV2: true,
      queueReportReview: true,
    },
    confirmationTimes: {
      clearKillSwitch: "2026-07-13T11:59:54.000Z",
      acceptPolicyV1: "2026-07-13T11:59:55.000Z",
      approveCampaignV1: "2026-07-13T11:59:56.000Z",
      acceptPolicyV2: "2026-07-13T11:59:57.000Z",
      approveCampaignV2: "2026-07-13T11:59:58.000Z",
      queueReportReview: "2026-07-13T11:59:59.000Z",
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
    eventSecrets(),
    () => EVENT_KEY_REFERENCE,
    () => new Date(NOW),
  );
  return { store, directory, orchestrator };
}

describe("Phase 2 complete local simulation", () => {
  it("executes the reproducible 18-step flow with zero external actions", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const { store, directory, orchestrator } = await setup();
    const summary = await orchestrator.run(evidence(orchestrator));

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
    expect(
      store
        .listApprovals()
        .some(({ kind }) => kind === "account_manual_action"),
    ).toBe(false);
    expect(
      store.listIdentities().every(({ status }) => status === "ready"),
    ).toBe(true);
    const approvals = store.listApprovals();
    expect(
      approvals.find(({ id }) => id === "policy-v1-acceptance")?.decidedAt,
    ).toBe("2026-07-13T11:59:55.000Z");
    expect(
      approvals.find(({ id }) => id === "campaign-v1-approval")?.decidedAt,
    ).toBe("2026-07-13T11:59:56.000Z");
    expect(
      approvals.find(({ id }) => id === "policy-v2-acceptance")?.decidedAt,
    ).toBe("2026-07-13T11:59:57.000Z");
    expect(
      approvals.find(({ id }) => id === "campaign-v2-approval")?.decidedAt,
    ).toBe("2026-07-13T11:59:58.000Z");
    expect(
      store
        .listAuditEntries()
        .filter(({ action }) => action === "approval_decision"),
    ).toHaveLength(4);

    const eventFiles = (await readdir(directory)).sort();
    expect(eventFiles).toHaveLength(3);
    for (const file of eventFiles) {
      const envelope = await readFile(join(directory, file), "utf8");
      expect(envelope).toContain('"ciphertext"');
      expect(envelope).not.toContain("PROGRAM_IMPORTED");
      expect(envelope).not.toContain("owned-object-001");
    }
  });

  it("binds the complete visible campaign contracts and policies into the review digest", async () => {
    const { orchestrator } = await setup();
    const review = orchestrator.preview();
    expect(review.policyV1).toMatchObject({
      allowedAssets: ["demo.local.test"],
      excludedAssets: ["admin.demo.local.test"],
      allowedTestClasses: ["document.read", "project.read"],
      rules: ["no_external_submission", "simulation_only"],
    });
    expect(review.campaignV1).toMatchObject({
      accountRefs: [
        "identity-owner-001",
        "identity-member-001",
        "identity-external-001",
      ],
      allowedActionClasses: ["offline_simulation"],
      contract: {
        allowedHosts: ["demo.local.test"],
        excludedHosts: ["admin.demo.local.test"],
        allowedMethods: ["GET", "HEAD"],
        writeActionsAllowed: false,
        rollbackRequired: true,
      },
    });
    const { reviewDigest, ...document } = review;
    expect(reviewDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(review.campaignV1.approvalDigest).toMatch(/^[a-f0-9]{64}$/u);
    const validity =
      Date.parse(review.campaignV1.contract.validUntil) -
      Date.parse(review.campaignV1.contract.validFrom);
    expect(validity).toBeLessThanOrEqual(86_460_000);
    const changed = {
      ...document,
      campaignV1: {
        ...document.campaignV1,
        contract: {
          ...document.campaignV1.contract,
          allowedMethods: ["GET"],
        },
      },
    };
    expect(sha256(canonicalJson(changed))).not.toBe(reviewDigest);
    expect(orchestrator.preview()).toBe(review);
  });

  it("fails closed before changing state when human evidence is missing or manipulated", async () => {
    const { store, orchestrator } = await setup();
    await expect(orchestrator.run(undefined)).rejects.toThrow(
      "SIMULATION_EVIDENCE_INVALID",
    );
    await expect(
      orchestrator.run({
        ...evidence(orchestrator),
        confirmations: {
          ...evidence(orchestrator).confirmations,
          approveCampaignV2: false,
        },
      }),
    ).rejects.toThrow("SIMULATION_EVIDENCE_INVALID");
    await expect(
      orchestrator.run({ ...evidence(orchestrator), unexpected: "field" }),
    ).rejects.toThrow("SIMULATION_EVIDENCE_INVALID");
    await expect(
      orchestrator.run({
        ...evidence(orchestrator),
        reviewDigest: "f".repeat(64),
      }),
    ).rejects.toThrow("SIMULATION_REVIEW_DIGEST_MISMATCH");
    await expect(
      orchestrator.run({
        ...evidence(orchestrator),
        confirmationTimes: {
          ...evidence(orchestrator).confirmationTimes,
          approveCampaignV1: "2026-07-13T11:59:55.000Z",
        },
      }),
    ).rejects.toThrow("SIMULATION_EVIDENCE_INVALID");
    expect(store.listPrograms()).toHaveLength(0);
    expect(store.isKillSwitchActive()).toBe(true);
  });

  it("blocks before state changes when the event secret store is missing or fails", async () => {
    for (const secrets of [
      new InMemorySecretStore(),
      {
        get: () => Promise.reject(new Error("SECRET_STORE_FAILED")),
      },
    ]) {
      const database = ControlPlaneDatabase.memory();
      databases.push(database);
      const store = new ControlPlaneStore(database);
      const directory = await mkdtemp(join(tmpdir(), "bbc-simulation-secret-"));
      const orchestrator = new SimulationOrchestrator(
        store,
        new DemoSaas(() => new Date(NOW)),
        directory,
        secrets,
        () => EVENT_KEY_REFERENCE,
        () => new Date(NOW),
      );
      await expect(orchestrator.run(evidence(orchestrator))).rejects.toThrow(
        "SIMULATION_EVENT_SECRET_UNAVAILABLE",
      );
      expect(store.isKillSwitchActive()).toBe(true);
      expect(store.listPrograms()).toHaveLength(0);
    }
  });

  it("rejects demo-policy drift after review before any control-plane mutation", async () => {
    const database = ControlPlaneDatabase.memory();
    databases.push(database);
    const store = new ControlPlaneStore(database);
    const demo = new DemoSaas(() => new Date(NOW));
    const directory = await mkdtemp(join(tmpdir(), "bbc-simulation-stale-"));
    const orchestrator = new SimulationOrchestrator(
      store,
      demo,
      directory,
      eventSecrets(),
      () => EVENT_KEY_REFERENCE,
      () => new Date(NOW),
    );
    const confirmed = evidence(orchestrator);
    const reviewedHash = demo.snapshot().currentPolicy.contentHash;
    demo.simulatePolicyDrift({
      expectedPolicyHash: reviewedHash,
      rules: {
        requestLimit: 9,
        allowedActions: ["document.read"],
        prohibitedTestClasses: ["active_security_test", "write_test"],
      },
    });
    await expect(orchestrator.run(confirmed)).rejects.toThrow(
      "SIMULATION_REVIEW_STALE",
    );
    expect(store.isKillSwitchActive()).toBe(true);
    expect(store.listPrograms()).toHaveLength(0);
    expect(store.listApprovals()).toHaveLength(0);
  });

  it("does not replay a completed simulation into existing state", async () => {
    const { orchestrator } = await setup();
    await orchestrator.run(evidence(orchestrator));
    await expect(orchestrator.run(evidence(orchestrator))).rejects.toThrow(
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
      eventSecrets(),
      () => EVENT_KEY_REFERENCE,
      () => new Date(NOW),
    );

    await expect(orchestrator.run(evidence(orchestrator))).rejects.toThrow(
      "SIMULATION_KILL_SWITCH",
    );
    expect(store.isKillSwitchActive()).toBe(true);
    expect(store.listOwnedObjects()).toHaveLength(0);
    expect(store.listReportDrafts()).toHaveLength(0);
  });

  it("re-engages the persistent kill switch after a post-clear failure", async () => {
    const { store, orchestrator } = await setup();
    store.createProgram(
      {
        id: "program-local-demo",
        name: "Conflicting local fixture",
        platform: "local_mock",
        status: "available",
        description: "Forces a deterministic post-clear conflict",
        programUrl: "http://127.0.0.1/local-metadata-only",
        programType: "simulation",
        allowedAssets: ["demo.local.test"],
        excludedAssets: ["admin.demo.local.test"],
        lastSynchronizedAt: NOW,
        automationPermission: "allowed",
        notes: "Never fetched",
        lifecycle: "active",
      },
      NOW,
    );
    await expect(orchestrator.run(evidence(orchestrator))).rejects.toThrow();
    expect(store.isKillSwitchActive()).toBe(true);
    expect(store.listCampaigns()).toHaveLength(0);
  });

  it("re-engages the persistent kill switch when the injected clock fails after clear", async () => {
    const database = ControlPlaneDatabase.memory();
    databases.push(database);
    const store = new ControlPlaneStore(database);
    const directory = await mkdtemp(join(tmpdir(), "bbc-simulation-clock-"));
    let calls = 0;
    const clock = (): Date => {
      calls += 1;
      if (calls >= 3) throw new Error("CLOCK_FAILED");
      return new Date(NOW);
    };
    const orchestrator = new SimulationOrchestrator(
      store,
      new DemoSaas(() => new Date(NOW)),
      directory,
      eventSecrets(),
      () => EVENT_KEY_REFERENCE,
      clock,
    );
    const confirmed = evidence(orchestrator);
    await expect(orchestrator.run(confirmed)).rejects.toThrow("CLOCK_FAILED");
    expect(store.isKillSwitchActive()).toBe(true);
  });
});
