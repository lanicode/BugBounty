import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../../packages/control-plane/index.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  campaign,
  controlPlanePolicy,
  identity,
  LATER,
  NOW,
  ownedObject,
  programInput,
} from "../../fixtures/control-plane.factory.js";

describe("ControlPlaneStore", () => {
  let database: ControlPlaneDatabase;
  let store: ControlPlaneStore;

  beforeEach(() => {
    database = ControlPlaneDatabase.memory();
    store = new ControlPlaneStore(database);
  });

  afterEach(() => {
    database.close();
  });

  function seedPolicy(): ReturnType<typeof controlPlanePolicy> {
    store.createProgram(programInput(), NOW);
    const policy = controlPlanePolicy();
    store.addPolicyVersion({
      programId: "program-local",
      version: 1,
      policy,
      createdAt: NOW,
    });
    return policy;
  }

  it("stores programs and immutable, explicitly accepted policies", () => {
    const policy = seedPolicy();
    expect(store.getProgram("program-local")?.ruleAcceptanceStatus).toBe(
      "pending",
    );
    const accepted = store.acceptPolicy({
      programId: "program-local",
      version: 1,
      expectedPolicyHash: policy.policyHash,
      acceptedBy: "local-reviewer",
      acceptedAt: LATER,
      auditReference: "audit:policy-1",
    });
    expect(accepted.acceptance?.acceptedBy).toBe("local-reviewer");
    expect(store.getProgram("program-local")?.ruleAcceptanceStatus).toBe(
      "accepted",
    );
    expect(() =>
      store.acceptPolicy({
        programId: "program-local",
        version: 1,
        expectedPolicyHash: policy.policyHash,
        acceptedBy: "local-reviewer",
        acceptedAt: LATER,
        auditReference: "audit:policy-replay",
      }),
    ).toThrow();
  });

  it("rejects an acceptance bound to the wrong hash", () => {
    seedPolicy();
    expect(() =>
      store.acceptPolicy({
        programId: "program-local",
        version: 1,
        expectedPolicyHash: "f".repeat(64),
        acceptedBy: "local-reviewer",
        acceptedAt: LATER,
        auditReference: "audit:wrong",
      }),
    ).toThrow("POLICY_ACCEPTANCE_HASH_MISMATCH");
  });

  it("uses optimistic revisions for campaign updates", () => {
    seedPolicy();
    store.insertCampaign(campaign());
    store.updateCampaign(
      0,
      campaign({ revision: 1, state: "awaiting_campaign_approval" }),
    );
    expect(() =>
      store.updateCampaign(0, campaign({ revision: 1, state: "cancelled" })),
    ).toThrow("CAMPAIGN_REVISION_CONFLICT");
  });

  it("stores only secret references for identities", () => {
    seedPolicy();
    store.insertIdentity(identity());
    expect(store.listIdentities()).toHaveLength(1);
    expect(() =>
      store.insertIdentity({
        ...identity(),
        id: "identity-secret",
        secretReferences: ["plaintext-password"],
      }),
    ).toThrow("IDENTITY_SECRET_REFERENCE_INVALID");
  });

  it("validates ownership across campaign, account, policy, action, and expiry", () => {
    const policy = seedPolicy();
    store.insertCampaign(campaign());
    store.insertIdentity(identity());
    store.insertOwnedObject(ownedObject({ policyHash: policy.policyHash }));
    expect(
      store.assertOwnedObject({
        objectRef: "object-local",
        campaignId: "campaign-local",
        accountId: "identity-owner",
        policyHash: policy.policyHash,
        action: "offline_inspect",
        now: NOW,
      }).researcherControlled,
    ).toBe(true);
    const base = {
      objectRef: "object-local",
      campaignId: "campaign-local",
      accountId: "identity-owner",
      policyHash: policy.policyHash,
      action: "offline_inspect",
      now: NOW,
    };
    expect(() =>
      store.assertOwnedObject({ ...base, objectRef: "unknown" }),
    ).toThrow("CONTROL_PLANE_OBJECT_UNKNOWN");
    expect(() =>
      store.assertOwnedObject({ ...base, campaignId: "campaign-other" }),
    ).toThrow("CONTROL_PLANE_OBJECT_CAMPAIGN_MISMATCH");
    expect(() =>
      store.assertOwnedObject({ ...base, policyHash: "f".repeat(64) }),
    ).toThrow("CONTROL_PLANE_OBJECT_POLICY_MISMATCH");
    expect(() => store.assertOwnedObject({ ...base, action: "write" })).toThrow(
      "CONTROL_PLANE_OBJECT_ACTION_BLOCKED",
    );
    expect(() =>
      store.assertOwnedObject({ ...base, now: "2026-07-15T00:00:00.000Z" }),
    ).toThrow("CONTROL_PLANE_OBJECT_EXPIRED");
  });

  it("keeps the persistent kill switch fail closed and records reports as drafts only", () => {
    const policy = seedPolicy();
    store.insertCampaign(campaign({ policyHash: policy.policyHash }));
    expect(store.isKillSwitchActive()).toBe(true);
    expect(store.setKillSwitch(false, "local-reviewer", NOW).active).toBe(
      false,
    );
    expect(store.isKillSwitchActive()).toBe(false);
    store.setKillSwitch(true, "local-reviewer", LATER);
    expect(store.isKillSwitchActive()).toBe(true);
    store.setKillSwitch(
      false,
      "local-reviewer",
      "2026-07-13T14:00:00.000Z",
    );
    expect(() =>
      store.setKillSwitch(true, "local-reviewer", LATER),
    ).toThrow("KILL_SWITCH_AUDIT_FAILED");
    expect(store.isKillSwitchActive()).toBe(true);
    const report = store.insertReportDraft({
      id: "report-local",
      campaignId: "campaign-local",
      title: "Simulation observation",
      summary: "Mock data only",
      createdAt: LATER,
      status: "queued_for_human_review",
      externalSubmissionPerformed: false,
    });
    expect(report.externalSubmissionPerformed).toBe(false);
  });

  it("treats a kill-switch read failure as engaged", () => {
    database.close();
    expect(store.isKillSwitchActive()).toBe(true);
    database = ControlPlaneDatabase.memory();
    store = new ControlPlaneStore(database);
  });
});
