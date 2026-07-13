import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../../packages/control-plane/index.js";
import { ApprovalQueue } from "../../../packages/control-plane/approval-queue.js";
import {
  campaignApprovalDigest,
  transitionCampaign,
  type CampaignEvent,
} from "../../../packages/control-plane/campaign-machine.js";
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

  function acceptSeededPolicy(
    policy: ReturnType<typeof controlPlanePolicy>,
  ): ReturnType<ControlPlaneStore["acceptPolicy"]> {
    if (store.isKillSwitchActive())
      store.setKillSwitch(false, "local-reviewer", NOW);
    const queue = new ApprovalQueue();
    const open = queue.enqueue({
      id: `policy-${policy.policyHash.slice(0, 12)}-approval`,
      kind: "program_policy_acceptance",
      summary: "Accept program-local policy version 1",
      technicalDetails: `Policy hash ${policy.policyHash}`,
      impact: "Allows deterministic local simulation only.",
      policyVersion: 1,
      policyHash: policy.policyHash,
      createdAt: NOW,
      auditReference: "audit:seed-policy",
    });
    store.persistApproval(open);
    store.decideApproval({
      id: open.id,
      expectedRevision: 0,
      expectedPayloadHash: open.payloadHash,
      decision: "accepted",
      actor: "local-reviewer",
      userAction: "explicit_policy_acceptance",
      at: LATER,
    });
    return store.acceptPolicy({
      programId: "program-local",
      version: 1,
      expectedPolicyHash: policy.policyHash,
      acceptedBy: "local-reviewer",
      acceptedAt: LATER,
      auditReference: "audit:seed-policy",
    });
  }

  function seedRunningCampaign(): ReturnType<typeof campaign> {
    const policy = seedPolicy();
    acceptSeededPolicy(policy);
    const draft = campaign({ policyHash: policy.policyHash });
    store.insertCampaign(draft);
    const awaiting = campaign({
      policyHash: policy.policyHash,
      state: "awaiting_campaign_approval",
      revision: 1,
    });
    store.updateCampaign(0, awaiting);
    const approvals = new ApprovalQueue();
    const open = approvals.enqueue({
      id: "campaign-local-approval",
      kind: "campaign_contract",
      summary: "Approve campaign-local",
      technicalDetails: `Policy ${policy.policyHash}; Campaign digest ${campaignApprovalDigest(awaiting)}; tier_0_offline only`,
      impact: "Allows deterministic local simulation only.",
      policyVersion: 1,
      policyHash: policy.policyHash,
      createdAt: NOW,
      auditReference: "audit:campaign-local-approval",
    });
    store.persistApproval(open);
    store.decideApproval({
      id: open.id,
      expectedRevision: 0,
      expectedPayloadHash: open.payloadHash,
      decision: "accepted",
      actor: "local-reviewer",
      userAction: "explicit_local_campaign_v1_approval",
      at: LATER,
    });
    const approved = campaign({
      policyHash: policy.policyHash,
      state: "approved",
      revision: 2,
      humanApprovedBy: "local-reviewer",
      humanApprovedAt: LATER,
    });
    store.updateCampaign(1, approved);
    const running = campaign({
      policyHash: policy.policyHash,
      state: "running_simulation",
      revision: 3,
      humanApprovedBy: "local-reviewer",
      humanApprovedAt: LATER,
      lastPolicyCheckAt: LATER,
    });
    store.updateCampaign(2, running);
    return running;
  }

  it("stores programs and immutable, explicitly accepted policies", () => {
    const policy = seedPolicy();
    expect(store.getProgram("program-local")?.ruleAcceptanceStatus).toBe(
      "pending",
    );
    const accepted = acceptSeededPolicy(policy);
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
        auditReference: "audit:seed-policy",
      }),
    ).toThrow();
  });

  it("rejects an acceptance bound to the wrong hash", () => {
    seedPolicy();
    store.setKillSwitch(false, "local-reviewer", NOW);
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

  it("requires a persisted accepted approval before policy acceptance", () => {
    const policy = seedPolicy();
    store.setKillSwitch(false, "local-reviewer", NOW);
    expect(() =>
      store.acceptPolicy({
        programId: "program-local",
        version: 1,
        expectedPolicyHash: policy.policyHash,
        acceptedBy: "local-reviewer",
        acceptedAt: LATER,
        auditReference: "audit:missing-policy-approval",
      }),
    ).toThrow("POLICY_ACCEPTANCE_EVIDENCE_REQUIRED");
  });

  it("rejects non-sequential and chronologically older policy versions", () => {
    seedPolicy();
    const next = controlPlanePolicy("Next local simulation policy");
    expect(() =>
      store.addPolicyVersion({
        programId: "program-local",
        version: 3,
        policy: next,
        createdAt: LATER,
      }),
    ).toThrow("POLICY_VERSION_NOT_SEQUENTIAL");
    expect(() =>
      store.addPolicyVersion({
        programId: "program-local",
        version: 2,
        policy: next,
        createdAt: "2026-07-13T11:59:59.000Z",
      }),
    ).toThrow("POLICY_VERSION_ORDER_INVALID");
    expect(store.getProgram("program-local")?.currentPolicyVersion).toBe(1);
  });

  it("uses optimistic revisions for campaign updates", () => {
    const policy = seedPolicy();
    acceptSeededPolicy(policy);
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
    const running = seedRunningCampaign();
    store.insertIdentity(identity());
    expect(() =>
      store.insertOwnedObject(
        ownedObject({
          objectRef: "object-write",
          protectedActualIdRef: "protected-ref:object-write",
          canaryHmac: "b".repeat(64),
          allowedActions: ["write"],
        }),
      ),
    ).toThrow("OWNED_OBJECT_INVALID");
    store.insertOwnedObject(ownedObject({ policyHash: running.policyHash }));
    expect(
      store.assertOwnedObject({
        objectRef: "object-local",
        campaignId: "campaign-local",
        accountId: "identity-owner",
        policyHash: running.policyHash,
        action: "offline_inspect",
        now: NOW,
      }).researcherControlled,
    ).toBe(true);
    const base = {
      objectRef: "object-local",
      campaignId: "campaign-local",
      accountId: "identity-owner",
      policyHash: running.policyHash,
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
    database.run(
      "UPDATE owned_objects SET allowed_actions_json=? WHERE object_ref=?",
      '["write"]',
      "object-local",
    );
    expect(() => store.assertOwnedObject({ ...base, action: "write" })).toThrow(
      "OWNED_OBJECT_INVALID",
    );
  });

  it("blocks active campaign insertion, hash mismatch, and invalid transitions", () => {
    const policy = seedPolicy();
    expect(() =>
      store.insertCampaign(
        campaign({ state: "running_simulation", revision: 3 }),
      ),
    ).toThrow("CAMPAIGN_INSERT_STATE_INVALID");
    expect(() =>
      store.insertCampaign(
        campaign({
          policyHash: "f".repeat(64),
          contract: {
            ...campaign().contract,
            policyHash: "f".repeat(64),
          },
        }),
      ),
    ).toThrow("CAMPAIGN_POLICY_HASH_MISMATCH");
    acceptSeededPolicy(policy);
    store.insertCampaign(campaign());
    store.updateCampaign(
      0,
      campaign({ state: "awaiting_campaign_approval", revision: 1 }),
    );
    expect(() =>
      store.updateCampaign(
        1,
        campaign({
          state: "approved",
          revision: 2,
          humanApprovedBy: "local-reviewer",
          humanApprovedAt: LATER,
        }),
      ),
    ).toThrow("CAMPAIGN_APPROVAL_EVIDENCE_REQUIRED");
  });

  it("automatically pauses active campaigns when a new policy version arrives", () => {
    seedRunningCampaign();
    const next = controlPlanePolicy("Changed local simulation policy");
    store.addPolicyVersion({
      programId: "program-local",
      version: 2,
      policy: next,
      createdAt: "2026-07-13T14:00:00.000Z",
    });
    expect(store.getCampaign("campaign-local")).toMatchObject({
      state: "paused",
      revision: 4,
      humanApprovedBy: null,
      humanApprovedAt: null,
      lastPolicyCheckAt: "2026-07-13T14:00:00.000Z",
    });
  });

  it("rejects raw active campaign rows without relational approval evidence", () => {
    const policy = seedPolicy();
    store.insertCampaign(campaign({ policyHash: policy.policyHash }));
    database.run(
      `UPDATE campaigns SET state='running_simulation',revision=3,
       human_approved_by=NULL,human_approved_at=NULL,
       last_policy_check_at=?,kill_switch_status='engaged'
       WHERE id='campaign-local'`,
      LATER,
    );
    expect(() => store.getCampaign("campaign-local")).toThrow(
      "CAMPAIGN_POLICY_NOT_ACCEPTED",
    );
    expect(() => store.listCampaigns()).toThrow("CAMPAIGN_POLICY_NOT_ACCEPTED");
  });

  it("rejects a raw policy acceptance without exact approval evidence", () => {
    const policy = seedPolicy();
    database.run(
      `INSERT INTO policy_acceptances(
        program_id,version,policy_hash,accepted_by,accepted_at,audit_reference
       ) VALUES(?,?,?,?,?,?)`,
      "program-local",
      1,
      policy.policyHash,
      "local-reviewer",
      LATER,
      "audit:forged-policy-acceptance",
    );
    expect(() => store.getPolicy("program-local", 1)).toThrow(
      "POLICY_ACCEPTANCE_EVIDENCE_INVALID",
    );
  });

  it("does not resume a paused campaign against a stale policy", () => {
    seedRunningCampaign();
    store.addPolicyVersion({
      programId: "program-local",
      version: 2,
      policy: controlPlanePolicy("Drifted local policy"),
      createdAt: "2026-07-13T14:00:00.000Z",
    });
    const paused = store.getCampaign("campaign-local");
    if (paused === undefined) throw new Error("MISSING_CAMPAIGN");
    expect(() =>
      store.updateCampaign(paused.revision, {
        ...paused,
        state: "awaiting_campaign_approval",
        revision: paused.revision + 1,
      }),
    ).toThrow("CAMPAIGN_POLICY_STALE");
  });

  it("rejects account-set mutation and policy budget escalation", () => {
    const running = seedRunningCampaign();
    expect(() =>
      store.updateCampaign(running.revision, {
        ...running,
        accountRefs: [...running.accountRefs, "identity-late"],
        state: "paused",
        revision: running.revision + 1,
        humanApprovedBy: null,
        humanApprovedAt: null,
      }),
    ).toThrow("CAMPAIGN_CONTRACT_MUTATION_BLOCKED");

    database.close();
    database = ControlPlaneDatabase.memory();
    store = new ControlPlaneStore(database);
    const policy = seedPolicy();
    acceptSeededPolicy(policy);
    expect(() =>
      store.insertCampaign(
        campaign({
          contract: {
            ...campaign().contract,
            maxRequests: 21,
          },
        }),
      ),
    ).toThrow("CAMPAIGN_POLICY_BUDGET_EXCEEDED");
  });

  it("rejects stale-policy, cross-program, and non-ready ownership bindings", () => {
    const running = seedRunningCampaign();
    store.insertIdentity(identity());
    store.createProgram(
      { ...programInput(), id: "program-other", name: "Other local program" },
      NOW,
    );
    store.insertIdentity({
      ...identity(),
      id: "identity-other",
      programId: "program-other",
      ownedObjectRefs: ["object-cross-program"],
    });
    expect(() =>
      store.insertOwnedObject(
        ownedObject({
          objectRef: "object-cross-program",
          protectedActualIdRef: "protected-ref:object-cross-program",
          canaryHmac: "d".repeat(64),
          accountId: "identity-other",
        }),
      ),
    ).toThrow("CONTROL_PLANE_OBJECT_PROGRAM_MISMATCH");
    store.insertIdentity({
      ...identity(),
      id: "identity-suspended",
      status: "suspended",
      humanActionRequired: true,
      suspendedAt: LATER,
      ownedObjectRefs: ["object-suspended"],
    });
    expect(() =>
      store.insertOwnedObject(
        ownedObject({
          objectRef: "object-suspended",
          protectedActualIdRef: "protected-ref:object-suspended",
          canaryHmac: "e".repeat(64),
          accountId: "identity-suspended",
        }),
      ),
    ).toThrow("CONTROL_PLANE_OBJECT_ACCOUNT_BINDING_INVALID");
    expect(() =>
      store.insertOwnedObject(
        ownedObject({ researcherControlled: false as true }),
      ),
    ).toThrow("OWNED_OBJECT_INVALID");
    expect(() =>
      store.insertOwnedObject(ownedObject({ policyHash: "f".repeat(64) })),
    ).toThrow("CONTROL_PLANE_OBJECT_CAMPAIGN_BINDING_INVALID");

    store.insertOwnedObject(ownedObject({ policyHash: running.policyHash }));
    const next = controlPlanePolicy("Ownership policy drift");
    store.addPolicyVersion({
      programId: "program-local",
      version: 2,
      policy: next,
      createdAt: "2026-07-13T14:00:00.000Z",
    });
    expect(() =>
      store.assertOwnedObject({
        objectRef: "object-local",
        campaignId: "campaign-local",
        accountId: "identity-owner",
        policyHash: running.policyHash,
        action: "offline_inspect",
        now: NOW,
      }),
    ).toThrow("CONTROL_PLANE_OBJECT_CAMPAIGN_BINDING_INVALID");
    expect(() =>
      store.assertOwnedObject({
        objectRef: "object-local",
        campaignId: "campaign-local",
        accountId: "identity-owner",
        policyHash: running.policyHash,
        action: "offline_inspect",
        now: "not-a-time",
      }),
    ).toThrow("CONTROL_PLANE_OBJECT_TIME_INVALID");
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
    store.setKillSwitch(false, "local-reviewer", "2026-07-13T14:00:00.000Z");
    expect(() => store.setKillSwitch(true, "local-reviewer", LATER)).toThrow(
      "KILL_SWITCH_AUDIT_FAILED",
    );
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

  it("never clears the kill switch for non-boolean runtime input", () => {
    for (const value of [undefined, null, 0, "false"]) {
      expect(() =>
        store.setKillSwitch(value as unknown as boolean, "local-reviewer", NOW),
      ).toThrow("KILL_SWITCH_VALUE_INVALID");
      expect(store.isKillSwitchActive()).toBe(true);
    }
  });

  it("treats unaudited or revision-corrupted clear state as engaged", () => {
    expect(() =>
      database.run(
        `UPDATE system_state SET value='clear',revision=9001,
         updated_at='not-a-time',audit_reference=NULL
         WHERE key='global_kill_switch'`,
      ),
    ).toThrow();
    expect(store.isKillSwitchActive()).toBe(true);

    store.setKillSwitch(false, "local-reviewer", NOW);
    expect(store.isKillSwitchActive()).toBe(false);
    database.run("DROP TRIGGER system_state_kill_switch_update_guard");
    database.run(
      `UPDATE system_state SET revision=9001,updated_at='not-a-time'
       WHERE key='global_kill_switch'`,
    );
    expect(store.isKillSwitchActive()).toBe(true);
  });

  it("pauses an active campaign before recording a kill-switch engagement", () => {
    seedRunningCampaign();
    store.setKillSwitch(true, "local-reviewer", "2026-07-13T14:00:00.000Z");
    expect(store.isKillSwitchActive()).toBe(true);
    expect(store.getCampaign("campaign-local")).toMatchObject({
      state: "paused",
      humanApprovedBy: null,
      humanApprovedAt: null,
      killSwitchStatus: "engaged",
    });
  });

  it.each([
    { kind: "pause" },
    { kind: "complete" },
    { kind: "cancel" },
  ] satisfies readonly CampaignEvent[])(
    "persists running campaign transition $kind without stale approval",
    (event) => {
      const running = seedRunningCampaign();
      const next = transitionCampaign(running, event, {
        acceptedPolicyVersion: 1,
        acceptedPolicyHash: running.policyHash,
        policyAssets: ["demo.local.test"],
        configurationValid: true,
        killSwitchActive: false,
        externalActionRequested: false,
        externalIntegrationsEnabled: false,
        now: LATER,
      });
      expect(next.humanApprovedBy).toBeNull();
      expect(next.humanApprovedAt).toBeNull();
      expect(() => store.updateCampaign(running.revision, next)).not.toThrow();
    },
  );

  it("treats a kill-switch read failure as engaged", () => {
    database.close();
    expect(store.isKillSwitchActive()).toBe(true);
    database = ControlPlaneDatabase.memory();
    store = new ControlPlaneStore(database);
  });

  it("rehydrates and decides persisted approvals under the global kill switch", () => {
    const queue = new ApprovalQueue();
    const approval = queue.enqueue({
      id: "approval-persisted",
      kind: "report_bundle",
      summary: "Review local report",
      technicalDetails: "Local draft only",
      impact: "No external submission",
      policyVersion: null,
      policyHash: null,
      createdAt: NOW,
      auditReference: "audit:approval-persisted",
    });
    store.persistApproval(approval);
    expect(() =>
      store.decideApproval({
        id: approval.id,
        expectedRevision: 0,
        expectedPayloadHash: approval.payloadHash,
        decision: "accepted",
        actor: "local-reviewer",
        userAction: "clicked_accept",
        at: LATER,
      }),
    ).toThrow("APPROVAL_KILL_SWITCH");
    store.setKillSwitch(false, "local-reviewer", NOW);
    const restartedStore = new ControlPlaneStore(database);
    expect(
      restartedStore.decideApproval({
        id: approval.id,
        expectedRevision: 0,
        expectedPayloadHash: approval.payloadHash,
        decision: "accepted",
        actor: "local-reviewer",
        userAction: "clicked_accept",
        at: LATER,
      }),
    ).toMatchObject({ status: "accepted", revision: 1 });
    expect(restartedStore.listAuditEntries()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          action: "approval_decision",
          decision: "accepted",
        }),
      ]),
    );
  });
});
