import { randomBytes } from "node:crypto";
import { mkdir } from "node:fs/promises";
import {
  AccountSimulationCoordinator,
  MockAccountProvider,
} from "../account-simulation/workflow.js";
import { ApprovalQueue } from "../control-plane/approval-queue.js";
import { transitionCampaign } from "../control-plane/campaign-machine.js";
import { diffPolicies, normalizePolicy } from "../control-plane/policy.js";
import type { ControlPlaneStore } from "../control-plane/store.js";
import type {
  ApprovalKind,
  CampaignRecord,
  TestIdentityRole,
} from "../control-plane/types.js";
import type { DemoSaas } from "../demo-saas/domain.js";
import { EncryptedEventStore } from "../event-store/store.js";
import {
  InMemoryOwnershipJournal,
  OwnershipLedger,
  SimulationReceiptAuthority,
} from "../ownership-ledger/ledger.js";
import { InMemorySecretStore } from "../secret-store/store.js";
import { sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

export interface HumanSimulationEvidence {
  readonly version: 1;
  readonly actor: string;
  readonly confirmedAt: string;
  readonly confirmations: {
    readonly clearKillSwitch: true;
    readonly acceptPolicyV1: true;
    readonly approveCampaignV1: true;
    readonly acceptPolicyV2: true;
    readonly approveCampaignV2: true;
    readonly queueReportReview: true;
  };
}

export type SimulationStep =
  | "campaign_auto_paused"
  | "campaign_contract_created"
  | "campaign_human_approved"
  | "encrypted_events_recorded"
  | "external_submission_not_performed"
  | "mock_identities_created"
  | "mock_objects_created"
  | "mock_organization_ready"
  | "mock_program_imported"
  | "ownership_ledger_updated"
  | "policy_drift_simulated"
  | "policy_v1_displayed"
  | "policy_v1_human_accepted"
  | "policy_v2_diff_displayed"
  | "policy_v2_human_accepted"
  | "report_approval_queued"
  | "report_draft_created"
  | "simulation_resumed";

export interface SimulationSummary {
  readonly mode: "simulation";
  readonly externalIntegrationsEnabled: false;
  readonly networkConnections: 0;
  readonly externalSubmissions: 0;
  readonly programId: string;
  readonly campaignId: string;
  readonly campaignState: "running_simulation";
  readonly policyVersions: number;
  readonly policyDiffChanged: true;
  readonly identities: number;
  readonly ownedObjects: number;
  readonly encryptedEvents: number;
  readonly openApprovals: number;
  readonly reportDrafts: number;
  readonly demoOrganizationRef: string;
  readonly steps: readonly SimulationStep[];
}

const EXPECTED_CONFIRMATION_KEYS = Object.freeze([
  "acceptPolicyV1",
  "acceptPolicyV2",
  "approveCampaignV1",
  "approveCampaignV2",
  "clearKillSwitch",
  "queueReportReview",
]);

export class SimulationOrchestrator {
  public constructor(
    private readonly store: ControlPlaneStore,
    private readonly demo: DemoSaas,
    private readonly eventDirectory: string,
    private readonly now: () => Date,
  ) {}

  public async run(evidence: unknown): Promise<SimulationSummary> {
    const confirmed = validateHumanSimulationEvidence(evidence);
    if (!this.store.isKillSwitchActive())
      throw new SecurityError("SIMULATION_REQUIRES_FRESH_STATE");
    const at = confirmed.confirmedAt;
    this.store.setKillSwitch(false, confirmed.actor, at);
    const steps: SimulationStep[] = [];
    const recordStep = (step: SimulationStep): void => {
      this.assertNotKilled();
      steps.push(step);
    };

    this.store.createProgram(
      {
        id: "program-local-demo",
        name: "Local Demo Program",
        platform: "local_mock",
        status: "available",
        description: "In-process Phase 2 simulation fixture",
        programUrl: "http://127.0.0.1/local-metadata-only",
        programType: "simulation",
        allowedAssets: ["demo.local.test"],
        excludedAssets: ["admin.demo.local.test"],
        lastSynchronizedAt: at,
        automationPermission: "allowed",
        notes: "No external target is associated with this record.",
        lifecycle: "active",
      },
      at,
    );
    recordStep("mock_program_imported");

    const demoPolicyV1 = this.demo.snapshot().currentPolicy;
    const policyV1 = normalizePolicy({
      text: "Local Demo Policy version 1",
      allowedAssets: ["demo.local.test"],
      excludedAssets: ["admin.demo.local.test"],
      requestLimits: {
        requestsPerMinute: demoPolicyV1.rules.requestLimit,
        maxRequestsTotal: demoPolicyV1.rules.requestLimit,
        maxConcurrency: 1,
      },
      allowedTestClasses: demoPolicyV1.rules.allowedActions,
      forbiddenTestClasses: demoPolicyV1.rules.prohibitedTestClasses,
      rules: ["simulation_only", "no_external_submission"],
      unclearRules: [],
    });
    this.store.addPolicyVersion({
      programId: "program-local-demo",
      version: 1,
      policy: policyV1,
      createdAt: at,
    });
    recordStep("policy_v1_displayed");
    this.acceptPolicy(
      "policy-v1-acceptance",
      1,
      policyV1.policyHash,
      confirmed,
    );
    recordStep("policy_v1_human_accepted");

    let campaign = makeCampaign(policyV1.policyHash, at);
    this.store.insertCampaign(campaign);
    campaign = this.advanceCampaign(campaign, { kind: "request_approval" }, 1);
    recordStep("campaign_contract_created");
    this.acceptCampaignApproval("campaign-v1-approval", campaign, confirmed);
    campaign = this.advanceCampaign(
      campaign,
      { kind: "approve", actor: confirmed.actor, at },
      1,
    );
    campaign = this.advanceCampaign(campaign, { kind: "start_simulation" }, 1);
    recordStep("campaign_human_approved");

    await this.provisionMockIdentities(policyV1.policyHash, at);
    recordStep("mock_identities_created");
    const demoSnapshot = this.demo.snapshot();
    recordStep("mock_organization_ready");
    const demoObject = this.demo.createTestObject({
      actorRef: "identity-owner-001",
      objectRef: "object-simulation-002",
      projectRef: "project-demo-001",
      canary: "canary-simulation-002",
    });
    recordStep("mock_objects_created");

    const receiptKey = randomBytes(32);
    const authority = new SimulationReceiptAuthority(receiptKey);
    const ownershipJournal = new InMemoryOwnershipJournal();
    const ledger = new OwnershipLedger(
      authority,
      ownershipJournal,
      policyV1.policyHash,
    );
    await ledger.activateAccount(
      authority.issueAccountActive({
        receiptId: "receipt-account-owner",
        applicationRef: "local-app:demo",
        accountRef: "identity-owner-001",
        policyHash: policyV1.policyHash,
      }),
    );
    this.assertNotKilled();
    const objectReceipt = authority.issueObjectCreated({
      receiptId: "receipt-object-owned",
      applicationRef: "local-app:demo",
      accountRef: "identity-owner-001",
      objectRef: "owned-object-001",
      policyHash: policyV1.policyHash,
      canary: demoObject.canary,
    });
    await ledger.registerObject(objectReceipt);
    this.assertNotKilled();
    this.store.insertOwnedObject({
      objectRef: "owned-object-001",
      protectedActualIdRef: `protected-ref:${sha256(demoObject.objectRef).slice(0, 32)}`,
      programId: "program-local-demo",
      campaignId: "campaign-local-demo",
      accountId: "identity-owner-001",
      tenantRef: demoSnapshot.organization.organizationRef,
      objectType: "document",
      canaryHmac: requireValue(objectReceipt.canaryHmac),
      createdAt: at,
      status: "active",
      researcherControlled: true,
      allowedActions: ["offline_inspect"],
      expiresAt: new Date(Date.parse(at) + 86_400_000).toISOString(),
      policyHash: policyV1.policyHash,
    });
    this.store.assertOwnedObject({
      objectRef: "owned-object-001",
      campaignId: "campaign-local-demo",
      accountId: "identity-owner-001",
      policyHash: policyV1.policyHash,
      action: "offline_inspect",
      now: at,
    });
    recordStep("ownership_ledger_updated");

    await this.recordEncryptedEvents(policyV1.policyHash, at);
    recordStep("encrypted_events_recorded");

    const drift = this.demo.simulatePolicyDrift({
      expectedPolicyHash: demoPolicyV1.contentHash,
      rules: {
        requestLimit: 10,
        allowedActions: ["document.read"],
        prohibitedTestClasses: ["active_security_test", "write_test"],
      },
    });
    recordStep("policy_drift_simulated");
    campaign = this.advanceCampaign(campaign, { kind: "policy_drift", at }, 1);
    recordStep("campaign_auto_paused");

    const policyV2 = normalizePolicy({
      text: "Local Demo Policy version 2",
      allowedAssets: ["demo.local.test"],
      excludedAssets: ["admin.demo.local.test"],
      requestLimits: {
        requestsPerMinute: 10,
        maxRequestsTotal: 10,
        maxConcurrency: 1,
      },
      allowedTestClasses: ["document.read"],
      forbiddenTestClasses: ["active_security_test", "write_test"],
      rules: ["simulation_only", "no_external_submission"],
      unclearRules: ["mock drift requires local review"],
    });
    this.store.addPolicyVersion({
      programId: "program-local-demo",
      version: 2,
      policy: policyV2,
      createdAt: drift.detectedAt,
    });
    const policyDiff = diffPolicies(policyV1, policyV2);
    if (!policyDiff.changed)
      throw new SecurityError("SIMULATION_POLICY_DRIFT_MISSING");
    recordStep("policy_v2_diff_displayed");
    this.acceptPolicy(
      "policy-v2-acceptance",
      2,
      policyV2.policyHash,
      confirmed,
    );
    recordStep("policy_v2_human_accepted");

    const rebound: CampaignRecord = Object.freeze({
      ...campaign,
      policyVersion: 2,
      policyHash: policyV2.policyHash,
      contract: Object.freeze({
        ...campaign.contract,
        maxRequests: 10,
        requestsPerMinute: 10,
        policyHash: policyV2.policyHash,
      }),
      state: "awaiting_campaign_approval",
      revision: campaign.revision + 1,
      humanApprovedBy: null,
      humanApprovedAt: null,
    });
    this.store.updateCampaign(campaign.revision, rebound);
    campaign = rebound;
    this.acceptCampaignApproval("campaign-v2-approval", campaign, confirmed);
    campaign = this.advanceCampaign(
      campaign,
      { kind: "approve", actor: confirmed.actor, at },
      2,
    );
    campaign = this.advanceCampaign(campaign, { kind: "start_simulation" }, 2);
    recordStep("simulation_resumed");

    this.store.insertReportDraft({
      id: "report-draft-local",
      campaignId: campaign.id,
      title: "Local simulation report draft",
      summary: "Contains only deterministic mock observations.",
      createdAt: at,
      status: "queued_for_human_review",
      externalSubmissionPerformed: false,
    });
    recordStep("report_draft_created");
    this.enqueueApproval({
      id: "report-review-approval",
      kind: "report_bundle",
      summary: "Review local simulation report",
      technicalDetails: "No submission runner exists in Phase 2.",
      impact: "Human review only; no external side effect.",
      policyVersion: 2,
      policyHash: policyV2.policyHash,
      at,
    });
    recordStep("report_approval_queued");
    recordStep("external_submission_not_performed");

    if (this.store.isKillSwitchActive())
      throw new SecurityError("SIMULATION_KILL_SWITCH");
    return Object.freeze({
      mode: "simulation",
      externalIntegrationsEnabled: false,
      networkConnections: 0,
      externalSubmissions: 0,
      programId: "program-local-demo",
      campaignId: campaign.id,
      campaignState: "running_simulation",
      policyVersions: 2,
      policyDiffChanged: true,
      identities: this.store.listIdentities().length,
      ownedObjects: this.store.listOwnedObjects().length,
      encryptedEvents: 3,
      openApprovals: this.store
        .listApprovals()
        .filter((approval) => approval.status === "open").length,
      reportDrafts: this.store.listReportDrafts().length,
      demoOrganizationRef: demoSnapshot.organization.organizationRef,
      steps: Object.freeze(steps),
    });
  }

  private acceptPolicy(
    approvalId: string,
    version: number,
    policyHash: string,
    evidence: HumanSimulationEvidence,
  ): void {
    const approval = this.enqueueApproval({
      id: approvalId,
      kind: "program_policy_acceptance",
      summary: `Accept local policy version ${String(version)}`,
      technicalDetails: `Hash ${policyHash}`,
      impact:
        "Allows only the local simulation campaign to reference this version.",
      policyVersion: version,
      policyHash,
      at: evidence.confirmedAt,
    });
    const decided = this.approvals.decide({
      id: approval.id,
      expectedRevision: approval.revision,
      expectedPayloadHash: approval.payloadHash,
      decision: "accepted",
      actor: evidence.actor,
      userAction: `explicit_local_policy_v${String(version)}_acceptance`,
      at: evidence.confirmedAt,
      killSwitchActive: this.store.isKillSwitchActive(),
    });
    this.store.updateApproval(approval.revision, decided);
    this.store.acceptPolicy({
      programId: "program-local-demo",
      version,
      expectedPolicyHash: policyHash,
      acceptedBy: evidence.actor,
      acceptedAt: evidence.confirmedAt,
      auditReference: `audit:${approvalId}`,
    });
  }

  private acceptCampaignApproval(
    approvalId: string,
    campaign: CampaignRecord,
    evidence: HumanSimulationEvidence,
  ): void {
    const approval = this.enqueueApproval({
      id: approvalId,
      kind: "campaign_contract",
      summary: `Approve ${campaign.id}`,
      technicalDetails: `Policy ${campaign.policyHash}; tier_0_offline only`,
      impact: "Allows deterministic local simulation only.",
      policyVersion: campaign.policyVersion,
      policyHash: campaign.policyHash,
      at: evidence.confirmedAt,
    });
    const decided = this.approvals.decide({
      id: approval.id,
      expectedRevision: 0,
      expectedPayloadHash: approval.payloadHash,
      decision: "accepted",
      actor: evidence.actor,
      userAction: `explicit_local_campaign_v${String(campaign.policyVersion)}_approval`,
      at: evidence.confirmedAt,
      killSwitchActive: this.store.isKillSwitchActive(),
    });
    this.store.updateApproval(0, decided);
  }

  private readonly approvals = new ApprovalQueue();

  private enqueueApproval(input: {
    readonly id: string;
    readonly kind: ApprovalKind;
    readonly summary: string;
    readonly technicalDetails: string;
    readonly impact: string;
    readonly policyVersion: number;
    readonly policyHash: string;
    readonly at: string;
  }) {
    const approval = this.approvals.enqueue({
      id: input.id,
      kind: input.kind,
      summary: input.summary,
      technicalDetails: input.technicalDetails,
      impact: input.impact,
      policyVersion: input.policyVersion,
      policyHash: input.policyHash,
      createdAt: input.at,
      auditReference: `audit:${input.id}`,
    });
    this.store.persistApproval(approval);
    return approval;
  }

  private advanceCampaign(
    current: CampaignRecord,
    event: Parameters<typeof transitionCampaign>[1],
    acceptedVersion: number,
  ): CampaignRecord {
    const next = transitionCampaign(current, event, {
      acceptedPolicyVersion: acceptedVersion,
      acceptedPolicyHash: current.policyHash,
      policyAssets: ["demo.local.test"],
      configurationValid: true,
      killSwitchActive: this.store.isKillSwitchActive(),
      externalActionRequested: false,
      externalIntegrationsEnabled: false,
      now: this.now().toISOString(),
    });
    this.store.updateCampaign(current.revision, next);
    return next;
  }

  private assertNotKilled(): void {
    if (this.store.isKillSwitchActive())
      throw new SecurityError("SIMULATION_KILL_SWITCH");
  }

  private async provisionMockIdentities(
    policyHash: string,
    at: string,
  ): Promise<void> {
    const roles: readonly (readonly [string, TestIdentityRole])[] =
      Object.freeze([
        Object.freeze(["identity-owner-001", "Owner"] as const),
        Object.freeze(["identity-member-001", "Member"] as const),
        Object.freeze(["identity-external-001", "External"] as const),
      ]);
    const application = new MockAccountProvider("local-app:demo", {});
    const coordinator = new AccountSimulationCoordinator(
      application,
      policyHash,
      new Set(roles.map(([account]) => account)),
      3,
      new AbortController().signal,
      this.now,
    );
    for (const [accountRef, role] of roles) {
      const result = await coordinator.execute({
        version: 1,
        proposal_id: `provision-${accountRef}`,
        action: "provision",
        mode: "simulation",
        workflow_ref: `workflow-${accountRef}`,
        application_ref: "local-app:demo",
        account_ref: accountRef,
        role,
        policy_hash_sha256: policyHash,
        expected_revision: 0,
        checkpoint_ref: null,
      });
      this.assertNotKilled();
      if (result.workflow.state !== "ACTIVE")
        throw new SecurityError("SIMULATION_ACCOUNT_NOT_ACTIVE");
      this.store.insertIdentity({
        id: accountRef,
        programId: "program-local-demo",
        role,
        status: "ready",
        emailReference: null,
        secretReferences: [],
        browserProfileReference: null,
        platformAccountReference: `ref:/${accountRef}`,
        createdAt: at,
        verifiedAt: at,
        suspendedAt: null,
        retiredAt: null,
        lastSuccessfulLoginAt: at,
        humanActionRequired: false,
        organizationRef: "org-demo-001",
        ownedObjectRefs: role === "Owner" ? ["owned-object-001"] : [],
      });
    }
  }

  private async recordEncryptedEvents(
    policyHash: string,
    at: string,
  ): Promise<void> {
    await mkdir(this.eventDirectory, { recursive: true, mode: 0o700 });
    const secretStore = new InMemorySecretStore();
    secretStore.set("secret://simulation/event-key", randomBytes(32));
    const events = new EncryptedEventStore(
      this.eventDirectory,
      secretStore,
      () => "secret://simulation/event-key",
    );
    await events.write("program-imported", {
      version: 1,
      type: "PROGRAM_IMPORTED",
      occurredAt: at,
      programId: "program-local-demo",
      policyHash,
    });
    this.assertNotKilled();
    await events.write("ownership-recorded", {
      version: 1,
      type: "OWNERSHIP_RECORDED",
      occurredAt: at,
      objectRef: "owned-object-001",
      policyHash,
    });
    this.assertNotKilled();
    await events.write("policy-drift", {
      version: 1,
      type: "POLICY_DRIFT_PENDING",
      occurredAt: at,
      campaignId: "campaign-local-demo",
      policyHash,
    });
    this.assertNotKilled();
  }
}

function makeCampaign(policyHash: string, at: string): CampaignRecord {
  return Object.freeze({
    id: "campaign-local-demo",
    programId: "program-local-demo",
    policyVersion: 1,
    policyHash,
    approvedAssets: Object.freeze(["demo.local.test"]),
    approvedRiskTiers: Object.freeze(["tier_0_offline"] as const),
    accountRefs: Object.freeze([
      "identity-owner-001",
      "identity-member-001",
      "identity-external-001",
    ]),
    allowedActionClasses: Object.freeze(["offline_simulation"] as const),
    contract: Object.freeze({
      allowedHosts: Object.freeze(["demo.local.test"]),
      excludedHosts: Object.freeze(["admin.demo.local.test"]),
      maxRequests: 20,
      requestsPerMinute: 20,
      maxConcurrency: 1,
      allowedRiskTiers: Object.freeze(["tier_0_offline"] as const),
      allowedMethods: Object.freeze(["GET", "HEAD"] as const),
      writeActionsAllowed: false,
      rollbackRequired: true,
      humanCheckpoints: Object.freeze([
        "policy_acceptance",
        "campaign_approval",
      ]),
      validFrom: new Date(Date.parse(at) - 60_000).toISOString(),
      validUntil: new Date(Date.parse(at) + 86_400_000).toISOString(),
      policyHash,
    }),
    state: "draft",
    revision: 0,
    humanApprovedBy: null,
    humanApprovedAt: null,
    lastPolicyCheckAt: null,
    killSwitchStatus: "clear",
    createdAt: at,
  });
}

export function validateHumanSimulationEvidence(
  value: unknown,
): HumanSimulationEvidence {
  if (
    !isObject(value) ||
    !hasExactKeys(value, ["actor", "confirmations", "confirmedAt", "version"])
  )
    throw new SecurityError("SIMULATION_EVIDENCE_INVALID");
  const actor = value["actor"];
  const confirmedAt = value["confirmedAt"];
  const confirmations = value["confirmations"];
  if (
    value["version"] !== 1 ||
    typeof actor !== "string" ||
    !/^[A-Za-z0-9._@-]{1,128}$/u.test(actor) ||
    typeof confirmedAt !== "string" ||
    !Number.isFinite(Date.parse(confirmedAt)) ||
    !isObject(confirmations) ||
    !hasExactKeys(confirmations, EXPECTED_CONFIRMATION_KEYS) ||
    EXPECTED_CONFIRMATION_KEYS.some((key) => confirmations[key] !== true)
  )
    throw new SecurityError("SIMULATION_EVIDENCE_INVALID");
  return Object.freeze({
    version: 1,
    actor,
    confirmedAt,
    confirmations: Object.freeze({
      clearKillSwitch: true,
      acceptPolicyV1: true,
      approveCampaignV1: true,
      acceptPolicyV2: true,
      approveCampaignV2: true,
      queueReportReview: true,
    }),
  });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(
  value: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function requireValue(value: string | null): string {
  if (value === null) throw new SecurityError("SIMULATION_RECEIPT_INVALID");
  return value;
}
