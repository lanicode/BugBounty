import { randomBytes } from "node:crypto";
import {
  AccountSimulationCoordinator,
  MockAccountProvider,
} from "../account-simulation/workflow.js";
import { ApprovalQueue } from "../control-plane/approval-queue.js";
import {
  campaignApprovalDigest,
  transitionCampaign,
} from "../control-plane/campaign-machine.js";
import {
  diffPolicies,
  normalizePolicy,
  type NormalizedPolicy,
} from "../control-plane/policy.js";
import type { ControlPlaneStore } from "../control-plane/store.js";
import type {
  ApprovalKind,
  ApprovalRecord,
  CampaignRecord,
  TestIdentityRole,
} from "../control-plane/types.js";
import type { DemoSaas } from "../demo-saas/domain.js";
import { EventKeyLifecycle } from "../event-key-lifecycle/index.js";
import {
  InMemoryOwnershipJournal,
  OwnershipLedger,
  SimulationReceiptAuthority,
} from "../ownership-ledger/ledger.js";
import type { SecretStore } from "../secret-store/store.js";
import {
  isTrustedOperatorSigner,
  type OperatorSigner,
} from "../operator-auth/index.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

export interface HumanSimulationEvidence {
  readonly version: 2;
  readonly actor: string;
  readonly confirmedAt: string;
  readonly reviewDigest: string;
  readonly confirmations: {
    readonly clearKillSwitch: true;
    readonly acceptPolicyV1: true;
    readonly approveCampaignV1: true;
    readonly acceptPolicyV2: true;
    readonly approveCampaignV2: true;
    readonly queueReportReview: true;
  };
  readonly confirmationTimes: Readonly<
    Record<SimulationConfirmationKey, string>
  >;
}

export type SimulationConfirmationKey =
  | "clearKillSwitch"
  | "acceptPolicyV1"
  | "approveCampaignV1"
  | "acceptPolicyV2"
  | "approveCampaignV2"
  | "queueReportReview";

export interface SimulationReviewPackage {
  readonly version: 1;
  readonly reviewDigest: string;
  readonly policyV1: {
    readonly hash: string;
    readonly text: string;
    readonly allowedAssets: readonly string[];
    readonly excludedAssets: readonly string[];
    readonly allowedTestClasses: readonly string[];
    readonly forbiddenTestClasses: readonly string[];
    readonly rules: readonly string[];
    readonly unclearRules: readonly string[];
    readonly requestLimits: NormalizedPolicy["requestLimits"];
  };
  readonly campaignV1: {
    readonly approvalDigest: string;
    readonly policyHash: string;
    readonly approvedAssets: readonly string[];
    readonly approvedRiskTiers: readonly string[];
    readonly accountRefs: readonly string[];
    readonly allowedActionClasses: readonly string[];
    readonly contract: CampaignRecord["contract"];
  };
  readonly policyV2: {
    readonly hash: string;
    readonly text: string;
    readonly allowedAssets: readonly string[];
    readonly excludedAssets: readonly string[];
    readonly allowedTestClasses: readonly string[];
    readonly forbiddenTestClasses: readonly string[];
    readonly rules: readonly string[];
    readonly unclearRules: readonly string[];
    readonly requestLimits: NormalizedPolicy["requestLimits"];
  };
  readonly policyDiff: {
    readonly changedRequestLimits: readonly string[];
    readonly newlyForbiddenTestClasses: readonly string[];
    readonly newlyAllowedTestClasses: readonly string[];
    readonly changedRulesAdded: readonly string[];
    readonly changedRulesRemoved: readonly string[];
    readonly unclearRules: readonly string[];
  };
  readonly campaignV2: {
    readonly approvalDigest: string;
    readonly policyHash: string;
    readonly approvedAssets: readonly string[];
    readonly approvedRiskTiers: readonly string[];
    readonly accountRefs: readonly string[];
    readonly allowedActionClasses: readonly string[];
    readonly contract: CampaignRecord["contract"];
  };
  readonly reportAction: "queue_local_review_only_no_submission";
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

export const SIMULATION_CONFIRMATION_ORDER = Object.freeze([
  "clearKillSwitch",
  "acceptPolicyV1",
  "approveCampaignV1",
  "acceptPolicyV2",
  "approveCampaignV2",
  "queueReportReview",
] as const satisfies readonly SimulationConfirmationKey[]);

export class SimulationOrchestrator {
  #review: SimulationReviewPackage | undefined;
  #eventKeys: EventKeyLifecycle | undefined;
  readonly #operatorSessionId = randomBytes(32).toString("base64url");

  public constructor(
    private readonly store: ControlPlaneStore,
    private readonly demo: DemoSaas,
    private readonly eventDirectory: string,
    private readonly eventSecrets: SecretStore,
    private readonly eventKeyReference: (version: number) => string,
    private readonly now: () => Date,
    private readonly eventMinimumActiveKeyVersion: number,
    private readonly operatorSigner?: OperatorSigner,
  ) {
    if (
      this.operatorSigner !== undefined &&
      !isTrustedOperatorSigner(this.operatorSigner)
    )
      throw new SecurityError("OPERATOR_SIGNER_UNTRUSTED");
  }

  public preview(): SimulationReviewPackage {
    if (this.#review !== undefined) return this.#review;
    const reviewTime = this.now();
    if (!Number.isFinite(reviewTime.getTime()))
      throw new SecurityError("SIMULATION_CLOCK_INVALID");
    const policyV1 = makePolicyV1(this.demo.snapshot().currentPolicy.rules);
    const policyV2 = makePolicyV2();
    const diff = diffPolicies(policyV1, policyV2);
    const campaignV1 = makeCampaign(
      policyV1.policyHash,
      reviewTime.toISOString(),
    );
    const campaignV2 = rebindCampaign(campaignV1, policyV2.policyHash);
    const document = {
      version: 1,
      policyV1: {
        hash: policyV1.policyHash,
        text: policyV1.text,
        allowedAssets: policyV1.allowedAssets,
        excludedAssets: policyV1.excludedAssets,
        allowedTestClasses: policyV1.allowedTestClasses,
        forbiddenTestClasses: policyV1.forbiddenTestClasses,
        rules: policyV1.rules,
        unclearRules: policyV1.unclearRules,
        requestLimits: policyV1.requestLimits,
      },
      campaignV1: campaignReview(campaignV1),
      policyV2: {
        hash: policyV2.policyHash,
        text: policyV2.text,
        allowedAssets: policyV2.allowedAssets,
        excludedAssets: policyV2.excludedAssets,
        allowedTestClasses: policyV2.allowedTestClasses,
        forbiddenTestClasses: policyV2.forbiddenTestClasses,
        rules: policyV2.rules,
        unclearRules: policyV2.unclearRules,
        requestLimits: policyV2.requestLimits,
      },
      policyDiff: {
        changedRequestLimits: diff.changedRequestLimits.map(
          ({ field, before, after }) =>
            `${field}:${String(before)}->${String(after)}`,
        ),
        newlyForbiddenTestClasses: diff.newlyForbiddenTestClasses,
        newlyAllowedTestClasses: diff.newlyAllowedTestClasses,
        changedRulesAdded: diff.changedRules.added,
        changedRulesRemoved: diff.changedRules.removed,
        unclearRules: diff.unclearRules.current,
      },
      campaignV2: campaignReview(campaignV2),
      reportAction: "queue_local_review_only_no_submission",
    } as const;
    this.#review = deepFreezeReview({
      ...document,
      reviewDigest: sha256(canonicalJson(document)),
    });
    return this.#review;
  }

  public async run(evidence: unknown): Promise<SimulationSummary> {
    let failureActor = "simulation-fail-closed";
    try {
      const confirmed = validateHumanSimulationEvidence(evidence);
      failureActor = confirmed.actor;
      const observedAt = this.now().getTime();
      const confirmedAt = Date.parse(confirmed.confirmedAt);
      if (
        !Number.isFinite(observedAt) ||
        confirmedAt > observedAt + 1_000 ||
        observedAt - confirmedAt > 300_000
      )
        throw new SecurityError("SIMULATION_EVIDENCE_STALE");
      if (confirmed.reviewDigest !== this.preview().reviewDigest)
        throw new SecurityError("SIMULATION_REVIEW_DIGEST_MISMATCH");
      if (!this.store.isKillSwitchActive())
        throw new SecurityError("SIMULATION_REQUIRES_FRESH_STATE");
      const signer = this.requireOperatorSigner(confirmed.actor);
      const demoPolicyV1 = this.demo.snapshot().currentPolicy;
      const policyV1 = makePolicyV1(demoPolicyV1.rules);
      if (policyV1.policyHash !== this.preview().policyV1.hash)
        throw new SecurityError("SIMULATION_REVIEW_STALE");
      await this.assertEventKeyReady();
      const at = confirmed.confirmedAt;
      const initialAt = confirmed.confirmationTimes.clearKillSwitch;
      const initialSignedAt = strictClockTimestamp(this.now);
      this.ensureOperatorEnrolled(signer, initialSignedAt);
      const killContext = this.store.describeKillSwitchClear();
      this.store.clearKillSwitch(
        signer.signKillSwitchClear({
          controlPlaneId: killContext.controlPlaneId,
          expectedRevision: killContext.expectedRevision,
          userAction: "explicit_local_simulation_kill_switch_clear",
          contextDigestSha256: killContext.contextDigestSha256,
          sessionId: this.#operatorSessionId,
          nonce: randomBytes(32).toString("base64url"),
          issuedAt: initialSignedAt,
          expiresAt: operatorStatementExpiry(initialSignedAt),
        }),
      );
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
        initialAt,
      );
      recordStep("mock_program_imported");

      this.store.addPolicyVersion({
        programId: "program-local-demo",
        version: 1,
        policy: policyV1,
        createdAt: initialAt,
      });
      recordStep("policy_v1_displayed");
      this.acceptPolicy(
        "policy-v1-acceptance",
        1,
        policyV1.policyHash,
        confirmed,
      );
      recordStep("policy_v1_human_accepted");

      const reviewedCampaignV1 = this.preview().campaignV1;
      let campaign = makeCampaign(
        policyV1.policyHash,
        confirmed.confirmationTimes.acceptPolicyV1,
        {
          validFrom: reviewedCampaignV1.contract.validFrom,
          validUntil: reviewedCampaignV1.contract.validUntil,
        },
      );
      if (
        campaignApprovalDigest(campaign) !==
        this.preview().campaignV1.approvalDigest
      )
        throw new SecurityError("SIMULATION_CAMPAIGN_REVIEW_MISMATCH");
      this.store.insertCampaign(campaign);
      campaign = this.advanceCampaign(
        campaign,
        { kind: "request_approval" },
        1,
      );
      recordStep("campaign_contract_created");
      const campaignV1DecisionAt = this.acceptCampaignApproval(
        "campaign-v1-approval",
        campaign,
        confirmed,
      );
      campaign = this.advanceCampaign(
        campaign,
        {
          kind: "approve",
          actor: confirmed.actor,
          at: campaignV1DecisionAt,
        },
        1,
      );
      campaign = this.advanceCampaign(
        campaign,
        { kind: "start_simulation" },
        1,
      );
      recordStep("campaign_human_approved");

      await this.materializeCheckpointFreeFixtureIdentities(
        policyV1.policyHash,
        confirmed.confirmationTimes.approveCampaignV1,
      );
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

      this.demo.simulatePolicyDrift({
        expectedPolicyHash: demoPolicyV1.contentHash,
        rules: {
          requestLimit: 10,
          allowedActions: ["document.read"],
          prohibitedTestClasses: ["active_security_test", "write_test"],
        },
      });
      recordStep("policy_drift_simulated");
      campaign = this.advanceCampaign(
        campaign,
        { kind: "policy_drift", at },
        1,
      );
      recordStep("campaign_auto_paused");

      const policyV2 = makePolicyV2();
      this.store.addPolicyVersion({
        programId: "program-local-demo",
        version: 2,
        policy: policyV2,
        createdAt: confirmed.confirmationTimes.approveCampaignV1,
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

      const rebound = rebindCampaign(campaign, policyV2.policyHash);
      if (
        campaignApprovalDigest(rebound) !==
        this.preview().campaignV2.approvalDigest
      )
        throw new SecurityError("SIMULATION_CAMPAIGN_REVIEW_MISMATCH");
      this.store.updateCampaign(campaign.revision, rebound);
      campaign = rebound;
      const campaignV2DecisionAt = this.acceptCampaignApproval(
        "campaign-v2-approval",
        campaign,
        confirmed,
      );
      campaign = this.advanceCampaign(
        campaign,
        {
          kind: "approve",
          actor: confirmed.actor,
          at: campaignV2DecisionAt,
        },
        2,
      );
      campaign = this.advanceCampaign(
        campaign,
        { kind: "start_simulation" },
        2,
      );
      recordStep("simulation_resumed");

      this.store.insertReportDraft({
        id: "report-draft-local",
        campaignId: campaign.id,
        title: "Local simulation report draft",
        summary: "Contains only deterministic mock observations.",
        createdAt: confirmed.confirmationTimes.approveCampaignV2,
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
        at: confirmed.confirmationTimes.queueReportReview,
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
    } catch (error) {
      try {
        if (!this.store.isKillSwitchActive())
          this.store.setKillSwitch(
            true,
            failureActor,
            failureTimestamp(this.now),
          );
      } catch {
        // Engagement is persisted before its audit write; read errors are active.
      }
      throw error;
    }
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
      summary: `Accept program-local-demo policy version ${String(version)}`,
      technicalDetails: `Policy hash ${policyHash}; Review digest ${evidence.reviewDigest}; Confirmation recorded ${policyConfirmationTime(evidence, version)}`,
      impact:
        "Allows only the local simulation campaign to reference this version.",
      policyVersion: version,
      policyHash,
      at: policyApprovalCreationTime(evidence, version),
    });
    const decision = this.decideApproval({
      approvalId: approval.id,
      decision: "accepted",
      userAction: `explicit_local_policy_v${String(version)}_acceptance`,
      actor: evidence.actor,
    });
    this.store.acceptPolicy({
      programId: "program-local-demo",
      version,
      expectedPolicyHash: policyHash,
      acceptedBy: evidence.actor,
      acceptedAt: requiredDecisionTimestamp(decision),
      auditReference: `audit:${approvalId}`,
    });
  }

  private acceptCampaignApproval(
    approvalId: string,
    campaign: CampaignRecord,
    evidence: HumanSimulationEvidence,
  ): string {
    const approval = this.enqueueApproval({
      id: approvalId,
      kind: "campaign_contract",
      summary: `Approve ${campaign.id}`,
      technicalDetails: `Policy ${campaign.policyHash}; Campaign digest ${campaignApprovalDigest(campaign)}; Review digest ${evidence.reviewDigest}; Confirmation recorded ${campaignConfirmationTime(evidence, campaign.policyVersion)}; tier_0_offline only`,
      impact: "Allows deterministic local simulation only.",
      policyVersion: campaign.policyVersion,
      policyHash: campaign.policyHash,
      at: campaignApprovalCreationTime(evidence, campaign.policyVersion),
    });
    return requiredDecisionTimestamp(
      this.decideApproval({
        approvalId: approval.id,
        decision: "accepted",
        userAction: `explicit_local_campaign_v${String(campaign.policyVersion)}_approval`,
        actor: evidence.actor,
      }),
    );
  }

  private decideApproval(input: {
    readonly approvalId: string;
    readonly decision: "accepted" | "rejected";
    readonly userAction: string;
    readonly actor: string;
  }): ApprovalRecord {
    const signer = this.requireOperatorSigner(input.actor);
    const signedAt = strictClockTimestamp(this.now);
    this.ensureOperatorEnrolled(signer, signedAt);
    const context = this.store.describeApprovalDecision(input.approvalId);
    return this.store.decideApproval(
      signer.signApprovalDecision({
        controlPlaneId: context.controlPlaneId,
        approvalId: context.approvalId,
        approvalKind: context.approvalKind,
        approvalPayloadHashSha256: context.approvalPayloadHashSha256,
        expectedRevision: context.expectedRevision,
        decision: input.decision,
        userAction: input.userAction,
        contextDigestSha256: context.contextDigestSha256,
        sessionId: this.#operatorSessionId,
        nonce: randomBytes(32).toString("base64url"),
        issuedAt: signedAt,
        expiresAt: operatorStatementExpiry(signedAt),
      }),
    );
  }

  private requireOperatorSigner(actor: string): OperatorSigner {
    const signer = this.operatorSigner;
    if (!isTrustedOperatorSigner(signer))
      throw new SecurityError("OPERATOR_SIGNER_REQUIRED");
    if (signer.credential.operator_id !== actor)
      throw new SecurityError("OPERATOR_IDENTITY_MISMATCH");
    return signer;
  }

  private ensureOperatorEnrolled(signer: OperatorSigner, at: string): void {
    const current = this.store.getLocalOperatorCredential();
    if (current !== undefined) {
      if (
        current.operator_id !== signer.credential.operator_id ||
        current.public_key_spki_base64url !==
          signer.credential.public_key_spki_base64url ||
        current.key_fingerprint_sha256 !==
          signer.credential.key_fingerprint_sha256 ||
        current.key_revision !== signer.credential.key_revision
      )
        throw new SecurityError("OPERATOR_CREDENTIAL_MISMATCH");
    }
    const proof = signer.signEnrollment({
      controlPlaneId: this.store.getControlPlaneId(),
      sessionId: this.#operatorSessionId,
      nonce: randomBytes(32).toString("base64url"),
      issuedAt: at,
      expiresAt: operatorStatementExpiry(at),
    });
    if (current === undefined) this.store.enrollLocalOperator(proof);
    else this.store.authenticateLocalOperatorSession(proof);
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

  private async assertEventKeyReady(): Promise<void> {
    try {
      this.#eventKeys = await EventKeyLifecycle.openOrInitializeFresh({
        directory: this.eventDirectory,
        secrets: this.eventSecrets,
        keyReference: this.eventKeyReference,
        minimumActiveKeyVersion: this.eventMinimumActiveKeyVersion,
      });
    } catch {
      throw new SecurityError("SIMULATION_EVENT_SECRET_UNAVAILABLE");
    }
  }

  private async materializeCheckpointFreeFixtureIdentities(
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
    // These are pre-authorized, in-process demo fixtures. An empty plan means
    // no CAPTCHA, terms, legal declaration, or program-rule action is modeled
    // or silently accepted; configured challenges always pause the workflow.
    const coordinator = new AccountSimulationCoordinator(
      application,
      policyHash,
      new Map(roles),
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
    const events = this.#eventKeys;
    if (events === undefined)
      throw new SecurityError("SIMULATION_EVENT_SECRET_UNAVAILABLE");
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

function makeCampaign(
  policyHash: string,
  at: string,
  validity?: { readonly validFrom: string; readonly validUntil: string },
): CampaignRecord {
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
      validFrom:
        validity?.validFrom ?? new Date(Date.parse(at) - 60_000).toISOString(),
      validUntil:
        validity?.validUntil ??
        new Date(Date.parse(at) + 86_400_000).toISOString(),
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

function rebindCampaign(
  campaign: CampaignRecord,
  policyHash: string,
): CampaignRecord {
  return Object.freeze({
    ...campaign,
    policyVersion: 2,
    policyHash,
    contract: Object.freeze({
      ...campaign.contract,
      maxRequests: 10,
      requestsPerMinute: 10,
      policyHash,
    }),
    state: "awaiting_campaign_approval",
    revision: campaign.revision + 1,
    humanApprovedBy: null,
    humanApprovedAt: null,
  });
}

function campaignReview(campaign: CampaignRecord) {
  return Object.freeze({
    approvalDigest: campaignApprovalDigest(campaign),
    policyHash: campaign.policyHash,
    approvedAssets: campaign.approvedAssets,
    approvedRiskTiers: campaign.approvedRiskTiers,
    accountRefs: campaign.accountRefs,
    allowedActionClasses: campaign.allowedActionClasses,
    contract: campaign.contract,
  });
}

function policyConfirmationTime(
  evidence: HumanSimulationEvidence,
  version: number,
): string {
  if (version === 1) return evidence.confirmationTimes.acceptPolicyV1;
  if (version === 2) return evidence.confirmationTimes.acceptPolicyV2;
  throw new SecurityError("SIMULATION_POLICY_VERSION_INVALID");
}

function policyApprovalCreationTime(
  evidence: HumanSimulationEvidence,
  version: number,
): string {
  if (version === 1) return evidence.confirmationTimes.clearKillSwitch;
  if (version === 2) return evidence.confirmationTimes.approveCampaignV1;
  throw new SecurityError("SIMULATION_POLICY_VERSION_INVALID");
}

function campaignConfirmationTime(
  evidence: HumanSimulationEvidence,
  version: number,
): string {
  if (version === 1) return evidence.confirmationTimes.approveCampaignV1;
  if (version === 2) return evidence.confirmationTimes.approveCampaignV2;
  throw new SecurityError("SIMULATION_POLICY_VERSION_INVALID");
}

function campaignApprovalCreationTime(
  evidence: HumanSimulationEvidence,
  version: number,
): string {
  if (version === 1) return evidence.confirmationTimes.acceptPolicyV1;
  if (version === 2) return evidence.confirmationTimes.acceptPolicyV2;
  throw new SecurityError("SIMULATION_POLICY_VERSION_INVALID");
}

function failureTimestamp(now: () => Date): string {
  try {
    const candidate = now();
    if (Number.isFinite(candidate.getTime())) return candidate.toISOString();
  } catch {
    // A clock dependency failure must not prevent kill-switch engagement.
  }
  return new Date().toISOString();
}

function strictClockTimestamp(now: () => Date): string {
  let candidate: unknown;
  try {
    candidate = now();
  } catch {
    throw new SecurityError("OPERATOR_CLOCK_UNAVAILABLE");
  }
  if (
    typeof candidate !== "object" ||
    candidate === null ||
    Reflect.getPrototypeOf(candidate) !== Date.prototype
  )
    throw new SecurityError("OPERATOR_CLOCK_INVALID");
  let milliseconds: unknown;
  try {
    const getTime: unknown = Reflect.get(Date.prototype, "getTime");
    if (typeof getTime !== "function") throw new Error("DATE_INTRINSIC");
    milliseconds = Reflect.apply(getTime, candidate, []);
  } catch {
    throw new SecurityError("OPERATOR_CLOCK_INVALID");
  }
  if (typeof milliseconds !== "number" || !Number.isFinite(milliseconds))
    throw new SecurityError("OPERATOR_CLOCK_INVALID");
  return new Date(milliseconds).toISOString();
}

function requiredDecisionTimestamp(decision: ApprovalRecord): string {
  if (
    decision.status === "open" ||
    decision.revision !== 1 ||
    decision.decidedAt === null
  )
    throw new SecurityError("SIGNED_APPROVAL_DECISION_INVALID");
  return decision.decidedAt;
}

function operatorStatementExpiry(issuedAt: string): string {
  const milliseconds = Date.parse(issuedAt);
  if (!Number.isFinite(milliseconds))
    throw new SecurityError("OPERATOR_STATEMENT_TIME_INVALID");
  return new Date(milliseconds + 5 * 60 * 1_000).toISOString();
}

function makePolicyV1(rules: {
  readonly requestLimit: number;
  readonly allowedActions: readonly string[];
  readonly prohibitedTestClasses: readonly string[];
}) {
  return normalizePolicy({
    text: "Local Demo Policy version 1",
    allowedAssets: ["demo.local.test"],
    excludedAssets: ["admin.demo.local.test"],
    requestLimits: {
      requestsPerMinute: rules.requestLimit,
      maxRequestsTotal: rules.requestLimit,
      maxConcurrency: 1,
    },
    allowedTestClasses: rules.allowedActions,
    forbiddenTestClasses: rules.prohibitedTestClasses,
    rules: ["simulation_only", "no_external_submission"],
    unclearRules: [],
  });
}

function makePolicyV2() {
  return normalizePolicy({
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
    rules: [
      "simulation_only",
      "no_external_submission",
      "reapproval_required_after_drift",
    ],
    unclearRules: ["mock drift requires local review"],
  });
}

function deepFreezeReview(value: {
  readonly version: 1;
  readonly reviewDigest: string;
  readonly policyV1: SimulationReviewPackage["policyV1"];
  readonly campaignV1: SimulationReviewPackage["campaignV1"];
  readonly policyV2: SimulationReviewPackage["policyV2"];
  readonly policyDiff: SimulationReviewPackage["policyDiff"];
  readonly campaignV2: SimulationReviewPackage["campaignV2"];
  readonly reportAction: SimulationReviewPackage["reportAction"];
}): SimulationReviewPackage {
  for (const nested of Object.values(value)) {
    if (typeof nested === "object") {
      for (const item of Object.values(nested))
        if (Array.isArray(item)) Object.freeze(item);
      Object.freeze(nested);
    }
  }
  return Object.freeze(value);
}

export function validateHumanSimulationEvidence(
  value: unknown,
): HumanSimulationEvidence {
  if (
    !isObject(value) ||
    !hasExactKeys(value, [
      "actor",
      "confirmations",
      "confirmationTimes",
      "confirmedAt",
      "reviewDigest",
      "version",
    ])
  )
    throw new SecurityError("SIMULATION_EVIDENCE_INVALID");
  const actor = value["actor"];
  const confirmedAt = value["confirmedAt"];
  const confirmations = value["confirmations"];
  const confirmationTimes = value["confirmationTimes"];
  const reviewDigest = value["reviewDigest"];
  if (
    value["version"] !== 2 ||
    typeof actor !== "string" ||
    !/^[A-Za-z0-9._@-]{1,128}$/u.test(actor) ||
    typeof confirmedAt !== "string" ||
    !Number.isFinite(Date.parse(confirmedAt)) ||
    typeof reviewDigest !== "string" ||
    !/^[a-f0-9]{64}$/u.test(reviewDigest) ||
    !isObject(confirmations) ||
    !hasExactKeys(confirmations, SIMULATION_CONFIRMATION_ORDER) ||
    SIMULATION_CONFIRMATION_ORDER.some((key) => confirmations[key] !== true) ||
    !isObject(confirmationTimes) ||
    !hasExactKeys(confirmationTimes, SIMULATION_CONFIRMATION_ORDER)
  )
    throw new SecurityError("SIMULATION_EVIDENCE_INVALID");
  let previous = Number.NEGATIVE_INFINITY;
  const confirmedTime = Date.parse(confirmedAt);
  const normalizedTimes = new Map<SimulationConfirmationKey, string>();
  for (const key of SIMULATION_CONFIRMATION_ORDER) {
    const time = confirmationTimes[key];
    if (typeof time !== "string")
      throw new SecurityError("SIMULATION_EVIDENCE_INVALID");
    const parsed = Date.parse(time);
    if (
      !Number.isFinite(parsed) ||
      parsed <= previous ||
      parsed > confirmedTime ||
      confirmedTime - parsed > 1_800_000
    )
      throw new SecurityError("SIMULATION_EVIDENCE_INVALID");
    previous = parsed;
    normalizedTimes.set(key, new Date(parsed).toISOString());
  }
  return Object.freeze({
    version: 2,
    actor,
    confirmedAt: new Date(Date.parse(confirmedAt)).toISOString(),
    reviewDigest,
    confirmations: Object.freeze({
      clearKillSwitch: true,
      acceptPolicyV1: true,
      approveCampaignV1: true,
      acceptPolicyV2: true,
      approveCampaignV2: true,
      queueReportReview: true,
    }),
    confirmationTimes: Object.freeze({
      clearKillSwitch: requireConfirmationTime(
        normalizedTimes,
        "clearKillSwitch",
      ),
      acceptPolicyV1: requireConfirmationTime(
        normalizedTimes,
        "acceptPolicyV1",
      ),
      approveCampaignV1: requireConfirmationTime(
        normalizedTimes,
        "approveCampaignV1",
      ),
      acceptPolicyV2: requireConfirmationTime(
        normalizedTimes,
        "acceptPolicyV2",
      ),
      approveCampaignV2: requireConfirmationTime(
        normalizedTimes,
        "approveCampaignV2",
      ),
      queueReportReview: requireConfirmationTime(
        normalizedTimes,
        "queueReportReview",
      ),
    }),
  });
}

function requireConfirmationTime(
  values: ReadonlyMap<SimulationConfirmationKey, string>,
  key: SimulationConfirmationKey,
): string {
  const value = values.get(key);
  if (value === undefined)
    throw new SecurityError("SIMULATION_EVIDENCE_INVALID");
  return value;
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
