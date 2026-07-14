import { ApprovalQueue } from "./approval-queue.js";
import type { ControlPlaneDatabase } from "./database.js";
import {
  externalActionApprovalBindingDigest,
  externalActionCampaignDigest,
  externalActionEvidenceDigest,
  externalActionIdentityDigest,
  externalActionOwnershipDigest,
  externalActionScopeReference,
  proposalMatchesContext,
  type ExternalActionApprovalBinding,
  type ExternalActionEvidenceDefinition,
  type ExternalActionProposalContext,
  type StoreBoundExternalActionAuthorization,
} from "./external-action-evidence.js";
import type {
  AuthenticatedApprovalDecisionEvidence,
  ControlPlaneAuditRecord,
  StoredPolicyVersion,
} from "./store.js";
import type {
  ApprovalRecord,
  CampaignRecord,
  OwnedObjectRecord,
  ProgramRecord,
  TestIdentityRecord,
} from "./types.js";
import {
  externalActionProposalDigest,
  type ExternalActionProposal,
} from "../external-actions/proposal.js";
import { sha256 } from "../shared/canonical.js";
import { SecurityError, errorCode } from "../shared/errors.js";

const MAX_APPROVAL_LIFETIME_MS = 15 * 60 * 1_000;

export interface ExternalActionEvidenceReader {
  getProgram(id: string): ProgramRecord | undefined;
  getPolicy(
    programId: string,
    version: number,
  ): StoredPolicyVersion | undefined;
  getCampaign(id: string): CampaignRecord | undefined;
  listIdentities(): readonly TestIdentityRecord[];
  assertOwnedObject(input: {
    readonly objectRef: string;
    readonly campaignId: string;
    readonly accountId: string;
    readonly policyHash: string;
    readonly action: string;
    readonly now: string;
  }): OwnedObjectRecord;
  listApprovals(): readonly ApprovalRecord[];
  listAuditEntries(): readonly ControlPlaneAuditRecord[];
  persistApproval(record: ApprovalRecord): void;
  requireAuthenticatedApprovalDecision(
    approval: ApprovalRecord,
    expectedContextDigest: string,
  ): AuthenticatedApprovalDecisionEvidence;
  isKillSwitchActive(): boolean;
}

export interface DescribeExternalActionContextInput {
  readonly definition: ExternalActionEvidenceDefinition;
  readonly campaignId: string;
  readonly accountId: string | null;
  readonly objectRef: string | null;
  readonly payloadRef: string | null;
  readonly now: string;
}

export interface CreateExternalActionApprovalInput {
  readonly proposal: ExternalActionProposal;
  readonly definition: ExternalActionEvidenceDefinition;
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface AuthorizeExternalActionInput {
  readonly proposal: ExternalActionProposal;
  readonly definition: ExternalActionEvidenceDefinition;
  readonly now: string;
  readonly runtimeMaxActions: number;
  readonly runtimeMaxConcurrency: number;
}

export interface ExternalActionAttemptRecord {
  readonly authorizationId: string;
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly actionId: string;
  readonly evidenceDigest: string;
  readonly status: "aborted" | "failed" | "reserved" | "running" | "succeeded";
  readonly units: 1;
  readonly reservedAt: string;
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
  readonly revision: number;
}

export class ExternalActionEvidenceStore {
  public constructor(
    private readonly database: ControlPlaneDatabase,
    private readonly reader: ExternalActionEvidenceReader,
  ) {
    Object.freeze(this);
  }

  public describe(
    input: DescribeExternalActionContextInput,
  ): ExternalActionProposalContext {
    return this.database.transaction(() => this.readContext(input));
  }

  public createApproval(
    input: CreateExternalActionApprovalInput,
  ): ApprovalRecord {
    return this.database.transaction(() => {
      assertTimestamp(input.createdAt, "ACTION_APPROVAL_TIME_INVALID");
      assertTimestamp(input.expiresAt, "ACTION_APPROVAL_TIME_INVALID");
      const createdAt = Date.parse(input.createdAt);
      const expiresAt = Date.parse(input.expiresAt);
      if (
        expiresAt <= createdAt ||
        expiresAt - createdAt > MAX_APPROVAL_LIFETIME_MS
      )
        throw new SecurityError("ACTION_APPROVAL_TIME_INVALID");
      assertProposalDefinition(input.proposal, input.definition);
      const context = this.readContext({
        definition: input.definition,
        campaignId: input.proposal.parameters.campaign_ref,
        accountId: input.proposal.parameters.account_ref,
        objectRef: input.proposal.parameters.object_ref,
        payloadRef: input.proposal.parameters.payload_ref,
        now: input.createdAt,
      });
      if (!proposalMatchesContext(input.proposal, context))
        throw new SecurityError("ACTION_PROPOSAL_EVIDENCE_MISMATCH");
      const approvalId = input.proposal.parameters.approval_ref;
      const operatorId = input.proposal.parameters.operator_ref;
      const proposalDigest = externalActionProposalDigest(input.proposal);
      const approval = new ApprovalQueue().enqueue({
        id: approvalId,
        kind: "external_action",
        summary: `Approve external action ${input.proposal.proposal_id}`,
        technicalDetails: `Action ${input.definition.actionId}; proposal digest ${proposalDigest}`,
        impact: "One deterministic local loopback simulation action",
        policyVersion: context.policyVersion,
        policyHash: context.policyHash,
        createdAt: input.createdAt,
        auditReference: `external-action:${input.proposal.proposal_id}`,
      });
      const withoutDigest: Omit<
        ExternalActionApprovalBinding,
        "bindingDigest"
      > = {
        ...context,
        approvalId,
        proposalId: input.proposal.proposal_id,
        proposalDigest,
        actionId: input.definition.actionId,
        operatorId,
        createdAt: input.createdAt,
        expiresAt: input.expiresAt,
        decisionAuditId: null,
      };
      const binding: ExternalActionApprovalBinding = Object.freeze({
        ...withoutDigest,
        bindingDigest: externalActionApprovalBindingDigest(withoutDigest),
      });
      this.reader.persistApproval(approval);
      this.insertBinding(binding);
      return approval;
    });
  }

  public approvalContextDigest(approvalId: string): string {
    const row = this.database.get(
      "SELECT * FROM external_action_approval_bindings WHERE approval_id=?",
      approvalId,
    );
    if (row === undefined)
      throw new SecurityError("ACTION_APPROVAL_BINDING_REQUIRED");
    const binding = bindingFromRow(row);
    if (
      binding.approvalId !== approvalId ||
      binding.bindingDigest !== externalActionApprovalBindingDigest(binding)
    )
      throw new SecurityError("ACTION_APPROVAL_BINDING_INVALID");
    return binding.bindingDigest;
  }

  public authorizeAndReserve(
    input: AuthorizeExternalActionInput,
  ): StoreBoundExternalActionAuthorization {
    return this.database.transaction(() => {
      assertRuntimeMaximum(input.runtimeMaxActions);
      assertRuntimeConcurrency(input.runtimeMaxConcurrency);
      assertProposalDefinition(input.proposal, input.definition);
      const context = this.readContext({
        definition: input.definition,
        campaignId: input.proposal.parameters.campaign_ref,
        accountId: input.proposal.parameters.account_ref,
        objectRef: input.proposal.parameters.object_ref,
        payloadRef: input.proposal.parameters.payload_ref,
        now: input.now,
      });
      if (!proposalMatchesContext(input.proposal, context))
        throw new SecurityError("ACTION_PROPOSAL_EVIDENCE_MISMATCH");
      const { binding, approval, decisionEvidence } = this.readAcceptedBinding(
        input.proposal,
        context,
        input.now,
      );
      const campaign = requiredCampaign(this.reader, context.campaignId);
      this.assertBudget(
        campaign,
        input.runtimeMaxActions,
        input.runtimeMaxConcurrency,
        input.proposal.proposal_id,
        externalActionProposalDigest(input.proposal),
        input.now,
      );
      const evidenceDigest = externalActionEvidenceDigest({
        binding,
        approvalPayloadHash: approval.payloadHash,
        approvalRevision: 1,
        decisionStatementDigest: decisionEvidence.statementDigest,
        decisionKeyFingerprintSha256: decisionEvidence.keyFingerprintSha256,
        decisionKeyRevision: decisionEvidence.keyRevision,
      });
      const authorizationId = `action-${sha256(
        `${binding.proposalDigest}\u0000${input.now}`,
      ).slice(0, 32)}`;
      const reservationAuditId = `reserve-${sha256(
        `${authorizationId}\u0000${evidenceDigest}`,
      ).slice(0, 32)}`;
      this.database.run(
        `INSERT INTO control_plane_audit(
          id,occurred_at,action,decision,reason_code,object_reference,payload_hash
        ) VALUES(?,?,?,?,?,?,?)`,
        reservationAuditId,
        input.now,
        "external_action_authorization",
        "reserved",
        "EXTERNAL_ACTION_RESERVED",
        authorizationId,
        evidenceDigest,
      );
      this.database.run(
        `INSERT INTO external_action_attempts(
          authorization_id,proposal_id,proposal_digest,action_id,program_id,
          campaign_id,campaign_revision,campaign_digest,policy_version,
          policy_hash,scope_ref,account_id,account_role,identity_digest,
          object_ref,ownership_digest,payload_ref,approval_id,operator_id,
          evidence_digest,units,status,reserved_at,started_at,finished_at,
          revision,reservation_audit_id
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'reserved',?,NULL,NULL,0,?)`,
        authorizationId,
        binding.proposalId,
        binding.proposalDigest,
        binding.actionId,
        binding.programId,
        binding.campaignId,
        binding.campaignRevision,
        binding.campaignDigest,
        binding.policyVersion,
        binding.policyHash,
        binding.scopeRef,
        binding.accountId,
        binding.accountRole,
        binding.identityDigest,
        binding.objectRef,
        binding.ownershipDigest,
        binding.payloadRef,
        binding.approvalId,
        binding.operatorId,
        evidenceDigest,
        input.now,
        reservationAuditId,
      );
      return Object.freeze({
        ...binding,
        authorizationId,
        evidenceDigest,
        approvalPayloadHash: approval.payloadHash,
        approvalRevision: 1 as const,
        decisionStatementDigest: decisionEvidence.statementDigest,
        decisionKeyFingerprintSha256: decisionEvidence.keyFingerprintSha256,
        decisionKeyRevision: decisionEvidence.keyRevision,
        reservationAuditId,
        reservedAt: input.now,
        units: 1 as const,
      });
    });
  }

  public start(
    proposal: ExternalActionProposal,
    definition: ExternalActionEvidenceDefinition,
    authorization: StoreBoundExternalActionAuthorization,
    at: string,
  ): void {
    assertTimestamp(at, "ACTION_EVIDENCE_TIME_INVALID");
    const denial = this.database.transaction(() => {
      try {
        this.assertAuthorizationCurrent(
          proposal,
          definition,
          authorization,
          at,
          "reserved",
          0,
        );
        const result = this.database.run(
          `UPDATE external_action_attempts
           SET status='running',started_at=?,revision=1
           WHERE authorization_id=? AND status='reserved' AND revision=0`,
          at,
          authorization.authorizationId,
        );
        if (result.changes !== 1)
          throw new SecurityError("ACTION_AUTHORIZATION_STATE_INVALID");
        return null;
      } catch (error) {
        return errorCode(error);
      }
    });
    if (denial !== null) throw new SecurityError(denial);
  }

  public abortReservation(
    proposal: ExternalActionProposal,
    authorization: StoreBoundExternalActionAuthorization,
    at: string,
  ): void {
    assertTimestamp(at, "ACTION_EVIDENCE_TIME_INVALID");
    this.database.transaction(() => {
      const attempt = this.assertAttemptMatches(
        proposal,
        authorization,
        "reserved",
        0,
      );
      const finishedAt = monotonicTimestamp(at, text(attempt, "reserved_at"));
      const result = this.database.run(
        `UPDATE external_action_attempts
         SET status='aborted',finished_at=?,revision=1
         WHERE authorization_id=? AND status='reserved' AND revision=0`,
        finishedAt,
        authorization.authorizationId,
      );
      if (result.changes !== 1)
        throw new SecurityError("ACTION_AUTHORIZATION_STATE_INVALID");
      this.insertSettlementAudit(
        authorization,
        "aborted",
        "STORE_BOUND_ACTION_ABORTED_BEFORE_START",
        finishedAt,
      );
    });
  }

  public settle(
    proposal: ExternalActionProposal,
    definition: ExternalActionEvidenceDefinition,
    authorization: StoreBoundExternalActionAuthorization,
    outcome: "aborted" | "failed" | "succeeded",
    at: string,
  ): void {
    assertTimestamp(at, "ACTION_EVIDENCE_TIME_INVALID");
    const denial = this.database.transaction(() => {
      let finalOutcome = outcome;
      let reason: string | null = null;
      let attempt: Readonly<Record<string, SqlValue>>;
      if (outcome === "succeeded") {
        try {
          attempt = this.assertAuthorizationCurrent(
            proposal,
            definition,
            authorization,
            at,
            "running",
            1,
          );
        } catch (error) {
          finalOutcome = "aborted";
          reason = errorCode(error);
          attempt = this.assertAttemptMatches(
            proposal,
            authorization,
            "running",
            1,
          );
        }
      } else {
        attempt = this.assertAttemptMatches(
          proposal,
          authorization,
          "running",
          1,
        );
      }
      const finishedAt = monotonicTimestamp(at, text(attempt, "started_at"));
      const result = this.database.run(
        `UPDATE external_action_attempts
         SET status=?,finished_at=?,revision=2
         WHERE authorization_id=? AND status='running' AND revision=1`,
        finalOutcome,
        finishedAt,
        authorization.authorizationId,
      );
      if (result.changes !== 1)
        throw new SecurityError("ACTION_AUTHORIZATION_STATE_INVALID");
      this.insertSettlementAudit(
        authorization,
        finalOutcome,
        reason ?? `STORE_BOUND_ACTION_${finalOutcome.toUpperCase()}`,
        finishedAt,
      );
      return reason;
    });
    if (denial !== null) throw new SecurityError(denial);
  }

  public listAttempts(): readonly ExternalActionAttemptRecord[] {
    return Object.freeze(
      this.database
        .all(
          `SELECT authorization_id,proposal_id,proposal_digest,action_id,
             evidence_digest,status,units,reserved_at,started_at,finished_at,
             revision
           FROM external_action_attempts ORDER BY reserved_at,authorization_id`,
        )
        .map(attemptFromRow),
    );
  }

  private readContext(
    input: DescribeExternalActionContextInput,
  ): ExternalActionProposalContext {
    assertTimestamp(input.now, "ACTION_EVIDENCE_TIME_INVALID");
    assertDefinition(input.definition);
    if (input.payloadRef !== null)
      throw new SecurityError("ACTION_PAYLOAD_REFERENCE_BLOCKED");
    if (this.reader.isKillSwitchActive())
      throw new SecurityError("ACTION_KILL_SWITCH");
    const campaign = requiredCampaign(this.reader, input.campaignId);
    if (
      campaign.state !== "running_simulation" ||
      campaign.killSwitchStatus !== "clear"
    )
      throw new SecurityError("ACTION_POLICY_BLOCKED");
    const now = Date.parse(input.now);
    if (
      now < Date.parse(campaign.contract.validFrom) ||
      now >= Date.parse(campaign.contract.validUntil) ||
      campaign.humanApprovedAt === null ||
      now < Date.parse(campaign.humanApprovedAt)
    )
      throw new SecurityError("ACTION_POLICY_BLOCKED");
    const program = this.reader.getProgram(campaign.programId);
    if (program === undefined) throw new SecurityError("ACTION_POLICY_BLOCKED");
    if (
      program.platform !== "local_mock" ||
      program.programType !== "simulation" ||
      program.status !== "available" ||
      program.lifecycle !== "active" ||
      program.automationPermission !== "allowed" ||
      program.ruleAcceptanceStatus !== "accepted" ||
      program.currentPolicyVersion !== campaign.policyVersion ||
      program.currentPolicyHash !== campaign.policyHash
    )
      throw new SecurityError("ACTION_POLICY_BLOCKED");
    if (
      campaign.approvedAssets.some(
        (asset) =>
          !program.allowedAssets.includes(asset) ||
          program.excludedAssets.includes(asset),
      )
    )
      throw new SecurityError("ACTION_SCOPE_BLOCKED");
    const policy = this.reader.getPolicy(
      campaign.programId,
      campaign.policyVersion,
    );
    if (policy === undefined) throw new SecurityError("ACTION_POLICY_BLOCKED");
    if (
      policy.acceptance === null ||
      now < Date.parse(policy.acceptance.acceptedAt) ||
      policy.policy.policyHash !== campaign.policyHash ||
      policy.policy.unclearRules.length !== 0 ||
      !policy.policy.allowedTestClasses.includes("offline_simulation") ||
      policy.policy.forbiddenTestClasses.includes("offline_simulation")
    )
      throw new SecurityError("ACTION_POLICY_BLOCKED");

    const { identity, object } = this.readOwnership(input, campaign);
    const scopeRef = externalActionScopeReference({
      definition: input.definition,
      campaign,
      policyVersion: campaign.policyVersion,
      policyHash: campaign.policyHash,
      identity,
      object,
    });
    return Object.freeze({
      programId: campaign.programId,
      campaignId: campaign.id,
      campaignRevision: campaign.revision,
      campaignDigest: externalActionCampaignDigest(campaign),
      policyVersion: campaign.policyVersion,
      policyHash: campaign.policyHash,
      scopeRef,
      accountId: identity?.id ?? null,
      accountRole: identity?.role ?? null,
      identityDigest:
        identity === null ? null : externalActionIdentityDigest(identity),
      objectRef: object?.objectRef ?? null,
      ownershipDigest:
        object === null ? null : externalActionOwnershipDigest(object),
      payloadRef: null,
    });
  }

  private readOwnership(
    input: DescribeExternalActionContextInput,
    campaign: CampaignRecord,
  ): {
    readonly identity: TestIdentityRecord | null;
    readonly object: OwnedObjectRecord | null;
  } {
    if (input.definition.ownershipCheck === "not_applicable") {
      if (input.accountId !== null || input.objectRef !== null)
        throw new SecurityError("ACTION_OWNERSHIP_BLOCKED");
      return { identity: null, object: null };
    }
    if (input.accountId === null)
      throw new SecurityError("ACTION_OWNERSHIP_BLOCKED");
    const identity = this.reader
      .listIdentities()
      .find((candidate) => candidate.id === input.accountId);
    if (identity === undefined)
      throw new SecurityError("ACTION_OWNERSHIP_BLOCKED");
    if (
      identity.programId !== campaign.programId ||
      identity.status !== "ready" ||
      identity.humanActionRequired ||
      identity.verifiedAt === null ||
      identity.organizationRef === null ||
      !campaign.accountRefs.includes(identity.id)
    )
      throw new SecurityError("ACTION_OWNERSHIP_BLOCKED");
    if (input.definition.ownershipCheck === "account") {
      if (input.objectRef !== null)
        throw new SecurityError("ACTION_OWNERSHIP_BLOCKED");
      return { identity, object: null };
    }
    if (input.objectRef === null || input.definition.ownedObjectAction === null)
      throw new SecurityError("ACTION_OWNERSHIP_BLOCKED");
    const object = this.reader.assertOwnedObject({
      objectRef: input.objectRef,
      campaignId: campaign.id,
      accountId: identity.id,
      policyHash: campaign.policyHash,
      action: input.definition.ownedObjectAction,
      now: input.now,
    });
    return { identity, object };
  }

  private readAcceptedBinding(
    proposal: ExternalActionProposal,
    context: ExternalActionProposalContext,
    now: string,
  ): {
    readonly binding: ExternalActionApprovalBinding;
    readonly approval: ApprovalRecord & { readonly revision: 1 };
    readonly decisionEvidence: AuthenticatedApprovalDecisionEvidence;
  } {
    const row = this.database.get(
      "SELECT * FROM external_action_approval_bindings WHERE approval_id=?",
      proposal.parameters.approval_ref,
    );
    if (row === undefined)
      throw new SecurityError("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    const binding = bindingFromRow(row);
    const expectedDigest = externalActionProposalDigest(proposal);
    if (
      binding.approvalId !== proposal.parameters.approval_ref ||
      binding.proposalId !== proposal.proposal_id ||
      binding.proposalDigest !== expectedDigest ||
      binding.actionId !== proposal.action_id ||
      binding.operatorId !== proposal.parameters.operator_ref ||
      binding.programId !== context.programId ||
      binding.campaignId !== context.campaignId ||
      binding.campaignRevision !== context.campaignRevision ||
      binding.campaignDigest !== context.campaignDigest ||
      binding.policyVersion !== context.policyVersion ||
      binding.policyHash !== context.policyHash ||
      binding.scopeRef !== context.scopeRef ||
      binding.accountId !== context.accountId ||
      binding.accountRole !== context.accountRole ||
      binding.identityDigest !== context.identityDigest ||
      binding.objectRef !== context.objectRef ||
      binding.ownershipDigest !== context.ownershipDigest ||
      binding.bindingDigest !== externalActionApprovalBindingDigest(binding) ||
      Date.parse(now) < Date.parse(binding.createdAt) ||
      Date.parse(now) >= Date.parse(binding.expiresAt)
    )
      throw new SecurityError("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    const approval = this.reader
      .listApprovals()
      .find((candidate) => candidate.id === binding.approvalId);
    if (approval === undefined)
      throw new SecurityError("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    new ApprovalQueue([approval]);
    if (
      approval.kind !== "external_action" ||
      approval.status !== "accepted" ||
      !isRevisionOneApproval(approval) ||
      approval.decidedBy !== binding.operatorId ||
      approval.decidedAt === null ||
      approval.userAction !== "approve_store_bound_external_action" ||
      approval.policyVersion !== binding.policyVersion ||
      approval.policyHash !== binding.policyHash ||
      Date.parse(approval.decidedAt) < Date.parse(binding.createdAt) ||
      Date.parse(approval.decidedAt) >= Date.parse(binding.expiresAt) ||
      binding.decisionAuditId === null
    )
      throw new SecurityError("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    assertTimestamp(approval.decidedAt, "ACTION_HUMAN_CHECKPOINT_REQUIRED");
    if (Date.parse(now) < Date.parse(approval.decidedAt))
      throw new SecurityError("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    const expectedAuditId = `approval-${sha256(
      `${approval.id}\u0000${approval.decidedAt}\u0000accepted`,
    ).slice(0, 32)}`;
    const audit = this.reader
      .listAuditEntries()
      .find((candidate) => candidate.id === binding.decisionAuditId);
    if (audit === undefined)
      throw new SecurityError("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    if (
      binding.decisionAuditId !== expectedAuditId ||
      audit.occurredAt !== approval.decidedAt ||
      audit.action !== "approval_decision" ||
      audit.decision !== "accepted" ||
      audit.reasonCode !== "HUMAN_APPROVAL_DECISION" ||
      audit.objectReference !== approval.id
    )
      throw new SecurityError("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    const decisionEvidence = this.reader.requireAuthenticatedApprovalDecision(
      approval,
      binding.bindingDigest,
    );
    if (audit.payloadHash !== decisionEvidence.statementDigest)
      throw new SecurityError("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    const campaign = requiredCampaign(this.reader, binding.campaignId);
    const policy = this.reader.getPolicy(
      binding.programId,
      binding.policyVersion,
    );
    if (
      campaign.humanApprovedBy !== binding.operatorId ||
      policy?.acceptance?.acceptedBy !== binding.operatorId
    )
      throw new SecurityError("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    return {
      binding,
      approval,
      decisionEvidence,
    };
  }

  private assertBudget(
    campaign: CampaignRecord,
    runtimeMaxActions: number,
    runtimeMaxConcurrency: number,
    proposalId: string,
    proposalDigest: string,
    now: string,
  ): void {
    if (
      this.database.get(
        `SELECT authorization_id FROM external_action_attempts
         WHERE proposal_id=? OR proposal_digest=?`,
        proposalId,
        proposalDigest,
      ) !== undefined
    )
      throw new SecurityError("ACTION_REPLAY_BLOCKED");
    const globalTotal = count(
      this.database.get(
        "SELECT count(*) AS value FROM external_action_attempts",
      ),
    );
    if (globalTotal >= runtimeMaxActions)
      throw new SecurityError("ACTION_BUDGET_EXCEEDED");
    const campaignTotal = count(
      this.database.get(
        "SELECT count(*) AS value FROM external_action_attempts WHERE campaign_id=?",
        campaign.id,
      ),
    );
    if (campaignTotal >= campaign.contract.maxRequests)
      throw new SecurityError("ACTION_BUDGET_EXCEEDED");
    const globalActive = count(
      this.database.get(
        `SELECT count(*) AS value FROM external_action_attempts
         WHERE status IN ('reserved','running')`,
      ),
    );
    if (globalActive >= runtimeMaxConcurrency)
      throw new SecurityError("ACTION_CONCURRENCY_EXCEEDED");
    const campaignActive = count(
      this.database.get(
        `SELECT count(*) AS value FROM external_action_attempts
         WHERE campaign_id=? AND status IN ('reserved','running')`,
        campaign.id,
      ),
    );
    if (campaignActive >= campaign.contract.maxConcurrency)
      throw new SecurityError("ACTION_CONCURRENCY_EXCEEDED");
    const last = this.database.get(
      "SELECT max(reserved_at) AS value FROM external_action_attempts",
    )?.["value"];
    if (typeof last === "string" && Date.parse(last) > Date.parse(now))
      throw new SecurityError("ACTION_CLOCK_ROLLBACK");
    const minuteStart = new Date(Date.parse(now) - 60_000).toISOString();
    const inMinute = count(
      this.database.get(
        `SELECT count(*) AS value FROM external_action_attempts
         WHERE campaign_id=? AND reserved_at>=?`,
        campaign.id,
        minuteStart,
      ),
    );
    if (inMinute >= campaign.contract.requestsPerMinute)
      throw new SecurityError("ACTION_RATE_BUDGET_EXCEEDED");
  }

  private assertAuthorizationCurrent(
    proposal: ExternalActionProposal,
    definition: ExternalActionEvidenceDefinition,
    authorization: StoreBoundExternalActionAuthorization,
    now: string,
    expectedStatus: ExternalActionAttemptRecord["status"],
    expectedRevision: number,
  ): Readonly<Record<string, SqlValue>> {
    const attempt = this.assertAttemptMatches(
      proposal,
      authorization,
      expectedStatus,
      expectedRevision,
    );
    const earliest =
      expectedStatus === "running"
        ? text(attempt, "started_at")
        : text(attempt, "reserved_at");
    if (Date.parse(now) < Date.parse(earliest))
      throw new SecurityError("ACTION_CLOCK_ROLLBACK");
    const context = this.readContext({
      definition,
      campaignId: proposal.parameters.campaign_ref,
      accountId: proposal.parameters.account_ref,
      objectRef: proposal.parameters.object_ref,
      payloadRef: proposal.parameters.payload_ref,
      now,
    });
    if (!proposalMatchesContext(proposal, context))
      throw new SecurityError("ACTION_EVIDENCE_CHANGED");
    const current = this.readAcceptedBinding(proposal, context, now);
    const digest = externalActionEvidenceDigest({
      binding: current.binding,
      approvalPayloadHash: current.approval.payloadHash,
      approvalRevision: 1,
      decisionStatementDigest: current.decisionEvidence.statementDigest,
      decisionKeyFingerprintSha256:
        current.decisionEvidence.keyFingerprintSha256,
      decisionKeyRevision: current.decisionEvidence.keyRevision,
    });
    if (digest !== authorization.evidenceDigest)
      throw new SecurityError("ACTION_EVIDENCE_CHANGED");
    return attempt;
  }

  private assertAttemptMatches(
    proposal: ExternalActionProposal,
    authorization: StoreBoundExternalActionAuthorization,
    expectedStatus: ExternalActionAttemptRecord["status"],
    expectedRevision: number,
  ): Readonly<Record<string, SqlValue>> {
    const row = this.database.get(
      "SELECT * FROM external_action_attempts WHERE authorization_id=?",
      authorization.authorizationId,
    );
    if (row === undefined)
      throw new SecurityError("ACTION_AUTHORIZATION_STATE_INVALID");
    if (
      row["proposal_id"] !== proposal.proposal_id ||
      row["proposal_digest"] !== externalActionProposalDigest(proposal) ||
      row["proposal_digest"] !== authorization.proposalDigest ||
      row["evidence_digest"] !== authorization.evidenceDigest ||
      row["approval_id"] !== authorization.approvalId ||
      row["operator_id"] !== authorization.operatorId ||
      row["status"] !== expectedStatus ||
      row["revision"] !== expectedRevision
    )
      throw new SecurityError("ACTION_AUTHORIZATION_STATE_INVALID");
    const reservationAuditId = text(row, "reservation_audit_id");
    const reservationAudit = this.database.get(
      "SELECT * FROM control_plane_audit WHERE id=?",
      reservationAuditId,
    );
    if (reservationAudit === undefined)
      throw new SecurityError("ACTION_AUTHORIZATION_STATE_INVALID");
    if (
      reservationAudit["occurred_at"] !== row["reserved_at"] ||
      reservationAudit["action"] !== "external_action_authorization" ||
      reservationAudit["decision"] !== "reserved" ||
      reservationAudit["reason_code"] !== "EXTERNAL_ACTION_RESERVED" ||
      reservationAudit["object_reference"] !== row["authorization_id"] ||
      reservationAudit["payload_hash"] !== row["evidence_digest"]
    )
      throw new SecurityError("ACTION_AUTHORIZATION_STATE_INVALID");
    return row;
  }

  private insertSettlementAudit(
    authorization: StoreBoundExternalActionAuthorization,
    outcome: "aborted" | "failed" | "succeeded",
    reason: string,
    at: string,
  ): void {
    const auditId = `settle-${sha256(
      `${authorization.authorizationId}\u0000${at}\u0000${outcome}`,
    ).slice(0, 32)}`;
    this.database.run(
      `INSERT INTO control_plane_audit(
        id,occurred_at,action,decision,reason_code,object_reference,payload_hash
      ) VALUES(?,?,?,?,?,?,?)`,
      auditId,
      at,
      "external_action_settlement",
      outcome,
      reason,
      authorization.proposalId,
      authorization.evidenceDigest,
    );
  }

  private insertBinding(binding: ExternalActionApprovalBinding): void {
    this.database.run(
      `INSERT INTO external_action_approval_bindings(
        approval_id,proposal_id,proposal_digest,action_id,program_id,campaign_id,
        campaign_revision,campaign_digest,policy_version,policy_hash,scope_ref,
        account_id,account_role,identity_digest,object_ref,ownership_digest,
        payload_ref,operator_id,created_at,expires_at,binding_digest,
        decision_audit_id
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
      binding.approvalId,
      binding.proposalId,
      binding.proposalDigest,
      binding.actionId,
      binding.programId,
      binding.campaignId,
      binding.campaignRevision,
      binding.campaignDigest,
      binding.policyVersion,
      binding.policyHash,
      binding.scopeRef,
      binding.accountId,
      binding.accountRole,
      binding.identityDigest,
      binding.objectRef,
      binding.ownershipDigest,
      binding.payloadRef,
      binding.operatorId,
      binding.createdAt,
      binding.expiresAt,
      binding.bindingDigest,
    );
  }
}

Object.freeze(ExternalActionEvidenceStore.prototype);
Object.freeze(ExternalActionEvidenceStore);

function assertProposalDefinition(
  proposal: ExternalActionProposal,
  definition: ExternalActionEvidenceDefinition,
): void {
  assertDefinition(definition);
  if (proposal.action_id !== definition.actionId)
    throw new SecurityError("ACTION_DEFINITION_MISMATCH");
}

function assertDefinition(definition: ExternalActionEvidenceDefinition): void {
  if (
    !isOne(definition.budgetUnits) ||
    (definition.ownershipCheck === "object") !==
      (definition.ownedObjectAction === "offline_inspect") ||
    (definition.ownershipCheck !== "object" &&
      definition.ownedObjectAction !== null)
  )
    throw new SecurityError("ACTION_DEFINITION_INVALID");
}

function requiredCampaign(
  reader: ExternalActionEvidenceReader,
  campaignId: string,
): CampaignRecord {
  const campaign = reader.getCampaign(campaignId);
  if (campaign === undefined) throw new SecurityError("ACTION_POLICY_BLOCKED");
  return campaign;
}

function assertTimestamp(value: string, code: string): void {
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  )
    throw new SecurityError(code);
}

function assertRuntimeMaximum(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 1_000)
    throw new SecurityError("ACTION_RUNTIME_INVALID");
}

function assertRuntimeConcurrency(value: number): void {
  if (value !== 1) throw new SecurityError("ACTION_RUNTIME_INVALID");
}

function monotonicTimestamp(value: string, earliest: string): string {
  return Date.parse(value) < Date.parse(earliest) ? earliest : value;
}

function bindingFromRow(
  row: Readonly<Record<string, SqlValue>>,
): ExternalActionApprovalBinding {
  const accountRole = nullableText(row, "account_role");
  if (
    accountRole !== null &&
    accountRole !== "Owner" &&
    accountRole !== "Member" &&
    accountRole !== "External"
  )
    throw new SecurityError("ACTION_BINDING_INVALID");
  const actionId = externalActionId(text(row, "action_id"));
  const payloadRef = nullableText(row, "payload_ref");
  if (payloadRef !== null) throw new SecurityError("ACTION_BINDING_INVALID");
  const binding: ExternalActionApprovalBinding = Object.freeze({
    approvalId: text(row, "approval_id"),
    proposalId: text(row, "proposal_id"),
    proposalDigest: digest(row, "proposal_digest"),
    actionId,
    programId: text(row, "program_id"),
    campaignId: text(row, "campaign_id"),
    campaignRevision: integer(row, "campaign_revision"),
    campaignDigest: digest(row, "campaign_digest"),
    policyVersion: integer(row, "policy_version"),
    policyHash: digest(row, "policy_hash"),
    scopeRef: text(row, "scope_ref"),
    accountId: nullableText(row, "account_id"),
    accountRole,
    identityDigest: nullableDigest(row, "identity_digest"),
    objectRef: nullableText(row, "object_ref"),
    ownershipDigest: nullableDigest(row, "ownership_digest"),
    payloadRef,
    operatorId: text(row, "operator_id"),
    createdAt: text(row, "created_at"),
    expiresAt: text(row, "expires_at"),
    bindingDigest: digest(row, "binding_digest"),
    decisionAuditId: nullableText(row, "decision_audit_id"),
  });
  assertTimestamp(binding.createdAt, "ACTION_BINDING_INVALID");
  assertTimestamp(binding.expiresAt, "ACTION_BINDING_INVALID");
  return binding;
}

function externalActionId(
  value: string,
): ExternalActionApprovalBinding["actionId"] {
  switch (value) {
    case "browser_journey_start":
    case "email_verification_open":
    case "platform_api_read":
    case "report_submit":
    case "target_request":
    case "test_account_register":
    case "triage_response_send":
      return value;
    default:
      throw new SecurityError("ACTION_BINDING_INVALID");
  }
}

function isRevisionOneApproval(
  approval: ApprovalRecord,
): approval is ApprovalRecord & { readonly revision: 1 } {
  return approval.revision === 1;
}

function isOne(value: unknown): value is 1 {
  return value === 1;
}

function attemptFromRow(
  row: Readonly<Record<string, SqlValue>>,
): ExternalActionAttemptRecord {
  const status = text(row, "status");
  if (
    status !== "aborted" &&
    status !== "failed" &&
    status !== "reserved" &&
    status !== "running" &&
    status !== "succeeded"
  )
    throw new SecurityError("ACTION_ATTEMPT_INVALID");
  if (integer(row, "units") !== 1)
    throw new SecurityError("ACTION_ATTEMPT_INVALID");
  return Object.freeze({
    authorizationId: text(row, "authorization_id"),
    proposalId: text(row, "proposal_id"),
    proposalDigest: digest(row, "proposal_digest"),
    actionId: text(row, "action_id"),
    evidenceDigest: digest(row, "evidence_digest"),
    status,
    units: 1,
    reservedAt: text(row, "reserved_at"),
    startedAt: nullableText(row, "started_at"),
    finishedAt: nullableText(row, "finished_at"),
    revision: integer(row, "revision"),
  });
}

function count(row: Readonly<Record<string, SqlValue>> | undefined): number {
  if (row === undefined) throw new SecurityError("ACTION_BUDGET_UNAVAILABLE");
  return integer(row, "value");
}

type SqlValue = null | number | bigint | string | Uint8Array;

function text(row: Readonly<Record<string, SqlValue>>, key: string): string {
  const value = row[key];
  if (typeof value !== "string")
    throw new SecurityError("ACTION_BINDING_INVALID");
  return value;
}

function nullableText(
  row: Readonly<Record<string, SqlValue>>,
  key: string,
): string | null {
  const value = row[key];
  if (value !== null && typeof value !== "string")
    throw new SecurityError("ACTION_BINDING_INVALID");
  return value;
}

function integer(row: Readonly<Record<string, SqlValue>>, key: string): number {
  const value = row[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value))
    throw new SecurityError("ACTION_BINDING_INVALID");
  return value;
}

function digest(row: Readonly<Record<string, SqlValue>>, key: string): string {
  const value = text(row, key);
  if (!/^[a-f0-9]{64}$/u.test(value))
    throw new SecurityError("ACTION_BINDING_INVALID");
  return value;
}

function nullableDigest(
  row: Readonly<Record<string, SqlValue>>,
  key: string,
): string | null {
  const value = nullableText(row, key);
  if (value !== null && !/^[a-f0-9]{64}$/u.test(value))
    throw new SecurityError("ACTION_BINDING_INVALID");
  return value;
}
