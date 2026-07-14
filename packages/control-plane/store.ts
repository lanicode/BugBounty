import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import { ApprovalQueue } from "./approval-queue.js";
import {
  campaignApprovalDigest,
  validateCampaignContract,
} from "./campaign-machine.js";
import { normalizePolicy, type NormalizedPolicy } from "./policy.js";
import {
  isTrustedControlPlaneDatabase,
  type ControlPlaneDatabase,
} from "./database.js";
import {
  ExternalActionEvidenceStore,
  type AuthorizeExternalActionInput,
  type CreateExternalActionApprovalInput,
  type DescribeExternalActionContextInput,
  type ExternalActionAttemptRecord,
} from "./external-action-store.js";
import type {
  ExternalActionProposalContext,
  StoreBoundExternalActionAuthorization,
} from "./external-action-evidence.js";
import type { ExternalActionProposal } from "../external-actions/proposal.js";
import type { ExternalActionEvidenceDefinition } from "./external-action-evidence.js";
import type {
  ApprovalRecord,
  CampaignRecord,
  OwnedObjectRecord,
  ProgramRecord,
  ReportDraftRecord,
  TestIdentityRecord,
} from "./types.js";
import { assertNoSensitiveMaterial } from "./sensitive.js";

export interface StoredPolicyVersion {
  readonly programId: string;
  readonly version: number;
  readonly policy: NormalizedPolicy;
  readonly createdAt: string;
  readonly acceptance: {
    readonly acceptedBy: string;
    readonly acceptedAt: string;
    readonly auditReference: string;
  } | null;
}

export interface ControlPlaneAuditRecord {
  readonly id: string;
  readonly occurredAt: string;
  readonly action: string;
  readonly decision: string;
  readonly reasonCode: string;
  readonly objectReference: string | null;
  readonly payloadHash: string;
}

const trustedControlPlaneStores = new WeakSet();

export class ControlPlaneStore {
  private readonly externalActions: ExternalActionEvidenceStore;

  public constructor(private readonly database: ControlPlaneDatabase) {
    if (!isTrustedControlPlaneDatabase(database))
      throw new SecurityError("CONTROL_PLANE_DATABASE_UNTRUSTED");
    this.externalActions = new ExternalActionEvidenceStore(database, this);
    trustedControlPlaneStores.add(this);
    Object.freeze(this);
  }

  public describeExternalActionContext(
    input: DescribeExternalActionContextInput,
  ): ExternalActionProposalContext {
    return this.externalActions.describe(input);
  }

  public createExternalActionApproval(
    input: CreateExternalActionApprovalInput,
  ): ApprovalRecord {
    return this.externalActions.createApproval(input);
  }

  public authorizeExternalAction(
    input: AuthorizeExternalActionInput,
  ): StoreBoundExternalActionAuthorization {
    return this.externalActions.authorizeAndReserve(input);
  }

  public startExternalAction(
    proposal: ExternalActionProposal,
    definition: ExternalActionEvidenceDefinition,
    authorization: StoreBoundExternalActionAuthorization,
    at: string,
  ): void {
    this.externalActions.start(proposal, definition, authorization, at);
  }

  public abortExternalActionReservation(
    proposal: ExternalActionProposal,
    authorization: StoreBoundExternalActionAuthorization,
    at: string,
  ): void {
    this.externalActions.abortReservation(proposal, authorization, at);
  }

  public settleExternalAction(
    proposal: ExternalActionProposal,
    definition: ExternalActionEvidenceDefinition,
    authorization: StoreBoundExternalActionAuthorization,
    outcome: "aborted" | "failed" | "succeeded",
    at: string,
  ): void {
    this.externalActions.settle(
      proposal,
      definition,
      authorization,
      outcome,
      at,
    );
  }

  public listExternalActionAttempts(): readonly ExternalActionAttemptRecord[] {
    return this.externalActions.listAttempts();
  }

  public createProgram(
    input: Omit<
      ProgramRecord,
      | "createdAt"
      | "currentPolicyHash"
      | "currentPolicyVersion"
      | "ruleAcceptanceStatus"
    >,
    createdAt: string,
  ): ProgramRecord {
    const program = freezeProgram({
      ...input,
      allowedAssets: normalizeStrings(input.allowedAssets),
      excludedAssets: normalizeStrings(input.excludedAssets),
      currentPolicyVersion: null,
      currentPolicyHash: null,
      ruleAcceptanceStatus: "pending",
      createdAt,
    });
    validateProgram(program);
    this.database.run(
      `INSERT INTO programs(
        id,name,platform,status,description,program_url,program_type,
        allowed_assets_json,excluded_assets_json,last_synchronized_at,
        current_policy_version,current_policy_hash,automation_permission,
        rule_acceptance_status,notes,lifecycle,created_at
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      program.id,
      program.name,
      program.platform,
      program.status,
      program.description,
      program.programUrl,
      program.programType,
      canonicalJson([...program.allowedAssets]),
      canonicalJson([...program.excludedAssets]),
      program.lastSynchronizedAt,
      program.currentPolicyVersion,
      program.currentPolicyHash,
      program.automationPermission,
      program.ruleAcceptanceStatus,
      program.notes,
      program.lifecycle,
      program.createdAt,
    );
    return program;
  }

  public getProgram(id: string): ProgramRecord | undefined {
    const row = this.database.get("SELECT * FROM programs WHERE id=?", id);
    return row === undefined ? undefined : programFromRow(row);
  }

  public listPrograms(): readonly ProgramRecord[] {
    return Object.freeze(
      this.database
        .all("SELECT * FROM programs ORDER BY id")
        .map(programFromRow),
    );
  }

  public addPolicyVersion(input: {
    readonly programId: string;
    readonly version: number;
    readonly policy: NormalizedPolicy;
    readonly createdAt: string;
  }): StoredPolicyVersion {
    assertId(input.programId, "PROGRAM_ID_INVALID");
    assertTimestamp(input.createdAt, "POLICY_TIMESTAMP_INVALID");
    if (!Number.isSafeInteger(input.version) || input.version < 1)
      throw new SecurityError("POLICY_VERSION_INVALID");
    const program = this.getProgram(input.programId);
    if (program === undefined) throw new SecurityError("PROGRAM_NOT_FOUND");
    const expectedVersion = (program.currentPolicyVersion ?? 0) + 1;
    if (input.version !== expectedVersion)
      throw new SecurityError("POLICY_VERSION_NOT_SEQUENTIAL");
    if (program.currentPolicyVersion !== null) {
      const current = this.getPolicy(
        input.programId,
        program.currentPolicyVersion,
      );
      if (
        current === undefined ||
        Date.parse(input.createdAt) < Date.parse(current.createdAt)
      )
        throw new SecurityError("POLICY_VERSION_ORDER_INVALID");
    }
    this.database.transaction(() => {
      this.database.run(
        `INSERT INTO policy_versions(
          program_id,version,normalized_json,policy_text,policy_hash,created_at
        ) VALUES(?,?,?,?,?,?)`,
        input.programId,
        input.version,
        input.policy.canonical,
        input.policy.text,
        input.policy.policyHash,
        input.createdAt,
      );
      this.database.run(
        `UPDATE programs SET current_policy_version=?,current_policy_hash=?,
          rule_acceptance_status='pending' WHERE id=?`,
        input.version,
        input.policy.policyHash,
        input.programId,
      );
      this.database.run(
        `UPDATE campaigns SET state='paused',revision=revision+1,
          human_approved_by=NULL,human_approved_at=NULL,
          last_policy_check_at=?
         WHERE program_id=? AND state IN ('approved','running_simulation')
           AND policy_hash<>?`,
        input.createdAt,
        input.programId,
        input.policy.policyHash,
      );
    });
    return freezePolicy({ ...input, acceptance: null });
  }

  public acceptPolicy(input: {
    readonly programId: string;
    readonly version: number;
    readonly expectedPolicyHash: string;
    readonly acceptedBy: string;
    readonly acceptedAt: string;
    readonly auditReference: string;
  }): StoredPolicyVersion {
    if (this.isKillSwitchActive())
      throw new SecurityError("POLICY_ACCEPTANCE_KILL_SWITCH");
    const program = this.getProgram(input.programId);
    if (program === undefined) throw new SecurityError("PROGRAM_NOT_FOUND");
    const policy = this.getPolicy(input.programId, input.version);
    if (policy === undefined) throw new SecurityError("POLICY_NOT_FOUND");
    if (policy.policy.policyHash !== input.expectedPolicyHash)
      throw new SecurityError("POLICY_ACCEPTANCE_HASH_MISMATCH");
    assertActor(input.acceptedBy, "POLICY_ACCEPTOR_INVALID");
    assertTimestamp(input.acceptedAt, "POLICY_ACCEPTANCE_TIMESTAMP_INVALID");
    if (Date.parse(input.acceptedAt) < Date.parse(policy.createdAt))
      throw new SecurityError("POLICY_ACCEPTANCE_TIMESTAMP_INVALID");
    assertReference(input.auditReference, "AUDIT_REFERENCE_INVALID");
    if (
      program.currentPolicyVersion !== input.version ||
      program.currentPolicyHash !== input.expectedPolicyHash
    )
      throw new SecurityError("POLICY_ACCEPTANCE_STALE");
    const approval = this.listApprovals().find(
      (candidate) =>
        candidate.kind === "program_policy_acceptance" &&
        candidate.status === "accepted" &&
        candidate.summary ===
          `Accept ${input.programId} policy version ${String(input.version)}` &&
        candidate.policyVersion === input.version &&
        candidate.policyHash === input.expectedPolicyHash &&
        candidate.decidedBy === input.acceptedBy &&
        candidate.decidedAt === input.acceptedAt &&
        candidate.auditReference === input.auditReference,
    );
    if (approval === undefined)
      throw new SecurityError("POLICY_ACCEPTANCE_EVIDENCE_REQUIRED");
    new ApprovalQueue([approval]);
    this.database.transaction(() => {
      this.database.run(
        `INSERT INTO policy_acceptances(
          program_id,version,policy_hash,accepted_by,accepted_at,audit_reference
        ) VALUES(?,?,?,?,?,?)`,
        input.programId,
        input.version,
        input.expectedPolicyHash,
        input.acceptedBy,
        input.acceptedAt,
        input.auditReference,
      );
      this.database.run(
        `UPDATE programs SET rule_acceptance_status='accepted'
         WHERE id=? AND current_policy_version=? AND current_policy_hash=?`,
        input.programId,
        input.version,
        input.expectedPolicyHash,
      );
    });
    return freezePolicy({
      ...policy,
      acceptance: Object.freeze({
        acceptedBy: input.acceptedBy,
        acceptedAt: input.acceptedAt,
        auditReference: input.auditReference,
      }),
    });
  }

  public getPolicy(
    programId: string,
    version: number,
  ): StoredPolicyVersion | undefined {
    const row = this.database.get(
      `SELECT p.*,a.accepted_by,a.accepted_at,a.audit_reference,
        a.policy_hash AS acceptance_policy_hash
       FROM policy_versions p LEFT JOIN policy_acceptances a
       ON p.program_id=a.program_id AND p.version=a.version
        AND p.policy_hash=a.policy_hash
       WHERE p.program_id=? AND p.version=?`,
      programId,
      version,
    );
    if (row === undefined) return undefined;
    const policy = policyFromRow(row);
    this.assertPolicyAcceptanceEvidence(policy);
    return policy;
  }

  public listPolicies(programId: string): readonly StoredPolicyVersion[] {
    return Object.freeze(
      this.database
        .all(
          `SELECT p.*,a.accepted_by,a.accepted_at,a.audit_reference,
            a.policy_hash AS acceptance_policy_hash
           FROM policy_versions p LEFT JOIN policy_acceptances a
           ON p.program_id=a.program_id AND p.version=a.version
            AND p.policy_hash=a.policy_hash
           WHERE p.program_id=? ORDER BY p.version`,
          programId,
        )
        .map((row) => {
          const policy = policyFromRow(row);
          this.assertPolicyAcceptanceEvidence(policy);
          return policy;
        }),
    );
  }

  public insertCampaign(campaign: CampaignRecord): CampaignRecord {
    validateCampaign(campaign);
    if (
      campaign.state !== "draft" ||
      campaign.revision !== 0 ||
      campaign.humanApprovedBy !== null ||
      campaign.humanApprovedAt !== null
    )
      throw new SecurityError("CAMPAIGN_INSERT_STATE_INVALID");
    this.assertCampaignPersistenceBindings(campaign);
    this.database.run(
      `INSERT INTO campaigns(
        id,program_id,policy_version,policy_hash,approved_assets_json,
        approved_risk_tiers_json,account_refs_json,allowed_action_classes_json,
        contract_json,state,revision,human_approved_by,human_approved_at,
        last_policy_check_at,kill_switch_status,created_at
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      campaign.id,
      campaign.programId,
      campaign.policyVersion,
      campaign.policyHash,
      canonicalJson([...campaign.approvedAssets]),
      canonicalJson([...campaign.approvedRiskTiers]),
      canonicalJson([...campaign.accountRefs]),
      canonicalJson([...campaign.allowedActionClasses]),
      canonicalJson(campaign.contract),
      campaign.state,
      campaign.revision,
      campaign.humanApprovedBy,
      campaign.humanApprovedAt,
      campaign.lastPolicyCheckAt,
      campaign.killSwitchStatus,
      campaign.createdAt,
    );
    return campaign;
  }

  public updateCampaign(
    expectedRevision: number,
    campaign: CampaignRecord,
  ): CampaignRecord {
    validateCampaign(campaign);
    if (campaign.revision !== expectedRevision + 1)
      throw new SecurityError("CAMPAIGN_REVISION_INVALID");
    const current = this.getCampaign(campaign.id);
    if (current?.revision !== expectedRevision)
      throw new SecurityError("CAMPAIGN_REVISION_CONFLICT");
    assertCampaignIdentityStable(current, campaign);
    assertCampaignTransition(current, campaign);
    this.assertCampaignPersistenceBindings(campaign);
    const result = this.database.run(
      `UPDATE campaigns SET policy_version=?,policy_hash=?,approved_assets_json=?,
       approved_risk_tiers_json=?,account_refs_json=?,allowed_action_classes_json=?,
       contract_json=?,state=?,revision=?,human_approved_by=?,human_approved_at=?,
       last_policy_check_at=?,kill_switch_status=? WHERE id=? AND revision=?`,
      campaign.policyVersion,
      campaign.policyHash,
      canonicalJson([...campaign.approvedAssets]),
      canonicalJson([...campaign.approvedRiskTiers]),
      canonicalJson([...campaign.accountRefs]),
      canonicalJson([...campaign.allowedActionClasses]),
      canonicalJson(campaign.contract),
      campaign.state,
      campaign.revision,
      campaign.humanApprovedBy,
      campaign.humanApprovedAt,
      campaign.lastPolicyCheckAt,
      campaign.killSwitchStatus,
      campaign.id,
      expectedRevision,
    );
    if (result.changes !== 1)
      throw new SecurityError("CAMPAIGN_REVISION_CONFLICT");
    return campaign;
  }

  public getCampaign(id: string): CampaignRecord | undefined {
    const row = this.database.get("SELECT * FROM campaigns WHERE id=?", id);
    if (row === undefined) return undefined;
    const campaign = campaignFromRow(row);
    this.assertCampaignPersistenceBindings(campaign);
    return campaign;
  }

  public listCampaigns(): readonly CampaignRecord[] {
    return Object.freeze(
      this.database.all("SELECT * FROM campaigns ORDER BY id").map((row) => {
        const campaign = campaignFromRow(row);
        this.assertCampaignPersistenceBindings(campaign);
        return campaign;
      }),
    );
  }

  public insertIdentity(identity: TestIdentityRecord): TestIdentityRecord {
    validateIdentity(identity);
    this.database.run(
      `INSERT INTO test_identities(
        id,program_id,role,status,email_reference,secret_references_json,
        browser_profile_reference,platform_account_reference,created_at,verified_at,
        suspended_at,retired_at,last_successful_login_at,human_action_required,
        organization_ref,owned_object_refs_json
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      identity.id,
      identity.programId,
      identity.role,
      identity.status,
      identity.emailReference,
      canonicalJson([...identity.secretReferences]),
      identity.browserProfileReference,
      identity.platformAccountReference,
      identity.createdAt,
      identity.verifiedAt,
      identity.suspendedAt,
      identity.retiredAt,
      identity.lastSuccessfulLoginAt,
      identity.humanActionRequired ? 1 : 0,
      identity.organizationRef,
      canonicalJson([...identity.ownedObjectRefs]),
    );
    return identity;
  }

  public listIdentities(): readonly TestIdentityRecord[] {
    return Object.freeze(
      this.database
        .all("SELECT * FROM test_identities ORDER BY id")
        .map(identityFromRow),
    );
  }

  public insertOwnedObject(object: OwnedObjectRecord): OwnedObjectRecord {
    validateOwnedObject(object);
    if (this.isKillSwitchActive())
      throw new SecurityError("CONTROL_PLANE_OBJECT_KILL_SWITCH");
    this.assertOwnershipBindings(object);
    this.database.run(
      `INSERT INTO owned_objects(
        object_ref,protected_actual_id_ref,program_id,campaign_id,account_id,
        tenant_ref,object_type,canary_hmac,created_at,status,researcher_controlled,
        allowed_actions_json,expires_at,policy_hash
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      object.objectRef,
      object.protectedActualIdRef,
      object.programId,
      object.campaignId,
      object.accountId,
      object.tenantRef,
      object.objectType,
      object.canaryHmac,
      object.createdAt,
      object.status,
      1,
      canonicalJson([...object.allowedActions]),
      object.expiresAt,
      object.policyHash,
    );
    return object;
  }

  public assertOwnedObject(input: {
    readonly objectRef: string;
    readonly campaignId: string;
    readonly accountId: string;
    readonly policyHash: string;
    readonly action: string;
    readonly now: string;
  }): OwnedObjectRecord {
    assertTimestamp(input.now, "CONTROL_PLANE_OBJECT_TIME_INVALID");
    if (this.isKillSwitchActive())
      throw new SecurityError("CONTROL_PLANE_OBJECT_KILL_SWITCH");
    const row = this.database.get(
      "SELECT * FROM owned_objects WHERE object_ref=?",
      input.objectRef,
    );
    if (row === undefined)
      throw new SecurityError("CONTROL_PLANE_OBJECT_UNKNOWN");
    const object = objectFromRow(row);
    if (object.status !== "active" || !isTrue(object.researcherControlled))
      throw new SecurityError("CONTROL_PLANE_OBJECT_NOT_ACTIVE");
    if (object.campaignId !== input.campaignId)
      throw new SecurityError("CONTROL_PLANE_OBJECT_CAMPAIGN_MISMATCH");
    if (object.accountId !== input.accountId)
      throw new SecurityError("CONTROL_PLANE_OBJECT_ACCOUNT_MISMATCH");
    if (object.policyHash !== input.policyHash)
      throw new SecurityError("CONTROL_PLANE_OBJECT_POLICY_MISMATCH");
    this.assertOwnershipBindings(object);
    if (!object.allowedActions.includes(input.action))
      throw new SecurityError("CONTROL_PLANE_OBJECT_ACTION_BLOCKED");
    if (Date.parse(object.expiresAt) <= Date.parse(input.now))
      throw new SecurityError("CONTROL_PLANE_OBJECT_EXPIRED");
    return object;
  }

  public listOwnedObjects(): readonly OwnedObjectRecord[] {
    return Object.freeze(
      this.database
        .all("SELECT * FROM owned_objects ORDER BY object_ref")
        .map(objectFromRow),
    );
  }

  public persistApproval(record: ApprovalRecord): void {
    new ApprovalQueue([record]);
    if (record.status !== "open" || record.revision !== 0)
      throw new SecurityError("APPROVAL_INSERT_STATE_INVALID");
    this.database.run(
      `INSERT INTO approvals(
        id,kind,summary,technical_details,impact,policy_version,policy_hash,
        created_at,status,decided_at,decided_by,user_action,audit_reference,
        payload_hash,revision
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      record.id,
      record.kind,
      record.summary,
      record.technicalDetails,
      record.impact,
      record.policyVersion,
      record.policyHash,
      record.createdAt,
      record.status,
      record.decidedAt,
      record.decidedBy,
      record.userAction,
      record.auditReference,
      record.payloadHash,
      record.revision,
    );
  }

  private updateApproval(
    expectedRevision: number,
    record: ApprovalRecord,
  ): void {
    new ApprovalQueue([record]);
    const result = this.database.run(
      `UPDATE approvals SET status=?,decided_at=?,decided_by=?,user_action=?,
       revision=? WHERE id=? AND revision=? AND payload_hash=?`,
      record.status,
      record.decidedAt,
      record.decidedBy,
      record.userAction,
      record.revision,
      record.id,
      expectedRevision,
      record.payloadHash,
    );
    if (result.changes !== 1)
      throw new SecurityError("APPROVAL_PERSISTENCE_CONFLICT");
  }

  public listApprovals(): readonly ApprovalRecord[] {
    return Object.freeze(
      this.database
        .all("SELECT * FROM approvals ORDER BY id")
        .map(approvalFromRow),
    );
  }

  public decideApproval(input: {
    readonly id: string;
    readonly expectedRevision: number;
    readonly expectedPayloadHash: string;
    readonly decision: "accepted" | "rejected";
    readonly actor: string;
    readonly userAction: string;
    readonly at: string;
  }): ApprovalRecord {
    return this.database.transaction(() => {
      if (this.isKillSwitchActive())
        throw new SecurityError("APPROVAL_KILL_SWITCH");
      const row = this.database.get(
        "SELECT * FROM approvals WHERE id=?",
        input.id,
      );
      if (row === undefined) throw new SecurityError("APPROVAL_NOT_FOUND");
      const current = approvalFromRow(row);
      const queue = new ApprovalQueue([current]);
      const decided = queue.decide({
        ...input,
        killSwitchActive: false,
      });
      this.updateApproval(current.revision, decided);
      this.database.run(
        `INSERT INTO control_plane_audit(
          id,occurred_at,action,decision,reason_code,object_reference,payload_hash
        ) VALUES(?,?,?,?,?,?,?)`,
        `approval-${sha256(`${input.id}\u0000${input.at}\u0000${input.decision}`).slice(0, 32)}`,
        input.at,
        "approval_decision",
        input.decision,
        "HUMAN_APPROVAL_DECISION",
        input.id,
        decided.payloadHash,
      );
      const binding = this.database.get(
        "SELECT approval_id FROM external_action_approval_bindings WHERE approval_id=?",
        input.id,
      );
      if (binding !== undefined && input.decision === "accepted") {
        const decisionAuditId = `approval-${sha256(`${input.id}\u0000${input.at}\u0000${input.decision}`).slice(0, 32)}`;
        const linked = this.database.run(
          `UPDATE external_action_approval_bindings
           SET decision_audit_id=?
           WHERE approval_id=? AND decision_audit_id IS NULL`,
          decisionAuditId,
          input.id,
        );
        if (linked.changes !== 1)
          throw new SecurityError("ACTION_APPROVAL_AUDIT_BINDING_FAILED");
      }
      return decided;
    });
  }

  public listAuditEntries(): readonly ControlPlaneAuditRecord[] {
    return Object.freeze(
      this.database
        .all("SELECT * FROM control_plane_audit ORDER BY occurred_at,id")
        .map((row) =>
          Object.freeze({
            id: text(row, "id"),
            occurredAt: text(row, "occurred_at"),
            action: text(row, "action"),
            decision: text(row, "decision"),
            reasonCode: text(row, "reason_code"),
            objectReference: nullableText(row, "object_reference"),
            payloadHash: text(row, "payload_hash"),
          }),
        ),
    );
  }

  public insertReportDraft(report: ReportDraftRecord): ReportDraftRecord {
    validateReport(report);
    this.database.run(
      `INSERT INTO report_drafts(
        id,campaign_id,title,summary,created_at,status,external_submission_performed
      ) VALUES(?,?,?,?,?,?,0)`,
      report.id,
      report.campaignId,
      report.title,
      report.summary,
      report.createdAt,
      report.status,
    );
    return report;
  }

  public listReportDrafts(): readonly ReportDraftRecord[] {
    return Object.freeze(
      this.database
        .all("SELECT * FROM report_drafts ORDER BY id")
        .map(reportFromRow),
    );
  }

  public isKillSwitchActive(): boolean {
    try {
      const row = this.database.get(
        `SELECT s.value,s.revision,s.updated_at,s.audit_reference,
          a.id AS audit_id,a.occurred_at AS audit_occurred_at,
          a.action AS audit_action,a.decision AS audit_decision,
          a.reason_code AS audit_reason_code,
          a.object_reference AS audit_actor,a.payload_hash AS audit_payload_hash
         FROM system_state s LEFT JOIN control_plane_audit a
           ON a.id=s.audit_reference
         WHERE s.key='global_kill_switch'`,
      );
      return row === undefined || !validKillSwitchClear(row);
    } catch {
      return true;
    }
  }

  public setKillSwitch(
    active: boolean,
    actor: string,
    at: string,
  ): { readonly active: boolean; readonly revision: number } {
    if (typeof active !== "boolean")
      throw new SecurityError("KILL_SWITCH_VALUE_INVALID");
    assertActor(actor, "KILL_SWITCH_ACTOR_INVALID");
    assertTimestamp(at, "KILL_SWITCH_TIMESTAMP_INVALID");
    const value = active ? "engaged" : "clear";
    const id = `kill-${sha256(`${actor}\u0000${at}\u0000${value}`).slice(0, 32)}`;
    const operation = (): {
      readonly active: boolean;
      readonly revision: number;
    } => {
      const revision = nextKillSwitchRevision(this.database);
      this.database.run(
        `INSERT INTO control_plane_audit(
          id,occurred_at,action,decision,reason_code,object_reference,payload_hash
        ) VALUES(?,?,?,?,?,?,?)`,
        id,
        at,
        "kill_switch_change",
        value,
        active ? "HUMAN_KILL_SWITCH_ENGAGED" : "HUMAN_KILL_SWITCH_CLEARED",
        actor,
        sha256(canonicalJson({ active, actor, at, revision })),
      );
      this.database.run(
        `UPDATE system_state SET value=?,revision=?,updated_at=?,audit_reference=?
         WHERE key='global_kill_switch'`,
        value,
        revision,
        at,
        id,
      );
      return Object.freeze({ active, revision });
    };
    if (!active) return this.database.transaction(operation);
    // Engagement is written first. If audit persistence fails, callers receive an
    // error but the system remains blocked instead of rolling back to unsafe state.
    const revision = nextKillSwitchRevision(this.database);
    this.database.run(
      `UPDATE system_state SET value='engaged',revision=?,updated_at=?,
       audit_reference=NULL
       WHERE key='global_kill_switch'`,
      revision,
      at,
    );
    this.database.run(
      `UPDATE campaigns SET state='paused',revision=revision+1,
       human_approved_by=NULL,human_approved_at=NULL,
       last_policy_check_at=?,kill_switch_status='engaged'
       WHERE state IN ('approved','running_simulation')`,
      at,
    );
    try {
      this.database.run(
        `INSERT INTO control_plane_audit(
          id,occurred_at,action,decision,reason_code,object_reference,payload_hash
        ) VALUES(?,?,?,?,?,?,?)`,
        id,
        at,
        "kill_switch_change",
        "engaged",
        "HUMAN_KILL_SWITCH_ENGAGED",
        actor,
        sha256(canonicalJson({ active, actor, at, revision })),
      );
      this.database.run(
        `UPDATE system_state SET audit_reference=?
         WHERE key='global_kill_switch' AND revision=? AND value='engaged'`,
        id,
        revision,
      );
    } catch (error) {
      throw new SecurityError(
        `KILL_SWITCH_AUDIT_FAILED:${error instanceof Error ? error.name : "UNKNOWN"}`,
      );
    }
    return Object.freeze({ active: true, revision });
  }

  private assertPolicyAcceptanceEvidence(policy: StoredPolicyVersion): void {
    const acceptance = policy.acceptance;
    if (acceptance === null) return;
    const approval = this.listApprovals().find(
      (candidate) =>
        candidate.kind === "program_policy_acceptance" &&
        candidate.status === "accepted" &&
        candidate.summary ===
          `Accept ${policy.programId} policy version ${String(policy.version)}` &&
        candidate.policyVersion === policy.version &&
        candidate.policyHash === policy.policy.policyHash &&
        candidate.decidedBy === acceptance.acceptedBy &&
        candidate.decidedAt === acceptance.acceptedAt &&
        candidate.auditReference === acceptance.auditReference,
    );
    if (approval === undefined)
      throw new SecurityError("POLICY_ACCEPTANCE_EVIDENCE_INVALID");
    new ApprovalQueue([approval]);
  }

  private assertCampaignPersistenceBindings(campaign: CampaignRecord): void {
    validateCampaignContract(campaign);
    const program = this.getProgram(campaign.programId);
    if (program === undefined) throw new SecurityError("PROGRAM_NOT_FOUND");
    const policy = this.getPolicy(campaign.programId, campaign.policyVersion);
    if (policy === undefined)
      throw new SecurityError("CAMPAIGN_POLICY_NOT_FOUND");
    if (policy.policy.policyHash !== campaign.policyHash)
      throw new SecurityError("CAMPAIGN_POLICY_HASH_MISMATCH");
    if (
      !["paused", "blocked", "cancelled", "completed"].includes(
        campaign.state,
      ) &&
      (program.currentPolicyVersion !== campaign.policyVersion ||
        program.currentPolicyHash !== campaign.policyHash)
    )
      throw new SecurityError("CAMPAIGN_POLICY_STALE");
    const allowedAssets = new Set(policy.policy.allowedAssets);
    if (
      campaign.approvedAssets.length === 0 ||
      campaign.approvedAssets.some((asset) => !allowedAssets.has(asset))
    )
      throw new SecurityError("CAMPAIGN_ASSET_UNKNOWN");
    if (
      canonicalJson([...campaign.contract.excludedHosts]) !==
      canonicalJson([...policy.policy.excludedAssets])
    )
      throw new SecurityError("CAMPAIGN_EXCLUDED_ASSET_MISMATCH");
    if (
      campaign.contract.maxRequests >
        policy.policy.requestLimits.maxRequestsTotal ||
      campaign.contract.requestsPerMinute >
        policy.policy.requestLimits.requestsPerMinute ||
      campaign.contract.maxConcurrency >
        policy.policy.requestLimits.maxConcurrency
    )
      throw new SecurityError("CAMPAIGN_POLICY_BUDGET_EXCEEDED");
    if (
      campaign.state === "awaiting_campaign_approval" ||
      campaign.state === "approved" ||
      campaign.state === "running_simulation"
    ) {
      if (policy.acceptance === null)
        throw new SecurityError("CAMPAIGN_POLICY_NOT_ACCEPTED");
    }
    if (
      campaign.state === "approved" ||
      campaign.state === "running_simulation"
    ) {
      if (
        campaign.humanApprovedBy === null ||
        campaign.humanApprovedAt === null
      )
        throw new SecurityError("CAMPAIGN_HUMAN_APPROVAL_REQUIRED");
      if (Date.parse(campaign.humanApprovedAt) < Date.parse(campaign.createdAt))
        throw new SecurityError("CAMPAIGN_APPROVAL_TIME_INVALID");
      const campaignApproval = this.listApprovals().find(
        (approval) =>
          approval.kind === "campaign_contract" &&
          approval.status === "accepted" &&
          approval.summary === `Approve ${campaign.id}` &&
          approval.policyVersion === campaign.policyVersion &&
          approval.policyHash === campaign.policyHash &&
          approval.decidedBy === campaign.humanApprovedBy &&
          approval.decidedAt === campaign.humanApprovedAt &&
          approval.technicalDetails.includes(
            `Campaign digest ${campaignApprovalDigest(campaign)}`,
          ),
      );
      if (campaignApproval === undefined)
        throw new SecurityError("CAMPAIGN_APPROVAL_EVIDENCE_REQUIRED");
      new ApprovalQueue([campaignApproval]);
      if (this.isKillSwitchActive() || campaign.killSwitchStatus !== "clear")
        throw new SecurityError("CAMPAIGN_KILL_SWITCH");
    }
  }

  private assertOwnershipBindings(object: OwnedObjectRecord): void {
    const campaign = this.getCampaign(object.campaignId);
    if (campaign === undefined)
      throw new SecurityError("CONTROL_PLANE_OBJECT_CAMPAIGN_UNKNOWN");
    this.assertCampaignPersistenceBindings(campaign);
    const identityRow = this.database.get(
      "SELECT * FROM test_identities WHERE id=?",
      object.accountId,
    );
    if (identityRow === undefined)
      throw new SecurityError("CONTROL_PLANE_OBJECT_ACCOUNT_UNKNOWN");
    const identity = identityFromRow(identityRow);
    if (
      campaign.programId !== object.programId ||
      identity.programId !== object.programId
    )
      throw new SecurityError("CONTROL_PLANE_OBJECT_PROGRAM_MISMATCH");
    if (
      identity.status !== "ready" ||
      identity.humanActionRequired ||
      identity.organizationRef !== object.tenantRef ||
      !identity.ownedObjectRefs.includes(object.objectRef)
    )
      throw new SecurityError("CONTROL_PLANE_OBJECT_ACCOUNT_BINDING_INVALID");
    if (
      campaign.state !== "running_simulation" ||
      campaign.policyHash !== object.policyHash ||
      !campaign.accountRefs.includes(identity.id)
    )
      throw new SecurityError("CONTROL_PLANE_OBJECT_CAMPAIGN_BINDING_INVALID");
    const policy = this.getPolicy(campaign.programId, campaign.policyVersion);
    if (
      policy?.policy.policyHash !== object.policyHash ||
      policy.acceptance === null
    )
      throw new SecurityError("CONTROL_PLANE_OBJECT_POLICY_BINDING_INVALID");
  }
}

Object.freeze(ControlPlaneStore.prototype);
Object.freeze(ControlPlaneStore);

export function isTrustedControlPlaneStore(
  value: unknown,
): value is ControlPlaneStore {
  if (typeof value !== "object" || value === null) return false;
  try {
    return (
      trustedControlPlaneStores.has(value) &&
      Reflect.getPrototypeOf(value) === ControlPlaneStore.prototype
    );
  } catch {
    return false;
  }
}

function nextKillSwitchRevision(database: ControlPlaneDatabase): number {
  const row = database.get(
    "SELECT revision FROM system_state WHERE key='global_kill_switch'",
  );
  const revision = row?.["revision"];
  if (
    typeof revision !== "number" ||
    !Number.isSafeInteger(revision) ||
    revision < 0 ||
    revision >= Number.MAX_SAFE_INTEGER
  )
    throw new SecurityError("KILL_SWITCH_STATE_UNAVAILABLE");
  return revision + 1;
}

function validKillSwitchClear(row: Row): boolean {
  const revision = row["revision"];
  const at = row["updated_at"];
  const actor = row["audit_actor"];
  const auditReference = row["audit_reference"];
  if (
    row["value"] !== "clear" ||
    typeof revision !== "number" ||
    !Number.isSafeInteger(revision) ||
    revision < 1 ||
    typeof at !== "string" ||
    !Number.isFinite(Date.parse(at)) ||
    typeof actor !== "string" ||
    !/^[A-Za-z0-9._@-]{1,128}$/u.test(actor) ||
    typeof auditReference !== "string"
  )
    return false;
  const expectedAuditId = `kill-${sha256(`${actor}\u0000${at}\u0000clear`).slice(0, 32)}`;
  return (
    auditReference === expectedAuditId &&
    row["audit_id"] === expectedAuditId &&
    row["audit_occurred_at"] === at &&
    row["audit_action"] === "kill_switch_change" &&
    row["audit_decision"] === "clear" &&
    row["audit_reason_code"] === "HUMAN_KILL_SWITCH_CLEARED" &&
    row["audit_payload_hash"] ===
      sha256(canonicalJson({ active: false, actor, at, revision }))
  );
}

type Row = Readonly<
  Record<string, null | number | bigint | string | Uint8Array>
>;

function programFromRow(row: Row): ProgramRecord {
  const program = freezeProgram({
    id: text(row, "id"),
    name: text(row, "name"),
    platform: enumText(row, "platform", ["manual", "local_mock"]),
    status: enumText(row, "status", ["available", "unavailable"]),
    description: text(row, "description"),
    programUrl: text(row, "program_url"),
    programType: enumText(row, "program_type", [
      "private",
      "public",
      "simulation",
    ]),
    allowedAssets: stringArray(row, "allowed_assets_json"),
    excludedAssets: stringArray(row, "excluded_assets_json"),
    lastSynchronizedAt: nullableText(row, "last_synchronized_at"),
    currentPolicyVersion: nullableNumber(row, "current_policy_version"),
    currentPolicyHash: nullableText(row, "current_policy_hash"),
    automationPermission: enumText(row, "automation_permission", [
      "allowed",
      "forbidden",
      "unclear",
    ]),
    ruleAcceptanceStatus: enumText(row, "rule_acceptance_status", [
      "accepted",
      "pending",
    ]),
    notes: text(row, "notes"),
    lifecycle: enumText(row, "lifecycle", [
      "active",
      "inactive",
      "paused",
      "archived",
    ]),
    createdAt: text(row, "created_at"),
  });
  validateProgram(program);
  return program;
}

function policyFromRow(row: Row): StoredPolicyVersion {
  const canonical = text(row, "normalized_json");
  const document = jsonObject(row, "normalized_json");
  assertExactKeys(document, [
    "allowedAssets",
    "allowedTestClasses",
    "excludedAssets",
    "forbiddenTestClasses",
    "requestLimits",
    "rules",
    "text",
    "unclearRules",
    "version",
  ]);
  if (document["version"] !== 1)
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  const requestLimits = recordValue(document["requestLimits"]);
  assertExactKeys(requestLimits, [
    "maxConcurrency",
    "maxRequestsTotal",
    "requestsPerMinute",
  ]);
  const policy = normalizePolicy({
    text: stringValue(document["text"]),
    allowedAssets: stringArrayValue(document["allowedAssets"]),
    excludedAssets: stringArrayValue(document["excludedAssets"]),
    requestLimits: {
      requestsPerMinute: integerValue(requestLimits["requestsPerMinute"]),
      maxRequestsTotal: integerValue(requestLimits["maxRequestsTotal"]),
      maxConcurrency: integerValue(requestLimits["maxConcurrency"]),
    },
    allowedTestClasses: stringArrayValue(document["allowedTestClasses"]),
    forbiddenTestClasses: stringArrayValue(document["forbiddenTestClasses"]),
    rules: stringArrayValue(document["rules"]),
    unclearRules: stringArrayValue(document["unclearRules"]),
  });
  if (
    policy.canonical !== canonical ||
    policy.policyHash !== text(row, "policy_hash")
  )
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  const acceptedBy = nullableText(row, "accepted_by");
  const acceptancePolicyHash = nullableText(row, "acceptance_policy_hash");
  if (
    (acceptedBy === null) !== (acceptancePolicyHash === null) ||
    (acceptancePolicyHash !== null &&
      acceptancePolicyHash !== policy.policyHash)
  )
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return freezePolicy({
    programId: text(row, "program_id"),
    version: number(row, "version"),
    policy,
    createdAt: text(row, "created_at"),
    acceptance:
      acceptedBy === null
        ? null
        : Object.freeze({
            acceptedBy,
            acceptedAt: text(row, "accepted_at"),
            auditReference: text(row, "audit_reference"),
          }),
  });
}

function campaignFromRow(row: Row): CampaignRecord {
  const campaign = Object.freeze({
    id: text(row, "id"),
    programId: text(row, "program_id"),
    policyVersion: number(row, "policy_version"),
    policyHash: text(row, "policy_hash"),
    approvedAssets: stringArray(row, "approved_assets_json"),
    approvedRiskTiers: tuple(row, "approved_risk_tiers_json", "tier_0_offline"),
    accountRefs: stringArray(row, "account_refs_json"),
    allowedActionClasses: tuple(
      row,
      "allowed_action_classes_json",
      "offline_simulation",
    ),
    contract: campaignContractFromRow(row),
    state: enumText(row, "state", [
      "draft",
      "awaiting_policy_acceptance",
      "awaiting_campaign_approval",
      "approved",
      "running_simulation",
      "paused",
      "blocked",
      "completed",
      "cancelled",
    ]),
    revision: number(row, "revision"),
    humanApprovedBy: nullableText(row, "human_approved_by"),
    humanApprovedAt: nullableText(row, "human_approved_at"),
    lastPolicyCheckAt: nullableText(row, "last_policy_check_at"),
    killSwitchStatus: enumText(row, "kill_switch_status", ["clear", "engaged"]),
    createdAt: text(row, "created_at"),
  });
  validateCampaign(campaign);
  validateCampaignContract(campaign);
  return campaign;
}

function identityFromRow(row: Row): TestIdentityRecord {
  const identity = Object.freeze({
    id: text(row, "id"),
    programId: text(row, "program_id"),
    role: enumText(row, "role", ["Owner", "Member", "External"]),
    status: enumText(row, "status", [
      "planned",
      "awaiting_manual_registration",
      "awaiting_email_verification",
      "awaiting_captcha",
      "awaiting_terms_acceptance",
      "ready",
      "session_expired",
      "suspended",
      "retired",
    ]),
    emailReference: nullableText(row, "email_reference"),
    secretReferences: stringArray(row, "secret_references_json"),
    browserProfileReference: nullableText(row, "browser_profile_reference"),
    platformAccountReference: nullableText(row, "platform_account_reference"),
    createdAt: text(row, "created_at"),
    verifiedAt: nullableText(row, "verified_at"),
    suspendedAt: nullableText(row, "suspended_at"),
    retiredAt: nullableText(row, "retired_at"),
    lastSuccessfulLoginAt: nullableText(row, "last_successful_login_at"),
    humanActionRequired: number(row, "human_action_required") === 1,
    organizationRef: nullableText(row, "organization_ref"),
    ownedObjectRefs: stringArray(row, "owned_object_refs_json"),
  });
  validateIdentity(identity);
  return identity;
}

function objectFromRow(row: Row): OwnedObjectRecord {
  if (number(row, "researcher_controlled") !== 1)
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  const object = Object.freeze({
    objectRef: text(row, "object_ref"),
    protectedActualIdRef: text(row, "protected_actual_id_ref"),
    programId: text(row, "program_id"),
    campaignId: text(row, "campaign_id"),
    accountId: text(row, "account_id"),
    tenantRef: text(row, "tenant_ref"),
    objectType: text(row, "object_type"),
    canaryHmac: text(row, "canary_hmac"),
    createdAt: text(row, "created_at"),
    status: enumText(row, "status", ["active", "deleted"]),
    researcherControlled: true,
    allowedActions: stringArray(row, "allowed_actions_json"),
    expiresAt: text(row, "expires_at"),
    policyHash: text(row, "policy_hash"),
  });
  validateOwnedObject(object);
  return object;
}

function approvalFromRow(row: Row): ApprovalRecord {
  const approval = Object.freeze({
    id: text(row, "id"),
    kind: enumText(row, "kind", [
      "program_policy_acceptance",
      "campaign_contract",
      "account_manual_action",
      "external_action",
      "tier_3_action",
      "privacy_alert",
      "report_bundle",
      "triage_response",
    ]),
    summary: text(row, "summary"),
    technicalDetails: text(row, "technical_details"),
    impact: text(row, "impact"),
    policyVersion: nullableNumber(row, "policy_version"),
    policyHash: nullableText(row, "policy_hash"),
    createdAt: text(row, "created_at"),
    status: enumText(row, "status", ["open", "accepted", "rejected"]),
    decidedAt: nullableText(row, "decided_at"),
    decidedBy: nullableText(row, "decided_by"),
    userAction: nullableText(row, "user_action"),
    auditReference: text(row, "audit_reference"),
    payloadHash: text(row, "payload_hash"),
    revision: number(row, "revision"),
  });
  new ApprovalQueue([approval]);
  return approval;
}

function reportFromRow(row: Row): ReportDraftRecord {
  if (number(row, "external_submission_performed") !== 0)
    throw new SecurityError("REPORT_EXTERNAL_STATE_INVALID");
  const report = Object.freeze({
    id: text(row, "id"),
    campaignId: text(row, "campaign_id"),
    title: text(row, "title"),
    summary: text(row, "summary"),
    createdAt: text(row, "created_at"),
    status: enumText(row, "status", ["draft", "queued_for_human_review"]),
    externalSubmissionPerformed: false,
  });
  validateReport(report);
  return report;
}

function validateProgram(program: ProgramRecord): void {
  assertId(program.id, "PROGRAM_ID_INVALID");
  assertTimestamp(program.createdAt, "PROGRAM_TIMESTAMP_INVALID");
  if (
    program.name.trim().length === 0 ||
    program.name.length > 200 ||
    program.description.length > 10_000 ||
    program.notes.length > 10_000 ||
    intersects(program.allowedAssets, program.excludedAssets)
  )
    throw new SecurityError("PROGRAM_INPUT_INVALID");
  assertNoSensitiveMaterial(
    [
      program.name,
      program.description,
      program.notes,
      program.programUrl,
      ...program.allowedAssets,
      ...program.excludedAssets,
    ],
    "PROGRAM_SENSITIVE_MATERIAL",
  );
  let url: URL;
  try {
    url = new URL(program.programUrl);
  } catch {
    throw new SecurityError("PROGRAM_URL_INVALID");
  }
  if (
    !["https:", "http:"].includes(url.protocol) ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== ""
  )
    throw new SecurityError("PROGRAM_URL_INVALID");
}

function validateCampaign(campaign: CampaignRecord): void {
  assertId(campaign.id, "CAMPAIGN_ID_INVALID");
  assertId(campaign.programId, "PROGRAM_ID_INVALID");
  assertTimestamp(campaign.createdAt, "CAMPAIGN_TIMESTAMP_INVALID");
  if (!/^[a-f0-9]{64}$/u.test(campaign.policyHash))
    throw new SecurityError("CAMPAIGN_POLICY_HASH_INVALID");
  if (
    campaign.accountRefs.length === 0 ||
    new Set(campaign.accountRefs).size !== campaign.accountRefs.length
  )
    throw new SecurityError("CAMPAIGN_ACCOUNT_REFS_INVALID");
  for (const accountRef of campaign.accountRefs)
    assertId(accountRef, "CAMPAIGN_ACCOUNT_REFS_INVALID");
}

function assertCampaignIdentityStable(
  current: CampaignRecord,
  next: CampaignRecord,
): void {
  if (
    current.id !== next.id ||
    current.programId !== next.programId ||
    current.createdAt !== next.createdAt
  )
    throw new SecurityError("CAMPAIGN_IDENTITY_MUTATION_BLOCKED");
  const policyRebind =
    current.state === "paused" && next.state === "awaiting_campaign_approval";
  if (
    !policyRebind &&
    (current.policyVersion !== next.policyVersion ||
      current.policyHash !== next.policyHash ||
      canonicalJson(current.contract) !== canonicalJson(next.contract) ||
      canonicalJson([...current.approvedAssets]) !==
        canonicalJson([...next.approvedAssets]) ||
      canonicalJson([...current.approvedRiskTiers]) !==
        canonicalJson([...next.approvedRiskTiers]) ||
      canonicalJson([...current.accountRefs]) !==
        canonicalJson([...next.accountRefs]) ||
      canonicalJson([...current.allowedActionClasses]) !==
        canonicalJson([...next.allowedActionClasses]))
  )
    throw new SecurityError("CAMPAIGN_CONTRACT_MUTATION_BLOCKED");
}

function assertCampaignTransition(
  current: CampaignRecord,
  next: CampaignRecord,
): void {
  const transitions: Readonly<
    Record<CampaignRecord["state"], readonly CampaignRecord["state"][]>
  > = {
    draft: [
      "awaiting_policy_acceptance",
      "awaiting_campaign_approval",
      "blocked",
      "cancelled",
    ],
    awaiting_policy_acceptance: [
      "awaiting_campaign_approval",
      "blocked",
      "cancelled",
    ],
    awaiting_campaign_approval: ["approved", "blocked", "cancelled"],
    approved: ["running_simulation", "paused", "blocked", "cancelled"],
    running_simulation: ["paused", "blocked", "completed", "cancelled"],
    paused: ["awaiting_campaign_approval", "blocked", "cancelled"],
    blocked: ["cancelled"],
    completed: [],
    cancelled: [],
  };
  if (!transitions[current.state].includes(next.state))
    throw new SecurityError("CAMPAIGN_TRANSITION_BLOCKED");
  if (
    next.state !== "approved" &&
    next.state !== "running_simulation" &&
    (next.humanApprovedBy !== null || next.humanApprovedAt !== null)
  )
    throw new SecurityError("CAMPAIGN_STALE_APPROVAL_BLOCKED");
}

function validateIdentity(identity: TestIdentityRecord): void {
  assertId(identity.id, "IDENTITY_ID_INVALID");
  assertId(identity.programId, "IDENTITY_PROGRAM_INVALID");
  assertTimestamp(identity.createdAt, "IDENTITY_TIMESTAMP_INVALID");
  for (const timestamp of [
    identity.verifiedAt,
    identity.suspendedAt,
    identity.retiredAt,
    identity.lastSuccessfulLoginAt,
  ])
    if (timestamp !== null)
      assertTimestamp(timestamp, "IDENTITY_TIMESTAMP_INVALID");
  for (const reference of identity.secretReferences)
    if (!/^(?:keychain|secret):\/\/[A-Za-z0-9_./-]{1,240}$/u.test(reference))
      throw new SecurityError("IDENTITY_SECRET_REFERENCE_INVALID");
  for (const reference of [
    identity.emailReference,
    identity.browserProfileReference,
    identity.platformAccountReference,
  ])
    if (
      reference !== null &&
      !/^(?:keychain|profile|ref|secret):\/[A-Za-z0-9_./:-]{1,240}$/u.test(
        reference,
      )
    )
      throw new SecurityError("IDENTITY_REFERENCE_INVALID");
  for (const objectRef of identity.ownedObjectRefs)
    assertId(objectRef, "IDENTITY_OWNED_OBJECT_REFERENCE_INVALID");
  if (identity.organizationRef !== null)
    assertId(
      identity.organizationRef,
      "IDENTITY_ORGANIZATION_REFERENCE_INVALID",
    );
  if (
    (identity.status === "ready" &&
      (identity.humanActionRequired || identity.verifiedAt === null)) ||
    ((identity.status === "awaiting_manual_registration" ||
      identity.status === "awaiting_email_verification" ||
      identity.status === "awaiting_captcha" ||
      identity.status === "awaiting_terms_acceptance" ||
      identity.status === "session_expired" ||
      identity.status === "suspended") &&
      !identity.humanActionRequired) ||
    (identity.status === "retired" && identity.retiredAt === null)
  )
    throw new SecurityError("IDENTITY_STATE_INVALID");
}

function validateOwnedObject(object: OwnedObjectRecord): void {
  for (const id of [
    object.objectRef,
    object.programId,
    object.campaignId,
    object.accountId,
  ])
    assertId(id, "OWNED_OBJECT_ID_INVALID");
  assertId(object.tenantRef, "OWNED_OBJECT_TENANT_REFERENCE_INVALID");
  if (
    !isTrue(object.researcherControlled) ||
    !/^protected-ref:[A-Za-z0-9_-]{1,160}$/u.test(
      object.protectedActualIdRef,
    ) ||
    !/^[a-f0-9]{64}$/u.test(object.canaryHmac) ||
    !/^[a-f0-9]{64}$/u.test(object.policyHash) ||
    object.objectType !== "document" ||
    canonicalJson([...object.allowedActions]) !==
      canonicalJson(["offline_inspect"]) ||
    !Number.isFinite(Date.parse(object.createdAt)) ||
    !Number.isFinite(Date.parse(object.expiresAt)) ||
    Date.parse(object.expiresAt) <= Date.parse(object.createdAt)
  )
    throw new SecurityError("OWNED_OBJECT_INVALID");
}

function validateReport(report: ReportDraftRecord): void {
  assertId(report.id, "REPORT_ID_INVALID");
  assertTimestamp(report.createdAt, "REPORT_TIMESTAMP_INVALID");
  if (
    !isFalse(report.externalSubmissionPerformed) ||
    report.title.trim().length === 0 ||
    report.title.length > 500 ||
    report.summary.length > 20_000
  )
    throw new SecurityError("REPORT_DRAFT_INVALID");
  assertNoSensitiveMaterial(
    [report.title, report.summary],
    "REPORT_SENSITIVE_MATERIAL",
  );
}

function assertId(value: string, code: string): void {
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(value)) throw new SecurityError(code);
}

function assertActor(value: string, code: string): void {
  if (!/^[A-Za-z0-9._@-]{1,128}$/u.test(value)) throw new SecurityError(code);
}

function assertReference(value: string, code: string): void {
  if (!/^[A-Za-z0-9_.:-]{1,160}$/u.test(value)) throw new SecurityError(code);
}

function assertTimestamp(value: string, code: string): void {
  if (!Number.isFinite(Date.parse(value))) throw new SecurityError(code);
}

function normalizeStrings(values: unknown): readonly string[] {
  if (!isUnknownArray(values) || values.length > 2_000)
    throw new SecurityError("STRING_LIST_INVALID");
  if (!values.every(isString)) throw new SecurityError("STRING_LIST_INVALID");
  const normalized = values.map((value) => value.trim());
  if (
    normalized.some(
      (value) =>
        value.length === 0 || value.length > 1_000 || value.includes("\0"),
    )
  )
    throw new SecurityError("STRING_LIST_INVALID");
  return Object.freeze([...new Set(normalized)].sort(compare));
}

function intersects(
  left: readonly string[],
  right: readonly string[],
): boolean {
  const values = new Set(left);
  return right.some((value) => values.has(value));
}

function freezeProgram(value: ProgramRecord): ProgramRecord {
  return Object.freeze({
    ...value,
    allowedAssets: Object.freeze([...value.allowedAssets]),
    excludedAssets: Object.freeze([...value.excludedAssets]),
  });
}

function freezePolicy(value: StoredPolicyVersion): StoredPolicyVersion {
  return Object.freeze(value);
}

function text(row: Row, key: string): string {
  const value = row[key];
  if (typeof value !== "string")
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return value;
}

function nullableText(row: Row, key: string): string | null {
  const value = row[key];
  if (value !== null && typeof value !== "string")
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return value;
}

function number(row: Row, key: string): number {
  const value = row[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value))
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return value;
}

function nullableNumber(row: Row, key: string): number | null {
  const value = row[key];
  if (value === null) return null;
  return number(row, key);
}

function enumText<const T extends string>(
  row: Row,
  key: string,
  allowed: readonly T[],
): T {
  const value = text(row, key);
  const matched = allowed.find((candidate) => candidate === value);
  if (matched === undefined)
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return matched;
}

function stringArray(row: Row, key: string): readonly string[] {
  let value: unknown;
  try {
    value = JSON.parse(text(row, key)) as unknown;
  } catch {
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  }
  if (!isUnknownArray(value) || !value.every(isString))
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return Object.freeze(value.map((item) => item));
}

function jsonObject(row: Row, key: string): Readonly<Record<string, unknown>> {
  let value: unknown;
  try {
    value = JSON.parse(text(row, key)) as unknown;
  } catch {
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  }
  return Object.freeze(recordValue(value));
}

function tuple<const T extends string>(
  row: Row,
  key: string,
  expected: T,
): readonly [T] {
  const values = stringArray(row, key);
  if (values.length !== 1 || values[0] !== expected)
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return Object.freeze([expected]);
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function campaignContractFromRow(row: Row): CampaignRecord["contract"] {
  const value = jsonObject(row, "contract_json");
  assertExactKeys(value, [
    "allowedHosts",
    "allowedMethods",
    "allowedRiskTiers",
    "excludedHosts",
    "humanCheckpoints",
    "maxConcurrency",
    "maxRequests",
    "policyHash",
    "requestsPerMinute",
    "rollbackRequired",
    "validFrom",
    "validUntil",
    "writeActionsAllowed",
  ]);
  const maxConcurrency = value["maxConcurrency"];
  const writeActionsAllowed = value["writeActionsAllowed"];
  if (maxConcurrency !== 1 || writeActionsAllowed !== false)
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  const riskTiers = exactTupleValue(
    value["allowedRiskTiers"],
    "tier_0_offline",
  );
  const methods = stringArrayValue(value["allowedMethods"]);
  if (
    methods.some(
      (method) => method !== "GET" && method !== "HEAD" && method !== "OPTIONS",
    )
  )
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  const allowedMethods: ("GET" | "HEAD" | "OPTIONS")[] = [];
  for (const method of methods) {
    if (method === "GET" || method === "HEAD" || method === "OPTIONS")
      allowedMethods.push(method);
  }
  return Object.freeze({
    allowedHosts: stringArrayValue(value["allowedHosts"]),
    excludedHosts: stringArrayValue(value["excludedHosts"]),
    maxRequests: integerValue(value["maxRequests"]),
    requestsPerMinute: integerValue(value["requestsPerMinute"]),
    maxConcurrency,
    allowedRiskTiers: riskTiers,
    allowedMethods: Object.freeze(allowedMethods),
    writeActionsAllowed,
    rollbackRequired: booleanValue(value["rollbackRequired"]),
    humanCheckpoints: stringArrayValue(value["humanCheckpoints"]),
    validFrom: stringValue(value["validFrom"]),
    validUntil: stringValue(value["validUntil"]),
    policyHash: stringValue(value["policyHash"]),
  });
}

function recordValue(value: unknown): Readonly<Record<string, unknown>> {
  if (!isRecord(value)) throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return value;
}

function assertExactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): void {
  const actual = Object.keys(value).sort(compare);
  const sortedExpected = [...expected].sort(compare);
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  )
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
}

function stringValue(value: unknown): string {
  if (typeof value !== "string")
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return value;
}

function integerValue(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value))
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return value;
}

function booleanValue(value: unknown): boolean {
  if (typeof value !== "boolean")
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return value;
}

function stringArrayValue(value: unknown): readonly string[] {
  if (!isUnknownArray(value) || !value.every(isString))
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return Object.freeze(value.map((item) => item));
}

function exactTupleValue<const T extends string>(
  value: unknown,
  expected: T,
): readonly [T] {
  const values = stringArrayValue(value);
  if (values.length !== 1 || values[0] !== expected)
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return Object.freeze([expected]);
}

function isUnknownArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isTrue(value: unknown): value is true {
  return value === true;
}

function isFalse(value: unknown): value is false {
  return value === false;
}
