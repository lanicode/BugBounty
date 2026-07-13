import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import { normalizePolicy, type NormalizedPolicy } from "./policy.js";
import type { ControlPlaneDatabase } from "./database.js";
import type {
  ApprovalRecord,
  CampaignRecord,
  OwnedObjectRecord,
  ProgramRecord,
  ReportDraftRecord,
  TestIdentityRecord,
} from "./types.js";

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

export class ControlPlaneStore {
  public constructor(private readonly database: ControlPlaneDatabase) {}

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
    if (this.getProgram(input.programId) === undefined)
      throw new SecurityError("PROGRAM_NOT_FOUND");
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
    const policy = this.getPolicy(input.programId, input.version);
    if (policy === undefined) throw new SecurityError("POLICY_NOT_FOUND");
    if (policy.policy.policyHash !== input.expectedPolicyHash)
      throw new SecurityError("POLICY_ACCEPTANCE_HASH_MISMATCH");
    assertActor(input.acceptedBy, "POLICY_ACCEPTOR_INVALID");
    assertTimestamp(input.acceptedAt, "POLICY_ACCEPTANCE_TIMESTAMP_INVALID");
    assertReference(input.auditReference, "AUDIT_REFERENCE_INVALID");
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
      `SELECT p.*,a.accepted_by,a.accepted_at,a.audit_reference
       FROM policy_versions p LEFT JOIN policy_acceptances a
       ON p.program_id=a.program_id AND p.version=a.version
       WHERE p.program_id=? AND p.version=?`,
      programId,
      version,
    );
    return row === undefined ? undefined : policyFromRow(row);
  }

  public listPolicies(programId: string): readonly StoredPolicyVersion[] {
    return Object.freeze(
      this.database
        .all(
          `SELECT p.*,a.accepted_by,a.accepted_at,a.audit_reference
           FROM policy_versions p LEFT JOIN policy_acceptances a
           ON p.program_id=a.program_id AND p.version=a.version
           WHERE p.program_id=? ORDER BY p.version`,
          programId,
        )
        .map(policyFromRow),
    );
  }

  public insertCampaign(campaign: CampaignRecord): CampaignRecord {
    validateCampaign(campaign);
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
    return row === undefined ? undefined : campaignFromRow(row);
  }

  public listCampaigns(): readonly CampaignRecord[] {
    return Object.freeze(
      this.database
        .all("SELECT * FROM campaigns ORDER BY id")
        .map(campaignFromRow),
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

  public updateApproval(
    expectedRevision: number,
    record: ApprovalRecord,
  ): void {
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
        "SELECT value FROM system_state WHERE key='global_kill_switch'",
      );
      return row?.["value"] !== "clear";
    } catch {
      return true;
    }
  }

  public setKillSwitch(
    active: boolean,
    actor: string,
    at: string,
  ): { readonly active: boolean; readonly revision: number } {
    assertActor(actor, "KILL_SWITCH_ACTOR_INVALID");
    assertTimestamp(at, "KILL_SWITCH_TIMESTAMP_INVALID");
    const value = active ? "engaged" : "clear";
    const id = `kill-${sha256(`${actor}\u0000${at}\u0000${value}`).slice(0, 32)}`;
    const operation = (): {
      readonly active: boolean;
      readonly revision: number;
    } => {
      const row = this.database.get(
        "SELECT revision FROM system_state WHERE key='global_kill_switch'",
      );
      if (typeof row?.["revision"] !== "number")
        throw new SecurityError("KILL_SWITCH_STATE_UNAVAILABLE");
      const revision = row["revision"] + 1;
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
        sha256(canonicalJson({ active, actor, at })),
      );
      this.database.run(
        `UPDATE system_state SET value=?,revision=?,updated_at=?
         WHERE key='global_kill_switch'`,
        value,
        revision,
        at,
      );
      return Object.freeze({ active, revision });
    };
    if (!active) return this.database.transaction(operation);
    // Engagement is written first. If audit persistence fails, callers receive an
    // error but the system remains blocked instead of rolling back to unsafe state.
    const row = this.database.get(
      "SELECT revision FROM system_state WHERE key='global_kill_switch'",
    );
    if (typeof row?.["revision"] !== "number")
      throw new SecurityError("KILL_SWITCH_STATE_UNAVAILABLE");
    const revision = row["revision"] + 1;
    this.database.run(
      `UPDATE system_state SET value='engaged',revision=?,updated_at=?
       WHERE key='global_kill_switch'`,
      revision,
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
        sha256(canonicalJson({ active, actor, at })),
      );
    } catch (error) {
      throw new SecurityError(
        `KILL_SWITCH_AUDIT_FAILED:${error instanceof Error ? error.name : "UNKNOWN"}`,
      );
    }
    return Object.freeze({ active: true, revision });
  }
}

type Row = Readonly<
  Record<string, null | number | bigint | string | Uint8Array>
>;

function programFromRow(row: Row): ProgramRecord {
  return freezeProgram({
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
  return Object.freeze({
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
}

function identityFromRow(row: Row): TestIdentityRecord {
  return Object.freeze({
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
}

function objectFromRow(row: Row): OwnedObjectRecord {
  if (number(row, "researcher_controlled") !== 1)
    throw new SecurityError("CONTROL_PLANE_ROW_INVALID");
  return Object.freeze({
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
}

function approvalFromRow(row: Row): ApprovalRecord {
  return Object.freeze({
    id: text(row, "id"),
    kind: enumText(row, "kind", [
      "program_policy_acceptance",
      "campaign_contract",
      "account_manual_action",
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
}

function reportFromRow(row: Row): ReportDraftRecord {
  if (number(row, "external_submission_performed") !== 0)
    throw new SecurityError("REPORT_EXTERNAL_STATE_INVALID");
  return Object.freeze({
    id: text(row, "id"),
    campaignId: text(row, "campaign_id"),
    title: text(row, "title"),
    summary: text(row, "summary"),
    createdAt: text(row, "created_at"),
    status: enumText(row, "status", ["draft", "queued_for_human_review"]),
    externalSubmissionPerformed: false,
  });
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
}

function validateIdentity(identity: TestIdentityRecord): void {
  assertId(identity.id, "IDENTITY_ID_INVALID");
  assertTimestamp(identity.createdAt, "IDENTITY_TIMESTAMP_INVALID");
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
}

function validateOwnedObject(object: OwnedObjectRecord): void {
  for (const id of [
    object.objectRef,
    object.programId,
    object.campaignId,
    object.accountId,
  ])
    assertId(id, "OWNED_OBJECT_ID_INVALID");
  if (
    !/^protected-ref:[A-Za-z0-9_-]{1,160}$/u.test(
      object.protectedActualIdRef,
    ) ||
    !/^[a-f0-9]{64}$/u.test(object.canaryHmac) ||
    !/^[a-f0-9]{64}$/u.test(object.policyHash) ||
    object.allowedActions.length === 0 ||
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
