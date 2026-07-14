import { types } from "node:util";
import { ApprovalQueue } from "../control-plane/approval-queue.js";
import {
  isTrustedControlPlaneDatabase,
  type ControlPlaneDatabase,
} from "../control-plane/database.js";
import {
  isTrustedControlPlaneStore,
  type ControlPlaneStore,
} from "../control-plane/store.js";
import type { ApprovalRecord } from "../control-plane/types.js";
import {
  captureTrustedHackerOneMetadataRequestPlan,
  type HackerOneMetadataOperation,
  type HackerOneMetadataRequestPlan,
} from "../hackerone-readonly/request-policy.js";
import {
  isTrustedHackerOneMetadataReadRuntime,
  type HackerOneMetadataReadRuntimeState,
} from "../hackerone-readonly/runtime.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import {
  assertExactSqliteSchema,
  assertSqliteSchemaNamespaceEmpty,
  buildSqliteSchemaExpectation,
} from "../shared/sqlite-schema.js";
import { getExternalActionDefinition } from "./registry.js";

const ACTION_ID = "hackerone_metadata_read" as const;
const ACTION_CLASS = "HACKERONE_METADATA_READ" as const;
const HOST = "api.hackerone.com" as const;
const PORT = 443 as const;
const SCHEME = "https" as const;
const METHOD = "GET" as const;
const APPROVAL_LIFETIME_MS = 5 * 60_000;
const FINGERPRINT = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9_-]{1,128}$/u;
const DIGEST = /^[0-9a-f]{64}$/u;

const trustedGates = new WeakSet();
const trustedAuthorizations = new WeakMap<
  object,
  StoreBoundHackerOneMetadataAuthorization
>();
const trustedTransportPlans = new WeakMap<
  object,
  AuthorizedHackerOneMetadataTransportPlan
>();

export interface HackerOneMetadataActivationApprovalInput {
  readonly approvalId: string;
  readonly operatorId: string;
  readonly credentialFingerprint: string;
  readonly createdAt: string;
}

export interface HackerOnePolicyAcceptanceApprovalInput {
  readonly approvalId: string;
  readonly operatorId: string;
  readonly programLocalRef: string;
  readonly snapshotDigest: string;
  readonly createdAt: string;
}

export interface HackerOneMetadataReservationInput {
  readonly operationId: string;
  readonly proposalId: string;
  readonly plan: HackerOneMetadataRequestPlan;
  readonly credentialFingerprint: string;
}

export interface StoreBoundHackerOneMetadataAuthorization {
  readonly authorizationId: string;
  readonly operationId: string;
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly planDigest: string;
  readonly activationApprovalId: string;
  readonly activationBindingDigest: string;
  readonly credentialFingerprint: string;
  readonly attemptIndex: number;
  readonly reservedAt: string;
  readonly reservationAuditId: string;
  readonly plan: HackerOneMetadataRequestPlan;
}

export interface AuthorizedHackerOneMetadataTransportPlan {
  readonly authorizationId: string;
  readonly proposalDigest: string;
  readonly credentialFingerprint: string;
  readonly endpointClass: HackerOneMetadataOperation;
  readonly requestTarget: string;
}

export interface HackerOneMetadataAttemptRecord {
  readonly authorizationId: string;
  readonly operationId: string;
  readonly proposalId: string;
  readonly actionId: typeof ACTION_ID;
  readonly endpointClass: HackerOneMetadataOperation;
  readonly status: "aborted" | "failed" | "reserved" | "running" | "succeeded";
  readonly attemptIndex: number;
  readonly reservedAt: string;
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
  readonly revision: number;
}

const ACTION_GATE_SCHEMA = Object.freeze([
  `CREATE TABLE IF NOT EXISTS hackerone_metadata_action_schema (
    component TEXT PRIMARY KEY CHECK(component='metadata_action_gate'),
    version INTEGER NOT NULL CHECK(version=1),
    schema_digest TEXT NOT NULL CHECK(length(schema_digest)=64)
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS hackerone_metadata_activation_bindings (
    approval_id TEXT PRIMARY KEY REFERENCES approvals(id) ON DELETE RESTRICT,
    approval_payload_hash TEXT NOT NULL CHECK(
      length(approval_payload_hash)=64 AND
      approval_payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    operator_id TEXT NOT NULL,
    credential_fingerprint TEXT NOT NULL CHECK(length(credential_fingerprint)=64),
    runtime_digest TEXT NOT NULL CHECK(length(runtime_digest)=64),
    adapter_generation INTEGER NOT NULL CHECK(adapter_generation>=0),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL CHECK(expires_at>created_at),
    binding_digest TEXT NOT NULL UNIQUE CHECK(length(binding_digest)=64),
    decision_audit_id TEXT UNIQUE REFERENCES control_plane_audit(id) ON DELETE RESTRICT,
    activated_generation INTEGER UNIQUE,
    CHECK(activated_generation IS NULL OR decision_audit_id IS NOT NULL)
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS hackerone_policy_acceptance_bindings (
    approval_id TEXT PRIMARY KEY REFERENCES approvals(id) ON DELETE RESTRICT,
    approval_payload_hash TEXT NOT NULL CHECK(
      length(approval_payload_hash)=64 AND
      approval_payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    operator_id TEXT NOT NULL,
    program_local_ref TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('hackerone_api_authenticated','manual_unverified')),
    snapshot_digest TEXT NOT NULL UNIQUE CHECK(length(snapshot_digest)=64),
    policy_digest TEXT NOT NULL CHECK(length(policy_digest)=64),
    previous_snapshot_digest TEXT,
    created_at TEXT NOT NULL,
    binding_digest TEXT NOT NULL UNIQUE CHECK(length(binding_digest)=64),
    decision_audit_id TEXT UNIQUE REFERENCES control_plane_audit(id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS hackerone_policy_acceptances (
    snapshot_digest TEXT PRIMARY KEY,
    program_local_ref TEXT NOT NULL,
    approval_id TEXT NOT NULL UNIQUE REFERENCES hackerone_policy_acceptance_bindings(approval_id) ON DELETE RESTRICT,
    accepted_by TEXT NOT NULL,
    accepted_at TEXT NOT NULL,
    decision_audit_id TEXT NOT NULL UNIQUE REFERENCES control_plane_audit(id) ON DELETE RESTRICT,
    statement_digest TEXT NOT NULL UNIQUE REFERENCES operator_signed_statements(statement_digest) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS hackerone_metadata_action_attempts (
    authorization_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    proposal_id TEXT NOT NULL UNIQUE,
    proposal_digest TEXT NOT NULL UNIQUE CHECK(length(proposal_digest)=64),
    plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64),
    action_id TEXT NOT NULL CHECK(action_id='hackerone_metadata_read'),
    action_class TEXT NOT NULL CHECK(action_class='HACKERONE_METADATA_READ'),
    endpoint_class TEXT NOT NULL CHECK(endpoint_class IN ('program','programs','scope_exclusions','structured_scopes')),
    method TEXT NOT NULL CHECK(method='GET'),
    scheme TEXT NOT NULL CHECK(scheme='https'),
    host TEXT NOT NULL CHECK(host='api.hackerone.com'),
    port INTEGER NOT NULL CHECK(port=443),
    request_target TEXT NOT NULL,
    activation_approval_id TEXT NOT NULL REFERENCES hackerone_metadata_activation_bindings(approval_id) ON DELETE RESTRICT,
    activation_binding_digest TEXT NOT NULL CHECK(length(activation_binding_digest)=64),
    credential_fingerprint TEXT NOT NULL CHECK(length(credential_fingerprint)=64),
    attempt_index INTEGER NOT NULL CHECK(attempt_index>0),
    units INTEGER NOT NULL CHECK(units=1),
    status TEXT NOT NULL CHECK(status IN ('reserved','running','succeeded','failed','aborted')),
    reserved_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 2),
    reservation_audit_id TEXT NOT NULL UNIQUE REFERENCES control_plane_audit(id) ON DELETE RESTRICT,
    settlement_audit_id TEXT UNIQUE REFERENCES control_plane_audit(id) ON DELETE RESTRICT,
    UNIQUE(operation_id,attempt_index),
    CHECK(
      (status='reserved' AND revision=0 AND started_at IS NULL AND finished_at IS NULL AND settlement_audit_id IS NULL)
      OR (status='running' AND revision=1 AND started_at IS NOT NULL AND finished_at IS NULL AND settlement_audit_id IS NULL)
      OR (status IN ('succeeded','failed','aborted') AND revision=2 AND started_at IS NOT NULL AND finished_at IS NOT NULL AND settlement_audit_id IS NOT NULL)
      OR (status='aborted' AND revision=1 AND started_at IS NULL AND finished_at IS NOT NULL AND settlement_audit_id IS NOT NULL)
    )
  ) STRICT`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_metadata_activation_no_delete
    BEFORE DELETE ON hackerone_metadata_activation_bindings
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACTIVATION_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_metadata_activation_immutable
    BEFORE UPDATE OF approval_id,approval_payload_hash,operator_id,
      credential_fingerprint,runtime_digest,adapter_generation,created_at,
      expires_at,binding_digest
    ON hackerone_metadata_activation_bindings
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACTIVATION_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_metadata_activation_insert_guard
    BEFORE INSERT ON hackerone_metadata_activation_bindings
    WHEN NOT EXISTS(
      SELECT 1 FROM approvals q
      WHERE q.id=NEW.approval_id AND q.kind='privacy_alert'
        AND q.status='open' AND q.revision=0
        AND q.created_at=NEW.created_at AND q.policy_hash=NEW.runtime_digest
        AND q.payload_hash=NEW.approval_payload_hash
    )
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACTIVATION_EVIDENCE_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_metadata_activation_decision_guard
    BEFORE UPDATE OF decision_audit_id,activated_generation
    ON hackerone_metadata_activation_bindings
    WHEN NEW.decision_audit_id IS NULL OR OLD.decision_audit_id IS NOT NULL
      OR NOT EXISTS(
        SELECT 1 FROM approvals q
        JOIN signed_approval_decisions d ON d.approval_id=q.id
        JOIN operator_signed_statements s ON s.statement_digest=d.statement_digest
        JOIN control_plane_audit a ON a.id=NEW.decision_audit_id
        WHERE q.id=NEW.approval_id AND q.kind='privacy_alert'
          AND q.status=d.decision AND q.revision=1
          AND q.decided_by=NEW.operator_id
          AND q.payload_hash=NEW.approval_payload_hash
          AND d.context_digest_sha256=NEW.approval_payload_hash
          AND s.operator_id=NEW.operator_id
          AND a.action='approval_decision' AND a.decision=d.decision
          AND a.object_reference=q.id AND a.payload_hash=d.statement_digest
          AND ((d.decision='accepted' AND NEW.activated_generation=NEW.adapter_generation+1)
            OR (d.decision='rejected' AND NEW.activated_generation IS NULL))
      )
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACTIVATION_EVIDENCE_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_adapter_enable_guard
    BEFORE UPDATE OF adapter_enabled,adapter_generation
    ON hackerone_integration_state
    WHEN NEW.adapter_enabled=1
    AND NOT EXISTS(
      SELECT 1 FROM hackerone_metadata_activation_bindings b
      JOIN approvals q ON q.id=b.approval_id
      WHERE b.activated_generation=NEW.adapter_generation
        AND b.adapter_generation=OLD.adapter_generation
        AND b.decision_audit_id IS NOT NULL
        AND q.status='accepted' AND q.revision=1
    )
    BEGIN SELECT RAISE(ABORT,'SIGNED_HACKERONE_ACTIVATION_REQUIRED'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_policy_acceptance_binding_no_delete
    BEFORE DELETE ON hackerone_policy_acceptance_bindings
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACCEPTANCE_BINDING_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_policy_acceptance_binding_immutable
    BEFORE UPDATE OF approval_id,approval_payload_hash,operator_id,
      program_local_ref,source,snapshot_digest,policy_digest,
      previous_snapshot_digest,created_at,binding_digest
    ON hackerone_policy_acceptance_bindings
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACCEPTANCE_BINDING_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_policy_acceptance_binding_insert_guard
    BEFORE INSERT ON hackerone_policy_acceptance_bindings
    WHEN NOT EXISTS(
      SELECT 1 FROM approvals q
      WHERE q.id=NEW.approval_id AND q.kind='program_policy_acceptance'
        AND q.status='open' AND q.revision=0
        AND q.created_at=NEW.created_at AND q.policy_hash=NEW.policy_digest
        AND q.payload_hash=NEW.approval_payload_hash
    )
    OR (NEW.source='hackerone_api_authenticated' AND NOT EXISTS(
      SELECT 1 FROM hackerone_api_programs p
      WHERE p.local_ref=NEW.program_local_ref AND p.catalog_active=1
        AND p.catalog_drift_pending=0
        AND p.current_snapshot_digest=NEW.snapshot_digest
    ))
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACCEPTANCE_BINDING_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_policy_acceptance_decision_guard
    BEFORE UPDATE OF decision_audit_id ON hackerone_policy_acceptance_bindings
    WHEN NEW.decision_audit_id IS NULL OR OLD.decision_audit_id IS NOT NULL
      OR (NEW.source='hackerone_api_authenticated' AND NOT EXISTS(
        SELECT 1 FROM hackerone_api_programs p
        WHERE p.local_ref=NEW.program_local_ref AND p.catalog_active=1
          AND p.catalog_drift_pending=0
          AND p.current_snapshot_digest=NEW.snapshot_digest
      ))
      OR NOT EXISTS(
        SELECT 1 FROM approvals q
        JOIN signed_approval_decisions d ON d.approval_id=q.id
        JOIN operator_signed_statements s ON s.statement_digest=d.statement_digest
        JOIN control_plane_audit a ON a.id=NEW.decision_audit_id
        WHERE q.id=NEW.approval_id AND q.kind='program_policy_acceptance'
          AND q.status=d.decision AND q.revision=1
          AND q.decided_by=NEW.operator_id
          AND q.payload_hash=NEW.approval_payload_hash
          AND d.context_digest_sha256=NEW.approval_payload_hash
          AND s.operator_id=NEW.operator_id
          AND a.action='approval_decision' AND a.decision=d.decision
          AND a.object_reference=q.id AND a.payload_hash=d.statement_digest
      )
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACCEPTANCE_BINDING_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_policy_acceptance_insert_guard
    BEFORE INSERT ON hackerone_policy_acceptances
    WHEN NOT EXISTS(
      SELECT 1 FROM hackerone_policy_acceptance_bindings b
      JOIN approvals q ON q.id=b.approval_id
      JOIN signed_approval_decisions d ON d.approval_id=q.id
      JOIN operator_signed_statements s ON s.statement_digest=d.statement_digest
      WHERE b.approval_id=NEW.approval_id
        AND b.snapshot_digest=NEW.snapshot_digest
        AND b.program_local_ref=NEW.program_local_ref
        AND b.decision_audit_id=NEW.decision_audit_id
        AND q.status='accepted' AND q.decided_by=NEW.accepted_by
        AND q.decided_at=NEW.accepted_at
        AND d.decision='accepted' AND d.statement_digest=NEW.statement_digest
        AND q.payload_hash=b.approval_payload_hash
        AND d.context_digest_sha256=b.approval_payload_hash
        AND (b.source='manual_unverified' OR EXISTS(
          SELECT 1 FROM hackerone_api_programs p
          WHERE p.local_ref=b.program_local_ref AND p.catalog_active=1
            AND p.catalog_drift_pending=0
            AND p.current_snapshot_digest=b.snapshot_digest
        ))
    )
    BEGIN SELECT RAISE(ABORT,'HACKERONE_POLICY_ACCEPTANCE_EVIDENCE_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_policy_acceptances_no_update
    BEFORE UPDATE ON hackerone_policy_acceptances
    BEGIN SELECT RAISE(ABORT,'HACKERONE_POLICY_ACCEPTANCE_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_policy_acceptances_no_delete
    BEFORE DELETE ON hackerone_policy_acceptances
    BEGIN SELECT RAISE(ABORT,'HACKERONE_POLICY_ACCEPTANCE_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_metadata_attempt_immutable
    BEFORE UPDATE OF authorization_id,operation_id,proposal_id,proposal_digest,
      plan_digest,action_id,action_class,endpoint_class,method,scheme,host,port,
      request_target,activation_approval_id,activation_binding_digest,
      credential_fingerprint,attempt_index,units,reserved_at,reservation_audit_id
    ON hackerone_metadata_action_attempts
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACTION_ATTEMPT_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_metadata_attempt_transition
    BEFORE UPDATE OF status,started_at,finished_at,revision,settlement_audit_id
    ON hackerone_metadata_action_attempts
    WHEN NOT (
      (OLD.status='reserved' AND OLD.revision=0 AND NEW.status='running' AND NEW.revision=1
        AND NEW.started_at IS NOT NULL AND NEW.finished_at IS NULL AND NEW.settlement_audit_id IS NULL)
      OR (OLD.status='reserved' AND OLD.revision=0 AND NEW.status='aborted' AND NEW.revision=1
        AND NEW.started_at IS NULL AND NEW.finished_at IS NOT NULL AND NEW.settlement_audit_id IS NOT NULL)
      OR (OLD.status='running' AND OLD.revision=1 AND NEW.status IN ('succeeded','failed','aborted') AND NEW.revision=2
        AND NEW.started_at IS OLD.started_at AND NEW.finished_at IS NOT NULL AND NEW.settlement_audit_id IS NOT NULL)
    )
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACTION_ATTEMPT_TRANSITION_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_metadata_attempt_no_delete
    BEFORE DELETE ON hackerone_metadata_action_attempts
    BEGIN SELECT RAISE(ABORT,'HACKERONE_ACTION_ATTEMPT_IMMUTABLE'); END`,
]);

const ACTION_GATE_SCHEMA_EXPECTATION = buildSqliteSchemaExpectation({
  statements: ACTION_GATE_SCHEMA,
  prerequisites: [
    `CREATE TABLE hackerone_integration_state (
      adapter_enabled INTEGER NOT NULL,
      adapter_generation INTEGER NOT NULL
    ) STRICT`,
  ],
});
const ACTION_GATE_SCHEMA_DIGEST = ACTION_GATE_SCHEMA_EXPECTATION.digest;

export class HackerOneMetadataActionGate {
  readonly #runtime: HackerOneMetadataReadRuntimeState;

  public constructor(
    private readonly database: ControlPlaneDatabase,
    private readonly controlPlane: ControlPlaneStore,
    runtime: HackerOneMetadataReadRuntimeState,
  ) {
    if (
      !isTrustedControlPlaneDatabase(database) ||
      !isTrustedControlPlaneStore(controlPlane) ||
      !controlPlane.isBoundToDatabase(database)
    )
      throw new SecurityError("HACKERONE_ACTION_STORE_UNTRUSTED");
    if (!isTrustedHackerOneMetadataReadRuntime(runtime))
      throw new SecurityError("HACKERONE_ACTION_RUNTIME_UNTRUSTED");
    assertRegistryDefinition();
    this.#runtime = runtime;
    this.initialize();
    trustedGates.add(this);
    Object.freeze(this);
  }

  public prepareActivationApproval(
    value: HackerOneMetadataActivationApprovalInput,
  ): ApprovalRecord {
    const input = captureActivationInput(value);
    return this.database.transaction(() => {
      this.assertRuntimeAndKillSwitch();
      const state = integrationState(this.database);
      if (state.adapterEnabled)
        throw new SecurityError("HACKERONE_ADAPTER_ALREADY_ENABLED");
      const expiresAt = new Date(
        Date.parse(input.createdAt) + APPROVAL_LIFETIME_MS,
      ).toISOString();
      const material = Object.freeze({
        actionClass: ACTION_CLASS,
        actionId: ACTION_ID,
        approvalId: input.approvalId,
        operatorId: input.operatorId,
        credentialFingerprint: input.credentialFingerprint,
        runtimeDigest: activationRuntimeDigest(this.#runtime),
        adapterGeneration: state.adapterGeneration,
        scheme: SCHEME,
        host: HOST,
        port: PORT,
        method: METHOD,
        createdAt: input.createdAt,
        expiresAt,
      });
      const bindingDigest = sha256(canonicalJson(material));
      const approval = new ApprovalQueue().enqueue({
        id: input.approvalId,
        kind: "privacy_alert",
        summary: "Activate HackerOne read-only metadata integration",
        technicalDetails: `Exact target ${SCHEME}://${HOST}:${String(PORT)}; GET-only; activation binding ${bindingDigest}`,
        impact:
          "Permits only bounded official HackerOne metadata reads; target requests and report submission remain disabled",
        policyVersion: 1,
        policyHash: material.runtimeDigest,
        createdAt: input.createdAt,
        auditReference: `h1-activation:${input.approvalId}`,
      });
      this.controlPlane.persistApproval(approval);
      this.database.run(
        `INSERT INTO hackerone_metadata_activation_bindings(
          approval_id,approval_payload_hash,operator_id,credential_fingerprint,
          runtime_digest,adapter_generation,created_at,expires_at,binding_digest,
          decision_audit_id,activated_generation
        ) VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL)`,
        input.approvalId,
        approval.payloadHash,
        input.operatorId,
        input.credentialFingerprint,
        material.runtimeDigest,
        state.adapterGeneration,
        input.createdAt,
        expiresAt,
        bindingDigest,
      );
      return approval;
    });
  }

  public preparePolicyAcceptanceApproval(
    value: HackerOnePolicyAcceptanceApprovalInput,
  ): ApprovalRecord {
    const input = capturePolicyAcceptanceInput(value);
    return this.database.transaction(() => {
      if (this.controlPlane.isKillSwitchActive())
        throw new SecurityError("HACKERONE_POLICY_ACCEPTANCE_KILL_SWITCH");
      const snapshot = this.database.get(
        `SELECT s.program_local_ref,s.source,s.snapshot_digest,s.policy_digest,
           s.previous_snapshot_digest,p.current_snapshot_digest
         FROM hackerone_policy_snapshots s
         LEFT JOIN hackerone_api_programs p ON p.local_ref=s.program_local_ref
         LEFT JOIN hackerone_manual_programs m ON m.local_ref=s.program_local_ref
         WHERE s.snapshot_digest=? AND s.program_local_ref=?
           AND COALESCE(p.current_snapshot_digest,m.current_snapshot_digest)=s.snapshot_digest
           AND (s.source='manual_unverified' OR
             (p.catalog_active=1 AND p.catalog_drift_pending=0))`,
        input.snapshotDigest,
        input.programLocalRef,
      );
      if (snapshot === undefined)
        throw new SecurityError(
          "HACKERONE_SNAPSHOT_ACCEPTANCE_REQUIRES_CURRENT",
        );
      if (
        this.database.get(
          "SELECT snapshot_digest FROM hackerone_policy_acceptances WHERE snapshot_digest=?",
          input.snapshotDigest,
        ) !== undefined
      )
        throw new SecurityError("HACKERONE_SNAPSHOT_ALREADY_ACCEPTED");
      const source = requiredSource(snapshot["source"]);
      const policyDigest = requiredDigest(snapshot["policy_digest"]);
      const previousSnapshotDigest = nullableDigest(
        snapshot["previous_snapshot_digest"],
      );
      const material = Object.freeze({
        approvalId: input.approvalId,
        operatorId: input.operatorId,
        programLocalRef: input.programLocalRef,
        source,
        snapshotDigest: input.snapshotDigest,
        policyDigest,
        previousSnapshotDigest,
        createdAt: input.createdAt,
      });
      const bindingDigest = sha256(canonicalJson(material));
      const approval = new ApprovalQueue().enqueue({
        id: input.approvalId,
        kind: "program_policy_acceptance",
        summary: `Accept HackerOne snapshot ${input.snapshotDigest.slice(0, 16)}`,
        technicalDetails: `Program ${input.programLocalRef}; source ${source}; snapshot ${input.snapshotDigest}; binding ${bindingDigest}`,
        impact:
          "Records only local acceptance of this exact immutable metadata snapshot; it grants no target or report action",
        policyVersion: 1,
        policyHash: policyDigest,
        createdAt: input.createdAt,
        auditReference: `h1-policy:${input.approvalId}`,
      });
      this.controlPlane.persistApproval(approval);
      this.database.run(
        `INSERT INTO hackerone_policy_acceptance_bindings(
          approval_id,approval_payload_hash,operator_id,program_local_ref,
          source,snapshot_digest,policy_digest,previous_snapshot_digest,
          created_at,binding_digest,decision_audit_id
        ) VALUES(?,?,?,?,?,?,?,?,?,?,NULL)`,
        input.approvalId,
        approval.payloadHash,
        input.operatorId,
        input.programLocalRef,
        source,
        input.snapshotDigest,
        policyDigest,
        previousSnapshotDigest,
        input.createdAt,
        bindingDigest,
      );
      return approval;
    });
  }

  public authorizeAndReserve(
    value: HackerOneMetadataReservationInput,
  ): StoreBoundHackerOneMetadataAuthorization {
    const input = captureReservationInput(value);
    const plan = captureTrustedHackerOneMetadataRequestPlan(input.plan);
    const now = systemTimestamp();
    const planDigest = metadataPlanDigest(plan);
    const proposalDigest = sha256(
      canonicalJson({
        version: 1,
        proposalId: input.proposalId,
        operationId: input.operationId,
        actionId: ACTION_ID,
        actionClass: ACTION_CLASS,
        planDigest,
        credentialFingerprint: input.credentialFingerprint,
      }),
    );
    return this.database.transaction(() => {
      this.assertRuntimeAndKillSwitch();
      this.assertPlanScope(plan);
      const activation = this.currentActivation(input.credentialFingerprint);
      this.assertClockMonotonic(now);
      const attemptIndex = this.assertAndCountBudget(input.operationId, now);
      const authorizationId = `h1auth-${sha256(
        `${proposalDigest}\u0000${now}`,
      ).slice(0, 40)}`;
      const reservationAuditId = `h1reserve-${sha256(
        `${authorizationId}\u0000${activation.bindingDigest}`,
      ).slice(0, 40)}`;
      this.database.run(
        `INSERT INTO control_plane_audit(
          id,occurred_at,action,decision,reason_code,object_reference,payload_hash
        ) VALUES(?,?,?,?,?,?,?)`,
        reservationAuditId,
        now,
        "hackerone_metadata_action_authorization",
        "reserved",
        "HACKERONE_METADATA_ACTION_RESERVED",
        authorizationId,
        proposalDigest,
      );
      this.database.run(
        `INSERT INTO hackerone_metadata_action_attempts(
          authorization_id,operation_id,proposal_id,proposal_digest,plan_digest,
          action_id,action_class,endpoint_class,method,scheme,host,port,
          request_target,activation_approval_id,activation_binding_digest,
          credential_fingerprint,attempt_index,units,status,reserved_at,
          started_at,finished_at,revision,reservation_audit_id,settlement_audit_id
        ) VALUES(?,?,?,?,?,'hackerone_metadata_read','HACKERONE_METADATA_READ',
          ?,'GET','https','api.hackerone.com',443,?,?,?,?,?,1,'reserved',?,
          NULL,NULL,0,?,NULL)`,
        authorizationId,
        input.operationId,
        input.proposalId,
        proposalDigest,
        planDigest,
        plan.operation,
        `${plan.path}${plan.query}`,
        activation.approvalId,
        activation.bindingDigest,
        input.credentialFingerprint,
        attemptIndex,
        now,
        reservationAuditId,
      );
      const authorization = Object.freeze({
        authorizationId,
        operationId: input.operationId,
        proposalId: input.proposalId,
        proposalDigest,
        planDigest,
        activationApprovalId: activation.approvalId,
        activationBindingDigest: activation.bindingDigest,
        credentialFingerprint: input.credentialFingerprint,
        attemptIndex,
        reservedAt: now,
        reservationAuditId,
        plan,
      });
      trustedAuthorizations.set(authorization, authorization);
      return authorization;
    });
  }

  public start(
    value: StoreBoundHackerOneMetadataAuthorization,
  ): AuthorizedHackerOneMetadataTransportPlan {
    const authorization = requireAuthorization(value);
    const at = monotonicTimestamp(authorization.reservedAt);
    return this.database.transaction(() => {
      this.assertRuntimeAndKillSwitch();
      this.assertAuthorizationCurrent(authorization, "reserved", 0);
      this.currentActivation(authorization.credentialFingerprint);
      const result = this.database.run(
        `UPDATE hackerone_metadata_action_attempts
         SET status='running',started_at=?,revision=1
         WHERE authorization_id=? AND status='reserved' AND revision=0`,
        at,
        authorization.authorizationId,
      );
      if (result.changes !== 1)
        throw new SecurityError("HACKERONE_ACTION_STATE_INVALID");
      const plan = Object.freeze({
        authorizationId: authorization.authorizationId,
        proposalDigest: authorization.proposalDigest,
        credentialFingerprint: authorization.credentialFingerprint,
        endpointClass: authorization.plan.operation,
        requestTarget: `${authorization.plan.path}${authorization.plan.query}`,
      });
      trustedTransportPlans.set(plan, plan);
      return plan;
    });
  }

  public abortReservation(
    value: StoreBoundHackerOneMetadataAuthorization,
  ): void {
    const authorization = requireAuthorization(value);
    const at = monotonicTimestamp(authorization.reservedAt);
    this.database.transaction(() => {
      this.assertAuthorizationCurrent(authorization, "reserved", 0);
      this.settleRow(authorization, "aborted", at, false);
    });
  }

  public settle(
    value: StoreBoundHackerOneMetadataAuthorization,
    outcome: "aborted" | "failed" | "succeeded",
  ): void {
    const authorization = requireAuthorization(value);
    if (!(["aborted", "failed", "succeeded"] as const).includes(outcome))
      throw new SecurityError("HACKERONE_ACTION_OUTCOME_INVALID");
    const at = monotonicTimestamp(authorization.reservedAt);
    this.database.transaction(() => {
      this.assertAuthorizationCurrent(authorization, "running", 1);
      if (outcome === "succeeded") {
        this.assertRuntimeAndKillSwitch();
        this.currentActivation(authorization.credentialFingerprint);
      }
      this.settleRow(authorization, outcome, at, true);
    });
  }

  public listAttempts(): readonly HackerOneMetadataAttemptRecord[] {
    const rows = this.database.all(
      `SELECT authorization_id,operation_id,proposal_id,action_id,
         endpoint_class,status,attempt_index,reserved_at,started_at,
         finished_at,revision
       FROM hackerone_metadata_action_attempts
       ORDER BY reserved_at,authorization_id LIMIT 10001`,
    );
    if (rows.length > 10_000)
      throw new SecurityError("HACKERONE_ACTION_ATTEMPT_READ_LIMIT_EXCEEDED");
    return Object.freeze(rows.map(attemptFromRow));
  }

  private initialize(): void {
    this.database.transaction(() => {
      const markerObject = this.database.get(
        `SELECT type FROM sqlite_schema
         WHERE name='hackerone_metadata_action_schema'`,
      );
      if (markerObject === undefined) {
        assertSqliteSchemaNamespaceEmpty(
          (sql) => this.database.all(sql),
          ACTION_GATE_SCHEMA_EXPECTATION,
          "HACKERONE_ACTION_SCHEMA_MISMATCH",
        );
        for (const statement of ACTION_GATE_SCHEMA)
          this.database.run(statement);
        assertExactSqliteSchema(
          (sql) => this.database.all(sql),
          ACTION_GATE_SCHEMA_EXPECTATION,
          "HACKERONE_ACTION_SCHEMA_MISMATCH",
        );
        this.database.run(
          `INSERT INTO hackerone_metadata_action_schema(
            component,version,schema_digest
          ) VALUES('metadata_action_gate',1,?)`,
          ACTION_GATE_SCHEMA_DIGEST,
        );
      } else {
        assertExactSqliteSchema(
          (sql) => this.database.all(sql),
          ACTION_GATE_SCHEMA_EXPECTATION,
          "HACKERONE_ACTION_SCHEMA_MISMATCH",
        );
      }
      const marker = this.database.get(
        `SELECT version,schema_digest FROM hackerone_metadata_action_schema
         WHERE component='metadata_action_gate'`,
      );
      if (
        marker?.["version"] !== 1 ||
        marker["schema_digest"] !== ACTION_GATE_SCHEMA_DIGEST
      )
        throw new SecurityError("HACKERONE_ACTION_SCHEMA_MISMATCH");
    });
  }

  private assertRuntimeAndKillSwitch(): void {
    if (
      !this.#runtime.enabled ||
      !this.#runtime.externalIntegrationsEnabled ||
      !this.#runtime.configured
    )
      throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
    if (this.controlPlane.isKillSwitchActive())
      throw new SecurityError("HACKERONE_KILL_SWITCH");
  }

  private assertPlanScope(plan: HackerOneMetadataRequestPlan): void {
    if (plan.operation === "programs") return;
    if (plan.handle === null)
      throw new SecurityError("HACKERONE_ACTION_SCOPE_BLOCKED");
    const synchronized = this.database.get(
      `SELECT local_ref FROM hackerone_api_programs
       WHERE handle=? AND catalog_active=1`,
      plan.handle,
    );
    if (synchronized === undefined)
      throw new SecurityError("HACKERONE_ACTION_SCOPE_BLOCKED");
  }

  private currentActivation(credentialFingerprint: string): {
    readonly approvalId: string;
    readonly bindingDigest: string;
  } {
    const state = integrationState(this.database);
    if (!state.adapterEnabled)
      throw new SecurityError("HACKERONE_ADAPTER_DISABLED");
    const row = this.database.get(
      `SELECT * FROM hackerone_metadata_activation_bindings
       WHERE activated_generation=? AND decision_audit_id IS NOT NULL`,
      state.adapterGeneration,
    );
    if (row === undefined)
      throw new SecurityError("HACKERONE_ACTIVATION_EVIDENCE_REQUIRED");
    const approvalId = requiredIdentifier(
      row["approval_id"],
      "HACKERONE_ACTIVATION_EVIDENCE_INVALID",
    );
    const bindingDigest = requiredDigest(row["binding_digest"]);
    const approvalPayloadHash = requiredDigest(row["approval_payload_hash"]);
    const operatorId = requiredIdentifier(
      row["operator_id"],
      "HACKERONE_ACTIVATION_EVIDENCE_INVALID",
    );
    const credential = requiredFingerprint(row["credential_fingerprint"]);
    const runtimeDigest = requiredDigest(row["runtime_digest"]);
    const adapterGeneration = requiredNonnegativeInteger(
      row["adapter_generation"],
    );
    const createdAt = requiredTimestamp(row["created_at"]);
    const expiresAt = requiredTimestamp(row["expires_at"]);
    const expectedBindingDigest = sha256(
      canonicalJson({
        actionClass: ACTION_CLASS,
        actionId: ACTION_ID,
        approvalId,
        operatorId,
        credentialFingerprint: credential,
        runtimeDigest,
        adapterGeneration,
        scheme: SCHEME,
        host: HOST,
        port: PORT,
        method: METHOD,
        createdAt,
        expiresAt,
      }),
    );
    if (
      credential !== credentialFingerprint ||
      runtimeDigest !== activationRuntimeDigest(this.#runtime) ||
      adapterGeneration + 1 !== state.adapterGeneration ||
      row["activated_generation"] !== state.adapterGeneration ||
      bindingDigest !== expectedBindingDigest
    )
      throw new SecurityError("HACKERONE_ACTIVATION_EVIDENCE_INVALID");
    const approval = this.controlPlane
      .listApprovals()
      .find((candidate) => candidate.id === approvalId);
    if (approval === undefined)
      throw new SecurityError("HACKERONE_ACTIVATION_EVIDENCE_INVALID");
    if (
      approval.kind !== "privacy_alert" ||
      approval.status !== "accepted" ||
      approval.payloadHash !== approvalPayloadHash ||
      approval.policyHash !== runtimeDigest ||
      approval.createdAt !== createdAt ||
      approval.auditReference !== `h1-activation:${approvalId}` ||
      approval.technicalDetails !==
        `Exact target ${SCHEME}://${HOST}:${String(PORT)}; GET-only; activation binding ${bindingDigest}` ||
      approval.decidedBy !== operatorId ||
      approval.decidedAt === null ||
      approval.decidedAt >= expiresAt
    )
      throw new SecurityError("HACKERONE_ACTIVATION_EVIDENCE_INVALID");
    this.controlPlane.requireAuthenticatedApprovalDecision(
      approval,
      approvalPayloadHash,
    );
    return Object.freeze({ approvalId, bindingDigest });
  }

  private assertAndCountBudget(operationId: string, now: string): number {
    const operationCount = count(
      this.database.get(
        `SELECT count(*) AS count FROM hackerone_metadata_action_attempts
         WHERE operation_id=?`,
        operationId,
      ),
    );
    const activeCount = count(
      this.database.get(
        `SELECT count(*) AS count FROM hackerone_metadata_action_attempts
         WHERE status IN ('reserved','running')`,
      ),
    );
    const threshold = new Date(Date.parse(now) - 60_000).toISOString();
    const minuteCount = count(
      this.database.get(
        `SELECT count(*) AS count FROM hackerone_metadata_action_attempts
         WHERE reserved_at>=?`,
        threshold,
      ),
    );
    if (
      operationCount >= this.#runtime.requestBudget.maxRequestsTotal ||
      activeCount >= this.#runtime.requestBudget.maxConcurrency ||
      minuteCount >= this.#runtime.requestBudget.requestsPerMinute
    )
      throw new SecurityError("HACKERONE_REQUEST_BUDGET_EXCEEDED");
    return operationCount + 1;
  }

  private assertClockMonotonic(now: string): void {
    const maximum = this.database.get(
      "SELECT max(reserved_at) AS maximum FROM hackerone_metadata_action_attempts",
    )?.["maximum"];
    if (maximum !== null && maximum !== undefined) {
      if (typeof maximum !== "string" || maximum > now)
        throw new SecurityError("HACKERONE_RATE_CLOCK_ROLLBACK");
    }
  }

  private assertAuthorizationCurrent(
    authorization: StoreBoundHackerOneMetadataAuthorization,
    status: "reserved" | "running",
    revision: 0 | 1,
  ): void {
    const row = this.database.get(
      "SELECT * FROM hackerone_metadata_action_attempts WHERE authorization_id=?",
      authorization.authorizationId,
    );
    if (row === undefined)
      throw new SecurityError("HACKERONE_ACTION_EVIDENCE_INVALID");
    if (
      row["status"] !== status ||
      row["revision"] !== revision ||
      row["proposal_id"] !== authorization.proposalId ||
      row["proposal_digest"] !== authorization.proposalDigest ||
      row["plan_digest"] !== authorization.planDigest ||
      row["activation_approval_id"] !== authorization.activationApprovalId ||
      row["activation_binding_digest"] !==
        authorization.activationBindingDigest ||
      row["credential_fingerprint"] !== authorization.credentialFingerprint ||
      row["request_target"] !==
        `${authorization.plan.path}${authorization.plan.query}`
    )
      throw new SecurityError("HACKERONE_ACTION_EVIDENCE_INVALID");
  }

  private settleRow(
    authorization: StoreBoundHackerOneMetadataAuthorization,
    outcome: "aborted" | "failed" | "succeeded",
    at: string,
    started: boolean,
  ): void {
    const settlementAuditId = `h1settle-${sha256(
      `${authorization.authorizationId}\u0000${outcome}\u0000${at}`,
    ).slice(0, 40)}`;
    this.database.run(
      `INSERT INTO control_plane_audit(
        id,occurred_at,action,decision,reason_code,object_reference,payload_hash
      ) VALUES(?,?,?,?,?,?,?)`,
      settlementAuditId,
      at,
      "hackerone_metadata_action_settlement",
      outcome,
      `HACKERONE_METADATA_ACTION_${outcome.toUpperCase()}`,
      authorization.authorizationId,
      authorization.proposalDigest,
    );
    const result = this.database.run(
      `UPDATE hackerone_metadata_action_attempts
       SET status=?,finished_at=?,revision=?,settlement_audit_id=?
       WHERE authorization_id=? AND status=? AND revision=?`,
      outcome,
      at,
      started ? 2 : 1,
      settlementAuditId,
      authorization.authorizationId,
      started ? "running" : "reserved",
      started ? 1 : 0,
    );
    if (result.changes !== 1)
      throw new SecurityError("HACKERONE_ACTION_STATE_INVALID");
  }
}

export function isTrustedHackerOneMetadataActionGate(
  value: unknown,
): value is HackerOneMetadataActionGate {
  if (value === null || typeof value !== "object") return false;
  try {
    return (
      !types.isProxy(value) &&
      Reflect.getPrototypeOf(value) === HackerOneMetadataActionGate.prototype &&
      trustedGates.has(value)
    );
  } catch {
    return false;
  }
}

export function captureAuthorizedHackerOneMetadataTransportPlan(
  value: unknown,
): AuthorizedHackerOneMetadataTransportPlan {
  if (value === null || typeof value !== "object")
    throw new SecurityError("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
  try {
    if (
      types.isProxy(value) ||
      Reflect.getPrototypeOf(value) !== Object.prototype
    )
      throw new Error("invalid");
    const plan = trustedTransportPlans.get(value);
    if (plan === undefined) throw new Error("invalid");
    trustedTransportPlans.delete(value);
    return Object.freeze({
      authorizationId: plan.authorizationId,
      proposalDigest: plan.proposalDigest,
      credentialFingerprint: plan.credentialFingerprint,
      endpointClass: plan.endpointClass,
      requestTarget: plan.requestTarget,
    });
  } catch {
    throw new SecurityError("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
  }
}

function captureActivationInput(
  value: HackerOneMetadataActivationApprovalInput,
): HackerOneMetadataActivationApprovalInput {
  const record = exactRecord(value, [
    "approvalId",
    "operatorId",
    "credentialFingerprint",
    "createdAt",
  ]);
  return Object.freeze({
    approvalId: requiredIdentifier(
      record["approvalId"],
      "HACKERONE_ACTIVATION_INPUT_INVALID",
    ),
    operatorId: requiredOperator(record["operatorId"]),
    credentialFingerprint: requiredFingerprint(record["credentialFingerprint"]),
    createdAt: requiredTimestamp(record["createdAt"]),
  });
}

function capturePolicyAcceptanceInput(
  value: HackerOnePolicyAcceptanceApprovalInput,
): HackerOnePolicyAcceptanceApprovalInput {
  const record = exactRecord(value, [
    "approvalId",
    "operatorId",
    "programLocalRef",
    "snapshotDigest",
    "createdAt",
  ]);
  const localRef = record["programLocalRef"];
  if (
    typeof localRef !== "string" ||
    !/^(?:h1a|h1m)_[0-9a-f]{64}$/u.test(localRef)
  )
    throw new SecurityError("HACKERONE_POLICY_ACCEPTANCE_INPUT_INVALID");
  return Object.freeze({
    approvalId: requiredIdentifier(
      record["approvalId"],
      "HACKERONE_POLICY_ACCEPTANCE_INPUT_INVALID",
    ),
    operatorId: requiredOperator(record["operatorId"]),
    programLocalRef: localRef,
    snapshotDigest: requiredDigest(record["snapshotDigest"]),
    createdAt: requiredTimestamp(record["createdAt"]),
  });
}

function captureReservationInput(
  value: HackerOneMetadataReservationInput,
): HackerOneMetadataReservationInput {
  const record = exactRecord(value, [
    "operationId",
    "proposalId",
    "plan",
    "credentialFingerprint",
  ]);
  return Object.freeze({
    operationId: requiredIdentifier(
      record["operationId"],
      "HACKERONE_ACTION_PROPOSAL_INVALID",
    ),
    proposalId: requiredIdentifier(
      record["proposalId"],
      "HACKERONE_ACTION_PROPOSAL_INVALID",
    ),
    plan: captureTrustedHackerOneMetadataRequestPlan(record["plan"]),
    credentialFingerprint: requiredFingerprint(record["credentialFingerprint"]),
  });
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
): Readonly<Record<string, unknown>> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== keys.length
  )
    throw new SecurityError("HACKERONE_ACTION_INPUT_INVALID");
  const result: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor))
      throw new SecurityError("HACKERONE_ACTION_INPUT_INVALID");
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function requireAuthorization(
  value: unknown,
): StoreBoundHackerOneMetadataAuthorization {
  if (value === null || typeof value !== "object")
    throw new SecurityError("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
  try {
    if (
      types.isProxy(value) ||
      Reflect.getPrototypeOf(value) !== Object.prototype
    )
      throw new Error("invalid");
    const authorization = trustedAuthorizations.get(value);
    if (authorization === undefined) throw new Error("invalid");
    return authorization;
  } catch {
    throw new SecurityError("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
  }
}

function integrationState(database: ControlPlaneDatabase): {
  readonly adapterEnabled: boolean;
  readonly adapterGeneration: number;
} {
  const row = database.get(
    "SELECT adapter_enabled,adapter_generation FROM hackerone_integration_state WHERE singleton=1",
  );
  if (
    row === undefined ||
    (row["adapter_enabled"] !== 0 && row["adapter_enabled"] !== 1) ||
    typeof row["adapter_generation"] !== "number" ||
    !Number.isSafeInteger(row["adapter_generation"]) ||
    row["adapter_generation"] < 0
  )
    throw new SecurityError("HACKERONE_INTEGRATION_STATE_INVALID");
  return Object.freeze({
    adapterEnabled: row["adapter_enabled"] === 1,
    adapterGeneration: row["adapter_generation"],
  });
}

function activationRuntimeDigest(
  runtime: HackerOneMetadataReadRuntimeState,
): string {
  return sha256(
    canonicalJson({
      version: 1,
      actionClass: ACTION_CLASS,
      actionId: ACTION_ID,
      capability: runtime.capability,
      configured: runtime.configured,
      enabled: runtime.enabled,
      externalIntegrationsEnabled: runtime.externalIntegrationsEnabled,
      requestBudget: {
        maxRequestsTotal: runtime.requestBudget.maxRequestsTotal,
        requestsPerMinute: runtime.requestBudget.requestsPerMinute,
        maxConcurrency: runtime.requestBudget.maxConcurrency,
      },
      transportPolicy: {
        adapterVersion: "hackerone-readonly-v1",
        captureMode: "metadata_only",
        followRedirects: false,
        responseLimitBytes: 1_048_576,
        timeoutMs: 10_000,
      },
      target: { scheme: SCHEME, host: HOST, port: PORT, method: METHOD },
    }),
  );
}

function metadataPlanDigest(plan: HackerOneMetadataRequestPlan): string {
  return sha256(
    canonicalJson({
      version: plan.version,
      capability: plan.capability,
      operation: plan.operation,
      method: plan.method,
      scheme: plan.scheme,
      host: plan.host,
      port: plan.port,
      path: plan.path,
      query: plan.query,
      handle: plan.handle,
      page: plan.page,
      captureMode: plan.captureMode,
      followRedirects: plan.followRedirects,
      budgetUnits: plan.budgetUnits,
    }),
  );
}

function assertRegistryDefinition(): void {
  const definition = getExternalActionDefinition(ACTION_ID);
  if (
    definition?.actionId !== ACTION_ID ||
    definition.targetClass !== "hackerone_metadata" ||
    definition.fixedTargetPolicy.kind !== "hackerone_metadata_readonly" ||
    definition.requiredSecretKind !== "hackerone_api_credentials" ||
    definition.humanCheckpoint !== "hackerone_metadata_activation" ||
    definition.ownershipCheck !== "not_applicable" ||
    definition.simulationSupported
  )
    throw new SecurityError("HACKERONE_ACTION_REGISTRY_INVALID");
}

function attemptFromRow(
  row: Readonly<Record<string, unknown>>,
): HackerOneMetadataAttemptRecord {
  const endpoint = row["endpoint_class"];
  if (
    endpoint !== "program" &&
    endpoint !== "programs" &&
    endpoint !== "scope_exclusions" &&
    endpoint !== "structured_scopes"
  )
    throw new SecurityError("HACKERONE_ACTION_EVIDENCE_INVALID");
  const status = row["status"];
  if (
    status !== "aborted" &&
    status !== "failed" &&
    status !== "reserved" &&
    status !== "running" &&
    status !== "succeeded"
  )
    throw new SecurityError("HACKERONE_ACTION_EVIDENCE_INVALID");
  const attemptIndex = requiredPositiveInteger(row["attempt_index"]);
  const revision = requiredNonnegativeInteger(row["revision"]);
  return Object.freeze({
    authorizationId: requiredIdentifier(
      row["authorization_id"],
      "HACKERONE_ACTION_EVIDENCE_INVALID",
    ),
    operationId: requiredIdentifier(
      row["operation_id"],
      "HACKERONE_ACTION_EVIDENCE_INVALID",
    ),
    proposalId: requiredIdentifier(
      row["proposal_id"],
      "HACKERONE_ACTION_EVIDENCE_INVALID",
    ),
    actionId: ACTION_ID,
    endpointClass: endpoint,
    status,
    attemptIndex,
    reservedAt: requiredTimestamp(row["reserved_at"]),
    startedAt: nullableTimestamp(row["started_at"]),
    finishedAt: nullableTimestamp(row["finished_at"]),
    revision,
  });
}

function requiredIdentifier(value: unknown, code: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value))
    throw new SecurityError(code);
  return value;
}

function requiredOperator(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9._@-]{1,128}$/u.test(value))
    throw new SecurityError("HACKERONE_OPERATOR_INVALID");
  return value;
}

function requiredFingerprint(value: unknown): string {
  if (typeof value !== "string" || !FINGERPRINT.test(value))
    throw new SecurityError("HACKERONE_CREDENTIAL_FINGERPRINT_INVALID");
  return value;
}

function requiredDigest(value: unknown): string {
  if (typeof value !== "string" || !DIGEST.test(value))
    throw new SecurityError("HACKERONE_ACTION_DIGEST_INVALID");
  return value;
}

function nullableDigest(value: unknown): string | null {
  return value === null ? null : requiredDigest(value);
}

function requiredSource(
  value: unknown,
): "hackerone_api_authenticated" | "manual_unverified" {
  if (value !== "hackerone_api_authenticated" && value !== "manual_unverified")
    throw new SecurityError("HACKERONE_ACTION_EVIDENCE_INVALID");
  return value;
}

function requiredTimestamp(value: unknown): string {
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(Date.parse(value)).toISOString() !== value
  )
    throw new SecurityError("HACKERONE_ACTION_TIME_INVALID");
  return value;
}

function nullableTimestamp(value: unknown): string | null {
  return value === null ? null : requiredTimestamp(value);
}

function requiredPositiveInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1)
    throw new SecurityError("HACKERONE_ACTION_EVIDENCE_INVALID");
  return value;
}

function requiredNonnegativeInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    throw new SecurityError("HACKERONE_ACTION_EVIDENCE_INVALID");
  return value;
}

function count(row: Readonly<Record<string, unknown>> | undefined): number {
  const value = row?.["count"];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    throw new SecurityError("HACKERONE_ACTION_BUDGET_EVIDENCE_INVALID");
  return value;
}

function systemTimestamp(): string {
  const value = new Date(Date.now());
  if (!Number.isFinite(value.getTime()))
    throw new SecurityError("HACKERONE_ACTION_TIME_INVALID");
  return value.toISOString();
}

function monotonicTimestamp(earliest: string): string {
  const current = systemTimestamp();
  return current < earliest ? earliest : current;
}

Object.freeze(HackerOneMetadataActionGate.prototype);
Object.freeze(HackerOneMetadataActionGate);
