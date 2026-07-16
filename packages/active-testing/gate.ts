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
  assertHackerOneActiveTestRegistryPlanBinding,
  hackerOneActiveTestRegistryDefinitionDigest,
} from "../external-actions/registry.js";
import { HackerOneMetadataStore } from "../hackerone-readonly/store.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import {
  assertExactSqliteSchema,
  assertSqliteSchemaNamespaceEmpty,
  buildSqliteSchemaExpectation,
} from "../shared/sqlite-schema.js";
import { activeTestCatalogDigest, createActiveTestPlan } from "./catalog.js";
import {
  activeTestPlanDigest,
  validateAndFreezeActiveTestPlan,
} from "./plan.js";
import {
  activeTestObservationDigest,
  analyzeActiveTestEvidence,
  createLocalActiveTestReportDraft,
  reconstructLocalActiveTestReportDraft,
  validateAndFreezeActiveTestObservation,
} from "./report.js";
import { isTrustedActiveTestingRuntime } from "./runtime.js";
import type {
  ActiveTestingRuntimeState,
  ActiveTestObservation,
  ActiveTestPlanV1,
  ActiveTestReportDraft,
} from "./types.js";
import {
  captureActiveTestTransportEvidence,
  type ActiveTestTransportEvidence,
} from "./transport.js";

const APPROVAL_LIFETIME_MS = 5 * 60_000;
const MAX_API_SNAPSHOT_AGE_MS = 15 * 60_000;
const IDENTIFIER = /^[A-Za-z0-9._-]{1,128}$/u;
const OPERATOR = /^[A-Za-z0-9._@-]{1,128}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;

const trustedGates = new WeakSet();
const trustedGateRuntimes = new WeakMap<object, ActiveTestingRuntimeState>();
const trustedAuthorizations = new WeakMap<
  object,
  StoreBoundActiveTestAuthorization
>();
const trustedTransportPlans = new WeakMap<
  object,
  AuthorizedActiveTestTransportPlan
>();

export interface ActiveTestApprovalInput {
  readonly approvalId: string;
  readonly operatorId: string;
  readonly plan: ActiveTestPlanV1;
  readonly createdAt: string;
}

export interface ActiveTestReservationInput {
  readonly proposalId: string;
  readonly approvalId: string;
  readonly planId: string;
  readonly confirmed: true;
}

export interface StoreBoundActiveTestAuthorization {
  readonly authorizationId: string;
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly approvalId: string;
  readonly approvalBindingDigest: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly registryDefinitionDigest: string;
  readonly reservedAt: string;
  readonly reservationAuditId: string;
  readonly attemptIndex: number;
}

export interface AuthorizedActiveTestTransportPlan {
  readonly authorizationId: string;
  readonly proposalDigest: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly registryDefinitionDigest: string;
  readonly testClass: ActiveTestPlanV1["test_class"];
  readonly target: ActiveTestPlanV1["target"];
  readonly request: ActiveTestPlanV1["request"];
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
}

export interface ActiveTestAttemptRecord {
  readonly authorizationId: string;
  readonly proposalId: string;
  readonly approvalId: string;
  readonly planId: string;
  readonly testClass: ActiveTestPlanV1["test_class"];
  readonly method: ActiveTestPlanV1["request"]["method"];
  readonly status: "aborted" | "failed" | "reserved" | "running" | "succeeded";
  readonly reservedAt: string;
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
  readonly revision: number;
}

export interface StoredActiveTestPlanRecord {
  readonly approvalId: string;
  readonly approvalStatus: "accepted" | "open" | "rejected";
  readonly planId: string;
  readonly planDigest: string;
  readonly programRef: string;
  readonly snapshotDigest: string;
  readonly scopeId: string;
  readonly assetIdentifierDigest: string;
  readonly testClass: ActiveTestPlanV1["test_class"];
  readonly attemptStatus:
    "aborted" | "failed" | "reserved" | "running" | "succeeded" | null;
  readonly createdAt: string;
  readonly expiresAt: string;
}

export interface StoredActiveTestReportSummary {
  readonly reportId: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly observationDigest: string;
  readonly markdownDigest: string;
  readonly jsonDigest: string;
  readonly transportKind: "loopback_test" | "production_https";
  readonly resolutionDigest: string;
  readonly reviewStatus: "local_draft_unsubmitted";
  readonly externalSubmissionPerformed: false;
  readonly createdAt: string;
}

export interface ActiveTestCompletionResult {
  readonly observation: ActiveTestObservation;
  readonly report: ActiveTestReportDraft;
}

const ACTIVE_TEST_SCHEMA = Object.freeze([
  `CREATE TABLE IF NOT EXISTS active_testing_schema (
    component TEXT PRIMARY KEY CHECK(component='active_testing_gate'),
    version INTEGER NOT NULL CHECK(version=1),
    schema_digest TEXT NOT NULL CHECK(length(schema_digest)=64)
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS active_test_plans (
    plan_id TEXT PRIMARY KEY,
    plan_digest TEXT NOT NULL UNIQUE CHECK(length(plan_digest)=64),
    program_ref TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest)=64),
    policy_digest TEXT NOT NULL CHECK(length(policy_digest)=64),
    scope_id TEXT NOT NULL,
    asset_identifier_digest TEXT NOT NULL CHECK(length(asset_identifier_digest)=64),
    test_class TEXT NOT NULL CHECK(test_class IN ('cors_preflight','http_headers','security_txt')),
    runner_version TEXT NOT NULL CHECK(runner_version='pilot-readiness-c-v1'),
    plan_json TEXT NOT NULL CHECK(json_valid(plan_json) AND length(plan_json)<=16384),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL CHECK(expires_at>created_at)
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS active_test_approval_bindings (
    approval_id TEXT PRIMARY KEY REFERENCES approvals(id) ON DELETE RESTRICT,
    approval_payload_hash TEXT NOT NULL CHECK(length(approval_payload_hash)=64),
    operator_id TEXT NOT NULL,
    plan_id TEXT NOT NULL UNIQUE REFERENCES active_test_plans(plan_id) ON DELETE RESTRICT,
    plan_digest TEXT NOT NULL UNIQUE CHECK(length(plan_digest)=64),
    snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest)=64),
    policy_digest TEXT NOT NULL CHECK(length(policy_digest)=64),
    scope_id TEXT NOT NULL,
    asset_identifier_digest TEXT NOT NULL CHECK(length(asset_identifier_digest)=64),
    runtime_digest TEXT NOT NULL CHECK(length(runtime_digest)=64),
    catalog_digest TEXT NOT NULL CHECK(length(catalog_digest)=64),
    registry_definition_digest TEXT NOT NULL CHECK(length(registry_definition_digest)=64 AND registry_definition_digest NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL CHECK(expires_at>created_at),
    binding_digest TEXT NOT NULL UNIQUE CHECK(length(binding_digest)=64),
    decision_audit_id TEXT UNIQUE REFERENCES control_plane_audit(id) ON DELETE RESTRICT
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS active_test_attempts (
    authorization_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL UNIQUE,
    proposal_digest TEXT NOT NULL UNIQUE CHECK(length(proposal_digest)=64 AND proposal_digest NOT GLOB '*[^0-9a-f]*'),
    approval_id TEXT NOT NULL UNIQUE REFERENCES active_test_approval_bindings(approval_id) ON DELETE RESTRICT,
    approval_binding_digest TEXT NOT NULL CHECK(length(approval_binding_digest)=64 AND approval_binding_digest NOT GLOB '*[^0-9a-f]*'),
    plan_id TEXT NOT NULL UNIQUE REFERENCES active_test_plans(plan_id) ON DELETE RESTRICT,
    plan_digest TEXT NOT NULL UNIQUE CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'),
    registry_definition_digest TEXT NOT NULL CHECK(length(registry_definition_digest)=64 AND registry_definition_digest NOT GLOB '*[^0-9a-f]*'),
    snapshot_digest TEXT NOT NULL CHECK(length(snapshot_digest)=64 AND snapshot_digest NOT GLOB '*[^0-9a-f]*'),
    scope_id TEXT NOT NULL,
    asset_identifier_digest TEXT NOT NULL CHECK(length(asset_identifier_digest)=64 AND asset_identifier_digest NOT GLOB '*[^0-9a-f]*'),
    test_class TEXT NOT NULL CHECK(test_class IN ('cors_preflight','http_headers','security_txt')),
    method TEXT NOT NULL CHECK(method IN ('GET','HEAD','OPTIONS')),
    attempt_index INTEGER NOT NULL CHECK(attempt_index>0),
    units INTEGER NOT NULL CHECK(units=1),
    status TEXT NOT NULL CHECK(status IN ('reserved','running','succeeded','failed','aborted')),
    reserved_at TEXT NOT NULL CHECK(length(reserved_at)=24),
    started_at TEXT CHECK(started_at IS NULL OR length(started_at)=24),
    finished_at TEXT CHECK(finished_at IS NULL OR length(finished_at)=24),
    revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 2),
    reservation_audit_id TEXT NOT NULL UNIQUE REFERENCES control_plane_audit(id) ON DELETE RESTRICT,
    settlement_audit_id TEXT UNIQUE REFERENCES control_plane_audit(id) ON DELETE RESTRICT,
    UNIQUE(snapshot_digest,scope_id,asset_identifier_digest,test_class),
    CHECK(
      (status='reserved' AND revision=0 AND started_at IS NULL AND finished_at IS NULL AND settlement_audit_id IS NULL)
      OR (status='running' AND revision=1 AND started_at>=reserved_at AND finished_at IS NULL AND settlement_audit_id IS NULL)
      OR (status IN ('succeeded','failed','aborted') AND revision=2 AND started_at>=reserved_at AND finished_at>=started_at AND settlement_audit_id IS NOT NULL)
      OR (status='aborted' AND revision=1 AND started_at IS NULL AND finished_at>=reserved_at AND settlement_audit_id IS NOT NULL)
    )
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS active_test_observations (
    authorization_id TEXT PRIMARY KEY REFERENCES active_test_attempts(authorization_id) ON DELETE RESTRICT,
    plan_id TEXT NOT NULL UNIQUE REFERENCES active_test_plans(plan_id) ON DELETE RESTRICT,
    plan_digest TEXT NOT NULL UNIQUE CHECK(length(plan_digest)=64),
    observation_digest TEXT NOT NULL UNIQUE CHECK(length(observation_digest)=64),
    observation_json TEXT NOT NULL CHECK(json_valid(observation_json) AND length(observation_json)<=32768),
    created_at TEXT NOT NULL
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS active_test_reports (
    report_id TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL UNIQUE REFERENCES active_test_observations(authorization_id) ON DELETE RESTRICT,
    plan_id TEXT NOT NULL UNIQUE REFERENCES active_test_plans(plan_id) ON DELETE RESTRICT,
    plan_digest TEXT NOT NULL UNIQUE CHECK(length(plan_digest)=64),
    observation_digest TEXT NOT NULL UNIQUE CHECK(length(observation_digest)=64),
    report_digest TEXT NOT NULL UNIQUE CHECK(length(report_digest)=64),
    report_json TEXT NOT NULL CHECK(json_valid(report_json) AND length(report_json)<=131072),
    review_status TEXT NOT NULL CHECK(review_status='local_draft_unsubmitted'),
    external_submission_performed INTEGER NOT NULL CHECK(external_submission_performed=0),
    created_at TEXT NOT NULL
  ) STRICT`,
  `CREATE TRIGGER IF NOT EXISTS active_test_plans_no_update
    BEFORE UPDATE ON active_test_plans
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_PLAN_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_plans_no_delete
    BEFORE DELETE ON active_test_plans
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_PLAN_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_binding_insert_guard
    BEFORE INSERT ON active_test_approval_bindings
    WHEN NOT EXISTS(
      SELECT 1 FROM approvals q JOIN active_test_plans p ON p.plan_id=NEW.plan_id
      WHERE q.id=NEW.approval_id AND q.kind='external_action'
        AND q.status='open' AND q.revision=0
        AND q.payload_hash=NEW.approval_payload_hash
        AND q.policy_hash=NEW.policy_digest
        AND q.created_at=NEW.created_at
        AND p.plan_digest=NEW.plan_digest
        AND p.snapshot_digest=NEW.snapshot_digest
        AND p.policy_digest=NEW.policy_digest
        AND p.scope_id=NEW.scope_id
        AND p.asset_identifier_digest=NEW.asset_identifier_digest
    )
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_APPROVAL_EVIDENCE_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_binding_immutable
    BEFORE UPDATE OF approval_id,approval_payload_hash,operator_id,plan_id,
      plan_digest,snapshot_digest,policy_digest,scope_id,asset_identifier_digest,
      runtime_digest,catalog_digest,registry_definition_digest,created_at,
      expires_at,binding_digest
    ON active_test_approval_bindings
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_APPROVAL_BINDING_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_binding_no_delete
    BEFORE DELETE ON active_test_approval_bindings
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_APPROVAL_BINDING_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_binding_decision_guard
    BEFORE UPDATE OF decision_audit_id ON active_test_approval_bindings
    WHEN NEW.decision_audit_id IS NULL OR OLD.decision_audit_id IS NOT NULL
      OR NOT EXISTS(
        SELECT 1 FROM approvals q
        JOIN signed_approval_decisions d ON d.approval_id=q.id
        JOIN operator_signed_statements s ON s.statement_digest=d.statement_digest
        JOIN control_plane_audit a ON a.id=NEW.decision_audit_id
        WHERE q.id=NEW.approval_id AND q.kind='external_action'
          AND q.status=d.decision AND q.revision=1
          AND q.decided_by=NEW.operator_id
          AND q.payload_hash=NEW.approval_payload_hash
          AND d.context_digest_sha256=NEW.binding_digest
          AND s.operator_id=NEW.operator_id
          AND a.action='approval_decision' AND a.decision=d.decision
          AND a.reason_code='HUMAN_APPROVAL_DECISION'
          AND a.object_reference=q.id AND a.payload_hash=d.statement_digest
      )
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_APPROVAL_EVIDENCE_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_attempts_immutable
    BEFORE UPDATE OF authorization_id,proposal_id,proposal_digest,approval_id,
      approval_binding_digest,plan_id,plan_digest,snapshot_digest,scope_id,
      asset_identifier_digest,registry_definition_digest,test_class,method,
      attempt_index,units,reserved_at,reservation_audit_id
    ON active_test_attempts
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_ATTEMPT_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_attempts_insert_guard
    BEFORE INSERT ON active_test_attempts
    WHEN NEW.status<>'reserved' OR NEW.revision<>0 OR NEW.units<>1
      OR NEW.started_at IS NOT NULL OR NEW.finished_at IS NOT NULL
      OR NEW.settlement_audit_id IS NOT NULL
      OR NEW.attempt_index<>(SELECT count(*)+1 FROM active_test_attempts)
      OR EXISTS(
        SELECT 1 FROM active_test_attempts
        WHERE status IN ('reserved','running')
      )
      OR NOT EXISTS(
        SELECT 1 FROM active_test_approval_bindings b
        JOIN active_test_plans p ON p.plan_id=b.plan_id
        JOIN approvals q ON q.id=b.approval_id
        JOIN control_plane_audit r ON r.id=NEW.reservation_audit_id
        WHERE b.approval_id=NEW.approval_id
          AND b.plan_id=NEW.plan_id AND b.plan_digest=NEW.plan_digest
          AND b.binding_digest=NEW.approval_binding_digest
          AND b.registry_definition_digest=NEW.registry_definition_digest
          AND b.snapshot_digest=NEW.snapshot_digest
          AND b.scope_id=NEW.scope_id
          AND b.asset_identifier_digest=NEW.asset_identifier_digest
          AND b.decision_audit_id IS NOT NULL
          AND p.test_class=NEW.test_class
          AND q.status='accepted' AND q.revision=1
          AND ((NEW.test_class='http_headers' AND NEW.method='HEAD')
            OR (NEW.test_class='cors_preflight' AND NEW.method='OPTIONS')
            OR (NEW.test_class='security_txt' AND NEW.method='GET'))
          AND r.occurred_at=NEW.reserved_at
          AND r.action='active_test_authorization'
          AND r.decision='reserved'
          AND r.reason_code='ACTIVE_TEST_REQUEST_RESERVED'
          AND r.object_reference=NEW.authorization_id
          AND r.payload_hash=NEW.proposal_digest
      )
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_ATTEMPT_EVIDENCE_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_attempts_transition_guard
    BEFORE UPDATE OF status,started_at,finished_at,revision,settlement_audit_id
    ON active_test_attempts
    WHEN NOT (
      (OLD.status='reserved' AND OLD.revision=0
        AND NEW.status='running' AND NEW.revision=1
        AND NEW.started_at>=OLD.reserved_at AND NEW.finished_at IS NULL
        AND NEW.settlement_audit_id IS NULL)
      OR
      (OLD.status='reserved' AND OLD.revision=0
        AND NEW.status='aborted' AND NEW.revision=1
        AND NEW.started_at IS NULL AND NEW.finished_at>=OLD.reserved_at
        AND EXISTS(
          SELECT 1 FROM control_plane_audit s
          WHERE s.id=NEW.settlement_audit_id
            AND s.occurred_at=NEW.finished_at
            AND s.action='active_test_settlement'
            AND s.decision='aborted' AND s.reason_code='ACTIVE_TEST_ABORTED'
            AND s.object_reference=OLD.authorization_id
            AND s.payload_hash=OLD.proposal_digest
        ))
      OR
      (OLD.status='running' AND OLD.revision=1
        AND NEW.status IN ('succeeded','failed','aborted') AND NEW.revision=2
        AND NEW.started_at=OLD.started_at AND NEW.finished_at>=OLD.started_at
        AND EXISTS(
          SELECT 1 FROM control_plane_audit s
          WHERE s.id=NEW.settlement_audit_id
            AND s.occurred_at=NEW.finished_at
            AND s.action='active_test_settlement'
            AND s.decision=NEW.status
            AND s.reason_code='ACTIVE_TEST_'||upper(NEW.status)
            AND s.object_reference=OLD.authorization_id
            AND s.payload_hash=CASE
              WHEN NEW.status='succeeded' THEN COALESCE(
                (SELECT o.observation_digest FROM active_test_observations o
                 WHERE o.authorization_id=OLD.authorization_id),'')
              ELSE OLD.proposal_digest END
        ))
    )
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_ATTEMPT_TRANSITION_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_attempts_no_delete
    BEFORE DELETE ON active_test_attempts
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_ATTEMPT_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_observations_insert_guard
    BEFORE INSERT ON active_test_observations
    WHEN json_extract(NEW.observation_json,'$.version') IS NOT 1
      OR json_extract(NEW.observation_json,'$.planId') IS NOT NEW.plan_id
      OR json_extract(NEW.observation_json,'$.planDigest') IS NOT NEW.plan_digest
      OR json_extract(NEW.observation_json,'$.completedAt') IS NOT NEW.created_at
      OR json_extract(NEW.observation_json,'$.rawBodyStored') IS NOT 0
      OR json_extract(NEW.observation_json,'$.rawHeadersStored') IS NOT 0
      OR json_extract(NEW.observation_json,'$.cookiesStored') IS NOT 0
      OR json_extract(NEW.observation_json,'$.redirectLocationPresent') IS NOT 0
      OR json_extract(NEW.observation_json,'$.transportKind') IS NULL
      OR json_extract(NEW.observation_json,'$.transportKind') NOT IN ('production_https','loopback_test')
      OR json_extract(NEW.observation_json,'$.resolutionDigest') IS NULL
      OR length(json_extract(NEW.observation_json,'$.resolutionDigest'))<>64
      OR json_extract(NEW.observation_json,'$.resolutionDigest') GLOB '*[^0-9a-f]*'
      OR NOT EXISTS(
      SELECT 1 FROM active_test_attempts a
      WHERE a.authorization_id=NEW.authorization_id
        AND a.plan_id=NEW.plan_id AND a.plan_digest=NEW.plan_digest
        AND json_extract(NEW.observation_json,'$.testClass')=a.test_class
        AND a.status='running' AND a.revision=1
    )
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_OBSERVATION_EVIDENCE_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_observations_no_update
    BEFORE UPDATE ON active_test_observations
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_OBSERVATION_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_observations_no_delete
    BEFORE DELETE ON active_test_observations
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_OBSERVATION_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_reports_insert_guard
    BEFORE INSERT ON active_test_reports
    WHEN NEW.review_status<>'local_draft_unsubmitted'
      OR NEW.external_submission_performed<>0
      OR json_extract(NEW.report_json,'$.version') IS NOT 1
      OR json_extract(NEW.report_json,'$.reportId') IS NOT NEW.report_id
      OR json_extract(NEW.report_json,'$.planId') IS NOT NEW.plan_id
      OR json_extract(NEW.report_json,'$.planDigest') IS NOT NEW.plan_digest
      OR json_extract(NEW.report_json,'$.observationDigest') IS NOT NEW.observation_digest
      OR json_extract(NEW.report_json,'$.createdAt') IS NOT NEW.created_at
      OR json_extract(NEW.report_json,'$.reviewStatus') IS NOT NEW.review_status
      OR json_extract(NEW.report_json,'$.externalSubmissionPerformed') IS NOT 0
      OR json_extract(NEW.report_json,'$.transportKind') IS NULL
      OR json_extract(NEW.report_json,'$.transportKind') NOT IN ('production_https','loopback_test')
      OR json_extract(NEW.report_json,'$.resolutionDigest') IS NULL
      OR length(json_extract(NEW.report_json,'$.resolutionDigest'))<>64
      OR json_extract(NEW.report_json,'$.resolutionDigest') GLOB '*[^0-9a-f]*'
      OR NOT EXISTS(
      SELECT 1 FROM active_test_observations o
      JOIN active_test_attempts a ON a.authorization_id=o.authorization_id
      WHERE o.authorization_id=NEW.authorization_id
        AND o.plan_id=NEW.plan_id AND o.plan_digest=NEW.plan_digest
        AND o.observation_digest=NEW.observation_digest
        AND a.status='running' AND a.revision=1
    )
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_REPORT_EVIDENCE_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_reports_no_update
    BEFORE UPDATE ON active_test_reports
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_REPORT_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS active_test_reports_no_delete
    BEFORE DELETE ON active_test_reports
    BEGIN SELECT RAISE(ABORT,'ACTIVE_TEST_REPORT_IMMUTABLE'); END`,
]);

const ACTIVE_TEST_SCHEMA_EXPECTATION = buildSqliteSchemaExpectation({
  statements: ACTIVE_TEST_SCHEMA,
});
const ACTIVE_TEST_SCHEMA_DIGEST = ACTIVE_TEST_SCHEMA_EXPECTATION.digest;

export class ActiveTestingActionGate {
  readonly #metadata: HackerOneMetadataStore;
  readonly #runtime: ActiveTestingRuntimeState;

  public constructor(
    private readonly database: ControlPlaneDatabase,
    private readonly controlPlane: ControlPlaneStore,
    runtime: ActiveTestingRuntimeState,
  ) {
    if (
      !isTrustedControlPlaneDatabase(database) ||
      !isTrustedControlPlaneStore(controlPlane) ||
      !controlPlane.isBoundToDatabase(database)
    )
      throw new SecurityError("ACTIVE_TEST_STORE_UNTRUSTED");
    if (!isTrustedActiveTestingRuntime(runtime))
      throw new SecurityError("ACTIVE_TEST_RUNTIME_UNTRUSTED");
    hackerOneActiveTestRegistryDefinitionDigest();
    this.#runtime = runtime;
    this.#metadata = new HackerOneMetadataStore(database);
    this.initialize();
    trustedGates.add(this);
    trustedGateRuntimes.set(this, runtime);
    Object.freeze(this);
  }

  public preparePlanApproval(value: ActiveTestApprovalInput): ApprovalRecord {
    const input = captureApprovalInput(value);
    const plan = validateAndFreezeActiveTestPlan(input.plan);
    const digest = activeTestPlanDigest(plan);
    return this.database.transaction(() => {
      this.assertRuntimeAndKillSwitch();
      const now = this.observeTime();
      if (input.createdAt !== plan.created_at || input.createdAt > now)
        throw new SecurityError("ACTIVE_TEST_APPROVAL_TIME_INVALID");
      this.assertPlanCurrent(plan, digest, now);
      const runtimeDigest = activeTestingRuntimeDigest(this.#runtime);
      const catalogDigest = activeTestCatalogDigest();
      const registryDefinitionDigest =
        assertHackerOneActiveTestRegistryPlanBinding(
          plan.test_class,
          plan.request.method,
          plan.target.scheme,
          plan.target.port,
        );
      const expiresAt = earliestTimestamp(
        plan.expires_at,
        new Date(
          Date.parse(input.createdAt) + APPROVAL_LIFETIME_MS,
        ).toISOString(),
      );
      const approval = new ApprovalQueue().enqueue({
        id: input.approvalId,
        kind: "external_action",
        summary: `Aktiven ${plan.test_class}-Einmaltest freigeben`,
        technicalDetails: `Plan ${digest}; Snapshot ${plan.snapshot_digest}; Scope ${plan.scope_id}; exakt ein ${plan.request.method}-Request`,
        impact:
          "Erlaubt nach einer zweiten Startbestätigung genau einen niedrig-riskanten Request; keine Redirects, Retries, Logins oder Report-Einreichung",
        policyVersion: 1,
        policyHash: plan.policy_digest,
        createdAt: input.createdAt,
        auditReference: `active-test:${input.approvalId}`,
      });
      const material = bindingMaterial({
        approvalId: input.approvalId,
        approvalPayloadHash: approval.payloadHash,
        operatorId: input.operatorId,
        plan,
        planDigest: digest,
        runtimeDigest,
        catalogDigest,
        registryDefinitionDigest,
        createdAt: input.createdAt,
        expiresAt,
      });
      const bindingDigest = sha256(canonicalJson(material));
      this.controlPlane.persistApproval(approval);
      this.database.run(
        `INSERT INTO active_test_plans(
          plan_id,plan_digest,program_ref,snapshot_digest,policy_digest,
          scope_id,asset_identifier_digest,test_class,runner_version,
          plan_json,created_at,expires_at
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
        plan.plan_id,
        digest,
        plan.program_ref,
        plan.snapshot_digest,
        plan.policy_digest,
        plan.scope_id,
        plan.asset_identifier_digest,
        plan.test_class,
        plan.runner_version,
        canonicalJson(plan),
        plan.created_at,
        plan.expires_at,
      );
      this.database.run(
        `INSERT INTO active_test_approval_bindings(
          approval_id,approval_payload_hash,operator_id,plan_id,plan_digest,
          snapshot_digest,policy_digest,scope_id,asset_identifier_digest,
          runtime_digest,catalog_digest,registry_definition_digest,created_at,
          expires_at,binding_digest,decision_audit_id
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
        input.approvalId,
        approval.payloadHash,
        input.operatorId,
        plan.plan_id,
        digest,
        plan.snapshot_digest,
        plan.policy_digest,
        plan.scope_id,
        plan.asset_identifier_digest,
        runtimeDigest,
        catalogDigest,
        registryDefinitionDigest,
        input.createdAt,
        expiresAt,
        bindingDigest,
      );
      return approval;
    });
  }

  public authorizeAndReserve(
    value: ActiveTestReservationInput,
  ): StoreBoundActiveTestAuthorization {
    const input = captureReservationInput(value);
    return this.database.transaction(() => {
      const now = this.observeTime();
      this.assertRuntimeAndKillSwitch();
      this.assertClockMonotonic(now);
      const current = this.requireApprovedPlan(
        input.planId,
        input.approvalId,
        now,
      );
      const attemptIndex = this.assertAndCountBudget(now);
      const proposalDigest = sha256(
        canonicalJson({
          version: 1,
          proposalId: input.proposalId,
          approvalId: input.approvalId,
          planId: input.planId,
          planDigest: current.planDigest,
          registryDefinitionDigest: current.registryDefinitionDigest,
          approvalBindingDigest: current.bindingDigest,
          confirmed: true,
        }),
      );
      const authorizationId = `atauth-${sha256(`${proposalDigest}\u0000${now}`).slice(0, 40)}`;
      const reservationAuditId = `atreserve-${sha256(`${authorizationId}\u0000${current.bindingDigest}`).slice(0, 40)}`;
      this.database.run(
        `INSERT INTO control_plane_audit(
          id,occurred_at,action,decision,reason_code,object_reference,payload_hash
        ) VALUES(?,?,?,?,?,?,?)`,
        reservationAuditId,
        now,
        "active_test_authorization",
        "reserved",
        "ACTIVE_TEST_REQUEST_RESERVED",
        authorizationId,
        proposalDigest,
      );
      this.database.run(
        `INSERT INTO active_test_attempts(
          authorization_id,proposal_id,proposal_digest,approval_id,
          approval_binding_digest,plan_id,plan_digest,snapshot_digest,scope_id,
          asset_identifier_digest,registry_definition_digest,test_class,method,
          attempt_index,units,status,reserved_at,started_at,finished_at,revision,
          reservation_audit_id,settlement_audit_id
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,'reserved',?,NULL,NULL,0,?,NULL)`,
        authorizationId,
        input.proposalId,
        proposalDigest,
        input.approvalId,
        current.bindingDigest,
        current.plan.plan_id,
        current.planDigest,
        current.plan.snapshot_digest,
        current.plan.scope_id,
        current.plan.asset_identifier_digest,
        current.registryDefinitionDigest,
        current.plan.test_class,
        current.plan.request.method,
        attemptIndex,
        now,
        reservationAuditId,
      );
      const authorization = Object.freeze({
        authorizationId,
        proposalId: input.proposalId,
        proposalDigest,
        approvalId: input.approvalId,
        approvalBindingDigest: current.bindingDigest,
        planId: input.planId,
        planDigest: current.planDigest,
        registryDefinitionDigest: current.registryDefinitionDigest,
        reservedAt: now,
        reservationAuditId,
        attemptIndex,
      });
      trustedAuthorizations.set(authorization, authorization);
      return authorization;
    });
  }

  public start(
    value: StoreBoundActiveTestAuthorization,
  ): AuthorizedActiveTestTransportPlan {
    const authorization = requireAuthorization(value);
    return this.database.transaction(() => {
      const now = this.observeTime(authorization.reservedAt);
      this.assertRuntimeAndKillSwitch();
      this.assertAuthorizationCurrent(authorization, "reserved", 0);
      const current = this.requireApprovedPlan(
        authorization.planId,
        authorization.approvalId,
        now,
      );
      if (
        current.planDigest !== authorization.planDigest ||
        current.bindingDigest !== authorization.approvalBindingDigest ||
        current.registryDefinitionDigest !==
          authorization.registryDefinitionDigest
      )
        throw new SecurityError("ACTIVE_TEST_AUTHORIZATION_EVIDENCE_INVALID");
      const updated = this.database.run(
        `UPDATE active_test_attempts SET status='running',started_at=?,revision=1
         WHERE authorization_id=? AND status='reserved' AND revision=0`,
        now,
        authorization.authorizationId,
      );
      if (updated.changes !== 1)
        throw new SecurityError("ACTIVE_TEST_STATE_INVALID");
      const transportPlan = Object.freeze({
        authorizationId: authorization.authorizationId,
        proposalDigest: authorization.proposalDigest,
        planId: current.plan.plan_id,
        planDigest: authorization.planDigest,
        registryDefinitionDigest: authorization.registryDefinitionDigest,
        testClass: current.plan.test_class,
        target: current.plan.target,
        request: current.plan.request,
        timeoutMs: this.#runtime.requestTimeoutMs,
        maxResponseBytes: this.#runtime.maxResponseBytes,
      });
      trustedTransportPlans.set(transportPlan, transportPlan);
      return transportPlan;
    });
  }

  public abortReservation(value: StoreBoundActiveTestAuthorization): void {
    const authorization = requireAuthorization(value);
    this.database.transaction(() => {
      const now = this.observeTime(authorization.reservedAt);
      this.assertAuthorizationCurrent(authorization, "reserved", 0);
      this.settleRow(authorization, "aborted", now, false);
    });
  }

  public settle(
    value: StoreBoundActiveTestAuthorization,
    outcome: "aborted" | "failed",
  ): void {
    const authorization = requireAuthorization(value);
    const normalizedOutcome = captureFailureOutcome(outcome);
    this.database.transaction(() => {
      const attempt = this.assertAuthorizationCurrent(
        authorization,
        "running",
        1,
      );
      const now = this.observeTime(attempt.startedAt);
      this.settleRow(authorization, normalizedOutcome, now, true);
    });
  }

  public complete(
    value: StoreBoundActiveTestAuthorization,
    transportEvidence: ActiveTestTransportEvidence,
  ): ActiveTestCompletionResult {
    const authorization = requireAuthorization(value);
    return this.database.transaction(() => {
      const attempt = this.assertAuthorizationCurrent(
        authorization,
        "running",
        1,
      );
      const now = this.observeTime(attempt.startedAt);
      this.assertRuntimeAndKillSwitch();
      const current = this.requireApprovedPlan(
        authorization.planId,
        authorization.approvalId,
        now,
      );
      if (
        current.planDigest !== authorization.planDigest ||
        current.bindingDigest !== authorization.approvalBindingDigest ||
        current.registryDefinitionDigest !==
          authorization.registryDefinitionDigest
      )
        throw new SecurityError("ACTIVE_TEST_AUTHORIZATION_EVIDENCE_INVALID");
      const attested = captureActiveTestTransportEvidence(
        transportEvidence,
        authorization,
      );
      const responseMetadata = attested.metadata;
      const observation = analyzeActiveTestEvidence(
        current.plan,
        responseMetadata,
      );
      if (
        observation.completedAt < attempt.startedAt ||
        observation.completedAt > now
      )
        throw new SecurityError("ACTIVE_TEST_EVIDENCE_TIME_INVALID");
      const report = createLocalActiveTestReportDraft(
        current.plan,
        responseMetadata,
      );
      const observationDigest = activeTestObservationDigest(observation);
      if (report.observationDigest !== observationDigest)
        throw new SecurityError("ACTIVE_TEST_REPORT_EVIDENCE_INVALID");
      const reportDigest = sha256(canonicalJson(report));
      this.database.run(
        `INSERT INTO active_test_observations(
          authorization_id,plan_id,plan_digest,observation_digest,
          observation_json,created_at
        ) VALUES(?,?,?,?,?,?)`,
        authorization.authorizationId,
        current.plan.plan_id,
        current.planDigest,
        observationDigest,
        canonicalJson(observation),
        observation.completedAt,
      );
      this.database.run(
        `INSERT INTO active_test_reports(
          report_id,authorization_id,plan_id,plan_digest,observation_digest,
          report_digest,report_json,review_status,
          external_submission_performed,created_at
        ) VALUES(?,?,?,?,?,?,?,'local_draft_unsubmitted',0,?)`,
        report.reportId,
        authorization.authorizationId,
        current.plan.plan_id,
        current.planDigest,
        observationDigest,
        reportDigest,
        canonicalJson(report),
        report.createdAt,
      );
      this.settleRow(authorization, "succeeded", now, true, observationDigest);
      return Object.freeze({ observation, report });
    });
  }

  public listAttempts(): readonly ActiveTestAttemptRecord[] {
    const rows = this.database.all(
      `SELECT authorization_id,proposal_id,approval_id,plan_id,test_class,
        method,status,reserved_at,started_at,finished_at,revision
       FROM active_test_attempts ORDER BY reserved_at,authorization_id LIMIT 1001`,
    );
    if (rows.length > 1_000)
      throw new SecurityError("ACTIVE_TEST_ATTEMPT_READ_LIMIT_EXCEEDED");
    return Object.freeze(rows.map(attemptFromRow));
  }

  public listPlans(): readonly StoredActiveTestPlanRecord[] {
    const rows = this.database.all(
      `SELECT p.plan_id,p.plan_digest,p.program_ref,p.snapshot_digest,
        p.scope_id,p.asset_identifier_digest,p.test_class,p.plan_json,
        p.created_at,p.expires_at,b.approval_id,q.status AS approval_status,
        a.status AS attempt_status
       FROM active_test_plans p
       JOIN active_test_approval_bindings b ON b.plan_id=p.plan_id
       JOIN approvals q ON q.id=b.approval_id
       LEFT JOIN active_test_attempts a ON a.plan_id=p.plan_id
       ORDER BY p.created_at DESC,p.plan_id DESC LIMIT 101`,
    );
    if (rows.length > 100)
      throw new SecurityError("ACTIVE_TEST_PLAN_READ_LIMIT_EXCEEDED");
    return Object.freeze(rows.map(storedPlanFromRow));
  }

  public listReportSummaries(): readonly StoredActiveTestReportSummary[] {
    const rows = this.database.all(
      `SELECT r.report_id,r.plan_id,r.plan_digest,r.observation_digest,
        r.report_digest,r.report_json,r.review_status,
        r.external_submission_performed,r.created_at,p.plan_json,
        o.observation_json
       FROM active_test_reports r
       JOIN active_test_plans p ON p.plan_id=r.plan_id
       JOIN active_test_observations o
         ON o.authorization_id=r.authorization_id
       ORDER BY r.created_at DESC,r.report_id DESC
       LIMIT 101`,
    );
    if (rows.length > 100)
      throw new SecurityError("ACTIVE_TEST_REPORT_READ_LIMIT_EXCEEDED");
    return Object.freeze(rows.map(storedReportSummaryFromRow));
  }

  private initialize(): void {
    this.database.transaction(() => {
      const marker = this.database.get(
        "SELECT type FROM sqlite_schema WHERE name='active_testing_schema'",
      );
      if (marker === undefined) {
        assertSqliteSchemaNamespaceEmpty(
          (sql) => this.database.all(sql),
          ACTIVE_TEST_SCHEMA_EXPECTATION,
          "ACTIVE_TEST_SCHEMA_MISMATCH",
        );
        for (const statement of ACTIVE_TEST_SCHEMA)
          this.database.run(statement);
        assertExactSqliteSchema(
          (sql) => this.database.all(sql),
          ACTIVE_TEST_SCHEMA_EXPECTATION,
          "ACTIVE_TEST_SCHEMA_MISMATCH",
        );
        this.database.run(
          `INSERT INTO active_testing_schema(component,version,schema_digest)
           VALUES('active_testing_gate',1,?)`,
          ACTIVE_TEST_SCHEMA_DIGEST,
        );
      } else {
        assertExactSqliteSchema(
          (sql) => this.database.all(sql),
          ACTIVE_TEST_SCHEMA_EXPECTATION,
          "ACTIVE_TEST_SCHEMA_MISMATCH",
        );
      }
      const row = this.database.get(
        `SELECT version,schema_digest FROM active_testing_schema
         WHERE component='active_testing_gate'`,
      );
      if (
        row?.["version"] !== 1 ||
        row["schema_digest"] !== ACTIVE_TEST_SCHEMA_DIGEST
      )
        throw new SecurityError("ACTIVE_TEST_SCHEMA_MISMATCH");
      this.validatePersistedEvidence();
    });
  }

  private validatePersistedEvidence(): void {
    const observations = this.database.all(
      `SELECT authorization_id,plan_id,plan_digest,observation_digest,
        observation_json,created_at FROM active_test_observations LIMIT 101`,
    );
    if (observations.length > 100)
      throw new SecurityError("ACTIVE_TEST_OBSERVATION_READ_LIMIT_EXCEEDED");
    for (const row of observations) {
      const observation = validateAndFreezeActiveTestObservation(
        parseJson(row["observation_json"]),
      );
      if (
        row["observation_json"] !== canonicalJson(observation) ||
        row["authorization_id"] === null ||
        row["plan_id"] !== observation.planId ||
        row["plan_digest"] !== observation.planDigest ||
        row["observation_digest"] !==
          activeTestObservationDigest(observation) ||
        row["created_at"] !== observation.completedAt
      )
        throw new SecurityError("ACTIVE_TEST_OBSERVATION_EVIDENCE_INVALID");
    }
    this.listPlans();
    this.listAttempts();
    this.listReportSummaries();
    const orphanedPlans = this.database.get(
      `SELECT count(*) AS count FROM active_test_plans p
       LEFT JOIN active_test_approval_bindings b ON b.plan_id=p.plan_id
       LEFT JOIN approvals q ON q.id=b.approval_id
       WHERE b.plan_id IS NULL OR q.id IS NULL`,
    );
    if (rowCount(orphanedPlans) !== 0)
      throw new SecurityError("ACTIVE_TEST_PERSISTED_EVIDENCE_INVALID");
    const inconsistentAttempts = this.database.get(
      `SELECT count(*) AS count FROM active_test_attempts a
       LEFT JOIN active_test_approval_bindings b
         ON b.approval_id=a.approval_id AND b.plan_id=a.plan_id
       LEFT JOIN approvals q ON q.id=a.approval_id
       LEFT JOIN control_plane_audit reservation
         ON reservation.id=a.reservation_audit_id
       LEFT JOIN control_plane_audit settlement
         ON settlement.id=a.settlement_audit_id
       LEFT JOIN active_test_observations o
         ON o.authorization_id=a.authorization_id
       WHERE b.approval_id IS NULL
          OR q.id IS NULL
          OR reservation.id IS NULL
          OR b.binding_digest<>a.approval_binding_digest
          OR b.plan_digest<>a.plan_digest
          OR b.registry_definition_digest<>a.registry_definition_digest
          OR b.snapshot_digest<>a.snapshot_digest
          OR b.scope_id<>a.scope_id
          OR b.asset_identifier_digest<>a.asset_identifier_digest
          OR b.decision_audit_id IS NULL
          OR q.status<>'accepted' OR q.revision<>1
          OR reservation.action<>'active_test_authorization'
          OR reservation.decision<>'reserved'
          OR reservation.reason_code<>'ACTIVE_TEST_REQUEST_RESERVED'
          OR reservation.object_reference<>a.authorization_id
          OR reservation.payload_hash<>a.proposal_digest
          OR reservation.occurred_at<>a.reserved_at
          OR (o.authorization_id IS NOT NULL AND (
            a.started_at IS NULL OR a.finished_at IS NULL
            OR o.created_at<a.started_at OR o.created_at>a.finished_at
          ))
          OR (a.status IN ('reserved','running') AND settlement.id IS NOT NULL)
          OR (a.status IN ('succeeded','failed','aborted') AND (
            settlement.id IS NULL
            OR settlement.action<>'active_test_settlement'
            OR settlement.decision<>a.status
            OR settlement.reason_code<>'ACTIVE_TEST_'||upper(a.status)
            OR settlement.object_reference<>a.authorization_id
            OR settlement.occurred_at<>a.finished_at
            OR settlement.payload_hash<>CASE
              WHEN a.status='succeeded' THEN COALESCE(o.observation_digest,'')
              ELSE a.proposal_digest END
          ))`,
    );
    if (rowCount(inconsistentAttempts) !== 0)
      throw new SecurityError("ACTIVE_TEST_PERSISTED_EVIDENCE_INVALID");
    const inconsistent = this.database.get(
      `SELECT count(*) AS count FROM active_test_attempts a
       LEFT JOIN active_test_observations o
         ON o.authorization_id=a.authorization_id
       LEFT JOIN active_test_reports r
         ON r.authorization_id=a.authorization_id
       WHERE (a.status='succeeded' AND (o.authorization_id IS NULL OR r.report_id IS NULL))
          OR (a.status<>'succeeded' AND (o.authorization_id IS NOT NULL OR r.report_id IS NOT NULL))`,
    );
    if (rowCount(inconsistent) !== 0)
      throw new SecurityError("ACTIVE_TEST_PERSISTED_EVIDENCE_INVALID");
  }

  private assertRuntimeAndKillSwitch(): void {
    if (
      !this.#runtime.configured ||
      !this.#runtime.enabled ||
      !this.#runtime.externalIntegrationsEnabled
    )
      throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
    if (this.controlPlane.isKillSwitchActive())
      throw new SecurityError("ACTIVE_TEST_KILL_SWITCH");
  }

  private assertPlanCurrent(
    plan: ActiveTestPlanV1,
    planDigest: string,
    now: string,
  ): void {
    if (now >= plan.expires_at)
      throw new SecurityError("ACTIVE_TEST_PLAN_EXPIRED");
    const program = this.#metadata.getProgram(plan.program_ref);
    const stored = this.#metadata.getSnapshot(plan.snapshot_digest);
    const integration = this.#metadata.getIntegrationState();
    const nowMilliseconds = Date.parse(now);
    const snapshotMilliseconds =
      stored === undefined ? Number.NaN : Date.parse(stored.snapshot.fetchedAt);
    const synchronizationMilliseconds =
      integration.lastSynchronizationAt === null
        ? Number.NaN
        : Date.parse(integration.lastSynchronizationAt);
    const activation = this.database.get(
      `SELECT b.activated_generation,b.created_at,q.decided_at
       FROM hackerone_metadata_activation_bindings b
       JOIN approvals q ON q.id=b.approval_id
       WHERE b.activated_generation=? AND b.decision_audit_id IS NOT NULL
         AND q.status='accepted' AND q.revision=1`,
      integration.adapterGeneration,
    );
    const activationMilliseconds =
      typeof activation?.["decided_at"] === "string"
        ? Date.parse(activation["decided_at"])
        : Number.NaN;
    if (
      program === undefined ||
      stored === undefined ||
      program.program.source !== "hackerone_api_authenticated" ||
      stored.snapshot.source !== "hackerone_api_authenticated" ||
      stored.programLocalRef !== plan.program_ref ||
      program.currentSnapshotDigest !== plan.snapshot_digest ||
      !program.catalogActive ||
      program.catalogDriftPending ||
      stored.acceptancePending ||
      stored.snapshot.policyDigest !== plan.policy_digest ||
      stored.snapshot.suitability.automationPermission === "forbidden" ||
      !integration.adapterEnabled ||
      integration.selectedProgramRef !== plan.program_ref ||
      integration.selectedProgramSource !== "hackerone_api_authenticated" ||
      integration.lastSynchronizationResult !== "succeeded" ||
      integration.lastErrorCode !== null ||
      integration.lastSynchronizationAt !== stored.snapshot.fetchedAt ||
      !Number.isFinite(snapshotMilliseconds) ||
      !Number.isFinite(synchronizationMilliseconds) ||
      !Number.isFinite(activationMilliseconds) ||
      snapshotMilliseconds > nowMilliseconds ||
      synchronizationMilliseconds > nowMilliseconds ||
      snapshotMilliseconds <= activationMilliseconds ||
      synchronizationMilliseconds <= activationMilliseconds ||
      nowMilliseconds - snapshotMilliseconds > MAX_API_SNAPSHOT_AGE_MS ||
      nowMilliseconds - synchronizationMilliseconds > MAX_API_SNAPSHOT_AGE_MS
    )
      throw new SecurityError("ACTIVE_TEST_SNAPSHOT_NOT_CURRENT_ACCEPTED");
    const expected = createActiveTestPlan({
      planId: plan.plan_id,
      programRef: plan.program_ref,
      snapshot: stored.snapshot,
      scopeId: plan.scope_id,
      assetIdentifierDigest: plan.asset_identifier_digest,
      testClass: plan.test_class,
      createdAt: plan.created_at,
      confirmations: {
        automationPermissionReviewed: true,
        scopeInstructionReviewed: true,
        scopeExclusionsReviewed: true,
        noSideEffectsConfirmed: true,
      },
    });
    if (activeTestPlanDigest(expected) !== planDigest)
      throw new SecurityError("ACTIVE_TEST_PLAN_SNAPSHOT_BINDING_INVALID");
  }

  private requireApprovedPlan(
    planId: string,
    approvalId: string,
    now: string,
  ): {
    readonly plan: ActiveTestPlanV1;
    readonly planDigest: string;
    readonly bindingDigest: string;
    readonly registryDefinitionDigest: string;
  } {
    const row = this.database.get(
      `SELECT p.plan_json,p.plan_digest,b.* FROM active_test_plans p
       JOIN active_test_approval_bindings b ON b.plan_id=p.plan_id
       WHERE p.plan_id=? AND b.approval_id=?`,
      planId,
      approvalId,
    );
    if (row === undefined)
      throw new SecurityError("ACTIVE_TEST_APPROVAL_BINDING_REQUIRED");
    const plan = validateAndFreezeActiveTestPlan(parseJson(row["plan_json"]));
    const planDigest = activeTestPlanDigest(plan);
    const bindingDigest = requiredDigest(row["binding_digest"]);
    const registryDefinitionDigest =
      assertHackerOneActiveTestRegistryPlanBinding(
        plan.test_class,
        plan.request.method,
        plan.target.scheme,
        plan.target.port,
      );
    const approval = this.controlPlane
      .listApprovals()
      .find((candidate) => candidate.id === approvalId);
    if (
      approval?.kind !== "external_action" ||
      approval.status !== "accepted" ||
      approval.decidedAt === null ||
      now < approval.decidedAt ||
      approval.payloadHash !== row["approval_payload_hash"] ||
      approval.policyHash !== plan.policy_digest ||
      approval.decidedBy !== row["operator_id"] ||
      row["decision_audit_id"] === null ||
      row["plan_digest"] !== planDigest ||
      row["runtime_digest"] !== activeTestingRuntimeDigest(this.#runtime) ||
      row["catalog_digest"] !== activeTestCatalogDigest() ||
      row["registry_definition_digest"] !== registryDefinitionDigest ||
      typeof row["expires_at"] !== "string" ||
      now >= row["expires_at"]
    )
      throw new SecurityError("ACTIVE_TEST_APPROVAL_EVIDENCE_INVALID");
    const expectedBinding = sha256(
      canonicalJson(
        bindingMaterial({
          approvalId,
          approvalPayloadHash: approval.payloadHash,
          operatorId: requiredOperator(row["operator_id"]),
          plan,
          planDigest,
          runtimeDigest: requiredDigest(row["runtime_digest"]),
          catalogDigest: requiredDigest(row["catalog_digest"]),
          registryDefinitionDigest: requiredDigest(
            row["registry_definition_digest"],
          ),
          createdAt: requiredTimestamp(row["created_at"]),
          expiresAt: requiredTimestamp(row["expires_at"]),
        }),
      ),
    );
    if (expectedBinding !== bindingDigest)
      throw new SecurityError("ACTIVE_TEST_APPROVAL_EVIDENCE_INVALID");
    this.controlPlane.requireAuthenticatedApprovalDecision(
      approval,
      bindingDigest,
    );
    this.assertPlanCurrent(plan, planDigest, now);
    return Object.freeze({
      plan,
      planDigest,
      bindingDigest,
      registryDefinitionDigest,
    });
  }

  private assertAndCountBudget(now: string): number {
    const total = rowCount(
      this.database.get("SELECT count(*) AS count FROM active_test_attempts"),
    );
    const active = rowCount(
      this.database.get(
        "SELECT count(*) AS count FROM active_test_attempts WHERE status IN ('reserved','running')",
      ),
    );
    const threshold = new Date(Date.parse(now) - 60_000).toISOString();
    const minute = rowCount(
      this.database.get(
        "SELECT count(*) AS count FROM active_test_attempts WHERE reserved_at>=?",
        threshold,
      ),
    );
    if (
      total >= this.#runtime.requestBudget.maxRequestsTotal ||
      active >= this.#runtime.requestBudget.maxConcurrency ||
      minute >= this.#runtime.requestBudget.requestsPerMinute
    )
      throw new SecurityError("ACTIVE_TEST_REQUEST_BUDGET_EXCEEDED");
    return total + 1;
  }

  private assertClockMonotonic(now: string): void {
    const maximum = this.database.get(
      "SELECT max(reserved_at) AS maximum FROM active_test_attempts",
    )?.["maximum"];
    if (maximum !== null && maximum !== undefined) {
      if (typeof maximum !== "string" || maximum > now)
        throw new SecurityError("ACTIVE_TEST_RATE_CLOCK_ROLLBACK");
    }
  }

  private assertAuthorizationCurrent(
    authorization: StoreBoundActiveTestAuthorization,
    status: "reserved" | "running",
    revision: 0 | 1,
  ): { readonly startedAt: string } {
    const row = this.database.get(
      "SELECT * FROM active_test_attempts WHERE authorization_id=?",
      authorization.authorizationId,
    );
    if (
      row?.["status"] !== status ||
      row["revision"] !== revision ||
      row["proposal_id"] !== authorization.proposalId ||
      row["proposal_digest"] !== authorization.proposalDigest ||
      row["approval_id"] !== authorization.approvalId ||
      row["approval_binding_digest"] !== authorization.approvalBindingDigest ||
      row["plan_id"] !== authorization.planId ||
      row["plan_digest"] !== authorization.planDigest ||
      row["registry_definition_digest"] !==
        authorization.registryDefinitionDigest ||
      row["reserved_at"] !== authorization.reservedAt ||
      row["reservation_audit_id"] !== authorization.reservationAuditId ||
      row["attempt_index"] !== authorization.attemptIndex
    )
      throw new SecurityError("ACTIVE_TEST_AUTHORIZATION_EVIDENCE_INVALID");
    return Object.freeze({
      startedAt:
        row["started_at"] === null
          ? authorization.reservedAt
          : requiredTimestamp(row["started_at"]),
    });
  }

  private observeTime(floor?: string): string {
    const observed = this.controlPlane.observeExternalActionTime();
    if (floor !== undefined && observed < floor)
      throw new SecurityError("ACTIVE_TEST_CLOCK_ROLLBACK");
    return observed;
  }

  private settleRow(
    authorization: StoreBoundActiveTestAuthorization,
    outcome: "aborted" | "failed" | "succeeded",
    at: string,
    started: boolean,
    evidenceDigest: string = authorization.proposalDigest,
  ): void {
    const settlementAuditId = `atsettle-${sha256(`${authorization.authorizationId}\u0000${outcome}\u0000${at}`).slice(0, 40)}`;
    this.database.run(
      `INSERT INTO control_plane_audit(
        id,occurred_at,action,decision,reason_code,object_reference,payload_hash
      ) VALUES(?,?,?,?,?,?,?)`,
      settlementAuditId,
      at,
      "active_test_settlement",
      outcome,
      `ACTIVE_TEST_${outcome.toUpperCase()}`,
      authorization.authorizationId,
      evidenceDigest,
    );
    const updated = this.database.run(
      `UPDATE active_test_attempts
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
    if (updated.changes !== 1)
      throw new SecurityError("ACTIVE_TEST_STATE_INVALID");
  }
}

export function isTrustedActiveTestingActionGate(
  value: unknown,
): value is ActiveTestingActionGate {
  if (value === null || typeof value !== "object") return false;
  try {
    return (
      !types.isProxy(value) &&
      Reflect.getPrototypeOf(value) === ActiveTestingActionGate.prototype &&
      trustedGates.has(value)
    );
  } catch {
    return false;
  }
}

export function isActiveTestingActionGateBoundToRuntime(
  gate: unknown,
  runtime: unknown,
): boolean {
  return (
    isTrustedActiveTestingActionGate(gate) &&
    isTrustedActiveTestingRuntime(runtime) &&
    trustedGateRuntimes.get(gate) === runtime
  );
}

export function captureAuthorizedActiveTestTransportPlan(
  value: unknown,
): AuthorizedActiveTestTransportPlan {
  if (value === null || typeof value !== "object")
    throw new SecurityError("ACTIVE_TEST_TRANSPORT_AUTHORIZATION_REQUIRED");
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
      ...plan,
      target: Object.freeze({ ...plan.target }),
      request: Object.freeze({ ...plan.request }),
    });
  } catch {
    throw new SecurityError("ACTIVE_TEST_TRANSPORT_AUTHORIZATION_REQUIRED");
  }
}

function captureApprovalInput(value: unknown): ActiveTestApprovalInput {
  const row = exactRecord(value, [
    "approvalId",
    "operatorId",
    "plan",
    "createdAt",
  ]);
  return Object.freeze({
    approvalId: requiredIdentifier(row["approvalId"]),
    operatorId: requiredOperator(row["operatorId"]),
    plan: validateAndFreezeActiveTestPlan(row["plan"]),
    createdAt: requiredTimestamp(row["createdAt"]),
  });
}

function captureReservationInput(value: unknown): ActiveTestReservationInput {
  const row = exactRecord(value, [
    "proposalId",
    "approvalId",
    "planId",
    "confirmed",
  ]);
  if (row["confirmed"] !== true)
    throw new SecurityError("ACTIVE_TEST_START_CONFIRMATION_REQUIRED");
  return Object.freeze({
    proposalId: requiredIdentifier(row["proposalId"]),
    approvalId: requiredIdentifier(row["approvalId"]),
    planId: requiredIdentifier(row["planId"]),
    confirmed: true,
  });
}

function captureFailureOutcome(value: unknown): "aborted" | "failed" {
  if (value !== "aborted" && value !== "failed")
    throw new SecurityError("ACTIVE_TEST_OUTCOME_INVALID");
  return value;
}

function requireAuthorization(
  value: unknown,
): StoreBoundActiveTestAuthorization {
  if (value === null || typeof value !== "object")
    throw new SecurityError("ACTIVE_TEST_AUTHORIZATION_REQUIRED");
  try {
    if (
      types.isProxy(value) ||
      Reflect.getPrototypeOf(value) !== Object.prototype
    )
      throw new Error("invalid");
    const authorization = trustedAuthorizations.get(value);
    if (authorization !== value) throw new Error("invalid");
    return authorization;
  } catch {
    throw new SecurityError("ACTIVE_TEST_AUTHORIZATION_REQUIRED");
  }
}

function bindingMaterial(input: {
  readonly approvalId: string;
  readonly approvalPayloadHash: string;
  readonly operatorId: string;
  readonly plan: ActiveTestPlanV1;
  readonly planDigest: string;
  readonly runtimeDigest: string;
  readonly catalogDigest: string;
  readonly registryDefinitionDigest: string;
  readonly createdAt: string;
  readonly expiresAt: string;
}): object {
  return Object.freeze({
    version: 1,
    actionClass: "HACKERONE_ACTIVE_TEST",
    approvalId: input.approvalId,
    approvalPayloadHash: input.approvalPayloadHash,
    operatorId: input.operatorId,
    planId: input.plan.plan_id,
    planDigest: input.planDigest,
    programRef: input.plan.program_ref,
    snapshotDigest: input.plan.snapshot_digest,
    policyDigest: input.plan.policy_digest,
    scopeId: input.plan.scope_id,
    assetIdentifierDigest: input.plan.asset_identifier_digest,
    testClass: input.plan.test_class,
    runnerVersion: input.plan.runner_version,
    runtimeDigest: input.runtimeDigest,
    catalogDigest: input.catalogDigest,
    registryDefinitionDigest: input.registryDefinitionDigest,
    createdAt: input.createdAt,
    expiresAt: input.expiresAt,
  });
}

export function activeTestingRuntimeDigest(
  runtime: ActiveTestingRuntimeState,
): string {
  if (!isTrustedActiveTestingRuntime(runtime))
    throw new SecurityError("ACTIVE_TEST_RUNTIME_UNTRUSTED");
  return sha256(
    canonicalJson({
      version: runtime.version,
      capability: runtime.capability,
      externalIntegrationsEnabled: runtime.externalIntegrationsEnabled,
      enabled: runtime.enabled,
      configured: runtime.configured,
      requestBudget: runtime.requestBudget,
      requestTimeoutMs: runtime.requestTimeoutMs,
      maxResponseBytes: runtime.maxResponseBytes,
      runnerVersion: runtime.runnerVersion,
    }),
  );
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype
  )
    throw new SecurityError("ACTIVE_TEST_INPUT_INVALID");
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== "string") ||
    !keys.every((key) => ownKeys.includes(key))
  )
    throw new SecurityError("ACTIVE_TEST_INPUT_INVALID");
  const result: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    )
      throw new SecurityError("ACTIVE_TEST_INPUT_INVALID");
    result[key] = descriptor.value;
  }
  return result;
}

function requiredIdentifier(value: unknown): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value))
    throw new SecurityError("ACTIVE_TEST_IDENTIFIER_INVALID");
  return value;
}

function requiredOperator(value: unknown): string {
  if (typeof value !== "string" || !OPERATOR.test(value))
    throw new SecurityError("ACTIVE_TEST_OPERATOR_INVALID");
  return value;
}

function requiredDigest(value: unknown): string {
  if (typeof value !== "string" || !DIGEST.test(value))
    throw new SecurityError("ACTIVE_TEST_DIGEST_INVALID");
  return value;
}

function requiredTimestamp(value: unknown): string {
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(Date.parse(value)).toISOString() !== value
  )
    throw new SecurityError("ACTIVE_TEST_TIME_INVALID");
  return value;
}

function earliestTimestamp(left: string, right: string): string {
  return left <= right ? left : right;
}

function parseJson(value: unknown): unknown {
  if (typeof value !== "string")
    throw new SecurityError("ACTIVE_TEST_PLAN_PERSISTENCE_INVALID");
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new SecurityError("ACTIVE_TEST_PLAN_PERSISTENCE_INVALID");
  }
}

function rowCount(row: Readonly<Record<string, unknown>> | undefined): number {
  const value = row?.["count"];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    throw new SecurityError("ACTIVE_TEST_BUDGET_EVIDENCE_INVALID");
  return value;
}

function attemptFromRow(
  row: Readonly<Record<string, unknown>>,
): ActiveTestAttemptRecord {
  const status = row["status"];
  const testClass = row["test_class"];
  const method = row["method"];
  if (
    !(
      status === "aborted" ||
      status === "failed" ||
      status === "reserved" ||
      status === "running" ||
      status === "succeeded"
    ) ||
    !(
      testClass === "cors_preflight" ||
      testClass === "http_headers" ||
      testClass === "security_txt"
    ) ||
    !(method === "GET" || method === "HEAD" || method === "OPTIONS")
  )
    throw new SecurityError("ACTIVE_TEST_ATTEMPT_EVIDENCE_INVALID");
  return Object.freeze({
    authorizationId: requiredIdentifier(row["authorization_id"]),
    proposalId: requiredIdentifier(row["proposal_id"]),
    approvalId: requiredIdentifier(row["approval_id"]),
    planId: requiredIdentifier(row["plan_id"]),
    testClass,
    method,
    status,
    reservedAt: requiredTimestamp(row["reserved_at"]),
    startedAt:
      row["started_at"] === null ? null : requiredTimestamp(row["started_at"]),
    finishedAt:
      row["finished_at"] === null
        ? null
        : requiredTimestamp(row["finished_at"]),
    revision: numberValue(row["revision"]),
  });
}

function storedPlanFromRow(
  row: Readonly<Record<string, unknown>>,
): StoredActiveTestPlanRecord {
  const plan = validateAndFreezeActiveTestPlan(parseJson(row["plan_json"]));
  const digest = activeTestPlanDigest(plan);
  const approvalStatus = row["approval_status"];
  const attemptStatus = row["attempt_status"];
  if (
    !(
      approvalStatus === "accepted" ||
      approvalStatus === "open" ||
      approvalStatus === "rejected"
    ) ||
    !(
      attemptStatus === null ||
      attemptStatus === "aborted" ||
      attemptStatus === "failed" ||
      attemptStatus === "reserved" ||
      attemptStatus === "running" ||
      attemptStatus === "succeeded"
    ) ||
    row["plan_json"] !== canonicalJson(plan) ||
    row["plan_id"] !== plan.plan_id ||
    row["plan_digest"] !== digest ||
    row["program_ref"] !== plan.program_ref ||
    row["snapshot_digest"] !== plan.snapshot_digest ||
    row["scope_id"] !== plan.scope_id ||
    row["asset_identifier_digest"] !== plan.asset_identifier_digest ||
    row["test_class"] !== plan.test_class ||
    row["created_at"] !== plan.created_at ||
    row["expires_at"] !== plan.expires_at
  )
    throw new SecurityError("ACTIVE_TEST_PLAN_EVIDENCE_INVALID");
  return Object.freeze({
    approvalId: requiredIdentifier(row["approval_id"]),
    approvalStatus,
    planId: plan.plan_id,
    planDigest: digest,
    programRef: plan.program_ref,
    snapshotDigest: plan.snapshot_digest,
    scopeId: plan.scope_id,
    assetIdentifierDigest: plan.asset_identifier_digest,
    testClass: plan.test_class,
    attemptStatus,
    createdAt: plan.created_at,
    expiresAt: plan.expires_at,
  });
}

function storedReportSummaryFromRow(
  row: Readonly<Record<string, unknown>>,
): StoredActiveTestReportSummary {
  const plan = validateAndFreezeActiveTestPlan(parseJson(row["plan_json"]));
  const observation = validateAndFreezeActiveTestObservation(
    parseJson(row["observation_json"]),
  );
  const expected = reconstructLocalActiveTestReportDraft(plan, observation);
  const report = exactRecord(parseJson(row["report_json"]), [
    "assetIdentifierDigest",
    "createdAt",
    "externalSubmissionPerformed",
    "json",
    "jsonDigest",
    "markdown",
    "markdownDigest",
    "observationDigest",
    "planDigest",
    "planId",
    "policyDigest",
    "reportId",
    "resolutionDigest",
    "responseMetadataDigest",
    "reviewStatus",
    "snapshotDigest",
    "transportKind",
    "version",
  ]);
  const reportId = requiredIdentifier(report["reportId"]);
  const planId = requiredIdentifier(report["planId"]);
  const planDigest = requiredDigest(report["planDigest"]);
  const observationDigest = requiredDigest(report["observationDigest"]);
  const markdownDigest = requiredDigest(report["markdownDigest"]);
  const jsonDigest = requiredDigest(report["jsonDigest"]);
  const createdAt = requiredTimestamp(report["createdAt"]);
  const resolutionDigest = requiredDigest(report["resolutionDigest"]);
  const transportKind = report["transportKind"];
  const markdown = report["markdown"];
  const json = report["json"];
  if (
    row["plan_json"] !== canonicalJson(plan) ||
    row["observation_json"] !== canonicalJson(observation) ||
    row["report_json"] !== canonicalJson(report) ||
    report["version"] !== 1 ||
    report["reviewStatus"] !== "local_draft_unsubmitted" ||
    report["externalSubmissionPerformed"] !== false ||
    !(
      transportKind === "production_https" || transportKind === "loopback_test"
    ) ||
    resolutionDigest.length !== 64 ||
    typeof markdown !== "string" ||
    Buffer.byteLength(markdown, "utf8") > 65_536 ||
    typeof json !== "string" ||
    Buffer.byteLength(json, "utf8") > 65_536 ||
    sha256(markdown) !== markdownDigest ||
    sha256(json) !== jsonDigest ||
    canonicalJson(report) !== canonicalJson(expected) ||
    row["report_id"] !== reportId ||
    row["plan_id"] !== planId ||
    row["plan_digest"] !== planDigest ||
    row["observation_digest"] !== observationDigest ||
    row["report_digest"] !== sha256(canonicalJson(report)) ||
    row["review_status"] !== "local_draft_unsubmitted" ||
    row["external_submission_performed"] !== 0 ||
    row["created_at"] !== createdAt
  )
    throw new SecurityError("ACTIVE_TEST_REPORT_EVIDENCE_INVALID");
  return Object.freeze({
    reportId,
    planId,
    planDigest,
    observationDigest,
    markdownDigest,
    jsonDigest,
    transportKind,
    resolutionDigest,
    reviewStatus: "local_draft_unsubmitted" as const,
    externalSubmissionPerformed: false as const,
    createdAt,
  });
}

function numberValue(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    throw new SecurityError("ACTIVE_TEST_NUMBER_INVALID");
  return value;
}
