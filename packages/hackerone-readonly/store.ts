import { types } from "node:util";
import {
  isTrustedControlPlaneDatabase,
  type ControlPlaneDatabase,
} from "../control-plane/database.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import {
  assertExactSqliteSchema,
  assertSqliteSchemaNamespaceEmpty,
  buildSqliteSchemaExpectation,
} from "../shared/sqlite-schema.js";
import {
  createHackerOnePolicySnapshot,
  detectHackerOnePolicyDrift,
} from "./snapshot.js";
import type {
  HackerOneConnectionResult,
  HackerOneDataSource,
  HackerOnePolicySnapshot,
  HackerOneProgram,
  HackerOneProgramSuitability,
  HackerOneRequestAuditEvent,
  HackerOneScopeExclusion,
  HackerOneStructuredScope,
  HackerOneSuitabilityReason,
} from "./types.js";
import {
  HACKERONE_ADAPTER_VERSION,
  HACKERONE_SCHEMA_VERSION,
} from "./types.js";

export interface HackerOnePersistedIntegrationState {
  readonly adapterEnabled: boolean;
  readonly adapterGeneration: number;
  readonly lastConnectionTestAt: string | null;
  readonly lastSuccessfulConnectionAt: string | null;
  readonly lastConnectionResult: HackerOneConnectionResult | null;
  readonly lastSynchronizationAt: string | null;
  readonly lastSynchronizationResult: "failed" | "succeeded" | null;
  readonly lastErrorCode: string | null;
  readonly selectedProgramRef: string | null;
  readonly selectedProgramSource: HackerOneDataSource | null;
  readonly revision: number;
}

export interface StoredHackerOneProgram {
  readonly localRef: string;
  readonly program: HackerOneProgram;
  readonly catalogActive: boolean;
  readonly catalogDriftPending: boolean;
  readonly recordDigest: string;
  readonly currentSnapshotDigest: string | null;
}

export interface StoredHackerOnePolicySnapshot {
  readonly programLocalRef: string;
  readonly snapshot: HackerOnePolicySnapshot;
  readonly acceptancePending: boolean;
}

export interface HackerOneConnectionStateUpdate {
  readonly expectedRevision: number;
  readonly occurredAt: string;
  readonly result: HackerOneConnectionResult;
  readonly errorCode: string | null;
}

export interface HackerOneSynchronizationStateUpdate {
  readonly expectedRevision: number;
  readonly occurredAt: string;
  readonly result: "failed" | "succeeded";
  readonly errorCode: string | null;
}

export interface StoredHackerOneRequestAuditEvent extends HackerOneRequestAuditEvent {
  readonly sequence: number;
}

export interface HackerOneSnapshotCommitResult {
  readonly stored: StoredHackerOnePolicySnapshot;
  readonly campaignsPaused: boolean;
}

const API_SOURCE = "hackerone_api_authenticated";
const MANUAL_SOURCE = "manual_unverified";
const MAX_PROGRAMS_PER_CATALOG = 10_000;
const MAX_SNAPSHOTS_PER_READ = 10_000;
const MAX_SNAPSHOT_JSON_BYTES = 4 * 1024 * 1024;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const API_LOCAL_REF_PATTERN = /^h1a_[0-9a-f]{64}$/u;
const MANUAL_LOCAL_REF_PATTERN = /^h1m_[0-9a-f]{64}$/u;
const ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{2,127}$/u;
const HANDLE_PATTERN = /^[A-Za-z0-9_-]{1,128}$/u;

const CONNECTION_RESULTS = Object.freeze([
  "blocked_by_kill_switch",
  "blocked_by_policy",
  "connected",
  "invalid_credentials",
  "malformed_response",
  "rate_limited",
  "secret_store_unavailable",
  "unauthorized",
  "unavailable",
] as const satisfies readonly HackerOneConnectionResult[]);

const SUITABILITY_REASONS = Object.freeze([
  "BOUNTIES_AVAILABLE",
  "BOUNTIES_UNAVAILABLE",
  "OPEN_SUBMISSIONS",
  "POLICY_MISSING",
  "POLICY_PRESENT",
  "SAFE_HARBOR_PRESENT",
  "SCOPE_EXCLUSIONS_PRESENT",
  "STRUCTURED_SCOPE_CLEAR",
  "STRUCTURED_SCOPE_MISSING",
  "WEB_OR_API_ASSET_PRESENT",
] as const satisfies readonly HackerOneSuitabilityReason[]);

const PROGRAM_KEYS = Object.freeze([
  "bookmarked",
  "createdAt",
  "currency",
  "goldStandardSafeHarbor",
  "hackerOneId",
  "handle",
  "name",
  "offersBounties",
  "openScope",
  "ownReportCount",
  "ownValidReportCount",
  "policy",
  "programState",
  "source",
  "startedAcceptingAt",
  "submissionState",
  "synchronizedAt",
  "updatedAt",
] as const satisfies readonly (keyof HackerOneProgram)[]);

const SCOPE_KEYS = Object.freeze([
  "assetIdentifier",
  "assetIdentifierDigest",
  "assetType",
  "availabilityRequirement",
  "confidentialityRequirement",
  "createdAt",
  "eligibleForBounty",
  "eligibleForSubmission",
  "id",
  "instruction",
  "integrityRequirement",
  "maximumSeverity",
  "updatedAt",
] as const satisfies readonly (keyof HackerOneStructuredScope)[]);

const EXCLUSION_KEYS = Object.freeze([
  "category",
  "createdAt",
  "details",
  "id",
  "updatedAt",
] as const satisfies readonly (keyof HackerOneScopeExclusion)[]);

const SUITABILITY_KEYS = Object.freeze([
  "accountWorkflows",
  "automationPermission",
  "legalDecisionMade",
  "reasons",
  "score",
] as const satisfies readonly (keyof HackerOneProgramSuitability)[]);

const SNAPSHOT_KEYS = Object.freeze([
  "adapterVersion",
  "fetchedAt",
  "policyDigest",
  "previousSnapshotDigest",
  "program",
  "schemaVersion",
  "scopeExclusions",
  "snapshotDigest",
  "source",
  "structuredScopes",
  "suitability",
] as const satisfies readonly (keyof HackerOnePolicySnapshot)[]);

const PROGRAM_TABLE_COLUMNS = `
  local_ref TEXT PRIMARY KEY,
  hackerone_id TEXT NOT NULL,
  handle TEXT NOT NULL,
  name TEXT NOT NULL,
  currency TEXT NOT NULL,
  policy TEXT NOT NULL,
  submission_state TEXT NOT NULL,
  program_state TEXT NOT NULL,
  offers_bounties INTEGER NOT NULL CHECK(offers_bounties IN (0,1)),
  open_scope INTEGER NOT NULL CHECK(open_scope IN (0,1)),
  gold_standard_safe_harbor INTEGER NOT NULL CHECK(gold_standard_safe_harbor IN (0,1)),
  bookmarked INTEGER NOT NULL CHECK(bookmarked IN (0,1)),
  own_report_count INTEGER NOT NULL CHECK(own_report_count >= 0),
  own_valid_report_count INTEGER NOT NULL CHECK(own_valid_report_count >= 0),
  started_accepting_at TEXT,
  created_at TEXT,
  updated_at TEXT,
  synchronized_at TEXT NOT NULL,
  catalog_active INTEGER NOT NULL CHECK(catalog_active IN (0,1)),
  catalog_drift_pending INTEGER NOT NULL CHECK(catalog_drift_pending IN (0,1)),
  record_digest TEXT NOT NULL CHECK(length(record_digest)=64),
  current_snapshot_digest TEXT CHECK(current_snapshot_digest IS NULL OR length(current_snapshot_digest)=64),
  UNIQUE(hackerone_id),
  UNIQUE(handle)
`;

const SCHEMA_STATEMENTS = Object.freeze([
  `CREATE TABLE IF NOT EXISTS hackerone_readonly_schema (
    component TEXT PRIMARY KEY CHECK(component='metadata_store'),
    version INTEGER NOT NULL CHECK(version=1),
    schema_digest TEXT NOT NULL CHECK(length(schema_digest)=64)
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS hackerone_api_programs (${PROGRAM_TABLE_COLUMNS}) STRICT`,
  `CREATE TABLE IF NOT EXISTS hackerone_manual_programs (${PROGRAM_TABLE_COLUMNS}) STRICT`,
  `CREATE TABLE IF NOT EXISTS hackerone_policy_snapshots (
    snapshot_digest TEXT PRIMARY KEY CHECK(length(snapshot_digest)=64),
    program_local_ref TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('hackerone_api_authenticated','manual_unverified')),
    policy_digest TEXT NOT NULL CHECK(length(policy_digest)=64),
    previous_snapshot_digest TEXT REFERENCES hackerone_policy_snapshots(snapshot_digest) ON DELETE RESTRICT,
    fetched_at TEXT NOT NULL,
    snapshot_json TEXT NOT NULL CHECK(json_valid(snapshot_json) AND length(snapshot_json) <= ${String(MAX_SNAPSHOT_JSON_BYTES)}),
    acceptance_pending INTEGER NOT NULL CHECK(acceptance_pending IN (0,1))
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS hackerone_integration_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    adapter_enabled INTEGER NOT NULL CHECK(adapter_enabled IN (0,1)),
    adapter_generation INTEGER NOT NULL CHECK(adapter_generation>=0),
    last_connection_test_at TEXT,
    last_successful_connection_at TEXT,
    last_connection_result TEXT CHECK(last_connection_result IS NULL OR last_connection_result IN (
      'blocked_by_kill_switch','blocked_by_policy','connected','invalid_credentials',
      'malformed_response','rate_limited','secret_store_unavailable','unauthorized','unavailable'
    )),
    last_synchronization_at TEXT,
    last_synchronization_result TEXT CHECK(last_synchronization_result IS NULL OR last_synchronization_result IN ('failed','succeeded')),
    last_error_code TEXT,
    selected_program_ref TEXT,
    selected_program_source TEXT CHECK(selected_program_source IS NULL OR selected_program_source IN ('hackerone_api_authenticated','manual_unverified')),
    revision INTEGER NOT NULL CHECK(revision >= 0),
    CHECK((selected_program_ref IS NULL)=(selected_program_source IS NULL))
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS hackerone_request_audit (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL CHECK(length(request_id)=32 AND request_id NOT GLOB '*[^0-9a-f]*'),
    action_class TEXT NOT NULL CHECK(action_class='HACKERONE_METADATA_READ'),
    endpoint_class TEXT NOT NULL CHECK(endpoint_class IN ('program','programs','scope_exclusions','structured_scopes')),
    outcome TEXT NOT NULL CHECK(length(outcome) BETWEEN 1 AND 128 AND outcome NOT GLOB '*[^A-Za-z0-9_]*'),
    status_code INTEGER CHECK(status_code IS NULL OR status_code BETWEEN 100 AND 599),
    duration_ms INTEGER NOT NULL CHECK(duration_ms >= 0 AND duration_ms <= 3600000)
  ) STRICT`,
  `CREATE TABLE IF NOT EXISTS hackerone_campaign_bindings (
    program_local_ref TEXT NOT NULL,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE RESTRICT,
    bound_at TEXT NOT NULL,
    PRIMARY KEY(program_local_ref,campaign_id)
  ) STRICT`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_campaign_binding_program_required
    BEFORE INSERT ON hackerone_campaign_bindings
    WHEN NOT EXISTS(
      SELECT 1 FROM hackerone_api_programs WHERE local_ref=NEW.program_local_ref
    ) AND NOT EXISTS(
      SELECT 1 FROM hackerone_manual_programs WHERE local_ref=NEW.program_local_ref
    )
    BEGIN SELECT RAISE(ABORT,'HACKERONE_CAMPAIGN_BINDING_PROGRAM_UNKNOWN'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_campaign_bindings_no_update
    BEFORE UPDATE ON hackerone_campaign_bindings
    BEGIN SELECT RAISE(ABORT,'HACKERONE_CAMPAIGN_BINDING_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_campaign_bindings_no_delete
    BEFORE DELETE ON hackerone_campaign_bindings
    BEGIN SELECT RAISE(ABORT,'HACKERONE_CAMPAIGN_BINDING_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_request_audit_no_update
    BEFORE UPDATE ON hackerone_request_audit
    BEGIN SELECT RAISE(ABORT,'HACKERONE_REQUEST_AUDIT_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_request_audit_no_delete
    BEFORE DELETE ON hackerone_request_audit
    BEGIN SELECT RAISE(ABORT,'HACKERONE_REQUEST_AUDIT_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_snapshots_no_update
    BEFORE UPDATE ON hackerone_policy_snapshots
    BEGIN SELECT RAISE(ABORT,'HACKERONE_SNAPSHOT_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_snapshots_pending_on_insert
    BEFORE INSERT ON hackerone_policy_snapshots
    WHEN NEW.acceptance_pending<>1
    BEGIN SELECT RAISE(ABORT,'HACKERONE_SNAPSHOT_ACCEPTANCE_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_snapshots_no_delete
    BEFORE DELETE ON hackerone_policy_snapshots
    BEGIN SELECT RAISE(ABORT,'HACKERONE_SNAPSHOT_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_snapshot_program_required
    BEFORE INSERT ON hackerone_policy_snapshots
    WHEN (
      NEW.source='hackerone_api_authenticated' AND
      NOT EXISTS(SELECT 1 FROM hackerone_api_programs WHERE local_ref=NEW.program_local_ref)
    ) OR (
      NEW.source='manual_unverified' AND
      NOT EXISTS(SELECT 1 FROM hackerone_manual_programs WHERE local_ref=NEW.program_local_ref)
    )
    BEGIN SELECT RAISE(ABORT,'HACKERONE_SNAPSHOT_PROGRAM_UNKNOWN'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_api_identity_immutable
    BEFORE UPDATE OF local_ref,hackerone_id ON hackerone_api_programs
    WHEN NEW.local_ref<>OLD.local_ref OR NEW.hackerone_id<>OLD.hackerone_id
    BEGIN SELECT RAISE(ABORT,'HACKERONE_PROGRAM_IDENTITY_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_manual_identity_immutable
    BEFORE UPDATE OF local_ref,hackerone_id,handle ON hackerone_manual_programs
    WHEN NEW.local_ref<>OLD.local_ref OR NEW.hackerone_id<>OLD.hackerone_id OR NEW.handle<>OLD.handle
    BEGIN SELECT RAISE(ABORT,'HACKERONE_PROGRAM_IDENTITY_IMMUTABLE'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_api_snapshot_pointer_valid
    BEFORE UPDATE OF current_snapshot_digest ON hackerone_api_programs
    WHEN NEW.current_snapshot_digest IS NOT NULL AND NOT EXISTS(
      SELECT 1 FROM hackerone_policy_snapshots
      WHERE snapshot_digest=NEW.current_snapshot_digest
        AND program_local_ref=NEW.local_ref
        AND source='hackerone_api_authenticated'
    )
    BEGIN SELECT RAISE(ABORT,'HACKERONE_SNAPSHOT_POINTER_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_manual_snapshot_pointer_valid
    BEFORE UPDATE OF current_snapshot_digest ON hackerone_manual_programs
    WHEN NEW.current_snapshot_digest IS NOT NULL AND NOT EXISTS(
      SELECT 1 FROM hackerone_policy_snapshots
      WHERE snapshot_digest=NEW.current_snapshot_digest
        AND program_local_ref=NEW.local_ref
        AND source='manual_unverified'
    )
    BEGIN SELECT RAISE(ABORT,'HACKERONE_SNAPSHOT_POINTER_INVALID'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_api_snapshots_prevent_delete
    BEFORE DELETE ON hackerone_api_programs
    WHEN EXISTS(SELECT 1 FROM hackerone_policy_snapshots WHERE program_local_ref=OLD.local_ref)
    BEGIN SELECT RAISE(ABORT,'HACKERONE_PROGRAM_HAS_SNAPSHOTS'); END`,
  `CREATE TRIGGER IF NOT EXISTS hackerone_manual_snapshots_prevent_delete
    BEFORE DELETE ON hackerone_manual_programs
    WHEN EXISTS(SELECT 1 FROM hackerone_policy_snapshots WHERE program_local_ref=OLD.local_ref)
    BEGIN SELECT RAISE(ABORT,'HACKERONE_PROGRAM_HAS_SNAPSHOTS'); END`,
]);

const STORE_SCHEMA_EXPECTATION = buildSqliteSchemaExpectation({
  statements: SCHEMA_STATEMENTS,
});
const STORE_SCHEMA_DIGEST = STORE_SCHEMA_EXPECTATION.digest;

export class HackerOneMetadataStore {
  public constructor(private readonly database: ControlPlaneDatabase) {
    if (!isTrustedControlPlaneDatabase(database))
      throw new SecurityError("HACKERONE_STORE_DATABASE_UNTRUSTED");
    this.initialize();
    Object.freeze(this);
  }

  public getIntegrationState(): HackerOnePersistedIntegrationState {
    const row = this.database.get(
      "SELECT * FROM hackerone_integration_state WHERE singleton=1",
    );
    if (row === undefined)
      throw new SecurityError("HACKERONE_INTEGRATION_STATE_MISSING");
    return integrationStateFromRow(row);
  }

  public setAdapterEnabled(
    expectedRevision: number,
    enabled: boolean,
  ): HackerOnePersistedIntegrationState {
    requireRevision(expectedRevision);
    if (typeof enabled !== "boolean")
      throw new SecurityError("HACKERONE_INTEGRATION_STATE_INVALID");
    if (enabled)
      throw new SecurityError("SIGNED_HACKERONE_ACTIVATION_REQUIRED");
    return this.updateIntegrationState(expectedRevision, () =>
      this.database.run(
        `UPDATE hackerone_integration_state
         SET adapter_enabled=0,adapter_generation=adapter_generation+1,
             revision=revision+1
         WHERE singleton=1 AND revision=?`,
        expectedRevision,
      ),
    );
  }

  public recordConnectionTest(
    input: HackerOneConnectionStateUpdate,
  ): HackerOnePersistedIntegrationState {
    const normalized = normalizeConnectionUpdate(input);
    return this.updateIntegrationState(normalized.expectedRevision, () =>
      this.database.run(
        `UPDATE hackerone_integration_state
         SET last_connection_test_at=?,last_connection_result=?,
             last_successful_connection_at=CASE WHEN ?='connected' THEN ?
               ELSE last_successful_connection_at END,last_error_code=?,
             revision=revision+1
         WHERE singleton=1 AND revision=?`,
        normalized.occurredAt,
        normalized.result,
        normalized.result,
        normalized.occurredAt,
        normalized.errorCode,
        normalized.expectedRevision,
      ),
    );
  }

  public recordSynchronization(
    input: HackerOneSynchronizationStateUpdate,
  ): HackerOnePersistedIntegrationState {
    const normalized = normalizeSynchronizationUpdate(input);
    return this.updateIntegrationState(normalized.expectedRevision, () =>
      this.database.run(
        `UPDATE hackerone_integration_state
         SET last_synchronization_at=?,last_synchronization_result=?,last_error_code=?,
             revision=revision+1
         WHERE singleton=1 AND revision=?`,
        normalized.occurredAt,
        normalized.result,
        normalized.errorCode,
        normalized.expectedRevision,
      ),
    );
  }

  public recordRequestAudit(
    event: HackerOneRequestAuditEvent,
  ): StoredHackerOneRequestAuditEvent {
    const actionClass = (event as { readonly actionClass: string }).actionClass;
    if (
      !/^[0-9a-f]{32}$/u.test(event.requestId) ||
      actionClass !== "HACKERONE_METADATA_READ" ||
      ![
        "program",
        "programs",
        "scope_exclusions",
        "structured_scopes",
      ].includes(event.endpointClass) ||
      !/^[A-Za-z0-9_]{1,128}$/u.test(event.outcome) ||
      (event.statusCode !== null &&
        (!Number.isSafeInteger(event.statusCode) ||
          event.statusCode < 100 ||
          event.statusCode > 599)) ||
      !Number.isSafeInteger(event.durationMs) ||
      event.durationMs < 0 ||
      event.durationMs > 3_600_000
    )
      throw new SecurityError("HACKERONE_REQUEST_AUDIT_INVALID");
    const result = this.database.run(
      `INSERT INTO hackerone_request_audit(
        request_id,action_class,endpoint_class,outcome,status_code,duration_ms
      ) VALUES(?,?,?,?,?,?)`,
      event.requestId,
      event.actionClass,
      event.endpointClass,
      event.outcome,
      event.statusCode,
      event.durationMs,
    );
    if (result.changes !== 1)
      throw new SecurityError("HACKERONE_REQUEST_AUDIT_WRITE_FAILED");
    const sequence = Number(result.lastInsertRowid);
    if (!Number.isSafeInteger(sequence) || sequence < 1)
      throw new SecurityError("HACKERONE_REQUEST_AUDIT_WRITE_FAILED");
    return Object.freeze({ ...event, sequence });
  }

  public listRequestAudit(): readonly StoredHackerOneRequestAuditEvent[] {
    return Object.freeze(
      this.database
        .all(
          `SELECT sequence,request_id,action_class,endpoint_class,outcome,
             status_code,duration_ms
           FROM hackerone_request_audit ORDER BY sequence LIMIT 10001`,
        )
        .map((row) => {
          const sequence = rowInteger(row, "sequence");
          if (sequence < 1)
            throw new SecurityError("HACKERONE_STORE_ROW_INVALID");
          const statusCodeValue = row["status_code"];
          const statusCode =
            statusCodeValue === null ? null : rowInteger(row, "status_code");
          const endpointClass = rowText(row, "endpoint_class");
          if (
            endpointClass !== "program" &&
            endpointClass !== "programs" &&
            endpointClass !== "scope_exclusions" &&
            endpointClass !== "structured_scopes"
          )
            throw new SecurityError("HACKERONE_STORE_ROW_INVALID");
          return Object.freeze({
            sequence,
            requestId: rowText(row, "request_id"),
            actionClass: "HACKERONE_METADATA_READ" as const,
            endpointClass,
            outcome: rowText(row, "outcome"),
            statusCode,
            durationMs: rowInteger(row, "duration_ms"),
          });
        }),
    );
  }

  public bindDependentCampaign(
    programLocalRef: string,
    campaignId: string,
    boundAt: string,
  ): void {
    const localRef = requireLocalRef(programLocalRef);
    const program = this.requireProgram(localRef);
    if (
      program.program.source === API_SOURCE &&
      (!program.catalogActive || program.catalogDriftPending)
    )
      throw new SecurityError("HACKERONE_CAMPAIGN_BINDING_POLICY_DRIFT");
    if (!/^[A-Za-z0-9_-]{1,128}$/u.test(campaignId))
      throw new SecurityError("HACKERONE_CAMPAIGN_REF_INVALID");
    const occurredAt = requireTimestamp(
      boundAt,
      "HACKERONE_CAMPAIGN_BINDING_TIME_INVALID",
    );
    try {
      this.database.transaction(() => {
        const result = this.database.run(
          `INSERT INTO hackerone_campaign_bindings(
            program_local_ref,campaign_id,bound_at
          ) VALUES(?,?,?)`,
          localRef,
          campaignId,
          occurredAt,
        );
        if (result.changes !== 1)
          throw new SecurityError("HACKERONE_CAMPAIGN_BINDING_FAILED");
        this.database.run(
          `INSERT INTO control_plane_audit(
            id,occurred_at,action,decision,reason_code,object_reference,payload_hash
          ) VALUES(?,?,?,?,?,?,?)`,
          `h1bind-${sha256(`${localRef}\u0000${campaignId}\u0000${occurredAt}`).slice(0, 40)}`,
          occurredAt,
          "hackerone_campaign_binding",
          "bound",
          "HACKERONE_CAMPAIGN_BOUND",
          campaignId,
          sha256(canonicalJson({ programLocalRef: localRef, campaignId })),
        );
      });
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("HACKERONE_CAMPAIGN_BINDING_FAILED");
    }
  }

  public pauseDependentCampaigns(
    programLocalRef: string,
    occurredAt: string,
  ): boolean {
    const localRef = requireLocalRef(programLocalRef);
    this.requireProgram(localRef);
    const at = requireTimestamp(
      occurredAt,
      "HACKERONE_CAMPAIGN_PAUSE_TIME_INVALID",
    );
    const current = this.getCurrentSnapshot(localRef);
    if (current === undefined)
      throw new SecurityError("HACKERONE_CAMPAIGN_PAUSE_EVIDENCE_REQUIRED");
    return this.database.transaction(() =>
      this.pauseDependentCampaignsInTransaction(
        localRef,
        at,
        current.snapshot.snapshotDigest,
      ),
    );
  }

  public selectProgram(
    expectedRevision: number,
    localRef: string | null,
  ): HackerOnePersistedIntegrationState {
    requireRevision(expectedRevision);
    const selected =
      localRef === null ? null : this.requireProgram(requireLocalRef(localRef));
    return this.updateIntegrationState(expectedRevision, () =>
      this.database.run(
        `UPDATE hackerone_integration_state
         SET selected_program_ref=?,selected_program_source=?,revision=revision+1
         WHERE singleton=1 AND revision=?`,
        selected?.localRef ?? null,
        selected?.program.source ?? null,
        expectedRevision,
      ),
    );
  }

  public replaceAuthenticatedApiCatalog(
    programs: readonly HackerOneProgram[],
    occurredAt?: string,
  ): readonly StoredHackerOneProgram[] {
    const normalized = normalizeProgramCatalog(programs, API_SOURCE);
    const at = catalogTimestamp(normalized, occurredAt);
    const expectedRevision = this.getIntegrationState().revision;
    try {
      return this.database.transaction(() => {
        this.assertIntegrationRevision(expectedRevision);
        const stored = this.replaceAuthenticatedApiCatalogInTransaction(
          normalized,
          at,
        );
        this.updateSynchronizationStateInTransaction({
          expectedRevision,
          occurredAt: at,
          result: "succeeded",
          errorCode: null,
        });
        return stored;
      });
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("HACKERONE_API_CATALOG_WRITE_FAILED");
    }
  }

  public commitAuthenticatedApiCatalogSynchronization(
    programs: readonly HackerOneProgram[],
    update: HackerOneSynchronizationStateUpdate,
  ): readonly StoredHackerOneProgram[] {
    const normalized = normalizeProgramCatalog(programs, API_SOURCE);
    const stateUpdate = normalizeSynchronizationUpdate(update);
    if (stateUpdate.result !== "succeeded" || stateUpdate.errorCode !== null)
      throw new SecurityError("HACKERONE_SYNCHRONIZATION_STATE_INVALID");
    try {
      return this.database.transaction(() => {
        this.assertIntegrationRevision(stateUpdate.expectedRevision);
        const stored = this.replaceAuthenticatedApiCatalogInTransaction(
          normalized,
          stateUpdate.occurredAt,
        );
        this.updateSynchronizationStateInTransaction(stateUpdate);
        return stored;
      });
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("HACKERONE_API_CATALOG_WRITE_FAILED");
    }
  }

  public insertManualProgram(
    program: HackerOneProgram,
  ): StoredHackerOneProgram {
    const normalized = normalizeProgram(program, MANUAL_SOURCE);
    try {
      return this.database.transaction(() =>
        this.insertManualProgramInTransaction(normalized),
      );
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("HACKERONE_MANUAL_PROGRAM_WRITE_FAILED");
    }
  }

  public commitManualImport(
    program: HackerOneProgram,
    snapshot: HackerOnePolicySnapshot,
  ): StoredHackerOnePolicySnapshot {
    const normalizedProgram = normalizeProgram(program, MANUAL_SOURCE);
    const normalizedSnapshot = normalizeSnapshot(snapshot);
    try {
      return this.database.transaction(() => {
        const stored = this.insertManualProgramInTransaction(normalizedProgram);
        return this.commitSnapshotInTransaction(
          stored.localRef,
          normalizedSnapshot,
        );
      });
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("HACKERONE_MANUAL_IMPORT_WRITE_FAILED");
    }
  }

  public getProgram(localRef: string): StoredHackerOneProgram | undefined {
    const normalizedRef = requireLocalRef(localRef);
    const row = this.database.get(
      normalizedRef.startsWith("h1a_")
        ? "SELECT * FROM hackerone_api_programs WHERE local_ref=?"
        : "SELECT * FROM hackerone_manual_programs WHERE local_ref=?",
      normalizedRef,
    );
    if (row === undefined) return undefined;
    return programFromRow(
      row,
      normalizedRef.startsWith("h1a_") ? API_SOURCE : MANUAL_SOURCE,
    );
  }

  public listPrograms(
    source?: HackerOneDataSource,
    includeInactive = false,
  ): readonly StoredHackerOneProgram[] {
    if (source !== undefined) requireSource(source);
    if (typeof includeInactive !== "boolean")
      throw new SecurityError("HACKERONE_STORE_QUERY_INVALID");
    const records: StoredHackerOneProgram[] = [];
    if (source === undefined || source === API_SOURCE) {
      const rows = this.database.all(
        `SELECT * FROM hackerone_api_programs
         ${includeInactive ? "" : "WHERE catalog_active=1"}
         ORDER BY handle,local_ref`,
      );
      records.push(...rows.map((row) => programFromRow(row, API_SOURCE)));
    }
    if (source === undefined || source === MANUAL_SOURCE) {
      const rows = this.database.all(
        "SELECT * FROM hackerone_manual_programs ORDER BY handle,local_ref",
      );
      records.push(...rows.map((row) => programFromRow(row, MANUAL_SOURCE)));
    }
    records.sort((left, right) =>
      left.program.handle < right.program.handle
        ? -1
        : left.program.handle > right.program.handle
          ? 1
          : left.localRef < right.localRef
            ? -1
            : left.localRef > right.localRef
              ? 1
              : 0,
    );
    return Object.freeze(records);
  }

  public hasPausedDependentCampaigns(programLocalRef: string): boolean {
    const localRef = requireLocalRef(programLocalRef);
    this.requireProgram(localRef);
    const row = this.database.get(
      `SELECT count(*) AS count
       FROM hackerone_campaign_bindings b
       JOIN campaigns c ON c.id=b.campaign_id
       WHERE b.program_local_ref=? AND c.state='paused'
         AND c.kill_switch_status='engaged'`,
      localRef,
    );
    if (row === undefined)
      throw new SecurityError("HACKERONE_CAMPAIGN_BINDING_STATE_INVALID");
    return rowInteger(row, "count") > 0;
  }

  public getSyncedProgram(localRef: string): HackerOneProgram {
    const normalizedRef = requireLocalRef(localRef);
    if (!normalizedRef.startsWith("h1a_"))
      throw new SecurityError("HACKERONE_SYNCED_PROGRAM_SOURCE_INVALID");
    const stored = this.getProgram(normalizedRef);
    if (!stored?.catalogActive)
      throw new SecurityError("HACKERONE_SYNCED_PROGRAM_UNKNOWN");
    return stored.program;
  }

  public commitSnapshot(
    localRef: string,
    snapshot: HackerOnePolicySnapshot,
  ): StoredHackerOnePolicySnapshot {
    const normalizedRef = requireLocalRef(localRef);
    const normalizedSnapshot = normalizeSnapshot(snapshot);
    try {
      return this.database.transaction(
        () =>
          this.commitSnapshotWithPolicyDriftInTransaction(
            normalizedRef,
            normalizedSnapshot,
            normalizedSnapshot.fetchedAt,
          ).stored,
      );
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("HACKERONE_SNAPSHOT_WRITE_FAILED");
    }
  }

  public commitSnapshotWithPolicyDrift(
    localRef: string,
    snapshot: HackerOnePolicySnapshot,
    occurredAt: string,
  ): HackerOneSnapshotCommitResult {
    const normalizedRef = requireLocalRef(localRef);
    const normalizedSnapshot = normalizeSnapshot(snapshot);
    const at = requireTimestamp(
      occurredAt,
      "HACKERONE_POLICY_DRIFT_TIME_INVALID",
    );
    try {
      return this.database.transaction(() => {
        return this.commitSnapshotWithPolicyDriftInTransaction(
          normalizedRef,
          normalizedSnapshot,
          at,
        );
      });
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("HACKERONE_SNAPSHOT_WRITE_FAILED");
    }
  }

  public commitSelectedProgramSynchronization(
    localRef: string,
    snapshot: HackerOnePolicySnapshot,
    update: HackerOneSynchronizationStateUpdate,
  ): HackerOneSnapshotCommitResult {
    const normalizedRef = requireLocalRef(localRef);
    const normalizedSnapshot = normalizeSnapshot(snapshot);
    const stateUpdate = normalizeSynchronizationUpdate(update);
    if (stateUpdate.result !== "succeeded" || stateUpdate.errorCode !== null)
      throw new SecurityError("HACKERONE_SYNCHRONIZATION_STATE_INVALID");
    try {
      return this.database.transaction(() => {
        this.assertIntegrationRevision(stateUpdate.expectedRevision);
        const committed = this.commitSnapshotWithPolicyDriftInTransaction(
          normalizedRef,
          normalizedSnapshot,
          stateUpdate.occurredAt,
        );
        const program = this.requireProgram(normalizedRef);
        const selected = this.database.run(
          `UPDATE hackerone_integration_state
           SET selected_program_ref=?,selected_program_source=?,
               last_synchronization_at=?,last_synchronization_result='succeeded',
               last_error_code=NULL,revision=revision+1
           WHERE singleton=1 AND revision=?`,
          program.localRef,
          program.program.source,
          stateUpdate.occurredAt,
          stateUpdate.expectedRevision,
        );
        if (selected.changes !== 1)
          throw new SecurityError("HACKERONE_INTEGRATION_REVISION_CONFLICT");
        return committed;
      });
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new SecurityError("HACKERONE_SNAPSHOT_WRITE_FAILED");
    }
  }

  private commitSnapshotWithPolicyDriftInTransaction(
    normalizedRef: string,
    normalizedSnapshot: HackerOnePolicySnapshot,
    occurredAt: string,
  ): HackerOneSnapshotCommitResult {
    const previous = this.getCurrentSnapshot(normalizedRef);
    const drift = detectHackerOnePolicyDrift(
      previous?.snapshot ?? null,
      normalizedSnapshot,
      false,
    );
    const stored = this.commitSnapshotInTransaction(
      normalizedRef,
      normalizedSnapshot,
    );
    const campaignsPaused =
      previous !== undefined && drift.changed
        ? this.pauseDependentCampaignsInTransaction(
            normalizedRef,
            occurredAt,
            normalizedSnapshot.snapshotDigest,
          )
        : false;
    return Object.freeze({ stored, campaignsPaused });
  }

  private commitSnapshotInTransaction(
    normalizedRef: string,
    normalizedSnapshot: HackerOnePolicySnapshot,
  ): StoredHackerOnePolicySnapshot {
    const storedProgram = this.requireProgram(normalizedRef);
    assertSnapshotBinding(storedProgram, normalizedSnapshot);
    const encoded = canonicalJson(normalizedSnapshot);
    if (Buffer.byteLength(encoded, "utf8") > MAX_SNAPSHOT_JSON_BYTES)
      throw new SecurityError("HACKERONE_SNAPSHOT_TOO_LARGE");
    const inserted = this.database.run(
      `INSERT INTO hackerone_policy_snapshots (
        snapshot_digest,program_local_ref,source,policy_digest,
        previous_snapshot_digest,fetched_at,snapshot_json,acceptance_pending
      ) VALUES (?,?,?,?,?,?,?,1)`,
      normalizedSnapshot.snapshotDigest,
      normalizedRef,
      normalizedSnapshot.source,
      normalizedSnapshot.policyDigest,
      normalizedSnapshot.previousSnapshotDigest,
      normalizedSnapshot.fetchedAt,
      encoded,
    );
    if (inserted.changes !== 1)
      throw new SecurityError("HACKERONE_SNAPSHOT_WRITE_FAILED");
    const updatedProgram = storedProgramMaterial(
      normalizedSnapshot.program,
      storedProgram.catalogActive,
      false,
      normalizedSnapshot.snapshotDigest,
    );
    const updated = this.updateProgramAfterSnapshot(updatedProgram);
    if (updated.changes !== 1)
      throw new SecurityError("HACKERONE_SNAPSHOT_WRITE_FAILED");
    return storedSnapshot(normalizedRef, normalizedSnapshot);
  }

  private pauseDependentCampaignsInTransaction(
    localRef: string,
    occurredAt: string,
    snapshotDigest: string,
  ): boolean {
    const result = this.database.run(
      `UPDATE campaigns SET state='paused',revision=revision+1,
         human_approved_by=NULL,human_approved_at=NULL,
         last_policy_check_at=?,kill_switch_status='engaged'
       WHERE id IN (
         SELECT campaign_id FROM hackerone_campaign_bindings
         WHERE program_local_ref=?
       ) AND state IN ('approved','running_simulation')`,
      occurredAt,
      localRef,
    );
    const campaignsPaused = result.changes > 0;
    this.database.run(
      `INSERT INTO control_plane_audit(
        id,occurred_at,action,decision,reason_code,object_reference,payload_hash
      ) VALUES(?,?,?,?,?,?,?)`,
      `h1drift-${sha256(`${localRef}\u0000${snapshotDigest}`).slice(0, 40)}`,
      occurredAt,
      "hackerone_policy_drift",
      campaignsPaused ? "campaigns_paused" : "no_active_campaigns",
      campaignsPaused
        ? "HACKERONE_POLICY_DRIFT_CAMPAIGNS_PAUSED"
        : "HACKERONE_POLICY_DRIFT_NO_ACTIVE_CAMPAIGNS",
      localRef,
      snapshotDigest,
    );
    return campaignsPaused;
  }

  public getSnapshot(
    snapshotDigest: string,
  ): StoredHackerOnePolicySnapshot | undefined {
    const digest = requireDigest(
      snapshotDigest,
      "HACKERONE_SNAPSHOT_DIGEST_INVALID",
    );
    const row = this.acceptanceEvidenceAvailable()
      ? this.database.get(
          `SELECT s.*,
             CASE WHEN a.snapshot_digest IS NULL THEN 1 ELSE 0 END
               AS acceptance_pending_evidence
           FROM hackerone_policy_snapshots s
           LEFT JOIN hackerone_policy_acceptances a
             ON a.snapshot_digest=s.snapshot_digest
           WHERE s.snapshot_digest=?`,
          digest,
        )
      : this.database.get(
          `SELECT s.*,1 AS acceptance_pending_evidence
           FROM hackerone_policy_snapshots s WHERE s.snapshot_digest=?`,
          digest,
        );
    return row === undefined ? undefined : snapshotFromRow(row);
  }

  public getCurrentSnapshot(
    localRef: string,
  ): StoredHackerOnePolicySnapshot | undefined {
    const program = this.requireProgram(requireLocalRef(localRef));
    if (program.currentSnapshotDigest === null) return undefined;
    const snapshot = this.getSnapshot(program.currentSnapshotDigest);
    if (snapshot?.programLocalRef !== program.localRef)
      throw new SecurityError("HACKERONE_SNAPSHOT_POINTER_INVALID");
    return snapshot;
  }

  public listSnapshots(
    localRef: string,
  ): readonly StoredHackerOnePolicySnapshot[] {
    const normalizedRef = requireLocalRef(localRef);
    this.requireProgram(normalizedRef);
    const rows = this.acceptanceEvidenceAvailable()
      ? this.database.all(
          `SELECT s.*,
             CASE WHEN a.snapshot_digest IS NULL THEN 1 ELSE 0 END
               AS acceptance_pending_evidence
           FROM hackerone_policy_snapshots s
           LEFT JOIN hackerone_policy_acceptances a
             ON a.snapshot_digest=s.snapshot_digest
           WHERE s.program_local_ref=? ORDER BY s.fetched_at,s.snapshot_digest
           LIMIT ?`,
          normalizedRef,
          MAX_SNAPSHOTS_PER_READ + 1,
        )
      : this.database.all(
          `SELECT s.*,1 AS acceptance_pending_evidence
           FROM hackerone_policy_snapshots s
           WHERE s.program_local_ref=? ORDER BY s.fetched_at,s.snapshot_digest
           LIMIT ?`,
          normalizedRef,
          MAX_SNAPSHOTS_PER_READ + 1,
        );
    if (rows.length > MAX_SNAPSHOTS_PER_READ)
      throw new SecurityError("HACKERONE_SNAPSHOT_READ_LIMIT_EXCEEDED");
    return Object.freeze(rows.map(snapshotFromRow));
  }

  public listAcceptancePendingSnapshots(
    localRef?: string,
  ): readonly StoredHackerOnePolicySnapshot[] {
    const normalizedRef =
      localRef === undefined ? undefined : requireLocalRef(localRef);
    if (normalizedRef !== undefined) this.requireProgram(normalizedRef);
    const evidenceClause = this.acceptanceEvidenceAvailable()
      ? `NOT EXISTS(
          SELECT 1 FROM hackerone_policy_acceptances a
          WHERE a.snapshot_digest=s.snapshot_digest
        )`
      : "1=1";
    const rows = this.database.all(
      `SELECT s.*,1 AS acceptance_pending_evidence
       FROM hackerone_policy_snapshots s
       WHERE ${evidenceClause}${
         normalizedRef === undefined ? "" : " AND s.program_local_ref=?"
       }
       ORDER BY s.fetched_at,s.snapshot_digest LIMIT ?`,
      ...(normalizedRef === undefined
        ? [MAX_SNAPSHOTS_PER_READ + 1]
        : [normalizedRef, MAX_SNAPSHOTS_PER_READ + 1]),
    );
    if (rows.length > MAX_SNAPSHOTS_PER_READ)
      throw new SecurityError("HACKERONE_SNAPSHOT_READ_LIMIT_EXCEEDED");
    return Object.freeze(rows.map(snapshotFromRow));
  }

  private initialize(): void {
    this.database.transaction(() => {
      const markerObject = this.database.get(
        `SELECT type FROM sqlite_schema
         WHERE name='hackerone_readonly_schema'`,
      );
      if (markerObject === undefined) {
        assertSqliteSchemaNamespaceEmpty(
          (sql) => this.database.all(sql),
          STORE_SCHEMA_EXPECTATION,
          "HACKERONE_STORE_SCHEMA_MISMATCH",
        );
        for (const statement of SCHEMA_STATEMENTS) this.database.run(statement);
        assertExactSqliteSchema(
          (sql) => this.database.all(sql),
          STORE_SCHEMA_EXPECTATION,
          "HACKERONE_STORE_SCHEMA_MISMATCH",
        );
        this.database.run(
          `INSERT INTO hackerone_integration_state (
            singleton,adapter_enabled,adapter_generation,last_connection_test_at,
            last_successful_connection_at,last_connection_result,
            last_synchronization_at,last_synchronization_result,last_error_code,
            selected_program_ref,selected_program_source,revision
          ) VALUES (1,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,0)`,
        );
        this.database.run(
          `INSERT INTO hackerone_readonly_schema
           (component,version,schema_digest) VALUES ('metadata_store',1,?)`,
          STORE_SCHEMA_DIGEST,
        );
      } else {
        assertExactSqliteSchema(
          (sql) => this.database.all(sql),
          STORE_SCHEMA_EXPECTATION,
          "HACKERONE_STORE_SCHEMA_MISMATCH",
        );
      }
      const marker = this.database.get(
        "SELECT version,schema_digest FROM hackerone_readonly_schema WHERE component='metadata_store'",
      );
      if (
        marker?.["version"] !== 1 ||
        marker["schema_digest"] !== STORE_SCHEMA_DIGEST
      )
        throw new SecurityError("HACKERONE_STORE_SCHEMA_MISMATCH");
      if (
        this.database.get(
          "SELECT singleton FROM hackerone_integration_state WHERE singleton=1",
        ) === undefined
      )
        throw new SecurityError("HACKERONE_STORE_SCHEMA_MISMATCH");
    });
  }

  private acceptanceEvidenceAvailable(): boolean {
    return (
      this.database.get(
        `SELECT name FROM sqlite_schema
         WHERE type='table' AND name='hackerone_policy_acceptances'`,
      ) !== undefined
    );
  }

  private updateIntegrationState(
    expectedRevision: number,
    operation: () => { readonly changes: bigint | number },
  ): HackerOnePersistedIntegrationState {
    return this.database.transaction(() => {
      const current = this.getIntegrationState();
      if (current.revision !== expectedRevision)
        throw new SecurityError("HACKERONE_INTEGRATION_REVISION_CONFLICT");
      const result = operation();
      if (result.changes !== 1)
        throw new SecurityError("HACKERONE_INTEGRATION_REVISION_CONFLICT");
      return this.getIntegrationState();
    });
  }

  private assertIntegrationRevision(expectedRevision: number): void {
    const current = this.getIntegrationState();
    if (current.revision !== expectedRevision)
      throw new SecurityError("HACKERONE_INTEGRATION_REVISION_CONFLICT");
  }

  private updateSynchronizationStateInTransaction(
    update: HackerOneSynchronizationStateUpdate,
  ): void {
    const result = this.database.run(
      `UPDATE hackerone_integration_state
       SET last_synchronization_at=?,last_synchronization_result=?,
           last_error_code=?,revision=revision+1
       WHERE singleton=1 AND revision=?`,
      update.occurredAt,
      update.result,
      update.errorCode,
      update.expectedRevision,
    );
    if (result.changes !== 1)
      throw new SecurityError("HACKERONE_INTEGRATION_REVISION_CONFLICT");
  }

  private replaceAuthenticatedApiCatalogInTransaction(
    programs: readonly HackerOneProgram[],
    occurredAt: string,
  ): readonly StoredHackerOneProgram[] {
    const incomingIds = new Set(programs.map(({ hackerOneId }) => hackerOneId));
    const previouslyActive = this.listPrograms(API_SOURCE, false);
    for (const previous of previouslyActive) {
      if (incomingIds.has(previous.program.hackerOneId)) continue;
      const driftPending = previous.currentSnapshotDigest !== null;
      const result = this.database.run(
        `UPDATE hackerone_api_programs
         SET catalog_active=0,catalog_drift_pending=?
         WHERE local_ref=? AND catalog_active=1`,
        driftPending ? 1 : 0,
        previous.localRef,
      );
      if (result.changes !== 1)
        throw new SecurityError("HACKERONE_API_CATALOG_WRITE_FAILED");
      if (driftPending && !previous.catalogDriftPending)
        this.pauseForCatalogDriftInTransaction(
          previous.localRef,
          occurredAt,
          sha256("hackerone-catalog-program-missing"),
        );
    }
    for (const program of programs) this.upsertApiProgram(program, occurredAt);
    return this.listPrograms(API_SOURCE, false);
  }

  private upsertApiProgram(
    program: HackerOneProgram,
    occurredAt: string,
  ): void {
    const identity = storedProgramMaterial(program, true, false, null);
    const existing = this.getProgram(identity.localRef);
    const currentSnapshot =
      existing?.currentSnapshotDigest === null || existing === undefined
        ? undefined
        : this.getSnapshot(existing.currentSnapshotDigest);
    const catalogDriftPending =
      (existing?.catalogDriftPending ?? false) ||
      (currentSnapshot !== undefined &&
        catalogPolicyMaterial(currentSnapshot.snapshot.program) !==
          catalogPolicyMaterial(program));
    const stored = storedProgramMaterial(
      program,
      true,
      catalogDriftPending,
      existing?.currentSnapshotDigest ?? null,
    );
    const result = this.database.run(
      `INSERT INTO hackerone_api_programs (
        local_ref,hackerone_id,handle,name,currency,policy,submission_state,
        program_state,offers_bounties,open_scope,gold_standard_safe_harbor,
        bookmarked,own_report_count,own_valid_report_count,started_accepting_at,
        created_at,updated_at,synchronized_at,catalog_active,catalog_drift_pending,
        record_digest,current_snapshot_digest
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(local_ref) DO UPDATE SET
        handle=excluded.handle,name=excluded.name,currency=excluded.currency,
        policy=excluded.policy,submission_state=excluded.submission_state,
        program_state=excluded.program_state,offers_bounties=excluded.offers_bounties,
        open_scope=excluded.open_scope,
        gold_standard_safe_harbor=excluded.gold_standard_safe_harbor,
        bookmarked=excluded.bookmarked,own_report_count=excluded.own_report_count,
        own_valid_report_count=excluded.own_valid_report_count,
        started_accepting_at=excluded.started_accepting_at,
        created_at=excluded.created_at,updated_at=excluded.updated_at,
        synchronized_at=excluded.synchronized_at,catalog_active=1,
        catalog_drift_pending=excluded.catalog_drift_pending,
        record_digest=excluded.record_digest`,
      ...programParameters(stored),
    );
    if (result.changes !== 1)
      throw new SecurityError("HACKERONE_API_CATALOG_WRITE_FAILED");
    if (
      catalogDriftPending &&
      existing !== undefined &&
      !existing.catalogDriftPending
    )
      this.pauseForCatalogDriftInTransaction(
        existing.localRef,
        occurredAt,
        stored.recordDigest,
      );
  }

  private insertManualProgramInTransaction(
    program: HackerOneProgram,
  ): StoredHackerOneProgram {
    const stored = storedProgramMaterial(program, true, false, null);
    const result = this.database.run(
      `INSERT INTO hackerone_manual_programs (
        local_ref,hackerone_id,handle,name,currency,policy,submission_state,
        program_state,offers_bounties,open_scope,gold_standard_safe_harbor,
        bookmarked,own_report_count,own_valid_report_count,started_accepting_at,
        created_at,updated_at,synchronized_at,catalog_active,catalog_drift_pending,
        record_digest,current_snapshot_digest
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      ...programParameters(stored),
    );
    if (result.changes !== 1)
      throw new SecurityError("HACKERONE_MANUAL_PROGRAM_WRITE_FAILED");
    return this.requireProgram(stored.localRef);
  }

  private pauseForCatalogDriftInTransaction(
    localRef: string,
    occurredAt: string,
    evidenceDigest: string,
  ): void {
    const result = this.database.run(
      `UPDATE campaigns SET state='paused',revision=revision+1,
         human_approved_by=NULL,human_approved_at=NULL,
         last_policy_check_at=?,kill_switch_status='engaged'
       WHERE id IN (
         SELECT campaign_id FROM hackerone_campaign_bindings
         WHERE program_local_ref=?
       ) AND state IN ('approved','running_simulation')`,
      occurredAt,
      localRef,
    );
    this.database.run(
      `INSERT INTO control_plane_audit(
        id,occurred_at,action,decision,reason_code,object_reference,payload_hash
      ) VALUES(?,?,?,?,?,?,?)`,
      `h1catalogdrift-${sha256(
        `${localRef}\u0000${evidenceDigest}\u0000${occurredAt}`,
      ).slice(0, 36)}`,
      occurredAt,
      "hackerone_catalog_policy_drift",
      result.changes > 0 ? "campaigns_paused" : "no_active_campaigns",
      result.changes > 0
        ? "HACKERONE_CATALOG_DRIFT_CAMPAIGNS_PAUSED"
        : "HACKERONE_CATALOG_DRIFT_NO_ACTIVE_CAMPAIGNS",
      localRef,
      evidenceDigest,
    );
  }

  private updateProgramAfterSnapshot(stored: StoredHackerOneProgram): {
    readonly changes: bigint | number;
  } {
    const table =
      stored.program.source === API_SOURCE
        ? "hackerone_api_programs"
        : "hackerone_manual_programs";
    return this.database.run(
      `UPDATE ${table} SET
        handle=?,name=?,currency=?,policy=?,submission_state=?,program_state=?,
        offers_bounties=?,open_scope=?,gold_standard_safe_harbor=?,bookmarked=?,
        own_report_count=?,own_valid_report_count=?,started_accepting_at=?,
        created_at=?,updated_at=?,synchronized_at=?,catalog_drift_pending=0,
        record_digest=?,
        current_snapshot_digest=? WHERE local_ref=?`,
      stored.program.handle,
      stored.program.name,
      stored.program.currency,
      stored.program.policy,
      stored.program.submissionState,
      stored.program.programState,
      stored.program.offersBounties ? 1 : 0,
      stored.program.openScope ? 1 : 0,
      stored.program.goldStandardSafeHarbor ? 1 : 0,
      stored.program.bookmarked ? 1 : 0,
      stored.program.ownReportCount,
      stored.program.ownValidReportCount,
      stored.program.startedAcceptingAt,
      stored.program.createdAt,
      stored.program.updatedAt,
      stored.program.synchronizedAt,
      stored.recordDigest,
      stored.currentSnapshotDigest,
      stored.localRef,
    );
  }

  private requireProgram(localRef: string): StoredHackerOneProgram {
    const program = this.getProgram(localRef);
    if (program === undefined)
      throw new SecurityError("HACKERONE_PROGRAM_UNKNOWN");
    return program;
  }
}

function normalizeProgramCatalog(
  value: readonly HackerOneProgram[],
  expectedSource: HackerOneDataSource,
): readonly HackerOneProgram[] {
  const entries = requirePlainArray(
    value,
    MAX_PROGRAMS_PER_CATALOG,
    "HACKERONE_PROGRAM_CATALOG_INVALID",
  );
  const programs = entries.map((program) =>
    normalizeProgram(program, expectedSource),
  );
  const ids = new Set<string>();
  const handles = new Set<string>();
  for (const program of programs) {
    if (ids.has(program.hackerOneId) || handles.has(program.handle))
      throw new SecurityError("HACKERONE_PROGRAM_CATALOG_DUPLICATE");
    ids.add(program.hackerOneId);
    handles.add(program.handle);
  }
  return Object.freeze(programs);
}

function normalizeProgram(
  value: unknown,
  expectedSource?: HackerOneDataSource,
): HackerOneProgram {
  const record = requireExactRecord(
    value,
    PROGRAM_KEYS,
    "HACKERONE_PROGRAM_INVALID",
  );
  const source = requireSource(record["source"]);
  if (expectedSource !== undefined && source !== expectedSource)
    throw new SecurityError("HACKERONE_PROGRAM_SOURCE_INVALID");
  const name = requireText(record["name"], 1, 512, "HACKERONE_PROGRAM_INVALID");
  if (name.trim() !== name)
    throw new SecurityError("HACKERONE_PROGRAM_INVALID");
  return Object.freeze({
    hackerOneId: requireText(
      record["hackerOneId"],
      1,
      128,
      "HACKERONE_PROGRAM_INVALID",
    ),
    handle: requirePatternText(
      record["handle"],
      HANDLE_PATTERN,
      "HACKERONE_PROGRAM_INVALID",
    ),
    name,
    currency: requireText(
      record["currency"],
      1,
      16,
      "HACKERONE_PROGRAM_INVALID",
    ),
    policy: requireText(
      record["policy"],
      0,
      262_144,
      "HACKERONE_PROGRAM_INVALID",
    ),
    submissionState: requireText(
      record["submissionState"],
      1,
      128,
      "HACKERONE_PROGRAM_INVALID",
    ),
    programState: requireText(
      record["programState"],
      1,
      128,
      "HACKERONE_PROGRAM_INVALID",
    ),
    offersBounties: requireBoolean(
      record["offersBounties"],
      "HACKERONE_PROGRAM_INVALID",
    ),
    openScope: requireBoolean(record["openScope"], "HACKERONE_PROGRAM_INVALID"),
    goldStandardSafeHarbor: requireBoolean(
      record["goldStandardSafeHarbor"],
      "HACKERONE_PROGRAM_INVALID",
    ),
    bookmarked: requireBoolean(
      record["bookmarked"],
      "HACKERONE_PROGRAM_INVALID",
    ),
    ownReportCount: requireNonNegativeInteger(
      record["ownReportCount"],
      "HACKERONE_PROGRAM_INVALID",
    ),
    ownValidReportCount: requireNonNegativeInteger(
      record["ownValidReportCount"],
      "HACKERONE_PROGRAM_INVALID",
    ),
    startedAcceptingAt: requireNullableTimestamp(
      record["startedAcceptingAt"],
      "HACKERONE_PROGRAM_INVALID",
    ),
    createdAt: requireNullableTimestamp(
      record["createdAt"],
      "HACKERONE_PROGRAM_INVALID",
    ),
    updatedAt: requireNullableTimestamp(
      record["updatedAt"],
      "HACKERONE_PROGRAM_INVALID",
    ),
    synchronizedAt: requireTimestamp(
      record["synchronizedAt"],
      "HACKERONE_PROGRAM_INVALID",
    ),
    source,
  });
}

function normalizeScope(value: unknown): HackerOneStructuredScope {
  const record = requireExactRecord(
    value,
    SCOPE_KEYS,
    "HACKERONE_SCOPE_INVALID",
  );
  const assetIdentifier = requireText(
    record["assetIdentifier"],
    1,
    4_096,
    "HACKERONE_SCOPE_INVALID",
  );
  const assetIdentifierDigest = requireDigest(
    record["assetIdentifierDigest"],
    "HACKERONE_SCOPE_INVALID",
  );
  if (assetIdentifierDigest !== sha256(assetIdentifier))
    throw new SecurityError("HACKERONE_SCOPE_DIGEST_INVALID");
  return Object.freeze({
    id: requireText(record["id"], 1, 128, "HACKERONE_SCOPE_INVALID"),
    assetType: requireText(
      record["assetType"],
      1,
      128,
      "HACKERONE_SCOPE_INVALID",
    ),
    assetIdentifier,
    assetIdentifierDigest,
    eligibleForSubmission: requireBoolean(
      record["eligibleForSubmission"],
      "HACKERONE_SCOPE_INVALID",
    ),
    eligibleForBounty: requireBoolean(
      record["eligibleForBounty"],
      "HACKERONE_SCOPE_INVALID",
    ),
    instruction: requireText(
      record["instruction"],
      0,
      65_536,
      "HACKERONE_SCOPE_INVALID",
    ),
    maximumSeverity: requireNullableText(
      record["maximumSeverity"],
      1,
      64,
      "HACKERONE_SCOPE_INVALID",
    ),
    createdAt: requireNullableTimestamp(
      record["createdAt"],
      "HACKERONE_SCOPE_INVALID",
    ),
    updatedAt: requireNullableTimestamp(
      record["updatedAt"],
      "HACKERONE_SCOPE_INVALID",
    ),
    confidentialityRequirement: requireNullableText(
      record["confidentialityRequirement"],
      1,
      64,
      "HACKERONE_SCOPE_INVALID",
    ),
    integrityRequirement: requireNullableText(
      record["integrityRequirement"],
      1,
      64,
      "HACKERONE_SCOPE_INVALID",
    ),
    availabilityRequirement: requireNullableText(
      record["availabilityRequirement"],
      1,
      64,
      "HACKERONE_SCOPE_INVALID",
    ),
  });
}

function normalizeExclusion(value: unknown): HackerOneScopeExclusion {
  const record = requireExactRecord(
    value,
    EXCLUSION_KEYS,
    "HACKERONE_SCOPE_EXCLUSION_INVALID",
  );
  return Object.freeze({
    id: requireText(record["id"], 1, 128, "HACKERONE_SCOPE_EXCLUSION_INVALID"),
    category: requireText(
      record["category"],
      1,
      256,
      "HACKERONE_SCOPE_EXCLUSION_INVALID",
    ),
    details: requireText(
      record["details"],
      0,
      65_536,
      "HACKERONE_SCOPE_EXCLUSION_INVALID",
    ),
    createdAt: requireNullableTimestamp(
      record["createdAt"],
      "HACKERONE_SCOPE_EXCLUSION_INVALID",
    ),
    updatedAt: requireNullableTimestamp(
      record["updatedAt"],
      "HACKERONE_SCOPE_EXCLUSION_INVALID",
    ),
  });
}

function normalizeSnapshot(value: unknown): HackerOnePolicySnapshot {
  const record = requireExactRecord(
    value,
    SNAPSHOT_KEYS,
    "HACKERONE_SNAPSHOT_INVALID",
  );
  const program = normalizeProgram(record["program"]);
  const structuredScopes = normalizeUniqueArray(
    record["structuredScopes"],
    normalizeScope,
    "HACKERONE_SCOPE_DUPLICATE",
  );
  const scopeExclusions = normalizeUniqueArray(
    record["scopeExclusions"],
    normalizeExclusion,
    "HACKERONE_SCOPE_EXCLUSION_DUPLICATE",
  );
  const fetchedAt = requireTimestamp(
    record["fetchedAt"],
    "HACKERONE_SNAPSHOT_INVALID",
  );
  if (record["adapterVersion"] !== HACKERONE_ADAPTER_VERSION)
    throw new SecurityError("HACKERONE_SNAPSHOT_ADAPTER_VERSION_INVALID");
  if (record["schemaVersion"] !== HACKERONE_SCHEMA_VERSION)
    throw new SecurityError("HACKERONE_SNAPSHOT_SCHEMA_VERSION_INVALID");
  const previousSnapshotDigest =
    record["previousSnapshotDigest"] === null
      ? null
      : requireDigest(
          record["previousSnapshotDigest"],
          "HACKERONE_SNAPSHOT_PREDECESSOR_INVALID",
        );
  const source = requireSource(record["source"]);
  if (source !== program.source)
    throw new SecurityError("HACKERONE_SNAPSHOT_SOURCE_MISMATCH");
  const suppliedSnapshotDigest = requireDigest(
    record["snapshotDigest"],
    "HACKERONE_SNAPSHOT_DIGEST_INVALID",
  );
  const suppliedPolicyDigest = requireDigest(
    record["policyDigest"],
    "HACKERONE_POLICY_DIGEST_INVALID",
  );
  const suppliedSuitability = normalizeSuitability(record["suitability"]);
  const expected = createHackerOnePolicySnapshot({
    program,
    structuredScopes,
    scopeExclusions,
    fetchedAt,
    previousSnapshotDigest,
  });
  if (
    suppliedSnapshotDigest !== expected.snapshotDigest ||
    suppliedPolicyDigest !== expected.policyDigest ||
    canonicalJson(suppliedSuitability) !==
      canonicalJson(expected.suitability) ||
    canonicalJson(structuredScopes) !==
      canonicalJson(expected.structuredScopes) ||
    canonicalJson(scopeExclusions) !== canonicalJson(expected.scopeExclusions)
  )
    throw new SecurityError("HACKERONE_SNAPSHOT_INTEGRITY_INVALID");
  return expected;
}

function normalizeSuitability(value: unknown): HackerOneProgramSuitability {
  const record = requireExactRecord(
    value,
    SUITABILITY_KEYS,
    "HACKERONE_SUITABILITY_INVALID",
  );
  const score = requireNonNegativeInteger(
    record["score"],
    "HACKERONE_SUITABILITY_INVALID",
  );
  if (score > 100) throw new SecurityError("HACKERONE_SUITABILITY_INVALID");
  const reasons = requireStringArray(
    record["reasons"],
    "HACKERONE_SUITABILITY_INVALID",
  );
  const suitabilityReasons: HackerOneSuitabilityReason[] = [];
  for (const reason of reasons) {
    if (!isSuitabilityReason(reason))
      throw new SecurityError("HACKERONE_SUITABILITY_INVALID");
    suitabilityReasons.push(reason);
  }
  const automationPermission = record["automationPermission"];
  if (
    automationPermission !== "allowed" &&
    automationPermission !== "forbidden" &&
    automationPermission !== "unknown_requires_human_review"
  )
    throw new SecurityError("HACKERONE_SUITABILITY_INVALID");
  if (
    record["accountWorkflows"] !== "manual_review_required" ||
    record["legalDecisionMade"] !== false
  )
    throw new SecurityError("HACKERONE_SUITABILITY_INVALID");
  return Object.freeze({
    score,
    reasons: Object.freeze(suitabilityReasons),
    automationPermission,
    accountWorkflows: "manual_review_required",
    legalDecisionMade: false,
  });
}

function normalizeUniqueArray<T extends { readonly id: string }>(
  value: unknown,
  normalize: (entry: unknown) => T,
  duplicateCode: string,
): readonly T[] {
  const entries = requirePlainArray(value, 2_000, "HACKERONE_SNAPSHOT_INVALID");
  const normalized = entries.map(normalize);
  const ids = new Set<string>();
  for (const entry of normalized) {
    if (ids.has(entry.id)) throw new SecurityError(duplicateCode);
    ids.add(entry.id);
  }
  return Object.freeze(normalized);
}

function normalizeConnectionUpdate(
  value: HackerOneConnectionStateUpdate,
): HackerOneConnectionStateUpdate {
  const record = requireExactRecord(
    value,
    ["errorCode", "expectedRevision", "occurredAt", "result"],
    "HACKERONE_CONNECTION_STATE_INVALID",
  );
  const expectedRevision = requireRevision(record["expectedRevision"]);
  const occurredAt = requireTimestamp(
    record["occurredAt"],
    "HACKERONE_CONNECTION_STATE_INVALID",
  );
  const result = requireConnectionResult(record["result"]);
  const errorCode = requireNullableErrorCode(record["errorCode"]);
  if ((result === "connected") !== (errorCode === null))
    throw new SecurityError("HACKERONE_CONNECTION_STATE_INVALID");
  return Object.freeze({ expectedRevision, occurredAt, result, errorCode });
}

function normalizeSynchronizationUpdate(
  value: HackerOneSynchronizationStateUpdate,
): HackerOneSynchronizationStateUpdate {
  const record = requireExactRecord(
    value,
    ["errorCode", "expectedRevision", "occurredAt", "result"],
    "HACKERONE_SYNCHRONIZATION_STATE_INVALID",
  );
  const expectedRevision = requireRevision(record["expectedRevision"]);
  const occurredAt = requireTimestamp(
    record["occurredAt"],
    "HACKERONE_SYNCHRONIZATION_STATE_INVALID",
  );
  const result = record["result"];
  if (result !== "failed" && result !== "succeeded")
    throw new SecurityError("HACKERONE_SYNCHRONIZATION_STATE_INVALID");
  const errorCode = requireNullableErrorCode(record["errorCode"]);
  if ((result === "succeeded") !== (errorCode === null))
    throw new SecurityError("HACKERONE_SYNCHRONIZATION_STATE_INVALID");
  return Object.freeze({ expectedRevision, occurredAt, result, errorCode });
}

function integrationStateFromRow(
  row: Readonly<Record<string, unknown>>,
): HackerOnePersistedIntegrationState {
  const selectedProgramRef = nullableRowText(row, "selected_program_ref");
  const selectedSourceValue = nullableRowText(row, "selected_program_source");
  const selectedProgramSource =
    selectedSourceValue === null ? null : requireSource(selectedSourceValue);
  if (
    (selectedProgramRef === null) !== (selectedProgramSource === null) ||
    (selectedProgramRef !== null &&
      sourceForLocalRef(requireLocalRef(selectedProgramRef)) !==
        selectedProgramSource)
  )
    throw new SecurityError("HACKERONE_INTEGRATION_STATE_INVALID");
  const connectionValue = nullableRowText(row, "last_connection_result");
  const synchronizationValue = nullableRowText(
    row,
    "last_synchronization_result",
  );
  if (
    synchronizationValue !== null &&
    synchronizationValue !== "failed" &&
    synchronizationValue !== "succeeded"
  )
    throw new SecurityError("HACKERONE_INTEGRATION_STATE_INVALID");
  return Object.freeze({
    adapterEnabled: rowBoolean(row, "adapter_enabled"),
    adapterGeneration: requireRevision(rowInteger(row, "adapter_generation")),
    lastConnectionTestAt: nullableRowTimestamp(row, "last_connection_test_at"),
    lastSuccessfulConnectionAt: nullableRowTimestamp(
      row,
      "last_successful_connection_at",
    ),
    lastConnectionResult:
      connectionValue === null
        ? null
        : requireConnectionResult(connectionValue),
    lastSynchronizationAt: nullableRowTimestamp(row, "last_synchronization_at"),
    lastSynchronizationResult: synchronizationValue,
    lastErrorCode: requireNullableErrorCode(
      nullableRowText(row, "last_error_code"),
    ),
    selectedProgramRef,
    selectedProgramSource,
    revision: requireRevision(rowInteger(row, "revision")),
  });
}

function programFromRow(
  row: Readonly<Record<string, unknown>>,
  source: HackerOneDataSource,
): StoredHackerOneProgram {
  const program = normalizeProgram(
    {
      hackerOneId: rowText(row, "hackerone_id"),
      handle: rowText(row, "handle"),
      name: rowText(row, "name"),
      currency: rowText(row, "currency"),
      policy: rowText(row, "policy"),
      submissionState: rowText(row, "submission_state"),
      programState: rowText(row, "program_state"),
      offersBounties: rowBoolean(row, "offers_bounties"),
      openScope: rowBoolean(row, "open_scope"),
      goldStandardSafeHarbor: rowBoolean(row, "gold_standard_safe_harbor"),
      bookmarked: rowBoolean(row, "bookmarked"),
      ownReportCount: rowInteger(row, "own_report_count"),
      ownValidReportCount: rowInteger(row, "own_valid_report_count"),
      startedAcceptingAt: nullableRowTimestamp(row, "started_accepting_at"),
      createdAt: nullableRowTimestamp(row, "created_at"),
      updatedAt: nullableRowTimestamp(row, "updated_at"),
      synchronizedAt: rowTimestamp(row, "synchronized_at"),
      source,
    },
    source,
  );
  const localRef = requireLocalRef(rowText(row, "local_ref"));
  const recordDigest = requireDigest(
    rowText(row, "record_digest"),
    "HACKERONE_PROGRAM_RECORD_DIGEST_INVALID",
  );
  const currentSnapshotValue = nullableRowText(row, "current_snapshot_digest");
  const currentSnapshotDigest =
    currentSnapshotValue === null
      ? null
      : requireDigest(
          currentSnapshotValue,
          "HACKERONE_SNAPSHOT_POINTER_INVALID",
        );
  const expected = storedProgramMaterial(
    program,
    rowBoolean(row, "catalog_active"),
    rowBoolean(row, "catalog_drift_pending"),
    currentSnapshotDigest,
  );
  if (localRef !== expected.localRef || recordDigest !== expected.recordDigest)
    throw new SecurityError("HACKERONE_PROGRAM_RECORD_INTEGRITY_INVALID");
  if (
    source === MANUAL_SOURCE &&
    (!expected.catalogActive || expected.catalogDriftPending)
  )
    throw new SecurityError("HACKERONE_PROGRAM_RECORD_INTEGRITY_INVALID");
  return expected;
}

function snapshotFromRow(
  row: Readonly<Record<string, unknown>>,
): StoredHackerOnePolicySnapshot {
  const encoded = rowText(row, "snapshot_json");
  let parsed: unknown;
  try {
    parsed = JSON.parse(encoded) as unknown;
  } catch {
    throw new SecurityError("HACKERONE_SNAPSHOT_STORAGE_INVALID");
  }
  const snapshot = normalizeSnapshot(parsed);
  const programLocalRef = requireLocalRef(rowText(row, "program_local_ref"));
  const previous = nullableRowText(row, "previous_snapshot_digest");
  const acceptancePending = rowBoolean(row, "acceptance_pending_evidence");
  if (
    rowText(row, "snapshot_digest") !== snapshot.snapshotDigest ||
    rowText(row, "source") !== snapshot.source ||
    rowText(row, "policy_digest") !== snapshot.policyDigest ||
    previous !== snapshot.previousSnapshotDigest ||
    rowTimestamp(row, "fetched_at") !== snapshot.fetchedAt ||
    encoded !== canonicalJson(snapshot) ||
    sourceForLocalRef(programLocalRef) !== snapshot.source
  )
    throw new SecurityError("HACKERONE_SNAPSHOT_STORAGE_INVALID");
  return storedSnapshot(programLocalRef, snapshot, acceptancePending);
}

function storedProgramMaterial(
  program: HackerOneProgram,
  catalogActive: boolean,
  catalogDriftPending: boolean,
  currentSnapshotDigest: string | null,
): StoredHackerOneProgram {
  const prefix = program.source === API_SOURCE ? "h1a_" : "h1m_";
  const localRef = `${prefix}${sha256(
    canonicalJson({
      domain: "bugbounty-copilot/hackerone-program-ref/v1",
      source: program.source,
      hackerOneId: program.hackerOneId,
    }),
  )}`;
  return Object.freeze({
    localRef,
    program,
    catalogActive,
    catalogDriftPending,
    recordDigest: sha256(canonicalJson(program)),
    currentSnapshotDigest,
  });
}

function catalogPolicyMaterial(program: HackerOneProgram): string {
  return canonicalJson({
    handle: program.handle,
    policy: program.policy,
    programState: program.programState,
    submissionState: program.submissionState,
    offersBounties: program.offersBounties,
    openScope: program.openScope,
    goldStandardSafeHarbor: program.goldStandardSafeHarbor,
  });
}

function catalogTimestamp(
  programs: readonly HackerOneProgram[],
  occurredAt: string | undefined,
): string {
  if (occurredAt !== undefined)
    return requireTimestamp(occurredAt, "HACKERONE_CATALOG_TIME_INVALID");
  const candidate = programs[0]?.synchronizedAt;
  if (
    candidate === undefined ||
    programs.some((program) => program.synchronizedAt !== candidate)
  )
    throw new SecurityError("HACKERONE_CATALOG_TIME_INVALID");
  return requireTimestamp(candidate, "HACKERONE_CATALOG_TIME_INVALID");
}

function storedSnapshot(
  programLocalRef: string,
  snapshot: HackerOnePolicySnapshot,
  acceptancePending = true,
): StoredHackerOnePolicySnapshot {
  return Object.freeze({
    programLocalRef,
    snapshot,
    acceptancePending,
  });
}

function programParameters(
  stored: StoredHackerOneProgram,
): readonly (null | number | string)[] {
  const program = stored.program;
  return [
    stored.localRef,
    program.hackerOneId,
    program.handle,
    program.name,
    program.currency,
    program.policy,
    program.submissionState,
    program.programState,
    program.offersBounties ? 1 : 0,
    program.openScope ? 1 : 0,
    program.goldStandardSafeHarbor ? 1 : 0,
    program.bookmarked ? 1 : 0,
    program.ownReportCount,
    program.ownValidReportCount,
    program.startedAcceptingAt,
    program.createdAt,
    program.updatedAt,
    program.synchronizedAt,
    stored.catalogActive ? 1 : 0,
    stored.catalogDriftPending ? 1 : 0,
    stored.recordDigest,
    stored.currentSnapshotDigest,
  ];
}

function assertSnapshotBinding(
  stored: StoredHackerOneProgram,
  snapshot: HackerOnePolicySnapshot,
): void {
  if (
    stored.program.source !== snapshot.source ||
    stored.program.hackerOneId !== snapshot.program.hackerOneId ||
    stored.program.handle !== snapshot.program.handle
  )
    throw new SecurityError("HACKERONE_SNAPSHOT_PROGRAM_MISMATCH");
  if (snapshot.source === API_SOURCE && !stored.catalogActive)
    throw new SecurityError("HACKERONE_SYNCED_PROGRAM_UNKNOWN");
  if (snapshot.previousSnapshotDigest !== stored.currentSnapshotDigest)
    throw new SecurityError("HACKERONE_SNAPSHOT_PREDECESSOR_MISMATCH");
}

function requireExactRecord(
  value: unknown,
  expectedKeys: readonly string[],
  code: string,
): Readonly<Record<string, unknown>> {
  if (!isPlainRecord(value)) throw new SecurityError(code);
  let actualKeys: string[];
  try {
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== "string"))
      throw new SecurityError(code);
    actualKeys = ownKeys.map(String).sort(compareStrings);
    for (const key of actualKeys) {
      const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable
      )
        throw new SecurityError(code);
    }
  } catch {
    throw new SecurityError(code);
  }
  const expected = [...expectedKeys].sort(compareStrings);
  if (
    actualKeys.length !== expected.length ||
    actualKeys.some((key, index) => key !== expected[index])
  )
    throw new SecurityError(code);
  return value;
}

function isPlainRecord(
  value: unknown,
): value is Readonly<Record<string, unknown>> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    types.isProxy(value)
  )
    return false;
  try {
    return Reflect.getPrototypeOf(value) === Object.prototype;
  } catch {
    return false;
  }
}

function requireText(
  value: unknown,
  minimum: number,
  maximum: number,
  code: string,
): string {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    value.includes("\u0000")
  )
    throw new SecurityError(code);
  return value;
}

function requirePatternText(
  value: unknown,
  pattern: RegExp,
  code: string,
): string {
  if (typeof value !== "string" || !pattern.test(value))
    throw new SecurityError(code);
  return value;
}

function requireNullableText(
  value: unknown,
  minimum: number,
  maximum: number,
  code: string,
): string | null {
  return value === null ? null : requireText(value, minimum, maximum, code);
}

function requireBoolean(value: unknown, code: string): boolean {
  if (typeof value !== "boolean") throw new SecurityError(code);
  return value;
}

function requireNonNegativeInteger(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    throw new SecurityError(code);
  return value;
}

function requireRevision(value: unknown): number {
  return requireNonNegativeInteger(
    value,
    "HACKERONE_INTEGRATION_REVISION_INVALID",
  );
}

function requireTimestamp(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length > 64)
    throw new SecurityError(code);
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  )
    throw new SecurityError(code);
  return value;
}

function requireNullableTimestamp(value: unknown, code: string): string | null {
  return value === null ? null : requireTimestamp(value, code);
}

function requireDigest(value: unknown, code: string): string {
  return requirePatternText(value, SHA256_PATTERN, code);
}

function requireSource(value: unknown): HackerOneDataSource {
  if (value !== API_SOURCE && value !== MANUAL_SOURCE)
    throw new SecurityError("HACKERONE_PROGRAM_SOURCE_INVALID");
  return value;
}

function requireConnectionResult(value: unknown): HackerOneConnectionResult {
  if (!isConnectionResult(value))
    throw new SecurityError("HACKERONE_CONNECTION_STATE_INVALID");
  return value;
}

function isConnectionResult(
  value: unknown,
): value is HackerOneConnectionResult {
  return CONNECTION_RESULTS.some((candidate) => candidate === value);
}

function isSuitabilityReason(
  value: string,
): value is HackerOneSuitabilityReason {
  return SUITABILITY_REASONS.some((candidate) => candidate === value);
}

function requireNullableErrorCode(value: unknown): string | null {
  if (value === null) return null;
  return requirePatternText(
    value,
    ERROR_CODE_PATTERN,
    "HACKERONE_ERROR_CODE_INVALID",
  );
}

function requireLocalRef(value: unknown): string {
  if (
    typeof value !== "string" ||
    (!API_LOCAL_REF_PATTERN.test(value) &&
      !MANUAL_LOCAL_REF_PATTERN.test(value))
  )
    throw new SecurityError("HACKERONE_PROGRAM_REF_INVALID");
  return value;
}

function sourceForLocalRef(localRef: string): HackerOneDataSource {
  if (API_LOCAL_REF_PATTERN.test(localRef)) return API_SOURCE;
  if (MANUAL_LOCAL_REF_PATTERN.test(localRef)) return MANUAL_SOURCE;
  throw new SecurityError("HACKERONE_PROGRAM_REF_INVALID");
}

function rowText(row: Readonly<Record<string, unknown>>, key: string): string {
  const value = row[key];
  if (typeof value !== "string")
    throw new SecurityError("HACKERONE_STORE_ROW_INVALID");
  return value;
}

function nullableRowText(
  row: Readonly<Record<string, unknown>>,
  key: string,
): string | null {
  const value = row[key];
  if (value === null) return null;
  if (typeof value !== "string")
    throw new SecurityError("HACKERONE_STORE_ROW_INVALID");
  return value;
}

function rowInteger(
  row: Readonly<Record<string, unknown>>,
  key: string,
): number {
  const value = row[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value))
    throw new SecurityError("HACKERONE_STORE_ROW_INVALID");
  return value;
}

function rowBoolean(
  row: Readonly<Record<string, unknown>>,
  key: string,
): boolean {
  const value = rowInteger(row, key);
  if (value !== 0 && value !== 1)
    throw new SecurityError("HACKERONE_STORE_ROW_INVALID");
  return value === 1;
}

function rowTimestamp(
  row: Readonly<Record<string, unknown>>,
  key: string,
): string {
  return requireTimestamp(rowText(row, key), "HACKERONE_STORE_ROW_INVALID");
}

function nullableRowTimestamp(
  row: Readonly<Record<string, unknown>>,
  key: string,
): string | null {
  const value = nullableRowText(row, key);
  return value === null
    ? null
    : requireTimestamp(value, "HACKERONE_STORE_ROW_INVALID");
}

function requireStringArray(value: unknown, code: string): readonly string[] {
  const valueEntries = requirePlainArray(value, 32, code);
  const entries: string[] = [];
  const seen = new Set<string>();
  for (const entry of valueEntries) {
    if (typeof entry !== "string" || seen.has(entry))
      throw new SecurityError(code);
    seen.add(entry);
    entries.push(entry);
  }
  return Object.freeze(entries);
}

function requirePlainArray(
  value: unknown,
  maximum: number,
  code: string,
): readonly unknown[] {
  if (!Array.isArray(value) || types.isProxy(value) || value.length > maximum)
    throw new SecurityError(code);
  try {
    if (Reflect.getPrototypeOf(value) !== Array.prototype)
      throw new SecurityError(code);
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes("length"))
      throw new SecurityError(code);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Reflect.getOwnPropertyDescriptor(value, String(index));
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable
      )
        throw new SecurityError(code);
    }
  } catch {
    throw new SecurityError(code);
  }
  return value;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
