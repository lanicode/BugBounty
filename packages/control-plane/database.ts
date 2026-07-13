import { chmod, lstat, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { DatabaseSync, type StatementResultingChanges } from "node:sqlite";
import { sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

interface Migration {
  readonly version: number;
  readonly sql: string;
}

const MIGRATIONS: readonly Migration[] = Object.freeze([
  Object.freeze({
    version: 1,
    sql: `
CREATE TABLE programs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  platform TEXT NOT NULL CHECK (platform IN ('manual','local_mock')),
  status TEXT NOT NULL CHECK (status IN ('available','unavailable')),
  description TEXT NOT NULL,
  program_url TEXT NOT NULL,
  program_type TEXT NOT NULL CHECK (program_type IN ('private','public','simulation')),
  allowed_assets_json TEXT NOT NULL CHECK (json_valid(allowed_assets_json)),
  excluded_assets_json TEXT NOT NULL CHECK (json_valid(excluded_assets_json)),
  last_synchronized_at TEXT,
  current_policy_version INTEGER,
  current_policy_hash TEXT,
  automation_permission TEXT NOT NULL CHECK (automation_permission IN ('allowed','forbidden','unclear')),
  rule_acceptance_status TEXT NOT NULL CHECK (rule_acceptance_status IN ('accepted','pending')),
  notes TEXT NOT NULL,
  lifecycle TEXT NOT NULL CHECK (lifecycle IN ('active','inactive','paused','archived')),
  created_at TEXT NOT NULL
) STRICT;
CREATE TABLE policy_versions (
  program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
  version INTEGER NOT NULL CHECK (version > 0),
  normalized_json TEXT NOT NULL CHECK (json_valid(normalized_json)),
  policy_text TEXT NOT NULL,
  policy_hash TEXT NOT NULL CHECK (length(policy_hash) = 64),
  created_at TEXT NOT NULL,
  PRIMARY KEY (program_id, version),
  UNIQUE (program_id, policy_hash)
) STRICT;
CREATE TABLE policy_acceptances (
  program_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  policy_hash TEXT NOT NULL,
  accepted_by TEXT NOT NULL,
  accepted_at TEXT NOT NULL,
  audit_reference TEXT NOT NULL UNIQUE,
  PRIMARY KEY (program_id, version),
  FOREIGN KEY (program_id, version) REFERENCES policy_versions(program_id, version) ON DELETE RESTRICT
) STRICT;
CREATE TABLE campaigns (
  id TEXT PRIMARY KEY,
  program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
  policy_version INTEGER NOT NULL,
  policy_hash TEXT NOT NULL,
  approved_assets_json TEXT NOT NULL CHECK (json_valid(approved_assets_json)),
  approved_risk_tiers_json TEXT NOT NULL CHECK (json_valid(approved_risk_tiers_json)),
  account_refs_json TEXT NOT NULL CHECK (json_valid(account_refs_json)),
  allowed_action_classes_json TEXT NOT NULL CHECK (json_valid(allowed_action_classes_json)),
  contract_json TEXT NOT NULL CHECK (json_valid(contract_json)),
  state TEXT NOT NULL CHECK (state IN ('draft','awaiting_policy_acceptance','awaiting_campaign_approval','approved','running_simulation','paused','blocked','completed','cancelled')),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  human_approved_by TEXT,
  human_approved_at TEXT,
  last_policy_check_at TEXT,
  kill_switch_status TEXT NOT NULL CHECK (kill_switch_status IN ('clear','engaged')),
  created_at TEXT NOT NULL,
  FOREIGN KEY (program_id, policy_version) REFERENCES policy_versions(program_id, version) ON DELETE RESTRICT
) STRICT;
CREATE TABLE test_identities (
  id TEXT PRIMARY KEY,
  program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
  role TEXT NOT NULL CHECK (role IN ('Owner','Member','External')),
  status TEXT NOT NULL CHECK (status IN ('planned','awaiting_manual_registration','awaiting_email_verification','awaiting_captcha','awaiting_terms_acceptance','ready','session_expired','suspended','retired')),
  email_reference TEXT,
  secret_references_json TEXT NOT NULL CHECK (json_valid(secret_references_json)),
  browser_profile_reference TEXT,
  platform_account_reference TEXT,
  created_at TEXT NOT NULL,
  verified_at TEXT,
  suspended_at TEXT,
  retired_at TEXT,
  last_successful_login_at TEXT,
  human_action_required INTEGER NOT NULL CHECK (human_action_required IN (0,1)),
  organization_ref TEXT,
  owned_object_refs_json TEXT NOT NULL CHECK (json_valid(owned_object_refs_json))
) STRICT;
CREATE TABLE owned_objects (
  object_ref TEXT PRIMARY KEY,
  protected_actual_id_ref TEXT NOT NULL UNIQUE,
  program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
  campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE RESTRICT,
  account_id TEXT NOT NULL REFERENCES test_identities(id) ON DELETE RESTRICT,
  tenant_ref TEXT NOT NULL,
  object_type TEXT NOT NULL,
  canary_hmac TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active','deleted')),
  researcher_controlled INTEGER NOT NULL CHECK (researcher_controlled = 1),
  allowed_actions_json TEXT NOT NULL CHECK (json_valid(allowed_actions_json)),
  expires_at TEXT NOT NULL,
  policy_hash TEXT NOT NULL
) STRICT;
CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('program_policy_acceptance','campaign_contract','account_manual_action','tier_3_action','privacy_alert','report_bundle','triage_response')),
  summary TEXT NOT NULL,
  technical_details TEXT NOT NULL,
  impact TEXT NOT NULL,
  policy_version INTEGER,
  policy_hash TEXT,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open','accepted','rejected')),
  decided_at TEXT,
  decided_by TEXT,
  user_action TEXT,
  audit_reference TEXT NOT NULL UNIQUE,
  payload_hash TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 0)
) STRICT;
CREATE TABLE report_drafts (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE RESTRICT,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft','queued_for_human_review')),
  external_submission_performed INTEGER NOT NULL CHECK (external_submission_performed = 0)
) STRICT;
CREATE TABLE system_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 0),
  updated_at TEXT NOT NULL
) STRICT;
CREATE TABLE control_plane_audit (
  id TEXT PRIMARY KEY,
  occurred_at TEXT NOT NULL,
  action TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  object_reference TEXT,
  payload_hash TEXT NOT NULL
) STRICT;
INSERT INTO system_state(key,value,revision,updated_at)
VALUES ('global_kill_switch','engaged',0,'1970-01-01T00:00:00.000Z');
`,
  }),
  Object.freeze({
    version: 2,
    sql: `
CREATE UNIQUE INDEX policy_versions_exact_binding
ON policy_versions(program_id,version,policy_hash);
CREATE UNIQUE INDEX campaigns_program_binding
ON campaigns(id,program_id);
CREATE UNIQUE INDEX identities_program_binding
ON test_identities(id,program_id);
CREATE TABLE policy_acceptances_v2 (
  program_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  policy_hash TEXT NOT NULL,
  accepted_by TEXT NOT NULL,
  accepted_at TEXT NOT NULL,
  audit_reference TEXT NOT NULL UNIQUE,
  PRIMARY KEY (program_id, version),
  FOREIGN KEY (program_id, version, policy_hash)
    REFERENCES policy_versions(program_id, version, policy_hash)
    ON DELETE RESTRICT
) STRICT;
INSERT INTO policy_acceptances_v2(
  program_id,version,policy_hash,accepted_by,accepted_at,audit_reference
)
SELECT a.program_id,a.version,a.policy_hash,a.accepted_by,a.accepted_at,a.audit_reference
FROM policy_acceptances a
JOIN policy_versions p
  ON p.program_id=a.program_id
 AND p.version=a.version
 AND p.policy_hash=a.policy_hash
JOIN approvals q
  ON q.kind='program_policy_acceptance'
 AND q.status='accepted'
 AND q.policy_version=a.version
 AND q.policy_hash=a.policy_hash
 AND q.summary='Accept ' || a.program_id || ' policy version ' || CAST(a.version AS TEXT)
 AND q.decided_by=a.accepted_by
 AND q.decided_at=a.accepted_at
 AND q.audit_reference=a.audit_reference;
CREATE TABLE migration_v2_guard (
  valid INTEGER NOT NULL CHECK (valid=1)
) STRICT;
INSERT INTO migration_v2_guard(valid)
SELECT CASE
  WHEN (SELECT count(*) FROM policy_acceptances_v2) =
       (SELECT count(*) FROM policy_acceptances)
  THEN 1 ELSE 0 END;
DROP TABLE migration_v2_guard;
DROP TABLE policy_acceptances;
ALTER TABLE policy_acceptances_v2 RENAME TO policy_acceptances;
UPDATE campaigns
SET state='paused',revision=revision+1,human_approved_by=NULL,
    human_approved_at=NULL,kill_switch_status='engaged'
WHERE state IN ('approved','running_simulation');
UPDATE system_state
SET value='engaged',revision=revision+1,
    updated_at='2026-07-13T00:00:00.000Z'
WHERE key='global_kill_switch';
CREATE TRIGGER campaigns_exact_policy_insert
BEFORE INSERT ON campaigns BEGIN
  SELECT RAISE(ABORT,'CAMPAIGN_POLICY_BINDING_INVALID')
  WHERE NOT EXISTS (
    SELECT 1 FROM policy_versions p
    WHERE p.program_id=NEW.program_id
      AND p.version=NEW.policy_version
      AND p.policy_hash=NEW.policy_hash
  );
END;
CREATE TRIGGER campaigns_exact_policy_update
BEFORE UPDATE OF program_id,policy_version,policy_hash ON campaigns BEGIN
  SELECT RAISE(ABORT,'CAMPAIGN_POLICY_BINDING_INVALID')
  WHERE NOT EXISTS (
    SELECT 1 FROM policy_versions p
    WHERE p.program_id=NEW.program_id
      AND p.version=NEW.policy_version
      AND p.policy_hash=NEW.policy_hash
  );
END;
CREATE TRIGGER owned_objects_exact_bindings_insert
BEFORE INSERT ON owned_objects BEGIN
  SELECT RAISE(ABORT,'OWNED_OBJECT_BINDING_INVALID')
  WHERE NOT EXISTS (
    SELECT 1 FROM campaigns c
    WHERE c.id=NEW.campaign_id AND c.program_id=NEW.program_id
  ) OR NOT EXISTS (
    SELECT 1 FROM test_identities i
    WHERE i.id=NEW.account_id AND i.program_id=NEW.program_id
  );
END;
CREATE TRIGGER owned_objects_exact_bindings_update
BEFORE UPDATE OF program_id,campaign_id,account_id ON owned_objects BEGIN
  SELECT RAISE(ABORT,'OWNED_OBJECT_BINDING_INVALID')
  WHERE NOT EXISTS (
    SELECT 1 FROM campaigns c
    WHERE c.id=NEW.campaign_id AND c.program_id=NEW.program_id
  ) OR NOT EXISTS (
    SELECT 1 FROM test_identities i
    WHERE i.id=NEW.account_id AND i.program_id=NEW.program_id
  );
END;
`,
  }),
  Object.freeze({
    version: 3,
    sql: `
ALTER TABLE system_state ADD COLUMN audit_reference TEXT
  REFERENCES control_plane_audit(id) ON DELETE RESTRICT;
UPDATE campaigns
SET state='paused',revision=revision+1,human_approved_by=NULL,
    human_approved_at=NULL,kill_switch_status='engaged',
    last_policy_check_at='2026-07-13T00:00:00.000Z'
WHERE state IN ('approved','running_simulation');
UPDATE system_state
SET value='engaged',revision=revision+1,
    updated_at='2026-07-13T00:00:00.000Z',audit_reference=NULL
WHERE key='global_kill_switch';
CREATE TRIGGER system_state_kill_switch_insert_guard
BEFORE INSERT ON system_state
WHEN NEW.key='global_kill_switch' BEGIN
  SELECT RAISE(ABORT,'KILL_SWITCH_STATE_INVALID')
  WHERE NEW.value NOT IN ('engaged','clear')
     OR NEW.revision < 0
     OR (NEW.value='clear' AND (
       NEW.audit_reference IS NULL OR NOT EXISTS (
         SELECT 1 FROM control_plane_audit a
         WHERE a.id=NEW.audit_reference
           AND a.occurred_at=NEW.updated_at
           AND a.action='kill_switch_change'
           AND a.decision='clear'
           AND a.reason_code='HUMAN_KILL_SWITCH_CLEARED'
           AND a.object_reference IS NOT NULL
       )
     ));
END;
CREATE TRIGGER system_state_kill_switch_update_guard
BEFORE UPDATE OF value,revision,updated_at,audit_reference ON system_state
WHEN NEW.key='global_kill_switch' BEGIN
  SELECT RAISE(ABORT,'KILL_SWITCH_STATE_INVALID')
  WHERE NEW.value NOT IN ('engaged','clear')
     OR NEW.revision < 0
     OR (NEW.value='clear' AND (
       NEW.audit_reference IS NULL OR NOT EXISTS (
         SELECT 1 FROM control_plane_audit a
         WHERE a.id=NEW.audit_reference
           AND a.occurred_at=NEW.updated_at
           AND a.action='kill_switch_change'
           AND a.decision='clear'
           AND a.reason_code='HUMAN_KILL_SWITCH_CLEARED'
           AND a.object_reference IS NOT NULL
       )
     ));
END;
`,
  }),
]);

export const CONTROL_PLANE_SCHEMA_VERSION = MIGRATIONS.length;

export class ControlPlaneDatabase {
  private constructor(private readonly database: DatabaseSync) {}

  public static memory(): ControlPlaneDatabase {
    return ControlPlaneDatabase.initialize(
      new DatabaseSync(":memory:", options()),
    );
  }

  public static async file(path: string): Promise<ControlPlaneDatabase> {
    if (path.length === 0)
      throw new SecurityError("CONTROL_PLANE_PATH_INVALID");
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await chmod(dirname(path), 0o700);
    try {
      if ((await lstat(path)).isSymbolicLink())
        throw new SecurityError("CONTROL_PLANE_PATH_SYMLINK");
    } catch (error) {
      if (
        error instanceof SecurityError ||
        !isNodeError(error) ||
        error.code !== "ENOENT"
      )
        throw error;
    }
    const instance = ControlPlaneDatabase.initialize(
      new DatabaseSync(path, options()),
    );
    await chmod(path, 0o600);
    return instance;
  }

  private static initialize(database: DatabaseSync): ControlPlaneDatabase {
    const instance = new ControlPlaneDatabase(database);
    try {
      instance.configure();
      instance.migrate();
      return instance;
    } catch (error) {
      database.close();
      throw error;
    }
  }

  public close(): void {
    this.database.close();
  }

  public migrationVersion(): number {
    const row = this.get(
      "SELECT MAX(version) AS version FROM schema_migrations",
    );
    return typeof row?.["version"] === "number" ? row["version"] : 0;
  }

  public run(
    sql: string,
    ...parameters: readonly SqlParameter[]
  ): StatementResultingChanges {
    return this.database.prepare(sql).run(...parameters);
  }

  public get(
    sql: string,
    ...parameters: readonly SqlParameter[]
  ): Readonly<Record<string, SqlValue>> | undefined {
    return this.database.prepare(sql).get(...parameters);
  }

  public all(
    sql: string,
    ...parameters: readonly SqlParameter[]
  ): readonly Readonly<Record<string, SqlValue>>[] {
    return this.database.prepare(sql).all(...parameters);
  }

  public transaction<T>(operation: () => T): T {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      this.database.exec("COMMIT");
      return result;
    } catch (error) {
      try {
        this.database.exec("ROLLBACK");
      } catch {
        // The original failure is more useful; fail closed at the caller.
      }
      throw error;
    }
  }

  private configure(): void {
    this.database.exec("PRAGMA foreign_keys=ON");
    this.database.exec("PRAGMA trusted_schema=OFF");
    this.database.exec("PRAGMA synchronous=FULL");
  }

  private migrate(): void {
    this.database.exec(`
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  checksum TEXT NOT NULL,
  applied_at TEXT NOT NULL
) STRICT;
`);
    const applied = this.all(
      "SELECT version,checksum FROM schema_migrations ORDER BY version",
    );
    for (let index = 0; index < applied.length; index += 1) {
      const row = applied[index];
      const expected = MIGRATIONS[index];
      if (
        row === undefined ||
        expected === undefined ||
        row["version"] !== expected.version ||
        row["checksum"] !== migrationChecksum(expected)
      )
        throw new SecurityError("CONTROL_PLANE_MIGRATION_INTEGRITY");
    }
    for (const migration of MIGRATIONS.slice(applied.length)) {
      this.transaction(() => {
        this.database.exec(migration.sql);
        this.run(
          "INSERT INTO schema_migrations(version,checksum,applied_at) VALUES(?,?,?)",
          migration.version,
          migrationChecksum(migration),
          "2026-07-13T00:00:00.000Z",
        );
      });
    }
    if (this.migrationVersion() !== CONTROL_PLANE_SCHEMA_VERSION)
      throw new SecurityError("CONTROL_PLANE_MIGRATION_INCOMPLETE");
  }
}

type SqlParameter = null | number | string | Uint8Array;
type SqlValue = null | number | bigint | string | Uint8Array;

function options(): ConstructorParameters<typeof DatabaseSync>[1] {
  return {
    enableForeignKeyConstraints: true,
    enableDoubleQuotedStringLiterals: false,
    allowExtension: false,
    timeout: 1_000,
    defensive: true,
  };
}

function migrationChecksum(migration: Migration): string {
  return sha256(`${String(migration.version)}\n${migration.sql}`);
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
