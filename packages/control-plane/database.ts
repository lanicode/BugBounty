import { chmod, lstat, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { DatabaseSync, type StatementResultingChanges } from "node:sqlite";
import { sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

interface Migration {
  readonly version: number;
  readonly sql: string;
}

const trustedControlPlaneDatabases = new WeakSet();

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
  Object.freeze({
    version: 4,
    sql: `
CREATE TABLE approvals_v4 (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  kind TEXT NOT NULL CHECK (kind IN ('program_policy_acceptance','campaign_contract','account_manual_action','external_action','tier_3_action','privacy_alert','report_bundle','triage_response')),
  summary TEXT NOT NULL,
  technical_details TEXT NOT NULL,
  impact TEXT NOT NULL,
  policy_version INTEGER,
  policy_hash TEXT CHECK (policy_hash IS NULL OR (length(policy_hash)=64 AND policy_hash NOT GLOB '*[^0-9a-f]*')),
  created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 20 AND 35),
  status TEXT NOT NULL CHECK (status IN ('open','accepted','rejected')),
  decided_at TEXT,
  decided_by TEXT,
  user_action TEXT,
  audit_reference TEXT NOT NULL UNIQUE,
  payload_hash TEXT NOT NULL CHECK (length(payload_hash)=64 AND payload_hash NOT GLOB '*[^0-9a-f]*'),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  CHECK (
    (status='open' AND revision=0 AND decided_at IS NULL AND decided_by IS NULL AND user_action IS NULL)
    OR
    (status IN ('accepted','rejected') AND revision=1 AND decided_at IS NOT NULL AND decided_by IS NOT NULL AND user_action IS NOT NULL)
  )
) STRICT;
INSERT INTO approvals_v4(
  id,kind,summary,technical_details,impact,policy_version,policy_hash,
  created_at,status,decided_at,decided_by,user_action,audit_reference,
  payload_hash,revision
)
SELECT id,kind,summary,technical_details,impact,policy_version,policy_hash,
       created_at,status,decided_at,decided_by,user_action,audit_reference,
       payload_hash,revision
FROM approvals;
CREATE TABLE migration_v4_approval_guard (
  valid INTEGER NOT NULL CHECK (valid=1)
) STRICT;
INSERT INTO migration_v4_approval_guard(valid)
SELECT CASE
  WHEN (SELECT count(*) FROM approvals_v4) =
       (SELECT count(*) FROM approvals)
  THEN 1 ELSE 0 END;
DROP TABLE migration_v4_approval_guard;
DROP TABLE approvals;
ALTER TABLE approvals_v4 RENAME TO approvals;

CREATE UNIQUE INDEX owned_objects_external_action_binding
ON owned_objects(object_ref,program_id,campaign_id,account_id);

CREATE TRIGGER control_plane_audit_update_guard
BEFORE UPDATE ON control_plane_audit BEGIN
  SELECT RAISE(ABORT,'CONTROL_PLANE_AUDIT_IMMUTABLE');
END;
CREATE TRIGGER control_plane_audit_delete_guard
BEFORE DELETE ON control_plane_audit BEGIN
  SELECT RAISE(ABORT,'CONTROL_PLANE_AUDIT_IMMUTABLE');
END;

CREATE TABLE external_action_approval_bindings (
  approval_id TEXT PRIMARY KEY REFERENCES approvals(id) ON DELETE RESTRICT,
  proposal_id TEXT NOT NULL UNIQUE
    CHECK (length(proposal_id) BETWEEN 1 AND 128 AND proposal_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  proposal_digest TEXT NOT NULL UNIQUE
    CHECK (length(proposal_digest)=64 AND proposal_digest NOT GLOB '*[^0-9a-f]*'),
  action_id TEXT NOT NULL CHECK (action_id IN (
    'platform_api_read','test_account_register','email_verification_open',
    'browser_journey_start','target_request','report_submit','triage_response_send'
  )),
  program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
  campaign_id TEXT NOT NULL,
  campaign_revision INTEGER NOT NULL CHECK (campaign_revision >= 0),
  campaign_digest TEXT NOT NULL
    CHECK (length(campaign_digest)=64 AND campaign_digest NOT GLOB '*[^0-9a-f]*'),
  policy_version INTEGER NOT NULL CHECK (policy_version > 0),
  policy_hash TEXT NOT NULL
    CHECK (length(policy_hash)=64 AND policy_hash NOT GLOB '*[^0-9a-f]*'),
  scope_ref TEXT NOT NULL
    CHECK (length(scope_ref) BETWEEN 1 AND 128 AND scope_ref NOT GLOB '*[^A-Za-z0-9_-]*'),
  account_id TEXT,
  account_role TEXT CHECK (account_role IS NULL OR account_role IN ('Owner','Member','External')),
  identity_digest TEXT
    CHECK (identity_digest IS NULL OR (length(identity_digest)=64 AND identity_digest NOT GLOB '*[^0-9a-f]*')),
  object_ref TEXT,
  ownership_digest TEXT
    CHECK (ownership_digest IS NULL OR (length(ownership_digest)=64 AND ownership_digest NOT GLOB '*[^0-9a-f]*')),
  payload_ref TEXT CHECK (payload_ref IS NULL OR length(payload_ref) BETWEEN 1 AND 128),
  operator_id TEXT NOT NULL
    CHECK (length(operator_id) BETWEEN 1 AND 128 AND operator_id NOT GLOB '*[^A-Za-z0-9._@-]*'),
  created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 20 AND 35),
  expires_at TEXT NOT NULL CHECK (length(expires_at) BETWEEN 20 AND 35),
  binding_digest TEXT NOT NULL UNIQUE
    CHECK (length(binding_digest)=64 AND binding_digest NOT GLOB '*[^0-9a-f]*'),
  decision_audit_id TEXT UNIQUE
    REFERENCES control_plane_audit(id) ON DELETE RESTRICT,
  UNIQUE (approval_id,proposal_id,proposal_digest),
  FOREIGN KEY (campaign_id,program_id)
    REFERENCES campaigns(id,program_id) ON DELETE RESTRICT,
  FOREIGN KEY (program_id,policy_version,policy_hash)
    REFERENCES policy_versions(program_id,version,policy_hash) ON DELETE RESTRICT,
  FOREIGN KEY (account_id,program_id)
    REFERENCES test_identities(id,program_id) ON DELETE RESTRICT,
  FOREIGN KEY (object_ref,program_id,campaign_id,account_id)
    REFERENCES owned_objects(object_ref,program_id,campaign_id,account_id) ON DELETE RESTRICT,
  CHECK (
    (account_id IS NULL AND account_role IS NULL AND identity_digest IS NULL)
    OR
    (account_id IS NOT NULL AND account_role IS NOT NULL AND identity_digest IS NOT NULL)
  ),
  CHECK (
    (object_ref IS NULL AND ownership_digest IS NULL)
    OR
    (object_ref IS NOT NULL AND ownership_digest IS NOT NULL AND account_id IS NOT NULL)
  ),
  CHECK (expires_at > created_at)
) STRICT;

CREATE TRIGGER external_action_approval_binding_insert_guard
BEFORE INSERT ON external_action_approval_bindings BEGIN
  SELECT RAISE(ABORT,'EXTERNAL_ACTION_APPROVAL_EVIDENCE_INVALID')
  WHERE NOT EXISTS (
    SELECT 1 FROM approvals q
    WHERE q.id=NEW.approval_id
      AND q.kind='external_action'
      AND q.status='open'
      AND q.revision=0
      AND q.policy_version=NEW.policy_version
      AND q.policy_hash=NEW.policy_hash
      AND q.created_at=NEW.created_at
      AND NEW.decision_audit_id IS NULL
  );
END;
CREATE TRIGGER external_action_approval_binding_update_guard
BEFORE UPDATE OF approval_id,proposal_id,proposal_digest,action_id,program_id,
  campaign_id,campaign_revision,campaign_digest,policy_version,policy_hash,
  scope_ref,account_id,account_role,identity_digest,object_ref,
  ownership_digest,payload_ref,operator_id,created_at,expires_at,binding_digest
ON external_action_approval_bindings BEGIN
  SELECT RAISE(ABORT,'EXTERNAL_ACTION_APPROVAL_BINDING_IMMUTABLE');
END;
CREATE TRIGGER external_action_approval_binding_decision_guard
BEFORE UPDATE OF decision_audit_id ON external_action_approval_bindings BEGIN
  SELECT RAISE(ABORT,'EXTERNAL_ACTION_APPROVAL_EVIDENCE_INVALID')
  WHERE OLD.decision_audit_id IS NOT NULL
     OR NEW.decision_audit_id IS NULL
     OR NOT EXISTS (
       SELECT 1
       FROM approvals q
       JOIN control_plane_audit a ON a.id=NEW.decision_audit_id
       WHERE q.id=NEW.approval_id
         AND q.kind='external_action'
         AND q.status='accepted'
         AND q.revision=1
         AND q.policy_version=NEW.policy_version
         AND q.policy_hash=NEW.policy_hash
         AND q.decided_by=NEW.operator_id
         AND q.decided_at=a.occurred_at
         AND a.action='approval_decision'
         AND a.decision='accepted'
         AND a.reason_code='HUMAN_APPROVAL_DECISION'
         AND a.object_reference=q.id
         AND a.payload_hash=q.payload_hash
     );
END;
CREATE TRIGGER external_action_approval_binding_delete_guard
BEFORE DELETE ON external_action_approval_bindings BEGIN
  SELECT RAISE(ABORT,'EXTERNAL_ACTION_APPROVAL_BINDING_IMMUTABLE');
END;

CREATE TABLE external_action_attempts (
  authorization_id TEXT PRIMARY KEY
    CHECK (length(authorization_id) BETWEEN 1 AND 128 AND authorization_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  approval_id TEXT NOT NULL UNIQUE,
  proposal_id TEXT NOT NULL UNIQUE
    CHECK (length(proposal_id) BETWEEN 1 AND 128 AND proposal_id NOT GLOB '*[^A-Za-z0-9_-]*'),
  proposal_digest TEXT NOT NULL UNIQUE
    CHECK (length(proposal_digest)=64 AND proposal_digest NOT GLOB '*[^0-9a-f]*'),
  action_id TEXT NOT NULL CHECK (action_id IN (
    'platform_api_read','test_account_register','email_verification_open',
    'browser_journey_start','target_request','report_submit','triage_response_send'
  )),
  program_id TEXT NOT NULL REFERENCES programs(id) ON DELETE RESTRICT,
  campaign_id TEXT NOT NULL,
  campaign_revision INTEGER NOT NULL CHECK (campaign_revision >= 0),
  campaign_digest TEXT NOT NULL
    CHECK (length(campaign_digest)=64 AND campaign_digest NOT GLOB '*[^0-9a-f]*'),
  policy_version INTEGER NOT NULL CHECK (policy_version > 0),
  policy_hash TEXT NOT NULL
    CHECK (length(policy_hash)=64 AND policy_hash NOT GLOB '*[^0-9a-f]*'),
  scope_ref TEXT NOT NULL
    CHECK (length(scope_ref) BETWEEN 1 AND 128 AND scope_ref NOT GLOB '*[^A-Za-z0-9_-]*'),
  account_id TEXT,
  account_role TEXT CHECK (account_role IS NULL OR account_role IN ('Owner','Member','External')),
  identity_digest TEXT
    CHECK (identity_digest IS NULL OR (length(identity_digest)=64 AND identity_digest NOT GLOB '*[^0-9a-f]*')),
  object_ref TEXT,
  ownership_digest TEXT
    CHECK (ownership_digest IS NULL OR (length(ownership_digest)=64 AND ownership_digest NOT GLOB '*[^0-9a-f]*')),
  payload_ref TEXT CHECK (payload_ref IS NULL OR length(payload_ref) BETWEEN 1 AND 128),
  operator_id TEXT NOT NULL
    CHECK (length(operator_id) BETWEEN 1 AND 128 AND operator_id NOT GLOB '*[^A-Za-z0-9._@-]*'),
  evidence_digest TEXT NOT NULL UNIQUE
    CHECK (length(evidence_digest)=64 AND evidence_digest NOT GLOB '*[^0-9a-f]*'),
  units INTEGER NOT NULL CHECK (units=1),
  status TEXT NOT NULL CHECK (status IN ('reserved','running','succeeded','failed','aborted')),
  reserved_at TEXT NOT NULL CHECK (length(reserved_at) BETWEEN 20 AND 35),
  started_at TEXT CHECK (started_at IS NULL OR length(started_at) BETWEEN 20 AND 35),
  finished_at TEXT CHECK (finished_at IS NULL OR length(finished_at) BETWEEN 20 AND 35),
  revision INTEGER NOT NULL CHECK (revision >= 0),
  reservation_audit_id TEXT NOT NULL UNIQUE
    REFERENCES control_plane_audit(id) ON DELETE RESTRICT,
  FOREIGN KEY (approval_id,proposal_id,proposal_digest)
    REFERENCES external_action_approval_bindings(approval_id,proposal_id,proposal_digest)
    ON DELETE RESTRICT,
  FOREIGN KEY (campaign_id,program_id)
    REFERENCES campaigns(id,program_id) ON DELETE RESTRICT,
  FOREIGN KEY (program_id,policy_version,policy_hash)
    REFERENCES policy_versions(program_id,version,policy_hash) ON DELETE RESTRICT,
  FOREIGN KEY (account_id,program_id)
    REFERENCES test_identities(id,program_id) ON DELETE RESTRICT,
  FOREIGN KEY (object_ref,program_id,campaign_id,account_id)
    REFERENCES owned_objects(object_ref,program_id,campaign_id,account_id) ON DELETE RESTRICT,
  CHECK (
    (account_id IS NULL AND account_role IS NULL AND identity_digest IS NULL)
    OR
    (account_id IS NOT NULL AND account_role IS NOT NULL AND identity_digest IS NOT NULL)
  ),
  CHECK (
    (object_ref IS NULL AND ownership_digest IS NULL)
    OR
    (object_ref IS NOT NULL AND ownership_digest IS NOT NULL AND account_id IS NOT NULL)
  ),
  CHECK (
    (status='reserved' AND revision=0 AND started_at IS NULL AND finished_at IS NULL)
    OR
    (status='running' AND revision=1 AND started_at IS NOT NULL
      AND started_at>=reserved_at AND finished_at IS NULL)
    OR
    (status='aborted' AND revision=1 AND started_at IS NULL
      AND finished_at IS NOT NULL AND finished_at>=reserved_at)
    OR
    (status IN ('succeeded','failed','aborted') AND revision=2
      AND started_at IS NOT NULL AND started_at>=reserved_at
      AND finished_at IS NOT NULL AND finished_at>=started_at)
  )
) STRICT;

CREATE TRIGGER external_action_attempt_insert_guard
BEFORE INSERT ON external_action_attempts BEGIN
  SELECT RAISE(ABORT,'EXTERNAL_ACTION_ATTEMPT_INITIAL_STATE_INVALID')
  WHERE NEW.status<>'reserved' OR NEW.revision<>0
     OR NEW.started_at IS NOT NULL OR NEW.finished_at IS NOT NULL;
  SELECT RAISE(ABORT,'EXTERNAL_ACTION_ATTEMPT_BINDING_INVALID')
  WHERE NOT EXISTS (
    SELECT 1
    FROM external_action_approval_bindings b
    JOIN approvals q ON q.id=b.approval_id
    WHERE b.approval_id=NEW.approval_id
      AND b.proposal_id=NEW.proposal_id
      AND b.proposal_digest=NEW.proposal_digest
      AND b.action_id=NEW.action_id
      AND b.program_id=NEW.program_id
      AND b.campaign_id=NEW.campaign_id
      AND b.campaign_revision=NEW.campaign_revision
      AND b.campaign_digest=NEW.campaign_digest
      AND b.policy_version=NEW.policy_version
      AND b.policy_hash=NEW.policy_hash
      AND b.scope_ref=NEW.scope_ref
      AND b.account_id IS NEW.account_id
      AND b.account_role IS NEW.account_role
      AND b.identity_digest IS NEW.identity_digest
      AND b.object_ref IS NEW.object_ref
      AND b.ownership_digest IS NEW.ownership_digest
      AND b.payload_ref IS NEW.payload_ref
      AND b.operator_id=NEW.operator_id
      AND b.decision_audit_id IS NOT NULL
      AND q.kind='external_action'
      AND q.status='accepted'
      AND q.revision=1
      AND q.decided_by=b.operator_id
      AND NEW.reserved_at>=b.created_at
      AND NEW.reserved_at<b.expires_at
  );
  SELECT RAISE(ABORT,'EXTERNAL_ACTION_RESERVATION_AUDIT_INVALID')
  WHERE NOT EXISTS (
    SELECT 1 FROM control_plane_audit a
    WHERE a.id=NEW.reservation_audit_id
      AND a.occurred_at=NEW.reserved_at
      AND a.action='external_action_authorization'
      AND a.decision='reserved'
      AND a.reason_code='EXTERNAL_ACTION_RESERVED'
      AND a.object_reference=NEW.authorization_id
      AND a.payload_hash=NEW.evidence_digest
  );
END;
CREATE TRIGGER external_action_attempt_immutable_fields_guard
BEFORE UPDATE OF authorization_id,approval_id,proposal_id,proposal_digest,
  action_id,program_id,campaign_id,campaign_revision,campaign_digest,
  policy_version,policy_hash,scope_ref,account_id,account_role,identity_digest,
  object_ref,ownership_digest,payload_ref,operator_id,evidence_digest,units,
  reserved_at,reservation_audit_id
ON external_action_attempts BEGIN
  SELECT RAISE(ABORT,'EXTERNAL_ACTION_ATTEMPT_BINDING_IMMUTABLE');
END;
CREATE TRIGGER external_action_attempt_transition_guard
BEFORE UPDATE OF status,started_at,finished_at,revision
ON external_action_attempts BEGIN
  SELECT RAISE(ABORT,'EXTERNAL_ACTION_ATTEMPT_TRANSITION_INVALID')
  WHERE NOT (
    (OLD.status='reserved' AND OLD.revision=0
      AND NEW.status='running' AND NEW.revision=1
      AND NEW.started_at IS NOT NULL AND NEW.started_at>=OLD.reserved_at
      AND NEW.finished_at IS NULL)
    OR
    (OLD.status='reserved' AND OLD.revision=0
      AND NEW.status='aborted' AND NEW.revision=1
      AND NEW.started_at IS NULL AND NEW.finished_at IS NOT NULL
      AND NEW.finished_at>=OLD.reserved_at)
    OR
    (OLD.status='running' AND OLD.revision=1
      AND NEW.status IN ('succeeded','failed','aborted') AND NEW.revision=2
      AND NEW.started_at=OLD.started_at AND NEW.finished_at IS NOT NULL
      AND NEW.finished_at>=OLD.started_at)
  );
END;
CREATE TRIGGER external_action_attempt_delete_guard
BEFORE DELETE ON external_action_attempts BEGIN
  SELECT RAISE(ABORT,'EXTERNAL_ACTION_ATTEMPT_IMMUTABLE');
END;

UPDATE system_state
SET value='engaged',revision=revision+1,
    updated_at='2026-07-13T00:00:00.000Z',audit_reference=NULL
WHERE key='global_kill_switch';
UPDATE campaigns
SET state='paused',revision=revision+1,human_approved_by=NULL,
    human_approved_at=NULL,kill_switch_status='engaged',
    last_policy_check_at='2026-07-13T00:00:00.000Z'
WHERE state IN ('approved','running_simulation');
`,
  }),
]);

export const CONTROL_PLANE_SCHEMA_VERSION = MIGRATIONS.length;

export class ControlPlaneDatabase {
  private constructor(private readonly database: DatabaseSync) {
    trustedControlPlaneDatabases.add(this);
    Object.freeze(this);
  }

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
      if (isThenable(result))
        throw new SecurityError("CONTROL_PLANE_TRANSACTION_ASYNC");
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

Object.freeze(ControlPlaneDatabase.prototype);
Object.freeze(ControlPlaneDatabase);

export function isTrustedControlPlaneDatabase(
  value: unknown,
): value is ControlPlaneDatabase {
  if (typeof value !== "object" || value === null) return false;
  try {
    return (
      trustedControlPlaneDatabases.has(value) &&
      Reflect.getPrototypeOf(value) === ControlPlaneDatabase.prototype
    );
  } catch {
    return false;
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

function isThenable(value: unknown): boolean {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function")
  )
    return false;
  try {
    return typeof Reflect.get(value, "then") === "function";
  } catch {
    return true;
  }
}
