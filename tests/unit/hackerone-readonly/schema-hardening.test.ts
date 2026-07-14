import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ControlPlaneDatabase,
  type ControlPlaneDatabase as ControlPlaneDatabaseType,
} from "../../../packages/control-plane/database.js";
import { ControlPlaneStore } from "../../../packages/control-plane/store.js";
import { HackerOneMetadataActionGate } from "../../../packages/external-actions/hackerone-metadata.js";
import {
  HACKERONE_METADATA_READ_CAPABILITY,
  resolveHackerOneMetadataReadRuntime,
} from "../../../packages/hackerone-readonly/runtime.js";
import { HackerOneMetadataStore } from "../../../packages/hackerone-readonly/store.js";

type SchemaMutator = (database: ControlPlaneDatabaseType) => void;

const STORE_TAMPERS = Object.freeze([
  [
    "table SQL and columns",
    (database) => {
      database.run(
        "ALTER TABLE hackerone_request_audit ADD COLUMN unsafe_extra TEXT",
      );
    },
  ],
  [
    "index inventory",
    (database) => {
      database.run(
        `CREATE INDEX hackerone_unexpected_audit_index
           ON hackerone_request_audit(outcome)`,
      );
    },
  ],
  [
    "trigger SQL",
    (database) => {
      database.run("DROP TRIGGER hackerone_request_audit_no_update");
      database.run(
        `CREATE TRIGGER hackerone_request_audit_no_update
           BEFORE UPDATE ON hackerone_request_audit BEGIN SELECT 1; END`,
      );
    },
  ],
] satisfies readonly (readonly [string, SchemaMutator])[]);

const ACTION_TAMPERS = Object.freeze([
  [
    "table SQL and columns",
    (database) => {
      database.run(
        `ALTER TABLE hackerone_metadata_action_attempts
           ADD COLUMN unsafe_extra TEXT`,
      );
    },
  ],
  [
    "index inventory",
    (database) => {
      database.run(
        `CREATE INDEX hackerone_unexpected_attempt_index
           ON hackerone_metadata_action_attempts(status)`,
      );
    },
  ],
  [
    "trigger SQL",
    (database) => {
      database.run("DROP TRIGGER hackerone_metadata_attempt_transition");
      database.run(
        `CREATE TRIGGER hackerone_metadata_attempt_transition
           BEFORE UPDATE ON hackerone_metadata_action_attempts
           BEGIN SELECT 1; END`,
      );
    },
  ],
] satisfies readonly (readonly [string, SchemaMutator])[]);

describe("HackerOne SQLite schema hardening", () => {
  let database: ControlPlaneDatabaseType;
  let controlPlane: ControlPlaneStore;
  let metadata: HackerOneMetadataStore;

  beforeEach(() => {
    database = ControlPlaneDatabase.memory();
    controlPlane = new ControlPlaneStore(database);
    metadata = new HackerOneMetadataStore(database);
  });

  afterEach(() => {
    database.close();
  });

  it.each(STORE_TAMPERS)(
    "rejects metadata-store %s tampering even while its marker remains valid",
    (_label, tamper) => {
      const marker = database.get(
        `SELECT version,schema_digest FROM hackerone_readonly_schema
         WHERE component='metadata_store'`,
      );
      tamper(database);

      expect(
        database.get(
          `SELECT version,schema_digest FROM hackerone_readonly_schema
           WHERE component='metadata_store'`,
        ),
      ).toEqual(marker);
      expect(() => new HackerOneMetadataStore(database)).toThrow(
        "HACKERONE_STORE_SCHEMA_MISMATCH",
      );
    },
  );

  it("rejects a partial metadata namespace instead of adopting or repairing it", () => {
    database.run("DROP TABLE hackerone_readonly_schema");

    expect(() => new HackerOneMetadataStore(database)).toThrow(
      "HACKERONE_STORE_SCHEMA_MISMATCH",
    );
  });

  it.each(ACTION_TAMPERS)(
    "rejects action-gate %s tampering even while its marker remains valid",
    (_label, tamper) => {
      const runtime = enabledRuntime();
      new HackerOneMetadataActionGate(database, controlPlane, runtime);
      const marker = database.get(
        `SELECT version,schema_digest FROM hackerone_metadata_action_schema
         WHERE component='metadata_action_gate'`,
      );
      tamper(database);

      expect(
        database.get(
          `SELECT version,schema_digest FROM hackerone_metadata_action_schema
           WHERE component='metadata_action_gate'`,
        ),
      ).toEqual(marker);
      expect(
        () => new HackerOneMetadataActionGate(database, controlPlane, runtime),
      ).toThrow("HACKERONE_ACTION_SCHEMA_MISMATCH");
    },
  );

  it("rejects a partial action namespace instead of adopting or repairing it", () => {
    database.run(`CREATE TABLE hackerone_metadata_action_attempts (
      authorization_id TEXT PRIMARY KEY
    ) STRICT`);

    expect(
      () =>
        new HackerOneMetadataActionGate(
          database,
          controlPlane,
          enabledRuntime(),
        ),
    ).toThrow("HACKERONE_ACTION_SCHEMA_MISMATCH");
    expect(metadata.getIntegrationState().adapterEnabled).toBe(false);
  });
});

function enabledRuntime() {
  return resolveHackerOneMetadataReadRuntime({
    version: 1,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    external_integrations_enabled: true,
    enabled: true,
    request_budget: {
      max_requests_total: 10,
      requests_per_minute: 5,
      max_concurrency: 1,
    },
  });
}
