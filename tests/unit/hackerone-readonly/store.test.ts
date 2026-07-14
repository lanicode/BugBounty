import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ControlPlaneDatabase,
  type ControlPlaneDatabase as ControlPlaneDatabaseType,
} from "../../../packages/control-plane/database.js";
import { ControlPlaneStore } from "../../../packages/control-plane/store.js";
import { canonicalJson, sha256 } from "../../../packages/shared/canonical.js";
import { createHackerOnePolicySnapshot } from "../../../packages/hackerone-readonly/snapshot.js";
import { HackerOneMetadataStore } from "../../../packages/hackerone-readonly/store.js";
import type {
  HackerOneDataSource,
  HackerOnePolicySnapshot,
  HackerOneProgram,
  HackerOneScopeExclusion,
  HackerOneStructuredScope,
} from "../../../packages/hackerone-readonly/types.js";
import {
  campaign,
  controlPlanePolicy,
  programInput,
} from "../../fixtures/control-plane.factory.js";

const FIRST_SYNC = "2026-07-14T10:00:00.000Z";
const SECOND_SYNC = "2026-07-14T11:00:00.000Z";

function program(overrides: Partial<HackerOneProgram> = {}): HackerOneProgram {
  return Object.freeze({
    hackerOneId: "synthetic-program-001",
    handle: "synthetic_program",
    name: "Synthetic Program",
    currency: "USD",
    policy: "Synthetic local policy. Automation permission is unclear.",
    submissionState: "open",
    programState: "public_mode",
    offersBounties: true,
    openScope: false,
    goldStandardSafeHarbor: true,
    bookmarked: false,
    ownReportCount: 2,
    ownValidReportCount: 1,
    startedAcceptingAt: "2026-01-01T00:00:00.000Z",
    createdAt: "2025-01-01T00:00:00.000Z",
    updatedAt: "2026-07-01T00:00:00.000Z",
    synchronizedAt: FIRST_SYNC,
    source: "hackerone_api_authenticated",
    ...overrides,
  });
}

function scope(
  overrides: Partial<HackerOneStructuredScope> = {},
): HackerOneStructuredScope {
  const assetIdentifier =
    overrides.assetIdentifier ?? "https://synthetic-target.invalid";
  return Object.freeze({
    id: "synthetic-scope-001",
    assetType: "URL",
    assetIdentifier,
    assetIdentifierDigest: sha256(assetIdentifier),
    eligibleForSubmission: true,
    eligibleForBounty: true,
    instruction: "Metadata only; never contact this synthetic asset.",
    maximumSeverity: "high",
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: null,
    confidentialityRequirement: "high",
    integrityRequirement: null,
    availabilityRequirement: null,
    ...overrides,
  });
}

function exclusion(
  overrides: Partial<HackerOneScopeExclusion> = {},
): HackerOneScopeExclusion {
  return Object.freeze({
    id: "synthetic-exclusion-001",
    category: "Synthetic excluded activity",
    details: "No requests are permitted by this local fixture.",
    createdAt: null,
    updatedAt: "2026-07-01T00:00:00.000Z",
    ...overrides,
  });
}

function snapshot(input: {
  readonly program: HackerOneProgram;
  readonly fetchedAt: string;
  readonly previousSnapshotDigest: string | null;
  readonly scopes?: readonly HackerOneStructuredScope[];
  readonly exclusions?: readonly HackerOneScopeExclusion[];
}): HackerOnePolicySnapshot {
  return createHackerOnePolicySnapshot({
    program: input.program,
    structuredScopes: input.scopes ?? [scope()],
    scopeExclusions: input.exclusions ?? [exclusion()],
    fetchedAt: input.fetchedAt,
    previousSnapshotDigest: input.previousSnapshotDigest,
  });
}

function refs(
  store: HackerOneMetadataStore,
  source: HackerOneDataSource,
  includeInactive = false,
): readonly string[] {
  return store
    .listPrograms(source, includeInactive)
    .map((record) => record.localRef);
}

function insertApprovedCampaign(
  database: ControlPlaneDatabaseType,
  id: string,
  policyHash: string,
): void {
  const active = campaign({
    id,
    policyHash,
    contract: Object.freeze({
      ...campaign().contract,
      policyHash,
    }),
    state: "approved",
    revision: 2,
    humanApprovedBy: "synthetic-reviewer",
    humanApprovedAt: FIRST_SYNC,
  });
  database.run(
    `INSERT INTO campaigns(
      id,program_id,policy_version,policy_hash,approved_assets_json,
      approved_risk_tiers_json,account_refs_json,allowed_action_classes_json,
      contract_json,state,revision,human_approved_by,human_approved_at,
      last_policy_check_at,kill_switch_status,created_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    active.id,
    active.programId,
    active.policyVersion,
    active.policyHash,
    canonicalJson([...active.approvedAssets]),
    canonicalJson([...active.approvedRiskTiers]),
    canonicalJson([...active.accountRefs]),
    canonicalJson([...active.allowedActionClasses]),
    canonicalJson(active.contract),
    active.state,
    active.revision,
    active.humanApprovedBy,
    active.humanApprovedAt,
    active.lastPolicyCheckAt,
    active.killSwitchStatus,
    active.createdAt,
  );
}

describe("HackerOneMetadataStore", () => {
  let database: ControlPlaneDatabaseType;
  let store: HackerOneMetadataStore;

  beforeEach(() => {
    database = ControlPlaneDatabase.memory();
    store = new HackerOneMetadataStore(database);
  });

  afterEach(() => {
    database.close();
  });

  it("initializes idempotent STRICT tables with a fail-closed disabled state", () => {
    const second = new HackerOneMetadataStore(database);

    expect(second.getIntegrationState()).toEqual({
      adapterEnabled: false,
      adapterGeneration: 0,
      lastConnectionTestAt: null,
      lastSuccessfulConnectionAt: null,
      lastConnectionResult: null,
      lastSynchronizationAt: null,
      lastSynchronizationResult: null,
      lastErrorCode: null,
      selectedProgramRef: null,
      selectedProgramSource: null,
      revision: 0,
    });
    const tables = database
      .all(
        `SELECT name,sql FROM sqlite_schema
         WHERE type='table' AND name LIKE 'hackerone_%' ORDER BY name`,
      )
      .map((row) => ({ name: row["name"], sql: row["sql"] }));
    expect(tables.map((table) => table.name)).toEqual([
      "hackerone_api_programs",
      "hackerone_campaign_bindings",
      "hackerone_integration_state",
      "hackerone_manual_programs",
      "hackerone_policy_snapshots",
      "hackerone_readonly_schema",
      "hackerone_request_audit",
    ]);
    expect(tables.every((table) => String(table.sql).endsWith(" STRICT"))).toBe(
      true,
    );
  });

  it("rejects database lookalikes and proxy inputs", () => {
    expect(
      () =>
        new HackerOneMetadataStore({} as unknown as ControlPlaneDatabaseType),
    ).toThrow("HACKERONE_STORE_DATABASE_UNTRUSTED");

    const proxied = new Proxy(program(), {});
    expect(() => store.replaceAuthenticatedApiCatalog([proxied])).toThrow(
      "HACKERONE_PROGRAM_INVALID",
    );

    let getterInvoked = false;
    const accessorInput: Record<string, unknown> = { ...program() };
    Object.defineProperty(accessorInput, "policy", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        throw new Error("SYNTHETIC_ACCESSOR_MUST_NOT_RUN");
      },
    });
    expect(() =>
      store.replaceAuthenticatedApiCatalog([
        accessorInput as unknown as HackerOneProgram,
      ]),
    ).toThrow("HACKERONE_PROGRAM_INVALID");
    expect(getterInvoked).toBe(false);
  });

  it("persists revision-bound status without accepting free-form errors", () => {
    expect(() => store.setAdapterEnabled(0, true)).toThrow(
      "SIGNED_HACKERONE_ACTIVATION_REQUIRED",
    );

    const connected = store.recordConnectionTest({
      expectedRevision: 0,
      occurredAt: FIRST_SYNC,
      result: "connected",
      errorCode: null,
    });
    expect(connected).toMatchObject({
      lastConnectionTestAt: FIRST_SYNC,
      lastConnectionResult: "connected",
      lastErrorCode: null,
      revision: 1,
    });

    const synchronized = store.recordSynchronization({
      expectedRevision: 1,
      occurredAt: SECOND_SYNC,
      result: "succeeded",
      errorCode: null,
    });
    expect(synchronized).toMatchObject({
      lastSynchronizationAt: SECOND_SYNC,
      lastSynchronizationResult: "succeeded",
      revision: 2,
    });
    expect(() => store.setAdapterEnabled(1, false)).toThrow(
      "HACKERONE_INTEGRATION_REVISION_CONFLICT",
    );
    expect(() =>
      store.recordConnectionTest({
        expectedRevision: 2,
        occurredAt: SECOND_SYNC,
        result: "unauthorized",
        errorCode: "contains lower-case or secret",
      }),
    ).toThrow("HACKERONE_ERROR_CODE_INVALID");
  });

  it("keeps API and manual records separated behind opaque local references", () => {
    const apiProgram = program();
    const [apiStored] = store.replaceAuthenticatedApiCatalog([apiProgram]);
    const manualStored = store.insertManualProgram(
      program({ source: "manual_unverified" }),
    );

    expect(apiStored).toBeDefined();
    expect(apiStored!.localRef).toMatch(/^h1a_[0-9a-f]{64}$/u);
    expect(manualStored.localRef).toMatch(/^h1m_[0-9a-f]{64}$/u);
    expect(apiStored!.localRef).not.toBe(manualStored.localRef);
    expect(store.listPrograms()).toHaveLength(2);
    expect(store.getSyncedProgram(apiStored!.localRef)).toEqual(apiProgram);
    expect(() => store.getSyncedProgram(manualStored.localRef)).toThrow(
      "HACKERONE_SYNCED_PROGRAM_SOURCE_INVALID",
    );
    expect(() => store.getSyncedProgram(apiProgram.handle)).toThrow(
      "HACKERONE_PROGRAM_REF_INVALID",
    );
  });

  it("atomically replaces the authenticated catalog and retains it on failure", () => {
    const first = program();
    const second = program({
      hackerOneId: "synthetic-program-002",
      handle: "synthetic_program_two",
      name: "Synthetic Program Two",
    });
    const original = store.replaceAuthenticatedApiCatalog([first, second]);
    const originalRefs = refs(store, "hackerone_api_authenticated");

    const conflicting = program({
      hackerOneId: "synthetic-program-003",
      handle: first.handle,
      name: "Conflicting Reused Handle",
    });
    expect(() => store.replaceAuthenticatedApiCatalog([conflicting])).toThrow(
      "HACKERONE_API_CATALOG_WRITE_FAILED",
    );
    expect(refs(store, "hackerone_api_authenticated")).toEqual(originalRefs);
    expect(store.listPrograms("hackerone_api_authenticated")).toHaveLength(2);

    const replacement = program({
      ...second,
      name: "Synthetic Program Two Updated",
      synchronizedAt: SECOND_SYNC,
    });
    const active = store.replaceAuthenticatedApiCatalog([replacement]);
    expect(active).toHaveLength(1);
    expect(active[0]!.program.name).toBe("Synthetic Program Two Updated");
    expect(
      store.listPrograms("hackerone_api_authenticated", true),
    ).toHaveLength(2);
    expect(() => store.getSyncedProgram(original[0]!.localRef)).toThrow(
      "HACKERONE_SYNCED_PROGRAM_UNKNOWN",
    );
  });

  it("commits catalog and synchronization state atomically", () => {
    const original = program();
    const replacement = program({
      hackerOneId: "synthetic-program-atomic-replacement",
      handle: "synthetic_program_atomic_replacement",
      name: "Synthetic Atomic Replacement",
      synchronizedAt: SECOND_SYNC,
    });
    const [storedOriginal] = store.replaceAuthenticatedApiCatalog([original]);
    database.run(
      `CREATE TRIGGER synthetic_fail_catalog_sync_state
       BEFORE UPDATE ON hackerone_integration_state
       BEGIN SELECT RAISE(ABORT,'synthetic catalog state failure'); END`,
    );

    expect(() =>
      store.commitAuthenticatedApiCatalogSynchronization([replacement], {
        expectedRevision: 1,
        occurredAt: SECOND_SYNC,
        result: "succeeded",
        errorCode: null,
      }),
    ).toThrow("HACKERONE_API_CATALOG_WRITE_FAILED");
    expect(store.listPrograms("hackerone_api_authenticated")).toEqual([
      storedOriginal,
    ]);
    expect(store.getIntegrationState()).toMatchObject({
      revision: 1,
      lastSynchronizationAt: FIRST_SYNC,
      lastSynchronizationResult: "succeeded",
    });
  });

  it("commits snapshot, selection, and synchronization state atomically", () => {
    const [storedProgram] = store.replaceAuthenticatedApiCatalog([program()]);
    const candidate = snapshot({
      program: program(),
      fetchedAt: FIRST_SYNC,
      previousSnapshotDigest: null,
    });
    database.run(
      `CREATE TRIGGER synthetic_fail_selected_sync_state
       BEFORE UPDATE ON hackerone_integration_state
       BEGIN SELECT RAISE(ABORT,'synthetic selected state failure'); END`,
    );

    expect(() =>
      store.commitSelectedProgramSynchronization(
        storedProgram!.localRef,
        candidate,
        {
          expectedRevision: 1,
          occurredAt: FIRST_SYNC,
          result: "succeeded",
          errorCode: null,
        },
      ),
    ).toThrow("HACKERONE_SNAPSHOT_WRITE_FAILED");
    expect(store.getCurrentSnapshot(storedProgram!.localRef)).toBeUndefined();
    expect(store.listSnapshots(storedProgram!.localRef)).toEqual([]);
    expect(store.getIntegrationState()).toMatchObject({
      selectedProgramRef: null,
      selectedProgramSource: null,
      revision: 1,
      lastSynchronizationAt: FIRST_SYNC,
    });
  });

  it("commits manual program and snapshot atomically", () => {
    const manualProgram = program({ source: "manual_unverified" });
    const manualSnapshot = snapshot({
      program: manualProgram,
      fetchedAt: FIRST_SYNC,
      previousSnapshotDigest: null,
    });
    database.run(
      `CREATE TRIGGER synthetic_fail_manual_snapshot
       BEFORE INSERT ON hackerone_policy_snapshots
       BEGIN SELECT RAISE(ABORT,'synthetic manual snapshot failure'); END`,
    );

    expect(() =>
      store.commitManualImport(manualProgram, manualSnapshot),
    ).toThrow("HACKERONE_MANUAL_IMPORT_WRITE_FAILED");
    expect(store.listPrograms("manual_unverified")).toEqual([]);
    expect(
      database.get(
        "SELECT snapshot_digest FROM hackerone_policy_snapshots LIMIT 1",
      ),
    ).toBeUndefined();
  });

  it("refuses unnormalized records and extra fields instead of storing raw data", () => {
    const withRawResponse = {
      ...program(),
      rawResponse: { authorization: "synthetic-secret-must-not-persist" },
    } as unknown as HackerOneProgram;
    expect(() =>
      store.replaceAuthenticatedApiCatalog([withRawResponse]),
    ).toThrow("HACKERONE_PROGRAM_INVALID");
    expect(store.listPrograms()).toEqual([]);
  });

  it("commits immutable snapshot content and keeps every version pending", () => {
    const [storedProgram] = store.replaceAuthenticatedApiCatalog([program()]);
    const first = snapshot({
      program: program(),
      fetchedAt: FIRST_SYNC,
      previousSnapshotDigest: null,
    });
    const committed = store.commitSnapshot(storedProgram!.localRef, first);

    expect(committed.acceptancePending).toBe(true);
    expect(store.getCurrentSnapshot(storedProgram!.localRef)).toEqual(
      committed,
    );
    expect(store.listAcceptancePendingSnapshots()).toEqual([committed]);
    expect(() =>
      database.run(
        "UPDATE hackerone_policy_snapshots SET policy_digest=? WHERE snapshot_digest=?",
        "0".repeat(64),
        first.snapshotDigest,
      ),
    ).toThrow("HACKERONE_SNAPSHOT_IMMUTABLE");
    expect(() =>
      database.run(
        "DELETE FROM hackerone_policy_snapshots WHERE snapshot_digest=?",
        first.snapshotDigest,
      ),
    ).toThrow("HACKERONE_SNAPSHOT_IMMUTABLE");
  });

  it("keeps snapshots pending and immutable without signed control-plane evidence", () => {
    const [storedProgram] = store.replaceAuthenticatedApiCatalog([program()]);
    const first = snapshot({
      program: program(),
      fetchedAt: FIRST_SYNC,
      previousSnapshotDigest: null,
    });
    store.commitSnapshot(storedProgram!.localRef, first);
    const updatedProgram = program({
      policy: "Changed synthetic policy requiring fresh local acceptance.",
      synchronizedAt: SECOND_SYNC,
      updatedAt: SECOND_SYNC,
    });
    const second = snapshot({
      program: updatedProgram,
      fetchedAt: SECOND_SYNC,
      previousSnapshotDigest: first.snapshotDigest,
    });
    store.commitSnapshot(storedProgram!.localRef, second);

    expect(() =>
      database.run(
        `UPDATE hackerone_policy_snapshots SET acceptance_pending=0
         WHERE snapshot_digest=?`,
        second.snapshotDigest,
      ),
    ).toThrow("HACKERONE_SNAPSHOT_IMMUTABLE");
    expect(store.getSnapshot(second.snapshotDigest)?.acceptancePending).toBe(
      true,
    );
    expect(store.getSnapshot(first.snapshotDigest)?.acceptancePending).toBe(
      true,
    );
    expect(
      store
        .listAcceptancePendingSnapshots(storedProgram!.localRef)
        .map((record) => record.snapshot.snapshotDigest),
    ).toEqual([first.snapshotDigest, second.snapshotDigest]);
  });

  it("retains the current snapshot when a later snapshot is invalid", () => {
    const [storedProgram] = store.replaceAuthenticatedApiCatalog([program()]);
    const first = snapshot({
      program: program(),
      fetchedAt: FIRST_SYNC,
      previousSnapshotDigest: null,
    });
    store.commitSnapshot(storedProgram!.localRef, first);
    const invalidSuccessor = snapshot({
      program: program({ synchronizedAt: SECOND_SYNC }),
      fetchedAt: SECOND_SYNC,
      previousSnapshotDigest: "0".repeat(64),
    });

    expect(() =>
      store.commitSnapshot(storedProgram!.localRef, invalidSuccessor),
    ).toThrow("HACKERONE_SNAPSHOT_PREDECESSOR_MISMATCH");
    expect(
      store.getCurrentSnapshot(storedProgram!.localRef)?.snapshot
        .snapshotDigest,
    ).toBe(first.snapshotDigest);
    expect(store.listSnapshots(storedProgram!.localRef)).toHaveLength(1);
  });

  it("binds persisted selection to a known source and opaque reference", () => {
    const [storedProgram] = store.replaceAuthenticatedApiCatalog([program()]);
    const selected = store.selectProgram(1, storedProgram!.localRef);
    expect(selected).toMatchObject({
      selectedProgramRef: storedProgram!.localRef,
      selectedProgramSource: "hackerone_api_authenticated",
      revision: 2,
    });
    const cleared = store.selectProgram(2, null);
    expect(cleared).toMatchObject({
      selectedProgramRef: null,
      selectedProgramSource: null,
      revision: 3,
    });
  });

  it("persists only redacted immutable request-audit metadata", () => {
    const event = store.recordRequestAudit({
      requestId: "a".repeat(32),
      actionClass: "HACKERONE_METADATA_READ",
      endpointClass: "programs",
      outcome: "response",
      statusCode: 200,
      durationMs: 12,
    });

    expect(event).toEqual({
      sequence: 1,
      requestId: "a".repeat(32),
      actionClass: "HACKERONE_METADATA_READ",
      endpointClass: "programs",
      outcome: "response",
      statusCode: 200,
      durationMs: 12,
    });
    expect(store.listRequestAudit()).toEqual([event]);
    expect(Object.keys(event).sort()).toEqual([
      "actionClass",
      "durationMs",
      "endpointClass",
      "outcome",
      "requestId",
      "sequence",
      "statusCode",
    ]);
    expect(() =>
      database.run(
        "UPDATE hackerone_request_audit SET outcome='changed' WHERE sequence=1",
      ),
    ).toThrow("HACKERONE_REQUEST_AUDIT_IMMUTABLE");
    expect(() =>
      database.run("DELETE FROM hackerone_request_audit WHERE sequence=1"),
    ).toThrow("HACKERONE_REQUEST_AUDIT_IMMUTABLE");
    expect(() =>
      store.recordRequestAudit({
        ...event,
        endpointClass: "weaknesses",
      }),
    ).toThrow("HACKERONE_REQUEST_AUDIT_INVALID");
  });

  it("marks catalog policy changes and missing programs pending and pauses every bound active campaign", () => {
    const core = new ControlPlaneStore(database, () => new Date(FIRST_SYNC));
    core.createProgram(programInput(), FIRST_SYNC);
    const policy = controlPlanePolicy();
    core.addPolicyVersion({
      programId: "program-local",
      version: 1,
      policy,
      createdAt: FIRST_SYNC,
    });
    insertApprovedCampaign(
      database,
      "campaign-catalog-policy",
      policy.policyHash,
    );
    insertApprovedCampaign(
      database,
      "campaign-catalog-missing",
      policy.policyHash,
    );

    const policyProgram = program();
    const missingProgram = program({
      hackerOneId: "synthetic-program-catalog-missing",
      handle: "synthetic_program_catalog_missing",
      name: "Synthetic Program Removed From Catalog",
    });
    const stored = store.replaceAuthenticatedApiCatalog([
      policyProgram,
      missingProgram,
    ]);
    const policyStored = stored.find(
      ({ program: candidate }) => candidate.handle === policyProgram.handle,
    )!;
    const missingStored = stored.find(
      ({ program: candidate }) => candidate.handle === missingProgram.handle,
    )!;
    const policyInitial = snapshot({
      program: policyProgram,
      fetchedAt: FIRST_SYNC,
      previousSnapshotDigest: null,
    });
    const missingInitial = snapshot({
      program: missingProgram,
      fetchedAt: FIRST_SYNC,
      previousSnapshotDigest: null,
    });
    store.commitSnapshot(policyStored.localRef, policyInitial);
    store.commitSnapshot(missingStored.localRef, missingInitial);
    store.bindDependentCampaign(
      policyStored.localRef,
      "campaign-catalog-policy",
      FIRST_SYNC,
    );
    store.bindDependentCampaign(
      missingStored.localRef,
      "campaign-catalog-missing",
      FIRST_SYNC,
    );

    store.replaceAuthenticatedApiCatalog(
      [
        program({
          policy: "Changed catalog policy requiring a detail synchronization.",
          synchronizedAt: SECOND_SYNC,
          updatedAt: SECOND_SYNC,
        }),
      ],
      SECOND_SYNC,
    );

    expect(store.getProgram(policyStored.localRef)).toMatchObject({
      catalogActive: true,
      catalogDriftPending: true,
      currentSnapshotDigest: policyInitial.snapshotDigest,
    });
    expect(store.getProgram(missingStored.localRef)).toMatchObject({
      catalogActive: false,
      catalogDriftPending: true,
      currentSnapshotDigest: missingInitial.snapshotDigest,
    });
    expect(
      database.all(
        `SELECT id,state,revision,kill_switch_status FROM campaigns
         WHERE id IN (?,?) ORDER BY id`,
        "campaign-catalog-policy",
        "campaign-catalog-missing",
      ),
    ).toEqual([
      {
        id: "campaign-catalog-missing",
        state: "paused",
        revision: 3,
        kill_switch_status: "engaged",
      },
      {
        id: "campaign-catalog-policy",
        state: "paused",
        revision: 3,
        kill_switch_status: "engaged",
      },
    ]);
    expect(
      core
        .listAuditEntries()
        .filter(({ action }) => action === "hackerone_catalog_policy_drift")
        .map(({ decision, reasonCode, objectReference }) => ({
          decision,
          reasonCode,
          objectReference,
        })),
    ).toEqual(
      expect.arrayContaining([
        {
          decision: "campaigns_paused",
          reasonCode: "HACKERONE_CATALOG_DRIFT_CAMPAIGNS_PAUSED",
          objectReference: policyStored.localRef,
        },
        {
          decision: "campaigns_paused",
          reasonCode: "HACKERONE_CATALOG_DRIFT_CAMPAIGNS_PAUSED",
          objectReference: missingStored.localRef,
        },
      ]),
    );

    store.replaceAuthenticatedApiCatalog(
      [
        program({
          synchronizedAt: "2026-07-14T12:00:00.000Z",
          updatedAt: "2026-07-14T12:00:00.000Z",
        }),
        program({
          ...missingProgram,
          synchronizedAt: "2026-07-14T12:00:00.000Z",
        }),
      ],
      "2026-07-14T12:00:00.000Z",
    );
    expect(store.getProgram(missingStored.localRef)).toMatchObject({
      catalogActive: true,
      catalogDriftPending: true,
      currentSnapshotDigest: missingInitial.snapshotDigest,
    });
  });

  it("pauses explicitly bound active campaigns when HackerOne policy drifts", () => {
    const core = new ControlPlaneStore(database, () => new Date(FIRST_SYNC));
    core.createProgram(programInput(), FIRST_SYNC);
    const policy = controlPlanePolicy();
    core.addPolicyVersion({
      programId: "program-local",
      version: 1,
      policy,
      createdAt: FIRST_SYNC,
    });
    const active = campaign({
      policyHash: policy.policyHash,
      contract: Object.freeze({
        ...campaign().contract,
        policyHash: policy.policyHash,
      }),
      state: "approved",
      revision: 2,
      humanApprovedBy: "synthetic-reviewer",
      humanApprovedAt: FIRST_SYNC,
    });
    database.run(
      `INSERT INTO campaigns(
        id,program_id,policy_version,policy_hash,approved_assets_json,
        approved_risk_tiers_json,account_refs_json,allowed_action_classes_json,
        contract_json,state,revision,human_approved_by,human_approved_at,
        last_policy_check_at,kill_switch_status,created_at
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      active.id,
      active.programId,
      active.policyVersion,
      active.policyHash,
      canonicalJson([...active.approvedAssets]),
      canonicalJson([...active.approvedRiskTiers]),
      canonicalJson([...active.accountRefs]),
      canonicalJson([...active.allowedActionClasses]),
      canonicalJson(active.contract),
      active.state,
      active.revision,
      active.humanApprovedBy,
      active.humanApprovedAt,
      active.lastPolicyCheckAt,
      active.killSwitchStatus,
      active.createdAt,
    );
    const [metadataProgram] = store.replaceAuthenticatedApiCatalog([program()]);
    const initial = snapshot({
      program: program(),
      fetchedAt: FIRST_SYNC,
      previousSnapshotDigest: null,
    });
    store.commitSnapshot(metadataProgram!.localRef, initial);
    store.bindDependentCampaign(
      metadataProgram!.localRef,
      active.id,
      FIRST_SYNC,
    );

    const changed = snapshot({
      program: program({
        policy: "Changed synthetic policy; human review required.",
        synchronizedAt: SECOND_SYNC,
        updatedAt: SECOND_SYNC,
      }),
      fetchedAt: SECOND_SYNC,
      previousSnapshotDigest: initial.snapshotDigest,
    });
    expect(
      store.commitSnapshotWithPolicyDrift(
        metadataProgram!.localRef,
        changed,
        SECOND_SYNC,
      ).campaignsPaused,
    ).toBe(true);
    expect(
      database.get(
        "SELECT state,revision,human_approved_by,human_approved_at,last_policy_check_at,kill_switch_status FROM campaigns WHERE id=?",
        active.id,
      ),
    ).toEqual({
      state: "paused",
      revision: 3,
      human_approved_by: null,
      human_approved_at: null,
      last_policy_check_at: SECOND_SYNC,
      kill_switch_status: "engaged",
    });
    expect(
      core
        .listAuditEntries()
        .filter(({ action }) => action === "hackerone_policy_drift"),
    ).toMatchObject([
      {
        occurredAt: SECOND_SYNC,
        decision: "campaigns_paused",
        reasonCode: "HACKERONE_POLICY_DRIFT_CAMPAIGNS_PAUSED",
        objectReference: metadataProgram!.localRef,
        payloadHash: changed.snapshotDigest,
      },
    ]);
    expect(() =>
      database.run(
        "DELETE FROM hackerone_campaign_bindings WHERE campaign_id=?",
        active.id,
      ),
    ).toThrow("HACKERONE_CAMPAIGN_BINDING_IMMUTABLE");
  });

  it("rolls back snapshot publication when atomic drift evidence cannot be written", () => {
    const [metadataProgram] = store.replaceAuthenticatedApiCatalog([program()]);
    const initial = snapshot({
      program: program(),
      fetchedAt: FIRST_SYNC,
      previousSnapshotDigest: null,
    });
    store.commitSnapshot(metadataProgram!.localRef, initial);
    const changed = snapshot({
      program: program({
        policy: "Changed policy that must not publish without drift evidence.",
        synchronizedAt: SECOND_SYNC,
      }),
      fetchedAt: SECOND_SYNC,
      previousSnapshotDigest: initial.snapshotDigest,
    });
    const conflictingAuditId = `h1drift-${sha256(
      `${metadataProgram!.localRef}\u0000${changed.snapshotDigest}`,
    ).slice(0, 40)}`;
    database.run(
      `INSERT INTO control_plane_audit(
        id,occurred_at,action,decision,reason_code,object_reference,payload_hash
      ) VALUES(?,?,?,?,?,?,?)`,
      conflictingAuditId,
      FIRST_SYNC,
      "synthetic_conflict",
      "blocked",
      "SYNTHETIC_CONFLICT",
      metadataProgram!.localRef,
      "0".repeat(64),
    );

    expect(() =>
      store.commitSnapshotWithPolicyDrift(
        metadataProgram!.localRef,
        changed,
        SECOND_SYNC,
      ),
    ).toThrow("HACKERONE_SNAPSHOT_WRITE_FAILED");
    expect(
      store.getCurrentSnapshot(metadataProgram!.localRef)?.snapshot,
    ).toEqual(initial);
    expect(store.listSnapshots(metadataProgram!.localRef)).toHaveLength(1);
  });
});
