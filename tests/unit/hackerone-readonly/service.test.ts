import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ControlPlaneDatabase,
  type ControlPlaneDatabase as ControlPlaneDatabaseType,
} from "../../../packages/control-plane/database.js";
import type { ControlPlaneStore } from "../../../packages/control-plane/store.js";
import { HackerOneMetadataActionGate } from "../../../packages/external-actions/index.js";
import { SecurityError } from "../../../packages/shared/errors.js";
import { sha256 } from "../../../packages/shared/canonical.js";
import type {
  HackerOneCredentialAccess,
  HackerOneCredentialPair,
  HackerOneCredentialPresence,
} from "../../../packages/hackerone-readonly/credential-vault.js";
import type {
  HackerOneReadOnlyClient,
  HackerOneSelectedProgramMetadata,
} from "../../../packages/hackerone-readonly/client.js";
import {
  resolveHackerOneMetadataReadRuntime,
  type HackerOneMetadataReadRuntimeState,
} from "../../../packages/hackerone-readonly/runtime.js";
import {
  HackerOneMetadataService,
  type HackerOneKillSwitchReader,
} from "../../../packages/hackerone-readonly/service.js";
import { HackerOneMetadataStore } from "../../../packages/hackerone-readonly/store.js";
import type {
  HackerOneConnectionTestSummary,
  HackerOneProgram,
  HackerOneScopeExclusion,
  HackerOneStructuredScope,
} from "../../../packages/hackerone-readonly/types.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
  decideTestApproval,
  TEST_OPERATOR_ID,
} from "../../fixtures/operator-auth.factory.js";

const FIRST_TIME = "2026-07-14T12:00:00.000Z";
const SECOND_TIME = "2026-07-14T13:00:00.000Z";

function program(overrides: Partial<HackerOneProgram> = {}): HackerOneProgram {
  return Object.freeze({
    hackerOneId: "service-synthetic-program-001",
    handle: "service_synthetic_program",
    name: "Service Synthetic Program",
    currency: "USD",
    policy: "Synthetic policy requiring manual review.",
    submissionState: "open",
    programState: "public_mode",
    offersBounties: true,
    openScope: false,
    goldStandardSafeHarbor: true,
    bookmarked: false,
    ownReportCount: 0,
    ownValidReportCount: 0,
    startedAcceptingAt: null,
    createdAt: null,
    updatedAt: null,
    synchronizedAt: FIRST_TIME,
    source: "hackerone_api_authenticated",
    ...overrides,
  });
}

function scope(
  overrides: Partial<HackerOneStructuredScope> = {},
): HackerOneStructuredScope {
  const assetIdentifier =
    overrides.assetIdentifier ?? "https://service-synthetic.invalid/metadata";
  return Object.freeze({
    id: "service-scope-001",
    assetType: "URL",
    assetIdentifier,
    assetIdentifierDigest: sha256(assetIdentifier),
    eligibleForSubmission: true,
    eligibleForBounty: true,
    instruction: "Never contact this synthetic identifier.",
    maximumSeverity: "high",
    createdAt: null,
    updatedAt: null,
    confidentialityRequirement: "high",
    integrityRequirement: null,
    availabilityRequirement: null,
    ...overrides,
  });
}

function exclusion(): HackerOneScopeExclusion {
  return Object.freeze({
    id: "service-exclusion-001",
    category: "Synthetic exclusion",
    details: "No external target action is permitted.",
    createdAt: null,
    updatedAt: null,
  });
}

function enabledRuntime(): HackerOneMetadataReadRuntimeState {
  return resolveHackerOneMetadataReadRuntime({
    version: 1,
    capability: "HACKERONE_METADATA_READ",
    external_integrations_enabled: true,
    enabled: true,
    request_budget: {
      max_requests_total: 100,
      requests_per_minute: 20,
      max_concurrency: 1,
    },
  });
}

class FakeCredentials implements HackerOneCredentialAccess {
  public presence: HackerOneCredentialPresence = Object.freeze({
    identifierPresent: true,
    tokenPresent: true,
    tokenFingerprint: "0123456789ab",
    tokenBindingDigest: "0123456789ab".padEnd(64, "0"),
    secretStoreAvailable: true,
  });
  public readonly stored: {
    readonly identifier: string;
    readonly token: string;
  }[] = [];
  public removeCount = 0;
  public probeCount = 0;
  public probeError: Error | undefined;

  public probe(): Promise<HackerOneCredentialPresence> {
    this.probeCount += 1;
    return this.probeError === undefined
      ? Promise.resolve(this.presence)
      : Promise.reject(this.probeError);
  }

  public load(): Promise<HackerOneCredentialPair> {
    return Promise.resolve(
      Object.freeze({
        identifier: new TextEncoder().encode("synthetic-identifier"),
        token: new TextEncoder().encode("synthetic-token"),
      }),
    );
  }

  public store(identifier: string, token: string): Promise<string> {
    this.stored.push(Object.freeze({ identifier, token }));
    this.presence = Object.freeze({
      identifierPresent: true,
      tokenPresent: true,
      tokenFingerprint: "fedcba987654",
      tokenBindingDigest: "fedcba987654".padEnd(64, "0"),
      secretStoreAvailable: true,
    });
    return Promise.resolve("fedcba987654");
  }

  public storeBytes(
    identifier: Uint8Array,
    token: Uint8Array,
  ): Promise<string> {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    return this.store(decoder.decode(identifier), decoder.decode(token));
  }

  public remove(): Promise<void> {
    this.removeCount += 1;
    this.presence = Object.freeze({
      identifierPresent: false,
      tokenPresent: false,
      tokenFingerprint: null,
      tokenBindingDigest: null,
      secretStoreAvailable: true,
    });
    return Promise.resolve();
  }
}

class FakeClient {
  public connectionResult: HackerOneConnectionTestSummary = Object.freeze({
    result: "connected",
    recordCount: 1,
    schemaValid: true,
    durationMs: 3,
    redactedStatus: "HACKERONE_CONNECTION_OK",
  });
  public programs: readonly HackerOneProgram[] = Object.freeze([program()]);
  public selectedMetadata: HackerOneSelectedProgramMetadata = Object.freeze({
    program: program(),
    structuredScopes: Object.freeze([scope()]),
    scopeExclusions: Object.freeze([exclusion()]),
  });
  public connectionError: Error | undefined;
  public programError: Error | undefined;
  public selectedError: Error | undefined;
  public connectionImplementation:
    | ((signal: AbortSignal) => Promise<HackerOneConnectionTestSummary>)
    | undefined;
  public readonly connectionSignals: boolean[] = [];
  public readonly programSignals: boolean[] = [];
  public readonly selectedCalls: {
    readonly handle: string;
    readonly aborted: boolean;
  }[] = [];

  public connectionTest(
    signal: AbortSignal,
  ): Promise<HackerOneConnectionTestSummary> {
    this.connectionSignals.push(signal.aborted);
    if (this.connectionImplementation !== undefined)
      return this.connectionImplementation(signal);
    return this.connectionError === undefined
      ? Promise.resolve(this.connectionResult)
      : Promise.reject(this.connectionError);
  }

  public listPrograms(
    signal: AbortSignal,
  ): Promise<readonly HackerOneProgram[]> {
    this.programSignals.push(signal.aborted);
    return this.programError === undefined
      ? Promise.resolve(this.programs)
      : Promise.reject(this.programError);
  }

  public readSelectedProgram(
    handle: string,
    signal: AbortSignal,
  ): Promise<HackerOneSelectedProgramMetadata> {
    this.selectedCalls.push(Object.freeze({ handle, aborted: signal.aborted }));
    return this.selectedError === undefined
      ? Promise.resolve(this.selectedMetadata)
      : Promise.reject(this.selectedError);
  }
}

class FakeKillSwitch implements HackerOneKillSwitchReader {
  public active = false;
  public throws = false;

  public isActive(): boolean {
    if (this.throws) throw new Error("SYNTHETIC_KILL_SWITCH_READ_FAILURE");
    return this.active;
  }
}

describe("HackerOneMetadataService", () => {
  let database: ControlPlaneDatabaseType;
  let store: HackerOneMetadataStore;
  let controlPlane: ControlPlaneStore;
  let actionGate: HackerOneMetadataActionGate;
  let credentials: FakeCredentials;
  let client: FakeClient;
  let killSwitch: FakeKillSwitch;
  let now: string;
  let service: HackerOneMetadataService;

  function createService(
    runtime: HackerOneMetadataReadRuntimeState = enabledRuntime(),
    metadataStore: HackerOneMetadataStore = store,
  ): HackerOneMetadataService {
    return new HackerOneMetadataService({
      runtime,
      store: metadataStore,
      credentials,
      client: client as unknown as HackerOneReadOnlyClient,
      actionGate,
      killSwitch,
      now: () => new Date(now),
    });
  }

  beforeEach(() => {
    database = ControlPlaneDatabase.memory();
    controlPlane = createTestControlPlaneStore(database, FIRST_TIME);
    store = new HackerOneMetadataStore(database);
    actionGate = new HackerOneMetadataActionGate(
      database,
      controlPlane,
      enabledRuntime(),
    );
    clearTestKillSwitch(controlPlane, FIRST_TIME);
    credentials = new FakeCredentials();
    client = new FakeClient();
    killSwitch = new FakeKillSwitch();
    now = FIRST_TIME;
    service = createService();
  });

  async function activate(): Promise<void> {
    const approval = await service.prepareActivationApproval({
      approvalId: `h1activation-${String(controlPlane.listApprovals().length + 1)}`,
      operatorId: TEST_OPERATOR_ID,
      createdAt: now,
    });
    decideTestApproval(controlPlane, {
      approvalId: approval.id,
      decision: "accepted",
      userAction: "explicit_test_hackerone_activation",
      issuedAt: now,
    });
    service.completeActivation();
  }

  async function acceptPolicy(
    localRef: string,
    snapshotDigest: string,
  ): Promise<void> {
    const approval = await service.preparePolicyAcceptanceApproval({
      approvalId: `h1policy-${String(controlPlane.listApprovals().length + 1)}`,
      operatorId: TEST_OPERATOR_ID,
      programLocalRef: localRef,
      snapshotDigest,
      createdAt: now,
    });
    decideTestApproval(controlPlane, {
      approvalId: approval.id,
      decision: "accepted",
      userAction: "explicit_test_hackerone_policy_acceptance",
      issuedAt: now,
    });
  }

  afterEach(() => {
    database.close();
  });

  it("stays deactivated by default and never calls the client for disabled sync", async () => {
    service = createService(resolveHackerOneMetadataReadRuntime(undefined));

    await expect(service.status()).resolves.toMatchObject({
      status: "deactivated",
      externalIntegrationsEnabled: false,
      adapterEnabled: false,
      targetRequestsEnabled: false,
      reportSubmissionEnabled: false,
    });
    await expect(
      service.prepareActivationApproval({
        approvalId: "h1activation-disabled",
        operatorId: TEST_OPERATOR_ID,
        createdAt: now,
      }),
    ).rejects.toThrow("HACKERONE_METADATA_CAPABILITY_DISABLED");
    expect(credentials.probeCount).toBe(0);
    await expect(service.synchronizePrograms()).rejects.toThrow(
      "HACKERONE_METADATA_CAPABILITY_DISABLED",
    );
    expect(client.programSignals).toEqual([]);
    expect(store.getIntegrationState()).toMatchObject({
      adapterEnabled: false,
      lastSynchronizationResult: "failed",
      lastErrorCode: "HACKERONE_METADATA_CAPABILITY_DISABLED",
    });
  });

  it("fails closed for an active or unreadable kill switch before client access", async () => {
    await activate();
    killSwitch.active = true;

    await expect(service.synchronizePrograms()).rejects.toThrow(
      "HACKERONE_KILL_SWITCH",
    );
    expect(client.programSignals).toEqual([]);
    expect(store.getIntegrationState().lastErrorCode).toBe(
      "HACKERONE_KILL_SWITCH",
    );

    killSwitch.active = false;
    killSwitch.throws = true;
    expect(() => {
      service.assertActionAllowed();
    }).toThrow("HACKERONE_KILL_SWITCH");
    expect((await service.status()).killSwitchActive).toBe(true);
  });

  it("disables before storing or removing credentials and aborts further use", async () => {
    await activate();
    await service.storeCredentialBytes(
      new TextEncoder().encode("synthetic-id"),
      new TextEncoder().encode("synthetic-token"),
    );

    expect(credentials.stored).toEqual([
      { identifier: "synthetic-id", token: "synthetic-token" },
    ]);
    expect(store.getIntegrationState().adapterEnabled).toBe(false);
    await expect(service.testConnection()).rejects.toThrow(
      "HACKERONE_ADAPTER_DISABLED",
    );
    expect(client.connectionSignals).toEqual([]);

    await activate();
    await service.removeCredentials();
    expect(credentials.removeCount).toBe(1);
    expect(store.getIntegrationState().adapterEnabled).toBe(false);
    await expect(service.status()).resolves.toMatchObject({
      status: "deactivated",
      identifierPresent: false,
      tokenPresent: false,
      tokenFingerprint: null,
    });
  });

  it("durably disables the adapter when the global kill switch is engaged", async () => {
    await activate();
    expect(store.getIntegrationState().adapterEnabled).toBe(true);

    service.engageKillSwitch();

    expect(store.getIntegrationState().adapterEnabled).toBe(false);
    await expect(service.status()).resolves.toMatchObject({
      status: "deactivated",
      adapterEnabled: false,
    });
    await expect(service.testConnection()).rejects.toThrow(
      "HACKERONE_ADAPTER_DISABLED",
    );
    expect(client.connectionSignals).toEqual([]);

    now = SECOND_TIME;
    await activate();
    await expect(service.testConnection()).resolves.toMatchObject({
      result: "connected",
    });
  });

  it("reports an enabled adapter with an unreadable secret store as error", async () => {
    await activate();
    credentials.probeError = new Error("SYNTHETIC_SECRET_STORE_FAILURE");

    await expect(service.status()).resolves.toMatchObject({
      status: "error",
      adapterEnabled: true,
      identifierPresent: false,
      tokenPresent: false,
      tokenFingerprint: null,
    });
  });

  it("disables and aborts in-flight work immediately before disable or removal completes", async () => {
    await activate();
    let observedSignal: AbortSignal | undefined;
    client.connectionImplementation = (signal) => {
      observedSignal = signal;
      return new Promise((_resolve, reject) => {
        signal.addEventListener(
          "abort",
          () => {
            reject(new SecurityError("HACKERONE_ADAPTER_DISABLED"));
          },
          { once: true },
        );
      });
    };
    const firstOperation = service.testConnection();
    const firstFailure = expect(firstOperation).rejects.toThrow(
      "HACKERONE_ADAPTER_DISABLED",
    );
    const disabling = service.disable();
    expect(store.getIntegrationState().adapterEnabled).toBe(false);
    expect(observedSignal?.aborted).toBe(true);
    await firstFailure;
    await disabling;

    client.connectionImplementation = undefined;
    await activate();
    client.connectionImplementation = (signal) => {
      observedSignal = signal;
      return new Promise((_resolve, reject) => {
        signal.addEventListener(
          "abort",
          () => {
            reject(new SecurityError("HACKERONE_ADAPTER_DISABLED"));
          },
          { once: true },
        );
      });
    };
    const secondOperation = service.testConnection();
    const secondFailure = expect(secondOperation).rejects.toThrow(
      "HACKERONE_ADAPTER_DISABLED",
    );
    const removing = service.removeCredentials();
    expect(store.getIntegrationState().adapterEnabled).toBe(false);
    expect(observedSignal?.aborted).toBe(true);
    expect(credentials.removeCount).toBe(0);
    await secondFailure;
    await removing;
    expect(credentials.removeCount).toBe(1);
  });

  it("aborts in-flight work even when persisting the disabled state fails", async () => {
    await activate();
    const failingStore = new Proxy(store, {
      get(target, property, receiver): unknown {
        if (property === "setAdapterEnabled")
          return () => {
            throw new SecurityError("HACKERONE_INTEGRATION_STATE_WRITE_FAILED");
          };
        return Reflect.get(target, property, receiver) as unknown;
      },
    });
    service = createService(enabledRuntime(), failingStore);
    let observedSignal: AbortSignal | undefined;
    client.connectionImplementation = (signal) => {
      observedSignal = signal;
      return new Promise((_resolve, reject) => {
        signal.addEventListener(
          "abort",
          () => {
            reject(new SecurityError("HACKERONE_ADAPTER_DISABLED"));
          },
          { once: true },
        );
      });
    };
    const operation = service.testConnection();
    const operationFailure = expect(operation).rejects.toThrow(
      "HACKERONE_ADAPTER_DISABLED",
    );

    await expect(service.disable()).rejects.toThrow(
      "HACKERONE_INTEGRATION_STATE_WRITE_FAILED",
    );
    expect(observedSignal?.aborted).toBe(true);
    await operationFailure;
  });

  it("records redacted connection results and exposes only safe status fields", async () => {
    await activate();

    await expect(service.testConnection()).resolves.toEqual(
      client.connectionResult,
    );
    expect(client.connectionSignals).toEqual([false]);
    expect(store.getIntegrationState()).toMatchObject({
      lastConnectionTestAt: FIRST_TIME,
      lastConnectionResult: "connected",
      lastErrorCode: null,
    });
    await expect(service.status()).resolves.toMatchObject({
      actionClass: "HACKERONE_METADATA_READ",
      status: "connected",
      adapterEnabled: true,
      identifierPresent: true,
      tokenPresent: true,
      tokenFingerprint: "0123456789ab",
      apiMode: "read_only",
      targetRequestsEnabled: false,
      reportSubmissionEnabled: false,
    });

    client.connectionResult = Object.freeze({
      result: "unauthorized",
      recordCount: 0,
      schemaValid: false,
      durationMs: 2,
      redactedStatus: "HACKERONE_UNAUTHORIZED",
    });
    now = SECOND_TIME;
    await service.testConnection();
    expect(store.getIntegrationState()).toMatchObject({
      lastConnectionTestAt: SECOND_TIME,
      lastConnectionResult: "unauthorized",
      lastErrorCode: "HACKERONE_UNAUTHORIZED",
    });
    expect((await service.status()).status).toBe("error");
  });

  it("synchronizes only normalized programs and records a successful run", async () => {
    client.programs = Object.freeze([
      program(),
      program({
        hackerOneId: "service-synthetic-program-002",
        handle: "service_synthetic_program_two",
        name: "Service Synthetic Program Two",
      }),
    ]);
    await activate();

    await expect(service.synchronizePrograms()).resolves.toEqual({
      programCount: 2,
      pages: 1,
      synchronizedAt: FIRST_TIME,
    });
    expect(client.programSignals).toEqual([false]);
    expect(service.listPrograms()).toHaveLength(2);
    expect(store.getIntegrationState()).toMatchObject({
      lastSynchronizationAt: FIRST_TIME,
      lastSynchronizationResult: "succeeded",
      lastErrorCode: null,
    });
    expect((await service.status()).importedProgramCount).toBe(2);
  });

  it("creates selected snapshots without implicit acceptance and preserves history", async () => {
    await activate();
    await service.synchronizePrograms();
    const localRef = service.listPrograms()[0]!.localRef;

    const initial = await service.synchronizeSelectedProgram(localRef);
    expect(initial.drift).toEqual({
      changed: true,
      changes: ["POLICY_TEXT_CHANGED"],
      campaignsPaused: false,
      requiresHumanAcceptance: true,
    });
    expect(service.selectedProgramRef()).toBe(localRef);
    expect(service.currentSnapshot(localRef)?.acceptancePending).toBe(true);
    expect(service.policyVersions(localRef)).toHaveLength(1);

    await acceptPolicy(localRef, initial.snapshot.snapshotDigest);
    expect(service.currentSnapshot(localRef)?.acceptancePending).toBe(false);

    now = SECOND_TIME;
    client.selectedMetadata = Object.freeze({
      program: program({
        policy: "Changed synthetic policy requiring a new decision.",
        synchronizedAt: SECOND_TIME,
        updatedAt: SECOND_TIME,
      }),
      structuredScopes: Object.freeze([
        scope({ instruction: "Changed local-only instructions." }),
      ]),
      scopeExclusions: Object.freeze([exclusion()]),
    });
    const changed = await service.synchronizeSelectedProgram(localRef);

    expect(changed.drift.changed).toBe(true);
    expect(changed.drift.campaignsPaused).toBe(false);
    expect(changed.drift.requiresHumanAcceptance).toBe(true);
    const versions = service.policyVersions(localRef);
    expect(versions).toHaveLength(2);
    expect(versions[0]!.snapshot.snapshotDigest).toBe(
      initial.snapshot.snapshotDigest,
    );
    expect(versions[0]!.acceptancePending).toBe(false);
    expect(versions[1]!.acceptancePending).toBe(true);
    await expect(
      acceptPolicy(localRef, initial.snapshot.snapshotDigest),
    ).rejects.toThrow("HACKERONE_SNAPSHOT_ACCEPTANCE_REQUIRES_CURRENT");
    await acceptPolicy(localRef, changed.snapshot.snapshotDigest);
    expect(service.currentSnapshot(localRef)?.acceptancePending).toBe(false);
  });

  it("retains the last readable snapshot when selected synchronization fails", async () => {
    await activate();
    await service.synchronizePrograms();
    const localRef = service.listPrograms()[0]!.localRef;
    const initial = await service.synchronizeSelectedProgram(localRef);
    const before = service.currentSnapshot(localRef);
    client.selectedError = new SecurityError("HACKERONE_UNAVAILABLE");
    now = SECOND_TIME;

    await expect(service.synchronizeSelectedProgram(localRef)).rejects.toThrow(
      "HACKERONE_UNAVAILABLE",
    );
    expect(service.currentSnapshot(localRef)).toEqual(before);
    expect(service.policyVersions(localRef)).toHaveLength(1);
    expect(service.currentSnapshot(localRef)?.snapshot.snapshotDigest).toBe(
      initial.snapshot.snapshotDigest,
    );
    expect(store.getIntegrationState()).toMatchObject({
      lastSynchronizationAt: SECOND_TIME,
      lastSynchronizationResult: "failed",
      lastErrorCode: "HACKERONE_UNAVAILABLE",
    });
  });
});
