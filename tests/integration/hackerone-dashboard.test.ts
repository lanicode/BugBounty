import { afterEach, describe, expect, it } from "vitest";
import { request as httpRequest } from "node:http";
import { ControlPlaneDatabase } from "../../packages/control-plane/database.js";
import type { ControlPlaneStore } from "../../packages/control-plane/store.js";
import {
  startDashboardServer,
  type RunningDashboardServer,
} from "../../packages/dashboard/index.js";
import { DemoSaas } from "../../packages/demo-saas/index.js";
import {
  HackerOneMetadataService,
  HackerOneMetadataStore,
  HackerOneReadOnlyClient,
  resolveHackerOneMetadataReadRuntime,
  type HackerOneCredentialAccess,
  type HackerOneCredentialPair,
  type HackerOneCredentialPresence,
  type HackerOneTransport,
  type HackerOneTransportPlan,
  type HackerOneTransportResponse,
} from "../../packages/hackerone-readonly/index.js";
import { deriveRuntimeReadiness } from "../../packages/local-runtime/index.js";
import { sha256 } from "../../packages/shared/canonical.js";
import { SecurityError } from "../../packages/shared/errors.js";
import { HackerOneMetadataActionGate } from "../../packages/external-actions/index.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
  TEST_OPERATOR_ID,
  TEST_OPERATOR_SIGNER,
} from "../fixtures/operator-auth.factory.js";
import {
  campaign,
  controlPlanePolicy,
  programInput,
} from "../fixtures/control-plane.factory.js";

const NOW = "2026-07-14T12:00:00.000Z";
const ASSET_IDENTIFIER =
  "http://127.0.0.1:9/hackerone-asset-identifier-text-only";

interface HackerOneDashboardProjection {
  readonly available: boolean;
  readonly secureCoreReady: boolean;
  readonly secureCoreReasonCodes: readonly string[];
  readonly status: {
    readonly status: string;
    readonly externalIntegrationsEnabled: boolean;
    readonly adapterConfigured: boolean;
    readonly adapterEnabled: boolean;
    readonly killSwitchActive: boolean;
    readonly identifierPresent: boolean;
    readonly tokenPresent: boolean;
    readonly tokenFingerprint: string | null;
    readonly lastConnectionResult: string | null;
    readonly lastErrorCode: string | null;
    readonly targetRequestsEnabled: false;
    readonly reportSubmissionEnabled: false;
  };
  readonly programs: readonly {
    readonly localRef: string;
    readonly source: string;
    readonly program: Readonly<Record<string, unknown>>;
  }[];
  readonly programCount: number;
  readonly programsTruncated: boolean;
  readonly selectedProgramRef: string | null;
  readonly currentSnapshot: null | {
    readonly programLocalRef: string;
    readonly acceptancePending: boolean;
    readonly snapshot: {
      readonly snapshotDigest: string;
      readonly structuredScopes: readonly {
        readonly assetIdentifier: string;
      }[];
    };
  };
  readonly policyVersions: readonly {
    readonly versionNumber: number;
    readonly snapshot: Readonly<Record<string, unknown>>;
  }[];
  readonly policyVersionCount: number;
  readonly policyVersionsTruncated: boolean;
  readonly previousPolicy: null | Readonly<Record<string, unknown>>;
  readonly campaigns: readonly Readonly<Record<string, unknown>>[];
  readonly campaignCount: number;
  readonly campaignsTruncated: boolean;
}

interface DashboardState {
  readonly csrfToken: string;
  readonly hackerOne: HackerOneDashboardProjection;
}

interface Harness {
  readonly database: ControlPlaneDatabase;
  readonly store: ControlPlaneStore;
  readonly credentials: InProcessCredentials;
  readonly transport: InProcessTransport;
  readonly server: RunningDashboardServer;
}

class InProcessCredentials implements HackerOneCredentialAccess {
  public identifier: string | null = null;
  public token: string | null = null;
  public storeCount = 0;
  public removeCount = 0;
  public readonly receivedBytePairs: {
    readonly identifier: Uint8Array;
    readonly token: Uint8Array;
  }[] = [];

  public probe(): Promise<HackerOneCredentialPresence> {
    const tokenBindingDigest =
      this.token === null ? null : sha256(new TextEncoder().encode(this.token));
    return Promise.resolve(
      Object.freeze({
        identifierPresent: this.identifier !== null,
        tokenPresent: this.token !== null,
        tokenFingerprint:
          tokenBindingDigest === null ? null : tokenBindingDigest.slice(0, 12),
        tokenBindingDigest,
        secretStoreAvailable: true,
      }),
    );
  }

  public load(): Promise<HackerOneCredentialPair> {
    if (this.identifier === null || this.token === null)
      return Promise.reject(
        new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE"),
      );
    return Promise.resolve(
      Object.freeze({
        identifier: new TextEncoder().encode(this.identifier),
        token: new TextEncoder().encode(this.token),
      }),
    );
  }

  public store(identifier: string, token: string): Promise<string> {
    this.storeCount += 1;
    this.identifier = identifier;
    this.token = token;
    return Promise.resolve(
      sha256(new TextEncoder().encode(token)).slice(0, 12),
    );
  }

  public storeBytes(
    identifier: Uint8Array,
    token: Uint8Array,
  ): Promise<string> {
    this.receivedBytePairs.push({ identifier, token });
    const decoder = new TextDecoder("utf-8", { fatal: true });
    return this.store(decoder.decode(identifier), decoder.decode(token));
  }

  public remove(): Promise<void> {
    this.removeCount += 1;
    this.identifier = null;
    this.token = null;
    return Promise.resolve();
  }
}

class InProcessTransport implements HackerOneTransport {
  public readonly plans: HackerOneTransportPlan[] = [];
  public responseBody: unknown = { data: [] };

  public get(
    plan: HackerOneTransportPlan,
  ): Promise<HackerOneTransportResponse> {
    this.plans.push(Object.freeze({ ...plan }));
    const body = new TextEncoder().encode(JSON.stringify(this.responseBody));
    return Promise.resolve(
      Object.freeze({
        statusCode: 200,
        body,
        contentType: "application/vnd.api+json",
        contentTypeCount: 1,
        contentEncoding: null,
        locationPresent: false,
        durationMs: 1,
        responseBytes: body.byteLength,
      }),
    );
  }
}

const harnesses: Harness[] = [];

afterEach(async () => {
  await Promise.all(harnesses.map(({ server }) => server.close()));
  for (const { database } of harnesses) database.close();
  harnesses.length = 0;
});

async function startHarness(
  options: {
    readonly includeHackerOne?: boolean;
    readonly runtimeEnabled?: boolean;
    readonly killSwitchActive?: boolean;
    readonly hackerOneOverride?: HackerOneMetadataService;
    readonly campaignSeedCount?: number;
    readonly secureCoreReady?: boolean;
  } = {},
): Promise<Harness> {
  const database = ControlPlaneDatabase.memory();
  const store = createTestControlPlaneStore(
    database,
    "2026-07-14T11:59:59.000Z",
  );
  if ((options.campaignSeedCount ?? 0) > 0) {
    const program = programInput();
    const policy = controlPlanePolicy();
    store.createProgram(program, NOW);
    store.addPolicyVersion({
      programId: program.id,
      version: 1,
      policy,
      createdAt: NOW,
    });
    for (let index = 0; index < (options.campaignSeedCount ?? 0); index += 1) {
      const base = campaign({
        id: `campaign_h1_${String(index)}`,
        policyHash: policy.policyHash,
      });
      store.insertCampaign({
        ...base,
        contract: Object.freeze({
          ...base.contract,
          policyHash: policy.policyHash,
        }),
      });
    }
  }
  if (options.killSwitchActive === false)
    clearTestKillSwitch(store, NOW, "dashboard_hackerone_test_clear");
  const now = (): Date => new Date(NOW);
  const demo = new DemoSaas(now);
  const credentials = new InProcessCredentials();
  const transport = new InProcessTransport();
  const runtime = resolveHackerOneMetadataReadRuntime(
    options.runtimeEnabled === false
      ? undefined
      : {
          version: 1,
          capability: "HACKERONE_METADATA_READ",
          external_integrations_enabled: true,
          enabled: true,
          request_budget: {
            max_requests_total: 20,
            requests_per_minute: 20,
            max_concurrency: 1,
          },
        },
  );
  const metadataStore = new HackerOneMetadataStore(database);
  const actionGate = new HackerOneMetadataActionGate(database, store, runtime);
  let hackerOne: HackerOneMetadataService | undefined;
  const client = new HackerOneReadOnlyClient({
    runtime,
    credentials,
    transport,
    actionGate,
    now,
    minimumIntervalMs: 0,
  });
  if (options.hackerOneOverride !== undefined)
    hackerOne = options.hackerOneOverride;
  else if (options.includeHackerOne !== false)
    hackerOne = new HackerOneMetadataService({
      runtime,
      store: metadataStore,
      credentials,
      client,
      actionGate,
      killSwitch: { isActive: () => store.isKillSwitchActive() },
      now,
    });

  try {
    const server = await startDashboardServer(
      {
        store,
        demo,
        readiness: deriveRuntimeReadiness(
          options.secureCoreReady === false
            ? {
                platform: "darwin",
                eventKeyMinimumVersion: undefined,
                operatorKeyReference: undefined,
                operatorId: undefined,
                operatorKeyRevision: undefined,
                secretStoreProbe: "not_checked",
                demoSaasReady: true,
                databaseReady: true,
              }
            : {
                platform: "darwin",
                eventKeyMinimumVersion: "1",
                operatorKeyReference:
                  "keychain://test/local-operator-ed25519-v1",
                operatorId: TEST_OPERATOR_ID,
                operatorKeyRevision: "1",
                secretStoreProbe: "available",
                demoSaasReady: true,
                databaseReady: true,
              },
        ),
        ...(hackerOne === undefined ? {} : { hackerOne }),
        operatorSigner: TEST_OPERATOR_SIGNER,
        now,
      },
      0,
    );
    const harness = { database, store, credentials, transport, server };
    harnesses.push(harness);
    return harness;
  } catch (error) {
    database.close();
    throw error;
  }
}

async function state(server: RunningDashboardServer): Promise<DashboardState> {
  const response = await fetch(`${server.origin}/api/state`);
  expect(response.status, await response.clone().text()).toBe(200);
  return (await response.json()) as DashboardState;
}

function postJson(
  server: RunningDashboardServer,
  path: string,
  csrfToken: string,
  body: unknown,
): Promise<Response> {
  return fetch(`${server.origin}${path}`, {
    method: "POST",
    headers: {
      origin: server.origin,
      "content-type": "application/json",
      "x-csrf-token": csrfToken,
    },
    body: JSON.stringify(body),
  });
}

function credentialFrame(identifier: string, token: string): Uint8Array {
  const encoder = new TextEncoder();
  const identifierBytes = encoder.encode(identifier);
  const tokenBytes = encoder.encode(token);
  const frame = new Uint8Array(
    9 + identifierBytes.byteLength + tokenBytes.byteLength,
  );
  frame.set([0x48, 0x31, 0x43, 0x52, 0x01], 0);
  const view = new DataView(frame.buffer, frame.byteOffset, 9);
  view.setUint16(5, identifierBytes.byteLength, false);
  view.setUint16(7, tokenBytes.byteLength, false);
  frame.set(identifierBytes, 9);
  frame.set(tokenBytes, 9 + identifierBytes.byteLength);
  identifierBytes.fill(0);
  tokenBytes.fill(0);
  return frame;
}

function postCredentialFrame(
  server: RunningDashboardServer,
  csrfToken: string,
  frame: Uint8Array,
  headers: Readonly<Record<string, string>> = {},
): Promise<Response> {
  return fetch(`${server.origin}/api/hackerone/credentials/store`, {
    method: "POST",
    headers: {
      origin: server.origin,
      "content-type": "application/octet-stream",
      "x-csrf-token": csrfToken,
      ...headers,
    },
    body: Buffer.from(frame),
  });
}

function postCredentialHeadersOnly(
  server: RunningDashboardServer,
  csrfToken: string,
  headers: Readonly<Record<string, string>>,
): Promise<{ readonly status: number; readonly body: unknown }> {
  return new Promise((resolve, reject) => {
    const url = new URL("/api/hackerone/credentials/store", server.origin);
    const request = httpRequest(
      {
        host: url.hostname,
        port: url.port,
        path: url.pathname,
        method: "POST",
        headers: {
          origin: server.origin,
          "content-type": "application/octet-stream",
          "x-csrf-token": csrfToken,
          ...headers,
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.once("error", reject);
        response.once("end", () => {
          try {
            resolve({
              status: response.statusCode ?? 0,
              body: JSON.parse(
                Buffer.concat(chunks).toString("utf8"),
              ) as unknown,
            });
          } catch (error) {
            reject(
              error instanceof Error
                ? error
                : new Error("TEST_RESPONSE_INVALID"),
            );
          } finally {
            for (const chunk of chunks) chunk.fill(0);
          }
        });
      },
    );
    request.once("error", reject);
    request.end();
  });
}

function postWithDeclaredContentLength(
  server: RunningDashboardServer,
  path: string,
  csrfToken: string,
  contentLength: number,
): Promise<{ readonly status: number; readonly body: unknown }> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, server.origin);
    const request = httpRequest(
      {
        host: url.hostname,
        port: url.port,
        path: url.pathname,
        method: "POST",
        headers: {
          origin: server.origin,
          "content-type": "application/json",
          "content-length": String(contentLength),
          "x-csrf-token": csrfToken,
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.once("error", reject);
        response.once("end", () => {
          request.destroy();
          try {
            resolve({
              status: response.statusCode ?? 0,
              body: JSON.parse(
                Buffer.concat(chunks).toString("utf8"),
              ) as unknown,
            });
          } catch (error) {
            reject(
              error instanceof Error
                ? error
                : new Error("TEST_RESPONSE_INVALID"),
            );
          }
        });
      },
    );
    request.once("error", reject);
    request.flushHeaders();
  });
}

function manualImportDocument(
  policy = "Local metadata fixture. No target request is permitted.",
): string {
  return JSON.stringify({
    version: 1,
    program: {
      hackerOneId: "dashboard-local-program-001",
      handle: "dashboard_local_program",
      name: "Dashboard Local Program",
      currency: "USD",
      policy,
      submissionState: "open",
      programState: "public_mode",
      offersBounties: false,
      openScope: false,
      goldStandardSafeHarbor: false,
      bookmarked: false,
      ownReportCount: 0,
      ownValidReportCount: 0,
      startedAcceptingAt: null,
      createdAt: null,
      updatedAt: null,
    },
    structuredScopes: [
      {
        id: "dashboard-local-scope-001",
        assetType: "URL",
        assetIdentifier: ASSET_IDENTIFIER,
        eligibleForSubmission: true,
        eligibleForBounty: false,
        instruction: "Display as text only; never navigate.",
        maximumSeverity: "medium",
        createdAt: null,
        updatedAt: null,
        confidentialityRequirement: "high",
        integrityRequirement: null,
        availabilityRequirement: null,
      },
    ],
    scopeExclusions: [
      {
        id: "dashboard-local-exclusion-001",
        category: "Local-only exclusion",
        details: "No network action is authorized.",
        createdAt: null,
        updatedAt: null,
      },
    ],
  });
}

function projectionOnlyService(
  programCount: number,
  policyVersionCount: number,
): HackerOneMetadataService {
  const programs = Array.from({ length: programCount }, (_, index) => {
    const digest = sha256(`projection-program-${String(index)}`);
    return Object.freeze({
      localRef: `h1m_${digest}`,
      catalogActive: true,
      recordDigest: sha256(`record-${String(index)}`),
      currentSnapshotDigest: sha256(`snapshot-${String(index)}`),
      program: projectionProgram(index, `catalog-policy-${String(index)}`),
    });
  });
  const selected = programs.at(-1);
  if (selected === undefined) throw new Error("TEST_PROGRAM_REQUIRED");
  const versions = Array.from({ length: policyVersionCount }, (_, index) => {
    const snapshotDigest = sha256(`history-snapshot-${String(index)}`);
    const previousSnapshotDigest =
      index === 0 ? null : sha256(`history-snapshot-${String(index - 1)}`);
    const current = index === policyVersionCount - 1;
    return Object.freeze({
      programLocalRef: selected.localRef,
      acceptancePending: true,
      snapshot: Object.freeze({
        program: projectionProgram(
          programCount - 1,
          current
            ? "current-visible-policy"
            : `historical-policy-${String(index)}`,
        ),
        structuredScopes: Object.freeze([
          Object.freeze({
            id: `scope-${String(index)}`,
            assetType: "URL",
            assetIdentifier: current
              ? "current-visible-asset"
              : `historical-asset-${String(index)}`,
            assetIdentifierDigest: sha256(`asset-${String(index)}`),
            eligibleForSubmission: true,
            eligibleForBounty: false,
            instruction: "text only",
            maximumSeverity: "medium",
            createdAt: null,
            updatedAt: null,
            confidentialityRequirement: null,
            integrityRequirement: null,
            availabilityRequirement: null,
          }),
        ]),
        scopeExclusions: Object.freeze([]),
        fetchedAt: new Date(Date.parse(NOW) + index).toISOString(),
        adapterVersion: "pilot-readiness-a-v1" as const,
        schemaVersion: 1 as const,
        snapshotDigest,
        policyDigest: sha256(`policy-${String(index)}`),
        previousSnapshotDigest,
        suitability: Object.freeze({
          score: 50,
          reasons: Object.freeze(["POLICY_PRESENT" as const]),
          automationPermission: "unknown_requires_human_review" as const,
          accountWorkflows: "manual_review_required" as const,
          legalDecisionMade: false as const,
        }),
        source: "manual_unverified" as const,
      }),
    });
  });
  const current = versions.at(-1);
  if (current === undefined) throw new Error("TEST_SNAPSHOT_REQUIRED");
  return {
    status: () =>
      Promise.resolve({
        actionClass: "HACKERONE_METADATA_READ",
        status: "deactivated",
        externalIntegrationsEnabled: false,
        adapterConfigured: false,
        adapterEnabled: false,
        killSwitchActive: true,
        identifierPresent: false,
        tokenPresent: false,
        tokenFingerprint: null,
        lastConnectionTestAt: null,
        lastSuccessfulConnectionAt: null,
        lastConnectionResult: null,
        lastSynchronizationAt: null,
        lastSynchronizationResult: null,
        importedProgramCount: programs.length,
        lastErrorCode: null,
        selectedHandle: selected.program.handle,
        apiMode: "read_only",
        targetRequestsEnabled: false,
        reportSubmissionEnabled: false,
      }),
    listPrograms: () => programs,
    selectedProgramRef: () => selected.localRef,
    currentSnapshot: () => current,
    policyVersions: () => versions,
    hasPausedDependentCampaigns: () => false,
  } as unknown as HackerOneMetadataService;
}

function projectionProgram(index: number, policy: string) {
  return Object.freeze({
    hackerOneId: `projection-${String(index)}`,
    handle: `projection_${String(index)}`,
    name: `Projection ${String(index)}`,
    currency: "USD",
    policy,
    submissionState: "open",
    programState: "public_mode",
    offersBounties: false,
    openScope: false,
    goldStandardSafeHarbor: false,
    bookmarked: false,
    ownReportCount: 0,
    ownValidReportCount: 0,
    startedAcceptingAt: null,
    createdAt: null,
    updatedAt: null,
    synchronizedAt: NOW,
    source: "manual_unverified" as const,
  });
}

describe("HackerOne dashboard HTTP boundary", () => {
  it("projects an unavailable integration fail-closed without any secret fields", async () => {
    const { server, transport } = await startHarness({
      includeHackerOne: false,
    });

    const initial = await state(server);
    expect(initial.hackerOne).toMatchObject({
      available: false,
      status: {
        status: "deactivated",
        externalIntegrationsEnabled: false,
        adapterConfigured: false,
        adapterEnabled: false,
        killSwitchActive: true,
        identifierPresent: false,
        tokenPresent: false,
        tokenFingerprint: null,
        targetRequestsEnabled: false,
        reportSubmissionEnabled: false,
      },
      programs: [],
      selectedProgramRef: null,
      currentSnapshot: null,
    });
    expect(JSON.stringify(initial)).not.toMatch(
      /(?:api[_-]?token|authorization|credentialValue|password|secretValue)/iu,
    );

    const blocked = await postJson(
      server,
      "/api/hackerone/integration/enable",
      initial.csrfToken,
      {},
    );
    expect(blocked.status).toBe(409);
    expect(await blocked.json()).toEqual({
      error: "HACKERONE_SERVICE_UNAVAILABLE",
    });
    expect(transport.plans).toHaveLength(0);
  });

  it("rejects unknown routes, legacy field names, and every extra body field before effects", async () => {
    const { server, credentials, transport } = await startHarness({
      killSwitchActive: false,
    });
    const initial = await state(server);
    const validRef = `h1m_${"a".repeat(64)}`;
    const validDigest = "b".repeat(64);
    const blockedCredentialStore = await postJson(
      server,
      "/api/hackerone/credentials/store",
      initial.csrfToken,
      { identifier: "local-id", token: "local-token" },
    );
    expect(blockedCredentialStore.status).toBe(415);
    expect(await blockedCredentialStore.json()).toEqual({
      error: "DASHBOARD_CONTENT_TYPE_BLOCKED",
    });

    const cases = [
      [
        "/api/hackerone/credentials/remove",
        { confirmed: true },
        "HACKERONE_DASHBOARD_REQUEST_INVALID",
      ],
      [
        "/api/hackerone/integration/enable",
        { confirmed: true },
        "HACKERONE_DASHBOARD_REQUEST_INVALID",
      ],
      [
        "/api/hackerone/integration/disable",
        { confirmed: true },
        "HACKERONE_DASHBOARD_REQUEST_INVALID",
      ],
      [
        "/api/hackerone/connection-test",
        { confirmed: true },
        "HACKERONE_DASHBOARD_REQUEST_INVALID",
      ],
      [
        "/api/hackerone/programs/synchronize",
        { confirmed: true },
        "HACKERONE_DASHBOARD_REQUEST_INVALID",
      ],
      [
        "/api/hackerone/program/select",
        { programLocalRef: validRef },
        "HACKERONE_DASHBOARD_PROGRAM_REF_INVALID",
      ],
      [
        "/api/hackerone/program/synchronize",
        { programRef: validRef, extra: true },
        "HACKERONE_DASHBOARD_PROGRAM_REF_INVALID",
      ],
      [
        "/api/hackerone/campaign/bind",
        { programRef: validRef, campaignId: "campaign_h1_0", extra: true },
        "HACKERONE_DASHBOARD_CAMPAIGN_BINDING_INVALID",
      ],
      [
        "/api/hackerone/policy/accept",
        {
          confirmed: true,
          programRef: validRef,
          snapshotDigest: validDigest,
          extra: true,
        },
        "HACKERONE_DASHBOARD_POLICY_ACCEPTANCE_INVALID",
      ],
      [
        "/api/hackerone/manual-import",
        { source: manualImportDocument(), extra: true },
        "HACKERONE_DASHBOARD_MANUAL_IMPORT_INVALID",
      ],
    ] as const;

    for (const [path, body, code] of cases) {
      const response = await postJson(server, path, initial.csrfToken, body);
      expect(response.status, path).toBe(409);
      expect(await response.json()).toEqual({ error: code });
    }
    const unknownRoute = await postJson(
      server,
      "/api/hackerone/connection-test/",
      initial.csrfToken,
      {},
    );
    expect(unknownRoute.status).toBe(404);
    expect(await unknownRoute.json()).toEqual({
      error: "DASHBOARD_ROUTE_NOT_FOUND",
    });
    expect(credentials.storeCount).toBe(0);
    expect(credentials.removeCount).toBe(0);
    expect(transport.plans).toHaveLength(0);
    expect((await state(server)).hackerOne.programs).toHaveLength(0);
  });

  it("fails closed for invalid credential framing, content type, origin, CSRF, and declared length without leaks", async () => {
    const { server, credentials, transport } = await startHarness({
      killSwitchActive: false,
    });
    const initial = await state(server);
    const identifier = "malformed-frame-identifier-2718";
    const token = "malformed-frame-token-3141";

    const invalidCases: Uint8Array[] = [];
    const badMagic = credentialFrame(identifier, token);
    badMagic[0] = 0;
    invalidCases.push(badMagic);
    const badVersion = credentialFrame(identifier, token);
    badVersion[4] = 2;
    invalidCases.push(badVersion);
    const zeroIdentifierLength = credentialFrame(identifier, token);
    zeroIdentifierLength[5] = 0;
    zeroIdentifierLength[6] = 0;
    invalidCases.push(zeroIdentifierLength);
    const mismatchedLength = credentialFrame(identifier, token);
    mismatchedLength[8] = (mismatchedLength[8] ?? 0) + 1;
    invalidCases.push(mismatchedLength);
    const nonPrintable = credentialFrame(identifier, token);
    nonPrintable[9] = 0x20;
    invalidCases.push(nonPrintable);

    for (const frame of invalidCases) {
      const response = await postCredentialFrame(
        server,
        initial.csrfToken,
        frame,
      );
      frame.fill(0);
      expect(response.status).toBe(409);
      const responseText = await response.text();
      expect(responseText).toBe(
        JSON.stringify({ error: "HACKERONE_CREDENTIAL_FRAME_INVALID" }),
      );
      expect(responseText).not.toContain(identifier);
      expect(responseText).not.toContain(token);
    }

    for (const [headers, expectedStatus, expectedError] of [
      [
        { "content-type": "application/octet-stream; charset=binary" },
        415,
        "DASHBOARD_CONTENT_TYPE_BLOCKED",
      ],
      [{ origin: "http://127.0.0.1:1" }, 403, "DASHBOARD_ORIGIN_BLOCKED"],
      [{ "x-csrf-token": "invalid-csrf-token" }, 403, "DASHBOARD_CSRF_BLOCKED"],
    ] as const) {
      const frame = credentialFrame(identifier, token);
      const response = await postCredentialFrame(
        server,
        initial.csrfToken,
        frame,
        headers,
      );
      frame.fill(0);
      expect(response.status).toBe(expectedStatus);
      expect(await response.json()).toEqual({ error: expectedError });
    }

    for (const [headers, expectedStatus, expectedError] of [
      [
        { "transfer-encoding": "chunked" },
        400,
        "DASHBOARD_CONTENT_LENGTH_INVALID",
      ],
      [{ "content-length": "00" }, 400, "DASHBOARD_CONTENT_LENGTH_INVALID"],
      [{ "content-length": "6010" }, 413, "DASHBOARD_BODY_TOO_LARGE"],
    ] as const) {
      const response = await postCredentialHeadersOnly(
        server,
        initial.csrfToken,
        headers,
      );
      expect(response.status).toBe(expectedStatus);
      expect(response.body).toEqual({ error: expectedError });
    }

    expect(credentials.storeCount).toBe(0);
    expect(credentials.receivedBytePairs).toHaveLength(0);
    expect(transport.plans).toHaveLength(0);
  });

  it("allows only local credential safety actions in the setup shell and blocks every external-capable action", async () => {
    const { server, database, credentials, transport } = await startHarness({
      secureCoreReady: false,
      killSwitchActive: false,
      campaignSeedCount: 1,
    });
    const initial = await state(server);
    const validRef = `h1m_${"a".repeat(64)}`;
    const validDigest = "b".repeat(64);
    const credentialPayload = credentialFrame(
      "setup-shell-identifier",
      "setup-shell-token",
    );
    expect(initial.hackerOne.secureCoreReady).toBe(false);
    expect(initial.hackerOne.secureCoreReasonCodes).toEqual([
      "RUNTIME_EVENT_KEY_MINIMUM_VERSION_SETUP_REQUIRED",
      "RUNTIME_OPERATOR_SETUP_REQUIRED",
      "RUNTIME_SECRET_STORE_SETUP_REQUIRED",
    ]);
    const storedCredential = await postCredentialFrame(
      server,
      initial.csrfToken,
      credentialPayload,
    );
    credentialPayload.fill(0);
    expect(storedCredential.status).toBe(200);
    expect(await storedCredential.json()).toEqual({
      stored: true,
      adapterEnabled: false,
    });
    const removedCredential = await postJson(
      server,
      "/api/hackerone/credentials/remove",
      initial.csrfToken,
      {},
    );
    expect(removedCredential.status).toBe(200);
    expect(await removedCredential.json()).toEqual({
      removed: true,
      adapterEnabled: false,
    });
    const disabled = await postJson(
      server,
      "/api/hackerone/integration/disable",
      initial.csrfToken,
      {},
    );
    expect(disabled.status).toBe(200);
    expect(await disabled.json()).toEqual({ enabled: false });
    const cases: readonly (readonly [string, unknown])[] = [
      ["/api/hackerone/integration/enable", {}],
      ["/api/hackerone/connection-test", {}],
      ["/api/hackerone/programs/synchronize", {}],
      ["/api/hackerone/program/select", { programRef: validRef }],
      ["/api/hackerone/program/synchronize", { programRef: validRef }],
      [
        "/api/hackerone/campaign/bind",
        { programRef: validRef, campaignId: "campaign_h1_0" },
      ],
      [
        "/api/hackerone/policy/accept",
        {
          confirmed: true,
          programRef: validRef,
          snapshotDigest: validDigest,
        },
      ],
      ["/api/hackerone/manual-import", { source: manualImportDocument() }],
    ];

    for (const [path, body] of cases) {
      const response = await postJson(server, path, initial.csrfToken, body);
      expect(response.status, path).toBe(409);
      expect(await response.json()).toEqual({
        error: "DASHBOARD_SECURE_CORE_NOT_READY",
      });
    }
    expect(credentials.storeCount).toBe(1);
    expect(credentials.removeCount).toBe(1);
    expect(transport.plans).toHaveLength(0);
    expect((await state(server)).hackerOne.programs).toHaveLength(0);
    expect(
      database.get("SELECT COUNT(*) AS total FROM hackerone_campaign_bindings"),
    ).toEqual({ total: 0 });
  });

  it("stores an exact binary credential frame locally without reflecting secrets and disables before mutation", async () => {
    const { server, credentials, transport } = await startHarness({
      killSwitchActive: false,
    });
    const identifier = "dashboard-local-identifier-7bf9";
    const token = "dashboard-local-token-4d2e";
    const initial = await state(server);

    const frame = credentialFrame(identifier, token);
    const stored = await postCredentialFrame(server, initial.csrfToken, frame);
    frame.fill(0);
    expect(stored.status).toBe(200);
    expect(await stored.json()).toEqual({
      stored: true,
      adapterEnabled: false,
    });
    expect(credentials).toMatchObject({ identifier, token, storeCount: 1 });
    expect(credentials.receivedBytePairs).toHaveLength(1);
    expect(
      credentials.receivedBytePairs[0]?.identifier.every((byte) => byte === 0),
    ).toBe(true);
    expect(
      credentials.receivedBytePairs[0]?.token.every((byte) => byte === 0),
    ).toBe(true);

    const afterStore = await state(server);
    expect(afterStore.hackerOne.status).toMatchObject({
      identifierPresent: true,
      tokenPresent: true,
      tokenFingerprint: sha256(new TextEncoder().encode(token)).slice(0, 12),
      adapterEnabled: false,
      targetRequestsEnabled: false,
      reportSubmissionEnabled: false,
    });
    const stateJson = JSON.stringify(afterStore);
    expect(stateJson).not.toContain(identifier);
    expect(stateJson).not.toContain(token);

    const [html, javascript] = await Promise.all([
      fetch(server.origin).then((response) => response.text()),
      fetch(`${server.origin}/hackerone.js`).then((response) =>
        response.text(),
      ),
    ]);
    expect(html).not.toContain(identifier);
    expect(html).not.toContain(token);
    expect(javascript).not.toContain(identifier);
    expect(javascript).not.toContain(token);
    expect(html).toContain("Credentials lokal speichern");
    expect(html).toContain('type="password"');
    expect(html).toContain('autocomplete="off"');
    expect(javascript).toContain("/api/hackerone/credentials/store");
    expect(javascript).toContain('"content-type": "application/octet-stream"');
    expect(javascript).toContain("frame.fill(0)");

    const enabled = await postJson(
      server,
      "/api/hackerone/integration/enable",
      initial.csrfToken,
      {},
    );
    expect(enabled.status).toBe(200);
    const connection = await postJson(
      server,
      "/api/hackerone/connection-test",
      initial.csrfToken,
      {},
    );
    expect(connection.status).toBe(200);
    expect(await connection.json()).toMatchObject({
      result: "connected",
      schemaValid: true,
    });
    expect(transport.plans).toHaveLength(1);
    expect(transport.plans[0]).toMatchObject({
      endpointClass: "programs",
      requestTarget: "/v1/hackers/programs?page[number]=1&page[size]=1",
    });

    const removed = await postJson(
      server,
      "/api/hackerone/credentials/remove",
      initial.csrfToken,
      {},
    );
    expect(removed.status).toBe(200);
    expect(await removed.json()).toEqual({
      removed: true,
      adapterEnabled: false,
    });
    expect((await state(server)).hackerOne.status).toMatchObject({
      adapterEnabled: false,
      identifierPresent: false,
      tokenPresent: false,
      tokenFingerprint: null,
    });
  });

  it("returns a local gateway error when a connection response fails schema validation", async () => {
    const { server, transport } = await startHarness({
      killSwitchActive: false,
    });
    const initial = await state(server);
    const frame = credentialFrame(
      "dashboard-malformed-identifier",
      "dashboard-malformed-token",
    );
    const stored = await postCredentialFrame(server, initial.csrfToken, frame);
    frame.fill(0);
    expect(stored.status).toBe(200);

    const enabled = await postJson(
      server,
      "/api/hackerone/integration/enable",
      initial.csrfToken,
      {},
    );
    expect(enabled.status).toBe(200);
    transport.responseBody = { data: "not-an-array" };

    const connection = await postJson(
      server,
      "/api/hackerone/connection-test",
      initial.csrfToken,
      {},
    );

    expect(connection.status).toBe(502);
    expect(await connection.json()).toEqual({
      error: "HACKERONE_CONNECTION_MALFORMED_RESPONSE",
    });
    expect(transport.plans).toHaveLength(1);
    expect((await state(server)).hackerOne.status).toMatchObject({
      lastConnectionResult: "malformed_response",
      lastErrorCode: "HACKERONE_CONNECTION_MALFORMED_RESPONSE",
    });
  });

  it("blocks the disabled capability and active kill switch before the in-process transport", async () => {
    const disabled = await startHarness({
      runtimeEnabled: false,
      killSwitchActive: false,
    });
    const disabledState = await state(disabled.server);
    expect(disabledState.hackerOne.status).toMatchObject({
      adapterConfigured: false,
      adapterEnabled: false,
      externalIntegrationsEnabled: false,
    });
    const enableBlocked = await postJson(
      disabled.server,
      "/api/hackerone/integration/enable",
      disabledState.csrfToken,
      {},
    );
    expect(enableBlocked.status).toBe(409);
    expect(await enableBlocked.json()).toEqual({
      error: "HACKERONE_METADATA_CAPABILITY_DISABLED",
    });
    expect(disabled.transport.plans).toHaveLength(0);

    const killed = await startHarness({ killSwitchActive: true });
    const killedState = await state(killed.server);
    const enabled = await postJson(
      killed.server,
      "/api/hackerone/integration/enable",
      killedState.csrfToken,
      {},
    );
    expect(enabled.status).toBe(409);
    expect(await enabled.json()).toEqual({ error: "HACKERONE_KILL_SWITCH" });
    expect((await state(killed.server)).hackerOne.status).toMatchObject({
      adapterEnabled: false,
      killSwitchActive: true,
    });
    expect(killed.transport.plans).toHaveLength(0);

    const disabledAgain = await postJson(
      killed.server,
      "/api/hackerone/integration/disable",
      killedState.csrfToken,
      {},
    );
    expect(disabledAgain.status).toBe(200);
    expect((await state(killed.server)).hackerOne.status.adapterEnabled).toBe(
      false,
    );
  });

  it("bounds catalog and policy-history projections while preserving the selected review snapshot", async () => {
    const { server } = await startHarness({
      hackerOneOverride: projectionOnlyService(1_005, 25),
      campaignSeedCount: 105,
    });

    const projected = (await state(server)).hackerOne;
    expect(projected.programCount).toBe(1_005);
    expect(projected.programsTruncated).toBe(true);
    expect(projected.programs).toHaveLength(1_000);
    expect(
      projected.programs.some(
        ({ localRef }) => localRef === projected.selectedProgramRef,
      ),
    ).toBe(true);
    for (const program of projected.programs)
      expect(program.program).not.toHaveProperty("policy");

    expect(projected.policyVersionCount).toBe(25);
    expect(projected.policyVersionsTruncated).toBe(true);
    expect(projected.policyVersions).toHaveLength(20);
    expect(projected.policyVersions[0]?.versionNumber).toBe(6);
    for (const version of projected.policyVersions) {
      expect(version.snapshot).not.toHaveProperty("program");
      expect(version.snapshot).not.toHaveProperty("structuredScopes");
      expect(version.snapshot).not.toHaveProperty("scopeExclusions");
    }
    expect(projected.previousPolicy).toMatchObject({
      policy: "historical-policy-23",
    });
    expect(projected.campaignCount).toBe(105);
    expect(projected.campaignsTruncated).toBe(true);
    expect(projected.campaigns).toHaveLength(100);
    for (const campaignSummary of projected.campaigns) {
      expect(campaignSummary).not.toHaveProperty("contract");
      expect(campaignSummary).not.toHaveProperty("approvedAssets");
      expect(campaignSummary).not.toHaveProperty("accountRefs");
    }

    const serialized = JSON.stringify(projected);
    expect(serialized).toContain("current-visible-policy");
    expect(serialized).toContain("current-visible-asset");
    expect(serialized).not.toContain("catalog-policy-");
    expect(serialized).toContain("historical-policy-23");
    expect(serialized).not.toContain("historical-policy-0");
    expect(serialized).not.toContain("historical-asset-");
  });

  it("accepts manual imports above 64 KiB and enforces the 1 MiB source plus bounded HTTP envelope", async () => {
    const { server, transport } = await startHarness({
      killSwitchActive: false,
    });
    const initial = await state(server);
    const accepted = await postJson(
      server,
      "/api/hackerone/manual-import",
      initial.csrfToken,
      { source: manualImportDocument("P".repeat(70_000)) },
    );
    expect(accepted.status).toBe(201);

    const oversizedSource = await postJson(
      server,
      "/api/hackerone/manual-import",
      initial.csrfToken,
      { source: "X".repeat(1_048_577) },
    );
    expect(oversizedSource.status).toBe(409);
    expect(await oversizedSource.json()).toEqual({
      error: "HACKERONE_DASHBOARD_MANUAL_IMPORT_INVALID",
    });

    const oversizedEnvelope = await postWithDeclaredContentLength(
      server,
      "/api/hackerone/manual-import",
      initial.csrfToken,
      2_098_177,
    );
    expect(oversizedEnvelope.status).toBe(413);
    expect(oversizedEnvelope.body).toEqual({
      error: "DASHBOARD_BODY_TOO_LARGE",
    });
    expect(transport.plans).toHaveLength(0);
    expect((await state(server)).hackerOne.programCount).toBe(1);
  });

  it("binds only the selected exact HackerOne program ref to an exact bounded local campaign ref", async () => {
    const { server, database, transport } = await startHarness({
      killSwitchActive: false,
      campaignSeedCount: 1,
    });
    const initial = await state(server);
    const imported = await postJson(
      server,
      "/api/hackerone/manual-import",
      initial.csrfToken,
      { source: manualImportDocument() },
    );
    expect(imported.status).toBe(201);
    const importedBody = (await imported.json()) as {
      readonly programRef: string;
    };
    const selected = await postJson(
      server,
      "/api/hackerone/program/select",
      initial.csrfToken,
      { programRef: importedBody.programRef },
    );
    expect(selected.status).toBe(200);

    const projected = (await state(server)).hackerOne;
    expect(projected.campaigns).toEqual([
      expect.objectContaining({
        id: "campaign_h1_0",
        state: "draft",
      }),
    ]);
    expect(projected.campaigns[0]).not.toHaveProperty("contract");

    const wrongSelected = await postJson(
      server,
      "/api/hackerone/campaign/bind",
      initial.csrfToken,
      {
        programRef: `h1m_${"f".repeat(64)}`,
        campaignId: "campaign_h1_0",
      },
    );
    expect(wrongSelected.status).toBe(409);
    expect(await wrongSelected.json()).toEqual({
      error: "HACKERONE_DASHBOARD_SELECTED_PROGRAM_CONFLICT",
    });

    const bound = await postJson(
      server,
      "/api/hackerone/campaign/bind",
      initial.csrfToken,
      {
        programRef: importedBody.programRef,
        campaignId: "campaign_h1_0",
      },
    );
    expect(bound.status).toBe(200);
    expect(await bound.json()).toEqual({
      bound: true,
      programRef: importedBody.programRef,
      campaignId: "campaign_h1_0",
    });
    expect(
      database.get(
        `SELECT program_local_ref,campaign_id
         FROM hackerone_campaign_bindings
         WHERE program_local_ref=? AND campaign_id=?`,
        importedBody.programRef,
        "campaign_h1_0",
      ),
    ).toEqual({
      program_local_ref: importedBody.programRef,
      campaign_id: "campaign_h1_0",
    });
    expect(transport.plans).toHaveLength(0);
  });

  it("imports and accepts a selected local snapshot only through exact explicit bodies", async () => {
    const { server, transport } = await startHarness({
      killSwitchActive: false,
    });
    const initial = await state(server);
    const imported = await postJson(
      server,
      "/api/hackerone/manual-import",
      initial.csrfToken,
      { source: manualImportDocument() },
    );
    expect(imported.status).toBe(201);
    const importResult = (await imported.json()) as {
      readonly programRef: string;
      readonly snapshotDigest: string;
      readonly source: string;
    };
    expect(importResult).toMatchObject({ source: "manual_unverified" });
    expect(importResult.programRef).toMatch(/^h1m_[0-9a-f]{64}$/u);
    expect(importResult.snapshotDigest).toMatch(/^[0-9a-f]{64}$/u);

    const selected = await postJson(
      server,
      "/api/hackerone/program/select",
      initial.csrfToken,
      { programRef: importResult.programRef },
    );
    expect(selected.status).toBe(200);
    const selectedState = await state(server);
    expect(selectedState.hackerOne).toMatchObject({
      selectedProgramRef: importResult.programRef,
      programs: [
        {
          localRef: importResult.programRef,
          source: "manual_unverified",
        },
      ],
      currentSnapshot: {
        programLocalRef: importResult.programRef,
        acceptancePending: true,
      },
    });
    expect(
      selectedState.hackerOne.currentSnapshot?.snapshot.structuredScopes[0]
        ?.assetIdentifier,
    ).toBe(ASSET_IDENTIFIER);
    expect(transport.plans).toHaveLength(0);

    const missingConfirmation = await postJson(
      server,
      "/api/hackerone/policy/accept",
      initial.csrfToken,
      {
        confirmed: false,
        programRef: importResult.programRef,
        snapshotDigest: importResult.snapshotDigest,
      },
    );
    expect(missingConfirmation.status).toBe(409);
    expect(await missingConfirmation.json()).toEqual({
      error: "HACKERONE_DASHBOARD_POLICY_ACCEPTANCE_INVALID",
    });

    const accepted = await postJson(
      server,
      "/api/hackerone/policy/accept",
      initial.csrfToken,
      {
        confirmed: true,
        programRef: importResult.programRef,
        snapshotDigest: importResult.snapshotDigest,
      },
    );
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toEqual({
      accepted: true,
      snapshotDigest: importResult.snapshotDigest,
    });
    expect(
      (await state(server)).hackerOne.currentSnapshot?.acceptancePending,
    ).toBe(false);
    expect(transport.plans).toHaveLength(0);
  });
});
