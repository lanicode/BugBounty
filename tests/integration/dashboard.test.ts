import { mkdtemp } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chromium } from "playwright";
import { afterEach, describe, expect, it } from "vitest";
import {
  ApprovalQueue,
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  startDashboardServer,
  type RunningDashboardServer,
} from "../../packages/dashboard/index.js";
import { DemoSaas } from "../../packages/demo-saas/index.js";
import { createGuardedContext } from "../../packages/egress-guard/playwright.js";
import {
  deriveRuntimeReadiness,
  type RuntimeReadiness,
} from "../../packages/local-runtime/index.js";
import { SimulationOrchestrator } from "../../packages/simulation/index.js";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";
import type { ProgramConfig } from "../../packages/config/types.js";
import { programConfig } from "../fixtures/factories.js";
import {
  TEST_OPERATOR_ID,
  TEST_OPERATOR_SIGNER,
} from "../fixtures/operator-auth.factory.js";

const NOW = Date.parse("2026-07-13T12:00:00.000Z");
const PHASE8_FLOW = Object.freeze([
  "onboarding_system_check",
  "onboarding_secret_store_check",
  "onboarding_select_simulation",
  "onboarding_configure_testmail",
  "onboarding_disable_ai",
  "onboarding_confirm_boundaries",
  "onboarding_initialize_demo",
  "create_program",
  "import_policy",
  "accept_policy",
  "create_campaign",
  "approve_campaign",
  "prepare_identities",
  "start_journey",
  "inspect_inventory",
  "generate_candidates",
  "verify_candidate",
  "open_evidence",
  "create_report",
  "queue_report_review",
  "approve_local_report",
] as const);
const PHASE8_CONFIRMATIONS = new Set([
  "onboarding_confirm_boundaries",
  "accept_policy",
  "approve_campaign",
  "start_journey",
  "verify_candidate",
  "queue_report_review",
  "approve_local_report",
]);

interface DashboardState {
  readonly csrfToken: string;
  readonly mode: "simulation";
  readonly externalIntegrationsEnabled: false;
  readonly phase1SecurityStatus: string;
  readonly simulationStatus: string;
  readonly simulationAvailable: boolean;
  readonly runtimeReadiness: {
    readonly status: string;
    readonly aiProviderStatus: string;
    readonly browserWorkerStatus: string;
    readonly externalIntegrationsEnabled: false;
  };
  readonly localProductIntegrity: {
    readonly status: "blocked_demo_drift" | "bound";
    readonly evidenceStatus: "not_created" | "stale_blocked" | "valid_bound";
    readonly reportStatus: "not_created" | "stale_blocked" | "valid_bound";
  };
  readonly operatorAuthentication: {
    readonly signerConfigured: boolean;
    readonly operatorId: string | null;
  };
  readonly killSwitch: { readonly active: boolean };
  readonly counts: {
    readonly programs: number;
    readonly activeCampaigns: number;
    readonly pausedCampaigns: number;
    readonly openApprovals: number;
    readonly reportDrafts: number;
    readonly identities: number;
    readonly ownedObjects: number;
    readonly policyVersions: number;
  };
  readonly programs: readonly { readonly id: string }[];
  readonly policyDiffs: readonly {
    readonly changedRules: {
      readonly added: readonly string[];
      readonly removed: readonly string[];
    };
  }[];
  readonly approvals: readonly {
    readonly id: string;
    readonly technicalDetails: string;
    readonly policyHash: string | null;
    readonly policyVersion: number | null;
    readonly payloadHash: string;
    readonly revision: number;
    readonly status: string;
  }[];
  readonly expert: { readonly auditLog: readonly string[] };
  readonly simulationReview: { readonly reviewDigest: string };
  readonly localProduct: {
    readonly workflowStatus: string;
    readonly stage: string;
    readonly nextAction: string | null;
    readonly progress: {
      readonly completedSteps: number;
      readonly totalSteps: 21;
    };
    readonly availableManagementActions: readonly string[];
    readonly onboarding: { readonly status: string };
    readonly program: null | { readonly lifecycle: string };
    readonly policy: null | {
      readonly status: string;
      readonly policyHash: string;
    };
    readonly campaign: null | { readonly status: string };
    readonly identities: readonly {
      readonly role: string;
      readonly sessionStatus: string;
    }[];
    readonly journey: null | {
      readonly browserStarted: false;
      readonly networkRequests: 0;
      readonly status: string;
    };
    readonly inventory: null | { readonly status: string };
    readonly candidates: readonly {
      readonly activeTestPerformed: false;
      readonly privacyStatus: string;
      readonly status: string;
    }[];
    readonly evidence: null | { readonly status: string };
    readonly report: null | {
      readonly externalSubmissionPerformed: false;
      readonly reviewStatus: string;
      readonly artifacts: {
        readonly markdown: string;
        readonly html: string;
        readonly json: string;
      };
    };
  };
}

interface SimulationResponse {
  readonly steps: readonly string[];
  readonly networkConnections: number;
  readonly externalSubmissions: number;
}

interface Harness {
  readonly database: ControlPlaneDatabase;
  readonly demo: DemoSaas;
  readonly store: ControlPlaneStore;
  readonly server: RunningDashboardServer;
}

const harnesses: Harness[] = [];

afterEach(async () => {
  await Promise.all(harnesses.map(({ server }) => server.close()));
  for (const { database } of harnesses) database.close();
  harnesses.length = 0;
});

async function startHarness(
  options: {
    readonly readiness?: RuntimeReadiness;
    readonly withOperatorSigner?: boolean;
    readonly withSimulation?: boolean;
  } = {},
): Promise<Harness> {
  const database = ControlPlaneDatabase.memory();
  let ticks = 0;
  const now = (): Date => new Date(NOW + ticks++ * 1_000);
  const store = new ControlPlaneStore(database, now);
  const demo = new DemoSaas(now);
  const operatorSigner =
    options.withOperatorSigner === false ? undefined : TEST_OPERATOR_SIGNER;
  let simulation: SimulationOrchestrator | undefined;
  if (options.withSimulation !== false) {
    const eventRoot = await mkdtemp(join(tmpdir(), "dashboard-events-"));
    const eventSecrets = new InMemorySecretStore();
    eventSecrets.set(
      "secret://dashboard/event-key",
      new Uint8Array(32).fill(9),
    );
    simulation = new SimulationOrchestrator(
      store,
      demo,
      eventRoot,
      eventSecrets,
      () => "secret://dashboard/event-key",
      now,
      1,
      operatorSigner,
    );
  }
  try {
    const dependencies = {
      store,
      demo,
      readiness:
        options.readiness ??
        deriveRuntimeReadiness({
          platform: "darwin",
          eventKeyMinimumVersion: simulation === undefined ? undefined : "1",
          operatorKeyReference:
            operatorSigner === undefined
              ? undefined
              : "keychain://test/operator-ed25519-v1",
          operatorId:
            operatorSigner === undefined ? undefined : TEST_OPERATOR_ID,
          operatorKeyRevision: operatorSigner === undefined ? undefined : "1",
          secretStoreProbe:
            simulation === undefined ? "not_checked" : "available",
          demoSaasReady: true,
          databaseReady: true,
        }),
      ...(simulation === undefined ? {} : { simulation }),
      ...(operatorSigner === undefined ? {} : { operatorSigner }),
      now,
    };
    const server = await startDashboardServer(dependencies, 0);
    const harness = { database, demo, store, server };
    harnesses.push(harness);
    return harness;
  } catch (error) {
    database.close();
    throw error;
  }
}

async function state(server: RunningDashboardServer): Promise<DashboardState> {
  const response = await fetch(`${server.origin}/api/state`);
  expect(response.status).toBe(200);
  return (await response.json()) as DashboardState;
}

async function postJson(
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

describe("local dashboard HTTP boundary", () => {
  it("serves a CSP-hardened same-origin UI and rejects forged requests", async () => {
    const { server } = await startHarness();
    expect(server.origin).toBe(`http://127.0.0.1:${server.port}`);

    const home = await fetch(server.origin);
    const html = await home.text();
    expect(home.status).toBe(200);
    expect(html).toContain("SIMULATIONSMODUS");
    expect(html).toContain("EXTERNE INTEGRATIONEN DEAKTIVIERT");
    expect(html).toContain("KEINE REALE REPORT-EINREICHUNG");
    expect(html).toContain("Geführter vollständiger Demoablauf");
    expect(html).toContain('src="/app.js"');
    expect(html).toContain('src="/phase8.js"');
    expect(html).toContain('href="/styles.css"');
    expect(home.headers.get("access-control-allow-origin")).toBeNull();
    const csp = home.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("unsafe-inline");

    const script = await (await fetch(`${server.origin}/app.js`)).text();
    expect(script).not.toContain("innerHTML");
    expect(script).not.toContain("https://");
    const phase8Script = await (
      await fetch(`${server.origin}/phase8.js`)
    ).text();
    expect(phase8Script).not.toContain("innerHTML");
    expect(phase8Script).not.toContain("https://");
    const initial = await state(server);
    expect(initial).toMatchObject({
      mode: "simulation",
      externalIntegrationsEnabled: false,
      phase1SecurityStatus: "enforced",
      operatorAuthentication: {
        signerConfigured: true,
        operatorId: TEST_OPERATOR_ID,
      },
      killSwitch: { active: true },
      counts: { programs: 0 },
    });

    const forgedHost = await rawRequest(server, {
      method: "GET",
      hostHeader: "attacker.invalid",
      path: "/api/state",
    });
    expect(forgedHost.statusCode).toBe(403);
    expect(forgedHost.body).toContain("DASHBOARD_HOST_BLOCKED");

    const foreignOrigin = await rawRequest(server, {
      method: "POST",
      hostHeader: `127.0.0.1:${server.port}`,
      path: "/api/kill-switch/engage",
      headers: {
        origin: "https://attacker.invalid",
        "content-type": "application/json",
        "x-csrf-token": initial.csrfToken,
      },
      body: Buffer.from('{"actor":"local-user","confirmed":true}'),
    });
    expect(foreignOrigin.statusCode).toBe(403);
    expect(foreignOrigin.body).toContain("DASHBOARD_ORIGIN_BLOCKED");

    const missingCsrf = await rawRequest(server, {
      method: "POST",
      hostHeader: `127.0.0.1:${server.port}`,
      path: "/api/kill-switch/engage",
      headers: {
        origin: server.origin,
        "content-type": "application/json",
      },
      body: Buffer.from('{"actor":"local-user","confirmed":true}'),
    });
    expect(missingCsrf.statusCode).toBe(403);
    expect(missingCsrf.body).toContain("DASHBOARD_CSRF_BLOCKED");

    const wrongContentType = await rawRequest(server, {
      method: "POST",
      hostHeader: `127.0.0.1:${server.port}`,
      path: "/api/kill-switch/engage",
      headers: {
        origin: server.origin,
        "content-type": "text/plain",
        "x-csrf-token": initial.csrfToken,
      },
      body: Buffer.from("blocked"),
    });
    expect(wrongContentType.statusCode).toBe(415);

    const duplicateJsonKey = await rawRequest(server, {
      method: "POST",
      hostHeader: `127.0.0.1:${server.port}`,
      path: "/api/kill-switch/engage",
      headers: {
        origin: server.origin,
        "content-type": "application/json",
        "x-csrf-token": initial.csrfToken,
      },
      body: Buffer.from('{"actor":"first","actor":"second","confirmed":true}'),
    });
    expect(duplicateJsonKey.statusCode).toBe(400);
    expect(duplicateJsonKey.body).toContain("DASHBOARD_JSON_INVALID");

    const invalidUtf8 = await rawRequest(server, {
      method: "POST",
      hostHeader: `127.0.0.1:${server.port}`,
      path: "/api/kill-switch/engage",
      headers: {
        origin: server.origin,
        "content-type": "application/json",
        "x-csrf-token": initial.csrfToken,
      },
      body: Buffer.from([0xc3, 0x28]),
    });
    expect(invalidUtf8.statusCode).toBe(400);
    expect(invalidUtf8.body).toContain("DASHBOARD_JSON_INVALID");

    const oversized = await rawRequest(server, {
      method: "POST",
      hostHeader: `127.0.0.1:${server.port}`,
      path: "/api/programs/import",
      headers: {
        origin: server.origin,
        "content-type": "application/json",
        "x-csrf-token": initial.csrfToken,
      },
      body: Buffer.alloc(65_537, 0x61),
    });
    expect(oversized.statusCode).toBe(413);
    expect(oversized.body).toContain("DASHBOARD_BODY_TOO_LARGE");
  });

  it("imports only supplied local JSON and YAML content", async () => {
    const { server } = await startHarness();
    const initial = await state(server);
    const jsonImport = JSON.stringify(importRecord("program-json", "JSON"));
    const jsonResponse = await postJson(
      server,
      "/api/programs/import",
      initial.csrfToken,
      { format: "json", source: jsonImport },
    );
    expect(jsonResponse.status).toBe(201);

    const yamlSource = `
id: program-yaml
name: Local YAML Program
platform: local_mock
status: available
description: Local fixture content
program_url: http://127.0.0.1/yaml-metadata
program_type: simulation
allowed_assets: [yaml.demo.local]
excluded_assets: [admin.yaml.demo.local]
last_synchronized_at: null
automation_permission: allowed
notes: Never fetched
lifecycle: active
`;
    const yamlResponse = await postJson(
      server,
      "/api/programs/import",
      initial.csrfToken,
      { format: "yaml", source: yamlSource },
    );
    expect(yamlResponse.status).toBe(201);

    const after = await state(server);
    expect(after.counts.programs).toBe(2);
    expect(after.programs.map(({ id }) => id)).toEqual([
      "program-json",
      "program-yaml",
    ]);
  });

  it("keeps the UI and guided demo available when secure simulation setup is missing", async () => {
    const { server, store } = await startHarness({
      withOperatorSigner: false,
      withSimulation: false,
    });
    const initial = await state(server);
    expect(initial).toMatchObject({
      simulationAvailable: false,
      simulationStatus: "setup_required",
      operatorAuthentication: {
        signerConfigured: false,
        operatorId: null,
      },
      runtimeReadiness: {
        status: "setup_required",
        externalIntegrationsEnabled: false,
        aiProviderStatus: "disabled_not_implemented",
        browserWorkerStatus: "test_harness_only",
      },
      killSwitch: { active: true },
      localProduct: {
        nextAction: "onboarding_system_check",
        workflowStatus: "guided",
      },
    });

    const blocked = await postJson(
      server,
      "/api/simulation/run",
      initial.csrfToken,
      {
        actor: TEST_OPERATOR_ID,
        confirmations: confirmations(),
        confirmationTimes: confirmationTimes(),
        reviewDigest: "a".repeat(64),
      },
    );
    expect(blocked.status).toBe(409);
    expect(await blocked.json()).toEqual({
      error: "DASHBOARD_SECURE_CORE_NOT_READY",
    });
    expect(store.isKillSwitchActive()).toBe(true);

    const blockedCoreMutations = [
      await postJson(server, "/api/programs/import", initial.csrfToken, {
        format: "json",
        source: JSON.stringify(importRecord("blocked-program", "Blocked")),
      }),
      await postJson(server, "/api/kill-switch/clear", initial.csrfToken, {
        actor: TEST_OPERATOR_ID,
        confirmed: true,
      }),
      await postJson(server, "/api/approvals/decide", initial.csrfToken, {}),
    ];
    for (const response of blockedCoreMutations) {
      expect(response.status).toBe(409);
      expect(await response.json()).toEqual({
        error: "DASHBOARD_SECURE_CORE_NOT_READY",
      });
    }
    expect(store.listPrograms()).toHaveLength(0);

    const guided = await postJson(
      server,
      "/api/local-product/action",
      initial.csrfToken,
      { action: "onboarding_system_check" },
    );
    expect(guided.status).toBe(200);
    expect((await state(server)).localProduct.progress.completedSteps).toBe(1);
    expect(store.listPrograms()).toHaveLength(0);
  });

  it("binds onboarding checks to observed local runtime gates", async () => {
    const databaseBlocked = deriveRuntimeReadiness({
      platform: "darwin",
      eventKeyMinimumVersion: undefined,
      operatorKeyReference: undefined,
      operatorId: undefined,
      operatorKeyRevision: undefined,
      secretStoreProbe: "not_checked",
      demoSaasReady: true,
      databaseReady: false,
    });
    const databaseHarness = await startHarness({
      readiness: databaseBlocked,
      withOperatorSigner: false,
      withSimulation: false,
    });
    const databaseState = await state(databaseHarness.server);
    const systemCheck = await postJson(
      databaseHarness.server,
      "/api/local-product/action",
      databaseState.csrfToken,
      { action: "onboarding_system_check" },
    );
    expect(systemCheck.status).toBe(409);
    expect(await systemCheck.json()).toEqual({
      error: "DASHBOARD_LOCAL_SYSTEM_CHECK_BLOCKED",
    });
    expect((await state(databaseHarness.server)).localProduct.progress).toEqual(
      { completedSteps: 0, totalSteps: 21 },
    );

    const secretBlocked = deriveRuntimeReadiness({
      platform: "darwin",
      eventKeyMinimumVersion: undefined,
      operatorKeyReference: undefined,
      operatorId: undefined,
      operatorKeyRevision: undefined,
      secretStoreProbe: "error",
      demoSaasReady: true,
      databaseReady: true,
    });
    const secretHarness = await startHarness({
      readiness: secretBlocked,
      withOperatorSigner: false,
      withSimulation: false,
    });
    const secretState = await state(secretHarness.server);
    expect(
      await postJson(
        secretHarness.server,
        "/api/local-product/action",
        secretState.csrfToken,
        { action: "onboarding_system_check" },
      ),
    ).toMatchObject({ status: 200 });
    const secretCheck = await postJson(
      secretHarness.server,
      "/api/local-product/action",
      secretState.csrfToken,
      { action: "onboarding_secret_store_check" },
    );
    expect(secretCheck.status).toBe(409);
    expect(await secretCheck.json()).toEqual({
      error: "DASHBOARD_LOCAL_SECRET_STORE_CHECK_BLOCKED",
    });
    expect((await state(secretHarness.server)).localProduct.progress).toEqual({
      completedSteps: 1,
      totalSteps: 21,
    });
  });

  it("blocks the guided projection when its bound Demo-SaaS snapshot drifts", async () => {
    const { demo, server } = await startHarness();
    const initial = await state(server);
    demo.createProject({
      actorRef: "identity-owner-001",
      projectRef: "project-drift-001",
      displayName: "Intentional local drift fixture",
    });

    const response = await postJson(
      server,
      "/api/local-product/action",
      initial.csrfToken,
      { action: "onboarding_system_check" },
    );
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      error: "DASHBOARD_LOCAL_DEMO_DRIFT_BLOCKED",
    });
    const drifted = await state(server);
    expect(drifted.localProduct.progress.completedSteps).toBe(0);
    expect(drifted.localProductIntegrity).toMatchObject({
      status: "blocked_demo_drift",
      evidenceStatus: "not_created",
      reportStatus: "not_created",
    });

    const reportHarness = await startHarness();
    for (const action of PHASE8_FLOW) {
      const before = await state(reportHarness.server);
      const completed = await postJson(
        reportHarness.server,
        "/api/local-product/action",
        before.csrfToken,
        phase8Payload(action),
      );
      expect(completed.status).toBe(200);
    }
    reportHarness.demo.createProject({
      actorRef: "identity-owner-001",
      projectRef: "project-report-drift-001",
      displayName: "Post-report local drift fixture",
    });
    expect(
      (await state(reportHarness.server)).localProductIntegrity,
    ).toMatchObject({
      status: "blocked_demo_drift",
      evidenceStatus: "stale_blocked",
      reportStatus: "stale_blocked",
    });
    const browser = await chromium.launch({ headless: true });
    const context = await createGuardedContext(
      browser,
      dashboardPolicy(reportHarness.server),
    );
    try {
      const page = await context.newPage();
      await page.goto(reportHarness.server.origin);
      await page
        .locator("#phase8-guidance")
        .filter({ hasText: "App beenden und mit pnpm app neu starten" })
        .waitFor();
      expect(await page.locator("#phase8-primary-action").isDisabled()).toBe(
        true,
      );
      expect(
        await page.locator("#phase8-report-preview").textContent(),
      ).toContain("BLOCKIERT: Demo-SaaS-Drift");
      expect(
        await page.locator("#phase8-journey-result-preview").textContent(),
      ).toContain("BLOCKIERT: Demo-SaaS-Drift");
    } finally {
      await context.close();
      await browser.close();
    }
  });

  it("runs all 18 local steps only after six confirmations and controls the kill switch", async () => {
    const { server } = await startHarness();
    const initial = await state(server);
    const missingConfirmation = await postJson(
      server,
      "/api/simulation/run",
      initial.csrfToken,
      {
        actor: TEST_OPERATOR_ID,
        confirmations: {
          ...confirmations(),
          queueReportReview: false,
        },
        confirmationTimes: confirmationTimes(),
        reviewDigest: initial.simulationReview.reviewDigest,
      },
    );
    expect(missingConfirmation.status).toBe(409);

    const response = await postJson(
      server,
      "/api/simulation/run",
      initial.csrfToken,
      {
        actor: TEST_OPERATOR_ID,
        confirmations: confirmations(),
        confirmationTimes: confirmationTimes(),
        reviewDigest: initial.simulationReview.reviewDigest,
      },
    );
    expect(response.status).toBe(200);
    const summary = (await response.json()) as SimulationResponse;
    expect(summary.steps).toHaveLength(18);
    expect(summary.networkConnections).toBe(0);
    expect(summary.externalSubmissions).toBe(0);

    const after = await state(server);
    expect(after).toMatchObject({
      simulationStatus: "completed",
      killSwitch: { active: false },
      counts: {
        programs: 1,
        activeCampaigns: 1,
        policyVersions: 2,
        identities: 3,
        ownedObjects: 1,
        reportDrafts: 1,
        openApprovals: 1,
      },
    });
    expect(after.policyDiffs).toHaveLength(1);
    expect(after.policyDiffs[0]?.changedRules.added).toEqual([
      "reapproval_required_after_drift",
    ]);

    const engaged = await postJson(
      server,
      "/api/kill-switch/engage",
      after.csrfToken,
      { actor: TEST_OPERATOR_ID, confirmed: true },
    );
    expect(engaged.status).toBe(200);
    expect(await engaged.json()).toMatchObject({ active: true });
    expect((await state(server)).killSwitch.active).toBe(true);

    const cleared = await postJson(
      server,
      "/api/kill-switch/clear",
      after.csrfToken,
      { actor: TEST_OPERATOR_ID, confirmed: true },
    );
    expect(cleared.status).toBe(200);
    expect(await cleared.json()).toMatchObject({ active: false });
    const afterClear = await state(server);
    expect(afterClear.killSwitch.active).toBe(false);
    expect(
      afterClear.expert.auditLog.some((line) =>
        line.includes("kill_switch_change"),
      ),
    ).toBe(true);

    const openApproval = afterClear.approvals.find(
      ({ id }) => id === "report-review-approval",
    );
    expect(openApproval).toBeDefined();
    const decision = await postJson(
      server,
      "/api/approvals/decide",
      afterClear.csrfToken,
      {
        id: openApproval?.id,
        expectedRevision: openApproval?.revision,
        expectedPayloadHash: openApproval?.payloadHash,
        decision: "accepted",
        actor: TEST_OPERATOR_ID,
        userAction: "explicit_local_report_review",
      },
    );
    expect(decision.status).toBe(200);
    const decidedState = await state(server);
    expect(
      decidedState.approvals.find(({ id }) => id === "report-review-approval"),
    ).toMatchObject({ status: "accepted", revision: 1 });
    expect(
      decidedState.expert.auditLog.some((line) =>
        line.includes("approval_decision"),
      ),
    ).toBe(true);
  });

  it("executes the closed Phase-8 product flow without network or core-store mutations", async () => {
    const { server, store } = await startHarness();
    const initial = await state(server);
    expect(initial.localProduct).toMatchObject({
      workflowStatus: "guided",
      stage: "onboarding",
      nextAction: "onboarding_system_check",
      progress: { completedSteps: 0, totalSteps: 21 },
    });
    const initialCounts = initial.counts;

    const forged = await postJson(
      server,
      "/api/local-product/action",
      initial.csrfToken,
      { action: "create_program", confirmed: true },
    );
    expect(forged.status).toBe(409);
    expect((await state(server)).localProduct.progress.completedSteps).toBe(0);

    for (const [index, action] of PHASE8_FLOW.entries()) {
      const before = await state(server);
      expect(before.localProduct.nextAction).toBe(action);
      if (action === "create_campaign") {
        const subset = await postJson(
          server,
          "/api/local-product/action",
          before.csrfToken,
          {
            ...phase8Payload(action),
            roles: ["Owner", "Member"],
          },
        );
        expect(subset.status).toBe(409);
        expect((await state(server)).localProduct.progress.completedSteps).toBe(
          index,
        );
      }
      const response = await postJson(
        server,
        "/api/local-product/action",
        before.csrfToken,
        phase8Payload(action),
      );
      expect(response.status).toBe(200);
      const body = (await response.json()) as {
        readonly localProduct: {
          readonly progress: { readonly completedSteps: number };
        };
      };
      expect(body.localProduct.progress.completedSteps).toBe(index + 1);
    }

    const completed = await state(server);
    expect(completed.localProduct).toMatchObject({
      workflowStatus: "completed_local_only",
      stage: "complete",
      nextAction: null,
      onboarding: { status: "complete" },
      program: { lifecycle: "active" },
      policy: { status: "accepted_local" },
      campaign: { status: "completed_local_only" },
      journey: {
        browserStarted: false,
        networkRequests: 0,
        status: "completed_local_simulation",
      },
      inventory: { status: "inspected_local" },
      evidence: { status: "open_local_bundle" },
      report: {
        reviewStatus: "approved_local_only",
        externalSubmissionPerformed: false,
      },
    });
    expect(completed.localProduct.identities.map(({ role }) => role)).toEqual([
      "Owner",
      "Member",
      "External",
    ]);
    expect(completed.localProduct.candidates).toEqual([
      expect.objectContaining({
        status: "verified_local_fixture",
        activeTestPerformed: false,
        privacyStatus: "redacted_metadata_only",
      }),
    ]);
    expect(completed.localProduct.report?.artifacts.markdown).toContain(
      "External action: none.",
    );
    expect(completed.counts).toEqual(initialCounts);
    expect(store.listPrograms()).toHaveLength(0);
    expect(store.listCampaigns()).toHaveLength(0);
    expect(store.listReportDrafts()).toHaveLength(0);
    expect(store.isKillSwitchActive()).toBe(true);
  });

  it("fails closed for positive operations when secure runtime readiness is absent", async () => {
    const { database, store, server } = await startHarness({
      withOperatorSigner: false,
    });
    const approval = new ApprovalQueue().enqueue({
      id: "unsigned-dashboard-approval",
      kind: "report_bundle",
      summary: "Review a local unsigned dashboard fixture",
      technicalDetails: "Local fixture only; no external submission exists.",
      impact: "No effect unless an authenticated operator decides it.",
      policyVersion: null,
      policyHash: null,
      createdAt: "2026-07-13T11:59:59.000Z",
      auditReference: "audit:unsigned-dashboard-approval",
    });
    store.persistApproval(approval);

    const initial = await state(server);
    const baseline = persistedDashboardState(initial);
    expect(initial).toMatchObject({
      simulationStatus: "setup_required",
      operatorAuthentication: {
        signerConfigured: false,
        operatorId: null,
      },
      killSwitch: { active: true },
      counts: { openApprovals: 1 },
    });

    const simulation = await postJson(
      server,
      "/api/simulation/run",
      initial.csrfToken,
      {
        actor: TEST_OPERATOR_ID,
        confirmations: confirmations(),
        confirmationTimes: confirmationTimes(),
        reviewDigest: initial.simulationReview.reviewDigest,
      },
    );
    expect(simulation.status).toBe(409);
    expect(await simulation.json()).toEqual({
      error: "DASHBOARD_SECURE_CORE_NOT_READY",
    });
    expect(persistedDashboardState(await state(server))).toEqual(baseline);

    const clear = await postJson(
      server,
      "/api/kill-switch/clear",
      initial.csrfToken,
      { actor: TEST_OPERATOR_ID, confirmed: true },
    );
    expect(clear.status).toBe(409);
    expect(await clear.json()).toEqual({
      error: "DASHBOARD_SECURE_CORE_NOT_READY",
    });
    expect(persistedDashboardState(await state(server))).toEqual(baseline);

    const decision = await postJson(
      server,
      "/api/approvals/decide",
      initial.csrfToken,
      {
        id: approval.id,
        expectedRevision: approval.revision,
        expectedPayloadHash: approval.payloadHash,
        decision: "accepted",
        actor: TEST_OPERATOR_ID,
        userAction: "unsigned_local_dashboard_decision",
      },
    );
    expect(decision.status).toBe(409);
    expect(await decision.json()).toEqual({
      error: "DASHBOARD_SECURE_CORE_NOT_READY",
    });
    expect(persistedDashboardState(await state(server))).toEqual(baseline);
    expect(store.isKillSwitchActive()).toBe(true);
    expect(store.getLocalOperatorCredential()).toBeUndefined();
    expect(
      database.get(
        "SELECT COUNT(*) AS total FROM operator_signed_statements",
      )?.["total"],
    ).toBe(0);
  });

  it("permits fail-safe kill-switch engagement without an operator signer", async () => {
    const { database, store, server } = await startHarness({
      withOperatorSigner: false,
    });
    const initial = await state(server);
    expect(initial.operatorAuthentication).toEqual({
      signerConfigured: false,
      operatorId: null,
    });
    expect(initial.killSwitch.active).toBe(true);
    const initialRevision = database.get(
      "SELECT revision FROM system_state WHERE key='global_kill_switch'",
    )?.["revision"];
    if (typeof initialRevision !== "number")
      throw new Error("TEST_KILL_SWITCH_REVISION_MISSING");

    const engaged = await postJson(
      server,
      "/api/kill-switch/engage",
      initial.csrfToken,
      { actor: TEST_OPERATOR_ID, confirmed: true },
    );
    expect(engaged.status).toBe(200);
    expect(await engaged.json()).toMatchObject({
      active: true,
      revision: initialRevision + 1,
    });

    const after = await state(server);
    expect(after.operatorAuthentication).toEqual(
      initial.operatorAuthentication,
    );
    expect(after.killSwitch.active).toBe(true);
    expect(after.counts).toEqual(initial.counts);
    expect(after.simulationStatus).toBe(initial.simulationStatus);
    expect(
      after.expert.auditLog.some(
        (line) =>
          line.includes("kill_switch_change") && line.includes("engaged"),
      ),
    ).toBe(true);
    expect(store.isKillSwitchActive()).toBe(true);
    expect(store.getLocalOperatorCredential()).toBeUndefined();
    expect(
      database.get(
        "SELECT COUNT(*) AS total FROM operator_signed_statements",
      )?.["total"],
    ).toBe(0);
  });
});

describe("local dashboard browser UI", () => {
  it("disables positive core controls but keeps fail-safe kill engagement usable during setup", async () => {
    const { server, store } = await startHarness({
      withOperatorSigner: false,
      withSimulation: false,
    });
    const browser = await chromium.launch({ headless: true });
    const context = await createGuardedContext(
      browser,
      dashboardPolicy(server),
    );
    try {
      const page = await context.newPage();
      let stateRefreshes = 0;
      page.on("request", (requestEvent) => {
        if (new URL(requestEvent.url()).pathname === "/api/state")
          stateRefreshes += 1;
      });
      await page.goto(server.origin);
      await page.locator("#phase8-runtime-state").waitFor();
      const refreshesAfterLoad = stateRefreshes;
      await expect
        .poll(() => stateRefreshes, { timeout: 4_000 })
        .toBeGreaterThan(refreshesAfterLoad);
      expect(await page.locator("#run-simulation").isDisabled()).toBe(true);
      expect(await page.locator("#clear-kill").isDisabled()).toBe(true);
      expect(await page.locator("#engage-kill").isEnabled()).toBe(true);
      expect(await page.locator("#simulation-actor").inputValue()).toBe(
        "local-operator",
      );
      await page.locator("#engage-kill").click();
      await page
        .locator("#kill-operation-status")
        .filter({ hasText: "Kill Switch ist aktiv." })
        .waitFor();
      expect(store.isKillSwitchActive()).toBe(true);
      expect(await page.locator("#phase8-primary-action").isEnabled()).toBe(
        true,
      );
    } finally {
      await context.close();
      await browser.close();
    }
  });

  it("completes the 21-step usable-product journey entirely through fixed UI controls", async () => {
    const { server, store } = await startHarness();
    const browser = await chromium.launch({ headless: true });
    const context = await createGuardedContext(
      browser,
      dashboardPolicy(server),
    );
    try {
      const requestedOrigins = new Set<string>();
      const page = await context.newPage();
      page.on("request", (requestEvent) => {
        requestedOrigins.add(new URL(requestEvent.url()).origin);
      });
      await page.goto(server.origin);
      await page
        .getByRole("heading", { name: "Geführter vollständiger Demoablauf" })
        .waitFor();
      const keychainInputs = page.locator(
        "#hackerone-identifier, #hackerone-token",
      );
      expect(await keychainInputs.count()).toBe(2);
      expect(await page.locator('input[type="password"]').count()).toBe(2);
      await page
        .getByText("weder angezeigt noch in Browser-Speichern persistiert", {
          exact: false,
        })
        .waitFor();
      expect(
        await page
          .locator("#phase8-primary-action")
          .getAttribute("data-action"),
      ).toBe(PHASE8_FLOW[0]);

      for (const [index, action] of PHASE8_FLOW.entries()) {
        const button = page.locator("#phase8-primary-action");
        expect(await button.getAttribute("data-action")).toBe(action);
        if (action === "onboarding_configure_testmail")
          await page
            .locator("#phase8-testmail-schema")
            .selectOption("subaddress_fixture");
        if (action === "create_program")
          await page.locator("#phase8-exclude-admin").uncheck();
        if (action === "import_policy") {
          expect(await page.locator("#phase8-edit-program").isEnabled()).toBe(
            true,
          );
          await page.locator("#phase8-edit-program").click();
          await page
            .locator("#phase8-program")
            .filter({ hasText: "Local Demo Program Reviewed" })
            .waitFor();
          expect(await button.getAttribute("data-action")).toBe(action);
          await page
            .locator("#phase8-policy-representation")
            .selectOption("structured_fixture");
        }
        if (action === "create_campaign") {
          await page.locator("#phase8-max-requests").selectOption("4");
          await page.locator("#phase8-requests-per-minute").selectOption("1");
        }
        if (action === "start_journey") {
          expect(await page.locator("#phase8-start-sessions").isEnabled()).toBe(
            true,
          );
          await page.locator("#phase8-start-sessions").click();
          await page
            .locator("#phase8-identities")
            .filter({ hasText: "active_local" })
            .waitFor();
          expect(await button.getAttribute("data-action")).toBe(action);
        }
        await button.click();
        await page
          .locator("#phase8-stage")
          .filter({ hasText: `${String(index + 1)}/21` })
          .waitFor();
      }

      expect(await page.locator("#phase8-primary-action").isDisabled()).toBe(
        true,
      );
      expect(await page.locator("#phase8-stage").textContent()).toContain(
        "complete · 21/21",
      );
      expect(
        await page.locator("#phase8-journey-details").textContent(),
      ).toContain("Produkt-Browser gestartet: nein");
      expect(
        await page.locator("#phase8-journey-details").textContent(),
      ).toContain("Netzwerkrequests: 0");
      expect(
        await page.locator("#phase8-candidate-details").textContent(),
      ).toContain("Risikostufe: tier_0_offline");
      expect(
        await page.locator("#phase8-candidate-details").textContent(),
      ).toContain("Aktiver Test: nein");
      expect(await page.locator("#phase8-program").textContent()).toContain(
        "Importdarstellung: structured_fixture",
      );
      expect(await page.locator("#phase8-program").textContent()).toContain(
        "Baseline-Hash:",
      );
      expect(await page.locator("#phase8-program").textContent()).toContain(
        "Request-Limit: 1 → 8",
      );
      expect(await page.locator("#phase8-program").textContent()).toContain(
        "Ausgeschlossen: —",
      );
      expect(await page.locator("#phase8-campaign").textContent()).toContain(
        "Request-Budget: 4",
      );
      expect(await page.locator("#phase8-campaign").textContent()).toContain(
        "Pro Minute: 1",
      );
      expect(
        await page.locator("#phase8-evidence-details").textContent(),
      ).toContain("Extern eingereicht: nein");
      await page.locator("#phase8-open-journey-result").click();
      expect(
        await page.locator("#phase8-journey-result-preview").textContent(),
      ).toContain("Projizierte Schritte: 20");
      await page.locator("#phase8-report-markdown").click();
      expect(
        await page.locator("#phase8-report-preview").textContent(),
      ).toContain("External action: none.");
      expect(await page.evaluate(() => localStorage.length)).toBe(0);
      expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
      expect(await context.cookies()).toEqual([]);
      expect([...requestedOrigins]).toEqual([server.origin]);
      expect(store.listPrograms()).toHaveLength(0);
      expect(store.listCampaigns()).toHaveLength(0);
      expect(store.listReportDrafts()).toHaveLength(0);
      expect(store.isKillSwitchActive()).toBe(true);
    } finally {
      await context.close();
      await browser.close();
    }
  });

  it("renders every section and completes the explicit local workflow", async () => {
    const { server } = await startHarness();
    const browser = await chromium.launch({ headless: true });
    const context = await createGuardedContext(
      browser,
      dashboardPolicy(server),
    );
    try {
      const requestedOrigins = new Set<string>();
      const page = await context.newPage();
      page.on("request", (requestEvent) => {
        requestedOrigins.add(new URL(requestEvent.url()).origin);
      });
      await page.goto(server.origin);
      const simulationBanner = page.getByText("SIMULATIONSMODUS", {
        exact: true,
      });
      await simulationBanner.waitFor();
      expect(await simulationBanner.isVisible()).toBe(true);
      const externalBanner = page.getByText(
        "EXTERNE INTEGRATIONEN DEAKTIVIERT",
        { exact: true },
      );
      await externalBanner.waitFor();
      expect(await externalBanner.isVisible()).toBe(true);
      expect(await page.locator("#simulation-actor").inputValue()).toBe(
        TEST_OPERATOR_ID,
      );
      expect(await page.locator("#simulation-actor").isEditable()).toBe(false);
      for (const heading of [
        "Übersicht",
        "Programme",
        "Policies und Änderungen",
        "Kampagnen",
        "Aktionen erforderlich",
        "Testidentitäten",
        "Eigene Testobjekte",
        "Reports und Report-Entwürfe",
        "Systemstatus und globaler Kill Switch",
        "Expertenansicht",
      ]) {
        const sectionHeading = page.getByRole("heading", { name: heading });
        await sectionHeading.waitFor();
        expect(await sectionHeading.isVisible()).toBe(true);
      }

      const xssPayload = `<img src=x onerror="document.body.dataset.dashboardXss='executed'">`;
      await page.evaluate(() => {
        document.body.dataset["dashboardXss"] = "safe";
      });
      await page.locator("#import-source").fill(
        JSON.stringify(
          {
            ...importRecord("program-ui-import", "UI"),
            name: `Lokales ${xssPayload}`,
          },
          null,
          2,
        ),
      );
      await page.locator("#import-program").click();
      await page
        .locator("#import-status")
        .filter({ hasText: "Importiert: program-ui-import" })
        .waitFor();
      expect(await page.locator("#import-status").textContent()).toContain(
        "Importiert: program-ui-import",
      );
      await page.locator("#count-programs").filter({ hasText: "1" }).waitFor();
      expect(await page.locator("#count-programs").textContent()).toBe("1");
      expect(await page.locator("#program-list").textContent()).toContain(
        xssPayload,
      );
      expect(await page.locator("#program-list img").count()).toBe(0);
      expect(
        await page.evaluate(() => document.body.dataset["dashboardXss"]),
      ).toBe("safe");

      const reviewText = await page.locator("#simulation-review").textContent();
      expect(reviewText).toContain("Review-Digest:");
      expect(reviewText).toContain("Kampagne v1: Digest");
      expect(reviewText).toContain("Methoden GET, HEAD");
      expect(reviewText).toContain("Write false");
      expect(reviewText).toContain("Rollback true");
      expect(reviewText).toContain("reapproval_required_after_drift");
      expect(reviewText).toContain("verbotene Klassen active_security_test");
      expect(await page.locator("#confirm-acceptPolicyV1").isDisabled()).toBe(
        true,
      );

      for (const name of [
        "clearKillSwitch",
        "acceptPolicyV1",
        "approveCampaignV1",
        "acceptPolicyV2",
        "approveCampaignV2",
        "queueReportReview",
      ])
        await page.locator(`#confirm-${name}`).check();
      expect(await page.locator("#run-simulation").isEnabled()).toBe(true);
      await page.locator("#run-simulation").click();
      await page
        .locator("#simulation-result")
        .filter({ hasText: "Simulation abgeschlossen: 18 Schritte" })
        .waitFor();
      expect(await page.locator("#simulation-result").textContent()).toContain(
        "Simulation abgeschlossen: 18 Schritte",
      );
      await page.locator("#count-programs").filter({ hasText: "2" }).waitFor();
      expect(await page.locator("#count-programs").textContent()).toBe("2");
      await page.locator("#count-reports").filter({ hasText: "1" }).waitFor();
      expect(await page.locator("#count-reports").textContent()).toBe("1");
      expect(await page.locator("#policy-diff-list").textContent()).toContain(
        "Sonstige Regeln hinzugefügt: reapproval_required_after_drift",
      );
      const approvalText = await page.locator("#approval-list").textContent();
      expect(approvalText).toContain("No submission runner exists in Phase 2.");
      expect(approvalText).toContain("Payload-Hash:");
      expect(approvalText).toContain("Policy: v2 /");

      await page.locator("#engage-kill").click();
      await page
        .locator("#kill-status")
        .filter({ hasText: "AKTIV / BLOCKIERT" })
        .waitFor();
      expect(await page.locator("#kill-status").textContent()).toBe(
        "AKTIV / BLOCKIERT",
      );
      await page
        .locator("#phase8-runtime-details")
        .filter({ hasText: "Kill Switch: aktiv" })
        .waitFor();
      await page.locator("#clear-kill").click();
      await page
        .locator("#kill-status")
        .filter({ hasText: "FREIGEGEBEN" })
        .waitFor();
      expect(await page.locator("#kill-status").textContent()).toBe(
        "FREIGEGEBEN",
      );
      await page
        .locator("#phase8-runtime-details")
        .filter({ hasText: "Kill Switch: freigegeben" })
        .waitFor();
      await page
        .getByRole("button", { name: "Ausdrücklich akzeptieren" })
        .click();
      const reportApproval = page
        .locator("#approval-list .data-item")
        .filter({ hasText: "Review local simulation report" });
      await reportApproval.filter({ hasText: "Status: accepted" }).waitFor();
      expect(await reportApproval.textContent()).toContain(
        "explicit_local_dashboard_accepted",
      );
      expect([...requestedOrigins]).toEqual([server.origin]);
    } finally {
      await context.close();
      await browser.close();
    }
  });
});

function importRecord(id: string, label: string): Record<string, unknown> {
  return {
    id,
    name: `Local ${label} Program`,
    platform: "local_mock",
    status: "available",
    description: "Local fixture content",
    program_url: "http://127.0.0.1/local-metadata",
    program_type: "simulation",
    allowed_assets: [`${id}.demo.local`],
    excluded_assets: [`admin.${id}.demo.local`],
    last_synchronized_at: null,
    automation_permission: "allowed",
    notes: "Never fetched",
    lifecycle: "active",
  };
}

function phase8Payload(
  action: (typeof PHASE8_FLOW)[number],
): Record<string, unknown> {
  switch (action) {
    case "onboarding_configure_testmail":
      return { action, schema: "plus_addressing_fixture" };
    case "onboarding_disable_ai":
      return { action, provider: "disabled" };
    case "create_program":
      return {
        action,
        displayName: "Local Demo Program",
        allowedAssetRefs: ["asset-local-primary"],
        excludedAssetRefs: ["asset-local-administration"],
      };
    case "import_policy":
      return { action, representation: "human_readable_text" };
    case "create_campaign":
      return {
        action,
        policyVersion: 1,
        roles: ["Owner", "Member", "External"],
        riskTiers: ["tier_0_offline"],
        maxRequests: 8,
        requestsPerMinute: 2,
        maxConcurrency: 1,
      };
    case "start_journey":
      return {
        action,
        confirmed: true,
        journeyId: "phase7-local-demo-role-boundary",
        roles: ["Owner", "Member", "External"],
      };
    default:
      return PHASE8_CONFIRMATIONS.has(action)
        ? { action, confirmed: true }
        : { action };
  }
}

function confirmations(): Record<string, true> {
  return {
    clearKillSwitch: true,
    acceptPolicyV1: true,
    approveCampaignV1: true,
    acceptPolicyV2: true,
    approveCampaignV2: true,
    queueReportReview: true,
  };
}

function confirmationTimes(): Record<string, string> {
  return {
    clearKillSwitch: "2026-07-13T11:59:54.000Z",
    acceptPolicyV1: "2026-07-13T11:59:55.000Z",
    approveCampaignV1: "2026-07-13T11:59:56.000Z",
    acceptPolicyV2: "2026-07-13T11:59:57.000Z",
    approveCampaignV2: "2026-07-13T11:59:58.000Z",
    queueReportReview: "2026-07-13T11:59:59.000Z",
  };
}

function persistedDashboardState(value: DashboardState): unknown {
  return {
    simulationStatus: value.simulationStatus,
    operatorAuthentication: value.operatorAuthentication,
    killSwitch: value.killSwitch,
    counts: value.counts,
    programs: value.programs,
    approvals: value.approvals,
    auditLog: value.expert.auditLog,
  };
}

function dashboardPolicy(server: RunningDashboardServer): {
  readonly config: ProgramConfig;
  readonly localTestMode: true;
} {
  const base = programConfig({
    host: "127.0.0.1",
    port: server.port,
    allowHttp: true,
  });
  return {
    config: {
      ...base,
      network: {
        ...base.network,
        targets: [],
        supporting_hosts: [
          {
            scheme: "http",
            host: "127.0.0.1",
            ports: [server.port],
            allowed_methods: ["GET", "POST"],
            capture: "metadata_only",
          },
        ],
        blocked_hosts: [],
      },
    },
    localTestMode: true,
  };
}

interface RawRequestOptions {
  readonly method: string;
  readonly hostHeader: string;
  readonly path: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: Buffer;
}

function rawRequest(
  server: RunningDashboardServer,
  options: RawRequestOptions,
): Promise<{ readonly body: string; readonly statusCode: number }> {
  return new Promise((resolve, reject) => {
    const call = request(
      {
        host: "127.0.0.1",
        port: server.port,
        method: options.method,
        path: options.path,
        headers: {
          host: options.hostHeader,
          ...(options.headers ?? {}),
          ...(options.body === undefined
            ? {}
            : { "content-length": options.body.byteLength }),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => {
          chunks.push(chunk);
        });
        response.on("end", () => {
          resolve({
            body: Buffer.concat(chunks).toString("utf8"),
            statusCode: response.statusCode ?? 0,
          });
        });
      },
    );
    call.on("error", reject);
    if (options.body !== undefined) call.write(options.body);
    call.end();
  });
}
