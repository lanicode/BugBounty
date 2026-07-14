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
import { SimulationOrchestrator } from "../../packages/simulation/index.js";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";
import type { ProgramConfig } from "../../packages/config/types.js";
import { programConfig } from "../fixtures/factories.js";
import {
  TEST_OPERATOR_ID,
  TEST_OPERATOR_SIGNER,
} from "../fixtures/operator-auth.factory.js";

const NOW = Date.parse("2026-07-13T12:00:00.000Z");

interface DashboardState {
  readonly csrfToken: string;
  readonly mode: "simulation";
  readonly externalIntegrationsEnabled: false;
  readonly phase1SecurityStatus: string;
  readonly simulationStatus: string;
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
}

interface SimulationResponse {
  readonly steps: readonly string[];
  readonly networkConnections: number;
  readonly externalSubmissions: number;
}

interface Harness {
  readonly database: ControlPlaneDatabase;
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
  options: { readonly withOperatorSigner?: boolean } = {},
): Promise<Harness> {
  const database = ControlPlaneDatabase.memory();
  let ticks = 0;
  const now = (): Date => new Date(NOW + ticks++ * 1_000);
  const store = new ControlPlaneStore(database, now);
  const demo = new DemoSaas(now);
  const operatorSigner =
    options.withOperatorSigner === false ? undefined : TEST_OPERATOR_SIGNER;
  const eventRoot = await mkdtemp(join(tmpdir(), "dashboard-events-"));
  const eventSecrets = new InMemorySecretStore();
  eventSecrets.set("secret://dashboard/event-key", new Uint8Array(32).fill(9));
  const simulation = new SimulationOrchestrator(
    store,
    demo,
    eventRoot,
    eventSecrets,
    () => "secret://dashboard/event-key",
    now,
    1,
    operatorSigner,
  );
  try {
    const dependencies =
      operatorSigner === undefined
        ? { store, demo, simulation, now }
        : { store, demo, simulation, operatorSigner, now };
    const server = await startDashboardServer(dependencies, 0);
    const harness = { database, store, server };
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
    expect(html).toContain('src="/app.js"');
    expect(html).toContain('href="/styles.css"');
    expect(home.headers.get("access-control-allow-origin")).toBeNull();
    const csp = home.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("unsafe-inline");

    const script = await (await fetch(`${server.origin}/app.js`)).text();
    expect(script).not.toContain("innerHTML");
    expect(script).not.toContain("https://");
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

  it("fails closed for positive operations when no operator signer is configured", async () => {
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
      simulationStatus: "ready",
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
      error: "OPERATOR_SIGNER_REQUIRED",
    });
    expect(persistedDashboardState(await state(server))).toEqual(baseline);

    const clear = await postJson(
      server,
      "/api/kill-switch/clear",
      initial.csrfToken,
      { actor: TEST_OPERATOR_ID, confirmed: true },
    );
    expect(clear.status).toBe(409);
    expect(await clear.json()).toEqual({ error: "OPERATOR_SIGNER_REQUIRED" });
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
      error: "OPERATOR_SIGNER_REQUIRED",
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
      await page.locator("#clear-kill").click();
      await page
        .locator("#kill-status")
        .filter({ hasText: "FREIGEGEBEN" })
        .waitFor();
      expect(await page.locator("#kill-status").textContent()).toBe(
        "FREIGEGEBEN",
      );
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
