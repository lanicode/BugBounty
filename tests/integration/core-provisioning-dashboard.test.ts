import { lstat, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  LocalCoreProvisioningController,
  startDashboardServer,
  type CoreProvisioningProjection,
  type RunningDashboardServer,
} from "../../packages/dashboard/index.js";
import { DemoSaas } from "../../packages/demo-saas/index.js";
import { deriveRuntimeReadiness } from "../../packages/local-runtime/index.js";
import { MacOSCoreKeychainBackend } from "../../packages/secret-store/index.js";
import { TestCoreKeychainRunner } from "../fixtures/core-keychain.factory.js";

const NOW = "2026-07-15T11:00:00.000Z";
const servers: RunningDashboardServer[] = [];
const databases: ControlPlaneDatabase[] = [];
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
  for (const database of databases.splice(0)) database.close();
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true })),
  );
});

describe("loopback Core provisioning route", () => {
  it("requires same-origin CSRF and an exact nonce-bound body, then blocks replay", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "core-provisioning-dashboard-")),
    );
    roots.push(root);
    const database = ControlPlaneDatabase.memory();
    databases.push(database);
    const now = () => new Date(NOW);
    const store = new ControlPlaneStore(database, now);
    store.setKillSwitch(true, "dashboard-core-test", NOW);
    const runner = new TestCoreKeychainRunner("absent");
    const controller = new LocalCoreProvisioningController({
      backend: new MacOSCoreKeychainBackend("darwin", runner),
      store,
      eventStoreDirectory: join(root, "event-store"),
      operatorId: "local-operator",
      startupKeychainStatus: "absent",
      configurationAllowed: true,
    });
    const server = await startDashboardServer(
      {
        store,
        demo: new DemoSaas(now),
        coreProvisioning: controller,
        readiness: deriveRuntimeReadiness({
          platform: "darwin",
          eventKeyMinimumVersion: undefined,
          operatorKeyReference: undefined,
          operatorId: undefined,
          operatorKeyRevision: undefined,
          secretStoreProbe: "not_checked",
          demoSaasReady: true,
          databaseReady: true,
        }),
        now,
      },
      0,
    );
    servers.push(server);

    const initial = await dashboardState(server);
    expect(initial.coreProvisioning).toMatchObject({
      status: "ready",
      keychainStatus: "absent",
      proposedMode: "fresh_bundle",
      operatorId: "local-operator",
      canProvision: true,
      secretInputAccepted: false,
    });
    const challenge = requireChallenge(initial.coreProvisioning);
    const body = {
      version: 1,
      confirmation: "provision_local_security_core",
      nonce: challenge.nonce,
      contextDigestSha256: challenge.contextDigestSha256,
    };

    const crossOrigin = await post(server, initial.csrfToken, body, {
      origin: "http://127.0.0.1:1",
    });
    expect(crossOrigin.status).toBe(403);
    expect(await crossOrigin.json()).toEqual({
      error: "DASHBOARD_ORIGIN_BLOCKED",
    });
    const forgedCsrf = await post(server, "invalid", body);
    expect(forgedCsrf.status).toBe(403);
    expect(await forgedCsrf.json()).toEqual({
      error: "DASHBOARD_CSRF_BLOCKED",
    });
    expect(runner.operations).not.toContain("provision-fresh");

    const secretField = await post(server, initial.csrfToken, {
      ...body,
      operatorPrivateKey: "forbidden",
    });
    expect(secretField.status).toBe(409);
    expect(await secretField.json()).toEqual({
      error: "CORE_PROVISIONING_REQUEST_INVALID",
    });
    expect(runner.operations).not.toContain("provision-fresh");

    const provisioned = await post(server, initial.csrfToken, body);
    expect(provisioned.status).toBe(200);
    const responseText = await provisioned.text();
    const response = JSON.parse(responseText) as {
      readonly coreProvisioning: CoreProvisioningProjection;
    };
    expect(response.coreProvisioning).toMatchObject({
      status: "restart_required",
      keychainStatus: "fresh_bundle",
      canProvision: false,
      restartRequired: true,
      secretInputAccepted: false,
      challenge: null,
    });
    expect(responseText).not.toContain("operatorPrivateKey");
    expect(responseText).not.toContain("eventKey");
    expect(store.getLocalOperatorCredential()).toBeUndefined();
    expect(store.isKillSwitchActive()).toBe(true);
    await expect(lstat(join(root, "event-store"))).rejects.toMatchObject({
      code: "ENOENT",
    });

    const replay = await post(server, initial.csrfToken, body);
    expect(replay.status).toBe(409);
    expect(await replay.json()).toEqual({
      error: "CORE_PROVISIONING_NOT_ALLOWED",
    });
    expect(
      runner.operations.filter((operation) => operation === "provision-fresh"),
    ).toHaveLength(1);
    expect((await dashboardState(server)).coreProvisioning).toMatchObject({
      status: "restart_required",
      canProvision: false,
      restartRequired: true,
    });
  });
});

async function dashboardState(server: RunningDashboardServer): Promise<{
  readonly csrfToken: string;
  readonly coreProvisioning: CoreProvisioningProjection;
}> {
  const response = await fetch(`${server.origin}/api/state`);
  expect(response.status).toBe(200);
  return (await response.json()) as {
    readonly csrfToken: string;
    readonly coreProvisioning: CoreProvisioningProjection;
  };
}

function requireChallenge(projection: CoreProvisioningProjection): {
  readonly nonce: string;
  readonly contextDigestSha256: string;
} {
  if (projection.challenge === null)
    throw new Error("TEST_CORE_CHALLENGE_REQUIRED");
  return projection.challenge;
}

function post(
  server: RunningDashboardServer,
  csrfToken: string,
  body: unknown,
  headers: { readonly origin?: string } = {},
): Promise<Response> {
  return fetch(`${server.origin}/api/core/provision`, {
    method: "POST",
    headers: {
      origin: headers.origin ?? server.origin,
      "content-type": "application/json",
      "x-csrf-token": csrfToken,
    },
    body: JSON.stringify(body),
  });
}
