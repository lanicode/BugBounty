import { mkdtemp, realpath, stat } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  startLocalApplication,
  type RunningLocalApplication,
} from "../../apps/dashboard/runtime.js";
import { TestCoreKeychainRunner } from "../fixtures/core-keychain.factory.js";

const running: RunningLocalApplication[] = [];

afterEach(async () => {
  await Promise.all(running.map((application) => application.close()));
  running.length = 0;
});

describe("Phase-8 local application loopback runtime", () => {
  it("starts dashboard, control plane and Demo-SaaS without terminal parameters", async () => {
    const runtimeRoot = await mkdtemp(join(tmpdir(), "phase8-local-app-"));
    let tick = 0;
    const application = await startLocalApplication({
      runtimeRoot,
      dashboardPort: 0,
      demoPort: 0,
      environment: {},
      platform: "darwin",
      coreKeychainRunner: new TestCoreKeychainRunner("absent"),
      now: () => new Date(Date.UTC(2026, 6, 14, 12, 0, tick++)),
    });
    running.push(application);

    expect(application.dashboard.origin).toMatch(
      /^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/u,
    );
    expect(application.demo.origin).toMatch(
      /^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/u,
    );
    expect(application.dashboard.origin).not.toBe(application.demo.origin);
    expect(application).toMatchObject({
      killSwitchActive: true,
      runtimeMode: "local_setup_shell",
      readiness: {
        status: "setup_required",
        ready: false,
        externalIntegrationsEnabled: false,
        aiProviderStatus: "disabled_not_implemented",
        browserWorkerStatus: "test_harness_only",
        killSwitchAssumedActive: true,
      },
    });

    const dashboardResponse = await fetch(
      `${application.dashboard.origin}/api/state`,
    );
    expect(dashboardResponse.status).toBe(200);
    const dashboard = (await dashboardResponse.json()) as {
      readonly simulationAvailable: boolean;
      readonly simulationStatus: string;
      readonly killSwitch: { readonly active: boolean };
      readonly activeTesting: {
        readonly capability: {
          readonly available: boolean;
          readonly configured: boolean;
          readonly enabled: boolean;
          readonly reasonCodes: readonly string[];
        };
      };
      readonly localProduct: {
        readonly nextAction: string;
        readonly progress: { readonly completedSteps: number };
        readonly runtimeContext: {
          readonly systemStatus: string;
          readonly secretStoreStatus: string;
          readonly demoSaasStatus: string;
          readonly databaseStatus: string;
          readonly demoSnapshotDigest: string;
        };
      };
    };
    expect(dashboard).toMatchObject({
      simulationAvailable: false,
      simulationStatus: "setup_required",
      killSwitch: { active: true },
      activeTesting: {
        capability: {
          available: true,
          configured: false,
          enabled: false,
        },
      },
      localProduct: {
        nextAction: "onboarding_system_check",
        progress: { completedSteps: 0 },
        runtimeContext: {
          systemStatus: "ready",
          secretStoreStatus: "setup_required",
          demoSaasStatus: "ready",
          databaseStatus: "ready",
        },
      },
    });
    expect(dashboard.localProduct.runtimeContext.demoSnapshotDigest).toMatch(
      /^[a-f0-9]{64}$/u,
    );
    expect(dashboard.activeTesting.capability.reasonCodes).toEqual(
      expect.arrayContaining([
        "ACTIVE_TESTING_EXTERNAL_INTEGRATIONS_DISABLED",
        "ACTIVE_TESTING_CAPABILITY_DISABLED",
        "ACTIVE_TESTING_SECURE_CORE_REQUIRED",
        "ACTIVE_TESTING_KILL_SWITCH_ACTIVE",
        "ACTIVE_TESTING_API_PROGRAM_SELECTION_REQUIRED",
      ]),
    );

    const demoResponse = await fetch(`${application.demo.origin}/health`);
    expect(demoResponse.status).toBe(200);
    expect(await demoResponse.json()).toEqual({
      status: "ok",
      mode: "simulation",
      externalIntegrationsEnabled: false,
    });

    const databaseMode = (await stat(join(runtimeRoot, "control-plane.sqlite")))
      .mode;
    expect(databaseMode & 0o077).toBe(0);
    await application.close();
    await expect(application.close()).resolves.toBeUndefined();
  });

  it("reports partial cryptographic configuration as blocked without probing a fallback", async () => {
    const runtimeRoot = await mkdtemp(join(tmpdir(), "phase8-blocked-app-"));
    const application = await startLocalApplication({
      runtimeRoot,
      dashboardPort: 0,
      demoPort: 0,
      environment: {
        eventKeyMinimumVersion: "1",
        operatorId: "partial-local-operator",
      },
      platform: "darwin",
      coreKeychainRunner: new TestCoreKeychainRunner("absent"),
      now: () => new Date("2026-07-14T12:00:00.000Z"),
    });
    running.push(application);

    expect(application.readiness).toMatchObject({
      status: "blocked",
      ready: false,
      eventKeyMinimumVersionStatus: "ready",
      operatorStatus: "blocked",
      secretStoreStatus: "setup_required",
      externalIntegrationsEnabled: false,
      killSwitchAssumedActive: true,
    });
    expect(application.readiness.reasonCodes).toContain(
      "RUNTIME_OPERATOR_CONFIGURATION_INVALID",
    );
    expect(application.readiness.reasonCodes).toContain(
      "RUNTIME_SECRET_STORE_SETUP_REQUIRED",
    );
    const state = (await (
      await fetch(`${application.dashboard.origin}/api/state`)
    ).json()) as {
      readonly simulationAvailable: boolean;
      readonly killSwitch: { readonly active: boolean };
      readonly runtimeReadiness: { readonly status: string };
    };
    expect(state).toMatchObject({
      simulationAvailable: false,
      killSwitch: { active: true },
      runtimeReadiness: { status: "blocked" },
    });
  });

  it("resolves a complete Core bundle to fixed logical references and signer metadata", async () => {
    const runtimeRoot = await realpath(
      await mkdtemp(join(tmpdir(), "phase8-core-runtime-")),
    );
    const coreKeychainRunner = new TestCoreKeychainRunner(
      "fresh_bundle",
      "bundle-operator",
    );
    const application = await startLocalApplication({
      runtimeRoot,
      dashboardPort: 0,
      demoPort: 0,
      environment: { eventKeyMinimumVersion: "1" },
      platform: "darwin",
      coreKeychainRunner,
      now: () => new Date("2026-07-14T12:00:00.000Z"),
    });
    running.push(application);

    expect(application).toMatchObject({
      runtimeMode: "local_simulation",
      readiness: {
        status: "ready",
        ready: true,
        eventKeyMinimumVersionStatus: "ready",
        operatorStatus: "ready",
        secretStoreStatus: "ready",
      },
    });
    expect(coreKeychainRunner.operations).toContain("read-operator");
    expect(coreKeychainRunner.operations).toContain("read-event");

    const dashboard = (await (
      await fetch(`${application.dashboard.origin}/api/state`)
    ).json()) as {
      readonly operatorAuthentication: {
        readonly signerConfigured: boolean;
        readonly operatorId: string | null;
      };
      readonly coreProvisioning: {
        readonly status: string;
        readonly keychainStatus: string;
        readonly canProvision: boolean;
      };
    };
    expect(dashboard).toMatchObject({
      operatorAuthentication: {
        signerConfigured: true,
        operatorId: "bundle-operator",
      },
      coreProvisioning: {
        status: "configured",
        keychainStatus: "fresh_bundle",
        canProvision: false,
      },
    });
  });

  it.each(["legacy_ready", "conflict"] as const)(
    "keeps the %s Core state fail-closed even with structurally complete runtime metadata",
    async (coreStatus) => {
      const runtimeRoot = await realpath(
        await mkdtemp(join(tmpdir(), `phase8-core-${coreStatus}-`)),
      );
      const coreKeychainRunner = new TestCoreKeychainRunner(coreStatus);
      const application = await startLocalApplication({
        runtimeRoot,
        dashboardPort: 0,
        demoPort: 0,
        environment: {
          eventKeyMinimumVersion: "1",
          operatorKeyReference:
            "keychain://bugbounty-copilot/operator-ed25519-v1",
          operatorId: "local-operator",
          operatorKeyRevision: "1",
        },
        platform: "darwin",
        coreKeychainRunner,
        now: () => new Date("2026-07-14T12:00:00.000Z"),
      });
      running.push(application);

      expect(application).toMatchObject({
        runtimeMode: "local_setup_shell",
        readiness: {
          status: "blocked",
          ready: false,
          secretStoreStatus: "blocked",
        },
      });
      expect(application.readiness.reasonCodes).toContain(
        "RUNTIME_SECRET_STORE_ERROR",
      );
      expect(coreKeychainRunner.operations).not.toContain("read-event");
      expect(coreKeychainRunner.operations).not.toContain("read-operator");
    },
  );

  it("falls back to an ephemeral loopback dashboard port when the preferred port is occupied", async () => {
    const blocker = createServer((_request, response) => response.end());
    await listen(blocker, 0);
    const blockedPort = portOf(blocker);
    const runtimeRoot = await mkdtemp(join(tmpdir(), "phase8-port-fallback-"));
    try {
      const application = await startLocalApplication({
        runtimeRoot,
        dashboardPort: blockedPort,
        demoPort: 0,
        environment: {},
        platform: "darwin",
        coreKeychainRunner: new TestCoreKeychainRunner("absent"),
        now: () => new Date("2026-07-14T12:00:00.000Z"),
      });
      running.push(application);

      expect(application.dashboardPortFallback).toBe(true);
      expect(application.dashboard.port).not.toBe(blockedPort);
      expect(application.dashboard.host).toBe("127.0.0.1");
      expect(
        (await fetch(`${application.dashboard.origin}/health`)).status,
      ).toBe(200);
    } finally {
      await close(blocker);
    }
  });

  it("closes the already-started Demo-SaaS when dashboard startup fails", async () => {
    const reservation = createServer((_request, response) => response.end());
    await listen(reservation, 0);
    const demoPort = portOf(reservation);
    await close(reservation);
    const runtimeRoot = await mkdtemp(join(tmpdir(), "phase8-cleanup-"));

    await expect(
      startLocalApplication({
        runtimeRoot,
        dashboardPort: 65_536,
        demoPort,
        environment: {},
        platform: "darwin",
        coreKeychainRunner: new TestCoreKeychainRunner("absent"),
        now: () => new Date("2026-07-14T12:00:00.000Z"),
      }),
    ).rejects.toThrow("DASHBOARD_PORT_INVALID");

    const probe = createServer((_request, response) => response.end());
    try {
      await expect(listen(probe, demoPort)).resolves.toBeUndefined();
    } finally {
      await close(probe);
    }
  });
});

async function listen(server: Server, port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, "127.0.0.1");
  });
}

function portOf(server: Server): number {
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("TEST_SERVER_ADDRESS_INVALID");
  return address.port;
}

async function close(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
  });
}
