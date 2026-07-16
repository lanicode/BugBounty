import { lstat, mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ControlPlaneDatabase } from "../../packages/control-plane/index.js";
import {
  LocalCoreProvisioningController,
  type CoreProvisioningProjection,
} from "../../packages/dashboard/index.js";
import { MacOSCoreKeychainBackend } from "../../packages/secret-store/index.js";
import { TestCoreKeychainRunner } from "../fixtures/core-keychain.factory.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
} from "../fixtures/operator-auth.factory.js";

const NOW = "2026-07-15T10:00:00.000Z";
const roots: string[] = [];
const databases: ControlPlaneDatabase[] = [];

afterEach(async () => {
  for (const database of databases) database.close();
  databases.length = 0;
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true })),
  );
});

describe("local Core provisioning controller", () => {
  it("projects a stable state-bound fresh challenge without secret fields", async () => {
    const harness = await setup("absent");
    const first = await harness.controller.project();
    const second = await harness.controller.project();

    expect(first).toMatchObject({
      version: 1,
      status: "ready",
      keychainStatus: "absent",
      proposedMode: "fresh_bundle",
      operatorId: "local-operator",
      canProvision: true,
      restartRequired: false,
      secretInputAccepted: false,
      reasonCode: "CORE_PROVISIONING_READY",
    });
    expect(first.challenge).toEqual(second.challenge);
    expect(first.challenge?.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(first.challenge?.contextDigestSha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(Object.keys(first).sort()).toEqual([
      "canProvision",
      "challenge",
      "initialEventKeyVersion",
      "keychainStatus",
      "operatorId",
      "operatorKeyRevision",
      "proposedMode",
      "reasonCode",
      "restartRequired",
      "secretInputAccepted",
      "status",
      "version",
    ]);
    expect(JSON.stringify(first)).not.toContain("51515151");
  });

  it("chooses fresh mode server-side, consumes the nonce, and requires restart", async () => {
    const harness = await setup("absent");
    const ready = await harness.controller.project();
    const request = provisioningRequest(ready);
    const completed = await harness.controller.provision(request);

    expect(completed).toMatchObject({
      status: "restart_required",
      keychainStatus: "fresh_bundle",
      proposedMode: null,
      operatorId: "local-operator",
      initialEventKeyVersion: 1,
      operatorKeyRevision: 1,
      canProvision: false,
      restartRequired: true,
      challenge: null,
    });
    expect(harness.runner.status).toBe("fresh_bundle");
    expect(harness.runner.operations).toContain("provision-fresh");
    expect(harness.runner.operations).not.toContain("complete-legacy");
    await expect(lstat(harness.eventStoreDirectory)).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(harness.store.getLocalOperatorCredential()).toBeUndefined();
    expect(harness.store.isKillSwitchActive()).toBe(true);

    await expect(harness.controller.provision(request)).rejects.toThrow(
      "CORE_PROVISIONING_NOT_ALLOWED",
    );
    expect(
      harness.runner.operations.filter(
        (operation) => operation === "provision-fresh",
      ),
    ).toHaveLength(1);
  });

  it("selects only the conservative legacy completion for legacy_ready", async () => {
    const harness = await setup("legacy_ready");
    const ready = await harness.controller.project();
    expect(ready.proposedMode).toBe("legacy_complete");

    const completed = await harness.controller.provision(
      provisioningRequest(ready),
    );
    expect(completed).toMatchObject({
      status: "restart_required",
      keychainStatus: "legacy_complete",
      restartRequired: true,
    });
    expect(harness.runner.operations).toContain("complete-legacy");
    expect(harness.runner.operations).not.toContain("provision-fresh");
    expect(harness.runner.operations).not.toContain("read-event");
  });

  it("rejects digest tampering and every extra request field before mutation", async () => {
    const harness = await setup("absent");
    const ready = await harness.controller.project();
    const request = provisioningRequest(ready);

    await expect(
      harness.controller.provision({
        ...request,
        contextDigestSha256: `${request.contextDigestSha256.startsWith("0") ? "1" : "0"}${request.contextDigestSha256.slice(1)}`,
      }),
    ).rejects.toThrow("CORE_PROVISIONING_CHALLENGE_INVALID");
    await expect(
      harness.controller.provision({ ...request, eventKey: "forbidden" }),
    ).rejects.toThrow("CORE_PROVISIONING_REQUEST_INVALID");
    expect(harness.runner.operations).not.toContain("provision-fresh");
  });

  it("revalidates the event directory, kill switch, and operator credential", async () => {
    const eventHarness = await setup("absent");
    const eventReady = await eventHarness.controller.project();
    await mkdir(eventHarness.eventStoreDirectory, { mode: 0o700 });
    await expect(
      eventHarness.controller.provision(provisioningRequest(eventReady)),
    ).rejects.toThrow("CORE_PROVISIONING_NOT_ALLOWED");
    expect(eventHarness.runner.operations).not.toContain("provision-fresh");

    const controlHarness = await setup("absent");
    const controlReady = await controlHarness.controller.project();
    clearTestKillSwitch(controlHarness.store, NOW);
    await expect(
      controlHarness.controller.provision(provisioningRequest(controlReady)),
    ).rejects.toThrow("CORE_PROVISIONING_NOT_ALLOWED");
    expect(controlHarness.runner.operations).not.toContain("provision-fresh");
  });

  it("projects complete startup material as configured and conflicts as blocked", async () => {
    const configured = await setup("fresh_bundle");
    expect(await configured.controller.project()).toMatchObject({
      status: "configured",
      keychainStatus: "fresh_bundle",
      canProvision: false,
      restartRequired: false,
      challenge: null,
    });

    const conflict = await setup("conflict");
    expect(await conflict.controller.project()).toMatchObject({
      status: "blocked",
      keychainStatus: "conflict",
      canProvision: false,
      reasonCode: "CORE_PROVISIONING_CONFLICT",
    });

    const legacyDirect = await setup("legacy_direct_complete", false);
    expect(await legacyDirect.controller.project()).toMatchObject({
      status: "blocked",
      keychainStatus: "legacy_direct_complete",
      canProvision: false,
      reasonCode: "CORE_PROVISIONING_STARTUP_CONFIGURATION_CONFLICT",
    });
    expect(legacyDirect.runner.operations).not.toContain("provision-fresh");
    expect(legacyDirect.runner.operations).not.toContain("complete-legacy");

    const incompatible = await setup("absent", false);
    expect(await incompatible.controller.project()).toMatchObject({
      status: "blocked",
      canProvision: false,
      reasonCode: "CORE_PROVISIONING_STARTUP_CONFIGURATION_CONFLICT",
    });
  });
});

async function setup(
  status: ConstructorParameters<typeof TestCoreKeychainRunner>[0],
  configurationAllowed = true,
): Promise<{
  readonly controller: LocalCoreProvisioningController;
  readonly eventStoreDirectory: string;
  readonly runner: TestCoreKeychainRunner;
  readonly store: ReturnType<typeof createTestControlPlaneStore>;
}> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "core-provisioning-controller-")),
  );
  roots.push(root);
  const database = ControlPlaneDatabase.memory();
  databases.push(database);
  const store = createTestControlPlaneStore(database, NOW);
  store.setKillSwitch(true, "core-provisioning-test", NOW);
  const runner = new TestCoreKeychainRunner(status);
  const backend = new MacOSCoreKeychainBackend("darwin", runner);
  const eventStoreDirectory = join(root, "event-store");
  const controller = new LocalCoreProvisioningController({
    backend,
    store,
    eventStoreDirectory,
    operatorId: "local-operator",
    ...(status === undefined ? {} : { startupKeychainStatus: status }),
    configurationAllowed,
  });
  return { controller, eventStoreDirectory, runner, store };
}

function provisioningRequest(projection: CoreProvisioningProjection): {
  readonly version: 1;
  readonly confirmation: "provision_local_security_core";
  readonly nonce: string;
  readonly contextDigestSha256: string;
} {
  const challenge = projection.challenge;
  if (challenge === null) throw new Error("TEST_CORE_CHALLENGE_REQUIRED");
  return Object.freeze({
    version: 1,
    confirmation: "provision_local_security_core",
    nonce: challenge.nonce,
    contextDigestSha256: challenge.contextDigestSha256,
  });
}
