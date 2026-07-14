import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  startDashboardServer,
  type RunningDashboardServer,
} from "../../packages/dashboard/index.js";
import {
  DemoSaas,
  startDemoSaasServer,
  type RunningDemoSaasServer,
} from "../../packages/demo-saas/index.js";
import { parseEventKeyMinimumVersion } from "../../packages/event-key-lifecycle/index.js";
import {
  deriveRuntimeReadiness,
  type RuntimeReadiness,
  type SecretStoreProbe,
} from "../../packages/local-runtime/index.js";
import {
  createKeychainOperatorSigner,
  type OperatorSigner,
} from "../../packages/operator-auth/index.js";
import { MacOSKeychainSecretStore } from "../../packages/secret-store/index.js";
import { SimulationOrchestrator } from "../../packages/simulation/index.js";
import { HackerOneMetadataActionGate } from "../../packages/external-actions/index.js";
import {
  HackerOneCredentialVault,
  HackerOneHttpsTransport,
  HackerOneMetadataService,
  HackerOneMetadataStore,
  HackerOneReadOnlyClient,
  MacOSHackerOneKeychainMutationBackend,
  resolveHackerOneMetadataReadRuntime,
} from "../../packages/hackerone-readonly/index.js";

const DASHBOARD_PORT = 4173;
const EVENT_KEY_BYTES = 32;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/u;

export interface LocalApplicationEnvironment {
  readonly eventKeyMinimumVersion?: string;
  readonly externalIntegrationsEnabled?: string;
  readonly hackerOneReadonlyEnabled?: string;
  readonly operatorKeyReference?: string;
  readonly operatorId?: string;
  readonly operatorKeyRevision?: string;
}

export interface LocalApplicationOptions {
  readonly runtimeRoot?: string;
  readonly dashboardPort?: number;
  readonly demoPort?: number;
  readonly environment?: LocalApplicationEnvironment;
  readonly platform?: NodeJS.Platform;
  readonly now?: () => Date;
}

export interface RunningLocalApplication {
  readonly dashboard: RunningDashboardServer;
  readonly demo: RunningDemoSaasServer;
  readonly readiness: RuntimeReadiness;
  readonly runtimeMode: "local_setup_shell" | "local_simulation";
  readonly killSwitchActive: true;
  readonly dashboardPortFallback: boolean;
  close(): Promise<void>;
}

/**
 * Starts the local product shell. Missing cryptographic prerequisites do not
 * make the read-only dashboard unavailable; they keep every signed/encrypted
 * action disabled while the startup kill switch remains engaged.
 */
export async function startLocalApplication(
  options: LocalApplicationOptions = {},
): Promise<RunningLocalApplication> {
  const runtimeRoot = resolve(
    options.runtimeRoot ?? resolve(".local", "dashboard"),
  );
  const now = options.now ?? (() => new Date());
  const environment = options.environment ?? environmentFromProcess();
  const platform = options.platform ?? process.platform;
  await mkdir(runtimeRoot, { recursive: true, mode: 0o700 });

  let database: ControlPlaneDatabase | undefined;
  let demoServer: RunningDemoSaasServer | undefined;
  let dashboardServer: RunningDashboardServer | undefined;
  let dashboardPortFallback = false;
  let closePromise: Promise<void> | undefined;

  const close = (): Promise<void> => {
    closePromise ??= closeResources(dashboardServer, demoServer, database);
    return closePromise;
  };

  try {
    database = await ControlPlaneDatabase.file(
      resolve(runtimeRoot, "control-plane.sqlite"),
    );
    const store = new ControlPlaneStore(database, now);
    store.setKillSwitch(
      true,
      `system-startup-${String(process.pid)}`,
      timestamp(now),
    );

    const demo = new DemoSaas(now);
    demoServer = await startDemoSaasServer(demo, options.demoPort ?? 0);
    const prepared = await prepareSecureSimulation(
      store,
      demo,
      runtimeRoot,
      environment,
      platform,
      now,
    );
    const hackerOne = prepareHackerOneMetadata(
      database,
      store,
      environment,
      platform,
      now,
    );
    const readiness = deriveRuntimeReadiness({
      platform,
      eventKeyMinimumVersion: environment.eventKeyMinimumVersion,
      operatorKeyReference: environment.operatorKeyReference,
      operatorId: environment.operatorId,
      operatorKeyRevision: environment.operatorKeyRevision,
      secretStoreProbe: prepared.secretStoreProbe,
      demoSaasReady: true,
      databaseReady: true,
    });

    const dashboardDependencies = {
      store,
      demo,
      readiness,
      hackerOne,
      ...(prepared.simulation === undefined
        ? {}
        : { simulation: prepared.simulation }),
      ...(prepared.operatorSigner === undefined
        ? {}
        : { operatorSigner: prepared.operatorSigner }),
      now,
    };
    try {
      dashboardServer = await startDashboardServer(
        dashboardDependencies,
        options.dashboardPort ?? DASHBOARD_PORT,
      );
    } catch (error) {
      if (!isAddressInUse(error)) throw error;
      dashboardServer = await startDashboardServer(dashboardDependencies, 0);
      dashboardPortFallback = true;
    }

    return Object.freeze({
      dashboard: dashboardServer,
      demo: demoServer,
      readiness,
      runtimeMode: readiness.ready
        ? ("local_simulation" as const)
        : ("local_setup_shell" as const),
      killSwitchActive: true as const,
      dashboardPortFallback,
      close,
    });
  } catch (error) {
    await close().catch(() => undefined);
    throw error;
  }
}

function isAddressInUse(error: unknown): boolean {
  if (error === null || typeof error !== "object") return false;
  try {
    return Reflect.get(error, "code") === "EADDRINUSE";
  } catch {
    return false;
  }
}

interface PreparedSecureSimulation {
  readonly operatorSigner?: OperatorSigner;
  readonly simulation?: SimulationOrchestrator;
  readonly secretStoreProbe: SecretStoreProbe;
}

async function prepareSecureSimulation(
  store: ControlPlaneStore,
  demo: DemoSaas,
  runtimeRoot: string,
  environment: LocalApplicationEnvironment,
  platform: NodeJS.Platform,
  now: () => Date,
): Promise<PreparedSecureSimulation> {
  const minimumVersion = configuredEventMinimum(
    environment.eventKeyMinimumVersion,
  );
  const operatorConfiguration = configuredOperator(environment);
  if (platform !== "darwin")
    return Object.freeze({ secretStoreProbe: "unavailable" as const });
  if (minimumVersion === undefined || operatorConfiguration === undefined)
    return Object.freeze({ secretStoreProbe: "not_checked" as const });

  const secretStore = new MacOSKeychainSecretStore(undefined, platform);
  let operatorSigner: OperatorSigner;
  try {
    operatorSigner = await createKeychainOperatorSigner(
      secretStore,
      operatorConfiguration,
    );
    await probeEventKey(secretStore, minimumVersion);
  } catch {
    return Object.freeze({ secretStoreProbe: "error" as const });
  }

  return Object.freeze({
    secretStoreProbe: "available" as const,
    operatorSigner,
    simulation: new SimulationOrchestrator(
      store,
      demo,
      resolve(runtimeRoot, "event-store"),
      secretStore,
      (version) =>
        `keychain://bugbounty-copilot/event-store-v${String(version)}`,
      now,
      minimumVersion,
      operatorSigner,
    ),
  });
}

function configuredEventMinimum(value: string | undefined): number | undefined {
  try {
    return parseEventKeyMinimumVersion(value);
  } catch {
    return undefined;
  }
}

function configuredOperator(environment: LocalApplicationEnvironment):
  | {
      readonly keyReference: string;
      readonly operatorId: string;
      readonly keyRevision: number;
    }
  | undefined {
  const keyReference = environment.operatorKeyReference;
  const operatorId = environment.operatorId;
  const revisionText = environment.operatorKeyRevision;
  if (
    keyReference === undefined ||
    operatorId === undefined ||
    revisionText === undefined ||
    !POSITIVE_DECIMAL.test(revisionText)
  )
    return undefined;
  const keyRevision = Number(revisionText);
  if (!Number.isSafeInteger(keyRevision)) return undefined;
  return Object.freeze({ keyReference, operatorId, keyRevision });
}

async function probeEventKey(
  secretStore: MacOSKeychainSecretStore,
  version: number,
): Promise<void> {
  const secret = await secretStore.get(
    `keychain://bugbounty-copilot/event-store-v${String(version)}`,
  );
  const invalid = secret.byteLength !== EVENT_KEY_BYTES;
  secret.fill(0);
  if (invalid) throw new Error("EVENT_KEY_UNAVAILABLE");
}

function environmentFromProcess(): LocalApplicationEnvironment {
  return Object.freeze({
    ...(process.env["BUGBOUNTY_EVENT_KEY_MIN_VERSION"] === undefined
      ? {}
      : {
          eventKeyMinimumVersion:
            process.env["BUGBOUNTY_EVENT_KEY_MIN_VERSION"],
        }),
    ...(process.env["BUGBOUNTY_OPERATOR_KEY_REFERENCE"] === undefined
      ? {}
      : {
          operatorKeyReference: process.env["BUGBOUNTY_OPERATOR_KEY_REFERENCE"],
        }),
    ...(process.env["BUGBOUNTY_OPERATOR_ID"] === undefined
      ? {}
      : { operatorId: process.env["BUGBOUNTY_OPERATOR_ID"] }),
    ...(process.env["BUGBOUNTY_OPERATOR_KEY_REVISION"] === undefined
      ? {}
      : {
          operatorKeyRevision: process.env["BUGBOUNTY_OPERATOR_KEY_REVISION"],
        }),
    ...(process.env["BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED"] === undefined
      ? {}
      : {
          externalIntegrationsEnabled:
            process.env["BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED"],
        }),
    ...(process.env["BUGBOUNTY_HACKERONE_READONLY_ENABLED"] === undefined
      ? {}
      : {
          hackerOneReadonlyEnabled:
            process.env["BUGBOUNTY_HACKERONE_READONLY_ENABLED"],
        }),
  });
}

function prepareHackerOneMetadata(
  database: ControlPlaneDatabase,
  controlPlane: ControlPlaneStore,
  environment: LocalApplicationEnvironment,
  platform: NodeJS.Platform,
  now: () => Date,
): HackerOneMetadataService {
  const runtime = resolveHackerOneMetadataReadRuntime({
    version: 1,
    capability: "HACKERONE_METADATA_READ",
    external_integrations_enabled:
      environment.externalIntegrationsEnabled === "true",
    enabled: environment.hackerOneReadonlyEnabled === "true",
    request_budget: {
      max_requests_total: 100,
      requests_per_minute: 60,
      max_concurrency: 1,
    },
  });
  const metadata = new HackerOneMetadataStore(database);
  const actionGate = new HackerOneMetadataActionGate(
    database,
    controlPlane,
    runtime,
  );
  const credentials = new HackerOneCredentialVault(
    new MacOSKeychainSecretStore(undefined, platform),
    new MacOSHackerOneKeychainMutationBackend(platform),
  );
  const killSwitch = Object.freeze({
    isActive: (): boolean => controlPlane.isKillSwitchActive(),
  });
  const client = new HackerOneReadOnlyClient({
    runtime,
    credentials,
    transport: new HackerOneHttpsTransport(),
    actionGate,
    audit: (event) => {
      metadata.recordRequestAudit(event);
    },
    now,
  });
  return new HackerOneMetadataService({
    runtime,
    store: metadata,
    credentials,
    client,
    actionGate,
    killSwitch,
    now,
  });
}

function timestamp(now: () => Date): string {
  const value = now();
  if (!Number.isFinite(value.getTime()))
    throw new Error("LOCAL_APPLICATION_CLOCK_INVALID");
  return value.toISOString();
}

async function closeResources(
  dashboard: RunningDashboardServer | undefined,
  demo: RunningDemoSaasServer | undefined,
  database: ControlPlaneDatabase | undefined,
): Promise<void> {
  const errors: unknown[] = [];
  for (const resource of [dashboard, demo]) {
    if (resource === undefined) continue;
    try {
      await resource.close();
    } catch (error) {
      errors.push(error);
    }
  }
  try {
    database?.close();
  } catch (error) {
    errors.push(error);
  }
  if (errors.length > 0)
    throw new AggregateError(errors, "LOCAL_APPLICATION_CLOSE_FAILED");
}
