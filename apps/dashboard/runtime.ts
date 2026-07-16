import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import {
  ActiveTestingActionGate,
  ActiveTestingService,
  ProductionActiveTestTransport,
  resolveActiveTestingRuntime,
} from "../../packages/active-testing/index.js";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  LocalActiveTestingController,
  LocalCoreProvisioningController,
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
import {
  CORE_OPERATOR_KEY_REFERENCE,
  MacOSCoreKeychainBackend,
  MacOSKeychainSecretStore,
  resolveMacOSCoreRuntimeSecretStore,
  type CoreKeychainHelperRunner,
  type CoreKeychainInspection,
  type SecretStore,
} from "../../packages/secret-store/index.js";
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
const SAFE_OPERATOR_ID = /^[A-Za-z0-9._@-]{1,128}$/u;
const DEFAULT_CORE_OPERATOR_ID = "local-operator";

export interface LocalApplicationEnvironment {
  readonly eventKeyMinimumVersion?: string;
  readonly externalIntegrationsEnabled?: string;
  readonly hackerOneReadonlyEnabled?: string;
  readonly activeTestingEnabled?: string;
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
  /** Test seam only; production starts always use the native helper runner. */
  readonly coreKeychainRunner?: CoreKeychainHelperRunner;
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

    const coreKeychain =
      options.coreKeychainRunner === undefined
        ? new MacOSCoreKeychainBackend(platform)
        : new MacOSCoreKeychainBackend(platform, options.coreKeychainRunner);
    const coreStartup = await inspectCoreKeychain(coreKeychain, platform);
    const coreResolution = resolveCoreStartup(environment, coreStartup);

    const demo = new DemoSaas(now);
    demoServer = await startDemoSaasServer(demo, options.demoPort ?? 0);
    const prepared = await prepareSecureSimulation(
      store,
      demo,
      runtimeRoot,
      coreResolution,
      coreKeychain,
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
    const activeTesting = prepareActiveTesting(
      database,
      store,
      hackerOne.metadata,
      environment,
    );
    const readiness = deriveRuntimeReadiness({
      platform,
      eventKeyMinimumVersion: coreResolution.environment.eventKeyMinimumVersion,
      operatorKeyReference: coreResolution.environment.operatorKeyReference,
      operatorId: coreResolution.environment.operatorId,
      operatorKeyRevision: coreResolution.environment.operatorKeyRevision,
      secretStoreProbe: prepared.secretStoreProbe,
      demoSaasReady: true,
      databaseReady: true,
    });
    const coreProvisioning =
      platform === "darwin"
        ? new LocalCoreProvisioningController({
            backend: coreKeychain,
            store,
            eventStoreDirectory: resolve(runtimeRoot, "event-store"),
            operatorId: coreResolution.provisioningOperatorId,
            ...(coreStartup.inspection === undefined
              ? {}
              : { startupKeychainStatus: coreStartup.inspection.status }),
            configurationAllowed:
              coreResolution.provisioningConfigurationAllowed,
          })
        : undefined;

    const dashboardDependencies = {
      store,
      demo,
      readiness,
      hackerOne: hackerOne.service,
      activeTesting,
      ...(coreProvisioning === undefined ? {} : { coreProvisioning }),
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

export interface CoreStartupObservation {
  readonly state: "available" | "error" | "unavailable";
  readonly inspection?: CoreKeychainInspection;
}

interface CoreStartupResolution {
  readonly environment: LocalApplicationEnvironment;
  readonly keychainMode: "bundled" | "generic" | "legacy_direct";
  readonly runtimeBlocked: boolean;
  readonly provisioningOperatorId: string;
  readonly provisioningConfigurationAllowed: boolean;
}

async function prepareSecureSimulation(
  store: ControlPlaneStore,
  demo: DemoSaas,
  runtimeRoot: string,
  core: CoreStartupResolution,
  coreKeychain: MacOSCoreKeychainBackend,
  platform: NodeJS.Platform,
  now: () => Date,
): Promise<PreparedSecureSimulation> {
  const environment = core.environment;
  const minimumVersion = configuredEventMinimum(
    environment.eventKeyMinimumVersion,
  );
  const operatorConfiguration = configuredOperator(environment);
  if (platform !== "darwin")
    return Object.freeze({ secretStoreProbe: "unavailable" as const });
  if (core.runtimeBlocked)
    return Object.freeze({ secretStoreProbe: "error" as const });
  if (minimumVersion === undefined || operatorConfiguration === undefined)
    return Object.freeze({ secretStoreProbe: "not_checked" as const });

  const genericKeychain = new MacOSKeychainSecretStore(undefined, platform);
  let operatorSigner: OperatorSigner;
  try {
    const resolvedSecrets =
      core.keychainMode === "generic"
        ? genericKeychain
        : await resolveMacOSCoreRuntimeSecretStore(
            coreKeychain,
            genericKeychain,
          ).then((resolution) => {
            if (resolution.mode !== core.keychainMode)
              throw new Error("CORE_KEYCHAIN_STATE_CHANGED");
            return resolution.secrets;
          });
    operatorSigner = await createKeychainOperatorSigner(
      resolvedSecrets,
      operatorConfiguration,
    );
    await probeEventKey(resolvedSecrets, minimumVersion);

    return Object.freeze({
      secretStoreProbe: "available" as const,
      operatorSigner,
      simulation: new SimulationOrchestrator(
        store,
        demo,
        resolve(runtimeRoot, "event-store"),
        resolvedSecrets,
        (version) =>
          `keychain://bugbounty-copilot/event-store-v${String(version)}`,
        now,
        minimumVersion,
        operatorSigner,
      ),
    });
  } catch {
    return Object.freeze({ secretStoreProbe: "error" as const });
  }
}

async function inspectCoreKeychain(
  backend: MacOSCoreKeychainBackend,
  platform: NodeJS.Platform,
): Promise<CoreStartupObservation> {
  if (platform !== "darwin")
    return Object.freeze({ state: "unavailable" as const });
  try {
    return Object.freeze({
      state: "available" as const,
      inspection: await backend.inspect(),
    });
  } catch {
    return Object.freeze({ state: "error" as const });
  }
}

export function resolveCoreStartup(
  environment: LocalApplicationEnvironment,
  observation: CoreStartupObservation,
): CoreStartupResolution {
  const provisioning = provisioningConfiguration(environment);
  const inspection = observation.inspection;
  if (observation.state !== "available" || inspection === undefined)
    return Object.freeze({
      environment,
      keychainMode: "generic",
      runtimeBlocked: observation.state === "error",
      provisioningOperatorId: provisioning.operatorId,
      provisioningConfigurationAllowed: false,
    });

  if (
    inspection.status === "fresh_bundle" ||
    inspection.status === "legacy_complete"
  ) {
    const receipt = inspection.receipt;
    if (receipt === null)
      return Object.freeze({
        environment,
        keychainMode: "generic",
        runtimeBlocked: true,
        provisioningOperatorId: provisioning.operatorId,
        provisioningConfigurationAllowed: false,
      });
    const operatorFields = configuredOperatorFieldState(environment);
    const matchesReceipt =
      operatorFields.kind === "missing" ||
      (operatorFields.kind === "complete" &&
        operatorFields.keyReference === CORE_OPERATOR_KEY_REFERENCE &&
        operatorFields.operatorId === receipt.operatorId &&
        operatorFields.keyRevision === 1);
    if (!matchesReceipt)
      return Object.freeze({
        environment,
        keychainMode: "generic",
        runtimeBlocked: true,
        provisioningOperatorId: provisioning.operatorId,
        provisioningConfigurationAllowed: false,
      });
    return Object.freeze({
      environment: Object.freeze({
        ...environment,
        operatorKeyReference: CORE_OPERATOR_KEY_REFERENCE,
        operatorId: receipt.operatorId,
        operatorKeyRevision: "1",
      }),
      keychainMode: "bundled",
      runtimeBlocked: false,
      provisioningOperatorId: receipt.operatorId,
      provisioningConfigurationAllowed: true,
    });
  }

  if (
    inspection.status === "legacy_direct_complete" &&
    inspection.receipt === null
  ) {
    const operatorFields = configuredOperatorFieldState(environment);
    if (
      operatorFields.kind !== "complete" ||
      operatorFields.keyReference !== CORE_OPERATOR_KEY_REFERENCE ||
      operatorFields.keyRevision !== 1
    )
      return Object.freeze({
        environment,
        keychainMode: "generic" as const,
        runtimeBlocked: true,
        provisioningOperatorId: provisioning.operatorId,
        provisioningConfigurationAllowed: false,
      });
    return Object.freeze({
      environment,
      keychainMode: "legacy_direct" as const,
      runtimeBlocked: false,
      provisioningOperatorId: operatorFields.operatorId,
      provisioningConfigurationAllowed: false,
    });
  }

  return Object.freeze({
    environment,
    keychainMode: "generic",
    runtimeBlocked: inspection.status !== "absent",
    provisioningOperatorId: provisioning.operatorId,
    provisioningConfigurationAllowed: provisioning.allowed,
  });
}

function provisioningConfiguration(environment: LocalApplicationEnvironment): {
  readonly allowed: boolean;
  readonly operatorId: string;
} {
  const operatorFields = configuredOperatorFieldState(environment);
  const eventVersionCompatible =
    environment.eventKeyMinimumVersion === undefined ||
    environment.eventKeyMinimumVersion === "1";
  if (operatorFields.kind === "missing")
    return Object.freeze({
      allowed: eventVersionCompatible,
      operatorId: DEFAULT_CORE_OPERATOR_ID,
    });
  if (
    operatorFields.kind === "complete" &&
    operatorFields.keyReference === CORE_OPERATOR_KEY_REFERENCE &&
    operatorFields.keyRevision === 1
  )
    return Object.freeze({
      allowed: eventVersionCompatible,
      operatorId: operatorFields.operatorId,
    });
  return Object.freeze({
    allowed: false,
    operatorId: DEFAULT_CORE_OPERATOR_ID,
  });
}

type ConfiguredOperatorFieldState =
  | { readonly kind: "missing" }
  | { readonly kind: "partial" }
  | {
      readonly kind: "complete";
      readonly keyReference: string;
      readonly operatorId: string;
      readonly keyRevision: number;
    };

function configuredOperatorFieldState(
  environment: LocalApplicationEnvironment,
): ConfiguredOperatorFieldState {
  const values = [
    environment.operatorKeyReference,
    environment.operatorId,
    environment.operatorKeyRevision,
  ] as const;
  if (values.every((value) => value === undefined))
    return Object.freeze({ kind: "missing" as const });
  const [keyReference, operatorId, revisionText] = values;
  if (
    typeof keyReference !== "string" ||
    typeof operatorId !== "string" ||
    !SAFE_OPERATOR_ID.test(operatorId) ||
    typeof revisionText !== "string" ||
    !POSITIVE_DECIMAL.test(revisionText)
  )
    return Object.freeze({ kind: "partial" as const });
  const keyRevision = Number(revisionText);
  if (!Number.isSafeInteger(keyRevision))
    return Object.freeze({ kind: "partial" as const });
  return Object.freeze({
    kind: "complete" as const,
    keyReference,
    operatorId,
    keyRevision,
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
  secretStore: SecretStore,
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
    ...(process.env["BUGBOUNTY_ACTIVE_TESTING_ENABLED"] === undefined
      ? {}
      : {
          activeTestingEnabled: process.env["BUGBOUNTY_ACTIVE_TESTING_ENABLED"],
        }),
  });
}

interface PreparedHackerOneMetadata {
  readonly service: HackerOneMetadataService;
  readonly metadata: HackerOneMetadataStore;
}

function prepareHackerOneMetadata(
  database: ControlPlaneDatabase,
  controlPlane: ControlPlaneStore,
  environment: LocalApplicationEnvironment,
  platform: NodeJS.Platform,
  now: () => Date,
): PreparedHackerOneMetadata {
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
  const hackerOneKeychain = new MacOSHackerOneKeychainMutationBackend(platform);
  const credentials = new HackerOneCredentialVault(
    hackerOneKeychain,
    hackerOneKeychain,
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
  return Object.freeze({
    metadata,
    service: new HackerOneMetadataService({
      runtime,
      store: metadata,
      credentials,
      client,
      actionGate,
      killSwitch,
      now,
    }),
  });
}

function prepareActiveTesting(
  database: ControlPlaneDatabase,
  controlPlane: ControlPlaneStore,
  metadata: HackerOneMetadataStore,
  environment: LocalApplicationEnvironment,
): LocalActiveTestingController {
  const explicitlyEnabled = environment.activeTestingEnabled === "1";
  const readOnlyEnabled = environment.hackerOneReadonlyEnabled === "true";
  const runtime = resolveActiveTestingRuntime({
    version: 1,
    capability: "HACKERONE_ACTIVE_TEST",
    external_integrations_enabled:
      environment.externalIntegrationsEnabled === "true",
    enabled: explicitlyEnabled && readOnlyEnabled,
    request_budget: {
      max_requests_total: 10,
      requests_per_minute: 2,
      max_concurrency: 1,
    },
    request_timeout_ms: 5_000,
    max_response_bytes: 65_536,
  });
  const gate = new ActiveTestingActionGate(database, controlPlane, runtime);
  const service = new ActiveTestingService(
    metadata,
    gate,
    new ProductionActiveTestTransport(controlPlane),
  );
  return new LocalActiveTestingController({ service, gate, runtime });
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
