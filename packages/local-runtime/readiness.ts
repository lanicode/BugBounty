import { types } from "node:util";

export type SecretStoreProbe =
  "not_checked" | "available" | "unavailable" | "error";

/**
 * Typed caller-side shape. Every value is still treated as untrusted by
 * deriveRuntimeReadiness, including values supplied by TypeScript callers.
 */
export interface RuntimeReadinessInput {
  readonly platform: string;
  readonly eventKeyMinimumVersion: unknown;
  readonly operatorKeyReference: unknown;
  readonly operatorId: unknown;
  readonly operatorKeyRevision: unknown;
  readonly secretStoreProbe: SecretStoreProbe;
  readonly demoSaasReady: boolean;
  readonly databaseReady: boolean;
}

export type RuntimeReadinessStatus = "ready" | "setup_required" | "blocked";

export type RuntimeGateStatus = "ready" | "blocked";

export type RuntimeConfigurationStatus = "ready" | "setup_required" | "blocked";

export type RuntimeOperatorStatus = RuntimeConfigurationStatus;

export type RuntimeReadinessReasonCode =
  | "RUNTIME_READY"
  | "RUNTIME_INPUT_INVALID"
  | "RUNTIME_PLATFORM_UNSUPPORTED"
  | "RUNTIME_EVENT_KEY_MINIMUM_VERSION_SETUP_REQUIRED"
  | "RUNTIME_EVENT_KEY_MINIMUM_VERSION_INVALID"
  | "RUNTIME_OPERATOR_SETUP_REQUIRED"
  | "RUNTIME_OPERATOR_CONFIGURATION_INVALID"
  | "RUNTIME_SECRET_STORE_SETUP_REQUIRED"
  | "RUNTIME_SECRET_STORE_UNAVAILABLE"
  | "RUNTIME_SECRET_STORE_ERROR"
  | "RUNTIME_DEMO_SAAS_NOT_READY"
  | "RUNTIME_DATABASE_NOT_READY";

export interface RuntimeReadiness {
  readonly status: RuntimeReadinessStatus;
  readonly ready: boolean;
  readonly platformStatus: RuntimeGateStatus;
  readonly eventKeyMinimumVersionStatus: RuntimeConfigurationStatus;
  readonly operatorStatus: RuntimeOperatorStatus;
  readonly secretStoreStatus: RuntimeConfigurationStatus;
  readonly demoSaasStatus: RuntimeGateStatus;
  readonly databaseStatus: RuntimeGateStatus;
  readonly externalIntegrationsEnabled: false;
  readonly aiProviderStatus: "disabled_not_implemented";
  readonly browserWorkerStatus: "test_harness_only";
  readonly killSwitchAssumedActive: true;
  readonly reasonCodes: readonly RuntimeReadinessReasonCode[];
}

const INPUT_KEYS = Object.freeze([
  "platform",
  "eventKeyMinimumVersion",
  "operatorKeyReference",
  "operatorId",
  "operatorKeyRevision",
  "secretStoreProbe",
  "demoSaasReady",
  "databaseReady",
] as const);

type InputKey = (typeof INPUT_KEYS)[number];
type UntrustedRuntimeRecord = Readonly<Record<InputKey, unknown>>;

const SAFE_ACTOR = /^[A-Za-z0-9._@-]{1,128}$/u;
const KEYCHAIN_REFERENCE =
  /^keychain:\/\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._/-]+)$/u;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/u;
const MAX_EVENT_KEY_VERSION = 10_000;

/**
 * Converts an untrusted readiness observation into a closed, non-sensitive
 * status projection. Validation failures are data, not exceptions.
 */
export function deriveRuntimeReadiness(input: unknown): RuntimeReadiness {
  try {
    const record = cloneExactRuntimeRecord(input);
    if (record === undefined) return invalidInputReadiness();

    const platform = record.platform;
    const secretStoreProbe = record.secretStoreProbe;
    const demoSaasReady = record.demoSaasReady;
    const databaseReady = record.databaseReady;
    if (
      typeof platform !== "string" ||
      !isSecretStoreProbe(secretStoreProbe) ||
      typeof demoSaasReady !== "boolean" ||
      typeof databaseReady !== "boolean"
    )
      return invalidInputReadiness();

    const reasonCodes: RuntimeReadinessReasonCode[] = [];

    const platformStatus: RuntimeGateStatus =
      platform === "darwin" ? "ready" : "blocked";
    if (platformStatus === "blocked")
      reasonCodes.push("RUNTIME_PLATFORM_UNSUPPORTED");

    const eventKeyMinimumVersionStatus: RuntimeConfigurationStatus =
      record.eventKeyMinimumVersion === undefined
        ? "setup_required"
        : isPositiveSafeInteger(
              record.eventKeyMinimumVersion,
              MAX_EVENT_KEY_VERSION,
            )
          ? "ready"
          : "blocked";
    if (eventKeyMinimumVersionStatus === "setup_required")
      reasonCodes.push("RUNTIME_EVENT_KEY_MINIMUM_VERSION_SETUP_REQUIRED");
    else if (eventKeyMinimumVersionStatus === "blocked")
      reasonCodes.push("RUNTIME_EVENT_KEY_MINIMUM_VERSION_INVALID");

    const operatorStatus = deriveOperatorStatus(record);
    if (operatorStatus === "setup_required")
      reasonCodes.push("RUNTIME_OPERATOR_SETUP_REQUIRED");
    else if (operatorStatus === "blocked")
      reasonCodes.push("RUNTIME_OPERATOR_CONFIGURATION_INVALID");

    const secretStoreStatus: RuntimeConfigurationStatus =
      secretStoreProbe === "available"
        ? "ready"
        : secretStoreProbe === "not_checked"
          ? "setup_required"
          : "blocked";
    if (secretStoreProbe === "not_checked")
      reasonCodes.push("RUNTIME_SECRET_STORE_SETUP_REQUIRED");
    else if (secretStoreProbe === "unavailable")
      reasonCodes.push("RUNTIME_SECRET_STORE_UNAVAILABLE");
    else if (secretStoreProbe === "error")
      reasonCodes.push("RUNTIME_SECRET_STORE_ERROR");

    const demoSaasStatus: RuntimeGateStatus = demoSaasReady
      ? "ready"
      : "blocked";
    if (!demoSaasReady) reasonCodes.push("RUNTIME_DEMO_SAAS_NOT_READY");

    const databaseStatus: RuntimeGateStatus = databaseReady
      ? "ready"
      : "blocked";
    if (!databaseReady) reasonCodes.push("RUNTIME_DATABASE_NOT_READY");

    const hasBlockingGate =
      platformStatus === "blocked" ||
      eventKeyMinimumVersionStatus === "blocked" ||
      operatorStatus === "blocked" ||
      secretStoreStatus === "blocked" ||
      demoSaasStatus === "blocked" ||
      databaseStatus === "blocked";
    const status: RuntimeReadinessStatus = hasBlockingGate
      ? "blocked"
      : eventKeyMinimumVersionStatus === "setup_required" ||
          operatorStatus === "setup_required" ||
          secretStoreStatus === "setup_required"
        ? "setup_required"
        : "ready";

    return freezeReadiness({
      status,
      platformStatus,
      eventKeyMinimumVersionStatus,
      operatorStatus,
      secretStoreStatus,
      demoSaasStatus,
      databaseStatus,
      reasonCodes: status === "ready" ? ["RUNTIME_READY"] : reasonCodes,
    });
  } catch {
    return invalidInputReadiness();
  }
}

function cloneExactRuntimeRecord(
  value: unknown,
): UntrustedRuntimeRecord | undefined {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype
  )
    return undefined;

  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== INPUT_KEYS.length ||
    ownKeys.some((key) => typeof key !== "string") ||
    !INPUT_KEYS.every((key) => ownKeys.includes(key))
  )
    return undefined;

  const fields = new Map<InputKey, unknown>();
  for (const key of INPUT_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      return undefined;
    const fieldValue: unknown = descriptor.value;
    fields.set(key, fieldValue);
  }

  return Object.freeze({
    platform: fields.get("platform"),
    eventKeyMinimumVersion: fields.get("eventKeyMinimumVersion"),
    operatorKeyReference: fields.get("operatorKeyReference"),
    operatorId: fields.get("operatorId"),
    operatorKeyRevision: fields.get("operatorKeyRevision"),
    secretStoreProbe: fields.get("secretStoreProbe"),
    demoSaasReady: fields.get("demoSaasReady"),
    databaseReady: fields.get("databaseReady"),
  });
}

function deriveOperatorStatus(
  record: UntrustedRuntimeRecord,
): RuntimeOperatorStatus {
  const reference = record.operatorKeyReference;
  const operatorId = record.operatorId;
  const revision = record.operatorKeyRevision;
  if (
    reference === undefined &&
    operatorId === undefined &&
    revision === undefined
  )
    return "setup_required";
  if (
    !isKeychainReference(reference) ||
    typeof operatorId !== "string" ||
    !SAFE_ACTOR.test(operatorId) ||
    !isPositiveSafeInteger(revision)
  )
    return "blocked";
  return "ready";
}

function isPositiveSafeInteger(
  value: unknown,
  maximum = Number.MAX_SAFE_INTEGER,
): boolean {
  if (typeof value === "number")
    return Number.isSafeInteger(value) && value > 0 && value <= maximum;
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 16 ||
    !POSITIVE_DECIMAL.test(value)
  )
    return false;
  const parsed = Number(value);
  return (
    Number.isSafeInteger(parsed) &&
    parsed > 0 &&
    parsed <= maximum &&
    String(parsed) === value
  );
}

function isKeychainReference(value: unknown): boolean {
  if (typeof value !== "string" || value.length === 0 || value.length > 512)
    return false;
  const match = KEYCHAIN_REFERENCE.exec(value);
  return (
    match?.[1] !== undefined &&
    match[2] !== undefined &&
    !match[2].includes("..")
  );
}

function isSecretStoreProbe(value: unknown): value is SecretStoreProbe {
  return (
    value === "not_checked" ||
    value === "available" ||
    value === "unavailable" ||
    value === "error"
  );
}

interface ReadinessParts {
  readonly status: RuntimeReadinessStatus;
  readonly platformStatus: RuntimeGateStatus;
  readonly eventKeyMinimumVersionStatus: RuntimeConfigurationStatus;
  readonly operatorStatus: RuntimeOperatorStatus;
  readonly secretStoreStatus: RuntimeConfigurationStatus;
  readonly demoSaasStatus: RuntimeGateStatus;
  readonly databaseStatus: RuntimeGateStatus;
  readonly reasonCodes: readonly RuntimeReadinessReasonCode[];
}

function freezeReadiness(parts: ReadinessParts): RuntimeReadiness {
  const reasonCodes = Object.freeze([...parts.reasonCodes]);
  return Object.freeze({
    status: parts.status,
    ready: parts.status === "ready",
    platformStatus: parts.platformStatus,
    eventKeyMinimumVersionStatus: parts.eventKeyMinimumVersionStatus,
    operatorStatus: parts.operatorStatus,
    secretStoreStatus: parts.secretStoreStatus,
    demoSaasStatus: parts.demoSaasStatus,
    databaseStatus: parts.databaseStatus,
    externalIntegrationsEnabled: false,
    aiProviderStatus: "disabled_not_implemented",
    browserWorkerStatus: "test_harness_only",
    killSwitchAssumedActive: true,
    reasonCodes,
  });
}

function invalidInputReadiness(): RuntimeReadiness {
  return freezeReadiness({
    status: "blocked",
    platformStatus: "blocked",
    eventKeyMinimumVersionStatus: "blocked",
    operatorStatus: "blocked",
    secretStoreStatus: "blocked",
    demoSaasStatus: "blocked",
    databaseStatus: "blocked",
    reasonCodes: ["RUNTIME_INPUT_INVALID"],
  });
}
