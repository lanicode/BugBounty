import { types } from "node:util";

export const HACKERONE_METADATA_READ_CAPABILITY =
  "HACKERONE_METADATA_READ" as const;

export const HACKERONE_METADATA_MAX_REQUESTS_TOTAL = 10_000;
export const HACKERONE_METADATA_MAX_REQUESTS_PER_MINUTE = 100;

export interface HackerOneMetadataRequestBudgetConfig {
  readonly maxRequestsTotal: number;
  readonly requestsPerMinute: number;
  readonly maxConcurrency: 1;
}

export interface HackerOneMetadataReadRuntimeConfig {
  readonly version: 1;
  readonly capability: typeof HACKERONE_METADATA_READ_CAPABILITY;
  readonly external_integrations_enabled: boolean;
  readonly enabled: boolean;
  readonly request_budget: {
    readonly max_requests_total: number;
    readonly requests_per_minute: number;
    readonly max_concurrency: 1;
  };
}

export type HackerOneMetadataReadDisableReason =
  | "CAPABILITY_DISABLED"
  | "CONFIG_INVALID"
  | "CONFIG_MISSING"
  | "EXTERNAL_INTEGRATIONS_DISABLED";

export interface HackerOneMetadataReadRuntimeState {
  readonly capability: typeof HACKERONE_METADATA_READ_CAPABILITY;
  readonly configured: boolean;
  readonly enabled: boolean;
  readonly externalIntegrationsEnabled: boolean;
  readonly disableReason: HackerOneMetadataReadDisableReason | null;
  readonly requestBudget: HackerOneMetadataRequestBudgetConfig;
}

const TOP_LEVEL_KEYS = Object.freeze([
  "capability",
  "enabled",
  "external_integrations_enabled",
  "request_budget",
  "version",
] as const);

const REQUEST_BUDGET_KEYS = Object.freeze([
  "max_concurrency",
  "max_requests_total",
  "requests_per_minute",
] as const);

const DISABLED_BUDGET = Object.freeze({
  maxRequestsTotal: 0,
  requestsPerMinute: 0,
  maxConcurrency: 1 as const,
});

const trustedRuntimeStates = new WeakSet();

/**
 * Resolves the isolated read-only capability without consulting or widening
 * the Phase-2 runtime. Untrusted, missing, accessor-backed, or malformed
 * configuration always becomes an inert state with a zero request budget.
 */
export function resolveHackerOneMetadataReadRuntime(
  value: unknown,
): HackerOneMetadataReadRuntimeState {
  if (value === undefined) return disabled("CONFIG_MISSING");
  try {
    const input = exactDataRecord(value, TOP_LEVEL_KEYS);
    const budget = exactDataRecord(
      input["request_budget"],
      REQUEST_BUDGET_KEYS,
    );
    if (
      input["version"] !== 1 ||
      input["capability"] !== HACKERONE_METADATA_READ_CAPABILITY ||
      typeof input["external_integrations_enabled"] !== "boolean" ||
      typeof input["enabled"] !== "boolean"
    )
      return disabled("CONFIG_INVALID");

    const maxRequestsTotal = boundedInteger(
      budget["max_requests_total"],
      1,
      HACKERONE_METADATA_MAX_REQUESTS_TOTAL,
    );
    const requestsPerMinute = boundedInteger(
      budget["requests_per_minute"],
      1,
      HACKERONE_METADATA_MAX_REQUESTS_PER_MINUTE,
    );
    if (
      maxRequestsTotal === undefined ||
      requestsPerMinute === undefined ||
      budget["max_concurrency"] !== 1
    )
      return disabled("CONFIG_INVALID");

    const requestBudget = Object.freeze({
      maxRequestsTotal,
      requestsPerMinute,
      maxConcurrency: 1 as const,
    });
    if (!input["external_integrations_enabled"])
      return disabled(
        "EXTERNAL_INTEGRATIONS_DISABLED",
        true,
        false,
        requestBudget,
      );
    if (!input["enabled"])
      return disabled("CAPABILITY_DISABLED", true, true, requestBudget);
    return freezeState({
      capability: HACKERONE_METADATA_READ_CAPABILITY,
      configured: true,
      enabled: true,
      externalIntegrationsEnabled: true,
      disableReason: null,
      requestBudget,
    });
  } catch {
    return disabled("CONFIG_INVALID");
  }
}

/**
 * Runtime authenticity is intentionally not structural: callers cannot turn
 * the capability on by fabricating a matching object or boolean.
 */
export function isTrustedHackerOneMetadataReadRuntime(
  value: unknown,
): value is HackerOneMetadataReadRuntimeState {
  if (value === null || typeof value !== "object") return false;
  try {
    return (
      !types.isProxy(value) &&
      Reflect.getPrototypeOf(value) === Object.prototype &&
      trustedRuntimeStates.has(value)
    );
  } catch {
    return false;
  }
}

function disabled(
  reason: HackerOneMetadataReadDisableReason,
  configured = false,
  externalIntegrationsEnabled = false,
  requestBudget: HackerOneMetadataRequestBudgetConfig = DISABLED_BUDGET,
): HackerOneMetadataReadRuntimeState {
  return freezeState({
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    configured,
    enabled: false,
    externalIntegrationsEnabled,
    disableReason: reason,
    requestBudget,
  });
}

function freezeState(
  value: HackerOneMetadataReadRuntimeState,
): HackerOneMetadataReadRuntimeState {
  const state = Object.freeze({
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    configured: value.configured,
    enabled: value.enabled,
    externalIntegrationsEnabled: value.externalIntegrationsEnabled,
    disableReason: value.disableReason,
    requestBudget: Object.freeze({
      maxRequestsTotal: value.requestBudget.maxRequestsTotal,
      requestsPerMinute: value.requestBudget.requestsPerMinute,
      maxConcurrency: 1 as const,
    }),
  });
  trustedRuntimeStates.add(state);
  return state;
}

function exactDataRecord(
  value: unknown,
  expectedKeys: readonly string[],
): Readonly<Record<string, unknown>> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype
  )
    throw new Error("HACKERONE_METADATA_RUNTIME_CONFIG_INVALID");
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string") ||
    !expectedKeys.every((key) => keys.includes(key))
  )
    throw new Error("HACKERONE_METADATA_RUNTIME_CONFIG_INVALID");

  const result: Record<string, unknown> = {};
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new Error("HACKERONE_METADATA_RUNTIME_CONFIG_INVALID");
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function boundedInteger(
  value: unknown,
  minimum: number,
  maximum: number,
): number | undefined {
  return typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
    ? value
    : undefined;
}
