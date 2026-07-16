import { types } from "node:util";
import { SecurityError } from "../shared/errors.js";
import {
  ACTIVE_TESTING_CAPABILITY,
  ACTIVE_TEST_RUNNER_VERSION,
  type ActiveTestingRuntimeInput,
  type ActiveTestingRuntimeState,
} from "./types.js";

const MAX_TOTAL_REQUESTS = 10;
const MAX_REQUESTS_PER_MINUTE = 2;
const MIN_TIMEOUT_MS = 1_000;
const MAX_TIMEOUT_MS = 10_000;
const MIN_RESPONSE_BYTES = 1_024;
const MAX_RESPONSE_BYTES = 65_536;
const trustedRuntimes = new WeakSet();

export function resolveActiveTestingRuntime(
  value: unknown,
): ActiveTestingRuntimeState {
  const input = captureRuntimeInput(value);
  const configured = input.external_integrations_enabled && input.enabled;
  const state = Object.freeze({
    version: 1 as const,
    capability: ACTIVE_TESTING_CAPABILITY,
    externalIntegrationsEnabled: input.external_integrations_enabled,
    enabled: input.enabled,
    configured,
    requestBudget: Object.freeze({
      maxRequestsTotal: input.request_budget.max_requests_total,
      requestsPerMinute: input.request_budget.requests_per_minute,
      maxConcurrency: 1 as const,
    }),
    requestTimeoutMs: input.request_timeout_ms,
    maxResponseBytes: input.max_response_bytes,
    runnerVersion: ACTIVE_TEST_RUNNER_VERSION,
  });
  trustedRuntimes.add(state);
  return state;
}

export function isTrustedActiveTestingRuntime(
  value: unknown,
): value is ActiveTestingRuntimeState {
  return (
    typeof value === "object" &&
    value !== null &&
    !types.isProxy(value) &&
    Reflect.getPrototypeOf(value) === Object.prototype &&
    Object.isFrozen(value) &&
    trustedRuntimes.has(value)
  );
}

function captureRuntimeInput(value: unknown): ActiveTestingRuntimeInput {
  if (!isPlainRecord(value))
    throw new SecurityError("ACTIVE_TEST_RUNTIME_INVALID");
  const record = value;
  assertExactKeys(record, [
    "capability",
    "enabled",
    "external_integrations_enabled",
    "max_response_bytes",
    "request_budget",
    "request_timeout_ms",
    "version",
  ]);
  if (
    record["version"] !== 1 ||
    record["capability"] !== ACTIVE_TESTING_CAPABILITY ||
    typeof record["external_integrations_enabled"] !== "boolean" ||
    typeof record["enabled"] !== "boolean"
  )
    throw new SecurityError("ACTIVE_TEST_RUNTIME_INVALID");
  const budget = record["request_budget"];
  if (!isPlainRecord(budget))
    throw new SecurityError("ACTIVE_TEST_RUNTIME_INVALID");
  const budgetRecord = budget;
  assertExactKeys(budgetRecord, [
    "max_concurrency",
    "max_requests_total",
    "requests_per_minute",
  ]);
  const total = budgetRecord["max_requests_total"];
  const perMinute = budgetRecord["requests_per_minute"];
  const timeout = record["request_timeout_ms"];
  const bytes = record["max_response_bytes"];
  if (
    !isIntegerBetween(total, 1, MAX_TOTAL_REQUESTS) ||
    !isIntegerBetween(perMinute, 1, MAX_REQUESTS_PER_MINUTE) ||
    budgetRecord["max_concurrency"] !== 1 ||
    !isIntegerBetween(timeout, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS) ||
    !isIntegerBetween(bytes, MIN_RESPONSE_BYTES, MAX_RESPONSE_BYTES)
  )
    throw new SecurityError("ACTIVE_TEST_RUNTIME_INVALID");
  return {
    version: 1,
    capability: ACTIVE_TESTING_CAPABILITY,
    external_integrations_enabled: record["external_integrations_enabled"],
    enabled: record["enabled"],
    request_budget: {
      max_requests_total: total,
      requests_per_minute: perMinute,
      max_concurrency: 1,
    },
    request_timeout_ms: timeout,
    max_response_bytes: bytes,
  };
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    Reflect.getPrototypeOf(value) === Object.prototype
  );
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): void {
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string") ||
    !expected.every((key) => keys.includes(key))
  )
    throw new SecurityError("ACTIVE_TEST_RUNTIME_INVALID");
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new SecurityError("ACTIVE_TEST_RUNTIME_INVALID");
  }
}

function isIntegerBetween(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}
