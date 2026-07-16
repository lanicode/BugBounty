import { types } from "node:util";
import type { ProgramConfig } from "../config/types.js";
import { decideEgress } from "../egress-guard/guard.js";
import { SecurityError } from "../shared/errors.js";
import {
  HACKERONE_API_HOST,
  HACKERONE_API_ORIGIN,
  HACKERONE_API_PORT,
} from "./types.js";
import {
  HACKERONE_METADATA_READ_CAPABILITY,
  isTrustedHackerOneMetadataReadRuntime,
  type HackerOneMetadataReadRuntimeState,
} from "./runtime.js";

export const HACKERONE_METADATA_MAX_PAGE_SIZE = 100;

export type HackerOneMetadataOperation =
  "program" | "programs" | "scope_exclusions" | "structured_scopes";

export interface HackerOneMetadataPage {
  readonly number: number;
  readonly size: number;
}

export interface HackerOneMetadataRequestIntent {
  readonly version: 1;
  readonly capability: typeof HACKERONE_METADATA_READ_CAPABILITY;
  readonly operation: HackerOneMetadataOperation;
  readonly handle: string | null;
  readonly page: HackerOneMetadataPage | null;
}

/**
 * Observation supplied by the persistent reservation store immediately before
 * it atomically consumes the single unit described by the resulting plan.
 */
export interface HackerOneMetadataRequestBudgetObservation {
  readonly consumedRequests: number;
  readonly activeRequests: number;
  readonly requestsInCurrentMinute: number;
}

export interface HackerOneMetadataRequestPlan {
  readonly version: 1;
  readonly capability: typeof HACKERONE_METADATA_READ_CAPABILITY;
  readonly operation: HackerOneMetadataOperation;
  readonly method: "GET";
  readonly scheme: "https";
  readonly host: typeof HACKERONE_API_HOST;
  readonly port: typeof HACKERONE_API_PORT;
  readonly origin: typeof HACKERONE_API_ORIGIN;
  readonly path: string;
  readonly query: string;
  readonly url: string;
  readonly handle: string | null;
  readonly page: HackerOneMetadataPage | null;
  readonly captureMode: "metadata_only";
  readonly followRedirects: false;
  readonly budgetUnits: 1;
}

const INTENT_KEYS = Object.freeze([
  "capability",
  "handle",
  "operation",
  "page",
  "version",
] as const);

const PAGE_KEYS = Object.freeze(["number", "size"] as const);
const BUDGET_KEYS = Object.freeze([
  "activeRequests",
  "consumedRequests",
  "requestsInCurrentMinute",
] as const);

const PROGRAMS_PATH = "/v1/hackers/programs";
const STRONG_HANDLE = /^[a-z0-9](?:[a-z0-9_-]{0,126}[a-z0-9])?$/u;
const MAX_NEXT_LINK_BYTES = 4_096;
const ZERO_HASH = "0".repeat(64);
const trustedPlans = new WeakMap<object, HackerOneMetadataRequestPlan>();

const FIXED_EGRESS_CONFIG: ProgramConfig = Object.freeze({
  version: 2,
  program: Object.freeze({
    platform: "hackerone",
    handle: "hackerone-metadata-read",
    display_name: "HackerOne read-only metadata capability",
    policy_source: "internal-fixed-metadata-policy",
    policy_hash_sha256: ZERO_HASH,
    policy_accepted_at: null,
    policy_accepted_by: null,
  }),
  network: Object.freeze({
    targets: Object.freeze([
      Object.freeze({
        scheme: "https" as const,
        host: HACKERONE_API_HOST,
        ports: Object.freeze([HACKERONE_API_PORT]),
        path_prefixes: Object.freeze([PROGRAMS_PATH]),
      }),
    ]),
    supporting_hosts: Object.freeze([]),
    blocked_hosts: Object.freeze([]),
    deny_by_default: true as const,
    allow_plain_http: false,
    follow_redirects: false as const,
    block_service_workers_during_capture: true as const,
  }),
  capture: Object.freeze({
    persist_unredacted_traffic: false as const,
    persist_response_bodies: "selective" as const,
    allowed_body_content_types: Object.freeze([
      "application/json",
      "application/vnd.api+json",
    ]),
    max_body_bytes: 1_048_576,
    binary_handling: "hash_only" as const,
    websocket_capture: "disabled",
    stable_pseudonyms: true as const,
    local_hmac_key_ref: "keychain://bugbounty-copilot/local-hmac",
    quarantine_unknown_identity_data: true as const,
  }),
  accounts: Object.freeze([]),
  budgets: Object.freeze({
    global_requests_per_minute: 100,
    max_concurrency: 1 as const,
    max_requests_per_candidate: 100,
    max_state_changes_per_candidate: 0,
    stop_after_first_positive_signal: true as const,
    cool_down_seconds_after_error: 60,
    stop_statuses: Object.freeze([301, 302, 303, 307, 308, 401, 403, 429]),
  }),
  forbidden: Object.freeze([
    "active_security_test",
    "report_submission",
    "weakness_catalog_request",
  ]),
  policy_drift: Object.freeze({
    block_campaign_when_policy_hash_changes: true as const,
    require_new_acceptance: true as const,
  }),
});

/**
 * Creates only the first request of one of the four closed metadata
 * operations. Paginated operations must start at page one; every continuation
 * must pass createNextHackerOneMetadataRequestPlan.
 */
export function createInitialHackerOneMetadataRequestPlan(
  value: unknown,
  runtime: unknown,
  budget: unknown,
): HackerOneMetadataRequestPlan {
  const intent = parseInitialIntent(value);
  assertRuntimeEnabled(runtime);
  assertBudget(runtime, budget);
  return createPlan(intent);
}

/**
 * Validates an untrusted API pagination link against the current branded plan.
 * A continuation may only keep the exact operation, handle, path, and page
 * size while advancing page[number] by exactly one.
 */
export function createNextHackerOneMetadataRequestPlan(
  current: unknown,
  next: unknown,
  runtime: unknown,
  budget: unknown,
): HackerOneMetadataRequestPlan | null {
  const plan = requireTrustedPlan(current);
  if (next === null) return null;
  if (plan.page === null)
    throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
  if (typeof next !== "string" || byteLength(next) > MAX_NEXT_LINK_BYTES)
    throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
  const nextNumber = plan.page.number + 1;
  if (!Number.isSafeInteger(nextNumber))
    throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
  assertCanonicalNextLink(next, plan.path, nextNumber, plan.page.size);
  assertRuntimeEnabled(runtime);
  assertBudget(runtime, budget);
  return createPlan({
    version: 1,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    operation: plan.operation,
    handle: plan.handle,
    page: Object.freeze({ number: nextNumber, size: plan.page.size }),
  });
}

export function isStrongHackerOneProgramHandle(
  value: unknown,
): value is string {
  return typeof value === "string" && STRONG_HANDLE.test(value);
}

/**
 * Captures a canonical data-only copy of a plan created by this module. The
 * copy is used at the persistent external-action boundary so accessors,
 * proxies, and structurally similar caller objects can never cross the gate.
 */
export function captureTrustedHackerOneMetadataRequestPlan(
  value: unknown,
): HackerOneMetadataRequestPlan {
  const plan = requireTrustedPlan(value);
  return createCapturedPlan(plan);
}

function parseInitialIntent(value: unknown): HackerOneMetadataRequestIntent {
  let record: Readonly<Record<string, unknown>>;
  try {
    record = exactDataRecord(value, INTENT_KEYS);
  } catch {
    throw new SecurityError("HACKERONE_REQUEST_SCHEMA_INVALID");
  }
  if (
    record["version"] !== 1 ||
    record["capability"] !== HACKERONE_METADATA_READ_CAPABILITY
  )
    throw new SecurityError("HACKERONE_REQUEST_SCHEMA_INVALID");
  const operation = parseOperation(record["operation"]);
  const handle = parseHandle(record["handle"], operation);
  const page = parseInitialPage(record["page"], operation);
  return Object.freeze({
    version: 1 as const,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    operation,
    handle,
    page,
  });
}

function parseOperation(value: unknown): HackerOneMetadataOperation {
  switch (value) {
    case "program":
    case "programs":
    case "scope_exclusions":
    case "structured_scopes":
      return value;
    default:
      throw new SecurityError("HACKERONE_METADATA_ENDPOINT_BLOCKED");
  }
}

function parseHandle(
  value: unknown,
  operation: HackerOneMetadataOperation,
): string | null {
  if (operation === "programs") {
    if (value !== null) throw new SecurityError("HACKERONE_HANDLE_INVALID");
    return null;
  }
  if (!isStrongHackerOneProgramHandle(value))
    throw new SecurityError("HACKERONE_HANDLE_INVALID");
  return value;
}

function parseInitialPage(
  value: unknown,
  operation: HackerOneMetadataOperation,
): HackerOneMetadataPage | null {
  if (operation === "program") {
    if (value !== null) throw new SecurityError("HACKERONE_PAGE_INVALID");
    return null;
  }
  let page: Readonly<Record<string, unknown>>;
  try {
    page = exactDataRecord(value, PAGE_KEYS);
  } catch {
    throw new SecurityError("HACKERONE_PAGE_INVALID");
  }
  if (
    page["number"] !== 1 ||
    !isBoundedInteger(page["size"], 1, HACKERONE_METADATA_MAX_PAGE_SIZE)
  )
    throw new SecurityError("HACKERONE_PAGE_INVALID");
  return Object.freeze({ number: 1, size: page["size"] });
}

function createPlan(
  intent: HackerOneMetadataRequestIntent,
): HackerOneMetadataRequestPlan {
  const path = operationPath(intent.operation, intent.handle);
  const query =
    intent.page === null
      ? ""
      : canonicalPageQuery(intent.page.number, intent.page.size);
  const url = `${HACKERONE_API_ORIGIN}${path}${query}`;
  assertFixedEgress(url, path);
  const plan = Object.freeze({
    version: 1 as const,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    operation: intent.operation,
    method: "GET" as const,
    scheme: "https" as const,
    host: HACKERONE_API_HOST,
    port: HACKERONE_API_PORT,
    origin: HACKERONE_API_ORIGIN,
    path,
    query,
    url,
    handle: intent.handle,
    page:
      intent.page === null
        ? null
        : Object.freeze({
            number: intent.page.number,
            size: intent.page.size,
          }),
    captureMode: "metadata_only" as const,
    followRedirects: false as const,
    budgetUnits: 1 as const,
  });
  trustedPlans.set(plan, plan);
  return plan;
}

function createCapturedPlan(
  plan: HackerOneMetadataRequestPlan,
): HackerOneMetadataRequestPlan {
  const captured = Object.freeze({
    version: 1 as const,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    operation: plan.operation,
    method: "GET" as const,
    scheme: "https" as const,
    host: HACKERONE_API_HOST,
    port: HACKERONE_API_PORT,
    origin: HACKERONE_API_ORIGIN,
    path: plan.path,
    query: plan.query,
    url: plan.url,
    handle: plan.handle,
    page:
      plan.page === null
        ? null
        : Object.freeze({ number: plan.page.number, size: plan.page.size }),
    captureMode: "metadata_only" as const,
    followRedirects: false as const,
    budgetUnits: 1 as const,
  });
  trustedPlans.set(captured, captured);
  return captured;
}

function operationPath(
  operation: HackerOneMetadataOperation,
  handle: string | null,
): string {
  switch (operation) {
    case "programs":
      return PROGRAMS_PATH;
    case "program":
      return `${PROGRAMS_PATH}/${requiredHandle(handle)}`;
    case "structured_scopes":
      return `${PROGRAMS_PATH}/${requiredHandle(handle)}/structured_scopes`;
    case "scope_exclusions":
      return `${PROGRAMS_PATH}/${requiredHandle(handle)}/scope_exclusions`;
  }
}

function requiredHandle(handle: string | null): string {
  if (!isStrongHackerOneProgramHandle(handle))
    throw new SecurityError("HACKERONE_HANDLE_INVALID");
  return handle;
}

function canonicalPageQuery(number: number, size: number): string {
  if (
    !Number.isSafeInteger(number) ||
    number < 1 ||
    !isBoundedInteger(size, 1, HACKERONE_METADATA_MAX_PAGE_SIZE)
  )
    throw new SecurityError("HACKERONE_PAGE_INVALID");
  return `?page[number]=${String(number)}&page[size]=${String(size)}`;
}

function assertCanonicalNextLink(
  value: string,
  expectedPath: string,
  expectedPageNumber: number,
  expectedPageSize: number,
): void {
  if (/[^\x00-\x7f]/u.test(value))
    throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
  const authority = rawAuthority(value);
  if (
    authority !== HACKERONE_API_HOST &&
    authority !== `${HACKERONE_API_HOST}:${String(HACKERONE_API_PORT)}`
  )
    throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.hostname !== HACKERONE_API_HOST ||
    (parsed.port !== "" && parsed.port !== String(HACKERONE_API_PORT)) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !== expectedPath
  )
    throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
  assertCanonicalPageParameters(
    parsed.searchParams,
    expectedPageNumber,
    expectedPageSize,
  );
}

function assertCanonicalPageParameters(
  parameters: URLSearchParams,
  expectedPageNumber: number,
  expectedPageSize: number,
): void {
  const entries = [...parameters.entries()];
  const numbers = parameters.getAll("page[number]");
  const sizes = parameters.getAll("page[size]");
  if (
    entries.length !== 2 ||
    numbers.length !== 1 ||
    sizes.length !== 1 ||
    entries.some(([key]) => key !== "page[number]" && key !== "page[size]") ||
    numbers[0] !== String(expectedPageNumber) ||
    sizes[0] !== String(expectedPageSize)
  )
    throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
}

function rawAuthority(value: string): string {
  if (!value.startsWith("https://")) return "";
  return value.slice("https://".length).split(/[/?#]/u, 1)[0] ?? "";
}

function assertRuntimeEnabled(
  value: unknown,
): asserts value is HackerOneMetadataReadRuntimeState {
  if (
    !isTrustedHackerOneMetadataReadRuntime(value) ||
    !value.enabled ||
    !value.externalIntegrationsEnabled ||
    value.disableReason !== null
  )
    throw new SecurityError("HACKERONE_METADATA_CAPABILITY_DISABLED");
}

function assertBudget(
  runtime: HackerOneMetadataReadRuntimeState,
  value: unknown,
): void {
  let observation: Readonly<Record<string, unknown>>;
  try {
    observation = exactDataRecord(value, BUDGET_KEYS);
  } catch {
    throw new SecurityError("HACKERONE_REQUEST_BUDGET_INVALID");
  }
  const consumedRequests = observation["consumedRequests"];
  const activeRequests = observation["activeRequests"];
  const requestsInCurrentMinute = observation["requestsInCurrentMinute"];
  if (
    !isNonNegativeSafeInteger(consumedRequests) ||
    !isNonNegativeSafeInteger(activeRequests) ||
    !isNonNegativeSafeInteger(requestsInCurrentMinute) ||
    activeRequests > consumedRequests ||
    requestsInCurrentMinute > consumedRequests
  )
    throw new SecurityError("HACKERONE_REQUEST_BUDGET_INVALID");
  if (consumedRequests >= runtime.requestBudget.maxRequestsTotal)
    throw new SecurityError("HACKERONE_REQUEST_BUDGET_EXCEEDED");
  if (activeRequests >= runtime.requestBudget.maxConcurrency)
    throw new SecurityError("HACKERONE_REQUEST_CONCURRENCY_EXCEEDED");
  if (requestsInCurrentMinute >= runtime.requestBudget.requestsPerMinute)
    throw new SecurityError("HACKERONE_REQUEST_RATE_EXCEEDED");
}

function assertFixedEgress(url: string, path: string): void {
  const decision = decideEgress(
    { config: FIXED_EGRESS_CONFIG },
    {
      url,
      method: "GET",
      captureMode: "metadata_only",
      resourceKind: "fetch",
      isRedirect: false,
    },
  );
  if (
    !decision.allow ||
    decision.reason !== "ALLOW_TARGET" ||
    decision.normalized?.scheme !== "https" ||
    decision.normalized.host !== HACKERONE_API_HOST ||
    decision.normalized.port !== HACKERONE_API_PORT ||
    decision.normalized.method !== "GET" ||
    decision.normalized.path !== path
  )
    throw new SecurityError("HACKERONE_EGRESS_POLICY_BLOCKED");
}

function requireTrustedPlan(value: unknown): HackerOneMetadataRequestPlan {
  if (value === null || typeof value !== "object")
    throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
  try {
    const plan = trustedPlans.get(value);
    if (
      types.isProxy(value) ||
      Reflect.getPrototypeOf(value) !== Object.prototype ||
      plan === undefined
    )
      throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
    return plan;
  } catch (error) {
    if (error instanceof SecurityError) throw error;
    throw new SecurityError("HACKERONE_PAGINATION_BLOCKED");
  }
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
    throw new Error("HACKERONE_DATA_RECORD_INVALID");
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string") ||
    !expectedKeys.every((key) => keys.includes(key))
  )
    throw new Error("HACKERONE_DATA_RECORD_INVALID");
  const result: Record<string, unknown> = {};
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new Error("HACKERONE_DATA_RECORD_INVALID");
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function isBoundedInteger(
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

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}
