import { types } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import schema from "./plan.schema.json" with { type: "json" };
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { normalizeRequestPath } from "../egress-guard/normalize.js";
import { SecurityError } from "../shared/errors.js";
import type { ActiveTestPlanV1 } from "./types.js";

const MAX_PLAN_LIFETIME_MS = 10 * 60_000;
const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validateSchema = ajv.compile<ActiveTestPlanV1>(schema);

export function validateAndFreezeActiveTestPlan(
  value: unknown,
): ActiveTestPlanV1 {
  try {
    const cloned = clonePlan(value);
    if (!validateSchema(cloned))
      throw new SecurityError("ACTIVE_TEST_PLAN_SCHEMA_INVALID");
    const createdAt = canonicalTimestamp(cloned.created_at);
    const expiresAt = canonicalTimestamp(cloned.expires_at);
    if (
      Date.parse(expiresAt) <= Date.parse(createdAt) ||
      Date.parse(expiresAt) - Date.parse(createdAt) > MAX_PLAN_LIFETIME_MS ||
      normalizeRequestPath(cloned.target.path) !== cloned.target.path
    )
      throw new SecurityError("ACTIVE_TEST_PLAN_SEMANTICS_INVALID");
    const expected = expectedRequestBinding(cloned.test_class);
    if (
      cloned.request.method !== expected.method ||
      cloned.request.header_profile !== expected.headerProfile ||
      (cloned.test_class === "security_txt" &&
        cloned.target.path !== "/.well-known/security.txt")
    )
      throw new SecurityError("ACTIVE_TEST_PLAN_SEMANTICS_INVALID");
    return deepFreezePlan(cloned);
  } catch (error) {
    if (error instanceof SecurityError) throw error;
    throw new SecurityError("ACTIVE_TEST_PLAN_SCHEMA_INVALID");
  }
}

export function activeTestPlanDigest(value: unknown): string {
  return sha256(canonicalJson(validateAndFreezeActiveTestPlan(value)));
}

function clonePlan(value: unknown): unknown {
  const top = exactRecord(value, [
    "asset_identifier_digest",
    "budget",
    "confirmations",
    "created_at",
    "expires_at",
    "plan_id",
    "policy_digest",
    "program_handle",
    "program_ref",
    "request",
    "runner_version",
    "scope_id",
    "snapshot_digest",
    "target",
    "test_class",
    "version",
  ]);
  return {
    asset_identifier_digest: top["asset_identifier_digest"],
    budget: exactRecord(top["budget"], [
      "max_concurrency",
      "max_requests_total",
      "requests_per_minute",
    ]),
    confirmations: exactRecord(top["confirmations"], [
      "automation_permission_reviewed",
      "no_side_effects_confirmed",
      "scope_exclusions_reviewed",
      "scope_instruction_reviewed",
    ]),
    created_at: top["created_at"],
    expires_at: top["expires_at"],
    plan_id: top["plan_id"],
    policy_digest: top["policy_digest"],
    program_handle: top["program_handle"],
    program_ref: top["program_ref"],
    request: exactRecord(top["request"], [
      "capture_mode",
      "follow_redirects",
      "header_profile",
      "method",
      "retries",
    ]),
    runner_version: top["runner_version"],
    scope_id: top["scope_id"],
    snapshot_digest: top["snapshot_digest"],
    target: exactRecord(top["target"], ["host", "path", "port", "scheme"]),
    test_class: top["test_class"],
    version: top["version"],
  };
}

function exactRecord(
  value: unknown,
  expectedKeys: readonly string[],
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype
  )
    throw new SecurityError("ACTIVE_TEST_PLAN_SCHEMA_INVALID");
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string") ||
    !expectedKeys.every((key) => keys.includes(key))
  )
    throw new SecurityError("ACTIVE_TEST_PLAN_SCHEMA_INVALID");
  const result: Record<string, unknown> = {};
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new SecurityError("ACTIVE_TEST_PLAN_SCHEMA_INVALID");
    result[key] = descriptor.value;
  }
  return result;
}

function deepFreezePlan(plan: ActiveTestPlanV1): ActiveTestPlanV1 {
  return Object.freeze({
    ...plan,
    target: Object.freeze({ ...plan.target }),
    request: Object.freeze({ ...plan.request }),
    budget: Object.freeze({ ...plan.budget }),
    confirmations: Object.freeze({ ...plan.confirmations }),
  });
}

function expectedRequestBinding(testClass: ActiveTestPlanV1["test_class"]): {
  readonly method: ActiveTestPlanV1["request"]["method"];
  readonly headerProfile: ActiveTestPlanV1["request"]["header_profile"];
} {
  if (testClass === "cors_preflight")
    return { method: "OPTIONS", headerProfile: "cors_probe_v1" };
  if (testClass === "http_headers")
    return { method: "HEAD", headerProfile: "metadata_v1" };
  return { method: "GET", headerProfile: "metadata_v1" };
}

function canonicalTimestamp(value: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value)
    throw new SecurityError("ACTIVE_TEST_PLAN_TIME_INVALID");
  return value;
}
