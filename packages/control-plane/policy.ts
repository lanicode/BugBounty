import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import { assertNoSensitiveMaterial } from "./sensitive.js";

export interface PolicyRequestLimits {
  readonly requestsPerMinute: number;
  readonly maxRequestsTotal: number;
  readonly maxConcurrency: number;
}

export interface PolicyInput {
  readonly text: string;
  readonly allowedAssets: readonly string[];
  readonly excludedAssets: readonly string[];
  readonly requestLimits: PolicyRequestLimits;
  readonly allowedTestClasses: readonly string[];
  readonly forbiddenTestClasses: readonly string[];
  readonly rules: readonly string[];
  readonly unclearRules: readonly string[];
}

export interface NormalizedPolicyDocument extends PolicyInput {
  readonly version: 1;
}

export interface NormalizedPolicy extends NormalizedPolicyDocument {
  readonly canonical: string;
  readonly policyHash: string;
}

export type RequestLimitField = keyof PolicyRequestLimits;

export interface RequestLimitChange {
  readonly field: RequestLimitField;
  readonly before: number;
  readonly after: number;
}

export interface StringSetDiff {
  readonly added: readonly string[];
  readonly removed: readonly string[];
}

export interface UnclearRulesDiff extends StringSetDiff {
  readonly current: readonly string[];
}

export interface PolicyDiff {
  readonly changed: boolean;
  readonly beforeHash: string;
  readonly afterHash: string;
  readonly textChanged: boolean;
  readonly addedAssets: readonly string[];
  readonly removedAssets: readonly string[];
  readonly newlyExcludedAssets: readonly string[];
  readonly noLongerExcludedAssets: readonly string[];
  readonly changedRequestLimits: readonly RequestLimitChange[];
  readonly newlyAllowedTestClasses: readonly string[];
  readonly noLongerAllowedTestClasses: readonly string[];
  readonly newlyForbiddenTestClasses: readonly string[];
  readonly noLongerForbiddenTestClasses: readonly string[];
  readonly changedRules: StringSetDiff;
  readonly unclearRules: UnclearRulesDiff;
}

const MAX_POLICY_TEXT_LENGTH = 1_000_000;
const MAX_LIST_ITEMS = 2_000;
const MAX_LIST_ITEM_LENGTH = 4_096;
const MAX_REQUESTS_PER_MINUTE = 1_000_000;
const MAX_REQUESTS_TOTAL = 10_000_000;
const MAX_CONCURRENCY = 1_000;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;

const INPUT_KEYS = new Set([
  "allowedAssets",
  "allowedTestClasses",
  "excludedAssets",
  "forbiddenTestClasses",
  "requestLimits",
  "rules",
  "text",
  "unclearRules",
]);

const NORMALIZED_KEYS = new Set([
  ...INPUT_KEYS,
  "canonical",
  "policyHash",
  "version",
]);

const REQUEST_LIMIT_KEYS = new Set([
  "maxConcurrency",
  "maxRequestsTotal",
  "requestsPerMinute",
]);

const REQUEST_LIMIT_FIELDS: readonly RequestLimitField[] = Object.freeze([
  "maxConcurrency",
  "maxRequestsTotal",
  "requestsPerMinute",
]);

export function normalizePolicy(input: PolicyInput): NormalizedPolicy {
  assertPlainObject(input, "POLICY_INPUT_INVALID");
  assertExactKeys(input, INPUT_KEYS, "POLICY_INPUT_UNKNOWN_FIELD");

  if (typeof input.text !== "string")
    throw new SecurityError("POLICY_TEXT_INVALID");
  const text = input.text.trim();
  if (
    text.length === 0 ||
    text.length > MAX_POLICY_TEXT_LENGTH ||
    text.includes("\u0000")
  )
    throw new SecurityError("POLICY_TEXT_INVALID");

  const allowedAssets = normalizeList(input.allowedAssets);
  const excludedAssets = normalizeList(input.excludedAssets);
  const allowedTestClasses = normalizeList(input.allowedTestClasses);
  const forbiddenTestClasses = normalizeList(input.forbiddenTestClasses);
  const rules = normalizeList(input.rules);
  const unclearRules = normalizeList(input.unclearRules);
  assertNoSensitiveMaterial(
    [
      text,
      ...allowedAssets,
      ...excludedAssets,
      ...allowedTestClasses,
      ...forbiddenTestClasses,
      ...rules,
      ...unclearRules,
    ],
    "POLICY_SENSITIVE_MATERIAL",
  );
  const requestLimits = normalizeRequestLimits(input.requestLimits);

  assertDisjoint(allowedAssets, excludedAssets, "POLICY_ASSET_OVERLAP");
  assertDisjoint(
    allowedTestClasses,
    forbiddenTestClasses,
    "POLICY_TEST_CLASS_OVERLAP",
  );

  const document: NormalizedPolicyDocument = Object.freeze({
    version: 1,
    text,
    allowedAssets,
    excludedAssets,
    requestLimits,
    allowedTestClasses,
    forbiddenTestClasses,
    rules,
    unclearRules,
  });
  const canonical = canonicalJson(document);
  return Object.freeze({
    ...document,
    canonical,
    policyHash: sha256(canonical),
  });
}

export function diffPolicies(
  suppliedBefore: NormalizedPolicy,
  suppliedAfter: NormalizedPolicy,
): PolicyDiff {
  const before = verifyNormalizedPolicy(suppliedBefore);
  const after = verifyNormalizedPolicy(suppliedAfter);
  const changedRequestLimits = Object.freeze(
    REQUEST_LIMIT_FIELDS.flatMap((field) =>
      before.requestLimits[field] === after.requestLimits[field]
        ? []
        : [
            Object.freeze({
              field,
              before: before.requestLimits[field],
              after: after.requestLimits[field],
            }),
          ],
    ),
  );
  const changedRules = stringSetDiff(before.rules, after.rules);
  const unclearRuleChanges = stringSetDiff(
    before.unclearRules,
    after.unclearRules,
  );
  const unclearRules: UnclearRulesDiff = Object.freeze({
    ...unclearRuleChanges,
    current: after.unclearRules,
  });

  return Object.freeze({
    changed: before.policyHash !== after.policyHash,
    beforeHash: before.policyHash,
    afterHash: after.policyHash,
    textChanged: before.text !== after.text,
    addedAssets: difference(after.allowedAssets, before.allowedAssets),
    removedAssets: difference(before.allowedAssets, after.allowedAssets),
    newlyExcludedAssets: difference(
      after.excludedAssets,
      before.excludedAssets,
    ),
    noLongerExcludedAssets: difference(
      before.excludedAssets,
      after.excludedAssets,
    ),
    changedRequestLimits,
    newlyAllowedTestClasses: difference(
      after.allowedTestClasses,
      before.allowedTestClasses,
    ),
    noLongerAllowedTestClasses: difference(
      before.allowedTestClasses,
      after.allowedTestClasses,
    ),
    newlyForbiddenTestClasses: difference(
      after.forbiddenTestClasses,
      before.forbiddenTestClasses,
    ),
    noLongerForbiddenTestClasses: difference(
      before.forbiddenTestClasses,
      after.forbiddenTestClasses,
    ),
    changedRules,
    unclearRules,
  });
}

function verifyNormalizedPolicy(value: NormalizedPolicy): NormalizedPolicy {
  assertPlainObject(value, "POLICY_INTEGRITY_INVALID");
  assertExactKeys(value, NORMALIZED_KEYS, "POLICY_INTEGRITY_INVALID");
  const checked = normalizePolicy({
    text: value.text,
    allowedAssets: value.allowedAssets,
    excludedAssets: value.excludedAssets,
    requestLimits: value.requestLimits,
    allowedTestClasses: value.allowedTestClasses,
    forbiddenTestClasses: value.forbiddenTestClasses,
    rules: value.rules,
    unclearRules: value.unclearRules,
  });
  if (
    checked.canonical !== value.canonical ||
    checked.policyHash !== value.policyHash
  )
    throw new SecurityError("POLICY_INTEGRITY_INVALID");
  return checked;
}

function normalizeList(values: readonly string[]): readonly string[] {
  if (!Array.isArray(values) || values.length > MAX_LIST_ITEMS)
    throw new SecurityError("POLICY_LIST_INVALID");
  const normalized = new Set<string>();
  for (const value of values) {
    if (typeof value !== "string")
      throw new SecurityError("POLICY_LIST_ITEM_INVALID");
    const item = value.trim();
    if (
      item.length === 0 ||
      item.length > MAX_LIST_ITEM_LENGTH ||
      CONTROL_CHARACTER.test(item)
    )
      throw new SecurityError("POLICY_LIST_ITEM_INVALID");
    normalized.add(item);
  }
  return Object.freeze([...normalized].sort(compareAscii));
}

function normalizeRequestLimits(
  value: PolicyRequestLimits,
): PolicyRequestLimits {
  assertPlainObject(value, "POLICY_REQUEST_LIMITS_INVALID");
  assertExactKeys(value, REQUEST_LIMIT_KEYS, "POLICY_REQUEST_LIMITS_INVALID");
  const requestsPerMinute = requireBoundedInteger(
    value.requestsPerMinute,
    MAX_REQUESTS_PER_MINUTE,
  );
  const maxRequestsTotal = requireBoundedInteger(
    value.maxRequestsTotal,
    MAX_REQUESTS_TOTAL,
  );
  const maxConcurrency = requireBoundedInteger(
    value.maxConcurrency,
    MAX_CONCURRENCY,
  );
  if (maxConcurrency > maxRequestsTotal)
    throw new SecurityError("POLICY_REQUEST_LIMITS_INVALID");
  return Object.freeze({
    requestsPerMinute,
    maxRequestsTotal,
    maxConcurrency,
  });
}

function requireBoundedInteger(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum)
    throw new SecurityError("POLICY_REQUEST_LIMITS_INVALID");
  return value;
}

function stringSetDiff(
  before: readonly string[],
  after: readonly string[],
): StringSetDiff {
  return Object.freeze({
    added: difference(after, before),
    removed: difference(before, after),
  });
}

function difference(
  candidates: readonly string[],
  existing: readonly string[],
): readonly string[] {
  const existingValues = new Set(existing);
  return Object.freeze(
    candidates.filter((candidate) => !existingValues.has(candidate)),
  );
}

function assertDisjoint(
  left: readonly string[],
  right: readonly string[],
  code: string,
): void {
  const rightValues = new Set(right);
  if (left.some((value) => rightValues.has(value)))
    throw new SecurityError(code);
}

function assertPlainObject(
  value: unknown,
  code: string,
): asserts value is object {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new SecurityError(code);
}

function assertExactKeys(
  value: object,
  expected: ReadonlySet<string>,
  code: string,
): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key)))
    throw new SecurityError(code);
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
