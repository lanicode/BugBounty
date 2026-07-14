import { createHash } from "node:crypto";
import { types } from "node:util";
import {
  LOCAL_JOURNEY_CATALOG_ID,
  journeyCapabilitiesFor,
  journeyPlanFor,
} from "../../../packages/local-journey-catalog/index.js";
import type {
  JourneyReplayProfile,
  JourneyRole,
  JourneyStep,
} from "../../../packages/local-journey-catalog/index.js";

export {
  JOURNEY_ROLES,
  LOCAL_JOURNEY_CATALOG,
  LOCAL_JOURNEY_CATALOG_DIGEST_SHA256,
  LOCAL_JOURNEY_CATALOG_ID,
  LOCAL_JOURNEY_REPLAY_PROFILES,
  LOCAL_JOURNEY_ROLE_PLANS,
  journeyCapabilitiesFor,
  journeyCatalog,
  journeyPlanFor,
} from "../../../packages/local-journey-catalog/index.js";
export type {
  JourneyCapability,
  JourneyPath,
  JourneyReplayProfile,
  JourneyRole,
  JourneyState,
  JourneyStep,
  LocalJourneyCatalog,
  LocalJourneyCatalogId,
} from "../../../packages/local-journey-catalog/index.js";

export type LoopbackOrigin = `http://127.0.0.1:${number}`;

export type JourneyEvidenceStatus = "blocked" | "completed";
export type JourneyStepOutcome = "http_error" | "success";

export interface JourneyStepEvidence {
  readonly outcome: JourneyStepOutcome;
  readonly recordCount: number;
  readonly redactedScreenshotByteLength: number;
  readonly redactedScreenshotDigestSha256: string;
  readonly responseDigestSha256: string;
  readonly statusCode: number;
}

export interface JourneyEvidenceInput {
  readonly role: JourneyRole;
  readonly status: JourneyEvidenceStatus;
  readonly blockedRequestCount: number;
  readonly steps: readonly JourneyStepEvidence[];
}

export interface JourneyEvidence {
  readonly version: 1;
  readonly role: JourneyRole;
  readonly status: JourneyEvidenceStatus;
  readonly plannedStepCount: number;
  readonly observedStepCount: number;
  readonly successfulStepCount: number;
  readonly blockedRequestCount: number;
  readonly statusCodes: readonly number[];
  readonly recordCounts: readonly number[];
  readonly redactedScreenshotByteLengths: readonly number[];
  readonly redactedScreenshotDigestsSha256: readonly string[];
  readonly planDigestSha256: string;
  readonly evidenceDigestSha256: string;
}

const CANONICAL_LOOPBACK_ORIGIN = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{3,4})$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_JOURNEY_STEPS = 8;

export function journeyPlan(role: unknown): readonly JourneyStep[] {
  return journeyPlanFor(LOCAL_JOURNEY_CATALOG_ID, role);
}

export function capabilitiesFor(role: unknown): JourneyReplayProfile {
  return journeyCapabilitiesFor(LOCAL_JOURNEY_CATALOG_ID, role);
}

export function assertLoopbackOrigin(origin: unknown): LoopbackOrigin {
  if (typeof origin !== "string")
    throw new Error("LOCAL_JOURNEY_ORIGIN_INVALID");
  const match = CANONICAL_LOOPBACK_ORIGIN.exec(origin);
  const portText = match?.[1];
  if (portText === undefined) throw new Error("LOCAL_JOURNEY_ORIGIN_INVALID");
  const port = Number(portText);
  if (
    !Number.isSafeInteger(port) ||
    port < 1_024 ||
    port > 65_535 ||
    String(port) !== portText
  )
    throw new Error("LOCAL_JOURNEY_ORIGIN_INVALID");
  return origin as LoopbackOrigin;
}

export function isAllowedJourneyRequest(
  role: unknown,
  currentIndex: unknown,
  rawUrl: unknown,
  method: unknown,
  expectedOrigin: unknown,
): boolean {
  try {
    const plan = journeyPlan(role);
    const origin = assertLoopbackOrigin(expectedOrigin);
    if (
      typeof currentIndex !== "number" ||
      !Number.isSafeInteger(currentIndex) ||
      currentIndex < 0 ||
      typeof rawUrl !== "string" ||
      method !== "GET"
    )
      return false;
    const step = plan[currentIndex];
    return step !== undefined && rawUrl === `${origin}${step.path}`;
  } catch {
    return false;
  }
}

export function finalizeJourneyEvidence(input: unknown): JourneyEvidence {
  const record = cloneExactDataRecord(input, [
    "role",
    "status",
    "blockedRequestCount",
    "steps",
  ]);
  const role = record["role"];
  const status = record["status"];
  const blockedRequestCount = record["blockedRequestCount"];
  if (!isJourneyRole(role)) throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");
  if (status !== "blocked" && status !== "completed")
    throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");
  if (
    typeof blockedRequestCount !== "number" ||
    !Number.isSafeInteger(blockedRequestCount) ||
    (blockedRequestCount !== 0 && blockedRequestCount !== 1)
  )
    throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");

  const rawSteps = cloneExactDataArray(record["steps"]);
  const steps = rawSteps.map(normalizeStepEvidence);
  const rolePlan = journeyPlan(role);
  const plannedStepCount = rolePlan.length;
  if (steps.length > plannedStepCount)
    throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");

  const errorIndexes = steps.flatMap((step, index) =>
    step.outcome === "http_error" ? [index] : [],
  );
  const completedIsValid =
    status === "completed" &&
    blockedRequestCount === 0 &&
    steps.length === plannedStepCount &&
    errorIndexes.length === 0;
  const egressBlockedIsValid =
    status === "blocked" &&
    blockedRequestCount === 1 &&
    steps.length < plannedStepCount &&
    errorIndexes.length === 0;
  const httpBlockedIsValid =
    status === "blocked" &&
    blockedRequestCount === 0 &&
    steps.length > 0 &&
    errorIndexes.length === 1 &&
    errorIndexes[0] === steps.length - 1;
  if (!completedIsValid && !egressBlockedIsValid && !httpBlockedIsValid)
    throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");

  const statusCodes = Object.freeze(steps.map((step) => step.statusCode));
  const recordCounts = Object.freeze(steps.map((step) => step.recordCount));
  const redactedScreenshotByteLengths = Object.freeze(
    steps.map((step) => step.redactedScreenshotByteLength),
  );
  const redactedScreenshotDigestsSha256 = Object.freeze(
    steps.map((step) => step.redactedScreenshotDigestSha256),
  );
  const planDigestSha256 = digest([
    role,
    ...rolePlan.map((step) => [
      step.index,
      step.method,
      step.path,
      step.capability,
      step.fromState,
      step.successState,
    ]),
  ]);
  const evidenceDigestSha256 = digest([
    1,
    role,
    status,
    plannedStepCount,
    steps.length,
    blockedRequestCount,
    ...steps.map((step) => [
      step.outcome,
      step.statusCode,
      step.recordCount,
      step.responseDigestSha256,
      step.redactedScreenshotDigestSha256,
      step.redactedScreenshotByteLength,
    ]),
    planDigestSha256,
  ]);

  return Object.freeze({
    version: 1,
    role,
    status,
    plannedStepCount,
    observedStepCount: steps.length,
    successfulStepCount: steps.filter(({ outcome }) => outcome === "success")
      .length,
    blockedRequestCount,
    statusCodes,
    recordCounts,
    redactedScreenshotByteLengths,
    redactedScreenshotDigestsSha256,
    planDigestSha256,
    evidenceDigestSha256,
  });
}

function normalizeStepEvidence(value: unknown): JourneyStepEvidence {
  const record = cloneExactDataRecord(value, [
    "outcome",
    "recordCount",
    "redactedScreenshotByteLength",
    "redactedScreenshotDigestSha256",
    "responseDigestSha256",
    "statusCode",
  ]);
  const outcome = record["outcome"];
  const recordCount = record["recordCount"];
  const redactedScreenshotByteLength = record["redactedScreenshotByteLength"];
  const redactedScreenshotDigestSha256 =
    record["redactedScreenshotDigestSha256"];
  const responseDigestSha256 = record["responseDigestSha256"];
  const statusCode = record["statusCode"];
  if (
    (outcome !== "success" && outcome !== "http_error") ||
    typeof recordCount !== "number" ||
    !Number.isSafeInteger(recordCount) ||
    recordCount < 0 ||
    recordCount > 1_000 ||
    typeof redactedScreenshotByteLength !== "number" ||
    !Number.isSafeInteger(redactedScreenshotByteLength) ||
    redactedScreenshotByteLength < 1 ||
    redactedScreenshotByteLength > 1_048_576 ||
    typeof redactedScreenshotDigestSha256 !== "string" ||
    !SHA256.test(redactedScreenshotDigestSha256) ||
    typeof responseDigestSha256 !== "string" ||
    !SHA256.test(responseDigestSha256) ||
    typeof statusCode !== "number" ||
    !Number.isSafeInteger(statusCode) ||
    statusCode < 100 ||
    statusCode > 599 ||
    (outcome === "success" && (statusCode < 200 || statusCode > 299)) ||
    (outcome === "http_error" && statusCode < 300)
  )
    throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");
  return Object.freeze({
    outcome,
    recordCount,
    redactedScreenshotByteLength,
    redactedScreenshotDigestSha256,
    responseDigestSha256,
    statusCode,
  });
}

function cloneExactDataRecord(
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
    throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string") ||
    !expectedKeys.every((key) => keys.includes(key))
  )
    throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");
  const entries: [string, unknown][] = [];
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true ||
      descriptor.configurable !== true ||
      descriptor.writable !== true
    )
      throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");
    entries.push([key, descriptor.value]);
  }
  return Object.fromEntries(entries);
}

function cloneExactDataArray(value: unknown): readonly unknown[] {
  if (
    !Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Array.prototype
  )
    throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    typeof lengthDescriptor.value !== "number" ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value < 0 ||
    lengthDescriptor.value > MAX_JOURNEY_STEPS ||
    lengthDescriptor.enumerable !== false ||
    lengthDescriptor.configurable !== false ||
    lengthDescriptor.writable !== true
  )
    throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");
  const expectedKeys = Array.from(
    { length: lengthDescriptor.value },
    (_, index) => String(index),
  );
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length + 1 ||
    !keys.includes("length") ||
    !expectedKeys.every((key) => keys.includes(key))
  )
    throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");
  return expectedKeys.map((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true ||
      descriptor.configurable !== true ||
      descriptor.writable !== true
    )
      throw new Error("LOCAL_JOURNEY_EVIDENCE_INVALID");
    const descriptorValue: unknown = descriptor.value;
    return descriptorValue;
  });
}

function isJourneyRole(value: unknown): value is JourneyRole {
  try {
    journeyPlan(value);
    return true;
  } catch {
    return false;
  }
}

function digest(value: unknown): string {
  return createHash("sha256")
    .update(JSON.stringify(value), "utf8")
    .digest("hex");
}
