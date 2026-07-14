import { createHash } from "node:crypto";
import type { JourneyPath } from "./journey-model.js";

const MAX_RESPONSE_BYTES = 65_536;
const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_TEXT = /^[^\u0000-\u001f\u007f]{1,256}$/u;
const SAFE_REFERENCE = /^[a-z][a-z0-9_-]{2,127}$/u;
const SAFE_RULE = /^[a-z][a-z0-9_.:-]{0,63}$/u;

export interface ValidatedDemoResponse {
  readonly responseDigestSha256: string;
  readonly recordCount: number;
  readonly simulationMode: boolean;
  readonly externalIntegrationsDisabled: boolean;
  readonly revision: number | null;
}

export function validateDemoResponse(
  path: JourneyPath,
  bytes: Uint8Array,
): ValidatedDemoResponse {
  if (bytes.byteLength < 2 || bytes.byteLength > MAX_RESPONSE_BYTES)
    throw new Error("LOCAL_JOURNEY_RESPONSE_SIZE_INVALID");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("LOCAL_JOURNEY_RESPONSE_UTF8_INVALID");
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new Error("LOCAL_JOURNEY_RESPONSE_JSON_INVALID");
  }
  if (JSON.stringify(value) !== text)
    throw new Error("LOCAL_JOURNEY_RESPONSE_NOT_CANONICAL");

  const facts = validateRouteValue(path, value);
  return Object.freeze({
    responseDigestSha256: createHash("sha256").update(bytes).digest("hex"),
    ...facts,
  });
}

function validateRouteValue(
  path: JourneyPath,
  value: unknown,
): Omit<ValidatedDemoResponse, "responseDigestSha256"> {
  switch (path) {
    case "/": {
      const record = exactRecord(value, [
        "service",
        "mode",
        "externalIntegrationsEnabled",
        "routes",
      ]);
      if (
        record["service"] !== "bug-bounty-copilot-demo-saas" ||
        record["mode"] !== "simulation" ||
        record["externalIntegrationsEnabled"] !== false
      )
        throw new Error("LOCAL_JOURNEY_RESPONSE_SAFETY_INVALID");
      const routes = exactArray(record["routes"]);
      const expectedRoutes = [
        "/health",
        "/api/v1/state",
        "/api/v1/organization",
        "/api/v1/projects",
        "/api/v1/documents",
        "/api/v1/invitations",
        "/api/v1/test-objects",
        "/api/v1/policy",
      ];
      if (
        routes.length !== expectedRoutes.length ||
        routes.some((route, index) => route !== expectedRoutes[index])
      )
        throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
      return safetyFacts(routes.length, true, true, null);
    }
    case "/api/v1/organization": {
      const organization = validateOrganization(value);
      return safetyFacts(organization.identityCount, false, false, null);
    }
    case "/api/v1/projects": {
      const record = exactRecord(value, ["projects"]);
      const projects = exactArray(record["projects"]);
      projects.forEach(validateProject);
      return safetyFacts(projects.length, false, false, null);
    }
    case "/api/v1/documents": {
      const record = exactRecord(value, ["documents"]);
      const documents = exactArray(record["documents"]);
      documents.forEach(validateDocument);
      return safetyFacts(documents.length, false, false, null);
    }
    case "/api/v1/invitations": {
      const record = exactRecord(value, ["invitations"]);
      const invitations = exactArray(record["invitations"]);
      invitations.forEach(validateInvitation);
      return safetyFacts(invitations.length, false, false, null);
    }
    case "/api/v1/test-objects": {
      const record = exactRecord(value, ["testObjects"]);
      const testObjects = exactArray(record["testObjects"]);
      testObjects.forEach(validateTestObject);
      return safetyFacts(testObjects.length, false, false, null);
    }
    case "/api/v1/policy": {
      const record = exactRecord(value, [
        "currentPolicy",
        "policyVersions",
        "lastPolicyDrift",
      ]);
      const current = validatePolicyVersion(record["currentPolicy"]);
      const versions = exactArray(record["policyVersions"]);
      versions.forEach(validatePolicyVersion);
      validatePolicyDrift(record["lastPolicyDrift"]);
      if (
        versions.length < 1 ||
        versions.length > 1_000 ||
        current.version !== versions.length
      )
        throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
      return safetyFacts(versions.length, false, false, null);
    }
    case "/api/v1/state": {
      const snapshot = validateSnapshot(value);
      return safetyFacts(snapshot.recordCount, true, true, snapshot.revision);
    }
  }
}

function validateSnapshot(value: unknown): {
  readonly mode: "simulation";
  readonly externalIntegrationsEnabled: false;
  readonly revision: number;
  readonly recordCount: number;
} {
  const record = exactRecord(value, [
    "mode",
    "externalIntegrationsEnabled",
    "revision",
    "organization",
    "projects",
    "documents",
    "invitations",
    "testObjects",
    "currentPolicy",
    "policyVersions",
    "lastPolicyDrift",
  ]);
  if (
    record["mode"] !== "simulation" ||
    record["externalIntegrationsEnabled"] !== false ||
    !isIntegerBetween(record["revision"], 1, Number.MAX_SAFE_INTEGER)
  )
    throw new Error("LOCAL_JOURNEY_RESPONSE_SAFETY_INVALID");
  validateOrganization(record["organization"]);
  const projects = exactArray(record["projects"]);
  projects.forEach(validateProject);
  const documents = exactArray(record["documents"]);
  documents.forEach(validateDocument);
  const invitations = exactArray(record["invitations"]);
  invitations.forEach(validateInvitation);
  const testObjects = exactArray(record["testObjects"]);
  testObjects.forEach(validateTestObject);
  const current = validatePolicyVersion(record["currentPolicy"]);
  const versions = exactArray(record["policyVersions"]);
  versions.forEach(validatePolicyVersion);
  validatePolicyDrift(record["lastPolicyDrift"]);
  if (versions.length !== current.version)
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  return {
    mode: "simulation",
    externalIntegrationsEnabled: false,
    revision: record["revision"],
    recordCount:
      projects.length +
      documents.length +
      invitations.length +
      testObjects.length +
      versions.length,
  };
}

function validateOrganization(value: unknown): {
  readonly identityCount: number;
} {
  const record = exactRecord(value, [
    "organizationRef",
    "displayName",
    "identities",
  ]);
  assertReference(record["organizationRef"]);
  assertText(record["displayName"]);
  const identities = exactArray(record["identities"]);
  identities.forEach((identity) => {
    const entry = exactRecord(identity, ["identityRef", "displayName", "role"]);
    assertReference(entry["identityRef"]);
    assertText(entry["displayName"]);
    if (
      entry["role"] !== "Owner" &&
      entry["role"] !== "Member" &&
      entry["role"] !== "External"
    )
      throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  });
  if (identities.length < 1 || identities.length > 1_000)
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  return { identityCount: identities.length };
}

function validateProject(value: unknown): void {
  const record = exactRecord(value, [
    "projectRef",
    "organizationRef",
    "displayName",
    "createdByRef",
    "createdAt",
  ]);
  assertReference(record["projectRef"]);
  assertReference(record["organizationRef"]);
  assertText(record["displayName"]);
  assertReference(record["createdByRef"]);
  assertTimestamp(record["createdAt"]);
}

function validateDocument(value: unknown): void {
  const record = exactRecord(value, [
    "documentRef",
    "projectRef",
    "title",
    "classification",
    "createdByRef",
    "createdAt",
  ]);
  assertReference(record["documentRef"]);
  assertReference(record["projectRef"]);
  assertText(record["title"]);
  if (
    record["classification"] !== "internal" &&
    record["classification"] !== "shared"
  )
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  assertReference(record["createdByRef"]);
  assertTimestamp(record["createdAt"]);
}

function validateInvitation(value: unknown): void {
  const record = exactRecord(value, [
    "invitationRef",
    "organizationRef",
    "inviteeRef",
    "role",
    "status",
    "createdByRef",
    "createdAt",
  ]);
  assertReference(record["invitationRef"]);
  assertReference(record["organizationRef"]);
  assertReference(record["inviteeRef"]);
  if (record["role"] !== "External" && record["role"] !== "Member")
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  if (record["status"] !== "pending")
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  assertReference(record["createdByRef"]);
  assertTimestamp(record["createdAt"]);
}

function validateTestObject(value: unknown): void {
  const record = exactRecord(value, [
    "objectRef",
    "projectRef",
    "controlledByRef",
    "canary",
    "status",
    "createdAt",
  ]);
  assertReference(record["objectRef"]);
  assertReference(record["projectRef"]);
  assertReference(record["controlledByRef"]);
  if (
    typeof record["canary"] !== "string" ||
    !/^canary-[A-Za-z0-9_-]{1,100}$/u.test(record["canary"])
  )
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  if (record["status"] !== "active")
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  assertTimestamp(record["createdAt"]);
}

function validatePolicyVersion(value: unknown): { readonly version: number } {
  const record = exactRecord(value, [
    "version",
    "contentHash",
    "effectiveAt",
    "rules",
  ]);
  if (!isIntegerBetween(record["version"], 1, 1_000))
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  if (
    typeof record["contentHash"] !== "string" ||
    !SHA256.test(record["contentHash"])
  )
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  assertTimestamp(record["effectiveAt"]);
  const rules = exactRecord(record["rules"], [
    "requestLimit",
    "allowedActions",
    "prohibitedTestClasses",
  ]);
  if (!isIntegerBetween(rules["requestLimit"], 1, 1_000))
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  validateRules(rules["allowedActions"]);
  validateRules(rules["prohibitedTestClasses"]);
  return { version: record["version"] };
}

function validatePolicyDrift(value: unknown): void {
  if (value === null) return;
  const record = exactRecord(value, [
    "previousVersion",
    "previousHash",
    "nextVersion",
    "nextHash",
    "changedFields",
    "detectedAt",
  ]);
  if (
    !isIntegerBetween(record["previousVersion"], 1, 1_000) ||
    !isIntegerBetween(record["nextVersion"], 2, 1_000) ||
    record["nextVersion"] !== record["previousVersion"] + 1 ||
    typeof record["previousHash"] !== "string" ||
    !SHA256.test(record["previousHash"]) ||
    typeof record["nextHash"] !== "string" ||
    !SHA256.test(record["nextHash"])
  )
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  const fields = exactArray(record["changedFields"]);
  if (
    fields.length < 1 ||
    fields.some(
      (field) =>
        field !== "allowedActions" &&
        field !== "prohibitedTestClasses" &&
        field !== "requestLimit",
    )
  )
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  assertTimestamp(record["detectedAt"]);
}

function validateRules(value: unknown): void {
  const rules = exactArray(value);
  if (
    rules.length > 100 ||
    rules.some((rule) => typeof rule !== "string" || !SAFE_RULE.test(rule)) ||
    new Set(rules).size !== rules.length
  )
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
}

function exactRecord(
  value: unknown,
  expectedKeys: readonly string[],
): Readonly<Record<string, unknown>> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  )
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  const keys = Object.keys(value);
  if (
    keys.length !== expectedKeys.length ||
    !expectedKeys.every((key) => keys.includes(key))
  )
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  return value as Readonly<Record<string, unknown>>;
}

function exactArray(value: unknown): readonly unknown[] {
  if (!Array.isArray(value) || value.length > 1_000)
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  return value;
}

function assertReference(value: unknown): asserts value is string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value))
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
}

function assertText(value: unknown): asserts value is string {
  if (typeof value !== "string" || !SAFE_TEXT.test(value))
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
}

function assertTimestamp(value: unknown): asserts value is string {
  if (typeof value !== "string")
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
  const time = new Date(value);
  if (!Number.isFinite(time.getTime()) || time.toISOString() !== value)
    throw new Error("LOCAL_JOURNEY_RESPONSE_SCHEMA_INVALID");
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

function safetyFacts(
  recordCount: number,
  simulationMode: boolean,
  externalIntegrationsDisabled: boolean,
  revision: number | null,
): Omit<ValidatedDemoResponse, "responseDigestSha256"> {
  return Object.freeze({
    recordCount,
    simulationMode,
    externalIntegrationsDisabled,
    revision,
  });
}
