import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parseDocument } from "yaml";
import { sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import type {
  HackerOneProgram,
  HackerOneScopeExclusion,
  HackerOneStructuredScope,
} from "./types.js";

const MAX_IMPORT_BYTES = 1_048_576;

interface ManualProgram {
  readonly hackerOneId: string;
  readonly handle: string;
  readonly name: string;
  readonly currency: string;
  readonly policy: string;
  readonly submissionState: string;
  readonly programState: string;
  readonly offersBounties: boolean;
  readonly openScope: boolean;
  readonly goldStandardSafeHarbor: boolean;
  readonly bookmarked: boolean;
  readonly ownReportCount: number;
  readonly ownValidReportCount: number;
  readonly startedAcceptingAt: string | null;
  readonly createdAt: string | null;
  readonly updatedAt: string | null;
}

interface ManualScope {
  readonly id: string;
  readonly assetType: string;
  readonly assetIdentifier: string;
  readonly eligibleForSubmission: boolean;
  readonly eligibleForBounty: boolean;
  readonly instruction: string;
  readonly maximumSeverity: string | null;
  readonly createdAt: string | null;
  readonly updatedAt: string | null;
  readonly confidentialityRequirement: string | null;
  readonly integrityRequirement: string | null;
  readonly availabilityRequirement: string | null;
}

interface ManualImportValue {
  readonly version: 1;
  readonly program: ManualProgram;
  readonly structuredScopes: readonly ManualScope[];
  readonly scopeExclusions: readonly HackerOneScopeExclusion[];
}

export interface ParsedHackerOneManualImport {
  readonly program: HackerOneProgram;
  readonly structuredScopes: readonly HackerOneStructuredScope[];
  readonly scopeExclusions: readonly HackerOneScopeExclusion[];
  readonly importedAt: string;
}

const text = (maximum: number, minimum = 0) => ({
  type: "string",
  minLength: minimum,
  maxLength: maximum,
  pattern: "^[^\\u0000]*$",
});
const timestamp = {
  anyOf: [
    { type: "string", format: "date-time", maxLength: 64 },
    { type: "null" },
  ],
};
const programProperties = {
  hackerOneId: text(128, 1),
  handle: { type: "string", pattern: "^[A-Za-z0-9_-]{1,128}$" },
  name: text(512, 1),
  currency: text(16, 1),
  policy: text(262_144),
  submissionState: text(128, 1),
  programState: text(128, 1),
  offersBounties: { type: "boolean" },
  openScope: { type: "boolean" },
  goldStandardSafeHarbor: { type: "boolean" },
  bookmarked: { type: "boolean" },
  ownReportCount: { type: "integer", minimum: 0 },
  ownValidReportCount: { type: "integer", minimum: 0 },
  startedAcceptingAt: timestamp,
  createdAt: timestamp,
  updatedAt: timestamp,
} as const;
const programRequired = Object.keys(programProperties);
const scopeProperties = {
  id: text(128, 1),
  assetType: text(128, 1),
  assetIdentifier: text(4_096, 1),
  eligibleForSubmission: { type: "boolean" },
  eligibleForBounty: { type: "boolean" },
  instruction: text(65_536),
  maximumSeverity: { anyOf: [text(64, 1), { type: "null" }] },
  createdAt: timestamp,
  updatedAt: timestamp,
  confidentialityRequirement: {
    anyOf: [text(64, 1), { type: "null" }],
  },
  integrityRequirement: { anyOf: [text(64, 1), { type: "null" }] },
  availabilityRequirement: { anyOf: [text(64, 1), { type: "null" }] },
} as const;
const exclusionProperties = {
  id: text(128, 1),
  category: text(256, 1),
  details: text(65_536),
  createdAt: timestamp,
  updatedAt: timestamp,
} as const;

const manualImportSchema = {
  type: "object",
  additionalProperties: false,
  required: ["program", "scopeExclusions", "structuredScopes", "version"],
  properties: {
    version: { const: 1 },
    program: {
      type: "object",
      additionalProperties: false,
      required: programRequired,
      properties: programProperties,
    },
    structuredScopes: {
      type: "array",
      maxItems: 2_000,
      items: {
        type: "object",
        additionalProperties: false,
        required: Object.keys(scopeProperties),
        properties: scopeProperties,
      },
    },
    scopeExclusions: {
      type: "array",
      maxItems: 2_000,
      items: {
        type: "object",
        additionalProperties: false,
        required: Object.keys(exclusionProperties),
        properties: exclusionProperties,
      },
    },
  },
} as const;

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validateManualImport = ajv.compile<ManualImportValue>(manualImportSchema);

export function parseHackerOneManualImport(
  source: string,
  importedAt: string,
): ParsedHackerOneManualImport {
  const bytes = new TextEncoder().encode(source);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_IMPORT_BYTES) {
    bytes.fill(0);
    throw new SecurityError("HACKERONE_MANUAL_IMPORT_SIZE_INVALID");
  }
  bytes.fill(0);
  assertUnambiguousJson(source);
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new SecurityError("HACKERONE_MANUAL_IMPORT_JSON_INVALID");
  }
  if (!validateManualImport(value))
    throw new SecurityError("HACKERONE_MANUAL_IMPORT_SCHEMA_INVALID");
  const at = normalizeTimestamp(importedAt);
  const program = Object.freeze({
    ...value.program,
    startedAcceptingAt: normalizeOptionalTimestamp(
      value.program.startedAcceptingAt,
    ),
    createdAt: normalizeOptionalTimestamp(value.program.createdAt),
    updatedAt: normalizeOptionalTimestamp(value.program.updatedAt),
    synchronizedAt: at,
    source: "manual_unverified" as const,
  });
  const structuredScopes = Object.freeze(
    value.structuredScopes.map((scope) =>
      Object.freeze({
        ...scope,
        assetIdentifierDigest: sha256(scope.assetIdentifier),
        createdAt: normalizeOptionalTimestamp(scope.createdAt),
        updatedAt: normalizeOptionalTimestamp(scope.updatedAt),
      }),
    ),
  );
  const scopeExclusions = Object.freeze(
    value.scopeExclusions.map((exclusion) =>
      Object.freeze({
        ...exclusion,
        createdAt: normalizeOptionalTimestamp(exclusion.createdAt),
        updatedAt: normalizeOptionalTimestamp(exclusion.updatedAt),
      }),
    ),
  );
  assertUniqueIds(structuredScopes, "HACKERONE_MANUAL_SCOPE_DUPLICATE");
  assertUniqueIds(scopeExclusions, "HACKERONE_MANUAL_EXCLUSION_DUPLICATE");
  return Object.freeze({
    program,
    structuredScopes,
    scopeExclusions,
    importedAt: at,
  });
}

function assertUnambiguousJson(source: string): void {
  const document = parseDocument(source, {
    merge: false,
    uniqueKeys: true,
    version: "1.2",
  });
  if (
    source.startsWith("\uFEFF") ||
    document.errors.length > 0 ||
    document.warnings.length > 0
  )
    throw new SecurityError("HACKERONE_MANUAL_IMPORT_JSON_INVALID");
}

function assertUniqueIds(
  records: readonly { readonly id: string }[],
  code: string,
): void {
  const ids = new Set(records.map((record) => record.id));
  if (ids.size !== records.length) throw new SecurityError(code);
}

function normalizeTimestamp(value: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds))
    throw new SecurityError("HACKERONE_MANUAL_IMPORT_TIMESTAMP_INVALID");
  return new Date(milliseconds).toISOString();
}

function normalizeOptionalTimestamp(value: string | null): string | null {
  return value === null ? null : normalizeTimestamp(value);
}
