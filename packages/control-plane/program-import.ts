import { isScalar, parseAllDocuments, visit, type Document } from "yaml";
import { SecurityError } from "../shared/errors.js";
import type { ProgramRecord } from "./types.js";
import { assertNoSensitiveMaterial } from "./sensitive.js";

export type ProgramImportFormat = "json" | "yaml";

export type ImportedProgram = Omit<
  ProgramRecord,
  | "createdAt"
  | "currentPolicyHash"
  | "currentPolicyVersion"
  | "ruleAcceptanceStatus"
>;

const MAX_SOURCE_BYTES = 1_048_576;
const MAX_ASSETS = 2_000;
const MAX_ASSET_LENGTH = 2_048;
const MAX_NAME_LENGTH = 256;
const MAX_DESCRIPTION_LENGTH = 32_768;
const MAX_NOTES_LENGTH = 32_768;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const ID = /^[A-Za-z0-9_-]{1,128}$/u;
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;

const IMPORT_KEYS = new Set([
  "allowed_assets",
  "automation_permission",
  "description",
  "excluded_assets",
  "id",
  "last_synchronized_at",
  "lifecycle",
  "name",
  "notes",
  "platform",
  "program_type",
  "program_url",
  "status",
]);

export function parseProgramImport(
  source: string | Uint8Array,
  format: ProgramImportFormat,
): ImportedProgram {
  assertImportFormat(format);
  const text = decodeSource(source);
  const value = parseSource(text, format);
  return normalizeProgramImport(value);
}

function parseSource(source: string, format: ProgramImportFormat): unknown {
  const documents = parseAllDocuments(source, {
    merge: false,
    uniqueKeys: true,
    version: "1.2",
  });
  if (documents.length !== 1)
    throw new SecurityError("PROGRAM_IMPORT_DOCUMENT_COUNT_INVALID");
  const document = documents[0];
  if (
    document === undefined ||
    document.errors.length > 0 ||
    document.warnings.length > 0
  )
    throw new SecurityError("PROGRAM_IMPORT_SYNTAX_INVALID");
  assertSafeYamlTree(document);
  if (format === "json") {
    try {
      return JSON.parse(source) as unknown;
    } catch {
      throw new SecurityError("PROGRAM_IMPORT_JSON_INVALID");
    }
  }
  try {
    const value: unknown = document.toJS({ maxAliasCount: 0 });
    return value;
  } catch {
    throw new SecurityError("PROGRAM_IMPORT_YAML_INVALID");
  }
}

function assertSafeYamlTree(document: Document.Parsed): void {
  const forbidden = new Set<"alias" | "merge" | "tag">();
  visit(document, {
    Alias: () => {
      forbidden.add("alias");
    },
    Node: (_key, node) => {
      if (node.tag !== undefined) forbidden.add("tag");
    },
    Pair: (_key, pair) => {
      if (isScalar(pair.key) && pair.key.value === "<<") forbidden.add("merge");
    },
  });
  if (forbidden.has("alias"))
    throw new SecurityError("PROGRAM_IMPORT_ALIAS_FORBIDDEN");
  if (forbidden.has("merge"))
    throw new SecurityError("PROGRAM_IMPORT_MERGE_FORBIDDEN");
  if (forbidden.has("tag"))
    throw new SecurityError("PROGRAM_IMPORT_TAG_FORBIDDEN");
}

function normalizeProgramImport(value: unknown): ImportedProgram {
  assertRecord(value, "PROGRAM_IMPORT_MODEL_INVALID");
  assertExactKeys(value, IMPORT_KEYS);

  const id = requiredString(value["id"], 128, false);
  if (!ID.test(id)) throw new SecurityError("PROGRAM_IMPORT_ID_INVALID");
  const name = requiredString(value["name"], MAX_NAME_LENGTH, false);
  const description = requiredString(
    value["description"],
    MAX_DESCRIPTION_LENGTH,
    true,
  );
  const notes = requiredString(value["notes"], MAX_NOTES_LENGTH, true);
  assertNoSensitiveMaterial(
    [name, description, notes],
    "PROGRAM_IMPORT_SENSITIVE_MATERIAL",
  );
  const platform = normalizePlatform(value["platform"]);
  const status = normalizeStatus(value["status"]);
  const programType = normalizeProgramType(value["program_type"]);
  const automationPermission = normalizeAutomationPermission(
    value["automation_permission"],
  );
  const lifecycle = normalizeLifecycle(value["lifecycle"]);
  const allowedAssets = normalizeAssets(value["allowed_assets"]);
  const excludedAssets = normalizeAssets(value["excluded_assets"]);
  assertNoSensitiveMaterial(
    [...allowedAssets, ...excludedAssets],
    "PROGRAM_IMPORT_SENSITIVE_MATERIAL",
  );
  assertNoOverlap(allowedAssets, excludedAssets);

  return Object.freeze({
    id,
    name,
    platform,
    status,
    description,
    programUrl: normalizeMetadataUrl(value["program_url"]),
    programType,
    allowedAssets,
    excludedAssets,
    lastSynchronizedAt: normalizeTimestamp(value["last_synchronized_at"]),
    automationPermission,
    notes,
    lifecycle,
  });
}

function decodeSource(source: string | Uint8Array): string {
  let decoded: string;
  if (typeof source === "string") {
    if (
      source.length > MAX_SOURCE_BYTES ||
      new TextEncoder().encode(source).byteLength > MAX_SOURCE_BYTES
    )
      throw new SecurityError("PROGRAM_IMPORT_SIZE_INVALID");
    decoded = source;
  } else if (source instanceof Uint8Array) {
    if (source.byteLength > MAX_SOURCE_BYTES)
      throw new SecurityError("PROGRAM_IMPORT_SIZE_INVALID");
    try {
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(source);
    } catch {
      throw new SecurityError("PROGRAM_IMPORT_UTF8_INVALID");
    }
  } else {
    throw new SecurityError("PROGRAM_IMPORT_SOURCE_INVALID");
  }
  return decoded.startsWith("\uFEFF") ? decoded.slice(1) : decoded;
}

function normalizeAssets(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length > MAX_ASSETS)
    throw new SecurityError("PROGRAM_IMPORT_ASSETS_INVALID");
  const assets = new Set<string>();
  for (const candidate of value) {
    if (typeof candidate !== "string")
      throw new SecurityError("PROGRAM_IMPORT_ASSET_INVALID");
    const asset = candidate.trim();
    if (
      asset.length === 0 ||
      asset.length > MAX_ASSET_LENGTH ||
      CONTROL_CHARACTER.test(asset)
    )
      throw new SecurityError("PROGRAM_IMPORT_ASSET_INVALID");
    assets.add(asset);
  }
  return Object.freeze([...assets].sort(compareAscii));
}

function normalizeMetadataUrl(value: unknown): string {
  const source = requiredString(value, 2_048, false);
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    throw new SecurityError("PROGRAM_IMPORT_URL_INVALID");
  }
  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.hostname.length === 0 ||
    url.username.length > 0 ||
    url.password.length > 0 ||
    url.search.length > 0 ||
    url.hash.length > 0
  )
    throw new SecurityError("PROGRAM_IMPORT_URL_INVALID");
  return source;
}

function normalizeTimestamp(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !RFC3339.test(value))
    throw new SecurityError("PROGRAM_IMPORT_TIMESTAMP_INVALID");
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp))
    throw new SecurityError("PROGRAM_IMPORT_TIMESTAMP_INVALID");
  return new Date(timestamp).toISOString();
}

function requiredString(
  value: unknown,
  maximumLength: number,
  allowEmpty: boolean,
): string {
  if (typeof value !== "string")
    throw new SecurityError("PROGRAM_IMPORT_STRING_INVALID");
  const normalized = value.trim();
  if (
    (!allowEmpty && normalized.length === 0) ||
    normalized.length > maximumLength ||
    normalized.includes("\u0000")
  )
    throw new SecurityError("PROGRAM_IMPORT_STRING_INVALID");
  return normalized;
}

function normalizePlatform(value: unknown): ImportedProgram["platform"] {
  if (value === "local_mock" || value === "manual") return value;
  throw new SecurityError("PROGRAM_IMPORT_ENUM_INVALID");
}

function normalizeStatus(value: unknown): ImportedProgram["status"] {
  if (value === "available" || value === "unavailable") return value;
  throw new SecurityError("PROGRAM_IMPORT_ENUM_INVALID");
}

function normalizeProgramType(value: unknown): ImportedProgram["programType"] {
  if (value === "private" || value === "public" || value === "simulation")
    return value;
  throw new SecurityError("PROGRAM_IMPORT_ENUM_INVALID");
}

function normalizeAutomationPermission(
  value: unknown,
): ImportedProgram["automationPermission"] {
  if (value === "allowed" || value === "forbidden" || value === "unclear")
    return value;
  throw new SecurityError("PROGRAM_IMPORT_ENUM_INVALID");
}

function normalizeLifecycle(value: unknown): ImportedProgram["lifecycle"] {
  if (
    value === "active" ||
    value === "archived" ||
    value === "inactive" ||
    value === "paused"
  )
    return value;
  throw new SecurityError("PROGRAM_IMPORT_ENUM_INVALID");
}

function assertImportFormat(
  value: unknown,
): asserts value is ProgramImportFormat {
  if (value !== "json" && value !== "yaml")
    throw new SecurityError("PROGRAM_IMPORT_FORMAT_INVALID");
}

function assertRecord(
  value: unknown,
  code: string,
): asserts value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new SecurityError(code);
}

function assertExactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: ReadonlySet<string>,
): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key)))
    throw new SecurityError("PROGRAM_IMPORT_UNKNOWN_FIELD");
}

function assertNoOverlap(
  allowed: readonly string[],
  excluded: readonly string[],
): void {
  const excludedSet = new Set(excluded);
  if (allowed.some((asset) => excludedSet.has(asset)))
    throw new SecurityError("PROGRAM_IMPORT_ASSET_OVERLAP");
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
