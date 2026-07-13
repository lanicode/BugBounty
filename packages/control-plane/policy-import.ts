import { isScalar, parseAllDocuments, visit, type Document } from "yaml";
import { SecurityError } from "../shared/errors.js";
import {
  normalizePolicy,
  type NormalizedPolicy,
  type PolicyInput,
  type PolicyRequestLimits,
} from "./policy.js";

export type PolicyImportFormat = "json" | "text" | "yaml";

const MAX_SOURCE_BYTES = 1_048_576;
const MAX_UNCLEAR_RULE_LENGTH = 4_096;
const TEXT_CHUNK_PREFIX_LENGTH = 13;
const POLICY_KEYS = new Set([
  "allowedAssets",
  "allowedTestClasses",
  "excludedAssets",
  "forbiddenTestClasses",
  "requestLimits",
  "rules",
  "text",
  "unclearRules",
]);
const REQUEST_LIMIT_KEYS = new Set([
  "maxConcurrency",
  "maxRequestsTotal",
  "requestsPerMinute",
]);

export function parsePolicyImport(
  source: string | Uint8Array,
  format: PolicyImportFormat,
): NormalizedPolicy {
  assertFormat(format);
  const text = decodeSource(source);
  if (format === "text") return normalizeTextPolicy(text);
  return normalizePolicy(policyInputFromUnknown(parseStructured(text, format)));
}

function normalizeTextPolicy(text: string): NormalizedPolicy {
  const trimmed = text.trim();
  return normalizePolicy({
    text: trimmed,
    allowedAssets: [],
    excludedAssets: [],
    requestLimits: {
      requestsPerMinute: 1,
      maxRequestsTotal: 1,
      maxConcurrency: 1,
    },
    allowedTestClasses: [],
    forbiddenTestClasses: [],
    rules: [],
    unclearRules: textAsUnclearRules(trimmed),
  });
}

function textAsUnclearRules(text: string): readonly string[] {
  const encoded = JSON.stringify(text).slice(1, -1);
  if (encoded.length <= MAX_UNCLEAR_RULE_LENGTH) return [encoded];
  const chunkLength = MAX_UNCLEAR_RULE_LENGTH - TEXT_CHUNK_PREFIX_LENGTH;
  const chunks: string[] = [];
  for (let offset = 0; offset < encoded.length; offset += chunkLength) {
    const index = String(chunks.length).padStart(6, "0");
    chunks.push(
      `part-${index}: ${encoded.slice(offset, offset + chunkLength)}`,
    );
  }
  return chunks;
}

function parseStructured(source: string, format: "json" | "yaml"): unknown {
  const documents = parseAllDocuments(source, {
    merge: false,
    uniqueKeys: true,
    version: "1.2",
  });
  if (documents.length !== 1)
    throw new SecurityError("POLICY_IMPORT_DOCUMENT_COUNT_INVALID");
  const document = documents[0];
  if (
    document === undefined ||
    document.errors.length > 0 ||
    document.warnings.length > 0
  )
    throw new SecurityError("POLICY_IMPORT_SYNTAX_INVALID");
  assertSafeYamlTree(document);
  if (format === "json") {
    try {
      return JSON.parse(source) as unknown;
    } catch {
      throw new SecurityError("POLICY_IMPORT_JSON_INVALID");
    }
  }
  try {
    const value: unknown = document.toJS({ maxAliasCount: 0 });
    return value;
  } catch {
    throw new SecurityError("POLICY_IMPORT_YAML_INVALID");
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
    throw new SecurityError("POLICY_IMPORT_ALIAS_FORBIDDEN");
  if (forbidden.has("merge"))
    throw new SecurityError("POLICY_IMPORT_MERGE_FORBIDDEN");
  if (forbidden.has("tag"))
    throw new SecurityError("POLICY_IMPORT_TAG_FORBIDDEN");
}

function policyInputFromUnknown(value: unknown): PolicyInput {
  assertRecord(value, "POLICY_IMPORT_MODEL_INVALID");
  assertExactKeys(value, POLICY_KEYS, "POLICY_IMPORT_UNKNOWN_FIELD");
  const requestLimits = requestLimitsFromUnknown(value["requestLimits"]);
  return {
    text: requireString(value["text"]),
    allowedAssets: requireStringArray(value["allowedAssets"]),
    excludedAssets: requireStringArray(value["excludedAssets"]),
    requestLimits,
    allowedTestClasses: requireStringArray(value["allowedTestClasses"]),
    forbiddenTestClasses: requireStringArray(value["forbiddenTestClasses"]),
    rules: requireStringArray(value["rules"]),
    unclearRules: requireStringArray(value["unclearRules"]),
  };
}

function requestLimitsFromUnknown(value: unknown): PolicyRequestLimits {
  assertRecord(value, "POLICY_IMPORT_REQUEST_LIMITS_INVALID");
  assertExactKeys(
    value,
    REQUEST_LIMIT_KEYS,
    "POLICY_IMPORT_REQUEST_LIMITS_INVALID",
  );
  return Object.freeze({
    requestsPerMinute: requireNumber(value["requestsPerMinute"]),
    maxRequestsTotal: requireNumber(value["maxRequestsTotal"]),
    maxConcurrency: requireNumber(value["maxConcurrency"]),
  });
}

function requireString(value: unknown): string {
  if (typeof value !== "string")
    throw new SecurityError("POLICY_IMPORT_STRING_INVALID");
  return value;
}

function requireStringArray(value: unknown): readonly string[] {
  if (!Array.isArray(value))
    throw new SecurityError("POLICY_IMPORT_ARRAY_INVALID");
  const result: string[] = [];
  for (const item of value) {
    if (typeof item !== "string")
      throw new SecurityError("POLICY_IMPORT_ARRAY_INVALID");
    result.push(item);
  }
  return Object.freeze(result);
}

function requireNumber(value: unknown): number {
  if (typeof value !== "number")
    throw new SecurityError("POLICY_IMPORT_NUMBER_INVALID");
  return value;
}

function decodeSource(source: string | Uint8Array): string {
  let decoded: string;
  if (typeof source === "string") {
    if (
      source.length > MAX_SOURCE_BYTES ||
      new TextEncoder().encode(source).byteLength > MAX_SOURCE_BYTES
    )
      throw new SecurityError("POLICY_IMPORT_SIZE_INVALID");
    decoded = source;
  } else if (source instanceof Uint8Array) {
    if (source.byteLength > MAX_SOURCE_BYTES)
      throw new SecurityError("POLICY_IMPORT_SIZE_INVALID");
    try {
      decoded = new TextDecoder("utf-8", { fatal: true }).decode(source);
    } catch {
      throw new SecurityError("POLICY_IMPORT_UTF8_INVALID");
    }
  } else {
    throw new SecurityError("POLICY_IMPORT_SOURCE_INVALID");
  }
  return decoded.startsWith("\uFEFF") ? decoded.slice(1) : decoded;
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
  code: string,
): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.size || keys.some((key) => !expected.has(key)))
    throw new SecurityError(code);
}

function assertFormat(value: unknown): asserts value is PolicyImportFormat {
  if (value !== "text" && value !== "json" && value !== "yaml")
    throw new SecurityError("POLICY_IMPORT_FORMAT_INVALID");
}
