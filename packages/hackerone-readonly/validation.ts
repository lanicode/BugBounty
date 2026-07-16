import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { types } from "node:util";
import { SecurityError } from "../shared/errors.js";
import { sha256 } from "../shared/canonical.js";
import type {
  HackerOneDataSource,
  HackerOneProgram,
  HackerOneScopeExclusion,
  HackerOneStructuredScope,
} from "./types.js";

interface ApiLinks {
  readonly first?: string | null;
  readonly last?: string | null;
  readonly next?: string | null;
  readonly prev?: string | null;
  readonly self?: string | null;
}

interface ApiProgramAttributes {
  readonly handle: string;
  readonly name?: string | null;
  readonly currency?: string | null;
  readonly policy?: string | null;
  readonly submission_state?: string | null;
  readonly state?: string | null;
  readonly offers_bounties?: boolean | null;
  readonly open_scope?: boolean | null;
  readonly gold_standard_safe_harbor?: boolean | null;
  readonly bookmarked?: boolean | null;
  readonly number_of_reports_for_user?: number | null;
  readonly number_of_valid_reports_for_user?: number | null;
  readonly started_accepting_at?: string | null;
  readonly created_at?: string | null;
  readonly updated_at?: string | null;
}

interface ApiProgramResource {
  readonly id: string | number;
  readonly type: "program";
  readonly attributes: ApiProgramAttributes;
}

interface ApiProgramPage {
  readonly data: readonly ApiProgramResource[];
  readonly links?: ApiLinks;
  readonly meta?: {
    readonly current_page?: number;
    readonly total_count?: number;
    readonly total_pages?: number;
  };
}

interface ApiProgramDocument {
  readonly data: ApiProgramResource;
}

interface ApiScopeAttributes {
  readonly asset_type: string;
  readonly asset_identifier: string;
  readonly eligible_for_submission: boolean;
  readonly eligible_for_bounty: boolean;
  readonly instruction: string | null;
  readonly max_severity: string | null;
  readonly created_at?: string | null;
  readonly updated_at?: string | null;
  readonly confidentiality_requirement?: string | null;
  readonly integrity_requirement?: string | null;
  readonly availability_requirement?: string | null;
}

interface ApiScopeResource {
  readonly id: string;
  readonly type: "structured-scope" | "structured_scope";
  readonly attributes: ApiScopeAttributes;
}

interface ApiScopePage {
  readonly data: readonly ApiScopeResource[];
  readonly links?: ApiLinks;
  readonly meta?: {
    readonly current_page?: number;
    readonly total_count?: number;
    readonly total_pages?: number;
  };
}

interface ApiExclusionAttributes {
  readonly category: string;
  readonly details: string;
  readonly created_at?: string | null;
  readonly updated_at?: string | null;
}

interface ApiExclusionResource {
  readonly id: string;
  readonly type: "scope-exclusion" | "scope_exclusion";
  readonly attributes: ApiExclusionAttributes;
}

interface ApiExclusionPage {
  readonly data: readonly ApiExclusionResource[];
  readonly links?: ApiLinks;
  readonly meta?: {
    readonly current_page?: number;
    readonly total_count?: number;
    readonly total_pages?: number;
  };
}

export interface ValidatedPage<T> {
  readonly records: readonly T[];
  readonly next: string | null;
}

const text = (maximum: number, minimum = 0) => ({
  type: "string",
  minLength: minimum,
  maxLength: maximum,
  pattern: "^[^\\u0000]*$",
});

const nullableTimestamp = {
  anyOf: [
    { type: "string", format: "date-time", maxLength: 64 },
    { type: "null" },
  ],
};

const nullableText = (maximum: number, minimum = 0) => ({
  anyOf: [text(maximum, minimum), { type: "null" }],
});

const nullableBoolean = {
  anyOf: [{ type: "boolean" }, { type: "null" }],
};

const nullableNonNegativeInteger = {
  anyOf: [{ type: "integer", minimum: 0 }, { type: "null" }],
};

const linksSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    first: { anyOf: [text(4_096), { type: "null" }] },
    last: { anyOf: [text(4_096), { type: "null" }] },
    next: { anyOf: [text(4_096), { type: "null" }] },
    prev: { anyOf: [text(4_096), { type: "null" }] },
    self: { anyOf: [text(4_096), { type: "null" }] },
  },
} as const;

const metaSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    current_page: { type: "integer", minimum: 1 },
    total_count: { type: "integer", minimum: 0 },
    total_pages: { type: "integer", minimum: 0 },
  },
} as const;

const programAttributesSchema = {
  type: "object",
  additionalProperties: false,
  // Catalog summaries are not guaranteed to include every detail attribute.
  // Only the server-bound handle is required. Missing or explicit null values
  // are normalized below to values that reduce authority: unknown state,
  // empty policy, no bounty, no open scope and no safe-harbor assertion.
  required: ["handle"],
  properties: {
    handle: {
      type: "string",
      pattern: "^[a-z0-9](?:[a-z0-9_-]{0,126}[a-z0-9])?$",
    },
    name: nullableText(512, 1),
    currency: nullableText(16, 1),
    policy: nullableText(262_144),
    submission_state: nullableText(128, 1),
    state: nullableText(128, 1),
    offers_bounties: nullableBoolean,
    open_scope: nullableBoolean,
    gold_standard_safe_harbor: nullableBoolean,
    bookmarked: nullableBoolean,
    number_of_reports_for_user: nullableNonNegativeInteger,
    number_of_valid_reports_for_user: nullableNonNegativeInteger,
    started_accepting_at: nullableTimestamp,
    created_at: nullableTimestamp,
    updated_at: nullableTimestamp,
  },
} as const;

const programResourceSchema = {
  type: "object",
  additionalProperties: false,
  required: ["attributes", "id", "type"],
  properties: {
    id: {
      anyOf: [
        text(128, 1),
        {
          type: "integer",
          minimum: 1,
          maximum: Number.MAX_SAFE_INTEGER,
        },
      ],
    },
    type: { const: "program" },
    attributes: programAttributesSchema,
  },
} as const;

const pageProperties = {
  data: { type: "array", maxItems: 100, items: programResourceSchema },
  links: linksSchema,
  meta: metaSchema,
} as const;

const programPageSchema = {
  type: "object",
  additionalProperties: false,
  required: ["data"],
  properties: pageProperties,
} as const;

const programDocumentSchema = {
  type: "object",
  additionalProperties: false,
  required: ["data"],
  properties: { data: programResourceSchema },
} as const;

const scopeAttributesSchema = {
  type: "object",
  additionalProperties: false,
  required: [
    "asset_identifier",
    "asset_type",
    "eligible_for_bounty",
    "eligible_for_submission",
    "instruction",
    "max_severity",
  ],
  properties: {
    asset_type: text(128, 1),
    asset_identifier: text(4_096, 1),
    eligible_for_submission: { type: "boolean" },
    eligible_for_bounty: { type: "boolean" },
    instruction: { anyOf: [text(65_536), { type: "null" }] },
    max_severity: { anyOf: [text(64, 1), { type: "null" }] },
    created_at: nullableTimestamp,
    updated_at: nullableTimestamp,
    confidentiality_requirement: {
      anyOf: [text(64, 1), { type: "null" }],
    },
    integrity_requirement: {
      anyOf: [text(64, 1), { type: "null" }],
    },
    availability_requirement: {
      anyOf: [text(64, 1), { type: "null" }],
    },
  },
} as const;

const scopeResourceSchema = {
  type: "object",
  additionalProperties: false,
  required: ["attributes", "id", "type"],
  properties: {
    id: text(128, 1),
    type: { enum: ["structured-scope", "structured_scope"] },
    attributes: scopeAttributesSchema,
  },
} as const;

const scopePageSchema = {
  type: "object",
  additionalProperties: false,
  required: ["data"],
  properties: {
    data: { type: "array", maxItems: 100, items: scopeResourceSchema },
    links: linksSchema,
    meta: metaSchema,
  },
} as const;

const exclusionResourceSchema = {
  type: "object",
  additionalProperties: false,
  required: ["attributes", "id", "type"],
  properties: {
    id: text(128, 1),
    type: { enum: ["scope-exclusion", "scope_exclusion"] },
    attributes: {
      type: "object",
      additionalProperties: false,
      required: ["category", "details"],
      properties: {
        category: text(256, 1),
        details: text(65_536),
        created_at: nullableTimestamp,
        updated_at: nullableTimestamp,
      },
    },
  },
} as const;

const exclusionPageSchema = {
  type: "object",
  additionalProperties: false,
  required: ["data"],
  properties: {
    data: { type: "array", maxItems: 100, items: exclusionResourceSchema },
    links: linksSchema,
    meta: metaSchema,
  },
} as const;

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validateProgramPageSchema =
  ajv.compile<ApiProgramPage>(programPageSchema);
const validateProgramDocumentSchema = ajv.compile<ApiProgramDocument>(
  programDocumentSchema,
);
const validateScopePageSchema = ajv.compile<ApiScopePage>(scopePageSchema);
const validateExclusionPageSchema =
  ajv.compile<ApiExclusionPage>(exclusionPageSchema);

const MAX_RESPONSE_OBJECT_PROPERTIES = 128;
const SAFE_RESPONSE_PROPERTY_NAME = /^[A-Za-z][A-Za-z0-9_-]{0,127}$/u;
const FORBIDDEN_RESPONSE_PROPERTY_NAMES = new Set([
  "__proto__",
  "constructor",
  "prototype",
]);

const LINK_FIELDS = Object.freeze(["first", "last", "next", "prev", "self"]);
const META_FIELDS = Object.freeze([
  "current_page",
  "total_count",
  "total_pages",
]);
const PROGRAM_ATTRIBUTE_FIELDS = Object.freeze([
  "handle",
  "name",
  "currency",
  "policy",
  "submission_state",
  "state",
  "offers_bounties",
  "open_scope",
  "gold_standard_safe_harbor",
  "bookmarked",
  "number_of_reports_for_user",
  "number_of_valid_reports_for_user",
  "started_accepting_at",
  "created_at",
  "updated_at",
]);
const SCOPE_ATTRIBUTE_FIELDS = Object.freeze([
  "asset_type",
  "asset_identifier",
  "eligible_for_submission",
  "eligible_for_bounty",
  "instruction",
  "max_severity",
  "created_at",
  "updated_at",
  "confidentiality_requirement",
  "integrity_requirement",
  "availability_requirement",
]);
const EXCLUSION_ATTRIBUTE_FIELDS = Object.freeze([
  "category",
  "details",
  "created_at",
  "updated_at",
]);

type ResponseRecord = Readonly<Record<string, unknown>>;

/**
 * HackerOne's JSON:API documents may add fields that are not consumed by the
 * product. Those untrusted extensions must not become a reason to weaken the
 * strict trusted schema or to persist unknown values. We therefore construct
 * a getter-free, prototype-safe projection containing only the explicit
 * fields below and apply the existing additionalProperties:false schemas to
 * that projection. Required fields, types, lengths, counts and timestamps
 * remain fail-closed.
 */
function projectProgramPageResponse(value: unknown): unknown {
  return projectPage(value, projectProgramResource);
}

function projectProgramDocumentResponse(value: unknown): unknown {
  const source = responseRecord(value);
  const projected = emptyResponseRecord();
  copyProjected(source, projected, "data", projectProgramResource);
  return Object.freeze(projected);
}

function projectScopePageResponse(value: unknown): unknown {
  return projectPage(value, projectScopeResource);
}

function projectExclusionPageResponse(value: unknown): unknown {
  return projectPage(value, projectExclusionResource);
}

function projectPage(
  value: unknown,
  projectResource: (value: unknown) => unknown,
): unknown {
  const source = responseRecord(value);
  const projected = emptyResponseRecord();
  copyProjected(source, projected, "data", (data) =>
    responseArray(data, 100, projectResource),
  );
  copyProjected(source, projected, "links", (links) =>
    projectKnownRecord(links, LINK_FIELDS),
  );
  copyProjected(source, projected, "meta", (meta) =>
    projectKnownRecord(meta, META_FIELDS),
  );
  return Object.freeze(projected);
}

function projectProgramResource(value: unknown): unknown {
  return projectResource(value, PROGRAM_ATTRIBUTE_FIELDS);
}

function projectScopeResource(value: unknown): unknown {
  return projectResource(value, SCOPE_ATTRIBUTE_FIELDS);
}

function projectExclusionResource(value: unknown): unknown {
  return projectResource(value, EXCLUSION_ATTRIBUTE_FIELDS);
}

function projectResource(
  value: unknown,
  attributeFields: readonly string[],
): unknown {
  const source = responseRecord(value);
  const projected = emptyResponseRecord();
  copyKnown(source, projected, Object.freeze(["id", "type"]));
  copyProjected(source, projected, "attributes", (attributes) =>
    projectKnownRecord(attributes, attributeFields),
  );
  return Object.freeze(projected);
}

function projectKnownRecord(
  value: unknown,
  fields: readonly string[],
): unknown {
  const source = responseRecord(value);
  const projected = emptyResponseRecord();
  copyKnown(source, projected, fields);
  return Object.freeze(projected);
}

function responseRecord(value: unknown): ResponseRecord {
  try {
    if (
      value === null ||
      typeof value !== "object" ||
      types.isProxy(value) ||
      Object.getPrototypeOf(value) !== Object.prototype
    )
      throw new Error("invalid");
    const keys = Reflect.ownKeys(value);
    if (
      keys.length > MAX_RESPONSE_OBJECT_PROPERTIES ||
      keys.some(
        (key) =>
          typeof key !== "string" ||
          !SAFE_RESPONSE_PROPERTY_NAME.test(key) ||
          FORBIDDEN_RESPONSE_PROPERTY_NAMES.has(key),
      )
    )
      throw new Error("invalid");
    const projected = emptyResponseRecord();
    for (const key of keys) {
      if (typeof key !== "string") throw new Error("invalid");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true
      )
        throw new Error("invalid");
      projected[key] = descriptor.value;
    }
    return Object.freeze(projected);
  } catch {
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  }
}

function responseArray(
  value: unknown,
  maximumItems: number,
  projectItem: (value: unknown) => unknown,
): readonly unknown[] {
  try {
    if (
      !Array.isArray(value) ||
      types.isProxy(value) ||
      Object.getPrototypeOf(value) !== Array.prototype ||
      value.length > maximumItems
    )
      throw new Error("invalid");
    const keys = Reflect.ownKeys(value);
    if (keys.length !== value.length + 1 || !keys.includes("length"))
      throw new Error("invalid");
    const projected: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const key = String(index);
      if (!keys.includes(key)) throw new Error("invalid");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true
      )
        throw new Error("invalid");
      projected.push(projectItem(descriptor.value));
    }
    return Object.freeze(projected);
  } catch (error) {
    if (error instanceof SecurityError) throw error;
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  }
}

function emptyResponseRecord(): Record<string, unknown> {
  return {};
}

function copyKnown(
  source: ResponseRecord,
  target: Record<string, unknown>,
  fields: readonly string[],
): void {
  for (const field of fields)
    if (Object.hasOwn(source, field)) target[field] = source[field];
}

function copyProjected(
  source: ResponseRecord,
  target: Record<string, unknown>,
  field: string,
  project: (value: unknown) => unknown,
): void {
  if (Object.hasOwn(source, field)) target[field] = project(source[field]);
}

export function validateProgramPage(
  value: unknown,
  synchronizedAt: string,
  source: HackerOneDataSource = "hackerone_api_authenticated",
): ValidatedPage<HackerOneProgram> {
  const projected = projectProgramPageResponse(value);
  if (!validateProgramPageSchema(projected))
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  return Object.freeze({
    records: Object.freeze(
      projected.data.map((record) =>
        normalizeProgram(record, synchronizedAt, source),
      ),
    ),
    next: normalizeNext(projected.links),
  });
}

export function validateProgramDocument(
  value: unknown,
  synchronizedAt: string,
  source: HackerOneDataSource = "hackerone_api_authenticated",
): HackerOneProgram {
  const projected = projectProgramDocumentResponse(value);
  if (!validateProgramDocumentSchema(projected))
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  return normalizeProgram(projected.data, synchronizedAt, source);
}

export function validateStructuredScopePage(
  value: unknown,
): ValidatedPage<HackerOneStructuredScope> {
  const projected = projectScopePageResponse(value);
  if (!validateScopePageSchema(projected))
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  return Object.freeze({
    records: Object.freeze(projected.data.map(normalizeScope)),
    next: normalizeNext(projected.links),
  });
}

export function validateScopeExclusionPage(
  value: unknown,
): ValidatedPage<HackerOneScopeExclusion> {
  const projected = projectExclusionPageResponse(value);
  if (!validateExclusionPageSchema(projected))
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  return Object.freeze({
    records: Object.freeze(projected.data.map(normalizeExclusion)),
    next: normalizeNext(projected.links),
  });
}

function normalizeProgram(
  resource: ApiProgramResource,
  synchronizedAt: string,
  source: HackerOneDataSource,
): HackerOneProgram {
  const attributes = resource.attributes;
  return Object.freeze({
    hackerOneId: String(resource.id),
    handle: attributes.handle,
    name: (attributes.name ?? attributes.handle).trim(),
    currency: attributes.currency ?? "UNKNOWN",
    policy: attributes.policy ?? "",
    submissionState: attributes.submission_state ?? "unknown",
    programState: attributes.state ?? "unknown",
    offersBounties: attributes.offers_bounties ?? false,
    openScope: attributes.open_scope ?? false,
    goldStandardSafeHarbor: attributes.gold_standard_safe_harbor ?? false,
    bookmarked: attributes.bookmarked ?? false,
    ownReportCount: attributes.number_of_reports_for_user ?? 0,
    ownValidReportCount: attributes.number_of_valid_reports_for_user ?? 0,
    startedAcceptingAt: normalizedTimestamp(attributes.started_accepting_at),
    createdAt: normalizedTimestamp(attributes.created_at),
    updatedAt: normalizedTimestamp(attributes.updated_at),
    synchronizedAt: normalizedTimestamp(synchronizedAt) ?? invalidTimestamp(),
    source,
  });
}

function normalizeScope(resource: ApiScopeResource): HackerOneStructuredScope {
  const attributes = resource.attributes;
  return Object.freeze({
    id: resource.id,
    assetType: attributes.asset_type,
    assetIdentifier: attributes.asset_identifier,
    assetIdentifierDigest: sha256(attributes.asset_identifier),
    eligibleForSubmission: attributes.eligible_for_submission,
    eligibleForBounty: attributes.eligible_for_bounty,
    instruction: attributes.instruction ?? "",
    maximumSeverity: attributes.max_severity,
    createdAt: normalizedTimestamp(attributes.created_at),
    updatedAt: normalizedTimestamp(attributes.updated_at),
    confidentialityRequirement: attributes.confidentiality_requirement ?? null,
    integrityRequirement: attributes.integrity_requirement ?? null,
    availabilityRequirement: attributes.availability_requirement ?? null,
  });
}

function normalizeExclusion(
  resource: ApiExclusionResource,
): HackerOneScopeExclusion {
  return Object.freeze({
    id: resource.id,
    category: resource.attributes.category,
    details: resource.attributes.details,
    createdAt: normalizedTimestamp(resource.attributes.created_at),
    updatedAt: normalizedTimestamp(resource.attributes.updated_at),
  });
}

function normalizeNext(links: ApiLinks | undefined): string | null {
  return links?.next ?? null;
}

function normalizedTimestamp(value: string | null | undefined): string | null {
  if (value === undefined || value === null) return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds))
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  return new Date(milliseconds).toISOString();
}

function invalidTimestamp(): never {
  throw new SecurityError("HACKERONE_TIMESTAMP_INVALID");
}
