import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
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
  readonly name: string;
  readonly currency: string;
  readonly policy: string;
  readonly submission_state: string;
  readonly state: string;
  readonly offers_bounties: boolean;
  readonly open_scope: boolean;
  readonly gold_standard_safe_harbor: boolean;
  readonly bookmarked: boolean;
  readonly number_of_reports_for_user: number;
  readonly number_of_valid_reports_for_user: number;
  readonly started_accepting_at?: string | null;
  readonly created_at?: string | null;
  readonly updated_at?: string | null;
}

interface ApiProgramResource {
  readonly id: string;
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
  required: [
    "bookmarked",
    "currency",
    "gold_standard_safe_harbor",
    "handle",
    "name",
    "number_of_reports_for_user",
    "number_of_valid_reports_for_user",
    "offers_bounties",
    "open_scope",
    "policy",
    "state",
    "submission_state",
  ],
  properties: {
    handle: {
      type: "string",
      pattern: "^[a-z0-9](?:[a-z0-9_-]{0,126}[a-z0-9])?$",
    },
    name: text(512, 1),
    currency: text(16, 1),
    policy: text(262_144),
    submission_state: text(128, 1),
    state: text(128, 1),
    offers_bounties: { type: "boolean" },
    open_scope: { type: "boolean" },
    gold_standard_safe_harbor: { type: "boolean" },
    bookmarked: { type: "boolean" },
    number_of_reports_for_user: { type: "integer", minimum: 0 },
    number_of_valid_reports_for_user: { type: "integer", minimum: 0 },
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
    id: text(128, 1),
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

export function validateProgramPage(
  value: unknown,
  synchronizedAt: string,
  source: HackerOneDataSource = "hackerone_api_authenticated",
): ValidatedPage<HackerOneProgram> {
  if (!validateProgramPageSchema(value))
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  return Object.freeze({
    records: Object.freeze(
      value.data.map((record) =>
        normalizeProgram(record, synchronizedAt, source),
      ),
    ),
    next: normalizeNext(value.links),
  });
}

export function validateProgramDocument(
  value: unknown,
  synchronizedAt: string,
  source: HackerOneDataSource = "hackerone_api_authenticated",
): HackerOneProgram {
  if (!validateProgramDocumentSchema(value))
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  return normalizeProgram(value.data, synchronizedAt, source);
}

export function validateStructuredScopePage(
  value: unknown,
): ValidatedPage<HackerOneStructuredScope> {
  if (!validateScopePageSchema(value))
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  return Object.freeze({
    records: Object.freeze(value.data.map(normalizeScope)),
    next: normalizeNext(value.links),
  });
}

export function validateScopeExclusionPage(
  value: unknown,
): ValidatedPage<HackerOneScopeExclusion> {
  if (!validateExclusionPageSchema(value))
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  return Object.freeze({
    records: Object.freeze(value.data.map(normalizeExclusion)),
    next: normalizeNext(value.links),
  });
}

function normalizeProgram(
  resource: ApiProgramResource,
  synchronizedAt: string,
  source: HackerOneDataSource,
): HackerOneProgram {
  const attributes = resource.attributes;
  return Object.freeze({
    hackerOneId: resource.id,
    handle: attributes.handle,
    name: attributes.name.trim(),
    currency: attributes.currency,
    policy: attributes.policy,
    submissionState: attributes.submission_state,
    programState: attributes.state,
    offersBounties: attributes.offers_bounties,
    openScope: attributes.open_scope,
    goldStandardSafeHarbor: attributes.gold_standard_safe_harbor,
    bookmarked: attributes.bookmarked,
    ownReportCount: attributes.number_of_reports_for_user,
    ownValidReportCount: attributes.number_of_valid_reports_for_user,
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
