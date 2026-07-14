import { types } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";
import proposalSchema from "./proposal.schema.json" with { type: "json" };
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

export type ExternalActionAccountRole = "External" | "Member" | "Owner";

export interface ExternalActionProposalV2 {
  readonly version: 2;
  readonly proposal_id: string;
  readonly action_id: string;
  readonly mode: "external" | "simulation";
  readonly parameters: {
    readonly program_ref: string;
    readonly campaign_ref: string;
    readonly campaign_revision: number;
    readonly campaign_digest: string;
    readonly policy_version: number;
    readonly policy_hash_sha256: string;
    readonly scope_ref: string;
    readonly account_ref: string | null;
    readonly account_role: ExternalActionAccountRole | null;
    readonly object_ref: string | null;
    readonly payload_ref: string | null;
    readonly approval_ref: string;
    readonly operator_ref: string;
  };
}

export type ExternalActionProposal = ExternalActionProposalV2;

const TOP_LEVEL_KEYS = Object.freeze([
  "action_id",
  "mode",
  "parameters",
  "proposal_id",
  "version",
] as const);

const PARAMETER_KEYS = Object.freeze([
  "account_ref",
  "account_role",
  "approval_ref",
  "campaign_digest",
  "campaign_ref",
  "campaign_revision",
  "object_ref",
  "operator_ref",
  "payload_ref",
  "policy_hash_sha256",
  "policy_version",
  "program_ref",
  "scope_ref",
] as const);

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateSchema = ajv.compile<ExternalActionProposalV2>(proposalSchema);

export function validateAndFreezeExternalActionProposal(
  value: unknown,
): ExternalActionProposalV2 {
  try {
    const top = cloneExactDataRecord(value, TOP_LEVEL_KEYS);
    const parameters = cloneExactDataRecord(top["parameters"], PARAMETER_KEYS);
    const candidate: unknown = {
      ...top,
      parameters,
    };
    if (!validateSchema(candidate))
      throw new SecurityError("ACTION_PROPOSAL_INVALID");
    return Object.freeze({
      version: candidate.version,
      proposal_id: candidate.proposal_id,
      action_id: candidate.action_id,
      mode: candidate.mode,
      parameters: Object.freeze({
        program_ref: candidate.parameters.program_ref,
        campaign_ref: candidate.parameters.campaign_ref,
        campaign_revision: candidate.parameters.campaign_revision,
        campaign_digest: candidate.parameters.campaign_digest,
        policy_version: candidate.parameters.policy_version,
        policy_hash_sha256: candidate.parameters.policy_hash_sha256,
        scope_ref: candidate.parameters.scope_ref,
        account_ref: candidate.parameters.account_ref,
        account_role: candidate.parameters.account_role,
        object_ref: candidate.parameters.object_ref,
        payload_ref: candidate.parameters.payload_ref,
        approval_ref: candidate.parameters.approval_ref,
        operator_ref: candidate.parameters.operator_ref,
      }),
    });
  } catch (error) {
    if (
      error instanceof SecurityError &&
      error.code === "ACTION_PROPOSAL_INVALID"
    )
      throw error;
    throw new SecurityError("ACTION_PROPOSAL_INVALID");
  }
}

export function externalActionProposalDigest(value: unknown): string {
  const proposal = validateAndFreezeExternalActionProposal(value);
  return sha256(canonicalJson(proposal));
}

function cloneExactDataRecord(
  value: unknown,
  expectedKeys: readonly string[],
): Readonly<Record<string, unknown>> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype
  )
    throw new SecurityError("ACTION_PROPOSAL_INVALID");

  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== expectedKeys.length ||
    ownKeys.some((key) => typeof key !== "string") ||
    !expectedKeys.every((key) => ownKeys.includes(key))
  )
    throw new SecurityError("ACTION_PROPOSAL_INVALID");

  const entries: [string, unknown][] = [];
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new SecurityError("ACTION_PROPOSAL_INVALID");
    entries.push([key, descriptor.value]);
  }
  return Object.fromEntries(entries);
}
