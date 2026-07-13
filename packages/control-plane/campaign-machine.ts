import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import type { CampaignRecord, CampaignState } from "./types.js";

const SAFE_METADATA_METHODS: ReadonlySet<unknown> = new Set([
  "GET",
  "HEAD",
  "OPTIONS",
]);

export type CampaignEvent =
  | { readonly kind: "approve"; readonly actor: string; readonly at: string }
  | { readonly kind: "block" }
  | { readonly kind: "cancel" }
  | { readonly kind: "complete" }
  | { readonly kind: "pause" }
  | { readonly kind: "policy_accepted" }
  | { readonly kind: "policy_drift"; readonly at: string }
  | { readonly kind: "request_approval" }
  | { readonly kind: "resume_requested" }
  | { readonly kind: "start_simulation" };

export interface CampaignGuardContext {
  readonly acceptedPolicyVersion: number | null;
  readonly acceptedPolicyHash: string | null;
  readonly policyAssets: readonly string[];
  readonly configurationValid: boolean;
  readonly killSwitchActive: boolean;
  readonly externalActionRequested: boolean;
  readonly externalIntegrationsEnabled: boolean;
  readonly now: string;
}

export function campaignApprovalDigest(campaign: CampaignRecord): string {
  return sha256(
    canonicalJson({
      programId: campaign.programId,
      policyVersion: campaign.policyVersion,
      policyHash: campaign.policyHash,
      approvedAssets: campaign.approvedAssets,
      approvedRiskTiers: campaign.approvedRiskTiers,
      accountRefs: campaign.accountRefs,
      allowedActionClasses: campaign.allowedActionClasses,
      contract: campaign.contract,
    }),
  );
}

export function transitionCampaign(
  campaign: CampaignRecord,
  event: CampaignEvent,
  context: CampaignGuardContext,
): CampaignRecord {
  assertTimestamp(context.now);
  if (typeof context.killSwitchActive !== "boolean")
    throw new SecurityError("CAMPAIGN_KILL_SWITCH");
  if (
    typeof context.externalActionRequested !== "boolean" ||
    typeof context.externalIntegrationsEnabled !== "boolean"
  )
    throw new SecurityError("CAMPAIGN_CONFIG_INVALID");
  let state: CampaignState;
  let approval = {
    humanApprovedBy: campaign.humanApprovedBy,
    humanApprovedAt: campaign.humanApprovedAt,
  };
  let lastPolicyCheckAt = campaign.lastPolicyCheckAt;
  switch (event.kind) {
    case "request_approval":
      requireState(campaign.state, "draft");
      state = policyAccepted(campaign, context)
        ? "awaiting_campaign_approval"
        : "awaiting_policy_acceptance";
      break;
    case "policy_accepted":
      requireState(campaign.state, "awaiting_policy_acceptance");
      assertPolicyAccepted(campaign, context);
      state = "awaiting_campaign_approval";
      break;
    case "approve":
      requireState(campaign.state, "awaiting_campaign_approval");
      assertPolicyAccepted(campaign, context);
      assertActor(event.actor);
      assertTimestamp(event.at);
      state = "approved";
      approval = { humanApprovedBy: event.actor, humanApprovedAt: event.at };
      break;
    case "start_simulation":
      requireState(campaign.state, "approved");
      assertStartable(campaign, context);
      state = "running_simulation";
      lastPolicyCheckAt = context.now;
      break;
    case "policy_drift":
      if (
        campaign.state !== "approved" &&
        campaign.state !== "running_simulation"
      )
        throw new SecurityError("CAMPAIGN_TRANSITION_BLOCKED");
      assertTimestamp(event.at);
      state = "paused";
      approval = { humanApprovedBy: null, humanApprovedAt: null };
      lastPolicyCheckAt = event.at;
      break;
    case "pause":
      requireState(campaign.state, "running_simulation");
      state = "paused";
      approval = { humanApprovedBy: null, humanApprovedAt: null };
      break;
    case "resume_requested":
      requireState(campaign.state, "paused");
      assertPolicyAccepted(campaign, context);
      state = "awaiting_campaign_approval";
      approval = { humanApprovedBy: null, humanApprovedAt: null };
      break;
    case "complete":
      requireState(campaign.state, "running_simulation");
      state = "completed";
      approval = { humanApprovedBy: null, humanApprovedAt: null };
      break;
    case "cancel":
      if (campaign.state === "completed" || campaign.state === "cancelled")
        throw new SecurityError("CAMPAIGN_TRANSITION_BLOCKED");
      state = "cancelled";
      approval = { humanApprovedBy: null, humanApprovedAt: null };
      break;
    case "block":
      if (campaign.state === "completed" || campaign.state === "cancelled")
        throw new SecurityError("CAMPAIGN_TRANSITION_BLOCKED");
      state = "blocked";
      approval = { humanApprovedBy: null, humanApprovedAt: null };
      break;
  }
  return deepFreeze({
    ...campaign,
    ...approval,
    lastPolicyCheckAt,
    state,
    revision: campaign.revision + 1,
    killSwitchStatus: context.killSwitchActive ? "engaged" : "clear",
  });
}

export function validateCampaignContract(campaign: CampaignRecord): void {
  const contract = campaign.contract;
  const validFrom = Date.parse(contract.validFrom);
  const validUntil = Date.parse(contract.validUntil);
  if (
    contract.policyHash !== campaign.policyHash ||
    contract.allowedHosts.length === 0 ||
    contract.allowedHosts.some((host) => !isMetadataHost(host)) ||
    contract.excludedHosts.some((host) => !isMetadataHost(host)) ||
    overlaps(contract.allowedHosts, contract.excludedHosts) ||
    campaign.approvedAssets.length === 0 ||
    !sameList(contract.allowedHosts, campaign.approvedAssets) ||
    contract.maxRequests < 1 ||
    contract.maxRequests > 10_000 ||
    !Number.isSafeInteger(contract.maxRequests) ||
    contract.requestsPerMinute < 1 ||
    contract.requestsPerMinute > contract.maxRequests ||
    !Number.isSafeInteger(contract.requestsPerMinute) ||
    !sameValue(contract.maxConcurrency, 1) ||
    !sameValue(contract.writeActionsAllowed, false) ||
    !sameValue(contract.rollbackRequired, true) ||
    !sameList(contract.allowedRiskTiers, ["tier_0_offline"]) ||
    !sameList(campaign.allowedActionClasses, ["offline_simulation"]) ||
    !sameList(campaign.approvedRiskTiers, ["tier_0_offline"]) ||
    contract.allowedMethods.length === 0 ||
    contract.allowedMethods.some(
      (method) => !SAFE_METADATA_METHODS.has(method),
    ) ||
    !contract.humanCheckpoints.includes("policy_acceptance") ||
    !contract.humanCheckpoints.includes("campaign_approval") ||
    !Number.isFinite(validFrom) ||
    !Number.isFinite(validUntil) ||
    validFrom >= validUntil
  )
    throw new SecurityError("CAMPAIGN_CONTRACT_INVALID");
}

function isMetadataHost(value: string): boolean {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 253 &&
    /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/u.test(
      value,
    )
  );
}

function overlaps(left: readonly string[], right: readonly string[]): boolean {
  const rightValues = new Set(right);
  return left.some((value) => rightValues.has(value));
}

function sameValue(actual: unknown, expected: unknown): boolean {
  return actual === expected;
}

function sameList(actual: unknown, expected: readonly string[]): boolean {
  if (!Array.isArray(actual) || actual.length !== expected.length) return false;
  return expected.every((value, index) => actual[index] === value);
}

function assertStartable(
  campaign: CampaignRecord,
  context: CampaignGuardContext,
): void {
  validateCampaignContract(campaign);
  assertPolicyAccepted(campaign, context);
  const configurationValid: unknown = context.configurationValid;
  const killSwitchActive: unknown = context.killSwitchActive;
  if (configurationValid !== true)
    throw new SecurityError("CAMPAIGN_CONFIG_INVALID");
  if (killSwitchActive !== false)
    throw new SecurityError("CAMPAIGN_KILL_SWITCH");
  if (context.externalActionRequested && !context.externalIntegrationsEnabled)
    throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
  if (campaign.approvedAssets.length === 0)
    throw new SecurityError("CAMPAIGN_SCOPE_MISSING");
  const allowed = new Set(context.policyAssets);
  if (campaign.approvedAssets.some((asset) => !allowed.has(asset)))
    throw new SecurityError("CAMPAIGN_ASSET_UNKNOWN");
  const now = Date.parse(context.now);
  if (
    now < Date.parse(campaign.contract.validFrom) ||
    now > Date.parse(campaign.contract.validUntil)
  )
    throw new SecurityError("CAMPAIGN_OUTSIDE_VALIDITY");
}

function policyAccepted(
  campaign: CampaignRecord,
  context: CampaignGuardContext,
): boolean {
  return (
    context.acceptedPolicyVersion === campaign.policyVersion &&
    context.acceptedPolicyHash === campaign.policyHash
  );
}

function assertPolicyAccepted(
  campaign: CampaignRecord,
  context: CampaignGuardContext,
): void {
  if (context.acceptedPolicyVersion === null)
    throw new SecurityError("CAMPAIGN_POLICY_NOT_ACCEPTED");
  if (!policyAccepted(campaign, context))
    throw new SecurityError("CAMPAIGN_POLICY_HASH_MISMATCH");
}

function requireState(actual: CampaignState, expected: CampaignState): void {
  if (actual !== expected)
    throw new SecurityError("CAMPAIGN_TRANSITION_BLOCKED");
}

function assertActor(actor: string): void {
  if (!/^[A-Za-z0-9._@-]{1,128}$/u.test(actor))
    throw new SecurityError("CAMPAIGN_APPROVER_INVALID");
}

function assertTimestamp(value: string): void {
  if (!Number.isFinite(Date.parse(value)))
    throw new SecurityError("CAMPAIGN_TIMESTAMP_INVALID");
}

function deepFreeze<T extends object>(value: T): Readonly<T> {
  for (const nested of Object.values(value))
    if (nested !== null && typeof nested === "object") Object.freeze(nested);
  return Object.freeze(value);
}
