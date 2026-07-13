import { SecurityError } from "../shared/errors.js";
import type { CampaignRecord, CampaignState } from "./types.js";

export type CampaignEvent =
  | { readonly kind: "approve"; readonly actor: string; readonly at: string }
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

export function transitionCampaign(
  campaign: CampaignRecord,
  event: CampaignEvent,
  context: CampaignGuardContext,
): CampaignRecord {
  assertTimestamp(context.now);
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
      lastPolicyCheckAt = event.at;
      break;
    case "pause":
      requireState(campaign.state, "running_simulation");
      state = "paused";
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
      break;
    case "cancel":
      if (campaign.state === "completed" || campaign.state === "cancelled")
        throw new SecurityError("CAMPAIGN_TRANSITION_BLOCKED");
      state = "cancelled";
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
  if (
    contract.policyHash !== campaign.policyHash ||
    contract.allowedHosts.length === 0 ||
    contract.maxRequests < 1 ||
    contract.maxRequests > 10_000 ||
    contract.requestsPerMinute < 1 ||
    contract.requestsPerMinute > contract.maxRequests ||
    !sameValue(contract.maxConcurrency, 1) ||
    !sameValue(contract.writeActionsAllowed, false) ||
    !sameList(contract.allowedRiskTiers, ["tier_0_offline"]) ||
    !sameList(campaign.allowedActionClasses, ["offline_simulation"]) ||
    !sameList(campaign.approvedRiskTiers, ["tier_0_offline"]) ||
    Date.parse(contract.validFrom) >= Date.parse(contract.validUntil)
  )
    throw new SecurityError("CAMPAIGN_CONTRACT_INVALID");
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
  if (!context.configurationValid)
    throw new SecurityError("CAMPAIGN_CONFIG_INVALID");
  if (context.killSwitchActive) throw new SecurityError("CAMPAIGN_KILL_SWITCH");
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
