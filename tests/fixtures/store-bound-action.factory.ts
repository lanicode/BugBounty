import { ApprovalQueue } from "../../packages/control-plane/approval-queue.js";
import { campaignApprovalDigest } from "../../packages/control-plane/campaign-machine.js";
import type {
  CampaignRecord,
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  enqueueStoreBoundExternalActionApproval,
  prepareStoreBoundExternalActionProposal,
  type ExternalActionProposal,
} from "../../packages/external-actions/index.js";
import type { ExternalActionId } from "../../packages/external-actions/registry.js";
import {
  campaign,
  controlPlanePolicy,
  identity,
  LATER,
  NOW,
  ownedObject,
  programInput,
} from "./control-plane.factory.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
  decideTestApproval,
  TEST_OPERATOR_ID,
} from "./operator-auth.factory.js";

export const ACTION_TIME = "2026-07-13T14:00:00.000Z";
export const ACTION_DECISION_TIME = "2026-07-13T14:00:01.000Z";
export const ACTION_EXECUTION_TIME = "2026-07-13T14:00:02.000Z";
export const ACTION_OPERATOR = TEST_OPERATOR_ID;

export interface SeededStoreBoundAction {
  readonly store: ControlPlaneStore;
  readonly campaign: CampaignRecord;
  readonly proposal: ExternalActionProposal;
  readonly approvalId: string;
}

export interface RunningCampaignSeedOptions {
  readonly programId: string;
  readonly campaignId: string;
  readonly namespace: string;
  readonly clearKillSwitch: boolean;
  readonly maxRequests: number;
  readonly requestsPerMinute: number;
  readonly approvalTime: string;
}

export function seedStoreBoundAction(
  database: ControlPlaneDatabase,
  actionId: ExternalActionId = "target_request",
  suffix = "1",
): SeededStoreBoundAction {
  const store = createTestControlPlaneStore(database, NOW);
  const running = seedRunningCampaign(store);
  const needsAccount =
    actionId === "browser_journey_start" ||
    actionId === "email_verification_open" ||
    actionId === "target_request";
  const needsObject = actionId === "target_request";
  if (needsAccount) store.insertIdentity(identity());
  if (needsObject)
    store.insertOwnedObject(ownedObject({ policyHash: running.policyHash }));
  const proposal = prepareStoreBoundExternalActionProposal(store, {
    proposalId: `proposal-${suffix}`,
    actionId,
    campaignRef: running.id,
    accountRef: needsAccount ? "identity-owner" : null,
    objectRef: needsObject ? "object-local" : null,
    payloadRef: null,
    approvalRef: `action-approval-${suffix}`,
    operatorRef: ACTION_OPERATOR,
  });
  const approval = enqueueStoreBoundExternalActionApproval(store, proposal);
  decideTestApproval(store, {
    approvalId: approval.id,
    decision: "accepted",
    userAction: "approve_store_bound_external_action",
    issuedAt: ACTION_DECISION_TIME,
  });
  return Object.freeze({
    store,
    campaign: running,
    proposal,
    approvalId: approval.id,
  });
}

export function seedRunningCampaign(
  store: ControlPlaneStore,
  options: Partial<RunningCampaignSeedOptions> = {},
): CampaignRecord {
  const programId = options.programId ?? "program-local";
  const campaignId = options.campaignId ?? "campaign-local";
  const namespace = options.namespace ?? "action";
  const approvalTime = options.approvalTime ?? LATER;
  const program = programInput();
  store.createProgram(
    programId === program.id
      ? program
      : {
          ...program,
          id: programId,
          name: `Local Mock Program ${namespace}`,
          programUrl: `https://program.invalid/${namespace}-metadata-only`,
        },
    NOW,
  );
  const policy = controlPlanePolicy();
  store.addPolicyVersion({
    programId,
    version: 1,
    policy,
    createdAt: NOW,
  });
  if ((options.clearKillSwitch ?? true) && store.isKillSwitchActive())
    clearTestKillSwitch(store, NOW);
  const policyApproval = new ApprovalQueue().enqueue({
    id: `policy-${namespace}-approval`,
    kind: "program_policy_acceptance",
    summary: `Accept ${programId} policy version 1`,
    technicalDetails: `Policy hash ${policy.policyHash}`,
    impact: "Allows deterministic local simulation only.",
    policyVersion: 1,
    policyHash: policy.policyHash,
    createdAt: NOW,
    auditReference: `audit:${namespace}-policy`,
  });
  store.persistApproval(policyApproval);
  decideTestApproval(store, {
    approvalId: policyApproval.id,
    decision: "accepted",
    userAction: "explicit_policy_acceptance",
    issuedAt: approvalTime,
  });
  store.acceptPolicy({
    programId,
    version: 1,
    expectedPolicyHash: policy.policyHash,
    acceptedBy: ACTION_OPERATOR,
    acceptedAt: approvalTime,
    auditReference: `audit:${namespace}-policy`,
  });
  const base = campaign();
  const contract = Object.freeze({
    ...base.contract,
    maxRequests: options.maxRequests ?? base.contract.maxRequests,
    requestsPerMinute:
      options.requestsPerMinute ?? base.contract.requestsPerMinute,
  });
  const draft = campaign({
    id: campaignId,
    programId,
    policyHash: policy.policyHash,
    contract,
    accountRefs:
      programId === "program-local"
        ? Object.freeze(["identity-owner"])
        : Object.freeze([`identity-${namespace}`]),
  });
  store.insertCampaign(draft);
  const awaiting = campaign({
    id: campaignId,
    programId,
    policyHash: policy.policyHash,
    contract,
    accountRefs: draft.accountRefs,
    state: "awaiting_campaign_approval",
    revision: 1,
  });
  store.updateCampaign(0, awaiting);
  const campaignApproval = new ApprovalQueue().enqueue({
    id: `campaign-${namespace}-approval`,
    kind: "campaign_contract",
    summary: `Approve ${campaignId}`,
    technicalDetails: `Policy ${policy.policyHash}; Campaign digest ${campaignApprovalDigest(awaiting)}; tier_0_offline only`,
    impact: "Allows deterministic local simulation only.",
    policyVersion: 1,
    policyHash: policy.policyHash,
    createdAt: NOW,
    auditReference: `audit:${namespace}-campaign`,
  });
  store.persistApproval(campaignApproval);
  decideTestApproval(store, {
    approvalId: campaignApproval.id,
    decision: "accepted",
    userAction: "explicit_local_campaign_v1_approval",
    issuedAt: approvalTime,
  });
  store.updateCampaign(
    1,
    campaign({
      id: campaignId,
      programId,
      policyHash: policy.policyHash,
      contract,
      accountRefs: draft.accountRefs,
      state: "approved",
      revision: 2,
      humanApprovedBy: ACTION_OPERATOR,
      humanApprovedAt: approvalTime,
    }),
  );
  const running = campaign({
    id: campaignId,
    programId,
    policyHash: policy.policyHash,
    contract,
    accountRefs: draft.accountRefs,
    state: "running_simulation",
    revision: 3,
    humanApprovedBy: ACTION_OPERATOR,
    humanApprovedAt: approvalTime,
    lastPolicyCheckAt: approvalTime,
  });
  store.updateCampaign(2, running);
  return running;
}
