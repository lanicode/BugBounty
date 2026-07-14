import type { ExternalActionProposal } from "../external-actions/proposal.js";
import type {
  ExternalActionId,
  ExternalActionTargetClass,
} from "../external-actions/registry.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { campaignApprovalDigest } from "./campaign-machine.js";
import type {
  CampaignRecord,
  OwnedObjectRecord,
  TestIdentityRecord,
  TestIdentityRole,
} from "./types.js";

export interface ExternalActionEvidenceDefinition {
  readonly actionId: ExternalActionId;
  readonly targetClass: ExternalActionTargetClass;
  readonly ownershipCheck: "account" | "not_applicable" | "object";
  readonly ownedObjectAction: "offline_inspect" | null;
  readonly budgetUnits: 1;
}

export interface ExternalActionProposalContext {
  readonly programId: string;
  readonly campaignId: string;
  readonly campaignRevision: number;
  readonly campaignDigest: string;
  readonly policyVersion: number;
  readonly policyHash: string;
  readonly scopeRef: string;
  readonly accountId: string | null;
  readonly accountRole: TestIdentityRole | null;
  readonly identityDigest: string | null;
  readonly objectRef: string | null;
  readonly ownershipDigest: string | null;
  readonly payloadRef: null;
}

export interface ExternalActionApprovalBinding extends ExternalActionProposalContext {
  readonly approvalId: string;
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly actionId: ExternalActionId;
  readonly operatorId: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly bindingDigest: string;
  readonly decisionAuditId: string | null;
}

export interface StoreBoundExternalActionAuthorization extends ExternalActionApprovalBinding {
  readonly authorizationId: string;
  readonly evidenceDigest: string;
  readonly approvalPayloadHash: string;
  readonly approvalRevision: 1;
  readonly reservationAuditId: string;
  readonly reservedAt: string;
  readonly units: 1;
}

export function externalActionCampaignDigest(campaign: CampaignRecord): string {
  return sha256(
    canonicalJson({
      id: campaign.id,
      programId: campaign.programId,
      revision: campaign.revision,
      state: campaign.state,
      approvalDigest: campaignApprovalDigest(campaign),
      humanApprovedBy: campaign.humanApprovedBy,
      humanApprovedAt: campaign.humanApprovedAt,
      lastPolicyCheckAt: campaign.lastPolicyCheckAt,
      killSwitchStatus: campaign.killSwitchStatus,
      createdAt: campaign.createdAt,
    }),
  );
}

export function externalActionIdentityDigest(
  identity: TestIdentityRecord,
): string {
  return sha256(
    canonicalJson({
      id: identity.id,
      programId: identity.programId,
      role: identity.role,
      status: identity.status,
      emailReference: identity.emailReference,
      secretReferences: identity.secretReferences,
      browserProfileReference: identity.browserProfileReference,
      platformAccountReference: identity.platformAccountReference,
      createdAt: identity.createdAt,
      verifiedAt: identity.verifiedAt,
      suspendedAt: identity.suspendedAt,
      retiredAt: identity.retiredAt,
      lastSuccessfulLoginAt: identity.lastSuccessfulLoginAt,
      humanActionRequired: identity.humanActionRequired,
      organizationRef: identity.organizationRef,
      ownedObjectRefs: identity.ownedObjectRefs,
    }),
  );
}

export function externalActionOwnershipDigest(
  object: OwnedObjectRecord,
): string {
  return sha256(
    canonicalJson({
      objectRef: object.objectRef,
      protectedActualIdRef: object.protectedActualIdRef,
      programId: object.programId,
      campaignId: object.campaignId,
      accountId: object.accountId,
      tenantRef: object.tenantRef,
      objectType: object.objectType,
      canaryHmac: object.canaryHmac,
      createdAt: object.createdAt,
      status: object.status,
      researcherControlled: object.researcherControlled,
      allowedActions: object.allowedActions,
      expiresAt: object.expiresAt,
      policyHash: object.policyHash,
    }),
  );
}

export function externalActionScopeReference(input: {
  readonly definition: ExternalActionEvidenceDefinition;
  readonly campaign: CampaignRecord;
  readonly policyVersion: number;
  readonly policyHash: string;
  readonly identity: TestIdentityRecord | null;
  readonly object: OwnedObjectRecord | null;
}): string {
  const identityDigest =
    input.identity === null
      ? null
      : externalActionIdentityDigest(input.identity);
  const ownershipDigest =
    input.object === null ? null : externalActionOwnershipDigest(input.object);
  return `scope-${sha256(
    canonicalJson({
      actionId: input.definition.actionId,
      targetClass: input.definition.targetClass,
      programId: input.campaign.programId,
      campaignId: input.campaign.id,
      campaignRevision: input.campaign.revision,
      campaignDigest: externalActionCampaignDigest(input.campaign),
      policyVersion: input.policyVersion,
      policyHash: input.policyHash,
      approvedAssets: input.campaign.approvedAssets,
      excludedAssets: input.campaign.contract.excludedHosts,
      allowedMethods: input.campaign.contract.allowedMethods,
      allowedRiskTiers: input.campaign.approvedRiskTiers,
      allowedActionClasses: input.campaign.allowedActionClasses,
      accountId: input.identity?.id ?? null,
      accountRole: input.identity?.role ?? null,
      organizationRef: input.identity?.organizationRef ?? null,
      identityDigest,
      objectRef: input.object?.objectRef ?? null,
      ownershipDigest,
    }),
  )}`;
}

export function externalActionApprovalBindingDigest(
  input: Omit<ExternalActionApprovalBinding, "bindingDigest">,
): string {
  return sha256(
    canonicalJson({
      approvalId: input.approvalId,
      proposalId: input.proposalId,
      proposalDigest: input.proposalDigest,
      actionId: input.actionId,
      programId: input.programId,
      campaignId: input.campaignId,
      campaignRevision: input.campaignRevision,
      campaignDigest: input.campaignDigest,
      policyVersion: input.policyVersion,
      policyHash: input.policyHash,
      scopeRef: input.scopeRef,
      accountId: input.accountId,
      accountRole: input.accountRole,
      identityDigest: input.identityDigest,
      objectRef: input.objectRef,
      ownershipDigest: input.ownershipDigest,
      payloadRef: input.payloadRef,
      operatorId: input.operatorId,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
    }),
  );
}

export function externalActionEvidenceDigest(input: {
  readonly binding: ExternalActionApprovalBinding;
  readonly approvalPayloadHash: string;
  readonly approvalRevision: 1;
}): string {
  return sha256(
    canonicalJson({
      bindingDigest: input.binding.bindingDigest,
      decisionAuditId: input.binding.decisionAuditId,
      approvalPayloadHash: input.approvalPayloadHash,
      approvalRevision: input.approvalRevision,
    }),
  );
}

export function proposalMatchesContext(
  proposal: ExternalActionProposal,
  context: ExternalActionProposalContext,
): boolean {
  const parameters = proposal.parameters;
  return (
    parameters.program_ref === context.programId &&
    parameters.campaign_ref === context.campaignId &&
    parameters.campaign_revision === context.campaignRevision &&
    parameters.campaign_digest === context.campaignDigest &&
    parameters.policy_version === context.policyVersion &&
    parameters.policy_hash_sha256 === context.policyHash &&
    parameters.scope_ref === context.scopeRef &&
    parameters.account_ref === context.accountId &&
    parameters.account_role === context.accountRole &&
    parameters.object_ref === context.objectRef &&
    parameters.payload_ref === context.payloadRef
  );
}
