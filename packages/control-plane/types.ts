export type ProgramLifecycle = "active" | "archived" | "inactive" | "paused";

export type AutomationPermission = "allowed" | "forbidden" | "unclear";

export interface ProgramRecord {
  readonly id: string;
  readonly name: string;
  readonly platform: "local_mock" | "manual";
  readonly status: "available" | "unavailable";
  readonly description: string;
  readonly programUrl: string;
  readonly programType: "private" | "public" | "simulation";
  readonly allowedAssets: readonly string[];
  readonly excludedAssets: readonly string[];
  readonly lastSynchronizedAt: string | null;
  readonly currentPolicyVersion: number | null;
  readonly currentPolicyHash: string | null;
  readonly automationPermission: AutomationPermission;
  readonly ruleAcceptanceStatus: "accepted" | "pending";
  readonly notes: string;
  readonly lifecycle: ProgramLifecycle;
  readonly createdAt: string;
}

export type CampaignState =
  | "approved"
  | "awaiting_campaign_approval"
  | "awaiting_policy_acceptance"
  | "blocked"
  | "cancelled"
  | "completed"
  | "draft"
  | "paused"
  | "running_simulation";

export interface CampaignContract {
  readonly allowedHosts: readonly string[];
  readonly excludedHosts: readonly string[];
  readonly maxRequests: number;
  readonly requestsPerMinute: number;
  readonly maxConcurrency: 1;
  readonly allowedRiskTiers: readonly ["tier_0_offline"];
  readonly allowedMethods: readonly ("GET" | "HEAD" | "OPTIONS")[];
  readonly writeActionsAllowed: false;
  readonly rollbackRequired: boolean;
  readonly humanCheckpoints: readonly string[];
  readonly validFrom: string;
  readonly validUntil: string;
  readonly policyHash: string;
}

export interface CampaignRecord {
  readonly id: string;
  readonly programId: string;
  readonly policyVersion: number;
  readonly policyHash: string;
  readonly approvedAssets: readonly string[];
  readonly approvedRiskTiers: readonly ["tier_0_offline"];
  readonly accountRefs: readonly string[];
  readonly allowedActionClasses: readonly ["offline_simulation"];
  readonly contract: CampaignContract;
  readonly state: CampaignState;
  readonly revision: number;
  readonly humanApprovedBy: string | null;
  readonly humanApprovedAt: string | null;
  readonly lastPolicyCheckAt: string | null;
  readonly killSwitchStatus: "clear" | "engaged";
  readonly createdAt: string;
}

export type TestIdentityRole = "External" | "Member" | "Owner";
export type TestIdentityStatus =
  | "awaiting_captcha"
  | "awaiting_email_verification"
  | "awaiting_manual_registration"
  | "awaiting_terms_acceptance"
  | "planned"
  | "ready"
  | "retired"
  | "session_expired"
  | "suspended";

export interface TestIdentityRecord {
  readonly id: string;
  readonly programId: string;
  readonly role: TestIdentityRole;
  readonly status: TestIdentityStatus;
  readonly emailReference: string | null;
  readonly secretReferences: readonly string[];
  readonly browserProfileReference: string | null;
  readonly platformAccountReference: string | null;
  readonly createdAt: string;
  readonly verifiedAt: string | null;
  readonly suspendedAt: string | null;
  readonly retiredAt: string | null;
  readonly lastSuccessfulLoginAt: string | null;
  readonly humanActionRequired: boolean;
  readonly organizationRef: string | null;
  readonly ownedObjectRefs: readonly string[];
}

export type ApprovalKind =
  | "account_manual_action"
  | "campaign_contract"
  | "external_action"
  | "privacy_alert"
  | "program_policy_acceptance"
  | "report_bundle"
  | "tier_3_action"
  | "triage_response";

export type ApprovalStatus = "accepted" | "open" | "rejected";

export interface ApprovalRecord {
  readonly id: string;
  readonly kind: ApprovalKind;
  readonly summary: string;
  readonly technicalDetails: string;
  readonly impact: string;
  readonly policyVersion: number | null;
  readonly policyHash: string | null;
  readonly createdAt: string;
  readonly status: ApprovalStatus;
  readonly decidedAt: string | null;
  readonly decidedBy: string | null;
  readonly userAction: string | null;
  readonly auditReference: string;
  readonly payloadHash: string;
  readonly revision: number;
}

export type PersistedExternalActionId =
  | "browser_journey_start"
  | "email_verification_open"
  | "platform_api_read"
  | "report_submit"
  | "target_request"
  | "test_account_register"
  | "triage_response_send";

export interface ExternalActionApprovalBindingRecord {
  readonly approvalId: string;
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly actionId: PersistedExternalActionId;
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
  readonly payloadRef: string | null;
  readonly operatorId: string;
  readonly createdAt: string;
  readonly expiresAt: string;
  readonly bindingDigest: string;
  readonly decisionAuditId: string | null;
}

export type ExternalActionAttemptStatus =
  "aborted" | "failed" | "reserved" | "running" | "succeeded";

export interface ExternalActionAttemptRecord {
  readonly authorizationId: string;
  readonly approvalId: string;
  readonly proposalId: string;
  readonly proposalDigest: string;
  readonly actionId: PersistedExternalActionId;
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
  readonly payloadRef: string | null;
  readonly operatorId: string;
  readonly evidenceDigest: string;
  readonly units: 1;
  readonly status: ExternalActionAttemptStatus;
  readonly reservedAt: string;
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
  readonly revision: number;
  readonly reservationAuditId: string;
}

export interface OwnedObjectRecord {
  readonly objectRef: string;
  readonly protectedActualIdRef: string;
  readonly programId: string;
  readonly campaignId: string;
  readonly accountId: string;
  readonly tenantRef: string;
  readonly objectType: string;
  readonly canaryHmac: string;
  readonly createdAt: string;
  readonly status: "active" | "deleted";
  readonly researcherControlled: true;
  readonly allowedActions: readonly string[];
  readonly expiresAt: string;
  readonly policyHash: string;
}

export interface ReportDraftRecord {
  readonly id: string;
  readonly campaignId: string;
  readonly title: string;
  readonly summary: string;
  readonly createdAt: string;
  readonly status: "draft" | "queued_for_human_review";
  readonly externalSubmissionPerformed: false;
}
