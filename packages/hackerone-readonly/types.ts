export const HACKERONE_API_ORIGIN = "https://api.hackerone.com:443";
export const HACKERONE_API_HOST = "api.hackerone.com";
export const HACKERONE_API_PORT = 443;
export const HACKERONE_ADAPTER_VERSION = "pilot-readiness-a-v1";
export const HACKERONE_SCHEMA_VERSION = 1;
export const HACKERONE_IDENTIFIER_REFERENCE =
  "keychain://bugbounty-copilot/hackerone-api-identifier";
export const HACKERONE_TOKEN_REFERENCE =
  "keychain://bugbounty-copilot/hackerone-api-token";

export type HackerOneDataSource =
  "hackerone_api_authenticated" | "manual_unverified";

export type HackerOneConnectionResult =
  | "blocked_by_kill_switch"
  | "blocked_by_policy"
  | "connected"
  | "invalid_credentials"
  | "malformed_response"
  | "rate_limited"
  | "secret_store_unavailable"
  | "unauthorized"
  | "unavailable";

export interface HackerOneProgram {
  readonly hackerOneId: string;
  readonly handle: string;
  readonly name: string;
  readonly currency: string;
  readonly policy: string;
  readonly submissionState: string;
  readonly programState: string;
  readonly offersBounties: boolean;
  readonly openScope: boolean;
  readonly goldStandardSafeHarbor: boolean;
  readonly bookmarked: boolean;
  readonly ownReportCount: number;
  readonly ownValidReportCount: number;
  readonly startedAcceptingAt: string | null;
  readonly createdAt: string | null;
  readonly updatedAt: string | null;
  readonly synchronizedAt: string;
  readonly source: HackerOneDataSource;
}

export interface HackerOneStructuredScope {
  readonly id: string;
  readonly assetType: string;
  readonly assetIdentifier: string;
  readonly assetIdentifierDigest: string;
  readonly eligibleForSubmission: boolean;
  readonly eligibleForBounty: boolean;
  readonly instruction: string;
  readonly maximumSeverity: string | null;
  readonly createdAt: string | null;
  readonly updatedAt: string | null;
  readonly confidentialityRequirement: string | null;
  readonly integrityRequirement: string | null;
  readonly availabilityRequirement: string | null;
}

export interface HackerOneScopeExclusion {
  readonly id: string;
  readonly category: string;
  readonly details: string;
  readonly createdAt: string | null;
  readonly updatedAt: string | null;
}

export type HackerOneAutomationPermission =
  "allowed" | "forbidden" | "unknown_requires_human_review";

export type HackerOneSuitabilityReason =
  | "BOUNTIES_AVAILABLE"
  | "BOUNTIES_UNAVAILABLE"
  | "OPEN_SUBMISSIONS"
  | "POLICY_MISSING"
  | "POLICY_PRESENT"
  | "SAFE_HARBOR_PRESENT"
  | "SCOPE_EXCLUSIONS_PRESENT"
  | "STRUCTURED_SCOPE_CLEAR"
  | "STRUCTURED_SCOPE_MISSING"
  | "WEB_OR_API_ASSET_PRESENT";

export interface HackerOneProgramSuitability {
  readonly score: number;
  readonly reasons: readonly HackerOneSuitabilityReason[];
  readonly automationPermission: HackerOneAutomationPermission;
  readonly accountWorkflows: "manual_review_required";
  readonly legalDecisionMade: false;
}

export interface HackerOnePolicySnapshot {
  readonly program: HackerOneProgram;
  readonly structuredScopes: readonly HackerOneStructuredScope[];
  readonly scopeExclusions: readonly HackerOneScopeExclusion[];
  readonly fetchedAt: string;
  readonly adapterVersion: typeof HACKERONE_ADAPTER_VERSION;
  readonly schemaVersion: typeof HACKERONE_SCHEMA_VERSION;
  readonly snapshotDigest: string;
  readonly policyDigest: string;
  readonly previousSnapshotDigest: string | null;
  readonly suitability: HackerOneProgramSuitability;
  readonly source: HackerOneDataSource;
}

export type HackerOnePolicyChangeCode =
  | "BOUNTY_ELIGIBILITY_CHANGED"
  | "INSTRUCTIONS_CHANGED"
  | "MAXIMUM_SEVERITY_CHANGED"
  | "OPEN_SCOPE_CHANGED"
  | "POLICY_TEXT_CHANGED"
  | "PROGRAM_STATE_CHANGED"
  | "SAFE_HARBOR_CHANGED"
  | "SCOPE_EXCLUSIONS_CHANGED"
  | "SCOPES_CHANGED"
  | "SUBMISSION_ELIGIBILITY_CHANGED";

export interface HackerOnePolicyDrift {
  readonly changed: boolean;
  readonly changes: readonly HackerOnePolicyChangeCode[];
  readonly campaignsPaused: boolean;
  readonly requiresHumanAcceptance: boolean;
}

export interface HackerOneIntegrationStatus {
  readonly actionClass: "HACKERONE_METADATA_READ";
  readonly status: "configured" | "connected" | "deactivated" | "error";
  readonly externalIntegrationsEnabled: boolean;
  readonly adapterConfigured: boolean;
  readonly adapterEnabled: boolean;
  readonly killSwitchActive: boolean;
  readonly identifierPresent: boolean;
  readonly tokenPresent: boolean;
  readonly tokenFingerprint: string | null;
  readonly lastConnectionTestAt: string | null;
  readonly lastSuccessfulConnectionAt: string | null;
  readonly lastConnectionResult: HackerOneConnectionResult | null;
  readonly lastSynchronizationAt: string | null;
  readonly lastSynchronizationResult: "failed" | "succeeded" | null;
  readonly importedProgramCount: number;
  readonly lastErrorCode: string | null;
  readonly selectedHandle: string | null;
  readonly apiMode: "read_only";
  readonly targetRequestsEnabled: false;
  readonly reportSubmissionEnabled: false;
}

export interface HackerOneRequestAuditEvent {
  readonly requestId: string;
  readonly actionClass: "HACKERONE_METADATA_READ";
  readonly endpointClass:
    | "program"
    | "programs"
    | "scope_exclusions"
    | "structured_scopes"
    | "weaknesses";
  readonly outcome: string;
  readonly statusCode: number | null;
  readonly durationMs: number;
}

export interface HackerOneConnectionTestSummary {
  readonly result: HackerOneConnectionResult;
  readonly recordCount: number;
  readonly schemaValid: boolean;
  readonly durationMs: number;
  readonly redactedStatus: string;
}

export interface HackerOneProgramSyncResult {
  readonly programCount: number;
  readonly pages: number;
  readonly synchronizedAt: string;
}

export interface HackerOneProgramSelectionResult {
  readonly snapshot: HackerOnePolicySnapshot;
  readonly drift: HackerOnePolicyDrift;
}

export interface HackerOneManualImportDocument {
  readonly version: 1;
  readonly source: "manual_unverified";
  readonly program: Omit<HackerOneProgram, "source" | "synchronizedAt">;
  readonly structuredScopes: readonly Omit<
    HackerOneStructuredScope,
    "assetIdentifierDigest"
  >[];
  readonly scopeExclusions: readonly HackerOneScopeExclusion[];
  readonly importedAt: string;
}
