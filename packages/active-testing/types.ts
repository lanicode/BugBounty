export const ACTIVE_TESTING_CAPABILITY = "HACKERONE_ACTIVE_TEST" as const;
export const ACTIVE_TEST_RUNNER_VERSION = "pilot-readiness-c-v1" as const;
export const ACTIVE_TEST_PLAN_VERSION = 1 as const;

export type ActiveTestClass =
  "cors_preflight" | "http_headers" | "security_txt";

export type ActiveTestMethod = "GET" | "HEAD" | "OPTIONS";

export interface ActiveTestingRuntimeInput {
  readonly version: 1;
  readonly capability: typeof ACTIVE_TESTING_CAPABILITY;
  readonly external_integrations_enabled: boolean;
  readonly enabled: boolean;
  readonly request_budget: {
    readonly max_requests_total: number;
    readonly requests_per_minute: number;
    readonly max_concurrency: 1;
  };
  readonly request_timeout_ms: number;
  readonly max_response_bytes: number;
}

export interface ActiveTestingRuntimeState {
  readonly version: 1;
  readonly capability: typeof ACTIVE_TESTING_CAPABILITY;
  readonly externalIntegrationsEnabled: boolean;
  readonly enabled: boolean;
  readonly configured: boolean;
  readonly requestBudget: {
    readonly maxRequestsTotal: number;
    readonly requestsPerMinute: number;
    readonly maxConcurrency: 1;
  };
  readonly requestTimeoutMs: number;
  readonly maxResponseBytes: number;
  readonly runnerVersion: typeof ACTIVE_TEST_RUNNER_VERSION;
}

export interface ActiveTestCatalogEntry {
  readonly id: ActiveTestClass;
  readonly displayName: string;
  readonly description: string;
  readonly method: ActiveTestMethod;
  readonly headerProfile: "cors_probe_v1" | "metadata_v1";
  readonly pathMode: "exact_scope_path" | "security_txt_root";
  readonly captureMode: "metadata_only";
  readonly maximumRequests: 1;
  readonly riskTier: "tier_1_public_read_only";
}

export interface ActiveTestAssetCandidate {
  readonly scopeId: string;
  readonly assetType: string;
  readonly displayIdentifier: string;
  readonly assetIdentifierDigest: string;
  readonly eligibleForSubmission: boolean;
  readonly eligibleForBounty: boolean;
  readonly supported: boolean;
  readonly reasonCodes: readonly ActiveTestAssetReasonCode[];
}

export type ActiveTestAssetReasonCode =
  | "ACTIVE_TEST_ASSET_IDENTIFIER_INVALID"
  | "ACTIVE_TEST_ASSET_TYPE_UNSUPPORTED"
  | "ACTIVE_TEST_SCOPE_BOUNTY_INELIGIBLE"
  | "ACTIVE_TEST_SCOPE_SUBMISSION_INELIGIBLE"
  | "ACTIVE_TEST_TARGET_NONCANONICAL"
  | "ACTIVE_TEST_TARGET_NOT_HTTPS"
  | "ACTIVE_TEST_TARGET_PATH_UNSUPPORTED"
  | "ACTIVE_TEST_TARGET_PORT_BLOCKED"
  | "ACTIVE_TEST_TARGET_WILDCARD_BLOCKED";

export interface ActiveTestPlanV1 {
  readonly version: typeof ACTIVE_TEST_PLAN_VERSION;
  readonly plan_id: string;
  readonly program_ref: string;
  readonly program_handle: string;
  readonly snapshot_digest: string;
  readonly policy_digest: string;
  readonly scope_id: string;
  readonly asset_identifier_digest: string;
  readonly test_class: ActiveTestClass;
  readonly runner_version: typeof ACTIVE_TEST_RUNNER_VERSION;
  readonly target: {
    readonly scheme: "https";
    readonly host: string;
    readonly port: 443;
    readonly path: string;
  };
  readonly request: {
    readonly method: ActiveTestMethod;
    readonly header_profile: "cors_probe_v1" | "metadata_v1";
    readonly capture_mode: "metadata_only";
    readonly follow_redirects: false;
    readonly retries: 0;
  };
  readonly budget: {
    readonly max_requests_total: 1;
    readonly requests_per_minute: 1;
    readonly max_concurrency: 1;
  };
  readonly confirmations: {
    readonly automation_permission_reviewed: true;
    readonly scope_instruction_reviewed: true;
    readonly scope_exclusions_reviewed: true;
    readonly no_side_effects_confirmed: true;
  };
  readonly created_at: string;
  readonly expires_at: string;
}

export interface CreateActiveTestPlanInput {
  readonly planId: string;
  readonly programRef: string;
  readonly snapshot: HackerOnePolicySnapshot;
  readonly scopeId: string;
  readonly assetIdentifierDigest: string;
  readonly testClass: ActiveTestClass;
  readonly createdAt: string;
  readonly confirmations: {
    readonly automationPermissionReviewed: boolean;
    readonly scopeInstructionReviewed: boolean;
    readonly scopeExclusionsReviewed: boolean;
    readonly noSideEffectsConfirmed: boolean;
  };
}

export type ActiveTestRedactedContentType =
  | "application/json"
  | "application/security.txt"
  | "text/html"
  | "text/plain"
  | null;

export type ActiveTestTlsProtocol = "TLSv1.2" | "TLSv1.3";
export type ActiveTestTlsCipherClassification = "modern" | "other_redacted";
export type ActiveTestTransportKind = "loopback_test" | "production_https";

export type ActiveTestResponseFacts =
  | {
      readonly kind: "cors_preflight";
      readonly allowOrigin:
        "absent" | "other_redacted" | "probe_origin" | "wildcard";
      readonly allowCredentials: boolean;
    }
  | {
      readonly kind: "http_headers";
      readonly contentSecurityPolicyPresent: boolean;
      readonly strictTransportSecurityPresent: boolean;
      readonly xContentTypeOptionsNosniff: boolean;
      readonly insecureCookieFlagsObserved: boolean;
    }
  | {
      readonly kind: "security_txt";
      readonly availability: "available" | "missing";
    };

/**
 * Closed, already-redacted metadata accepted by the local evidence analyzer.
 * It deliberately contains classifications rather than raw response headers
 * or body material.
 */
export interface ActiveTestRedactedResponseMetadata {
  readonly version: 1;
  readonly planId: string;
  readonly planDigest: string;
  readonly testClass: ActiveTestClass;
  readonly statusCode: number;
  readonly durationMs: number;
  readonly responseBytesObserved: number;
  readonly contentType: ActiveTestRedactedContentType;
  readonly redirectLocationPresent: false;
  readonly tls: {
    readonly authorized: true;
    readonly protocol: ActiveTestTlsProtocol;
    readonly cipher: ActiveTestTlsCipherClassification;
  };
  readonly transport: {
    readonly kind: ActiveTestTransportKind;
    readonly resolutionDigest: string;
  };
  readonly facts: ActiveTestResponseFacts;
  readonly responseDigest: string | null;
  readonly redaction: {
    readonly status: "complete";
    readonly rawBodyStored: false;
    readonly rawHeadersStored: false;
    readonly cookiesStored: false;
  };
  readonly completedAt: string;
}

/** Metadata before a concrete, privately branded transport attests it. */
export type UnattestedActiveTestResponseMetadata = Omit<
  ActiveTestRedactedResponseMetadata,
  "transport"
>;

export interface ActiveTestObservation {
  readonly version: 1;
  readonly planId: string;
  readonly planDigest: string;
  readonly metadataDigest: string;
  readonly testClass: ActiveTestClass;
  readonly statusCode: number;
  readonly durationMs: number;
  readonly responseBytesObserved: number;
  readonly contentType: ActiveTestRedactedContentType;
  readonly redirectLocationPresent: false;
  readonly tls: {
    readonly authorized: true;
    readonly protocol: ActiveTestTlsProtocol;
    readonly cipher: ActiveTestTlsCipherClassification;
  };
  readonly transportKind: ActiveTestTransportKind;
  readonly resolutionDigest: string;
  readonly signals: readonly ActiveTestSignal[];
  readonly responseDigest: string | null;
  readonly rawBodyStored: false;
  readonly rawHeadersStored: false;
  readonly cookiesStored: false;
  readonly completedAt: string;
}

export interface ActiveTestSignal {
  readonly code:
    | "CORS_CREDENTIALS_WITH_REFLECTED_ORIGIN"
    | "CORS_REFLECTS_PROBE_ORIGIN"
    | "HEADER_CONTENT_SECURITY_POLICY_MISSING"
    | "HEADER_HSTS_MISSING"
    | "HEADER_X_CONTENT_TYPE_OPTIONS_MISSING"
    | "INSECURE_COOKIE_FLAGS_OBSERVED"
    | "SECURITY_TXT_AVAILABLE"
    | "SECURITY_TXT_MISSING";
  readonly severity: "informational" | "low" | "medium";
  readonly evidence: string;
}

export interface ActiveTestReportDraft {
  readonly version: 1;
  readonly reportId: string;
  readonly planId: string;
  readonly planDigest: string;
  readonly snapshotDigest: string;
  readonly policyDigest: string;
  readonly assetIdentifierDigest: string;
  readonly responseMetadataDigest: string;
  readonly observationDigest: string;
  readonly transportKind: ActiveTestTransportKind;
  readonly resolutionDigest: string;
  readonly reviewStatus: "local_draft_unsubmitted";
  readonly externalSubmissionPerformed: false;
  readonly markdown: string;
  readonly markdownDigest: string;
  readonly json: string;
  readonly jsonDigest: string;
  readonly createdAt: string;
}
import type { HackerOnePolicySnapshot } from "../hackerone-readonly/index.js";
