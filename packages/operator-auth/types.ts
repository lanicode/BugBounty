import type { SecretStore } from "../secret-store/store.js";

export const OPERATOR_ENROLLMENT_DOMAIN =
  "bugbounty-copilot:control-plane:operator-enrollment:v1" as const;
export const APPROVAL_DECISION_DOMAIN =
  "bugbounty-copilot:control-plane:approval-decision:v1" as const;
export const KILL_SWITCH_CLEAR_DOMAIN =
  "bugbounty-copilot:control-plane:kill-switch-clear:v1" as const;

export const OPERATOR_STATEMENT_MAX_LIFETIME_MS = 5 * 60 * 1_000;

export type OperatorApprovalKind =
  | "account_manual_action"
  | "campaign_contract"
  | "external_action"
  | "privacy_alert"
  | "program_policy_acceptance"
  | "report_bundle"
  | "tier_3_action"
  | "triage_response";

export interface OperatorCredentialDescriptor {
  readonly operator_id: string;
  readonly public_key_spki_base64url: string;
  readonly key_fingerprint_sha256: string;
  readonly key_revision: number;
}

export interface OperatorEnrollmentStatement {
  readonly version: 1;
  readonly domain: typeof OPERATOR_ENROLLMENT_DOMAIN;
  readonly control_plane_id: string;
  readonly operator_id: string;
  readonly public_key_spki_base64url: string;
  readonly key_fingerprint_sha256: string;
  readonly key_revision: number;
  readonly session_id: string;
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
}

export interface SignedOperatorEnrollmentProof extends OperatorEnrollmentStatement {
  readonly signature_base64url: string;
}

export interface ApprovalDecisionStatement {
  readonly version: 1;
  readonly domain: typeof APPROVAL_DECISION_DOMAIN;
  readonly control_plane_id: string;
  readonly approval_id: string;
  readonly approval_kind: OperatorApprovalKind;
  readonly approval_payload_hash_sha256: string;
  readonly expected_revision: number;
  readonly decision: "accepted" | "rejected";
  readonly user_action: string;
  readonly operator_id: string;
  readonly key_fingerprint_sha256: string;
  readonly key_revision: number;
  readonly context_digest_sha256: string;
  readonly session_id: string;
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
}

export interface SignedApprovalDecision extends ApprovalDecisionStatement {
  readonly signature_base64url: string;
}

export interface KillSwitchClearStatement {
  readonly version: 1;
  readonly domain: typeof KILL_SWITCH_CLEAR_DOMAIN;
  readonly control_plane_id: string;
  readonly command: "clear";
  readonly expected_revision: number;
  readonly user_action: string;
  readonly operator_id: string;
  readonly key_fingerprint_sha256: string;
  readonly key_revision: number;
  readonly context_digest_sha256: string;
  readonly session_id: string;
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
}

export interface SignedKillSwitchClearCommand extends KillSwitchClearStatement {
  readonly signature_base64url: string;
}

export interface OperatorEnrollmentSigningInput {
  readonly controlPlaneId: string;
  readonly sessionId: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface ApprovalDecisionSigningInput {
  readonly controlPlaneId: string;
  readonly approvalId: string;
  readonly approvalKind: OperatorApprovalKind;
  readonly approvalPayloadHashSha256: string;
  readonly expectedRevision: number;
  readonly decision: "accepted" | "rejected";
  readonly userAction: string;
  readonly contextDigestSha256: string;
  readonly sessionId: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface KillSwitchClearSigningInput {
  readonly controlPlaneId: string;
  readonly expectedRevision: number;
  readonly userAction: string;
  readonly contextDigestSha256: string;
  readonly sessionId: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface OperatorSigner {
  readonly credential: OperatorCredentialDescriptor;
  signEnrollment(
    input: OperatorEnrollmentSigningInput,
  ): SignedOperatorEnrollmentProof;
  signApprovalDecision(
    input: ApprovalDecisionSigningInput,
  ): SignedApprovalDecision;
  signKillSwitchClear(
    input: KillSwitchClearSigningInput,
  ): SignedKillSwitchClearCommand;
}

export interface KeychainOperatorSignerOptions {
  readonly keyReference: string;
  readonly operatorId: string;
  readonly keyRevision: number;
}

export interface OperatorEnrollmentVerificationExpectations {
  readonly controlPlaneId: string;
  readonly operatorId: string;
  readonly keyRevision: number;
  readonly sessionId: string;
  readonly observedAt: string;
}

export interface ApprovalDecisionVerificationExpectations {
  readonly controlPlaneId: string;
  readonly credential: OperatorCredentialDescriptor;
  readonly sessionId: string;
  readonly observedAt: string;
  readonly approvalId: string;
  readonly approvalKind: OperatorApprovalKind;
  readonly approvalPayloadHashSha256: string;
  readonly expectedRevision: number;
  readonly contextDigestSha256: string;
}

export interface KillSwitchClearVerificationExpectations {
  readonly controlPlaneId: string;
  readonly credential: OperatorCredentialDescriptor;
  readonly sessionId: string;
  readonly observedAt: string;
  readonly expectedRevision: number;
  readonly contextDigestSha256: string;
}

export type OperatorSigningSecretStore = Pick<SecretStore, "get">;
