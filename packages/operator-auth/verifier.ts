import {
  createPublicKey,
  verify as ed25519Verify,
  type KeyObject,
} from "node:crypto";
import { sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import {
  assertStatementCurrent,
  canonicalApprovalDecisionStatement,
  canonicalKillSwitchClearStatement,
  canonicalOperatorEnrollmentStatement,
  decodeCanonicalBase64Url,
  validateAndFreezeOperatorCredential,
  validateAndFreezeOperatorEnrollmentProof,
  validateAndFreezeSignedApprovalDecision,
  validateAndFreezeSignedKillSwitchClearCommand,
} from "./envelope.js";
import type {
  ApprovalDecisionVerificationExpectations,
  KillSwitchClearVerificationExpectations,
  OperatorCredentialDescriptor,
  OperatorEnrollmentVerificationExpectations,
  SignedApprovalDecision,
  SignedKillSwitchClearCommand,
  SignedOperatorEnrollmentProof,
} from "./types.js";

export function verifyOperatorEnrollmentProof(
  value: unknown,
  expectations: OperatorEnrollmentVerificationExpectations,
): SignedOperatorEnrollmentProof {
  const proof = validateAndFreezeOperatorEnrollmentProof(value);
  if (
    proof.control_plane_id !== expectations.controlPlaneId ||
    proof.operator_id !== expectations.operatorId ||
    proof.key_revision !== expectations.keyRevision ||
    proof.session_id !== expectations.sessionId
  )
    throw new SecurityError("OPERATOR_STATEMENT_BINDING_INVALID");
  assertStatementCurrent(
    proof.issued_at,
    proof.expires_at,
    expectations.observedAt,
  );
  const credential = validateAndFreezeOperatorCredential({
    operator_id: proof.operator_id,
    public_key_spki_base64url: proof.public_key_spki_base64url,
    key_fingerprint_sha256: proof.key_fingerprint_sha256,
    key_revision: proof.key_revision,
  });
  const publicKey = importCredentialPublicKey(credential);
  verifyCanonicalSignature(
    publicKey,
    canonicalOperatorEnrollmentStatement(proof),
    proof.signature_base64url,
  );
  return proof;
}

export function verifySignedApprovalDecision(
  value: unknown,
  expectations: ApprovalDecisionVerificationExpectations,
): SignedApprovalDecision {
  const decision = validateAndFreezeSignedApprovalDecision(value);
  const credential = validateAndFreezeOperatorCredential(
    expectations.credential,
  );
  if (
    decision.control_plane_id !== expectations.controlPlaneId ||
    decision.operator_id !== credential.operator_id ||
    decision.key_fingerprint_sha256 !== credential.key_fingerprint_sha256 ||
    decision.key_revision !== credential.key_revision ||
    decision.session_id !== expectations.sessionId ||
    decision.approval_id !== expectations.approvalId ||
    decision.approval_kind !== expectations.approvalKind ||
    decision.approval_payload_hash_sha256 !==
      expectations.approvalPayloadHashSha256 ||
    decision.expected_revision !== expectations.expectedRevision ||
    decision.context_digest_sha256 !== expectations.contextDigestSha256
  )
    throw new SecurityError("OPERATOR_STATEMENT_BINDING_INVALID");
  assertStatementCurrent(
    decision.issued_at,
    decision.expires_at,
    expectations.observedAt,
  );
  verifyCanonicalSignature(
    importCredentialPublicKey(credential),
    canonicalApprovalDecisionStatement(decision),
    decision.signature_base64url,
  );
  return decision;
}

export function verifySignedKillSwitchClearCommand(
  value: unknown,
  expectations: KillSwitchClearVerificationExpectations,
): SignedKillSwitchClearCommand {
  const command = validateAndFreezeSignedKillSwitchClearCommand(value);
  const credential = validateAndFreezeOperatorCredential(
    expectations.credential,
  );
  if (
    command.control_plane_id !== expectations.controlPlaneId ||
    command.operator_id !== credential.operator_id ||
    command.key_fingerprint_sha256 !== credential.key_fingerprint_sha256 ||
    command.key_revision !== credential.key_revision ||
    command.session_id !== expectations.sessionId ||
    command.expected_revision !== expectations.expectedRevision ||
    command.context_digest_sha256 !== expectations.contextDigestSha256
  )
    throw new SecurityError("OPERATOR_STATEMENT_BINDING_INVALID");
  assertStatementCurrent(
    command.issued_at,
    command.expires_at,
    expectations.observedAt,
  );
  verifyCanonicalSignature(
    importCredentialPublicKey(credential),
    canonicalKillSwitchClearStatement(command),
    command.signature_base64url,
  );
  return command;
}

function importCredentialPublicKey(
  credential: OperatorCredentialDescriptor,
): KeyObject {
  try {
    const publicDer = decodeCanonicalBase64Url(
      credential.public_key_spki_base64url,
      null,
    );
    if (
      publicDer.byteLength === 0 ||
      publicDer.byteLength > 512 ||
      sha256(publicDer) !== credential.key_fingerprint_sha256
    )
      throw new Error("PUBLIC_KEY_BINDING_INVALID");
    const publicKey = createPublicKey({
      key: publicDer,
      format: "der",
      type: "spki",
    });
    if (publicKey.asymmetricKeyType !== "ed25519")
      throw new Error("PUBLIC_KEY_TYPE_INVALID");
    const canonicalDer = publicKey.export({ format: "der", type: "spki" });
    if (!canonicalDer.equals(publicDer))
      throw new Error("PUBLIC_KEY_DER_NON_CANONICAL");
    return publicKey;
  } catch {
    throw new SecurityError("OPERATOR_CREDENTIAL_INVALID");
  }
}

function verifyCanonicalSignature(
  publicKey: KeyObject,
  canonical: string,
  signatureBase64Url: string,
): void {
  try {
    const signature = decodeCanonicalBase64Url(signatureBase64Url, 64);
    if (
      !ed25519Verify(null, Buffer.from(canonical, "utf8"), publicKey, signature)
    )
      throw new Error("SIGNATURE_MISMATCH");
  } catch {
    throw new SecurityError("OPERATOR_SIGNATURE_INVALID");
  }
}
