import { types } from "node:util";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import {
  APPROVAL_DECISION_DOMAIN,
  KILL_SWITCH_CLEAR_DOMAIN,
  OPERATOR_ENROLLMENT_DOMAIN,
  OPERATOR_STATEMENT_MAX_LIFETIME_MS,
  type ApprovalDecisionStatement,
  type KillSwitchClearStatement,
  type OperatorApprovalKind,
  type OperatorCredentialDescriptor,
  type OperatorEnrollmentStatement,
  type SignedApprovalDecision,
  type SignedKillSwitchClearCommand,
  type SignedOperatorEnrollmentProof,
} from "./types.js";

const CREDENTIAL_KEYS = Object.freeze([
  "key_fingerprint_sha256",
  "key_revision",
  "operator_id",
  "public_key_spki_base64url",
] as const);

const ENROLLMENT_KEYS = Object.freeze([
  "control_plane_id",
  "domain",
  "expires_at",
  "issued_at",
  "key_fingerprint_sha256",
  "key_revision",
  "nonce",
  "operator_id",
  "public_key_spki_base64url",
  "session_id",
  "version",
] as const);

const APPROVAL_KEYS = Object.freeze([
  "approval_id",
  "approval_kind",
  "approval_payload_hash_sha256",
  "context_digest_sha256",
  "control_plane_id",
  "decision",
  "domain",
  "expected_revision",
  "expires_at",
  "issued_at",
  "key_fingerprint_sha256",
  "key_revision",
  "nonce",
  "operator_id",
  "session_id",
  "user_action",
  "version",
] as const);

const KILL_CLEAR_KEYS = Object.freeze([
  "command",
  "context_digest_sha256",
  "control_plane_id",
  "domain",
  "expected_revision",
  "expires_at",
  "issued_at",
  "key_fingerprint_sha256",
  "key_revision",
  "nonce",
  "operator_id",
  "session_id",
  "user_action",
  "version",
] as const);

const SIGNATURE_KEY = "signature_base64url" as const;
const SIGNED_ENROLLMENT_KEYS = Object.freeze([
  ...ENROLLMENT_KEYS,
  SIGNATURE_KEY,
] as const);
const SIGNED_APPROVAL_KEYS = Object.freeze([
  ...APPROVAL_KEYS,
  SIGNATURE_KEY,
] as const);
const SIGNED_KILL_CLEAR_KEYS = Object.freeze([
  ...KILL_CLEAR_KEYS,
  SIGNATURE_KEY,
] as const);

const HEX_SHA256 = /^[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9_-]{1,128}$/u;
const OPERATOR_ID = /^[A-Za-z0-9._@-]{1,128}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;

export function validateAndFreezeOperatorCredential(
  value: unknown,
): OperatorCredentialDescriptor {
  return sanitize("OPERATOR_CREDENTIAL_INVALID", () => {
    const record = cloneExactDataRecord(value, CREDENTIAL_KEYS);
    const operatorId = requiredOperatorId(record["operator_id"]);
    const publicKey = requiredBase64Url(
      record["public_key_spki_base64url"],
      null,
    );
    if (decodeCanonicalBase64Url(publicKey, null).byteLength > 512)
      throw new Error("PUBLIC_KEY_TOO_LARGE");
    return Object.freeze({
      operator_id: operatorId,
      public_key_spki_base64url: publicKey,
      key_fingerprint_sha256: requiredSha256(record["key_fingerprint_sha256"]),
      key_revision: requiredPositiveInteger(record["key_revision"]),
    });
  });
}

export function validateAndFreezeOperatorEnrollmentStatement(
  value: unknown,
): OperatorEnrollmentStatement {
  return sanitize("OPERATOR_ENROLLMENT_INVALID", () =>
    enrollmentStatementFromRecord(cloneExactDataRecord(value, ENROLLMENT_KEYS)),
  );
}

export function validateAndFreezeOperatorEnrollmentProof(
  value: unknown,
): SignedOperatorEnrollmentProof {
  return sanitize("OPERATOR_ENROLLMENT_INVALID", () => {
    const record = cloneExactDataRecord(value, SIGNED_ENROLLMENT_KEYS);
    return Object.freeze({
      ...enrollmentStatementFromRecord(record),
      signature_base64url: requiredBase64Url(record[SIGNATURE_KEY], 64),
    });
  });
}

export function validateAndFreezeApprovalDecisionStatement(
  value: unknown,
): ApprovalDecisionStatement {
  return sanitize("OPERATOR_APPROVAL_DECISION_INVALID", () =>
    approvalStatementFromRecord(cloneExactDataRecord(value, APPROVAL_KEYS)),
  );
}

export function validateAndFreezeSignedApprovalDecision(
  value: unknown,
): SignedApprovalDecision {
  return sanitize("OPERATOR_APPROVAL_DECISION_INVALID", () => {
    const record = cloneExactDataRecord(value, SIGNED_APPROVAL_KEYS);
    return Object.freeze({
      ...approvalStatementFromRecord(record),
      signature_base64url: requiredBase64Url(record[SIGNATURE_KEY], 64),
    });
  });
}

export function validateAndFreezeKillSwitchClearStatement(
  value: unknown,
): KillSwitchClearStatement {
  return sanitize("OPERATOR_KILL_CLEAR_INVALID", () =>
    killClearStatementFromRecord(cloneExactDataRecord(value, KILL_CLEAR_KEYS)),
  );
}

export function validateAndFreezeSignedKillSwitchClearCommand(
  value: unknown,
): SignedKillSwitchClearCommand {
  return sanitize("OPERATOR_KILL_CLEAR_INVALID", () => {
    const record = cloneExactDataRecord(value, SIGNED_KILL_CLEAR_KEYS);
    return Object.freeze({
      ...killClearStatementFromRecord(record),
      signature_base64url: requiredBase64Url(record[SIGNATURE_KEY], 64),
    });
  });
}

export function operatorEnrollmentStatementDigest(value: unknown): string {
  return sha256(canonicalOperatorEnrollmentStatement(value));
}

export function approvalDecisionStatementDigest(value: unknown): string {
  return sha256(canonicalApprovalDecisionStatement(value));
}

export function killSwitchClearStatementDigest(value: unknown): string {
  return sha256(canonicalKillSwitchClearStatement(value));
}

export function canonicalOperatorEnrollmentStatement(value: unknown): string {
  return canonicalJson(unsignedEnrollment(value));
}

export function canonicalApprovalDecisionStatement(value: unknown): string {
  return canonicalJson(unsignedApproval(value));
}

export function canonicalKillSwitchClearStatement(value: unknown): string {
  return canonicalJson(unsignedKillClear(value));
}

export function decodeCanonicalBase64Url(
  value: string,
  expectedBytes: number | null,
): Buffer {
  if (!BASE64URL.test(value)) throw new Error("BASE64URL_INVALID");
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.toString("base64url") !== value ||
    (expectedBytes !== null && decoded.byteLength !== expectedBytes)
  )
    throw new Error("BASE64URL_INVALID");
  return decoded;
}

export function assertStatementCurrent(
  issuedAt: string,
  expiresAt: string,
  observedAt: string,
): void {
  try {
    const observed = canonicalTimestamp(observedAt);
    const issued = Date.parse(issuedAt);
    const expires = Date.parse(expiresAt);
    const now = Date.parse(observed);
    if (now >= issued && now < expires) return;
  } catch {
    // All malformed or unavailable clock evidence is fail-closed below.
  }
  throw new SecurityError("OPERATOR_STATEMENT_TIME_INVALID");
}

function unsignedEnrollment(value: unknown): OperatorEnrollmentStatement {
  try {
    return validateAndFreezeOperatorEnrollmentStatement(value);
  } catch {
    const signed = validateAndFreezeOperatorEnrollmentProof(value);
    return Object.freeze({
      version: signed.version,
      domain: signed.domain,
      control_plane_id: signed.control_plane_id,
      operator_id: signed.operator_id,
      public_key_spki_base64url: signed.public_key_spki_base64url,
      key_fingerprint_sha256: signed.key_fingerprint_sha256,
      key_revision: signed.key_revision,
      session_id: signed.session_id,
      nonce: signed.nonce,
      issued_at: signed.issued_at,
      expires_at: signed.expires_at,
    });
  }
}

function unsignedApproval(value: unknown): ApprovalDecisionStatement {
  try {
    return validateAndFreezeApprovalDecisionStatement(value);
  } catch {
    const signed = validateAndFreezeSignedApprovalDecision(value);
    return Object.freeze({
      version: signed.version,
      domain: signed.domain,
      control_plane_id: signed.control_plane_id,
      approval_id: signed.approval_id,
      approval_kind: signed.approval_kind,
      approval_payload_hash_sha256: signed.approval_payload_hash_sha256,
      expected_revision: signed.expected_revision,
      decision: signed.decision,
      user_action: signed.user_action,
      operator_id: signed.operator_id,
      key_fingerprint_sha256: signed.key_fingerprint_sha256,
      key_revision: signed.key_revision,
      context_digest_sha256: signed.context_digest_sha256,
      session_id: signed.session_id,
      nonce: signed.nonce,
      issued_at: signed.issued_at,
      expires_at: signed.expires_at,
    });
  }
}

function unsignedKillClear(value: unknown): KillSwitchClearStatement {
  try {
    return validateAndFreezeKillSwitchClearStatement(value);
  } catch {
    const signed = validateAndFreezeSignedKillSwitchClearCommand(value);
    return Object.freeze({
      version: signed.version,
      domain: signed.domain,
      control_plane_id: signed.control_plane_id,
      command: signed.command,
      expected_revision: signed.expected_revision,
      user_action: signed.user_action,
      operator_id: signed.operator_id,
      key_fingerprint_sha256: signed.key_fingerprint_sha256,
      key_revision: signed.key_revision,
      context_digest_sha256: signed.context_digest_sha256,
      session_id: signed.session_id,
      nonce: signed.nonce,
      issued_at: signed.issued_at,
      expires_at: signed.expires_at,
    });
  }
}

function enrollmentStatementFromRecord(
  record: Readonly<Record<string, unknown>>,
): OperatorEnrollmentStatement {
  if (
    record["version"] !== 1 ||
    record["domain"] !== OPERATOR_ENROLLMENT_DOMAIN
  )
    throw new Error("ENROLLMENT_VERSION_INVALID");
  const publicKey = requiredBase64Url(
    record["public_key_spki_base64url"],
    null,
  );
  if (decodeCanonicalBase64Url(publicKey, null).byteLength > 512)
    throw new Error("PUBLIC_KEY_TOO_LARGE");
  const issuedAt = requiredTimestamp(record["issued_at"]);
  const expiresAt = requiredTimestamp(record["expires_at"]);
  assertWindow(issuedAt, expiresAt);
  return Object.freeze({
    version: 1,
    domain: OPERATOR_ENROLLMENT_DOMAIN,
    control_plane_id: requiredSha256(record["control_plane_id"]),
    operator_id: requiredOperatorId(record["operator_id"]),
    public_key_spki_base64url: publicKey,
    key_fingerprint_sha256: requiredSha256(record["key_fingerprint_sha256"]),
    key_revision: requiredPositiveInteger(record["key_revision"]),
    session_id: requiredBase64Url(record["session_id"], 32),
    nonce: requiredBase64Url(record["nonce"], 32),
    issued_at: issuedAt,
    expires_at: expiresAt,
  });
}

function approvalStatementFromRecord(
  record: Readonly<Record<string, unknown>>,
): ApprovalDecisionStatement {
  if (record["version"] !== 1 || record["domain"] !== APPROVAL_DECISION_DOMAIN)
    throw new Error("APPROVAL_VERSION_INVALID");
  const decision = record["decision"];
  if (decision !== "accepted" && decision !== "rejected")
    throw new Error("APPROVAL_DECISION_INVALID");
  const issuedAt = requiredTimestamp(record["issued_at"]);
  const expiresAt = requiredTimestamp(record["expires_at"]);
  assertWindow(issuedAt, expiresAt);
  const approvalKind = requiredApprovalKind(record["approval_kind"]);
  const approvalPayloadHash = requiredSha256(
    record["approval_payload_hash_sha256"],
  );
  const contextDigest = requiredSha256(record["context_digest_sha256"]);
  if (
    approvalKind !== "external_action" &&
    contextDigest !== approvalPayloadHash
  )
    throw new Error("APPROVAL_CONTEXT_INVALID");
  return Object.freeze({
    version: 1,
    domain: APPROVAL_DECISION_DOMAIN,
    control_plane_id: requiredSha256(record["control_plane_id"]),
    approval_id: requiredIdentifier(record["approval_id"]),
    approval_kind: approvalKind,
    approval_payload_hash_sha256: approvalPayloadHash,
    expected_revision: requiredNonNegativeInteger(record["expected_revision"]),
    decision,
    user_action: requiredUserAction(record["user_action"]),
    operator_id: requiredOperatorId(record["operator_id"]),
    key_fingerprint_sha256: requiredSha256(record["key_fingerprint_sha256"]),
    key_revision: requiredPositiveInteger(record["key_revision"]),
    context_digest_sha256: contextDigest,
    session_id: requiredBase64Url(record["session_id"], 32),
    nonce: requiredBase64Url(record["nonce"], 32),
    issued_at: issuedAt,
    expires_at: expiresAt,
  });
}

function killClearStatementFromRecord(
  record: Readonly<Record<string, unknown>>,
): KillSwitchClearStatement {
  if (
    record["version"] !== 1 ||
    record["domain"] !== KILL_SWITCH_CLEAR_DOMAIN ||
    record["command"] !== "clear"
  )
    throw new Error("KILL_CLEAR_VERSION_INVALID");
  const issuedAt = requiredTimestamp(record["issued_at"]);
  const expiresAt = requiredTimestamp(record["expires_at"]);
  assertWindow(issuedAt, expiresAt);
  return Object.freeze({
    version: 1,
    domain: KILL_SWITCH_CLEAR_DOMAIN,
    control_plane_id: requiredSha256(record["control_plane_id"]),
    command: "clear",
    expected_revision: requiredNonNegativeInteger(record["expected_revision"]),
    user_action: requiredUserAction(record["user_action"]),
    operator_id: requiredOperatorId(record["operator_id"]),
    key_fingerprint_sha256: requiredSha256(record["key_fingerprint_sha256"]),
    key_revision: requiredPositiveInteger(record["key_revision"]),
    context_digest_sha256: requiredSha256(record["context_digest_sha256"]),
    session_id: requiredBase64Url(record["session_id"], 32),
    nonce: requiredBase64Url(record["nonce"], 32),
    issued_at: issuedAt,
    expires_at: expiresAt,
  });
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
    throw new Error("PLAIN_OBJECT_REQUIRED");
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== expectedKeys.length ||
    ownKeys.some((key) => typeof key !== "string") ||
    !expectedKeys.every((key) => ownKeys.includes(key))
  )
    throw new Error("EXACT_FIELDS_REQUIRED");
  const entries: [string, unknown][] = [];
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new Error("DATA_FIELD_REQUIRED");
    entries.push([key, descriptor.value]);
  }
  return Object.fromEntries(entries);
}

function requiredIdentifier(value: unknown): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value))
    throw new Error("IDENTIFIER_INVALID");
  return value;
}

function requiredOperatorId(value: unknown): string {
  if (typeof value !== "string" || !OPERATOR_ID.test(value))
    throw new Error("OPERATOR_ID_INVALID");
  return value;
}

function requiredSha256(value: unknown): string {
  if (typeof value !== "string" || !HEX_SHA256.test(value))
    throw new Error("SHA256_INVALID");
  return value;
}

function requiredBase64Url(
  value: unknown,
  expectedBytes: number | null,
): string {
  if (typeof value !== "string") throw new Error("BASE64URL_INVALID");
  decodeCanonicalBase64Url(value, expectedBytes);
  return value;
}

function requiredPositiveInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1)
    throw new Error("INTEGER_INVALID");
  return value;
}

function requiredNonNegativeInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    throw new Error("INTEGER_INVALID");
  return value;
}

function requiredTimestamp(value: unknown): string {
  if (typeof value !== "string") throw new Error("TIMESTAMP_INVALID");
  return canonicalTimestamp(value);
}

function canonicalTimestamp(value: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value)
    throw new Error("TIMESTAMP_INVALID");
  return value;
}

function assertWindow(issuedAt: string, expiresAt: string): void {
  const lifetime = Date.parse(expiresAt) - Date.parse(issuedAt);
  if (lifetime <= 0 || lifetime > OPERATOR_STATEMENT_MAX_LIFETIME_MS)
    throw new Error("STATEMENT_WINDOW_INVALID");
}

function requiredUserAction(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 500 ||
    value.trim() !== value ||
    containsControlCharacter(value)
  )
    throw new Error("USER_ACTION_INVALID");
  return value;
}

function containsControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined || codePoint < 0x20 || codePoint === 0x7f)
      return true;
  }
  return false;
}

function requiredApprovalKind(value: unknown): OperatorApprovalKind {
  switch (value) {
    case "account_manual_action":
    case "campaign_contract":
    case "external_action":
    case "privacy_alert":
    case "program_policy_acceptance":
    case "report_bundle":
    case "tier_3_action":
    case "triage_response":
      return value;
    default:
      throw new Error("APPROVAL_KIND_INVALID");
  }
}

function sanitize<T>(code: string, operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (error instanceof SecurityError && error.code === code) throw error;
    throw new SecurityError(code);
  }
}
