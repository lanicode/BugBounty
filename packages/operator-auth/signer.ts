import {
  createPrivateKey,
  createPublicKey,
  KeyObject,
  sign as ed25519Sign,
} from "node:crypto";
import { types } from "node:util";
import { sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import {
  canonicalApprovalDecisionStatement,
  canonicalKillSwitchClearStatement,
  canonicalOperatorEnrollmentStatement,
  validateAndFreezeApprovalDecisionStatement,
  validateAndFreezeKillSwitchClearStatement,
  validateAndFreezeOperatorCredential,
  validateAndFreezeOperatorEnrollmentStatement,
  validateAndFreezeOperatorEnrollmentProof,
  validateAndFreezeSignedApprovalDecision,
  validateAndFreezeSignedKillSwitchClearCommand,
} from "./envelope.js";
import {
  APPROVAL_DECISION_DOMAIN,
  KILL_SWITCH_CLEAR_DOMAIN,
  OPERATOR_ENROLLMENT_DOMAIN,
  type ApprovalDecisionSigningInput,
  type ApprovalDecisionStatement,
  type KeychainOperatorSignerOptions,
  type KillSwitchClearSigningInput,
  type KillSwitchClearStatement,
  type OperatorCredentialDescriptor,
  type OperatorEnrollmentSigningInput,
  type OperatorEnrollmentStatement,
  type OperatorSigner,
  type OperatorSigningSecretStore,
  type SignedApprovalDecision,
  type SignedKillSwitchClearCommand,
  type SignedOperatorEnrollmentProof,
} from "./types.js";

const KEYCHAIN_REFERENCE =
  /^keychain:\/\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._/-]+)$/u;
const trustedOperatorSigners = new WeakSet();

const ENROLLMENT_INPUT_KEYS = Object.freeze([
  "controlPlaneId",
  "expiresAt",
  "issuedAt",
  "nonce",
  "sessionId",
] as const);
const APPROVAL_INPUT_KEYS = Object.freeze([
  "approvalId",
  "approvalKind",
  "approvalPayloadHashSha256",
  "contextDigestSha256",
  "controlPlaneId",
  "decision",
  "expectedRevision",
  "expiresAt",
  "issuedAt",
  "nonce",
  "sessionId",
  "userAction",
] as const);
const KILL_CLEAR_INPUT_KEYS = Object.freeze([
  "contextDigestSha256",
  "controlPlaneId",
  "expectedRevision",
  "expiresAt",
  "issuedAt",
  "nonce",
  "sessionId",
  "userAction",
] as const);
const OPTION_KEYS = Object.freeze([
  "keyReference",
  "keyRevision",
  "operatorId",
] as const);

class KeychainOperatorSigner implements OperatorSigner {
  public readonly credential: OperatorCredentialDescriptor;
  readonly #privateKey: KeyObject;

  public constructor(
    privateKey: KeyObject,
    credential: OperatorCredentialDescriptor,
  ) {
    this.#privateKey = privateKey;
    this.credential = validateAndFreezeOperatorCredential(credential);
    trustedOperatorSigners.add(this);
    Object.freeze(this);
  }

  public signEnrollment(
    input: OperatorEnrollmentSigningInput,
  ): SignedOperatorEnrollmentProof {
    assertTrustedSigner(this);
    const fields = cloneExactDataRecord(input, ENROLLMENT_INPUT_KEYS);
    const statement = validateAndFreezeOperatorEnrollmentStatement({
      version: 1,
      domain: OPERATOR_ENROLLMENT_DOMAIN,
      control_plane_id: fields["controlPlaneId"],
      operator_id: this.credential.operator_id,
      public_key_spki_base64url: this.credential.public_key_spki_base64url,
      key_fingerprint_sha256: this.credential.key_fingerprint_sha256,
      key_revision: this.credential.key_revision,
      session_id: fields["sessionId"],
      nonce: fields["nonce"],
      issued_at: fields["issuedAt"],
      expires_at: fields["expiresAt"],
    });
    return signEnrollment(this.#privateKey, statement);
  }

  public signApprovalDecision(
    input: ApprovalDecisionSigningInput,
  ): SignedApprovalDecision {
    assertTrustedSigner(this);
    const fields = cloneExactDataRecord(input, APPROVAL_INPUT_KEYS);
    const statement = validateAndFreezeApprovalDecisionStatement({
      version: 1,
      domain: APPROVAL_DECISION_DOMAIN,
      control_plane_id: fields["controlPlaneId"],
      approval_id: fields["approvalId"],
      approval_kind: fields["approvalKind"],
      approval_payload_hash_sha256: fields["approvalPayloadHashSha256"],
      expected_revision: fields["expectedRevision"],
      decision: fields["decision"],
      user_action: fields["userAction"],
      operator_id: this.credential.operator_id,
      key_fingerprint_sha256: this.credential.key_fingerprint_sha256,
      key_revision: this.credential.key_revision,
      context_digest_sha256: fields["contextDigestSha256"],
      session_id: fields["sessionId"],
      nonce: fields["nonce"],
      issued_at: fields["issuedAt"],
      expires_at: fields["expiresAt"],
    });
    return signApproval(this.#privateKey, statement);
  }

  public signKillSwitchClear(
    input: KillSwitchClearSigningInput,
  ): SignedKillSwitchClearCommand {
    assertTrustedSigner(this);
    const fields = cloneExactDataRecord(input, KILL_CLEAR_INPUT_KEYS);
    const statement = validateAndFreezeKillSwitchClearStatement({
      version: 1,
      domain: KILL_SWITCH_CLEAR_DOMAIN,
      control_plane_id: fields["controlPlaneId"],
      command: "clear",
      expected_revision: fields["expectedRevision"],
      user_action: fields["userAction"],
      operator_id: this.credential.operator_id,
      key_fingerprint_sha256: this.credential.key_fingerprint_sha256,
      key_revision: this.credential.key_revision,
      context_digest_sha256: fields["contextDigestSha256"],
      session_id: fields["sessionId"],
      nonce: fields["nonce"],
      issued_at: fields["issuedAt"],
      expires_at: fields["expiresAt"],
    });
    return signKillClear(this.#privateKey, statement);
  }
}

Object.freeze(KeychainOperatorSigner.prototype);
Object.freeze(KeychainOperatorSigner);

export async function createKeychainOperatorSigner(
  secretStore: OperatorSigningSecretStore,
  options: KeychainOperatorSignerOptions,
): Promise<OperatorSigner> {
  const config = signerConfig(options);
  if (types.isProxy(secretStore))
    throw new SecurityError("OPERATOR_SECRET_STORE_INVALID");
  let secret: Uint8Array;
  try {
    secret = await secretStore.get(config.keyReference);
  } catch {
    throw new SecurityError("OPERATOR_KEY_UNAVAILABLE");
  }
  let privateDer: Buffer | undefined;
  let signer: OperatorSigner | undefined;
  let keyFailure: unknown;
  try {
    if (!types.isUint8Array(secret) || secret.byteLength === 0)
      throw new SecurityError("OPERATOR_KEY_INVALID");
    if (secret.byteLength > 4_096)
      throw new SecurityError("OPERATOR_KEY_INVALID");
    privateDer = Buffer.from(secret);
    const privateKey = createPrivateKey({
      key: privateDer,
      format: "der",
      type: "pkcs8",
    });
    if (privateKey.asymmetricKeyType !== "ed25519")
      throw new SecurityError("OPERATOR_KEY_INVALID");
    const publicDer = derivePublicKey(privateKey).export({
      format: "der",
      type: "spki",
    });
    const credential = validateAndFreezeOperatorCredential({
      operator_id: config.operatorId,
      public_key_spki_base64url: publicDer.toString("base64url"),
      key_fingerprint_sha256: sha256(publicDer),
      key_revision: config.keyRevision,
    });
    signer = new KeychainOperatorSigner(privateKey, credential);
  } catch (error) {
    keyFailure = error;
  }
  let zeroizationFailed = !zeroizeBytes(secret);
  if (privateDer !== undefined && !zeroizeBytes(privateDer))
    zeroizationFailed = true;
  if (zeroizationFailed)
    throw new SecurityError("OPERATOR_KEY_ZEROIZATION_FAILED");
  if (keyFailure !== undefined) {
    if (keyFailure instanceof SecurityError) throw keyFailure;
    throw new SecurityError("OPERATOR_KEY_INVALID");
  }
  if (signer === undefined) throw new SecurityError("OPERATOR_KEY_INVALID");
  return signer;
}

function zeroizeBytes(value: Uint8Array): boolean {
  try {
    const fill: unknown = Reflect.get(Uint8Array.prototype, "fill");
    if (typeof fill !== "function") return false;
    Reflect.apply(fill, value, [0]);
    return true;
  } catch {
    return false;
  }
}

function derivePublicKey(privateKey: KeyObject): KeyObject {
  // The Node runtime accepts a private KeyObject here and returns its public
  // half. The current @types/node overload omits KeyObject despite documenting
  // this exact operation, so validate the reflective result at runtime.
  const derived: unknown = Reflect.apply(createPublicKey, undefined, [
    privateKey,
  ]);
  if (!(derived instanceof KeyObject))
    throw new SecurityError("OPERATOR_KEY_INVALID");
  return derived;
}

export function isTrustedOperatorSigner(
  value: unknown,
): value is OperatorSigner {
  if (typeof value !== "object" || value === null || types.isProxy(value))
    return false;
  try {
    return (
      trustedOperatorSigners.has(value) &&
      Reflect.getPrototypeOf(value) === KeychainOperatorSigner.prototype
    );
  } catch {
    return false;
  }
}

function signEnrollment(
  key: KeyObject,
  statement: OperatorEnrollmentStatement,
): SignedOperatorEnrollmentProof {
  return validateAndFreezeOperatorEnrollmentProof({
    ...statement,
    signature_base64url: signCanonical(
      key,
      canonicalOperatorEnrollmentStatement(statement),
    ),
  });
}

function signApproval(
  key: KeyObject,
  statement: ApprovalDecisionStatement,
): SignedApprovalDecision {
  return validateAndFreezeSignedApprovalDecision({
    ...statement,
    signature_base64url: signCanonical(
      key,
      canonicalApprovalDecisionStatement(statement),
    ),
  });
}

function signKillClear(
  key: KeyObject,
  statement: KillSwitchClearStatement,
): SignedKillSwitchClearCommand {
  return validateAndFreezeSignedKillSwitchClearCommand({
    ...statement,
    signature_base64url: signCanonical(
      key,
      canonicalKillSwitchClearStatement(statement),
    ),
  });
}

function signCanonical(key: KeyObject, canonical: string): string {
  try {
    return ed25519Sign(null, Buffer.from(canonical, "utf8"), key).toString(
      "base64url",
    );
  } catch {
    throw new SecurityError("OPERATOR_SIGNING_FAILED");
  }
}

function assertTrustedSigner(value: unknown): asserts value is OperatorSigner {
  if (!isTrustedOperatorSigner(value))
    throw new SecurityError("OPERATOR_SIGNER_UNTRUSTED");
}

function signerConfig(options: unknown): {
  readonly keyReference: string;
  readonly operatorId: string;
  readonly keyRevision: number;
} {
  try {
    const fields = cloneExactDataRecord(options, OPTION_KEYS);
    const keyReference = fields["keyReference"];
    const operatorId = fields["operatorId"];
    const keyRevision = fields["keyRevision"];
    if (typeof keyReference !== "string")
      throw new Error("KEY_REFERENCE_INVALID");
    const match = KEYCHAIN_REFERENCE.exec(keyReference);
    if (
      match?.[1] === undefined ||
      match[2] === undefined ||
      match[2].includes("..")
    )
      throw new Error("KEY_REFERENCE_INVALID");
    const credential = validateAndFreezeOperatorCredential({
      operator_id: operatorId,
      public_key_spki_base64url: Buffer.from([1]).toString("base64url"),
      key_fingerprint_sha256: "0".repeat(64),
      key_revision: keyRevision,
    });
    return Object.freeze({
      keyReference,
      operatorId: credential.operator_id,
      keyRevision: credential.key_revision,
    });
  } catch {
    throw new SecurityError("OPERATOR_SIGNER_CONFIG_INVALID");
  }
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
    throw new SecurityError("OPERATOR_SIGNING_INPUT_INVALID");
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== expectedKeys.length ||
    ownKeys.some((key) => typeof key !== "string") ||
    !expectedKeys.every((key) => ownKeys.includes(key))
  )
    throw new SecurityError("OPERATOR_SIGNING_INPUT_INVALID");
  const entries: [string, unknown][] = [];
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new SecurityError("OPERATOR_SIGNING_INPUT_INVALID");
    entries.push([key, descriptor.value]);
  }
  return Object.fromEntries(entries);
}
