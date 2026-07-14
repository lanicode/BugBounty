import { generateKeyPairSync, randomBytes } from "node:crypto";
import {
  ControlPlaneStore,
  type ApprovalRecord,
  type ControlPlaneDatabase,
} from "../../packages/control-plane/index.js";
import {
  createKeychainOperatorSigner,
  type OperatorCredentialDescriptor,
  type SignedApprovalDecision,
  type SignedKillSwitchClearCommand,
  type SignedOperatorEnrollmentProof,
} from "../../packages/operator-auth/index.js";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";

export const TEST_OPERATOR_ID = "local-reviewer";

const TEST_OPERATOR_KEY_REFERENCE = "keychain://test/local-operator-ed25519-v1";
const STATEMENT_LIFETIME_MS = 60_000;
const TEST_OPERATOR_SESSION_ID = randomBytes(32).toString("base64url");
const testClockStates = new WeakMap<
  ControlPlaneStore,
  { observedAt: string }
>();

const signingSecrets = new InMemorySecretStore();
const { privateKey } = generateKeyPairSync("ed25519");
const privateKeyDer = privateKey.export({ format: "der", type: "pkcs8" });
signingSecrets.set(TEST_OPERATOR_KEY_REFERENCE, privateKeyDer);
privateKeyDer.fill(0);

export const TEST_OPERATOR_SIGNER = await createKeychainOperatorSigner(
  signingSecrets,
  {
    keyReference: TEST_OPERATOR_KEY_REFERENCE,
    operatorId: TEST_OPERATOR_ID,
    keyRevision: 1,
  },
);

export function createTestControlPlaneStore(
  database: ControlPlaneDatabase,
  initialObservedAt = "2026-07-13T00:00:00.000Z",
): ControlPlaneStore {
  const state = { observedAt: canonicalTestTimestamp(initialObservedAt) };
  const store = new ControlPlaneStore(
    database,
    () => new Date(state.observedAt),
  );
  testClockStates.set(store, state);
  return store;
}

export function setTestControlPlaneTime(
  store: ControlPlaneStore,
  observedAt: string,
): void {
  const state = testClockStates.get(store);
  if (state === undefined) throw new Error("TEST_CONTROL_PLANE_CLOCK_REQUIRED");
  state.observedAt = canonicalTestTimestamp(observedAt);
}

export function signTestOperatorEnrollment(
  store: ControlPlaneStore,
  issuedAt: string,
): SignedOperatorEnrollmentProof {
  return TEST_OPERATOR_SIGNER.signEnrollment({
    controlPlaneId: store.getControlPlaneId(),
    ...statementFreshness(issuedAt),
  });
}

export function enrollTestOperator(
  store: ControlPlaneStore,
  issuedAt: string,
): OperatorCredentialDescriptor {
  setTestControlPlaneTime(store, issuedAt);
  const existing = store.getLocalOperatorCredential();
  if (existing !== undefined) {
    if (
      existing.operator_id !== TEST_OPERATOR_SIGNER.credential.operator_id ||
      existing.public_key_spki_base64url !==
        TEST_OPERATOR_SIGNER.credential.public_key_spki_base64url ||
      existing.key_fingerprint_sha256 !==
        TEST_OPERATOR_SIGNER.credential.key_fingerprint_sha256 ||
      existing.key_revision !== TEST_OPERATOR_SIGNER.credential.key_revision
    )
      throw new Error("TEST_OPERATOR_CREDENTIAL_MISMATCH");
  }
  const proof = signTestOperatorEnrollment(store, issuedAt);
  return existing === undefined
    ? store.enrollLocalOperator(proof)
    : store.authenticateLocalOperatorSession(proof);
}

export function signTestKillSwitchClear(
  store: ControlPlaneStore,
  issuedAt: string,
  userAction = "explicit_local_kill_switch_clear",
): SignedKillSwitchClearCommand {
  const context = store.describeKillSwitchClear();
  return TEST_OPERATOR_SIGNER.signKillSwitchClear({
    controlPlaneId: context.controlPlaneId,
    expectedRevision: context.expectedRevision,
    userAction,
    contextDigestSha256: context.contextDigestSha256,
    ...statementFreshness(issuedAt),
  });
}

export function clearTestKillSwitch(
  store: ControlPlaneStore,
  issuedAt: string,
  userAction = "explicit_local_kill_switch_clear",
): { readonly active: false; readonly revision: number } {
  enrollTestOperator(store, issuedAt);
  return store.clearKillSwitch(
    signTestKillSwitchClear(store, issuedAt, userAction),
  );
}

export function signTestApprovalDecision(
  store: ControlPlaneStore,
  input: {
    readonly approvalId: string;
    readonly decision: "accepted" | "rejected";
    readonly userAction: string;
    readonly issuedAt: string;
  },
): SignedApprovalDecision {
  const context = store.describeApprovalDecision(input.approvalId);
  return TEST_OPERATOR_SIGNER.signApprovalDecision({
    controlPlaneId: context.controlPlaneId,
    approvalId: context.approvalId,
    approvalKind: context.approvalKind,
    approvalPayloadHashSha256: context.approvalPayloadHashSha256,
    expectedRevision: context.expectedRevision,
    decision: input.decision,
    userAction: input.userAction,
    contextDigestSha256: context.contextDigestSha256,
    ...statementFreshness(input.issuedAt),
  });
}

export function decideTestApproval(
  store: ControlPlaneStore,
  input: {
    readonly approvalId: string;
    readonly decision: "accepted" | "rejected";
    readonly userAction: string;
    readonly issuedAt: string;
  },
): ApprovalRecord {
  enrollTestOperator(store, input.issuedAt);
  return store.decideApproval(signTestApprovalDecision(store, input));
}

function canonicalTestTimestamp(value: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds))
    throw new Error("TEST_CONTROL_PLANE_CLOCK_INVALID");
  const canonical = new Date(milliseconds).toISOString();
  if (canonical !== value) throw new Error("TEST_CONTROL_PLANE_CLOCK_INVALID");
  return canonical;
}

function statementFreshness(issuedAt: string): {
  readonly sessionId: string;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
} {
  return Object.freeze({
    sessionId: TEST_OPERATOR_SESSION_ID,
    nonce: randomBytes(32).toString("base64url"),
    issuedAt,
    expiresAt: new Date(
      Date.parse(issuedAt) + STATEMENT_LIFETIME_MS,
    ).toISOString(),
  });
}
