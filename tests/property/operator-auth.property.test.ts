import { generateKeyPairSync } from "node:crypto";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  ApprovalQueue,
  ControlPlaneDatabase,
  type ApprovalDecisionSigningContext,
  type ControlPlaneStore,
  type KillSwitchClearSigningContext,
} from "../../packages/control-plane/index.js";
import {
  createKeychainOperatorSigner,
  verifyOperatorEnrollmentProof,
  verifySignedApprovalDecision,
  verifySignedKillSwitchClearCommand,
  type OperatorSigner,
  type SignedApprovalDecision,
  type SignedKillSwitchClearCommand,
  type SignedOperatorEnrollmentProof,
} from "../../packages/operator-auth/index.js";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";
import { sha256 } from "../../packages/shared/canonical.js";
import {
  clearTestKillSwitch,
  createTestControlPlaneStore,
  enrollTestOperator,
  setTestControlPlaneTime,
  TEST_OPERATOR_ID,
  TEST_OPERATOR_SIGNER,
} from "../fixtures/operator-auth.factory.js";

const CREATED_AT = "2026-07-14T12:00:00.000Z";
const DECIDED_AT = "2026-07-14T12:00:01.000Z";
const EXPIRES_AT = "2026-07-14T12:01:01.000Z";
const SIGNED_FIELDS = Object.freeze([
  "version",
  "domain",
  "control_plane_id",
  "approval_id",
  "approval_kind",
  "approval_payload_hash_sha256",
  "expected_revision",
  "decision",
  "user_action",
  "operator_id",
  "key_fingerprint_sha256",
  "key_revision",
  "context_digest_sha256",
  "session_id",
  "nonce",
  "issued_at",
  "expires_at",
  "signature_base64url",
] as const satisfies readonly (keyof SignedApprovalDecision)[]);
const ENROLLMENT_FIELDS = Object.freeze([
  "version",
  "domain",
  "control_plane_id",
  "operator_id",
  "public_key_spki_base64url",
  "key_fingerprint_sha256",
  "key_revision",
  "session_id",
  "nonce",
  "issued_at",
  "expires_at",
  "signature_base64url",
] as const satisfies readonly (keyof SignedOperatorEnrollmentProof)[]);
const KILL_CLEAR_FIELDS = Object.freeze([
  "version",
  "domain",
  "control_plane_id",
  "command",
  "expected_revision",
  "user_action",
  "operator_id",
  "key_fingerprint_sha256",
  "key_revision",
  "context_digest_sha256",
  "session_id",
  "nonce",
  "issued_at",
  "expires_at",
  "signature_base64url",
] as const satisfies readonly (keyof SignedKillSwitchClearCommand)[]);

describe("signed operator decision properties", () => {
  it("rejects every generated mutation of every signed envelope field", () => {
    const database = ControlPlaneDatabase.memory();
    try {
      const store = authenticatedStore(database);
      const approval = persistApproval(store, "mutation-approval");
      const context = store.describeApprovalDecision(approval.id);
      const signed = signDecision(
        TEST_OPERATOR_SIGNER,
        context,
        token("session", new Uint8Array(32)),
        token("nonce", new Uint8Array(32)),
      );
      const expectations = verificationExpectations(context, signed);
      expect(verifySignedApprovalDecision(signed, expectations)).toEqual(
        signed,
      );

      fc.assert(
        fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (seed) => {
          for (const field of SIGNED_FIELDS)
            expect(() =>
              verifySignedApprovalDecision(
                mutateSignedField(signed, field, seed),
                expectations,
              ),
            ).toThrow();
        }),
        { numRuns: 50 },
      );
      expect(store.listApprovals()).toMatchObject([
        { id: approval.id, status: "open", revision: 0 },
      ]);
    } finally {
      database.close();
    }
  });

  it("rejects every generated mutation of every enrollment-proof field", () => {
    const database = ControlPlaneDatabase.memory();
    try {
      const store = createTestControlPlaneStore(database, CREATED_AT);
      const proof = TEST_OPERATOR_SIGNER.signEnrollment({
        controlPlaneId: store.getControlPlaneId(),
        sessionId: token("enrollment-session", new Uint8Array(32)),
        nonce: token("enrollment-nonce", new Uint8Array(32)),
        issuedAt: CREATED_AT,
        expiresAt: "2026-07-14T12:01:00.000Z",
      });
      const expectations = {
        controlPlaneId: store.getControlPlaneId(),
        operatorId: TEST_OPERATOR_ID,
        keyRevision: 1,
        sessionId: proof.session_id,
        observedAt: proof.issued_at,
      };
      expect(Object.keys(proof).sort()).toEqual([...ENROLLMENT_FIELDS].sort());
      expect(verifyOperatorEnrollmentProof(proof, expectations)).toEqual(proof);

      fc.assert(
        fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (seed) => {
          for (const field of ENROLLMENT_FIELDS)
            expect(() =>
              verifyOperatorEnrollmentProof(
                mutateEnrollmentField(proof, field, seed),
                expectations,
              ),
            ).toThrow();
        }),
        { numRuns: 50 },
      );
      expect(store.getLocalOperatorCredential()).toBeUndefined();
      expect(store.isKillSwitchActive()).toBe(true);
    } finally {
      database.close();
    }
  });

  it("rejects every generated mutation of every signed kill-clear field", () => {
    const database = ControlPlaneDatabase.memory();
    try {
      const store = createTestControlPlaneStore(database, CREATED_AT);
      enrollTestOperator(store, CREATED_AT);
      const context = store.describeKillSwitchClear();
      const command = signKillClear(
        context,
        authenticatedSessionId(database),
        token("kill-clear-nonce", new Uint8Array(32)),
      );
      const expectations = {
        controlPlaneId: context.controlPlaneId,
        credential: TEST_OPERATOR_SIGNER.credential,
        sessionId: command.session_id,
        observedAt: command.issued_at,
        expectedRevision: context.expectedRevision,
        contextDigestSha256: context.contextDigestSha256,
      };
      expect(Object.keys(command).sort()).toEqual(
        [...KILL_CLEAR_FIELDS].sort(),
      );
      expect(verifySignedKillSwitchClearCommand(command, expectations)).toEqual(
        command,
      );

      fc.assert(
        fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (seed) => {
          for (const field of KILL_CLEAR_FIELDS)
            expect(() =>
              verifySignedKillSwitchClearCommand(
                mutateKillClearField(command, field, seed),
                expectations,
              ),
            ).toThrow();
        }),
        { numRuns: 50 },
      );
      expect(store.isKillSwitchActive()).toBe(true);
    } finally {
      database.close();
    }
  });

  it("rejects decisions made by generated untrusted Ed25519 keys", async () => {
    const database = ControlPlaneDatabase.memory();
    try {
      const store = authenticatedStore(database);
      const approval = persistApproval(store, "wrong-key-approval");
      const context = store.describeApprovalDecision(approval.id);
      const wrongSigner = await ephemeralSigner();

      fc.assert(
        fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (seed) => {
          const signedByWrongKey = signDecision(
            wrongSigner,
            context,
            token("wrong-session", seed),
            token("wrong-nonce", seed),
          );
          const expectations = verificationExpectations(
            context,
            signedByWrongKey,
          );
          expect(() =>
            verifySignedApprovalDecision(signedByWrongKey, expectations),
          ).toThrow("OPERATOR_STATEMENT_BINDING_INVALID");
          expect(() =>
            verifySignedApprovalDecision(
              {
                ...signedByWrongKey,
                key_fingerprint_sha256:
                  TEST_OPERATOR_SIGNER.credential.key_fingerprint_sha256,
              },
              expectations,
            ),
          ).toThrow("OPERATOR_SIGNATURE_INVALID");
        }),
        { numRuns: 40 },
      );
    } finally {
      database.close();
    }
  });

  it("never accepts a valid decision in another control plane", () => {
    const firstDatabase = ControlPlaneDatabase.memory();
    const secondDatabase = ControlPlaneDatabase.memory();
    try {
      const first = authenticatedStore(firstDatabase);
      const second = authenticatedStore(secondDatabase);
      expect(first.getControlPlaneId()).not.toBe(second.getControlPlaneId());
      let sequence = 0;

      fc.assert(
        fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (seed) => {
          sequence += 1;
          const id = `cross-plane-${String(sequence)}`;
          persistApproval(first, id);
          persistApproval(second, id);
          const signed = signDecision(
            TEST_OPERATOR_SIGNER,
            first.describeApprovalDecision(id),
            token("cross-session", seed),
            token("cross-nonce", seed),
          );
          setTestControlPlaneTime(second, DECIDED_AT);
          expect(() => second.decideApproval(signed)).toThrow(
            "OPERATOR_STATEMENT_BINDING_INVALID",
          );
          expect(
            second.listApprovals().find((approval) => approval.id === id),
          ).toMatchObject({ status: "open", revision: 0 });
        }),
        { numRuns: 40 },
      );
    } finally {
      firstDatabase.close();
      secondDatabase.close();
    }
  });

  it("rejects every observation at or after statement expiry", () => {
    const database = ControlPlaneDatabase.memory();
    try {
      const store = authenticatedStore(database);
      const approval = persistApproval(store, "expired-approval");
      const context = store.describeApprovalDecision(approval.id);
      const signed = signDecision(
        TEST_OPERATOR_SIGNER,
        context,
        token("expiry-session", new Uint8Array(32)),
        token("expiry-nonce", new Uint8Array(32)),
      );

      fc.assert(
        fc.property(
          fc.integer({ min: 0, max: 86_400_000 }),
          (millisecondsAfterExpiry) => {
            const observedAt = new Date(
              Date.parse(signed.expires_at) + millisecondsAfterExpiry,
            ).toISOString();
            expect(() =>
              verifySignedApprovalDecision(signed, {
                ...verificationExpectations(context, signed),
                observedAt,
              }),
            ).toThrow("OPERATOR_STATEMENT_TIME_INVALID");
          },
        ),
        { numRuns: 100 },
      );
    } finally {
      database.close();
    }
  });

  it("persists nonce replay protection across approvals", () => {
    let sequence = 0;
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), (seed) => {
        const database = ControlPlaneDatabase.memory();
        try {
          const store = authenticatedStore(database);
          sequence += 1;
          const firstId = `nonce-first-${String(sequence)}`;
          const secondId = `nonce-second-${String(sequence)}`;
          persistApproval(store, firstId);
          persistApproval(store, secondId);
          const replayedNonce = token("replayed-nonce", seed);
          const sessionId = authenticatedSessionId(database);
          const first = signDecision(
            TEST_OPERATOR_SIGNER,
            store.describeApprovalDecision(firstId),
            sessionId,
            replayedNonce,
          );
          const second = signDecision(
            TEST_OPERATOR_SIGNER,
            store.describeApprovalDecision(secondId),
            sessionId,
            replayedNonce,
          );

          setTestControlPlaneTime(store, DECIDED_AT);
          expect(store.decideApproval(first)).toMatchObject({
            id: firstId,
            status: "accepted",
            revision: 1,
          });
          expect(() => store.decideApproval(first)).toThrow(
            "APPROVAL_ALREADY_PROCESSED",
          );
          expect(() => store.decideApproval(second)).toThrow();
          expect(
            store.listApprovals().find((approval) => approval.id === secondId),
          ).toMatchObject({ status: "open", revision: 0 });
          expect(
            database.get(
              `SELECT count(*) AS value FROM operator_signed_statements
                 WHERE nonce=?`,
              replayedNonce,
            )?.["value"],
          ).toBe(1);
        } finally {
          database.close();
        }
      }),
      { numRuns: 25 },
    );
  });
});

function authenticatedStore(database: ControlPlaneDatabase): ControlPlaneStore {
  const store = createTestControlPlaneStore(database, CREATED_AT);
  enrollTestOperator(store, CREATED_AT);
  clearTestKillSwitch(store, CREATED_AT);
  return store;
}

function authenticatedSessionId(database: ControlPlaneDatabase): string {
  const value = database.get(
    `SELECT session_id FROM operator_signed_statements
     WHERE purpose='operator_enrollment'
     ORDER BY verified_at DESC,statement_digest DESC LIMIT 1`,
  )?.["session_id"];
  if (typeof value !== "string")
    throw new Error("TEST_OPERATOR_SESSION_MISSING");
  return value;
}

function persistApproval(store: ControlPlaneStore, id: string) {
  const approval = new ApprovalQueue().enqueue({
    id,
    kind: "privacy_alert",
    summary: `Review ${id}`,
    technicalDetails: "Local property-test evidence only.",
    impact: "No external action is available.",
    policyVersion: null,
    policyHash: null,
    createdAt: CREATED_AT,
    auditReference: `audit:${id}`,
  });
  store.persistApproval(approval);
  return approval;
}

function signDecision(
  signer: OperatorSigner,
  context: ApprovalDecisionSigningContext,
  sessionId: string,
  nonce: string,
): SignedApprovalDecision {
  return signer.signApprovalDecision({
    controlPlaneId: context.controlPlaneId,
    approvalId: context.approvalId,
    approvalKind: context.approvalKind,
    approvalPayloadHashSha256: context.approvalPayloadHashSha256,
    expectedRevision: context.expectedRevision,
    decision: "accepted",
    userAction: "explicit_local_property_test_approval",
    contextDigestSha256: context.contextDigestSha256,
    sessionId,
    nonce,
    issuedAt: DECIDED_AT,
    expiresAt: EXPIRES_AT,
  });
}

function signKillClear(
  context: KillSwitchClearSigningContext,
  sessionId: string,
  nonce: string,
): SignedKillSwitchClearCommand {
  return TEST_OPERATOR_SIGNER.signKillSwitchClear({
    controlPlaneId: context.controlPlaneId,
    expectedRevision: context.expectedRevision,
    userAction: "explicit_local_property_test_kill_clear",
    contextDigestSha256: context.contextDigestSha256,
    sessionId,
    nonce,
    issuedAt: DECIDED_AT,
    expiresAt: EXPIRES_AT,
  });
}

function verificationExpectations(
  context: ApprovalDecisionSigningContext,
  signed: SignedApprovalDecision,
) {
  return {
    controlPlaneId: context.controlPlaneId,
    credential: TEST_OPERATOR_SIGNER.credential,
    sessionId: signed.session_id,
    observedAt: signed.issued_at,
    approvalId: context.approvalId,
    approvalKind: context.approvalKind,
    approvalPayloadHashSha256: context.approvalPayloadHashSha256,
    expectedRevision: context.expectedRevision,
    contextDigestSha256: context.contextDigestSha256,
  };
}

function mutateSignedField(
  signed: SignedApprovalDecision,
  field: (typeof SIGNED_FIELDS)[number],
  seed: Uint8Array,
): unknown {
  const digest = sha256(`mutation:${Buffer.from(seed).toString("hex")}`);
  const changed: Record<string, unknown> = { ...signed };
  switch (field) {
    case "version":
      changed[field] = 2;
      break;
    case "domain":
      changed[field] = "bugbounty-copilot:control-plane:other:v1";
      break;
    case "control_plane_id":
    case "approval_payload_hash_sha256":
    case "key_fingerprint_sha256":
    case "context_digest_sha256":
      changed[field] = alternate(digest, signed[field]);
      break;
    case "approval_id":
      changed[field] = `approval-${digest.slice(0, 24)}`;
      break;
    case "approval_kind":
      changed[field] = "report_bundle";
      break;
    case "expected_revision":
      changed[field] = 1;
      break;
    case "decision":
      changed[field] = "rejected";
      break;
    case "user_action":
      changed[field] = `explicit_mutation_${digest.slice(0, 24)}`;
      break;
    case "operator_id":
      changed[field] = `reviewer-${digest.slice(0, 24)}`;
      break;
    case "key_revision":
      changed[field] = signed.key_revision + 1;
      break;
    case "session_id":
    case "nonce":
      changed[field] = alternate(token(field, seed), signed[field]);
      break;
    case "issued_at":
      changed[field] = "2026-07-14T12:00:02.000Z";
      break;
    case "expires_at":
      changed[field] = "2026-07-14T12:01:02.000Z";
      break;
    case "signature_base64url":
      changed[field] = `${
        signed.signature_base64url.startsWith("A") ? "B" : "A"
      }${signed.signature_base64url.slice(1)}`;
      break;
  }
  return changed;
}

function mutateEnrollmentField(
  proof: SignedOperatorEnrollmentProof,
  field: (typeof ENROLLMENT_FIELDS)[number],
  seed: Uint8Array,
): unknown {
  const digest = sha256(`enrollment:${Buffer.from(seed).toString("hex")}`);
  const changed: Record<string, unknown> = { ...proof };
  switch (field) {
    case "version":
      changed[field] = 2;
      break;
    case "domain":
      changed[field] = "bugbounty-copilot:control-plane:other-enrollment:v1";
      break;
    case "control_plane_id":
    case "key_fingerprint_sha256":
      changed[field] = alternate(digest, proof[field]);
      break;
    case "operator_id":
      changed[field] = `reviewer-${digest.slice(0, 24)}`;
      break;
    case "public_key_spki_base64url":
      changed[field] = alternate(token("public-key", seed), proof[field]);
      break;
    case "key_revision":
      changed[field] = proof.key_revision + 1;
      break;
    case "session_id":
    case "nonce":
      changed[field] = alternate(
        token(`enrollment-${field}`, seed),
        proof[field],
      );
      break;
    case "issued_at":
      changed[field] = "2026-07-14T12:00:01.000Z";
      break;
    case "expires_at":
      changed[field] = "2026-07-14T12:01:01.000Z";
      break;
    case "signature_base64url":
      changed[field] = mutatedSignature(proof.signature_base64url);
      break;
  }
  return changed;
}

function mutateKillClearField(
  command: SignedKillSwitchClearCommand,
  field: (typeof KILL_CLEAR_FIELDS)[number],
  seed: Uint8Array,
): unknown {
  const digest = sha256(`kill-clear:${Buffer.from(seed).toString("hex")}`);
  const changed: Record<string, unknown> = { ...command };
  switch (field) {
    case "version":
      changed[field] = 2;
      break;
    case "domain":
      changed[field] = "bugbounty-copilot:control-plane:other-kill:v1";
      break;
    case "control_plane_id":
    case "key_fingerprint_sha256":
    case "context_digest_sha256":
      changed[field] = alternate(digest, command[field]);
      break;
    case "command":
      changed[field] = "engage";
      break;
    case "expected_revision":
      changed[field] = command.expected_revision + 1;
      break;
    case "user_action":
      changed[field] = `explicit_kill_mutation_${digest.slice(0, 24)}`;
      break;
    case "operator_id":
      changed[field] = `reviewer-${digest.slice(0, 24)}`;
      break;
    case "key_revision":
      changed[field] = command.key_revision + 1;
      break;
    case "session_id":
    case "nonce":
      changed[field] = alternate(token(`kill-${field}`, seed), command[field]);
      break;
    case "issued_at":
      changed[field] = "2026-07-14T12:00:02.000Z";
      break;
    case "expires_at":
      changed[field] = "2026-07-14T12:01:02.000Z";
      break;
    case "signature_base64url":
      changed[field] = mutatedSignature(command.signature_base64url);
      break;
  }
  return changed;
}

function token(label: string, seed: Uint8Array): string {
  return Buffer.from(
    sha256(`${label}:${Buffer.from(seed).toString("hex")}`),
    "hex",
  ).toString("base64url");
}

function alternate(candidate: string, current: string): string {
  if (candidate !== current) return candidate;
  return `${candidate.startsWith("a") ? "b" : "a"}${candidate.slice(1)}`;
}

function mutatedSignature(value: string): string {
  return `${value.startsWith("A") ? "B" : "A"}${value.slice(1)}`;
}

async function ephemeralSigner(): Promise<OperatorSigner> {
  const secrets = new InMemorySecretStore();
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateDer = privateKey.export({ format: "der", type: "pkcs8" });
  secrets.set("keychain://test/wrong-operator-ed25519", privateDer);
  privateDer.fill(0);
  return createKeychainOperatorSigner(secrets, {
    keyReference: "keychain://test/wrong-operator-ed25519",
    operatorId: TEST_OPERATOR_ID,
    keyRevision: 1,
  });
}
