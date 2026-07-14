import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  approvalDecisionStatementDigest,
  createKeychainOperatorSigner,
  isTrustedOperatorSigner,
  killSwitchClearStatementDigest,
  operatorEnrollmentStatementDigest,
  validateAndFreezeOperatorEnrollmentProof,
  validateAndFreezeSignedApprovalDecision,
  verifyOperatorEnrollmentProof,
  verifySignedApprovalDecision,
  verifySignedKillSwitchClearCommand,
  type OperatorSigner,
  type OperatorSigningSecretStore,
  type SignedApprovalDecision,
} from "../../packages/operator-auth/index.js";

const CONTROL_PLANE_ID = "a".repeat(64);
const APPROVAL_HASH = "b".repeat(64);
const APPROVAL_CONTEXT = "c".repeat(64);
const KILL_CONTEXT = "d".repeat(64);
const SESSION = Buffer.alloc(32, 1).toString("base64url");
const NONCE_ENROLLMENT = Buffer.alloc(32, 2).toString("base64url");
const NONCE_APPROVAL = Buffer.alloc(32, 3).toString("base64url");
const NONCE_KILL = Buffer.alloc(32, 4).toString("base64url");
const ISSUED_AT = "2026-07-14T12:00:00.000Z";
const OBSERVED_AT = "2026-07-14T12:01:00.000Z";
const EXPIRES_AT = "2026-07-14T12:05:00.000Z";

interface SignerHarness {
  readonly signer: OperatorSigner;
  readonly suppliedKeyBytes: Uint8Array;
  readonly references: readonly string[];
}

async function signerHarness(
  operatorId = "local-reviewer",
): Promise<SignerHarness> {
  const { privateKey } = generateKeyPairSync("ed25519");
  const suppliedKeyBytes = Uint8Array.from(
    privateKey.export({ format: "der", type: "pkcs8" }),
  );
  const references: string[] = [];
  const store: OperatorSigningSecretStore = {
    get(reference) {
      references.push(reference);
      return Promise.resolve(suppliedKeyBytes);
    },
  };
  const signer = await createKeychainOperatorSigner(store, {
    keyReference: "keychain://bugbounty-copilot/operator-ed25519-v1",
    operatorId,
    keyRevision: 1,
  });
  return { signer, suppliedKeyBytes, references };
}

function approvalInput() {
  return {
    controlPlaneId: CONTROL_PLANE_ID,
    approvalId: "approval-local",
    approvalKind: "external_action" as const,
    approvalPayloadHashSha256: APPROVAL_HASH,
    expectedRevision: 0,
    decision: "accepted" as const,
    userAction: "approve_store_bound_external_action",
    contextDigestSha256: APPROVAL_CONTEXT,
    sessionId: SESSION,
    nonce: NONCE_APPROVAL,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  };
}

function approvalExpectations(signer: OperatorSigner) {
  return {
    controlPlaneId: CONTROL_PLANE_ID,
    credential: signer.credential,
    sessionId: SESSION,
    observedAt: OBSERVED_AT,
    approvalId: "approval-local",
    approvalKind: "external_action" as const,
    approvalPayloadHashSha256: APPROVAL_HASH,
    expectedRevision: 0,
    contextDigestSha256: APPROVAL_CONTEXT,
  };
}

describe("local Ed25519 operator authentication", () => {
  it("imports only a Keychain-referenced PKCS#8 key and zeroes temporary bytes", async () => {
    const harness = await signerHarness();
    expect(harness.references).toEqual([
      "keychain://bugbounty-copilot/operator-ed25519-v1",
    ]);
    expect([...harness.suppliedKeyBytes]).toEqual(
      Array.from({ length: harness.suppliedKeyBytes.byteLength }, () => 0),
    );
    expect(harness.signer.credential).toMatchObject({
      operator_id: "local-reviewer",
      key_revision: 1,
    });
    expect(harness.signer.credential.key_fingerprint_sha256).toMatch(
      /^[a-f0-9]{64}$/u,
    );
    expect(Object.isFrozen(harness.signer)).toBe(true);
    expect(Object.isFrozen(harness.signer.credential)).toBe(true);
    expect(Reflect.ownKeys(harness.signer)).toEqual(["credential"]);
    expect(Reflect.get(harness.signer, "privateKey")).toBeUndefined();
    expect(isTrustedOperatorSigner(harness.signer)).toBe(true);
    expect(isTrustedOperatorSigner({ ...harness.signer })).toBe(false);
    expect(isTrustedOperatorSigner(new Proxy(harness.signer, {}))).toBe(false);
  });

  it("produces and verifies a serializable enrollment proof of possession", async () => {
    const { signer } = await signerHarness();
    const proof = signer.signEnrollment({
      controlPlaneId: CONTROL_PLANE_ID,
      sessionId: SESSION,
      nonce: NONCE_ENROLLMENT,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
    });
    expect(
      verifyOperatorEnrollmentProof(proof, {
        controlPlaneId: CONTROL_PLANE_ID,
        operatorId: "local-reviewer",
        keyRevision: 1,
        sessionId: SESSION,
        observedAt: OBSERVED_AT,
      }),
    ).toEqual(proof);
    expect(operatorEnrollmentStatementDigest(proof)).toMatch(/^[a-f0-9]{64}$/u);
    expect(Object.isFrozen(proof)).toBe(true);
    expect(JSON.parse(JSON.stringify(proof))).toEqual(proof);
  });

  it("signs approval intent and binds every store-controlled expectation", async () => {
    const { signer } = await signerHarness();
    const decision = signer.signApprovalDecision(approvalInput());
    expect(
      verifySignedApprovalDecision(decision, approvalExpectations(signer)),
    ).toEqual(decision);
    expect(approvalDecisionStatementDigest(decision)).toMatch(
      /^[a-f0-9]{64}$/u,
    );

    const mismatches = [
      { controlPlaneId: "f".repeat(64) },
      { sessionId: Buffer.alloc(32, 9).toString("base64url") },
      { approvalId: "approval-other" },
      { approvalKind: "campaign_contract" as const },
      { approvalPayloadHashSha256: "e".repeat(64) },
      { expectedRevision: 1 },
      { contextDigestSha256: "f".repeat(64) },
    ];
    for (const mismatch of mismatches)
      expect(() =>
        verifySignedApprovalDecision(decision, {
          ...approvalExpectations(signer),
          ...mismatch,
        }),
      ).toThrow("OPERATOR_STATEMENT_BINDING_INVALID");
  });

  it("signs a distinct, state-bound kill-switch clear command", async () => {
    const { signer } = await signerHarness();
    const command = signer.signKillSwitchClear({
      controlPlaneId: CONTROL_PLANE_ID,
      expectedRevision: 4,
      userAction: "explicit_local_kill_switch_clear",
      contextDigestSha256: KILL_CONTEXT,
      sessionId: SESSION,
      nonce: NONCE_KILL,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
    });
    expect(
      verifySignedKillSwitchClearCommand(command, {
        controlPlaneId: CONTROL_PLANE_ID,
        credential: signer.credential,
        sessionId: SESSION,
        observedAt: OBSERVED_AT,
        expectedRevision: 4,
        contextDigestSha256: KILL_CONTEXT,
      }),
    ).toEqual(command);
    expect(killSwitchClearStatementDigest(command)).toMatch(/^[a-f0-9]{64}$/u);
    expect(() =>
      verifySignedKillSwitchClearCommand(command, {
        controlPlaneId: CONTROL_PLANE_ID,
        credential: signer.credential,
        sessionId: SESSION,
        observedAt: OBSERVED_AT,
        expectedRevision: 5,
        contextDigestSha256: KILL_CONTEXT,
      }),
    ).toThrow("OPERATOR_STATEMENT_BINDING_INVALID");
  });

  it("rejects expired, future, cross-key, and cryptographically mutated decisions", async () => {
    const { signer } = await signerHarness();
    const other = await signerHarness("other-reviewer");
    const decision = signer.signApprovalDecision(approvalInput());

    for (const observedAt of [
      "2026-07-14T11:59:59.999Z",
      EXPIRES_AT,
      "not-a-time",
    ])
      expect(() =>
        verifySignedApprovalDecision(decision, {
          ...approvalExpectations(signer),
          observedAt,
        }),
      ).toThrow("OPERATOR_STATEMENT_TIME_INVALID");

    expect(() =>
      verifySignedApprovalDecision(decision, {
        ...approvalExpectations(signer),
        credential: other.signer.credential,
      }),
    ).toThrow("OPERATOR_STATEMENT_BINDING_INVALID");

    const mutated: SignedApprovalDecision = {
      ...decision,
      decision: "rejected",
    };
    expect(() =>
      verifySignedApprovalDecision(mutated, approvalExpectations(signer)),
    ).toThrow("OPERATOR_SIGNATURE_INVALID");
    const signatureMutation: SignedApprovalDecision = {
      ...decision,
      signature_base64url: `${decision.signature_base64url.startsWith("A") ? "B" : "A"}${decision.signature_base64url.slice(1)}`,
    };
    expect(() =>
      verifySignedApprovalDecision(
        signatureMutation,
        approvalExpectations(signer),
      ),
    ).toThrow("OPERATOR_SIGNATURE_INVALID");
  });

  it("rejects non-Ed25519, malformed, unavailable, and non-Keychain key sources", async () => {
    const invalid = Uint8Array.from([1, 2, 3, 4]);
    await expect(
      createKeychainOperatorSigner(
        { get: () => Promise.resolve(invalid) },
        {
          keyReference: "keychain://bugbounty-copilot/invalid-key",
          operatorId: "local-reviewer",
          keyRevision: 1,
        },
      ),
    ).rejects.toThrow("OPERATOR_KEY_INVALID");
    expect([...invalid]).toEqual([0, 0, 0, 0]);

    const { privateKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const wrongAlgorithm = Uint8Array.from(
      privateKey.export({ format: "der", type: "pkcs8" }),
    );
    await expect(
      createKeychainOperatorSigner(
        { get: () => Promise.resolve(wrongAlgorithm) },
        {
          keyReference: "keychain://bugbounty-copilot/wrong-algorithm",
          operatorId: "local-reviewer",
          keyRevision: 1,
        },
      ),
    ).rejects.toThrow("OPERATOR_KEY_INVALID");
    expect([...wrongAlgorithm].every((value) => value === 0)).toBe(true);

    await expect(
      createKeychainOperatorSigner(
        { get: () => Promise.reject(new Error("sensitive internal detail")) },
        {
          keyReference: "keychain://bugbounty-copilot/missing-key",
          operatorId: "local-reviewer",
          keyRevision: 1,
        },
      ),
    ).rejects.toThrow("OPERATOR_KEY_UNAVAILABLE");
    await expect(
      createKeychainOperatorSigner(
        { get: () => Promise.resolve(new Uint8Array([1])) },
        {
          keyReference: "secret://plaintext/operator-key",
          operatorId: "local-reviewer",
          keyRevision: 1,
        },
      ),
    ).rejects.toThrow("OPERATOR_SIGNER_CONFIG_INVALID");
  });

  it("uses intrinsic zeroization even when returned key bytes shadow fill", async () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const keyBytes = Uint8Array.from(
      privateKey.export({ format: "der", type: "pkcs8" }),
    );
    let shadowFillCalls = 0;
    Object.defineProperty(keyBytes, "fill", {
      value() {
        shadowFillCalls += 1;
        throw new Error("caller-controlled fill must not run");
      },
    });

    await createKeychainOperatorSigner(
      { get: () => Promise.resolve(keyBytes) },
      {
        keyReference: "keychain://bugbounty-copilot/shadowed-fill",
        operatorId: "local-reviewer",
        keyRevision: 1,
      },
    );

    expect(shadowFillCalls).toBe(0);
    expect([...keyBytes].every((value) => value === 0)).toBe(true);
  });

  it("rejects accessors and proxies before invoking user-controlled envelope fields", async () => {
    const { signer } = await signerHarness();
    const decision = signer.signApprovalDecision(approvalInput());
    let getterCalls = 0;
    const accessor = Object.defineProperty({ ...decision }, "approval_id", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "approval-forged";
      },
    });
    expect(() => validateAndFreezeSignedApprovalDecision(accessor)).toThrow(
      "OPERATOR_APPROVAL_DECISION_INVALID",
    );
    expect(getterCalls).toBe(0);
    expect(() =>
      validateAndFreezeSignedApprovalDecision(new Proxy(decision, {})),
    ).toThrow("OPERATOR_APPROVAL_DECISION_INVALID");
    expect(() =>
      validateAndFreezeSignedApprovalDecision({
        ...decision,
        unexpected: true,
      }),
    ).toThrow("OPERATOR_APPROVAL_DECISION_INVALID");

    const proof = signer.signEnrollment({
      controlPlaneId: CONTROL_PLANE_ID,
      sessionId: SESSION,
      nonce: NONCE_ENROLLMENT,
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
    });
    expect(() =>
      validateAndFreezeOperatorEnrollmentProof(
        Object.assign(Object.create(null), proof),
      ),
    ).toThrow("OPERATOR_ENROLLMENT_INVALID");

    const signingAccessor = Object.defineProperty(
      { ...approvalInput() },
      "approvalId",
      {
        enumerable: true,
        get() {
          getterCalls += 1;
          return "approval-signing-accessor";
        },
      },
    );
    expect(() => signer.signApprovalDecision(signingAccessor)).toThrow(
      "OPERATOR_SIGNING_INPUT_INVALID",
    );
    expect(getterCalls).toBe(0);
  });

  it("enforces canonical session, lifetime, and non-external context contracts before signing", async () => {
    const { signer } = await signerHarness();
    expect(() =>
      signer.signApprovalDecision({
        ...approvalInput(),
        approvalKind: "campaign_contract",
      }),
    ).toThrow("OPERATOR_APPROVAL_DECISION_INVALID");
    expect(() =>
      signer.signApprovalDecision({
        ...approvalInput(),
        sessionId: "not-canonical-base64url",
      }),
    ).toThrow("OPERATOR_APPROVAL_DECISION_INVALID");
    expect(() =>
      signer.signApprovalDecision({
        ...approvalInput(),
        expiresAt: "2026-07-14T12:05:00.001Z",
      }),
    ).toThrow("OPERATOR_APPROVAL_DECISION_INVALID");

    const campaignDecision = signer.signApprovalDecision({
      ...approvalInput(),
      approvalKind: "campaign_contract",
      contextDigestSha256: APPROVAL_HASH,
    });
    expect(campaignDecision.context_digest_sha256).toBe(APPROVAL_HASH);
  });
});
