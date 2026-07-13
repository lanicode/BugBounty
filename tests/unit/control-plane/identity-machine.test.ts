import { describe, expect, it } from "vitest";
import {
  createIdentityMachine,
  transitionIdentity,
  type IdentityTransition,
  type IdentityMachineState,
  type LocalHumanEvidence,
} from "../../../packages/control-plane/identity-machine.js";
import type { TestIdentityRecord } from "../../../packages/control-plane/types.js";

const START = "2026-07-13T10:00:00.000Z";

function identity(): TestIdentityRecord {
  return {
    id: "identity-owner",
    programId: "program-local",
    role: "Owner",
    status: "planned",
    emailReference: "mock-email:owner",
    secretReferences: ["mock-secret:owner"],
    browserProfileReference: "mock-profile:owner",
    platformAccountReference: "mock-account:owner",
    createdAt: START,
    verifiedAt: null,
    suspendedAt: null,
    retiredAt: null,
    lastSuccessfulLoginAt: null,
    humanActionRequired: false,
    organizationRef: "mock-org:researchers",
    ownedObjectRefs: ["mock-object:one"],
  };
}

function human(timestamp: string): LocalHumanEvidence {
  return { confirmed: true, actor: "local-reviewer", timestamp };
}

function begin(state = createIdentityMachine(identity())) {
  return transitionIdentity(state, {
    kind: "begin_registration",
    expectedRevision: state.revision,
    timestamp: "2026-07-13T10:01:00.000Z",
  });
}

function readyState(): IdentityMachineState {
  let state = begin();
  state = transitionIdentity(state, {
    kind: "confirm_human_checkpoint",
    expectedRevision: state.revision,
    evidence: human("2026-07-13T10:02:00.000Z"),
    nextStatus: "awaiting_email_verification",
  });
  state = transitionIdentity(state, {
    kind: "confirm_human_checkpoint",
    expectedRevision: state.revision,
    evidence: human("2026-07-13T10:03:00.000Z"),
    nextStatus: "awaiting_captcha",
  });
  state = transitionIdentity(state, {
    kind: "confirm_human_checkpoint",
    expectedRevision: state.revision,
    evidence: human("2026-07-13T10:04:00.000Z"),
    nextStatus: "awaiting_terms_acceptance",
  });
  return transitionIdentity(state, {
    kind: "confirm_human_checkpoint",
    expectedRevision: state.revision,
    evidence: human("2026-07-13T10:05:00.000Z"),
    nextStatus: "ready",
  });
}

describe("test identity state machine", () => {
  it("requires explicit local human evidence for every registration checkpoint", () => {
    const ready = readyState();

    expect(ready.identity.status).toBe("ready");
    expect(ready.identity.humanActionRequired).toBe(false);
    expect(ready.identity.verifiedAt).toBe("2026-07-13T10:05:00.000Z");
    expect(ready.revision).toBe(5);
    expect(ready.completedHumanCheckpoints).toEqual([
      "captcha",
      "email_verification",
      "manual_registration",
      "terms_acceptance",
    ]);
    expect(Object.isFrozen(ready)).toBe(true);
    expect(Object.isFrozen(ready.identity)).toBe(true);
    expect(Object.isFrozen(ready.identity.secretReferences)).toBe(true);
    expect(Object.isFrozen(ready.identity.ownedObjectRefs)).toBe(true);
    expect(Object.isFrozen(ready.completedHumanCheckpoints)).toBe(true);
  });

  it("never skips or automatically confirms manual, email, CAPTCHA or terms gates", () => {
    const awaitingManual = begin();
    expect(() =>
      transitionIdentity(awaitingManual, {
        kind: "confirm_human_checkpoint",
        expectedRevision: awaitingManual.revision,
        evidence: human("2026-07-13T10:02:00.000Z"),
        nextStatus: "ready",
      }),
    ).toThrow("IDENTITY_CHECKPOINT_SEQUENCE_INVALID");
    expect(() =>
      transitionIdentity(awaitingManual, {
        kind: "confirm_human_checkpoint",
        expectedRevision: awaitingManual.revision,
        evidence: {
          confirmed: false,
          actor: "local-reviewer",
          timestamp: "2026-07-13T10:02:00.000Z",
        } as unknown as LocalHumanEvidence,
        nextStatus: "awaiting_email_verification",
      }),
    ).toThrow("IDENTITY_HUMAN_EVIDENCE_INVALID");
    expect(() =>
      transitionIdentity(awaitingManual, {
        kind: "confirm_human_checkpoint",
        expectedRevision: awaitingManual.revision,
        evidence: human("not-a-timestamp"),
        nextStatus: "awaiting_email_verification",
      }),
    ).toThrow("IDENTITY_TIMESTAMP_INVALID");
  });

  it("restores an expired session only through a successful local mock login", () => {
    const ready = readyState();
    const expired = transitionIdentity(ready, {
      kind: "expire_session",
      expectedRevision: ready.revision,
      timestamp: "2026-07-13T10:06:00.000Z",
    });
    expect(expired.identity.status).toBe("session_expired");
    expect(() =>
      transitionIdentity(expired, {
        kind: "mock_login",
        expectedRevision: expired.revision,
        evidence: {
          successful: true,
          provider: "external" as "local_mock",
          actor: "mock-runner",
          timestamp: "2026-07-13T10:07:00.000Z",
        },
      }),
    ).toThrow("IDENTITY_MOCK_LOGIN_INVALID");

    const restored = transitionIdentity(expired, {
      kind: "mock_login",
      expectedRevision: expired.revision,
      evidence: {
        successful: true,
        provider: "local_mock",
        actor: "mock-runner",
        timestamp: "2026-07-13T10:07:00.000Z",
      },
    });
    expect(restored.identity.status).toBe("ready");
    expect(restored.identity.lastSuccessfulLoginAt).toBe(
      "2026-07-13T10:07:00.000Z",
    );
  });

  it("restores a suspension only with explicit human evidence", () => {
    const ready = readyState();
    const suspended = transitionIdentity(ready, {
      kind: "suspend",
      expectedRevision: ready.revision,
      actor: "local-operator",
      timestamp: "2026-07-13T10:06:00.000Z",
    });
    expect(suspended.identity.status).toBe("suspended");
    expect(() =>
      transitionIdentity(suspended, {
        kind: "mock_login",
        expectedRevision: suspended.revision,
        evidence: {
          successful: true,
          provider: "local_mock",
          actor: "mock-runner",
          timestamp: "2026-07-13T10:07:00.000Z",
        },
      }),
    ).toThrow("IDENTITY_TRANSITION_INVALID");

    const restored = transitionIdentity(suspended, {
      kind: "human_restore",
      expectedRevision: suspended.revision,
      evidence: human("2026-07-13T10:07:00.000Z"),
    });
    expect(restored.identity.status).toBe("ready");
    expect(restored.identity.suspendedAt).toBe("2026-07-13T10:06:00.000Z");
  });

  it("allows explicit retirement from every non-retired state", () => {
    const planned = createIdentityMachine(identity());
    const awaiting = begin(createIdentityMachine(identity()));
    const ready = readyState();
    const expired = transitionIdentity(readyState(), {
      kind: "expire_session",
      expectedRevision: 5,
      timestamp: "2026-07-13T10:06:00.000Z",
    });
    const readyForSuspension = readyState();
    const suspended = transitionIdentity(readyForSuspension, {
      kind: "suspend",
      expectedRevision: readyForSuspension.revision,
      actor: "local-operator",
      timestamp: "2026-07-13T10:06:00.000Z",
    });

    for (const state of [planned, awaiting, ready, expired, suspended]) {
      const retired = transitionIdentity(state, {
        kind: "retire",
        expectedRevision: state.revision,
        evidence: human("2026-07-13T10:10:00.000Z"),
      });
      expect(retired.identity.status).toBe("retired");
      expect(retired.identity.retiredAt).toBe("2026-07-13T10:10:00.000Z");
      expect(retired.identity.programId).toBe(identity().programId);
      expect(retired.identity.role).toBe(identity().role);
      expect(retired.identity.emailReference).toBe(identity().emailReference);
      expect(retired.identity.secretReferences).toEqual(
        identity().secretReferences,
      );
      expect(() =>
        transitionIdentity(retired, {
          kind: "retire",
          expectedRevision: retired.revision,
          evidence: human("2026-07-13T10:11:00.000Z"),
        }),
      ).toThrow("IDENTITY_ALREADY_RETIRED");
    }
  });

  it("blocks illegal transitions, stale revisions and time regression", () => {
    const planned = createIdentityMachine(identity());
    expect(() =>
      transitionIdentity(planned, {
        kind: "expire_session",
        expectedRevision: planned.revision,
        timestamp: "2026-07-13T10:01:00.000Z",
      }),
    ).toThrow("IDENTITY_TRANSITION_INVALID");
    expect(() =>
      transitionIdentity(planned, {
        kind: "begin_registration",
        expectedRevision: 99,
        timestamp: "2026-07-13T10:01:00.000Z",
      }),
    ).toThrow("IDENTITY_REVISION_MISMATCH");
    expect(() =>
      transitionIdentity(planned, {
        kind: "begin_registration",
        expectedRevision: planned.revision,
        timestamp: "2026-07-13T09:59:00.000Z",
      }),
    ).toThrow("IDENTITY_TIMESTAMP_REGRESSION");
    const awaitingManual = begin();
    expect(() =>
      transitionIdentity(awaitingManual, {
        kind: "confirm_human_checkpoint",
        expectedRevision: awaitingManual.revision,
        evidence: human("2026-07-13T10:02:00.000Z"),
        nextStatus: "external" as "ready",
      }),
    ).toThrow("IDENTITY_NEXT_STATUS_INVALID");
    expect(() =>
      transitionIdentity(planned, {
        kind: "unknown",
        expectedRevision: planned.revision,
      } as unknown as IdentityTransition),
    ).toThrow("IDENTITY_TRANSITION_INVALID");
  });
});
