import { SecurityError } from "../shared/errors.js";
import type { TestIdentityRecord, TestIdentityStatus } from "./types.js";

export type HumanIdentityCheckpoint =
  "captcha" | "email_verification" | "manual_registration" | "terms_acceptance";

export type HumanWaitStatus =
  | "awaiting_captcha"
  | "awaiting_email_verification"
  | "awaiting_terms_acceptance";

export interface LocalHumanEvidence {
  readonly confirmed: true;
  readonly actor: string;
  readonly timestamp: string;
}

export interface MockLoginEvidence {
  readonly successful: true;
  readonly provider: "local_mock";
  readonly actor: string;
  readonly timestamp: string;
}

export interface IdentityMachineState {
  readonly identity: TestIdentityRecord;
  readonly revision: number;
  readonly completedHumanCheckpoints: readonly HumanIdentityCheckpoint[];
  readonly lastTransitionAt: string;
}

export type IdentityTransition =
  | {
      readonly kind: "begin_registration";
      readonly expectedRevision: number;
      readonly timestamp: string;
    }
  | {
      readonly kind: "confirm_human_checkpoint";
      readonly expectedRevision: number;
      readonly evidence: LocalHumanEvidence;
      readonly nextStatus: HumanWaitStatus | "ready";
    }
  | {
      readonly kind: "expire_session";
      readonly expectedRevision: number;
      readonly timestamp: string;
    }
  | {
      readonly kind: "mock_login";
      readonly expectedRevision: number;
      readonly evidence: MockLoginEvidence;
    }
  | {
      readonly kind: "suspend";
      readonly expectedRevision: number;
      readonly actor: string;
      readonly timestamp: string;
    }
  | {
      readonly kind: "human_restore";
      readonly expectedRevision: number;
      readonly evidence: LocalHumanEvidence;
    }
  | {
      readonly kind: "retire";
      readonly expectedRevision: number;
      readonly evidence: LocalHumanEvidence;
    };

type IdentityPatch = Partial<
  Pick<
    TestIdentityRecord,
    | "humanActionRequired"
    | "lastSuccessfulLoginAt"
    | "retiredAt"
    | "status"
    | "suspendedAt"
    | "verifiedAt"
  >
>;

const REFERENCE = /^[A-Za-z0-9._:/@-]{1,256}$/u;
const ACTOR = /^[A-Za-z0-9._@-]{1,128}$/u;
const RFC3339 =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/u;

const CHECKPOINT_FOR_STATUS: Readonly<
  Partial<Record<TestIdentityStatus, HumanIdentityCheckpoint>>
> = Object.freeze({
  awaiting_manual_registration: "manual_registration",
  awaiting_email_verification: "email_verification",
  awaiting_captcha: "captcha",
  awaiting_terms_acceptance: "terms_acceptance",
});

const REQUIRED_NEXT_STATUS: Readonly<
  Partial<Record<TestIdentityStatus, HumanWaitStatus | "ready">>
> = Object.freeze({
  awaiting_manual_registration: "awaiting_email_verification",
  awaiting_email_verification: "awaiting_captcha",
  awaiting_captcha: "awaiting_terms_acceptance",
  awaiting_terms_acceptance: "ready",
});

export function createIdentityMachine(
  suppliedIdentity: TestIdentityRecord,
): IdentityMachineState {
  if (
    suppliedIdentity.status !== "planned" ||
    suppliedIdentity.humanActionRequired ||
    suppliedIdentity.verifiedAt !== null ||
    suppliedIdentity.suspendedAt !== null ||
    suppliedIdentity.retiredAt !== null ||
    suppliedIdentity.lastSuccessfulLoginAt !== null
  )
    throw new SecurityError("IDENTITY_INITIAL_STATE_INVALID");
  validateStableIdentityFields(suppliedIdentity);
  const createdAt = normalizeTimestamp(suppliedIdentity.createdAt);
  const identity = freezeIdentity({
    ...suppliedIdentity,
    createdAt,
  });
  return Object.freeze({
    identity,
    revision: 0,
    completedHumanCheckpoints: Object.freeze([]),
    lastTransitionAt: createdAt,
  });
}

export function transitionIdentity(
  state: IdentityMachineState,
  transition: IdentityTransition,
): IdentityMachineState {
  assertMachineState(state);
  assertExpectedRevision(transition.expectedRevision, state.revision);

  switch (transition.kind) {
    case "begin_registration": {
      assertStatus(state, "planned");
      const timestamp = transitionTimestamp(transition.timestamp, state);
      return updateState(
        state,
        {
          status: "awaiting_manual_registration",
          humanActionRequired: true,
        },
        timestamp,
      );
    }
    case "confirm_human_checkpoint": {
      assertNextStatus(transition.nextStatus);
      const checkpoint = CHECKPOINT_FOR_STATUS[state.identity.status];
      if (checkpoint === undefined)
        throw new SecurityError("IDENTITY_HUMAN_CHECKPOINT_NOT_PENDING");
      const timestamp = humanEvidenceTimestamp(transition.evidence, state);
      if (state.completedHumanCheckpoints.includes(checkpoint))
        throw new SecurityError("IDENTITY_HUMAN_EVIDENCE_REPLAY");
      if (REQUIRED_NEXT_STATUS[state.identity.status] !== transition.nextStatus)
        throw new SecurityError("IDENTITY_CHECKPOINT_SEQUENCE_INVALID");
      const completed = Object.freeze(
        [...state.completedHumanCheckpoints, checkpoint].sort(compareAscii),
      );
      return updateState(
        state,
        {
          status: transition.nextStatus,
          humanActionRequired: transition.nextStatus !== "ready",
          ...(transition.nextStatus === "ready" &&
          state.identity.verifiedAt === null
            ? { verifiedAt: timestamp }
            : {}),
        },
        timestamp,
        completed,
      );
    }
    case "expire_session": {
      assertStatus(state, "ready");
      const timestamp = transitionTimestamp(transition.timestamp, state);
      return updateState(
        state,
        { status: "session_expired", humanActionRequired: true },
        timestamp,
      );
    }
    case "mock_login": {
      assertStatus(state, "session_expired");
      const timestamp = mockLoginTimestamp(transition.evidence, state);
      return updateState(
        state,
        {
          status: "ready",
          humanActionRequired: false,
          lastSuccessfulLoginAt: timestamp,
        },
        timestamp,
      );
    }
    case "suspend": {
      assertStatus(state, "ready");
      validateActor(transition.actor);
      const timestamp = transitionTimestamp(transition.timestamp, state);
      return updateState(
        state,
        {
          status: "suspended",
          humanActionRequired: true,
          suspendedAt: timestamp,
        },
        timestamp,
      );
    }
    case "human_restore": {
      assertStatus(state, "suspended");
      const timestamp = humanEvidenceTimestamp(transition.evidence, state);
      return updateState(
        state,
        { status: "ready", humanActionRequired: false },
        timestamp,
      );
    }
    case "retire": {
      if (state.identity.status === "retired")
        throw new SecurityError("IDENTITY_ALREADY_RETIRED");
      const timestamp = humanEvidenceTimestamp(transition.evidence, state);
      return updateState(
        state,
        {
          status: "retired",
          humanActionRequired: false,
          retiredAt: timestamp,
        },
        timestamp,
      );
    }
  }
  throw new SecurityError("IDENTITY_TRANSITION_INVALID");
}

function updateState(
  state: IdentityMachineState,
  patch: IdentityPatch,
  timestamp: string,
  completedHumanCheckpoints = state.completedHumanCheckpoints,
): IdentityMachineState {
  const identity = freezeIdentity({ ...state.identity, ...patch });
  return Object.freeze({
    identity,
    revision: state.revision + 1,
    completedHumanCheckpoints,
    lastTransitionAt: timestamp,
  });
}

function freezeIdentity(identity: TestIdentityRecord): TestIdentityRecord {
  return Object.freeze({
    ...identity,
    secretReferences: Object.freeze([...identity.secretReferences]),
    ownedObjectRefs: Object.freeze([...identity.ownedObjectRefs]),
  });
}

function assertMachineState(state: IdentityMachineState): void {
  if (!Number.isSafeInteger(state.revision) || state.revision < 0)
    throw new SecurityError("IDENTITY_REVISION_INVALID");
  validateStableIdentityFields(state.identity);
  if (!isIdentityStatus(state.identity.status))
    throw new SecurityError("IDENTITY_STATE_INVALID");
  const shouldRequireHumanAction =
    state.identity.status === "awaiting_manual_registration" ||
    state.identity.status === "awaiting_email_verification" ||
    state.identity.status === "awaiting_captcha" ||
    state.identity.status === "awaiting_terms_acceptance" ||
    state.identity.status === "session_expired" ||
    state.identity.status === "suspended";
  if (state.identity.humanActionRequired !== shouldRequireHumanAction)
    throw new SecurityError("IDENTITY_STATE_INVALID");
  normalizeTimestamp(state.lastTransitionAt);
  const unique = new Set(state.completedHumanCheckpoints);
  if (
    unique.size !== state.completedHumanCheckpoints.length ||
    state.completedHumanCheckpoints.some(
      (checkpoint) => !isHumanCheckpoint(checkpoint),
    )
  )
    throw new SecurityError("IDENTITY_CHECKPOINT_HISTORY_INVALID");
}

function validateStableIdentityFields(identity: TestIdentityRecord): void {
  for (const reference of [identity.id, identity.programId])
    validateReference(reference);
  for (const reference of [
    identity.emailReference,
    identity.browserProfileReference,
    identity.platformAccountReference,
    identity.organizationRef,
  ])
    if (reference !== null) validateReference(reference);
  for (const reference of [
    ...identity.secretReferences,
    ...identity.ownedObjectRefs,
  ])
    validateReference(reference);
}

function validateReference(value: unknown): void {
  if (typeof value !== "string" || !REFERENCE.test(value))
    throw new SecurityError("IDENTITY_REFERENCE_INVALID");
}

function assertExpectedRevision(value: unknown, current: number): void {
  if (!Number.isSafeInteger(value) || value !== current)
    throw new SecurityError("IDENTITY_REVISION_MISMATCH");
}

function assertStatus(
  state: IdentityMachineState,
  required: TestIdentityStatus,
): void {
  if (state.identity.status !== required)
    throw new SecurityError("IDENTITY_TRANSITION_INVALID");
}

function humanEvidenceTimestamp(
  value: unknown,
  state: IdentityMachineState,
): string {
  assertRecord(value, "IDENTITY_HUMAN_EVIDENCE_INVALID");
  if (
    Object.keys(value).length !== 3 ||
    value["confirmed"] !== true ||
    !("actor" in value) ||
    !("timestamp" in value)
  )
    throw new SecurityError("IDENTITY_HUMAN_EVIDENCE_INVALID");
  validateActor(value["actor"]);
  return transitionTimestamp(value["timestamp"], state);
}

function mockLoginTimestamp(
  value: unknown,
  state: IdentityMachineState,
): string {
  assertRecord(value, "IDENTITY_MOCK_LOGIN_INVALID");
  if (
    Object.keys(value).length !== 4 ||
    value["successful"] !== true ||
    value["provider"] !== "local_mock" ||
    !("actor" in value) ||
    !("timestamp" in value)
  )
    throw new SecurityError("IDENTITY_MOCK_LOGIN_INVALID");
  validateActor(value["actor"]);
  return transitionTimestamp(value["timestamp"], state);
}

function validateActor(value: unknown): void {
  if (typeof value !== "string" || !ACTOR.test(value))
    throw new SecurityError("IDENTITY_ACTOR_INVALID");
}

function assertRecord(
  value: unknown,
  code: string,
): asserts value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new SecurityError(code);
}

function isHumanCheckpoint(value: unknown): boolean {
  return (
    value === "captcha" ||
    value === "email_verification" ||
    value === "manual_registration" ||
    value === "terms_acceptance"
  );
}

function isIdentityStatus(value: unknown): value is TestIdentityStatus {
  return (
    value === "planned" ||
    value === "awaiting_manual_registration" ||
    value === "awaiting_email_verification" ||
    value === "awaiting_captcha" ||
    value === "awaiting_terms_acceptance" ||
    value === "ready" ||
    value === "session_expired" ||
    value === "suspended" ||
    value === "retired"
  );
}

function assertNextStatus(
  value: unknown,
): asserts value is HumanWaitStatus | "ready" {
  if (
    value !== "awaiting_email_verification" &&
    value !== "awaiting_captcha" &&
    value !== "awaiting_terms_acceptance" &&
    value !== "ready"
  )
    throw new SecurityError("IDENTITY_NEXT_STATUS_INVALID");
}

function transitionTimestamp(
  value: unknown,
  state: IdentityMachineState,
): string {
  const normalized = normalizeTimestamp(value);
  if (Date.parse(normalized) < Date.parse(state.lastTransitionAt))
    throw new SecurityError("IDENTITY_TIMESTAMP_REGRESSION");
  return normalized;
}

function normalizeTimestamp(value: unknown): string {
  if (typeof value !== "string" || !RFC3339.test(value))
    throw new SecurityError("IDENTITY_TIMESTAMP_INVALID");
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp))
    throw new SecurityError("IDENTITY_TIMESTAMP_INVALID");
  return new Date(timestamp).toISOString();
}

function compareAscii(
  left: HumanIdentityCheckpoint,
  right: HumanIdentityCheckpoint,
): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
