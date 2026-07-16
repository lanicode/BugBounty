import { types } from "node:util";
import type { ApprovalRecord } from "../control-plane/types.js";
import { HackerOneMetadataStore } from "../hackerone-readonly/store.js";
import type {
  StoredHackerOnePolicySnapshot,
  StoredHackerOneProgram,
} from "../hackerone-readonly/store.js";
import { SecurityError } from "../shared/errors.js";
import { createActiveTestPlan } from "./catalog.js";
import {
  isTrustedActiveTestingActionGate,
  type ActiveTestCompletionResult,
  type ActiveTestAttemptRecord,
  type ActiveTestReservationInput,
  type ActiveTestingActionGate,
  type StoredActiveTestPlanRecord,
  type StoredActiveTestReportSummary,
} from "./gate.js";
import {
  isTrustedActiveTestTransport,
  type ActiveTestTransport,
} from "./transport.js";
import type { ActiveTestClass, ActiveTestPlanV1 } from "./types.js";

const IDENTIFIER = /^[A-Za-z0-9._-]{1,128}$/u;
const OPERATOR = /^[A-Za-z0-9._@-]{1,128}$/u;
const PROGRAM_REF = /^h1a_[a-f0-9]{64}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;
const trustedServices = new WeakMap<object, ActiveTestingActionGate>();

export interface ActiveTestPlanApprovalPreparationInput {
  readonly planId: string;
  readonly approvalId: string;
  readonly operatorId: string;
  readonly programRef: string;
  readonly snapshotDigest: string;
  readonly scopeId: string;
  readonly assetIdentifierDigest: string;
  readonly testClass: ActiveTestClass;
  readonly createdAt: string;
  readonly confirmations: {
    readonly automationPermissionReviewed: true;
    readonly scopeInstructionReviewed: true;
    readonly scopeExclusionsReviewed: true;
    readonly noSideEffectsConfirmed: true;
  };
}

export interface ActiveTestPlanApprovalPreparationResult {
  readonly plan: ActiveTestPlanV1;
  readonly approval: ApprovalRecord;
}

/**
 * Store-bound two-step orchestration for the active-test pilot.
 *
 * Preparing an approval never executes a request. Execution remains a second,
 * explicit operation after the control plane has persisted a valid signed
 * approval decision for the returned approval record.
 */
export class ActiveTestingService {
  public constructor(
    private readonly metadata: HackerOneMetadataStore,
    private readonly gate: ActiveTestingActionGate,
    private readonly transport: ActiveTestTransport,
  ) {
    if (!isTrustedMetadataStore(metadata))
      throw new SecurityError("ACTIVE_TEST_METADATA_STORE_UNTRUSTED");
    if (!isTrustedActiveTestingActionGate(gate))
      throw new SecurityError("ACTIVE_TEST_GATE_UNTRUSTED");
    if (!isTrustedActiveTestTransport(transport))
      throw new SecurityError("ACTIVE_TEST_TRANSPORT_UNTRUSTED");
    trustedServices.set(this, gate);
    Object.freeze(this);
  }

  public preparePlanApproval(
    value: ActiveTestPlanApprovalPreparationInput,
  ): ActiveTestPlanApprovalPreparationResult {
    const input = capturePreparationInput(value);
    const current = this.metadata.getCurrentSnapshot(input.programRef);
    if (current === undefined)
      throw new SecurityError("ACTIVE_TEST_CURRENT_SNAPSHOT_REQUIRED");
    if (current.snapshot.snapshotDigest !== input.snapshotDigest)
      throw new SecurityError("ACTIVE_TEST_SNAPSHOT_SELECTION_STALE");
    const scope = current.snapshot.structuredScopes.find(
      (candidate) => candidate.id === input.scopeId,
    );
    if (scope === undefined)
      throw new SecurityError("ACTIVE_TEST_SCOPE_BINDING_INVALID");
    if (scope.assetIdentifierDigest !== input.assetIdentifierDigest)
      throw new SecurityError("ACTIVE_TEST_ASSET_SELECTION_STALE");
    const plan = createActiveTestPlan({
      planId: input.planId,
      programRef: input.programRef,
      snapshot: current.snapshot,
      scopeId: scope.id,
      assetIdentifierDigest: scope.assetIdentifierDigest,
      testClass: input.testClass,
      createdAt: input.createdAt,
      confirmations: input.confirmations,
    });
    const approval = this.gate.preparePlanApproval({
      approvalId: input.approvalId,
      operatorId: input.operatorId,
      plan,
      createdAt: input.createdAt,
    });
    return Object.freeze({ plan, approval });
  }

  public async executeConfirmed(
    value: ActiveTestReservationInput,
  ): Promise<ActiveTestCompletionResult> {
    const authorization = this.gate.authorizeAndReserve(value);
    let transportPlan;
    try {
      transportPlan = this.gate.start(authorization);
    } catch (error) {
      this.gate.abortReservation(authorization);
      throw error;
    }
    try {
      const evidence = await this.transport.run(transportPlan);
      return this.gate.complete(authorization, evidence);
    } catch (error) {
      this.gate.settle(authorization, "failed");
      throw error;
    }
  }

  public selectedProgramRef(): string | null {
    return this.metadata.getIntegrationState().selectedProgramRef;
  }

  public listPrograms(): readonly StoredHackerOneProgram[] {
    return this.metadata.listPrograms();
  }

  public currentSnapshot(
    programRef: string,
  ): StoredHackerOnePolicySnapshot | undefined {
    return this.metadata.getCurrentSnapshot(programRef);
  }

  public listAttempts(): readonly ActiveTestAttemptRecord[] {
    return this.gate.listAttempts();
  }

  public listPlans(): readonly StoredActiveTestPlanRecord[] {
    return this.gate.listPlans();
  }

  public listReportSummaries(): readonly StoredActiveTestReportSummary[] {
    return this.gate.listReportSummaries();
  }
}

export function isTrustedActiveTestingService(
  value: unknown,
): value is ActiveTestingService {
  if (value === null || typeof value !== "object") return false;
  try {
    return (
      !types.isProxy(value) &&
      Reflect.getPrototypeOf(value) === ActiveTestingService.prototype &&
      trustedServices.has(value)
    );
  } catch {
    return false;
  }
}

export function isActiveTestingServiceBoundToGate(
  service: unknown,
  gate: unknown,
): gate is ActiveTestingActionGate {
  return (
    isTrustedActiveTestingService(service) &&
    typeof gate === "object" &&
    gate !== null &&
    trustedServices.get(service) === gate
  );
}

function isTrustedMetadataStore(
  value: unknown,
): value is HackerOneMetadataStore {
  if (value === null || typeof value !== "object") return false;
  try {
    return (
      !types.isProxy(value) &&
      Reflect.getPrototypeOf(value) === HackerOneMetadataStore.prototype
    );
  } catch {
    return false;
  }
}

function capturePreparationInput(
  value: unknown,
): ActiveTestPlanApprovalPreparationInput {
  const row = exactRecord(value, [
    "planId",
    "approvalId",
    "operatorId",
    "programRef",
    "snapshotDigest",
    "scopeId",
    "assetIdentifierDigest",
    "testClass",
    "createdAt",
    "confirmations",
  ]);
  const confirmations = exactRecord(row["confirmations"], [
    "automationPermissionReviewed",
    "scopeInstructionReviewed",
    "scopeExclusionsReviewed",
    "noSideEffectsConfirmed",
  ]);
  if (
    confirmations["automationPermissionReviewed"] !== true ||
    confirmations["scopeInstructionReviewed"] !== true ||
    confirmations["scopeExclusionsReviewed"] !== true ||
    confirmations["noSideEffectsConfirmed"] !== true
  )
    throw new SecurityError("ACTIVE_TEST_CONFIRMATIONS_REQUIRED");
  const testClass = row["testClass"];
  if (!(
    testClass === "cors_preflight" ||
    testClass === "http_headers" ||
    testClass === "security_txt"
  ))
    throw new SecurityError("ACTIVE_TEST_CLASS_INVALID");
  return Object.freeze({
    planId: required(
      row["planId"],
      IDENTIFIER,
      "ACTIVE_TEST_IDENTIFIER_INVALID",
    ),
    approvalId: required(
      row["approvalId"],
      IDENTIFIER,
      "ACTIVE_TEST_IDENTIFIER_INVALID",
    ),
    operatorId: required(
      row["operatorId"],
      OPERATOR,
      "ACTIVE_TEST_OPERATOR_INVALID",
    ),
    programRef: required(
      row["programRef"],
      PROGRAM_REF,
      "ACTIVE_TEST_PROGRAM_REF_INVALID",
    ),
    snapshotDigest: required(
      row["snapshotDigest"],
      DIGEST,
      "ACTIVE_TEST_DIGEST_INVALID",
    ),
    scopeId: required(
      row["scopeId"],
      IDENTIFIER,
      "ACTIVE_TEST_IDENTIFIER_INVALID",
    ),
    assetIdentifierDigest: required(
      row["assetIdentifierDigest"],
      DIGEST,
      "ACTIVE_TEST_DIGEST_INVALID",
    ),
    testClass,
    createdAt: requiredTimestamp(row["createdAt"]),
    confirmations: Object.freeze({
      automationPermissionReviewed: true,
      scopeInstructionReviewed: true,
      scopeExclusionsReviewed: true,
      noSideEffectsConfirmed: true,
    }),
  });
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
): Readonly<Record<string, unknown>> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype
  )
    throw new SecurityError("ACTIVE_TEST_INPUT_INVALID");
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== "string") ||
    !keys.every((key) => ownKeys.includes(key))
  )
    throw new SecurityError("ACTIVE_TEST_INPUT_INVALID");
  const result: Record<string, unknown> = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    )
      throw new SecurityError("ACTIVE_TEST_INPUT_INVALID");
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function required(value: unknown, pattern: RegExp, code: string): string {
  if (typeof value !== "string" || !pattern.test(value))
    throw new SecurityError(code);
  return value;
}

function requiredTimestamp(value: unknown): string {
  if (typeof value !== "string")
    throw new SecurityError("ACTIVE_TEST_TIME_INVALID");
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  )
    throw new SecurityError("ACTIVE_TEST_TIME_INVALID");
  return value;
}
