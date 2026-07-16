import { types } from "node:util";
import {
  isActiveTestingActionGateBoundToRuntime,
  isActiveTestingServiceBoundToGate,
  isTrustedActiveTestingRuntime,
  listActiveTestCatalog,
  projectActiveTestAsset,
  type ActiveTestCompletionResult,
  type ActiveTestPlanApprovalPreparationInput,
  type ActiveTestPlanApprovalPreparationResult,
  type ActiveTestReservationInput,
  type ActiveTestingActionGate,
  type ActiveTestingRuntimeState,
  type ActiveTestingService,
  type StoredActiveTestPlanRecord,
} from "../active-testing/index.js";
import { SecurityError } from "../shared/errors.js";

const MAX_ASSET_CANDIDATES = 500;
const IDENTIFIER = /^[A-Za-z0-9._-]{1,128}$/u;
const trustedControllers = new WeakSet();

export interface LocalActiveTestingControllerOptions {
  readonly service: ActiveTestingService;
  readonly gate: ActiveTestingActionGate;
  readonly runtime: ActiveTestingRuntimeState;
}

export interface ActiveTestingProjectionContext {
  readonly secureCoreReady: boolean;
  readonly operatorSignerAvailable: boolean;
  readonly killSwitchActive: boolean;
  readonly now: string;
}

export class LocalActiveTestingController {
  readonly #service: ActiveTestingService;
  readonly #runtime: ActiveTestingRuntimeState;

  public constructor(options: LocalActiveTestingControllerOptions) {
    if (
      !isTrustedActiveTestingRuntime(options.runtime) ||
      !isActiveTestingServiceBoundToGate(options.service, options.gate) ||
      !isActiveTestingActionGateBoundToRuntime(options.gate, options.runtime)
    )
      throw new SecurityError("ACTIVE_TESTING_CONTROLLER_UNTRUSTED");
    this.#service = options.service;
    this.#runtime = options.runtime;
    trustedControllers.add(this);
    Object.freeze(this);
  }

  public preparePlanApproval(
    input: ActiveTestPlanApprovalPreparationInput,
  ): ActiveTestPlanApprovalPreparationResult {
    return this.#service.preparePlanApproval(input);
  }

  public executeConfirmed(
    input: ActiveTestReservationInput,
  ): Promise<ActiveTestCompletionResult> {
    return this.#service.executeConfirmed(input);
  }

  public assertApprovalState(
    planId: string,
    approvalId: string,
    expected: "accepted" | "open",
  ): void {
    const plan = this.#service
      .listPlans()
      .find(
        (candidate) =>
          candidate.planId === planId && candidate.approvalId === approvalId,
      );
    if (plan?.approvalStatus !== expected || plan.attemptStatus !== null)
      throw new SecurityError("ACTIVE_TESTING_APPROVAL_NOT_CURRENT");
  }

  public assertRuntimeEnabled(): void {
    if (
      !this.#runtime.configured ||
      !this.#runtime.enabled ||
      !this.#runtime.externalIntegrationsEnabled
    )
      throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
  }

  public project(context: ActiveTestingProjectionContext): unknown {
    assertProjectionContext(context);
    const selectedProgramRef = this.#service.selectedProgramRef();
    const allPrograms = this.#service.listPrograms();
    const selected =
      selectedProgramRef === null
        ? undefined
        : allPrograms.find(({ localRef }) => localRef === selectedProgramRef);
    const current =
      selected === undefined
        ? undefined
        : this.#service.currentSnapshot(selected.localRef);
    const selectedApiProgram =
      selected?.program.source === "hackerone_api_authenticated"
        ? selected
        : undefined;
    const currentApiSnapshot =
      current?.snapshot.source === "hackerone_api_authenticated"
        ? current
        : undefined;
    const reasons: string[] = [];
    if (!this.#runtime.externalIntegrationsEnabled)
      reasons.push("ACTIVE_TESTING_EXTERNAL_INTEGRATIONS_DISABLED");
    if (!this.#runtime.enabled)
      reasons.push("ACTIVE_TESTING_CAPABILITY_DISABLED");
    if (!context.secureCoreReady)
      reasons.push("ACTIVE_TESTING_SECURE_CORE_REQUIRED");
    if (!context.operatorSignerAvailable)
      reasons.push("ACTIVE_TESTING_OPERATOR_SIGNER_REQUIRED");
    if (context.killSwitchActive)
      reasons.push("ACTIVE_TESTING_KILL_SWITCH_ACTIVE");
    if (selectedApiProgram === undefined)
      reasons.push("ACTIVE_TESTING_API_PROGRAM_SELECTION_REQUIRED");
    if (
      selectedApiProgram !== undefined &&
      (!selectedApiProgram.catalogActive ||
        selectedApiProgram.catalogDriftPending)
    )
      reasons.push("ACTIVE_TESTING_PROGRAM_CATALOG_NOT_CURRENT");
    if (
      currentApiSnapshot === undefined ||
      currentApiSnapshot.programLocalRef !== selectedApiProgram?.localRef
    )
      reasons.push("ACTIVE_TESTING_CURRENT_API_SNAPSHOT_REQUIRED");
    else if (currentApiSnapshot.acceptancePending)
      reasons.push("ACTIVE_TESTING_CURRENT_SNAPSHOT_ACCEPTANCE_REQUIRED");

    const scopes = currentApiSnapshot?.snapshot.structuredScopes ?? [];
    if (scopes.length > MAX_ASSET_CANDIDATES)
      reasons.push("ACTIVE_TESTING_ASSET_LIMIT_EXCEEDED");
    if (scopes.some(({ id }) => !IDENTIFIER.test(id)))
      reasons.push("ACTIVE_TESTING_SCOPE_IDENTIFIER_INVALID");
    const canProjectAssets =
      scopes.length <= MAX_ASSET_CANDIDATES &&
      scopes.every(({ id }) => IDENTIFIER.test(id));
    const assetCandidates =
      currentApiSnapshot === undefined || !canProjectAssets
        ? Object.freeze([])
        : Object.freeze(
            scopes.map((scope) =>
              Object.freeze({
                programRef: currentApiSnapshot.programLocalRef,
                snapshotDigest: currentApiSnapshot.snapshot.snapshotDigest,
                ...projectActiveTestAsset(scope),
              }),
            ),
          );
    if (
      currentApiSnapshot !== undefined &&
      canProjectAssets &&
      !assetCandidates.some(({ supported }) => supported)
    )
      reasons.push("ACTIVE_TESTING_NO_SUPPORTED_ASSET");

    const plans = this.#service.listPlans();
    const currentPlan = selectCurrentPlan(
      plans,
      selectedApiProgram?.localRef,
      currentApiSnapshot?.snapshot.snapshotDigest,
      context.now,
    );
    const attempts = Object.freeze(
      this.#service
        .listAttempts()
        .slice(-100)
        .reverse()
        .map((attempt) =>
          Object.freeze({
            authorizationId: attempt.authorizationId,
            planId: attempt.planId,
            testClass: attempt.testClass,
            method: attempt.method,
            status: attempt.status,
            reservedAt: attempt.reservedAt,
            startedAt: attempt.startedAt,
            finishedAt: attempt.finishedAt,
          }),
        ),
    );
    const reports = Object.freeze(
      this.#service
        .listReportSummaries()
        .map((report) => Object.freeze({ ...report })),
    );

    return Object.freeze({
      capability: Object.freeze({
        available: true,
        configured: this.#runtime.configured,
        enabled: this.#runtime.enabled,
        secureCoreReady: context.secureCoreReady,
        killSwitchActive: context.killSwitchActive,
        reasonCodes: Object.freeze([...new Set(reasons)]),
      }),
      programs:
        selectedApiProgram === undefined
          ? Object.freeze([])
          : Object.freeze([
              Object.freeze({
                programRef: selectedApiProgram.localRef,
                name: selectedApiProgram.program.name,
                handle: selectedApiProgram.program.handle,
                source: "hackerone_api_authenticated" as const,
                catalogActive: selectedApiProgram.catalogActive,
                catalogDriftPending: selectedApiProgram.catalogDriftPending,
              }),
            ]),
      snapshots:
        currentApiSnapshot === undefined
          ? Object.freeze([])
          : Object.freeze([
              Object.freeze({
                programRef: currentApiSnapshot.programLocalRef,
                snapshotDigest: currentApiSnapshot.snapshot.snapshotDigest,
                policyDigest: currentApiSnapshot.snapshot.policyDigest,
                source: "hackerone_api_authenticated" as const,
                current: true,
                accepted: !currentApiSnapshot.acceptancePending,
              }),
            ]),
      assetCandidates,
      testCatalog: listActiveTestCatalog(),
      currentPlan:
        currentPlan === null
          ? null
          : Object.freeze({
              planId: currentPlan.planId,
              planDigest: currentPlan.planDigest,
              programRef: currentPlan.programRef,
              snapshotDigest: currentPlan.snapshotDigest,
              scopeId: currentPlan.scopeId,
              assetIdentifierDigest: currentPlan.assetIdentifierDigest,
              testClass: currentPlan.testClass,
              status: currentPlanStatus(currentPlan),
            }),
      currentApproval:
        currentPlan === null
          ? null
          : Object.freeze({
              approvalId: currentPlan.approvalId,
              planId: currentPlan.planId,
              status: currentPlan.approvalStatus,
            }),
      attempts,
      reports,
    });
  }
}

export function isTrustedLocalActiveTestingController(
  value: unknown,
): value is LocalActiveTestingController {
  if (value === null || typeof value !== "object") return false;
  try {
    return (
      !types.isProxy(value) &&
      Reflect.getPrototypeOf(value) ===
        LocalActiveTestingController.prototype &&
      trustedControllers.has(value)
    );
  } catch {
    return false;
  }
}

export function unavailableActiveTestingProjection(
  secureCoreReady: boolean,
  killSwitchActive: boolean,
): unknown {
  return Object.freeze({
    capability: Object.freeze({
      available: false,
      configured: false,
      enabled: false,
      secureCoreReady,
      killSwitchActive,
      reasonCodes: Object.freeze(["ACTIVE_TESTING_CONTROLLER_UNAVAILABLE"]),
    }),
    programs: Object.freeze([]),
    snapshots: Object.freeze([]),
    assetCandidates: Object.freeze([]),
    testCatalog: listActiveTestCatalog(),
    currentPlan: null,
    currentApproval: null,
    attempts: Object.freeze([]),
    reports: Object.freeze([]),
  });
}

function selectCurrentPlan(
  plans: readonly StoredActiveTestPlanRecord[],
  selectedProgramRef: string | undefined,
  snapshotDigest: string | undefined,
  now: string,
): StoredActiveTestPlanRecord | null {
  if (selectedProgramRef === undefined || snapshotDigest === undefined)
    return null;
  return (
    plans.find(
      (plan) =>
        plan.programRef === selectedProgramRef &&
        plan.snapshotDigest === snapshotDigest &&
        now < plan.expiresAt &&
        plan.approvalStatus !== "rejected" &&
        (plan.attemptStatus === null ||
          plan.attemptStatus === "reserved" ||
          plan.attemptStatus === "running"),
    ) ?? null
  );
}

function currentPlanStatus(
  plan: StoredActiveTestPlanRecord,
): "approved" | "prepared" | "running" {
  if (plan.attemptStatus === "reserved" || plan.attemptStatus === "running")
    return "running";
  return plan.approvalStatus === "accepted" ? "approved" : "prepared";
}

function assertProjectionContext(value: ActiveTestingProjectionContext): void {
  if (
    typeof value.secureCoreReady !== "boolean" ||
    typeof value.operatorSignerAvailable !== "boolean" ||
    typeof value.killSwitchActive !== "boolean" ||
    typeof value.now !== "string" ||
    !Number.isFinite(Date.parse(value.now)) ||
    new Date(Date.parse(value.now)).toISOString() !== value.now
  )
    throw new SecurityError("ACTIVE_TESTING_PROJECTION_CONTEXT_INVALID");
}
