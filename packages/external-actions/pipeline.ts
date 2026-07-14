import { types } from "node:util";
import type { Phase2RuntimeState } from "../phase2-config/runtime.js";
import { SecurityError } from "../shared/errors.js";
import type { JsonValue } from "../shared/canonical.js";
import {
  isTrustedControlPlaneStore,
  type ControlPlaneStore,
} from "../control-plane/store.js";
import type {
  ExternalActionEvidenceDefinition,
  StoreBoundExternalActionAuthorization,
} from "../control-plane/external-action-evidence.js";
import type { ApprovalRecord } from "../control-plane/types.js";
import {
  getExternalActionDefinition,
  type ExternalActionDefinition,
  type ExternalActionId,
} from "./registry.js";
import {
  validateAndFreezeExternalActionProposal,
  type ExternalActionProposal,
} from "./proposal.js";

export type ExternalActionKind = ExternalActionId;
export type { ExternalActionProposal } from "./proposal.js";

export type ExternalActionTrace = readonly [
  "schema",
  "policy",
  "scope",
  "ownership",
  "budget",
  "human_checkpoint",
  "runner",
];

export interface ExternalActionResult {
  readonly proposalId: string;
  readonly actionId: ExternalActionId;
  readonly result: JsonValue;
  readonly trace: ExternalActionTrace;
}

export interface TrustedExternalActionExecution {
  readonly proposal: ExternalActionProposal;
  readonly definition: ExternalActionDefinition;
  readonly target: {
    readonly class: ExternalActionDefinition["targetClass"];
    readonly scheme: "http";
    readonly host: "127.0.0.1";
  };
}

export interface DeterministicActionRunner {
  readonly kind: "external_disabled" | "simulation_mock";
  run(
    execution: TrustedExternalActionExecution,
    signal: AbortSignal,
  ): Promise<JsonValue>;
}

export interface Phase2KillSwitchStateReader {
  readActive(): boolean;
}

export interface DeterministicMockActionRunnerOptions {
  readonly deferredProposalIds?: readonly string[];
}

export interface StoreBoundActionProposalInput {
  readonly proposalId: string;
  readonly actionId: ExternalActionId;
  readonly campaignRef: string;
  readonly accountRef: string | null;
  readonly objectRef: string | null;
  readonly payloadRef: null;
  readonly approvalRef: string;
  readonly operatorRef: string;
}

export interface ExternalActionAuthorizationEvaluator {
  authorizeAndReserve(
    execution: TrustedExternalActionExecution,
    runtimeMaxActions: number,
    runtimeMaxConcurrency: number,
  ): StoreBoundExternalActionAuthorization;
  start(
    execution: TrustedExternalActionExecution,
    authorization: StoreBoundExternalActionAuthorization,
  ): void;
  abortReservation(
    execution: TrustedExternalActionExecution,
    authorization: StoreBoundExternalActionAuthorization,
  ): void;
  settle(
    execution: TrustedExternalActionExecution,
    authorization: StoreBoundExternalActionAuthorization,
    outcome: "aborted" | "failed" | "succeeded",
  ): void;
}

const trustedAuthorizationEvaluators =
  new WeakSet<ExternalActionAuthorizationEvaluator>();
const trustedKillSwitches = new WeakSet<Phase2KillSwitch>();

class DenyAllExternalActionEvaluator implements ExternalActionAuthorizationEvaluator {
  public constructor() {
    trustedAuthorizationEvaluators.add(this);
    Object.freeze(this);
  }

  public authorizeAndReserve(): StoreBoundExternalActionAuthorization {
    throw new SecurityError("ACTION_STORE_EVIDENCE_REQUIRED");
  }

  public start(): void {
    throw new SecurityError("ACTION_STORE_EVIDENCE_REQUIRED");
  }

  public abortReservation(): void {
    throw new SecurityError("ACTION_STORE_EVIDENCE_REQUIRED");
  }

  public settle(): void {
    throw new SecurityError("ACTION_STORE_EVIDENCE_REQUIRED");
  }
}

export class StoreBoundExternalActionEvaluator implements ExternalActionAuthorizationEvaluator {
  public constructor(private readonly store: ControlPlaneStore) {
    if (!isTrustedControlPlaneStore(store))
      throw new SecurityError("ACTION_STORE_UNTRUSTED");
    trustedAuthorizationEvaluators.add(this);
    Object.freeze(this);
  }

  public authorizeAndReserve(
    execution: TrustedExternalActionExecution,
    runtimeMaxActions: number,
    runtimeMaxConcurrency: number,
  ): StoreBoundExternalActionAuthorization {
    return this.store.authorizeExternalAction({
      proposal: execution.proposal,
      definition: evidenceDefinition(execution.definition),
      now: systemTimestamp(),
      runtimeMaxActions,
      runtimeMaxConcurrency,
    });
  }

  public start(
    execution: TrustedExternalActionExecution,
    authorization: StoreBoundExternalActionAuthorization,
  ): void {
    this.store.startExternalAction(
      execution.proposal,
      evidenceDefinition(execution.definition),
      authorization,
      systemTimestamp(),
    );
  }

  public abortReservation(
    execution: TrustedExternalActionExecution,
    authorization: StoreBoundExternalActionAuthorization,
  ): void {
    this.store.abortExternalActionReservation(
      execution.proposal,
      authorization,
      monotonicSystemTimestamp(authorization.reservedAt),
    );
  }

  public settle(
    execution: TrustedExternalActionExecution,
    authorization: StoreBoundExternalActionAuthorization,
    outcome: "aborted" | "failed" | "succeeded",
  ): void {
    this.store.settleExternalAction(
      execution.proposal,
      evidenceDefinition(execution.definition),
      authorization,
      outcome,
      systemTimestamp(),
    );
  }
}

const DENY_ALL_AUTHORIZATIONS = new DenyAllExternalActionEvaluator();

const SUCCESS_TRACE: ExternalActionTrace = Object.freeze([
  "schema",
  "policy",
  "scope",
  "ownership",
  "budget",
  "human_checkpoint",
  "runner",
]);

const trustedMockRunners = new WeakSet();
const trustedDisabledRunners = new WeakSet();

export class Phase2KillSwitch {
  readonly #controller = new AbortController();
  private readonly readState: (() => boolean) | undefined;

  public constructor(stateReader: Phase2KillSwitchStateReader | undefined) {
    this.readState = captureKillSwitchReader(stateReader);
    trustedKillSwitches.add(this);
    Object.freeze(this);
  }

  public get signal(): AbortSignal {
    return this.#controller.signal;
  }

  public kill(): void {
    if (!this.signal.aborted)
      this.#controller.abort(new Error("PHASE2_GLOBAL_KILL_SWITCH"));
  }

  public assertInactive(): void {
    assertNotAborted(this.signal, "ACTION_KILL_SWITCH");
    if (this.readState === undefined) {
      this.kill();
      throw new SecurityError("ACTION_KILL_SWITCH");
    }
    let active: unknown;
    try {
      active = this.readState();
    } catch {
      this.kill();
      throw new SecurityError("ACTION_KILL_SWITCH");
    }
    if (active !== false) {
      this.kill();
      throw new SecurityError("ACTION_KILL_SWITCH");
    }
    assertNotAborted(this.signal, "ACTION_KILL_SWITCH");
  }

  public monitor<T>(operation: () => Promise<T>): Promise<T> {
    this.assertInactive();
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const finish = (complete: () => void): void => {
        if (settled) return;
        settled = true;
        clearInterval(timer);
        complete();
      };
      const timer = setInterval(() => {
        try {
          this.assertInactive();
        } catch {
          finish(() => {
            reject(new SecurityError("ACTION_KILL_SWITCH"));
          });
        }
      }, 5);
      timer.unref();
      let pending: Promise<T>;
      try {
        pending = operation();
      } catch (error) {
        finish(() => {
          reject(asError(error));
        });
        return;
      }
      void pending.then(
        (value) => {
          finish(() => {
            resolve(value);
          });
        },
        (error: unknown) => {
          finish(() => {
            reject(asError(error));
          });
        },
      );
    });
  }
}

export class ExternalActionPipeline {
  private readonly runtime: Phase2RuntimeState;
  private readonly runner: DeterministicActionRunner;
  private readonly killSwitch: Phase2KillSwitch;
  private readonly authorizer: ExternalActionAuthorizationEvaluator;

  public constructor(
    runtime: Phase2RuntimeState,
    runner: DeterministicActionRunner,
    killSwitch: Phase2KillSwitch,
    authorizer: ExternalActionAuthorizationEvaluator = DENY_ALL_AUTHORIZATIONS,
  ) {
    assertTrustedRunner(runner);
    assertTrustedAuthorizer(authorizer);
    assertTrustedKillSwitch(killSwitch);
    assertRuntimeBudget(runtime);
    this.runtime = runtime;
    this.runner = runner;
    this.killSwitch = killSwitch;
    this.authorizer = authorizer;
    Object.freeze(this);
  }

  public async execute(value: unknown): Promise<ExternalActionResult> {
    this.killSwitch.assertInactive();
    let proposal: ExternalActionProposal;
    try {
      proposal = validateAndFreezeExternalActionProposal(value);
    } catch {
      throw new SecurityError("ACTION_SCHEMA_INVALID");
    }
    const definition = getExternalActionDefinition(proposal.action_id);
    if (definition === undefined) throw new SecurityError("ACTION_UNKNOWN");
    if (proposal.mode === "external")
      throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
    if (!definition.simulationSupported)
      throw new SecurityError("ACTION_SIMULATION_NOT_SUPPORTED");
    if (this.runner.kind !== "simulation_mock")
      throw new SecurityError("ACTION_RUNNER_MODE_INVALID");
    if (proposal.parameters.payload_ref !== null)
      throw new SecurityError("ACTION_PAYLOAD_REFERENCE_BLOCKED");

    const execution = resolveTrustedExecution(proposal, definition);
    assertOwnershipReferences(execution);
    this.killSwitch.assertInactive();
    let authorization: StoreBoundExternalActionAuthorization | undefined;
    let started = false;
    let settlementAttempted = false;
    try {
      authorization = this.authorizer.authorizeAndReserve(
        execution,
        this.runtime.config.budgets.max_actions_total,
        this.runtime.config.budgets.max_concurrency,
      );
      this.killSwitch.assertInactive();
      this.authorizer.start(execution, authorization);
      started = true;
      this.killSwitch.assertInactive();
      const result = await this.killSwitch.monitor(() =>
        this.runner.run(execution, this.killSwitch.signal),
      );
      this.killSwitch.assertInactive();
      settlementAttempted = true;
      this.authorizer.settle(execution, authorization, "succeeded");
      return {
        proposalId: proposal.proposal_id,
        actionId: definition.actionId,
        result,
        trace: SUCCESS_TRACE,
      };
    } catch (error) {
      if (authorization !== undefined && !started && !settlementAttempted) {
        try {
          this.authorizer.abortReservation(execution, authorization);
        } catch (settlementError) {
          throw asError(settlementError);
        }
      }
      if (authorization !== undefined && started && !settlementAttempted) {
        const outcome = isKillError(error) ? "aborted" : "failed";
        try {
          this.authorizer.settle(execution, authorization, outcome);
        } catch (settlementError) {
          throw asError(settlementError);
        }
      }
      throw asError(error);
    }
  }
}

export function prepareStoreBoundExternalActionProposal(
  store: ControlPlaneStore,
  input: StoreBoundActionProposalInput,
): ExternalActionProposal {
  assertTrustedStore(store);
  const definition = requiredSimulationDefinition(input.actionId);
  const context = store.describeExternalActionContext({
    definition: evidenceDefinition(definition),
    campaignId: input.campaignRef,
    accountId: input.accountRef,
    objectRef: input.objectRef,
    payloadRef: input.payloadRef,
    now: systemTimestamp(),
  });
  return validateAndFreezeExternalActionProposal({
    version: 2,
    proposal_id: input.proposalId,
    action_id: input.actionId,
    mode: "simulation",
    parameters: {
      program_ref: context.programId,
      campaign_ref: context.campaignId,
      campaign_revision: context.campaignRevision,
      campaign_digest: context.campaignDigest,
      policy_version: context.policyVersion,
      policy_hash_sha256: context.policyHash,
      scope_ref: context.scopeRef,
      account_ref: context.accountId,
      account_role: context.accountRole,
      object_ref: context.objectRef,
      payload_ref: context.payloadRef,
      approval_ref: input.approvalRef,
      operator_ref: input.operatorRef,
    },
  });
}

export function enqueueStoreBoundExternalActionApproval(
  store: ControlPlaneStore,
  value: unknown,
): ApprovalRecord {
  assertTrustedStore(store);
  const proposal = validateAndFreezeExternalActionProposal(value);
  const definition = requiredSimulationDefinition(proposal.action_id);
  if (proposal.mode !== "simulation")
    throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
  const createdAt = systemTimestamp();
  const expiresAt = new Date(Date.parse(createdAt) + 5 * 60_000).toISOString();
  return store.createExternalActionApproval({
    proposal,
    definition: evidenceDefinition(definition),
    createdAt,
    expiresAt,
  });
}

function assertRuntimeBudget(runtime: Phase2RuntimeState): void {
  let maximum: unknown;
  let concurrency: unknown;
  try {
    maximum = runtime.config.budgets.max_actions_total;
    concurrency = runtime.config.budgets.max_concurrency;
  } catch {
    throw new SecurityError("ACTION_RUNTIME_INVALID");
  }
  if (
    !Number.isSafeInteger(maximum) ||
    typeof maximum !== "number" ||
    maximum < 1 ||
    maximum > 1_000 ||
    concurrency !== 1 ||
    (runtime.externalIntegrationsEnabled as unknown) !== false
  )
    throw new SecurityError("ACTION_RUNTIME_INVALID");
}

function asError(value: unknown): Error {
  return value instanceof Error ? value : new Error("ACTION_RUNNER_FAILED");
}

function isKillError(value: unknown): boolean {
  return value instanceof SecurityError && value.code === "ACTION_KILL_SWITCH";
}

function assertTrustedAuthorizer(
  authorizer: ExternalActionAuthorizationEvaluator,
): void {
  let prototype: object | null;
  try {
    prototype = Reflect.getPrototypeOf(authorizer);
  } catch {
    throw new SecurityError("ACTION_AUTHORIZER_UNTRUSTED");
  }
  const storeBound = prototype === StoreBoundExternalActionEvaluator.prototype;
  const denyAll = prototype === DenyAllExternalActionEvaluator.prototype;
  if (
    !trustedAuthorizationEvaluators.has(authorizer) ||
    (!storeBound && !denyAll)
  )
    throw new SecurityError("ACTION_AUTHORIZER_UNTRUSTED");
}

function assertTrustedRunner(runner: DeterministicActionRunner): void {
  let prototype: object | null;
  try {
    prototype = Reflect.getPrototypeOf(runner);
  } catch {
    throw new SecurityError("ACTION_RUNNER_UNTRUSTED");
  }
  const trustedMock =
    trustedMockRunners.has(runner) &&
    prototype === DeterministicMockActionRunner.prototype;
  const trustedDisabled =
    trustedDisabledRunners.has(runner) &&
    prototype === DisabledExternalActionRunner.prototype;
  if (!trustedMock && !trustedDisabled)
    throw new SecurityError("ACTION_RUNNER_UNTRUSTED");
}

function assertTrustedKillSwitch(killSwitch: Phase2KillSwitch): void {
  let prototype: object | null;
  try {
    prototype = Reflect.getPrototypeOf(killSwitch);
  } catch {
    throw new SecurityError("ACTION_KILL_SWITCH_UNTRUSTED");
  }
  if (
    !trustedKillSwitches.has(killSwitch) ||
    prototype !== Phase2KillSwitch.prototype
  )
    throw new SecurityError("ACTION_KILL_SWITCH_UNTRUSTED");
}

function captureKillSwitchReader(
  value: Phase2KillSwitchStateReader | undefined,
): (() => boolean) | undefined {
  if (value === undefined) return undefined;
  try {
    if (
      types.isProxy(value) ||
      Reflect.getPrototypeOf(value) !== Object.prototype ||
      Reflect.ownKeys(value).length !== 1
    )
      throw new SecurityError("ACTION_KILL_SWITCH_READER_INVALID");
    const descriptor = Object.getOwnPropertyDescriptor(value, "readActive");
    const candidate: unknown = descriptor?.value;
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !isUnknownCallback(candidate)
    )
      throw new SecurityError("ACTION_KILL_SWITCH_READER_INVALID");
    return () => {
      const state = candidate();
      if (typeof state !== "boolean")
        throw new SecurityError("ACTION_KILL_SWITCH");
      return state;
    };
  } catch (error) {
    if (
      error instanceof SecurityError &&
      error.code === "ACTION_KILL_SWITCH_READER_INVALID"
    )
      throw error;
    throw new SecurityError("ACTION_KILL_SWITCH_READER_INVALID");
  }
}

function isUnknownCallback(value: unknown): value is () => unknown {
  return typeof value === "function" && !types.isProxy(value);
}

function resolveTrustedExecution(
  proposal: ExternalActionProposal,
  definition: ExternalActionDefinition,
): TrustedExternalActionExecution {
  const target = definition.fixedTargetPolicy;
  if (target.kind !== "registry_loopback_mock")
    throw new SecurityError("ACTION_SIMULATION_LOOPBACK_REQUIRED");
  return Object.freeze({
    proposal,
    definition,
    target: Object.freeze({
      class: definition.targetClass,
      scheme: target.scheme,
      host: target.host,
    }),
  });
}

function assertOwnershipReferences(
  execution: TrustedExternalActionExecution,
): void {
  const requirement = execution.definition.ownershipCheck;
  const parameters = execution.proposal.parameters;
  if ((parameters.account_ref === null) !== (parameters.account_role === null))
    throw new SecurityError("ACTION_OWNERSHIP_REFERENCE_REQUIRED");
  if (
    requirement === "not_applicable" &&
    (parameters.account_ref !== null || parameters.object_ref !== null)
  )
    throw new SecurityError("ACTION_OWNERSHIP_REFERENCE_REQUIRED");
  if (
    requirement === "account" &&
    (parameters.account_ref === null || parameters.object_ref !== null)
  )
    throw new SecurityError("ACTION_OWNERSHIP_REFERENCE_REQUIRED");
  if (
    requirement === "object" &&
    (parameters.account_ref === null || parameters.object_ref === null)
  )
    throw new SecurityError("ACTION_OWNERSHIP_REFERENCE_REQUIRED");
}

function requiredSimulationDefinition(
  actionId: string,
): ExternalActionDefinition {
  const definition = getExternalActionDefinition(actionId);
  if (definition === undefined) throw new SecurityError("ACTION_UNKNOWN");
  if (
    !definition.simulationSupported ||
    definition.fixedTargetPolicy.kind !== "registry_loopback_mock"
  )
    throw new SecurityError("ACTION_SIMULATION_NOT_SUPPORTED");
  return definition;
}

function evidenceDefinition(
  definition: ExternalActionDefinition,
): ExternalActionEvidenceDefinition {
  return Object.freeze({
    actionId: definition.actionId,
    targetClass: definition.targetClass,
    ownershipCheck: definition.ownershipCheck,
    ownedObjectAction:
      definition.actionId === "target_request" ? "offline_inspect" : null,
    budgetUnits: definition.budget.units,
  });
}

function assertTrustedStore(store: ControlPlaneStore): void {
  if (!isTrustedControlPlaneStore(store))
    throw new SecurityError("ACTION_STORE_UNTRUSTED");
}

function systemTimestamp(): string {
  try {
    return new Date(Date.now()).toISOString();
  } catch {
    throw new SecurityError("ACTION_CLOCK_INVALID");
  }
}

function monotonicSystemTimestamp(earliest: string): string {
  const current = systemTimestamp();
  return Date.parse(current) < Date.parse(earliest) ? earliest : current;
}

function assertNotAborted(signal: AbortSignal, code: string): void {
  if (signal.aborted) throw new SecurityError(code);
}

export class DeterministicMockActionRunner implements DeterministicActionRunner {
  public readonly kind = "simulation_mock" as const;

  readonly #responses: ReadonlyMap<string, JsonValue>;
  readonly #deferredProposalIds: Set<string>;
  readonly #waiters = new Map<
    string,
    Set<{
      readonly resolve: (value: JsonValue) => void;
      readonly reject: (error: SecurityError) => void;
      readonly signal: AbortSignal;
      readonly onAbort: () => void;
    }>
  >();
  readonly #executions: TrustedExternalActionExecution[] = [];

  public constructor(
    responses: Readonly<Record<string, JsonValue>>,
    options: DeterministicMockActionRunnerOptions = {},
  ) {
    this.#responses = cloneMockResponses(responses);
    this.#deferredProposalIds = cloneDeferredIds(
      options.deferredProposalIds,
      this.#responses,
    );
    trustedMockRunners.add(this);
    Object.freeze(this);
  }

  public run(
    execution: TrustedExternalActionExecution,
    signal: AbortSignal,
  ): Promise<JsonValue> {
    if (signal.aborted)
      return Promise.reject(new SecurityError("ACTION_KILL_SWITCH"));
    const proposalId = execution.proposal.proposal_id;
    const response = this.#responses.get(proposalId);
    if (response === undefined)
      return Promise.reject(new Error("MOCK_ACTION_NOT_CONFIGURED"));
    this.#executions.push(execution);
    if (this.#deferredProposalIds.has(proposalId))
      return new Promise<JsonValue>((resolve, reject) => {
        const waiters = this.#waiters.get(proposalId) ?? new Set();
        const onAbort = () => {
          waiters.delete(waiter);
          reject(new SecurityError("ACTION_KILL_SWITCH"));
        };
        const waiter = { resolve, reject, signal, onAbort };
        waiters.add(waiter);
        this.#waiters.set(proposalId, waiters);
        signal.addEventListener("abort", onAbort, { once: true });
      });
    return Promise.resolve(cloneJsonValue(response, new Set()));
  }

  public release(proposalId: string): void {
    const response = this.#responses.get(proposalId);
    if (response === undefined) throw new Error("MOCK_ACTION_NOT_CONFIGURED");
    this.#deferredProposalIds.delete(proposalId);
    const waiters = this.#waiters.get(proposalId);
    if (waiters === undefined) return;
    this.#waiters.delete(proposalId);
    for (const waiter of waiters) {
      waiter.signal.removeEventListener("abort", waiter.onAbort);
      if (!waiter.signal.aborted)
        waiter.resolve(cloneJsonValue(response, new Set()));
    }
  }

  public recordedExecutions(): readonly TrustedExternalActionExecution[] {
    return Object.freeze([...this.#executions]);
  }
}

export class DisabledExternalActionRunner implements DeterministicActionRunner {
  public readonly kind = "external_disabled" as const;

  public constructor() {
    trustedDisabledRunners.add(this);
    Object.freeze(this);
  }

  public run(): Promise<JsonValue> {
    return Promise.reject(new Error("EXTERNAL_ADAPTER_NOT_IMPLEMENTED"));
  }
}

function cloneMockResponses(
  responses: Readonly<Record<string, JsonValue>>,
): ReadonlyMap<string, JsonValue> {
  if (!isPlainRecord(responses)) throw new Error("MOCK_RESPONSES_INVALID");
  const entries: [string, JsonValue][] = [];
  for (const key of Reflect.ownKeys(responses)) {
    if (typeof key !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(key))
      throw new Error("MOCK_RESPONSE_ID_INVALID");
    const descriptor = Object.getOwnPropertyDescriptor(responses, key);
    if (descriptor === undefined || !("value" in descriptor))
      throw new Error("MOCK_RESPONSES_INVALID");
    entries.push([key, cloneJsonValue(descriptor.value, new Set())]);
  }
  return new Map(entries);
}

function cloneDeferredIds(
  ids: readonly string[] | undefined,
  responses: ReadonlyMap<string, JsonValue>,
): Set<string> {
  if (ids === undefined) return new Set();
  if (!Array.isArray(ids)) throw new Error("MOCK_DEFERRED_IDS_INVALID");
  const deferred = new Set<string>();
  for (const id of ids) {
    if (typeof id !== "string" || !responses.has(id) || deferred.has(id))
      throw new Error("MOCK_DEFERRED_IDS_INVALID");
    deferred.add(id);
  }
  return deferred;
}

function cloneJsonValue(value: unknown, ancestors: Set<object>): JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("MOCK_RESPONSE_INVALID");
    return value;
  }
  if (typeof value !== "object" || ancestors.has(value))
    throw new Error("MOCK_RESPONSE_INVALID");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype)
        throw new Error("MOCK_RESPONSE_INVALID");
      const keys = Reflect.ownKeys(value);
      if (
        keys.some(
          (key) =>
            typeof key !== "string" ||
            (key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key)),
        )
      )
        throw new Error("MOCK_RESPONSE_INVALID");
      const cloned: JsonValue[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(
          value,
          String(index),
        );
        if (descriptor === undefined || !("value" in descriptor))
          throw new Error("MOCK_RESPONSE_INVALID");
        cloned.push(cloneJsonValue(descriptor.value, ancestors));
      }
      return cloned;
    }
    if (!isPlainRecord(value)) throw new Error("MOCK_RESPONSE_INVALID");
    const entries: [string, JsonValue][] = [];
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") throw new Error("MOCK_RESPONSE_INVALID");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !("value" in descriptor))
        throw new Error("MOCK_RESPONSE_INVALID");
      entries.push([key, cloneJsonValue(descriptor.value, ancestors)]);
    }
    const cloned: Record<string, JsonValue> = Object.fromEntries(entries);
    return cloned;
  } finally {
    ancestors.delete(value);
  }
}

function isPlainRecord(value: object): boolean {
  const prototype = Reflect.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

Object.freeze(DeterministicMockActionRunner.prototype);
Object.freeze(DeterministicMockActionRunner);
Object.freeze(DisabledExternalActionRunner.prototype);
Object.freeze(DisabledExternalActionRunner);
Object.freeze(StoreBoundExternalActionEvaluator.prototype);
Object.freeze(StoreBoundExternalActionEvaluator);
Object.freeze(DenyAllExternalActionEvaluator.prototype);
Object.freeze(DenyAllExternalActionEvaluator);
Object.freeze(Phase2KillSwitch.prototype);
Object.freeze(Phase2KillSwitch);
Object.freeze(ExternalActionPipeline.prototype);
Object.freeze(ExternalActionPipeline);
