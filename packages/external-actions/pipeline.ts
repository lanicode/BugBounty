import Ajv2020 from "ajv/dist/2020.js";
import proposalSchema from "./proposal.schema.json" with { type: "json" };
import type { Phase2RuntimeState } from "../phase2-config/runtime.js";
import { SecurityError } from "../shared/errors.js";
import { canonicalJson, type JsonValue } from "../shared/canonical.js";
import {
  getExternalActionDefinition,
  type ExternalActionDefinition,
  type ExternalActionId,
} from "./registry.js";

export type ExternalActionKind = ExternalActionId;

export interface ExternalActionProposal {
  readonly version: 1;
  readonly proposal_id: string;
  readonly action_id: string;
  readonly mode: "external" | "simulation";
  readonly parameters: {
    readonly campaign_ref: string | null;
    readonly policy_hash_sha256: string | null;
    readonly scope_ref: string | null;
    readonly account_ref: string | null;
    readonly object_ref: string | null;
    readonly payload_ref: string | null;
  };
}

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

export interface ExternalActionGateEvaluator {
  decidePolicy(execution: TrustedExternalActionExecution): boolean;
  decideScope(execution: TrustedExternalActionExecution): boolean;
  decideOwnership(execution: TrustedExternalActionExecution): boolean;
  decideHumanCheckpoint(execution: TrustedExternalActionExecution): boolean;
}

export interface DeterministicSimulationGateDecisions {
  readonly policy: boolean;
  readonly scope: boolean;
  readonly ownership: boolean;
  readonly humanCheckpoint: boolean;
}

const trustedGateEvaluators = new WeakSet();

export class DeterministicSimulationGateEvaluator implements ExternalActionGateEvaluator {
  readonly #decisions: DeterministicSimulationGateDecisions;
  readonly #proposalBinding: string;

  public constructor(
    proposal: ExternalActionProposal,
    decisions: DeterministicSimulationGateDecisions,
  ) {
    const suppliedDecisions: unknown = decisions;
    if (!isExactGateDecisions(suppliedDecisions))
      throw new SecurityError("ACTION_GATES_INVALID");
    this.#proposalBinding = proposalBinding(proposal);
    this.#decisions = Object.freeze({ ...suppliedDecisions });
    trustedGateEvaluators.add(this);
    Object.freeze(this);
  }

  public decidePolicy(execution: TrustedExternalActionExecution): boolean {
    return this.matches(execution) && this.#decisions.policy;
  }

  public decideScope(execution: TrustedExternalActionExecution): boolean {
    return this.matches(execution) && this.#decisions.scope;
  }

  public decideOwnership(execution: TrustedExternalActionExecution): boolean {
    return this.matches(execution) && this.#decisions.ownership;
  }

  public decideHumanCheckpoint(
    execution: TrustedExternalActionExecution,
  ): boolean {
    return this.matches(execution) && this.#decisions.humanCheckpoint;
  }

  private matches(execution: TrustedExternalActionExecution): boolean {
    return this.#proposalBinding === proposalBinding(execution.proposal);
  }
}

const DENY_ALL_GATES = new DeterministicSimulationGateEvaluator(
  {
    version: 1,
    proposal_id: "deny-all",
    action_id: "platform_api_read",
    mode: "simulation",
    parameters: {
      campaign_ref: "deny-all",
      policy_hash_sha256: "0".repeat(64),
      scope_ref: "deny-all",
      account_ref: null,
      object_ref: null,
      payload_ref: null,
    },
  },
  {
    policy: false,
    scope: false,
    ownership: false,
    humanCheckpoint: false,
  },
);

const SUCCESS_TRACE: ExternalActionTrace = Object.freeze([
  "schema",
  "policy",
  "scope",
  "ownership",
  "budget",
  "human_checkpoint",
  "runner",
]);

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile<ExternalActionProposal>(proposalSchema);

const trustedMockRunners = new WeakSet();
const trustedDisabledRunners = new WeakSet();

function proposalBinding(proposal: ExternalActionProposal): string {
  return canonicalJson({
    version: proposal.version,
    proposalId: proposal.proposal_id,
    actionId: proposal.action_id,
    mode: proposal.mode,
    parameters: {
      campaignRef: proposal.parameters.campaign_ref,
      policyHash: proposal.parameters.policy_hash_sha256,
      scopeRef: proposal.parameters.scope_ref,
      accountRef: proposal.parameters.account_ref,
      objectRef: proposal.parameters.object_ref,
      payloadRef: proposal.parameters.payload_ref,
    },
  });
}

export class Phase2KillSwitch {
  readonly #controller = new AbortController();

  public constructor(
    private readonly stateReader: Phase2KillSwitchStateReader | undefined,
  ) {}

  public get signal(): AbortSignal {
    return this.#controller.signal;
  }

  public kill(): void {
    if (!this.signal.aborted)
      this.#controller.abort(new Error("PHASE2_GLOBAL_KILL_SWITCH"));
  }

  public assertInactive(): void {
    assertNotAborted(this.signal, "ACTION_KILL_SWITCH");
    if (this.stateReader === undefined) {
      this.kill();
      throw new SecurityError("ACTION_KILL_SWITCH");
    }
    let active: unknown;
    try {
      active = this.stateReader.readActive();
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
  #active = 0;
  #count = 0;

  private readonly runtime: Phase2RuntimeState;
  private readonly runner: DeterministicActionRunner;
  private readonly killSwitch: Phase2KillSwitch;
  private readonly gates: ExternalActionGateEvaluator;

  public constructor(
    runtime: Phase2RuntimeState,
    runner: DeterministicActionRunner,
    killSwitch: Phase2KillSwitch,
    gates: ExternalActionGateEvaluator = DENY_ALL_GATES,
  ) {
    assertTrustedRunner(runner);
    assertTrustedGates(gates);
    assertRuntimeBudget(runtime);
    this.runtime = runtime;
    this.runner = runner;
    this.killSwitch = killSwitch;
    this.gates = gates;
  }

  public async execute(value: unknown): Promise<ExternalActionResult> {
    this.killSwitch.assertInactive();
    if (!validate(value)) throw new SecurityError("ACTION_SCHEMA_INVALID");
    const proposal = freezeProposal(value);
    const definition = getExternalActionDefinition(proposal.action_id);
    if (definition === undefined) throw new SecurityError("ACTION_UNKNOWN");
    if (proposal.mode === "external")
      throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
    if (!definition.simulationSupported)
      throw new SecurityError("ACTION_SIMULATION_NOT_SUPPORTED");
    if (this.runner.kind !== "simulation_mock")
      throw new SecurityError("ACTION_RUNNER_MODE_INVALID");
    if (proposal.parameters.campaign_ref === null)
      throw new SecurityError("ACTION_CAMPAIGN_REFERENCE_REQUIRED");
    if (proposal.parameters.policy_hash_sha256 === null)
      throw new SecurityError("ACTION_POLICY_REFERENCE_REQUIRED");

    const execution = resolveTrustedExecution(proposal, definition);
    this.killSwitch.assertInactive();
    assertGate(
      () => this.gates.decidePolicy(execution),
      "ACTION_POLICY_BLOCKED",
    );
    this.killSwitch.assertInactive();
    if (execution.proposal.parameters.scope_ref === null)
      throw new SecurityError("ACTION_SCOPE_REFERENCE_REQUIRED");
    assertGate(() => this.gates.decideScope(execution), "ACTION_SCOPE_BLOCKED");
    this.killSwitch.assertInactive();
    assertOwnershipReferences(execution);
    assertGate(
      () => this.gates.decideOwnership(execution),
      "ACTION_OWNERSHIP_BLOCKED",
    );
    this.killSwitch.assertInactive();
    const release = this.enterBudget(definition.budget.units);
    try {
      this.killSwitch.assertInactive();
      assertGate(
        () => this.gates.decideHumanCheckpoint(execution),
        "ACTION_HUMAN_CHECKPOINT_REQUIRED",
      );
      this.killSwitch.assertInactive();
      const result = await this.killSwitch.monitor(() =>
        this.runner.run(execution, this.killSwitch.signal),
      );
      this.killSwitch.assertInactive();
      return {
        proposalId: proposal.proposal_id,
        actionId: definition.actionId,
        result,
        trace: SUCCESS_TRACE,
      };
    } finally {
      release();
    }
  }

  private enterBudget(units: number): () => void {
    if (this.#active >= this.runtime.config.budgets.max_concurrency)
      throw new SecurityError("ACTION_CONCURRENCY_EXCEEDED");
    if (this.#count + units > this.runtime.config.budgets.max_actions_total)
      throw new SecurityError("ACTION_BUDGET_EXCEEDED");
    this.#active += 1;
    this.#count += units;
    let released = false;
    return () => {
      if (!released) {
        released = true;
        this.#active -= 1;
      }
    };
  }
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

function isExactGateDecisions(
  value: unknown,
): value is DeterministicSimulationGateDecisions {
  if (typeof value !== "object" || value === null) return false;
  try {
    return (
      Reflect.getPrototypeOf(value) === Object.prototype &&
      Reflect.ownKeys(value).sort().join(",") ===
        "humanCheckpoint,ownership,policy,scope" &&
      isBooleanDataProperty(value, "policy") &&
      isBooleanDataProperty(value, "scope") &&
      isBooleanDataProperty(value, "ownership") &&
      isBooleanDataProperty(value, "humanCheckpoint")
    );
  } catch {
    return false;
  }
}

function isBooleanDataProperty(value: object, key: string): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return (
    descriptor !== undefined &&
    "value" in descriptor &&
    typeof descriptor.value === "boolean"
  );
}

function asError(value: unknown): Error {
  return value instanceof Error ? value : new Error("ACTION_RUNNER_FAILED");
}

function assertTrustedGates(gates: ExternalActionGateEvaluator): void {
  let prototype: object | null;
  try {
    prototype = Reflect.getPrototypeOf(gates);
  } catch {
    throw new SecurityError("ACTION_GATES_UNTRUSTED");
  }
  if (
    !trustedGateEvaluators.has(gates) ||
    prototype !== DeterministicSimulationGateEvaluator.prototype
  )
    throw new SecurityError("ACTION_GATES_UNTRUSTED");
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

function freezeProposal(
  proposal: ExternalActionProposal,
): ExternalActionProposal {
  return Object.freeze({
    ...proposal,
    parameters: Object.freeze({ ...proposal.parameters }),
  });
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
  if (
    requirement === "account" &&
    execution.proposal.parameters.account_ref === null
  )
    throw new SecurityError("ACTION_OWNERSHIP_REFERENCE_REQUIRED");
  if (
    requirement === "object" &&
    (execution.proposal.parameters.account_ref === null ||
      execution.proposal.parameters.object_ref === null)
  )
    throw new SecurityError("ACTION_OWNERSHIP_REFERENCE_REQUIRED");
}

function assertGate(decide: () => boolean, reason: string): void {
  let decision: unknown;
  try {
    decision = decide();
  } catch {
    throw new SecurityError(reason);
  }
  if (decision !== true) throw new SecurityError(reason);
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
Object.freeze(DeterministicSimulationGateEvaluator.prototype);
Object.freeze(DeterministicSimulationGateEvaluator);
