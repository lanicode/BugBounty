import Ajv2020 from "ajv/dist/2020.js";
import proposalSchema from "./proposal.schema.json" with { type: "json" };
import type { Phase2RuntimeState } from "../phase2-config/runtime.js";
import { SecurityError } from "../shared/errors.js";
import type { JsonValue } from "../shared/canonical.js";
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

export interface ExternalActionGateEvaluator {
  decidePolicy(execution: TrustedExternalActionExecution): boolean;
  decideScope(execution: TrustedExternalActionExecution): boolean;
  decideOwnership(execution: TrustedExternalActionExecution): boolean;
  decideHumanCheckpoint(execution: TrustedExternalActionExecution): boolean;
}

const DENY_ALL_GATES: ExternalActionGateEvaluator = Object.freeze({
  decidePolicy: () => false,
  decideScope: () => false,
  decideOwnership: () => false,
  decideHumanCheckpoint: () => false,
});

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

export class Phase2KillSwitch {
  readonly #controller = new AbortController();
  public get signal(): AbortSignal {
    return this.#controller.signal;
  }
  public kill(): void {
    if (!this.signal.aborted)
      this.#controller.abort(new Error("PHASE2_GLOBAL_KILL_SWITCH"));
  }
}

export class ExternalActionPipeline {
  #active = 0;
  #count = 0;

  public constructor(
    private readonly runtime: Phase2RuntimeState,
    private readonly runner: DeterministicActionRunner,
    private readonly killSwitch: Phase2KillSwitch,
    private readonly gates: ExternalActionGateEvaluator = DENY_ALL_GATES,
  ) {}

  public async execute(value: unknown): Promise<ExternalActionResult> {
    assertNotAborted(this.killSwitch.signal, "ACTION_KILL_SWITCH");
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

    const execution = resolveTrustedExecution(proposal, definition);
    assertGate(
      () => this.gates.decidePolicy(execution),
      "ACTION_POLICY_BLOCKED",
    );
    if (execution.proposal.parameters.scope_ref === null)
      throw new SecurityError("ACTION_SCOPE_REFERENCE_REQUIRED");
    assertGate(() => this.gates.decideScope(execution), "ACTION_SCOPE_BLOCKED");
    assertOwnershipReferences(execution);
    assertGate(
      () => this.gates.decideOwnership(execution),
      "ACTION_OWNERSHIP_BLOCKED",
    );
    const release = this.enterBudget(definition.budget.units);
    try {
      assertNotAborted(this.killSwitch.signal, "ACTION_KILL_SWITCH");
      assertGate(
        () => this.gates.decideHumanCheckpoint(execution),
        "ACTION_HUMAN_CHECKPOINT_REQUIRED",
      );
      assertNotAborted(this.killSwitch.signal, "ACTION_KILL_SWITCH");
      const result = await this.runner.run(execution, this.killSwitch.signal);
      assertNotAborted(this.killSwitch.signal, "ACTION_KILL_SWITCH");
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
  public constructor(
    private readonly responses: Readonly<Record<string, JsonValue>>,
  ) {}
  public run(
    execution: TrustedExternalActionExecution,
    signal: AbortSignal,
  ): Promise<JsonValue> {
    if (signal.aborted)
      return Promise.reject(new SecurityError("ACTION_KILL_SWITCH"));
    const response = this.responses[execution.proposal.proposal_id];
    if (response === undefined)
      return Promise.reject(new Error("MOCK_ACTION_NOT_CONFIGURED"));
    return Promise.resolve(response);
  }
}

export class DisabledExternalActionRunner implements DeterministicActionRunner {
  public readonly kind = "external_disabled" as const;
  public run(): Promise<JsonValue> {
    return Promise.reject(new Error("EXTERNAL_ADAPTER_NOT_IMPLEMENTED"));
  }
}
