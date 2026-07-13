import Ajv2020 from "ajv/dist/2020.js";
import proposalSchema from "./proposal.schema.json" with { type: "json" };
import type { Phase2RuntimeState } from "../phase2-config/runtime.js";
import { isLoopback, normalizeUrl } from "../egress-guard/normalize.js";
import { SecurityError } from "../shared/errors.js";
import type { JsonValue } from "../shared/canonical.js";

export type ExternalActionKind =
  | "account_create_local"
  | "policy_read"
  | "program_read"
  | "program_rules_accept"
  | "report_submit"
  | "terms_accept";

export interface ExternalActionProposal {
  readonly version: 1;
  readonly proposal_id: string;
  readonly action: ExternalActionKind;
  readonly mode: "external" | "simulation";
  readonly platform: "hackerone" | "local_mock";
  readonly target_url: string;
  readonly method: "GET" | "POST";
  readonly required_secret_ref: string | null;
  readonly human_checkpoint:
    | "not_required"
    | "program_policy_acceptance"
    | "report_submission_approval"
    | "terms_acceptance";
}

export interface ExternalActionResult {
  readonly proposalId: string;
  readonly result: JsonValue;
  readonly trace: readonly ["schema", "policy", "scope", "budget", "runner"];
}

export interface DeterministicActionRunner {
  readonly kind: "external_disabled" | "simulation_mock";
  run(
    proposal: ExternalActionProposal,
    signal: AbortSignal,
  ): Promise<JsonValue>;
}

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
  ) {}

  public async execute(value: unknown): Promise<ExternalActionResult> {
    if (!validate(value)) throw new SecurityError("ACTION_SCHEMA_INVALID");
    this.assertPolicy(value);
    this.assertScope(value);
    const release = this.enterBudget();
    try {
      assertNotAborted(this.killSwitch.signal, "ACTION_KILL_SWITCH");
      if (value.mode === "simulation" && this.runner.kind !== "simulation_mock")
        throw new SecurityError("ACTION_RUNNER_MODE_INVALID");
      if (value.mode === "external")
        throw new SecurityError("EXTERNAL_ADAPTER_NOT_IMPLEMENTED");
      const result = await this.runner.run(value, this.killSwitch.signal);
      assertNotAborted(this.killSwitch.signal, "ACTION_KILL_SWITCH");
      return {
        proposalId: value.proposal_id,
        result,
        trace: ["schema", "policy", "scope", "budget", "runner"],
      };
    } finally {
      release();
    }
  }

  private assertPolicy(proposal: ExternalActionProposal): void {
    if (
      proposal.action === "program_rules_accept" ||
      proposal.action === "terms_accept" ||
      proposal.action === "report_submit"
    )
      throw new SecurityError("ACTION_HUMAN_DECISION_REQUIRED");
    if (proposal.human_checkpoint !== "not_required")
      throw new SecurityError("ACTION_HUMAN_DECISION_REQUIRED");
    if (proposal.mode === "external") {
      if (!this.runtime.externalIntegrationsEnabled)
        throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
      if (proposal.platform !== "hackerone")
        throw new SecurityError("ACTION_PLATFORM_INVALID");
      if (proposal.required_secret_ref === null)
        throw new SecurityError("ACTION_SECRET_REFERENCE_REQUIRED");
    } else if (
      proposal.platform !== "local_mock" ||
      proposal.required_secret_ref !== null
    ) {
      throw new SecurityError("ACTION_SIMULATION_POLICY_INVALID");
    }
    if (
      proposal.action === "account_create_local" &&
      (proposal.mode !== "simulation" || proposal.method !== "POST")
    )
      throw new SecurityError("ACTION_ACCOUNT_LOCAL_ONLY");
    if (
      (proposal.action === "program_read" ||
        proposal.action === "policy_read") &&
      proposal.method !== "GET"
    )
      throw new SecurityError("ACTION_METHOD_INVALID");
  }

  private assertScope(proposal: ExternalActionProposal): void {
    let normalized: ReturnType<typeof normalizeUrl>;
    try {
      normalized = normalizeUrl(proposal.target_url);
    } catch {
      throw new SecurityError("ACTION_SCOPE_INVALID");
    }
    if (proposal.mode === "simulation") {
      if (normalized.scheme !== "http" || !isLoopback(normalized.host))
        throw new SecurityError("ACTION_SIMULATION_LOOPBACK_REQUIRED");
      return;
    }
    if (
      normalized.scheme !== "https" ||
      !this.runtime.config.allowed_platform_hosts.includes(normalized.host)
    )
      throw new SecurityError("ACTION_EXTERNAL_SCOPE_BLOCKED");
  }

  private enterBudget(): () => void {
    if (this.#active >= 1)
      throw new SecurityError("ACTION_CONCURRENCY_EXCEEDED");
    if (this.#count >= this.runtime.config.budgets.max_actions_total)
      throw new SecurityError("ACTION_BUDGET_EXCEEDED");
    this.#active += 1;
    this.#count += 1;
    let released = false;
    return () => {
      if (!released) {
        released = true;
        this.#active -= 1;
      }
    };
  }
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
    proposal: ExternalActionProposal,
    signal: AbortSignal,
  ): Promise<JsonValue> {
    if (signal.aborted) return Promise.reject(new Error("ACTION_KILL_SWITCH"));
    const response = this.responses[proposal.proposal_id];
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
