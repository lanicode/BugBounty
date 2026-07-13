import Ajv2020 from "ajv/dist/2020.js";
import schema from "./proposal.schema.json" with { type: "json" };
import { SecurityError } from "../shared/errors.js";

export type HumanCheckpointKind =
  "captcha" | "legal" | "program_rules" | "terms" | "two_factor";

export type AccountSimulationRole = "External" | "Member" | "Owner";

export interface AccountSimulationProposal {
  readonly version: 1;
  readonly proposal_id: string;
  readonly action: "provision" | "resume" | "retire";
  readonly mode: "simulation";
  readonly workflow_ref: string;
  readonly application_ref: string;
  readonly account_ref: string;
  readonly role: AccountSimulationRole;
  readonly policy_hash_sha256: string;
  readonly expected_revision: number;
  readonly checkpoint_ref: string | null;
}

export interface AccountWorkflowState {
  readonly workflowRef: string;
  readonly applicationRef: string;
  readonly accountRef: string;
  readonly role: AccountSimulationRole;
  readonly policyHash: string;
  readonly revision: number;
  readonly state: "ACTIVE" | "NEW" | "PAUSED" | "RETIRED";
  readonly checkpoint?: {
    readonly checkpointRef: string;
    readonly kind: HumanCheckpointKind;
    readonly expiresAt: string;
  };
  readonly accountLocatorRef?: string;
}

interface AdapterStep {
  readonly kind: "complete" | "paused";
  readonly checkpointKind?: HumanCheckpointKind;
  readonly checkpointRef?: string;
  readonly accountLocatorRef?: string;
}

export interface AccountSimulationAdapter {
  readonly kind: "external_disabled" | "local_mock";
  readonly applicationRef: string;
  start(accountRef: string, signal: AbortSignal): Promise<AdapterStep>;
  observeAndContinue(
    checkpointRef: string,
    signal: AbortSignal,
  ): Promise<AdapterStep | "pending">;
  retire(accountRef: string, signal: AbortSignal): Promise<void>;
}

export interface AccountSimulationResult {
  readonly workflow: AccountWorkflowState;
  readonly trace: readonly ["schema", "policy", "scope", "budget", "runner"];
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile<AccountSimulationProposal>(schema);
const trustedMockAccountAdapters = new WeakSet();
const trustedDisabledAccountAdapters = new WeakSet();

export class AccountSimulationCoordinator {
  readonly #workflows = new Map<string, AccountWorkflowState>();
  readonly #allowedAccounts: ReadonlyMap<string, AccountSimulationRole>;
  #active = 0;
  #count = 0;

  public constructor(
    private readonly adapter: AccountSimulationAdapter,
    private readonly policyHash: string,
    allowedAccounts: ReadonlyMap<string, AccountSimulationRole>,
    private readonly maxActions: number,
    private readonly killSignal: AbortSignal,
    private readonly now: () => Date,
  ) {
    assertTrustedAccountAdapter(adapter);
    if (!/^[a-f0-9]{64}$/u.test(policyHash))
      throw new SecurityError("ACCOUNT_POLICY_INVALID");
    if (
      Reflect.getPrototypeOf(allowedAccounts) !== Map.prototype ||
      allowedAccounts.size === 0
    )
      throw new SecurityError("ACCOUNT_SCOPE_INVALID");
    const scopeSnapshot = new Map<string, AccountSimulationRole>();
    for (const [accountRef, role] of allowedAccounts) {
      const suppliedRole: unknown = role;
      if (
        !/^[A-Za-z0-9_-]{1,128}$/u.test(accountRef) ||
        (suppliedRole !== "External" &&
          suppliedRole !== "Member" &&
          suppliedRole !== "Owner")
      )
        throw new SecurityError("ACCOUNT_SCOPE_INVALID");
      scopeSnapshot.set(accountRef, suppliedRole);
    }
    this.#allowedAccounts = scopeSnapshot;
    if (
      !Number.isSafeInteger(maxActions) ||
      maxActions < 1 ||
      maxActions > 1_000
    )
      throw new SecurityError("ACCOUNT_BUDGET_INVALID");
  }

  public async execute(value: unknown): Promise<AccountSimulationResult> {
    if (!validate(value)) throw new SecurityError("ACCOUNT_SCHEMA_INVALID");
    this.assertPolicy(value);
    this.assertScope(value);
    const release = this.enterBudget();
    try {
      assertActive(this.killSignal);
      const workflow = await this.run(value);
      assertActive(this.killSignal);
      return {
        workflow,
        trace: ["schema", "policy", "scope", "budget", "runner"],
      };
    } finally {
      release();
    }
  }

  public get(workflowRef: string): AccountWorkflowState | undefined {
    return this.#workflows.get(workflowRef);
  }

  private assertPolicy(proposal: AccountSimulationProposal): void {
    if (proposal.policy_hash_sha256 !== this.policyHash)
      throw new SecurityError("ACCOUNT_POLICY_DRIFT");
    const approvedRole = this.#allowedAccounts.get(proposal.account_ref);
    if (approvedRole === undefined)
      throw new SecurityError("ACCOUNT_NOT_APPROVED");
    if (approvedRole !== proposal.role)
      throw new SecurityError("ACCOUNT_ROLE_SCOPE_BLOCKED");
    if (this.adapter.kind !== "local_mock")
      throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
  }

  private assertScope(proposal: AccountSimulationProposal): void {
    if (proposal.application_ref !== this.adapter.applicationRef)
      throw new SecurityError("ACCOUNT_APPLICATION_SCOPE_BLOCKED");
  }

  private enterBudget(): () => void {
    if (this.#active >= 1)
      throw new SecurityError("ACCOUNT_CONCURRENCY_EXCEEDED");
    if (this.#count >= this.maxActions)
      throw new SecurityError("ACCOUNT_BUDGET_EXCEEDED");
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

  private async run(
    proposal: AccountSimulationProposal,
  ): Promise<AccountWorkflowState> {
    const current = this.#workflows.get(proposal.workflow_ref);
    if (proposal.action === "provision") {
      if (
        current !== undefined ||
        proposal.expected_revision !== 0 ||
        proposal.checkpoint_ref !== null
      )
        throw new SecurityError("ACCOUNT_WORKFLOW_CONFLICT");
      const step = await this.adapter.start(
        proposal.account_ref,
        this.killSignal,
      );
      return this.applyStep(proposal, 1, step);
    }
    if (current === undefined)
      throw new SecurityError("ACCOUNT_WORKFLOW_NOT_FOUND");
    if (current.revision !== proposal.expected_revision)
      throw new SecurityError("ACCOUNT_WORKFLOW_REVISION_MISMATCH");
    if (
      current.accountRef !== proposal.account_ref ||
      current.applicationRef !== proposal.application_ref ||
      current.role !== proposal.role ||
      current.policyHash !== proposal.policy_hash_sha256
    )
      throw new SecurityError("ACCOUNT_WORKFLOW_BINDING_MISMATCH");
    if (proposal.action === "retire") {
      if (proposal.checkpoint_ref !== null || current.state !== "ACTIVE")
        throw new SecurityError("ACCOUNT_RETIRE_INVALID");
      await this.adapter.retire(proposal.account_ref, this.killSignal);
      const retired = Object.freeze({
        workflowRef: current.workflowRef,
        applicationRef: current.applicationRef,
        accountRef: current.accountRef,
        role: current.role,
        policyHash: current.policyHash,
        revision: current.revision + 1,
        state: "RETIRED" as const,
        ...(current.accountLocatorRef === undefined
          ? {}
          : { accountLocatorRef: current.accountLocatorRef }),
      });
      this.#workflows.set(proposal.workflow_ref, retired);
      return retired;
    }
    const checkpoint = current.checkpoint;
    if (
      current.state !== "PAUSED" ||
      proposal.checkpoint_ref !== checkpoint?.checkpointRef
    )
      throw new SecurityError("ACCOUNT_CHECKPOINT_INVALID");
    if (Date.parse(checkpoint.expiresAt) <= this.now().getTime())
      throw new SecurityError("ACCOUNT_CHECKPOINT_EXPIRED");
    const step = await this.adapter.observeAndContinue(
      checkpoint.checkpointRef,
      this.killSignal,
    );
    if (step === "pending") return current;
    return this.applyStep(proposal, current.revision + 1, step);
  }

  private applyStep(
    proposal: AccountSimulationProposal,
    revision: number,
    step: AdapterStep,
  ): AccountWorkflowState {
    let workflow: AccountWorkflowState;
    if (
      step.kind === "paused" &&
      step.checkpointKind !== undefined &&
      step.checkpointRef !== undefined
    ) {
      workflow = Object.freeze({
        workflowRef: proposal.workflow_ref,
        applicationRef: proposal.application_ref,
        accountRef: proposal.account_ref,
        role: proposal.role,
        policyHash: proposal.policy_hash_sha256,
        revision,
        state: "PAUSED",
        checkpoint: Object.freeze({
          checkpointRef: step.checkpointRef,
          kind: step.checkpointKind,
          expiresAt: new Date(this.now().getTime() + 300_000).toISOString(),
        }),
      });
    } else if (
      step.kind === "complete" &&
      step.accountLocatorRef !== undefined
    ) {
      workflow = Object.freeze({
        workflowRef: proposal.workflow_ref,
        applicationRef: proposal.application_ref,
        accountRef: proposal.account_ref,
        role: proposal.role,
        policyHash: proposal.policy_hash_sha256,
        revision,
        state: "ACTIVE",
        accountLocatorRef: step.accountLocatorRef,
      });
    } else {
      throw new SecurityError("ACCOUNT_ADAPTER_RESULT_INVALID");
    }
    this.#workflows.set(proposal.workflow_ref, workflow);
    return workflow;
  }
}

export class MockLocalAccountApplication implements AccountSimulationAdapter {
  public readonly kind = "local_mock" as const;
  readonly #plans = new Map<string, HumanCheckpointKind[]>();
  readonly #positions = new Map<string, number>();
  readonly #satisfied = new Set<string>();
  readonly #checkpoints = new Map<
    string,
    { readonly accountRef: string; readonly position: number }
  >();

  public constructor(
    public readonly applicationRef: string,
    plans: Readonly<Record<string, readonly HumanCheckpointKind[]>>,
  ) {
    for (const [account, plan] of Object.entries(plans))
      this.#plans.set(account, [...plan]);
    trustedMockAccountAdapters.add(this);
    Object.freeze(this);
  }

  public start(accountRef: string, signal: AbortSignal): Promise<AdapterStep> {
    assertActive(signal);
    this.#positions.set(accountRef, 0);
    return Promise.resolve(this.step(accountRef));
  }

  public observeAndContinue(
    checkpointRef: string,
    signal: AbortSignal,
  ): Promise<AdapterStep | "pending"> {
    assertActive(signal);
    if (!this.#satisfied.has(checkpointRef)) return Promise.resolve("pending");
    this.#satisfied.delete(checkpointRef);
    const checkpoint = this.#checkpoints.get(checkpointRef);
    if (checkpoint === undefined)
      return Promise.reject(new Error("MOCK_CHECKPOINT_INVALID"));
    this.#positions.set(checkpoint.accountRef, checkpoint.position + 1);
    return Promise.resolve(this.step(checkpoint.accountRef));
  }

  public retire(_accountRef: string, signal: AbortSignal): Promise<void> {
    assertActive(signal);
    return Promise.resolve();
  }

  public satisfyCheckpoint(checkpointRef: string): void {
    this.#satisfied.add(checkpointRef);
  }

  private step(accountRef: string): AdapterStep {
    const position = this.#positions.get(accountRef) ?? 0;
    const kind = this.#plans.get(accountRef)?.[position];
    if (kind === undefined)
      return {
        kind: "complete",
        accountLocatorRef: `local-account:${accountRef}`,
      };
    const checkpointRef = `${accountRef}-checkpoint-${String(position)}`;
    this.#checkpoints.set(checkpointRef, { accountRef, position });
    return {
      kind: "paused",
      checkpointKind: kind,
      checkpointRef,
    };
  }
}

/** Phase-2 provider name used by the control plane; it remains in-process only. */
export class MockAccountProvider extends MockLocalAccountApplication {}

export class DisabledExternalAccountAdapter implements AccountSimulationAdapter {
  public readonly kind = "external_disabled" as const;
  public readonly applicationRef = "external-disabled";
  public constructor() {
    trustedDisabledAccountAdapters.add(this);
    Object.freeze(this);
  }
  public start(): Promise<AdapterStep> {
    return Promise.reject(new Error("EXTERNAL_INTEGRATIONS_DISABLED"));
  }
  public observeAndContinue(): Promise<AdapterStep> {
    return Promise.reject(new Error("EXTERNAL_INTEGRATIONS_DISABLED"));
  }
  public retire(): Promise<void> {
    return Promise.reject(new Error("EXTERNAL_INTEGRATIONS_DISABLED"));
  }
}

function assertActive(signal: AbortSignal): void {
  if (signal.aborted) throw new SecurityError("PHASE2_GLOBAL_KILL_SWITCH");
}

function assertTrustedAccountAdapter(adapter: AccountSimulationAdapter): void {
  let prototype: object | null;
  try {
    prototype = Reflect.getPrototypeOf(adapter);
  } catch {
    throw new SecurityError("ACCOUNT_ADAPTER_UNTRUSTED");
  }
  const trustedMock =
    trustedMockAccountAdapters.has(adapter) &&
    (prototype === MockLocalAccountApplication.prototype ||
      prototype === MockAccountProvider.prototype);
  const trustedDisabled =
    trustedDisabledAccountAdapters.has(adapter) &&
    prototype === DisabledExternalAccountAdapter.prototype;
  if (!trustedMock && !trustedDisabled)
    throw new SecurityError("ACCOUNT_ADAPTER_UNTRUSTED");
}

Object.freeze(MockLocalAccountApplication.prototype);
Object.freeze(MockLocalAccountApplication);
Object.freeze(MockAccountProvider.prototype);
Object.freeze(MockAccountProvider);
Object.freeze(DisabledExternalAccountAdapter.prototype);
Object.freeze(DisabledExternalAccountAdapter);
