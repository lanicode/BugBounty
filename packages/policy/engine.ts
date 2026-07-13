import type { RiskTier, TestContract } from "./contract.js";

export type PolicyReasonCode =
  | "ALLOW_OFFLINE"
  | "ALLOW_PASSIVE_CAPTURE"
  | "BLOCK_ACCOUNT"
  | "BLOCK_ACTIVE_TIER_PHASE1"
  | "BLOCK_ASSET"
  | "BLOCK_BUDGET"
  | "BLOCK_CONCURRENCY"
  | "BLOCK_CONTRACT_EXPIRED"
  | "BLOCK_CONTRACT_NOT_YET_VALID"
  | "BLOCK_KILL_SWITCH"
  | "BLOCK_POLICY_DRIFT"
  | "BLOCK_RISK_TIER";

export interface PolicyInput {
  readonly contract: TestContract;
  readonly currentPolicyHash: string;
  readonly now: Date;
  readonly action: "offline" | "passive_capture" | "active_test";
  readonly riskTier: RiskTier;
  readonly assetRef: string;
  readonly accountRef: string;
  readonly runtime: {
    readonly requestCount: number;
    readonly activeRequests: number;
  };
  readonly killed: boolean;
}

export interface PolicyDecision {
  readonly allow: boolean;
  readonly reason: PolicyReasonCode;
}

export function decidePolicy(input: PolicyInput): PolicyDecision {
  const block = (reason: PolicyReasonCode): PolicyDecision => ({
    allow: false,
    reason,
  });
  if (input.killed) return block("BLOCK_KILL_SWITCH");
  if (input.currentPolicyHash !== input.contract.policy_hash_sha256)
    return block("BLOCK_POLICY_DRIFT");
  if (input.now.getTime() < Date.parse(input.contract.valid_from))
    return block("BLOCK_CONTRACT_NOT_YET_VALID");
  if (input.now.getTime() > Date.parse(input.contract.valid_until))
    return block("BLOCK_CONTRACT_EXPIRED");
  if (!input.contract.approved_risk_tiers.includes(input.riskTier))
    return block("BLOCK_RISK_TIER");
  if (!input.contract.asset_refs.includes(input.assetRef))
    return block("BLOCK_ASSET");
  if (!input.contract.account_refs.includes(input.accountRef))
    return block("BLOCK_ACCOUNT");
  if (input.runtime.activeRequests >= input.contract.budgets.max_concurrency)
    return block("BLOCK_CONCURRENCY");
  if (input.runtime.requestCount >= input.contract.budgets.max_requests_total)
    return block("BLOCK_BUDGET");
  if (input.action === "active_test" || input.riskTier !== "tier_0_offline")
    return block("BLOCK_ACTIVE_TIER_PHASE1");
  return {
    allow: true,
    reason:
      input.action === "offline" ? "ALLOW_OFFLINE" : "ALLOW_PASSIVE_CAPTURE",
  };
}

export class KillSwitch {
  readonly #controller = new AbortController();
  #killed = false;

  public get signal(): AbortSignal {
    return this.#controller.signal;
  }
  public get killed(): boolean {
    return this.#killed;
  }
  public kill(): void {
    if (!this.#killed) {
      this.#killed = true;
      this.#controller.abort(new Error("GLOBAL_KILL_SWITCH"));
    }
  }
  public assertRunning(): void {
    if (this.#killed) throw new Error("GLOBAL_KILL_SWITCH");
  }
}

export class SerialBudget {
  #active = 0;
  #count = 0;
  public constructor(private readonly maximum: number) {}
  public enter(signal?: AbortSignal): () => void {
    if (signal?.aborted === true) throw new Error("GLOBAL_KILL_SWITCH");
    if (this.#active >= 1) throw new Error("BUDGET_CONCURRENCY_EXCEEDED");
    if (this.#count >= this.maximum)
      throw new Error("BUDGET_REQUESTS_EXCEEDED");
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
  public get snapshot(): { active: number; count: number } {
    return { active: this.#active, count: this.#count };
  }
}
