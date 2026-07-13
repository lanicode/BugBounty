import { describe, expect, it } from "vitest";
import {
  decidePolicy,
  KillSwitch,
  SerialBudget,
} from "../../packages/policy/engine.js";
import { contract } from "../fixtures/factories.js";

const input = () => ({
  contract: contract(),
  currentPolicyHash: "a".repeat(64),
  now: new Date("2026-06-01T00:00:00Z"),
  action: "offline" as const,
  riskTier: "tier_0_offline" as const,
  assetRef: "asset-a",
  accountRef: "account-a",
  runtime: { requestCount: 0, activeRequests: 0 },
  killed: false,
});

describe("policy engine", () => {
  it("allows only phase-1 offline/passive actions", () => {
    expect(decidePolicy(input()).reason).toBe("ALLOW_OFFLINE");
    expect(decidePolicy({ ...input(), action: "active_test" }).reason).toBe(
      "BLOCK_ACTIVE_TIER_PHASE1",
    );
  });
  it("blocks expired contracts, drift, assets, accounts and risk tiers", () => {
    expect(
      decidePolicy({ ...input(), now: new Date("2028-01-01") }).reason,
    ).toBe("BLOCK_CONTRACT_EXPIRED");
    expect(
      decidePolicy({ ...input(), currentPolicyHash: "b".repeat(64) }).reason,
    ).toBe("BLOCK_POLICY_DRIFT");
    expect(decidePolicy({ ...input(), assetRef: "other" }).reason).toBe(
      "BLOCK_ASSET",
    );
    expect(decidePolicy({ ...input(), accountRef: "other" }).reason).toBe(
      "BLOCK_ACCOUNT",
    );
    expect(
      decidePolicy({ ...input(), riskTier: "tier_1_owned_read_only" }).reason,
    ).toBe("BLOCK_RISK_TIER");
  });
  it("blocks budget and parallel requests", () => {
    expect(
      decidePolicy({
        ...input(),
        runtime: { requestCount: 3, activeRequests: 0 },
      }).reason,
    ).toBe("BLOCK_BUDGET");
    expect(
      decidePolicy({
        ...input(),
        runtime: { requestCount: 0, activeRequests: 1 },
      }).reason,
    ).toBe("BLOCK_CONCURRENCY");
    const budget = new SerialBudget(1);
    const leave = budget.enter();
    expect(() => budget.enter()).toThrow("BUDGET_CONCURRENCY_EXCEEDED");
    leave();
    expect(() => {
      budget.enter();
    }).toThrow("BUDGET_REQUESTS_EXCEEDED");
  });
  it("propagates the global kill switch and abort signal", () => {
    const kill = new KillSwitch();
    const budget = new SerialBudget(2);
    const release = budget.enter(kill.signal);
    release();
    kill.kill();
    expect(kill.signal.aborted).toBe(true);
    expect(() => {
      kill.assertRunning();
    }).toThrow("GLOBAL_KILL_SWITCH");
    expect(() => budget.enter(kill.signal)).toThrow("GLOBAL_KILL_SWITCH");
    expect(decidePolicy({ ...input(), killed: true }).reason).toBe(
      "BLOCK_KILL_SWITCH",
    );
  });
});
