import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  AccountSimulationCoordinator,
  MockLocalAccountApplication,
} from "../../packages/account-simulation/workflow.js";
import { validateCampaignContract } from "../../packages/control-plane/campaign-machine.js";
import {
  normalizePolicy,
  type PolicyInput,
} from "../../packages/control-plane/policy.js";
import { campaign } from "../fixtures/control-plane.factory.js";

const POLICY_HASH = "a".repeat(64);

describe("phase 2 security boundaries", () => {
  it("rejects every generated invalid account-action budget", () => {
    const invalidBudget = fc.oneof(
      fc.integer({ min: -10_000, max: 0 }),
      fc.integer({ min: 1_001, max: 100_000 }),
      fc.integer({ min: 1, max: 1_000 }).map((value) => value + 0.5),
      fc.constantFrom(
        Number.NaN,
        Number.POSITIVE_INFINITY,
        Number.NEGATIVE_INFINITY,
      ),
    );

    fc.assert(
      fc.property(invalidBudget, (budget) => {
        expect(
          () =>
            new AccountSimulationCoordinator(
              new MockLocalAccountApplication("local-app:fixture", {}),
              POLICY_HASH,
              new Map([["account-a", "Owner"] as const]),
              budget,
              new AbortController().signal,
              () => new Date("2026-07-13T12:00:00.000Z"),
            ),
        ).toThrow("ACCOUNT_BUDGET_INVALID");
      }),
      { numRuns: 100 },
    );
  });

  it("never allows a generated host beyond the exact reviewed asset list", () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[a-z]{1,24}$/u), (label) => {
        const candidate = campaign({
          contract: {
            ...campaign().contract,
            allowedHosts: ["demo.local.test", `${label}.invalid`],
          },
        });
        expect(() => {
          validateCampaignContract(candidate);
        }).toThrow("CAMPAIGN_CONTRACT_INVALID");
      }),
      { numRuns: 100 },
    );
  });

  it("rejects generated secret-like policy material before persistence", () => {
    const secretMaterial = fc
      .tuple(
        fc.constantFrom(
          "api_key",
          "client_secret",
          "password",
          "session",
          "token",
        ),
        fc.stringMatching(/^[A-Za-z0-9]{8,32}$/u),
      )
      .map(([label, value]) => `${label}=${value}`);

    fc.assert(
      fc.property(secretMaterial, (text) => {
        const input: PolicyInput = {
          text,
          allowedAssets: ["demo.local.test"],
          excludedAssets: ["admin.demo.local.test"],
          requestLimits: {
            requestsPerMinute: 10,
            maxRequestsTotal: 20,
            maxConcurrency: 1,
          },
          allowedTestClasses: ["offline_simulation"],
          forbiddenTestClasses: ["active_security_test"],
          rules: ["Local fixtures only"],
          unclearRules: [],
        };
        expect(() => normalizePolicy(input)).toThrow(
          "POLICY_SENSITIVE_MATERIAL",
        );
      }),
      { numRuns: 100 },
    );
  });
});
