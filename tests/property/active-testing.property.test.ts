import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  activeTestPlanDigest,
  createActiveTestPlan,
  projectActiveTestAsset,
  validateAndFreezeActiveTestPlan,
} from "../../packages/active-testing/index.js";
import { sha256 } from "../../packages/shared/canonical.js";
import {
  activeTestPlanInput,
  activeTestScope,
  activeTestSnapshot,
} from "../fixtures/active-testing.factory.js";

describe("active testing properties", () => {
  it("never supports a non-HTTPS, wildcard, query-bearing or non-URL asset", () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.domain().map((host) => `http://${host}/`),
          fc.domain().map((host) => `https://*.${host}/`),
          fc.domain().map((host) => `https://${host}/?probe=value`),
        ),
        fc.constantFrom("URL", "DOMAIN", "CIDR", "OTHER"),
        (identifier, assetType) => {
          const projected = projectActiveTestAsset(
            activeTestScope({
              assetType,
              assetIdentifier: identifier,
              assetIdentifierDigest: sha256(identifier),
            }),
          );
          expect(projected.supported).toBe(false);
        },
      ),
      { numRuns: 150 },
    );
  });

  it("binds every plan digest to every executable field", () => {
    const plan = createActiveTestPlan(activeTestPlanInput());
    const digest = activeTestPlanDigest(plan);
    fc.assert(
      fc.property(
        fc.constantFrom(
          "program_ref",
          "snapshot_digest",
          "policy_digest",
          "scope_id",
          "asset_identifier_digest",
          "test_class",
          "runner_version",
        ),
        fc.string({ minLength: 1, maxLength: 40 }),
        (field, replacement) => {
          if (replacement === plan[field]) return;
          const candidate = { ...plan, [field]: replacement };
          try {
            const validated = validateAndFreezeActiveTestPlan(candidate);
            expect(activeTestPlanDigest(validated)).not.toBe(digest);
          } catch {
            expect(true).toBe(true);
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  it("never accepts an asset digest that differs from the snapshot", () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[a-f0-9]{64}$/u), (digest) => {
        const scope = activeTestScope();
        if (digest === scope.assetIdentifierDigest) return;
        const snapshot = activeTestSnapshot({ scopes: [scope] });
        expect(() =>
          createActiveTestPlan(
            activeTestPlanInput({ snapshot, assetIdentifierDigest: digest }),
          ),
        ).toThrow("ACTIVE_TEST_SCOPE_BINDING_INVALID");
      }),
      { numRuns: 100 },
    );
  });
});
