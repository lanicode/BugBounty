import fc from "fast-check";
import { expect, it } from "vitest";
import { decideEgress } from "../../packages/egress-guard/guard.js";
import { programConfig } from "../fixtures/factories.js";

it("never permits a non-exact generated hostname", () => {
  fc.assert(
    fc.property(fc.domain(), (domain) => {
      fc.pre(domain !== "api.example.test");
      const decision = decideEgress(
        { config: programConfig() },
        {
          url: `https://${domain}/api/`,
          method: "GET",
          captureMode: "redacted",
          resourceKind: "fetch",
          isRedirect: false,
        },
      );
      expect(decision.allow).toBe(false);
    }),
    { numRuns: 300 },
  );
});

it("encoded traversal never becomes an allowed path", () => {
  fc.assert(
    fc.property(
      fc.constantFrom("%2e%2e", "%252e%252e", "%25252e%25252e"),
      fc.stringMatching(/^[a-z]{1,12}$/),
      (traversal, suffix) => {
        const decision = decideEgress(
          { config: programConfig() },
          {
            url: `https://api.example.test/api/${traversal}/${suffix}`,
            method: "GET",
            captureMode: "redacted",
            resourceKind: "fetch",
            isRedirect: false,
          },
        );
        expect(decision.allow).toBe(false);
      },
    ),
  );
});
