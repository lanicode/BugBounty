import fc from "fast-check";
import { expect, it } from "vitest";
import { compilePlatformPolicy } from "../../packages/platform-source/compiler.js";
import { validateProgramSnapshot } from "../../packages/platform-source/fixture-source.js";
import { snapshotValue } from "../fixtures/platform-source.factory.js";

it("compiles generated target order into the same deterministic host order", () => {
  fc.assert(
    fc.property(
      fc.uniqueArray(fc.stringMatching(/^[a-z]{1,10}$/u), {
        minLength: 1,
        maxLength: 20,
      }),
      fc.boolean(),
      (labels, reverse) => {
        const base = snapshotValue();
        const targets = labels.map((label) => ({
          scheme: "https" as const,
          host: `${label}.example.test`,
          ports: [443],
          path_prefixes: ["/"],
        }));
        const shuffled = reverse ? [...targets].reverse() : targets;
        const policy = compilePlatformPolicy(
          validateProgramSnapshot({
            ...base,
            network: { ...base.network, targets: shuffled },
          }),
        );
        expect(policy.targets.map((target) => target.host)).toEqual(
          targets.map((target) => target.host).sort(),
        );
      },
    ),
    { numRuns: 200 },
  );
});
