import fc from "fast-check";
import { expect, it } from "vitest";
import { rankPrograms } from "../../packages/platform/ranking.js";
import { compilePlatformPolicy } from "../../packages/platform-source/compiler.js";
import { validateProgramSnapshot } from "../../packages/platform-source/fixture-source.js";
import { snapshotValue } from "../fixtures/platform-source.factory.js";

it("ranking is permutation-invariant for generated unique handles", () => {
  fc.assert(
    fc.property(
      fc.uniqueArray(fc.stringMatching(/^[a-z]{1,12}$/u), {
        minLength: 1,
        maxLength: 20,
      }),
      (handles) => {
        const base = snapshotValue();
        const entries = handles.map((handle) => ({
          policy: compilePlatformPolicy(
            validateProgramSnapshot({
              ...base,
              program: { ...base.program, handle },
            }),
          ),
          acceptance: "accepted" as const,
        }));
        expect(rankPrograms(entries, "2026-07-13T13:00:00Z")).toEqual(
          rankPrograms([...entries].reverse(), "2026-07-13T13:00:00Z"),
        );
      },
    ),
    { numRuns: 100 },
  );
});
