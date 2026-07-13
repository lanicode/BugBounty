import { describe, expect, it } from "vitest";
import { rankPrograms } from "../../../packages/platform/ranking.js";
import { compilePlatformPolicy } from "../../../packages/platform-source/compiler.js";
import { validateProgramSnapshot } from "../../../packages/platform-source/fixture-source.js";
import { snapshotValue } from "../../fixtures/platform-source.factory.js";

const entry = (
  handle: string,
  acceptance: "accepted" | "pending_human_acceptance",
) => {
  const base = snapshotValue();
  const policy = compilePlatformPolicy(
    validateProgramSnapshot({
      ...base,
      program: { ...base.program, handle },
    }),
  );
  return { policy, acceptance } as const;
};

describe("deterministic program ranking", () => {
  it("is stable, bounded and uses an ASCII handle tie-break", () => {
    const entries = [entry("zeta", "accepted"), entry("alpha", "accepted")];
    const first = rankPrograms(entries, "2026-07-13T13:00:00Z");
    const second = rankPrograms([...entries].reverse(), "2026-07-13T13:00:00Z");
    expect(first).toEqual(second);
    expect(first.map((value) => value.handle)).toEqual(["alpha", "zeta"]);
    for (const value of first) {
      expect(value.score).toBeGreaterThanOrEqual(0);
      expect(value.score).toBeLessThanOrEqual(100);
    }
  });

  it("conservatively caps unaccepted and rejects future snapshots", () => {
    const pending = rankPrograms(
      [entry("pending", "pending_human_acceptance")],
      "2026-07-13T13:00:00Z",
    )[0];
    expect(pending?.score).toBeLessThanOrEqual(25);
    expect(pending?.eligibleForSimulation).toBe(false);
    const future = rankPrograms(
      [entry("future", "accepted")],
      "2026-07-12T13:00:00Z",
    )[0];
    expect(future).toMatchObject({ score: 0, eligibleForSimulation: false });
  });

  it("rejects an invalid explicit reference time", () => {
    expect(() => rankPrograms([], "invalid")).toThrow("RANKING_TIME_INVALID");
  });
});
