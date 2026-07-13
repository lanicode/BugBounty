import { describe, expect, it } from "vitest";
import { collectInteractiveSimulationEvidence } from "../../packages/simulation/interactive-evidence.js";

describe("interactive simulation evidence", () => {
  it("collects every confirmation sequentially after naming the actor", async () => {
    const answers = [
      "local-reviewer",
      ...Array.from({ length: 6 }, () => "yes"),
    ];
    const prompts: string[] = [];
    let clock = Date.parse("2026-07-13T12:00:00.000Z");
    const evidence = await collectInteractiveSimulationEvidence({
      reviewDigest: "a".repeat(64),
      prompt: (message) => {
        prompts.push(message);
        return Promise.resolve(answers.shift() ?? "");
      },
      now: () => new Date(clock++),
    });

    expect(prompts).toHaveLength(7);
    expect(prompts[0]).toContain("Akteur");
    expect(evidence).toMatchObject({
      actor: "local-reviewer",
      reviewDigest: "a".repeat(64),
      confirmations: {
        clearKillSwitch: true,
        acceptPolicyV1: true,
        approveCampaignV1: true,
        acceptPolicyV2: true,
        approveCampaignV2: true,
        queueReportReview: true,
      },
    });
    const times = Object.values(evidence.confirmationTimes).map((value) =>
      Date.parse(value),
    );
    expect(
      times.every(
        (value, index) => index === 0 || value > (times[index - 1] ?? value),
      ),
    ).toBe(true);
    expect(Date.parse(evidence.confirmedAt)).toBeGreaterThanOrEqual(
      Date.parse(evidence.confirmationTimes.queueReportReview),
    );
  });

  it("stops immediately and fails closed when any answer is not exact yes", async () => {
    const answers = ["local-reviewer", "yes", "no", "yes"];
    let prompts = 0;
    await expect(
      collectInteractiveSimulationEvidence({
        reviewDigest: "a".repeat(64),
        prompt: () => {
          prompts += 1;
          return Promise.resolve(answers.shift() ?? "");
        },
        now: () => new Date("2026-07-13T12:00:00.000Z"),
      }),
    ).rejects.toThrow("SIMULATION_CONFIRMATION_DECLINED");
    expect(prompts).toBe(3);
  });
});
