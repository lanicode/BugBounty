import fc from "fast-check";
import { expect, it } from "vitest";
import {
  AccountSimulationCoordinator,
  MockLocalAccountApplication,
  type HumanCheckpointKind,
} from "../../packages/account-simulation/workflow.js";

it("never reaches ACTIVE before every generated human checkpoint is satisfied", async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.array(
        fc.constantFrom<HumanCheckpointKind>(
          "captcha",
          "two_factor",
          "program_rules",
          "terms",
          "legal",
        ),
        { minLength: 1, maxLength: 8 },
      ),
      async (plan) => {
        const app = new MockLocalAccountApplication("local-app:fixture", {
          account: plan,
        });
        const workflow = new AccountSimulationCoordinator(
          app,
          "a".repeat(64),
          new Set(["account"]),
          20,
          new AbortController().signal,
          () => new Date("2026-07-13T12:00:00Z"),
        );
        let result = await workflow.execute({
          version: 1,
          proposal_id: "start",
          action: "provision",
          mode: "simulation",
          workflow_ref: "workflow",
          application_ref: "local-app:fixture",
          account_ref: "account",
          role: "owner",
          policy_hash_sha256: "a".repeat(64),
          expected_revision: 0,
          checkpoint_ref: null,
        });
        for (let index = 0; index < plan.length; index += 1) {
          expect(result.workflow.state).toBe("PAUSED");
          const checkpoint = result.workflow.checkpoint?.checkpointRef;
          if (checkpoint === undefined) throw new Error("MISSING_CHECKPOINT");
          app.satisfyCheckpoint(checkpoint);
          result = await workflow.execute({
            version: 1,
            proposal_id: `resume-${String(index)}`,
            action: "resume",
            mode: "simulation",
            workflow_ref: "workflow",
            application_ref: "local-app:fixture",
            account_ref: "account",
            role: "owner",
            policy_hash_sha256: "a".repeat(64),
            expected_revision: index + 1,
            checkpoint_ref: checkpoint,
          });
        }
        expect(result.workflow.state).toBe("ACTIVE");
      },
    ),
    { numRuns: 50 },
  );
});
