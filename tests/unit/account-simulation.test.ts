import { describe, expect, it } from "vitest";
import {
  AccountSimulationCoordinator,
  DisabledExternalAccountAdapter,
  MockLocalAccountApplication,
  type AccountSimulationProposal,
  type HumanCheckpointKind,
} from "../../packages/account-simulation/workflow.js";

const POLICY_HASH = "a".repeat(64);
const proposal = (
  overrides: Partial<AccountSimulationProposal> = {},
): AccountSimulationProposal => ({
  version: 1,
  proposal_id: "account-proposal-1",
  action: "provision",
  mode: "simulation",
  workflow_ref: "workflow-1",
  application_ref: "local-app:fixture",
  account_ref: "account-a",
  role: "owner",
  policy_hash_sha256: POLICY_HASH,
  expected_revision: 0,
  checkpoint_ref: null,
  ...overrides,
});

const coordinator = (
  adapter: MockLocalAccountApplication,
  options: { maxActions?: number; signal?: AbortSignal; now?: () => Date } = {},
) =>
  new AccountSimulationCoordinator(
    adapter,
    POLICY_HASH,
    new Set(["account-a"]),
    options.maxActions ?? 20,
    options.signal ?? new AbortController().signal,
    options.now ?? (() => new Date("2026-07-13T12:00:00Z")),
  );

describe("local account workflow simulation", () => {
  it("pauses for every human-only challenge and never auto-accepts it", async () => {
    for (const kind of [
      "captcha",
      "two_factor",
      "program_rules",
      "terms",
      "legal",
    ] as HumanCheckpointKind[]) {
      const app = new MockLocalAccountApplication("local-app:fixture", {
        "account-a": [kind],
      });
      const result = await coordinator(app).execute(proposal());
      expect(result.workflow).toMatchObject({
        state: "PAUSED",
        checkpoint: { kind },
      });
      expect(result.trace).toEqual([
        "schema",
        "policy",
        "scope",
        "budget",
        "runner",
      ]);
    }
  });

  it("requires direct human completion before a resume can advance", async () => {
    const app = new MockLocalAccountApplication("local-app:fixture", {
      "account-a": ["captcha", "two_factor"],
    });
    const workflow = coordinator(app);
    const first = await workflow.execute(proposal());
    const checkpoint = first.workflow.checkpoint?.checkpointRef;
    if (checkpoint === undefined) throw new Error("MISSING_CHECKPOINT");
    const resume = proposal({
      proposal_id: "account-proposal-2",
      action: "resume",
      expected_revision: 1,
      checkpoint_ref: checkpoint,
    });
    await expect(workflow.execute(resume)).resolves.toMatchObject({
      workflow: { state: "PAUSED", revision: 1 },
    });
    app.satisfyCheckpoint(checkpoint);
    const second = await workflow.execute(resume);
    expect(second.workflow).toMatchObject({
      state: "PAUSED",
      revision: 2,
      checkpoint: { kind: "two_factor" },
    });
    const secondCheckpoint = second.workflow.checkpoint?.checkpointRef;
    if (secondCheckpoint === undefined) throw new Error("MISSING_CHECKPOINT");
    app.satisfyCheckpoint(secondCheckpoint);
    const active = await workflow.execute(
      proposal({
        proposal_id: "account-proposal-3",
        action: "resume",
        expected_revision: 2,
        checkpoint_ref: secondCheckpoint,
      }),
    );
    expect(active.workflow).toMatchObject({ state: "ACTIVE", revision: 3 });
    await expect(workflow.execute(resume)).rejects.toThrow(
      "ACCOUNT_WORKFLOW_REVISION_MISMATCH",
    );
  });

  it("supports deterministic local retirement but no external adapter", async () => {
    const app = new MockLocalAccountApplication("local-app:fixture", {
      "account-a": [],
    });
    const workflow = coordinator(app);
    await workflow.execute(proposal());
    await expect(
      workflow.execute(
        proposal({
          proposal_id: "retire-1",
          action: "retire",
          expected_revision: 1,
        }),
      ),
    ).resolves.toMatchObject({ workflow: { state: "RETIRED", revision: 2 } });
    await expect(
      new AccountSimulationCoordinator(
        new DisabledExternalAccountAdapter(),
        POLICY_HASH,
        new Set(["account-a"]),
        1,
        new AbortController().signal,
        () => new Date("2026-07-13T12:00:00Z"),
      ).execute(proposal()),
    ).rejects.toThrow("EXTERNAL_INTEGRATIONS_DISABLED");
  });

  it("blocks secret fields, drift, scope, expiry, budget and kill switch", async () => {
    const app = new MockLocalAccountApplication("local-app:fixture", {
      "account-a": ["captcha"],
    });
    const workflow = coordinator(app, { maxActions: 1 });
    await expect(
      workflow.execute({ ...proposal(), password: "x" }),
    ).rejects.toThrow("ACCOUNT_SCHEMA_INVALID");
    await expect(
      workflow.execute(proposal({ policy_hash_sha256: "b".repeat(64) })),
    ).rejects.toThrow("ACCOUNT_POLICY_DRIFT");
    await expect(
      workflow.execute(proposal({ application_ref: "local-app:other" })),
    ).rejects.toThrow("ACCOUNT_APPLICATION_SCOPE_BLOCKED");
    const paused = await workflow.execute(proposal());
    const checkpoint = paused.workflow.checkpoint?.checkpointRef;
    if (checkpoint === undefined) throw new Error("MISSING_CHECKPOINT");
    await expect(
      workflow.execute(
        proposal({
          action: "resume",
          expected_revision: 1,
          checkpoint_ref: checkpoint,
        }),
      ),
    ).rejects.toThrow("ACCOUNT_BUDGET_EXCEEDED");

    let now = new Date("2026-07-13T12:00:00Z");
    const expiring = coordinator(app, { now: () => now });
    const initial = await expiring.execute(
      proposal({ workflow_ref: "workflow-expiry" }),
    );
    const expiringCheckpoint = initial.workflow.checkpoint?.checkpointRef;
    if (expiringCheckpoint === undefined) throw new Error("MISSING_CHECKPOINT");
    now = new Date("2026-07-13T12:06:00Z");
    await expect(
      expiring.execute(
        proposal({
          workflow_ref: "workflow-expiry",
          action: "resume",
          expected_revision: 1,
          checkpoint_ref: expiringCheckpoint,
        }),
      ),
    ).rejects.toThrow("ACCOUNT_CHECKPOINT_EXPIRED");

    const killedController = new AbortController();
    killedController.abort();
    await expect(
      coordinator(app, { signal: killedController.signal }).execute(
        proposal({ workflow_ref: "workflow-killed" }),
      ),
    ).rejects.toThrow("PHASE2_GLOBAL_KILL_SWITCH");
  });
});
