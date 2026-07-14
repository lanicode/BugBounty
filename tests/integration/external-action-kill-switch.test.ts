import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ControlPlaneDatabase,
  type ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  DeterministicMockActionRunner,
  ExternalActionPipeline,
  Phase2KillSwitch,
  StoreBoundExternalActionEvaluator,
  enqueueStoreBoundExternalActionApproval,
  prepareStoreBoundExternalActionProposal,
} from "../../packages/external-actions/index.js";
import {
  resolvePhase2Runtime,
  SAFE_PHASE2_CONFIG,
} from "../../packages/phase2-config/index.js";
import {
  ACTION_EXECUTION_TIME,
  ACTION_OPERATOR,
  ACTION_TIME,
  seedStoreBoundAction,
} from "../fixtures/store-bound-action.factory.js";

const databases: ControlPlaneDatabase[] = [];

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(ACTION_TIME);
});

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  vi.useRealTimers();
});

describe("persistent global kill switch composition", () => {
  it("blocks before reservation without invoking the runner", async () => {
    const database = trackedDatabase();
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    seeded.store.setKillSwitch(true, "local-reviewer", ACTION_EXECUTION_TIME);
    vi.setSystemTime(ACTION_EXECUTION_TIME);

    await expect(
      pipeline(seeded.store, runner).execute(seeded.proposal),
    ).rejects.toThrow("ACTION_KILL_SWITCH");
    expect(seeded.store.listExternalActionAttempts()).toEqual([]);
    expect(runner.recordedExecutions()).toEqual([]);
  });

  it("aborts a fail-closed reservation when killed before the runner", async () => {
    const database = trackedDatabase();
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    let reads = 0;
    const killSwitch = new Phase2KillSwitch({
      readActive: () => {
        reads += 1;
        if (reads === 3)
          seeded.store.setKillSwitch(
            true,
            "local-reviewer",
            ACTION_EXECUTION_TIME,
          );
        return seeded.store.isKillSwitchActive();
      },
    });
    vi.setSystemTime(ACTION_EXECUTION_TIME);

    await expect(
      new ExternalActionPipeline(
        runtime(),
        runner,
        killSwitch,
        new StoreBoundExternalActionEvaluator(seeded.store),
      ).execute(seeded.proposal),
    ).rejects.toThrow("ACTION_KILL_SWITCH");
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "aborted", revision: 1 },
    ]);
    expect(runner.recordedExecutions()).toEqual([]);
  });

  it("releases concurrency after a handled pre-run abort without refunding budget", async () => {
    const database = trackedDatabase();
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    let reads = 0;
    const transientKill = new Phase2KillSwitch({
      readActive: () => {
        reads += 1;
        return reads >= 3;
      },
    });
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    await expect(
      new ExternalActionPipeline(
        runtime(),
        new DeterministicMockActionRunner({
          "proposal-1": { unexpected: true },
        }),
        transientKill,
        new StoreBoundExternalActionEvaluator(seeded.store),
      ).execute(seeded.proposal),
    ).rejects.toThrow("ACTION_KILL_SWITCH");

    vi.setSystemTime("2026-07-13T14:00:03.000Z");
    const secondProposal = prepareStoreBoundExternalActionProposal(
      seeded.store,
      {
        proposalId: "proposal-2",
        actionId: "platform_api_read",
        campaignRef: seeded.campaign.id,
        accountRef: null,
        objectRef: null,
        payloadRef: null,
        approvalRef: "action-approval-2",
        operatorRef: ACTION_OPERATOR,
      },
    );
    const secondApproval = enqueueStoreBoundExternalActionApproval(
      seeded.store,
      secondProposal,
    );
    seeded.store.decideApproval({
      id: secondApproval.id,
      expectedRevision: 0,
      expectedPayloadHash: secondApproval.payloadHash,
      decision: "accepted",
      actor: ACTION_OPERATOR,
      userAction: "approve_store_bound_external_action",
      at: "2026-07-13T14:00:04.000Z",
    });
    vi.setSystemTime("2026-07-13T14:00:05.000Z");
    const budgetRunner = new DeterministicMockActionRunner({
      "proposal-2": { unexpected: true },
    });
    await expect(
      pipeline(seeded.store, budgetRunner, 1).execute(secondProposal),
    ).rejects.toThrow("ACTION_BUDGET_EXCEEDED");
    expect(budgetRunner.recordedExecutions()).toEqual([]);
    await expect(
      pipeline(
        seeded.store,
        new DeterministicMockActionRunner({
          "proposal-2": { ok: true },
        }),
      ).execute(secondProposal),
    ).resolves.toMatchObject({ proposalId: "proposal-2" });
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "aborted", revision: 1 },
      { proposalId: "proposal-2", status: "succeeded", revision: 2 },
    ]);
  });

  it("blocks an inter-stage attempt to mutate reservation audit evidence", async () => {
    const database = trackedDatabase();
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    let reads = 0;
    const killSwitch = new Phase2KillSwitch({
      readActive: () => {
        reads += 1;
        if (reads === 3)
          database.run(
            `UPDATE control_plane_audit SET decision='tampered'
             WHERE action='external_action_authorization'`,
          );
        return seeded.store.isKillSwitchActive();
      },
    });
    vi.setSystemTime(ACTION_EXECUTION_TIME);

    await expect(
      new ExternalActionPipeline(
        runtime(),
        runner,
        killSwitch,
        new StoreBoundExternalActionEvaluator(seeded.store),
      ).execute(seeded.proposal),
    ).rejects.toThrow("ACTION_KILL_SWITCH");
    expect(runner.recordedExecutions()).toEqual([]);
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "aborted", revision: 1 },
    ]);
  });

  it("aborts a deferred runner when persistent state engages", async () => {
    const database = trackedDatabase();
    const seeded = seedStoreBoundAction(database, "target_request");
    const runner = new DeterministicMockActionRunner(
      { "proposal-1": { ignored: true } },
      { deferredProposalIds: ["proposal-1"] },
    );
    vi.setSystemTime(ACTION_EXECUTION_TIME);

    const pending = pipeline(seeded.store, runner).execute(seeded.proposal);
    const rejected = expect(pending).rejects.toThrow("ACTION_KILL_SWITCH");
    expect(runner.recordedExecutions()).toHaveLength(1);
    seeded.store.setKillSwitch(
      true,
      "local-reviewer",
      "2026-07-13T14:00:03.000Z",
    );
    vi.setSystemTime("2026-07-13T14:00:03.000Z");
    await vi.advanceTimersByTimeAsync(10);

    await rejected;
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "aborted", revision: 2 },
    ]);
  });

  it("treats a closed database as an active kill switch", async () => {
    const database = trackedDatabase();
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    database.close();
    databases.splice(databases.indexOf(database), 1);
    vi.setSystemTime(ACTION_EXECUTION_TIME);

    await expect(
      pipeline(seeded.store, runner).execute(seeded.proposal),
    ).rejects.toThrow("ACTION_KILL_SWITCH");
    expect(runner.recordedExecutions()).toEqual([]);
  });
});

function runtime(maxActions = 20) {
  return resolvePhase2Runtime(
    {
      ...SAFE_PHASE2_CONFIG,
      budgets: { max_actions_total: maxActions, max_concurrency: 1 },
    },
    { secretsAvailable: false, externalAdapterAvailable: false },
  );
}

function pipeline(
  store: ControlPlaneStore,
  runner: DeterministicMockActionRunner,
  maxActions = 20,
): ExternalActionPipeline {
  return new ExternalActionPipeline(
    runtime(maxActions),
    runner,
    new Phase2KillSwitch({ readActive: () => store.isKillSwitchActive() }),
    new StoreBoundExternalActionEvaluator(store),
  );
}

function trackedDatabase(): ControlPlaneDatabase {
  const database = ControlPlaneDatabase.memory();
  databases.push(database);
  return database;
}
