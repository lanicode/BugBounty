import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ControlPlaneDatabase,
  type ControlPlaneStore as ControlPlaneStoreType,
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
import { controlPlanePolicy } from "../fixtures/control-plane.factory.js";
import {
  createTestControlPlaneStore,
  decideTestApproval,
} from "../fixtures/operator-auth.factory.js";
import {
  ACTION_EXECUTION_TIME,
  ACTION_DECISION_TIME,
  ACTION_OPERATOR,
  ACTION_TIME,
  seedRunningCampaign,
  seedStoreBoundAction,
} from "../fixtures/store-bound-action.factory.js";

const databases: ControlPlaneDatabase[] = [];
const temporaryRoots: string[] = [];
const SECOND_CAMPAIGN_APPROVAL_TIME = ACTION_EXECUTION_TIME;
const SECOND_ACTION_DECISION_TIME = "2026-07-13T14:00:03.000Z";
const SECOND_ACTION_EXECUTION_TIME = "2026-07-13T14:00:04.000Z";

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(ACTION_TIME);
});

afterEach(async () => {
  for (const database of databases.splice(0)) database.close();
  for (const root of temporaryRoots.splice(0))
    await rm(root, { recursive: true, force: true });
  vi.useRealTimers();
});

describe("persisted store-bound external actions", () => {
  it("enforces the persisted per-campaign rolling rate budget", async () => {
    const database = trackedDatabase();
    const store = createTestControlPlaneStore(database, ACTION_TIME);
    const campaign = seedRunningCampaign(store, { requestsPerMinute: 1 });
    const first = approvePlatformProposal(store, campaign.id, "1");
    const second = approvePlatformProposal(store, campaign.id, "2");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    await pipeline(
      store,
      new DeterministicMockActionRunner({ "proposal-1": { ok: true } }),
    ).execute(first);

    vi.setSystemTime("2026-07-13T14:00:03.000Z");
    const runner = new DeterministicMockActionRunner({
      "proposal-2": { unexpected: true },
    });
    await expect(pipeline(store, runner).execute(second)).rejects.toThrow(
      "ACTION_RATE_BUDGET_EXCEEDED",
    );
    expect(runner.recordedExecutions()).toEqual([]);

    vi.setSystemTime("2026-07-13T14:01:02.000Z");
    await expect(pipeline(store, runner).execute(second)).rejects.toThrow(
      "ACTION_RATE_BUDGET_EXCEEDED",
    );
    vi.setSystemTime("2026-07-13T14:01:02.001Z");
    await expect(
      pipeline(store, runner).execute(second),
    ).resolves.toMatchObject({ proposalId: "proposal-2" });
  });

  it("blocks clock rollback before creating another reservation", async () => {
    const database = trackedDatabase();
    const store = createTestControlPlaneStore(database, ACTION_TIME);
    const firstCampaign = seedRunningCampaign(store);
    const secondCampaign = seedRunningCampaign(store, {
      programId: "program-second",
      campaignId: "campaign-second",
      namespace: "second",
      clearKillSwitch: false,
      approvalTime: SECOND_CAMPAIGN_APPROVAL_TIME,
    });
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const first = approvePlatformProposal(
      store,
      firstCampaign.id,
      "1",
      SECOND_ACTION_DECISION_TIME,
    );
    const second = approvePlatformProposal(
      store,
      secondCampaign.id,
      "2",
      SECOND_ACTION_DECISION_TIME,
    );
    vi.setSystemTime("2026-07-13T14:00:10.000Z");
    await pipeline(
      store,
      new DeterministicMockActionRunner({ "proposal-1": { ok: true } }),
    ).execute(first);

    vi.setSystemTime("2026-07-13T14:00:05.000Z");
    const runner = new DeterministicMockActionRunner({
      "proposal-2": { unexpected: true },
    });
    await expect(pipeline(store, runner).execute(second)).rejects.toThrow(
      "ACTION_CLOCK_ROLLBACK",
    );
    expect(runner.recordedExecutions()).toEqual([]);
  });

  it("leaves a crash-boundary reservation persisted and blocking", async () => {
    const root = await mkdtemp(join(tmpdir(), "bbc-phase3-crash-"));
    temporaryRoots.push(root);
    const path = join(root, "control-plane.sqlite");
    let database = await ControlPlaneDatabase.file(path);
    databases.push(database);
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    seeded.store.authorizeExternalAction({
      proposal: seeded.proposal,
      definition: Object.freeze({
        actionId: "platform_api_read",
        targetClass: "platform_api",
        ownershipCheck: "not_applicable",
        ownedObjectAction: null,
        budgetUnits: 1,
      }),
      now: ACTION_EXECUTION_TIME,
      runtimeMaxActions: 20,
      runtimeMaxConcurrency: 1,
    });

    database.close();
    databases.splice(databases.indexOf(database), 1);
    database = await ControlPlaneDatabase.file(path);
    databases.push(database);
    const reopened = createTestControlPlaneStore(
      database,
      ACTION_EXECUTION_TIME,
    );
    expect(reopened.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "reserved", revision: 0 },
    ]);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    await expect(
      pipeline(reopened, runner).execute(seeded.proposal),
    ).rejects.toThrow("ACTION_REPLAY_BLOCKED");
    expect(runner.recordedExecutions()).toEqual([]);
  });

  it("enforces the runtime total budget globally across campaigns", async () => {
    const database = trackedDatabase();
    const first = seedStoreBoundAction(database, "platform_api_read");
    const secondCampaign = seedRunningCampaign(first.store, {
      programId: "program-second",
      campaignId: "campaign-second",
      namespace: "second",
      clearKillSwitch: false,
      approvalTime: SECOND_CAMPAIGN_APPROVAL_TIME,
    });
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const secondProposal = prepareStoreBoundExternalActionProposal(
      first.store,
      {
        proposalId: "proposal-2",
        actionId: "platform_api_read",
        campaignRef: secondCampaign.id,
        accountRef: null,
        objectRef: null,
        payloadRef: null,
        approvalRef: "action-approval-2",
        operatorRef: ACTION_OPERATOR,
      },
    );
    const secondApproval = enqueueStoreBoundExternalActionApproval(
      first.store,
      secondProposal,
    );
    decideTestApproval(first.store, {
      approvalId: secondApproval.id,
      decision: "accepted",
      userAction: "approve_store_bound_external_action",
      issuedAt: SECOND_ACTION_DECISION_TIME,
    });
    vi.setSystemTime(SECOND_ACTION_EXECUTION_TIME);
    await pipeline(
      first.store,
      new DeterministicMockActionRunner({ "proposal-1": { ok: true } }),
      1,
    ).execute(first.proposal);

    const secondRunner = new DeterministicMockActionRunner({
      "proposal-2": { unexpected: true },
    });
    await expect(
      pipeline(first.store, secondRunner, 1).execute(secondProposal),
    ).rejects.toThrow("ACTION_BUDGET_EXCEEDED");
    expect(secondRunner.recordedExecutions()).toEqual([]);
    expect(first.store.listExternalActionAttempts()).toHaveLength(1);
  });

  it("enforces runtime concurrency globally across campaigns", async () => {
    const database = trackedDatabase();
    const first = seedStoreBoundAction(database, "platform_api_read");
    const secondCampaign = seedRunningCampaign(first.store, {
      programId: "program-second",
      campaignId: "campaign-second",
      namespace: "second",
      clearKillSwitch: false,
      approvalTime: SECOND_CAMPAIGN_APPROVAL_TIME,
    });
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const secondProposal = prepareStoreBoundExternalActionProposal(
      first.store,
      {
        proposalId: "proposal-2",
        actionId: "platform_api_read",
        campaignRef: secondCampaign.id,
        accountRef: null,
        objectRef: null,
        payloadRef: null,
        approvalRef: "action-approval-2",
        operatorRef: ACTION_OPERATOR,
      },
    );
    const secondApproval = enqueueStoreBoundExternalActionApproval(
      first.store,
      secondProposal,
    );
    decideTestApproval(first.store, {
      approvalId: secondApproval.id,
      decision: "accepted",
      userAction: "approve_store_bound_external_action",
      issuedAt: SECOND_ACTION_DECISION_TIME,
    });
    vi.setSystemTime(SECOND_ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner(
      {
        "proposal-1": { first: true },
        "proposal-2": { unexpected: true },
      },
      { deferredProposalIds: ["proposal-1"] },
    );
    const firstPending = pipeline(first.store, runner).execute(first.proposal);
    expect(runner.recordedExecutions()).toHaveLength(1);

    await expect(
      pipeline(first.store, runner).execute(secondProposal),
    ).rejects.toThrow("ACTION_CONCURRENCY_EXCEEDED");
    expect(runner.recordedExecutions()).toHaveLength(1);
    runner.release("proposal-1");
    await expect(firstPending).resolves.toMatchObject({
      proposalId: "proposal-1",
    });
  });

  it("keeps replay and total budget consumed after database reopen", async () => {
    const root = await mkdtemp(join(tmpdir(), "bbc-phase3-action-"));
    temporaryRoots.push(root);
    const path = join(root, "control-plane.sqlite");
    let database = await ControlPlaneDatabase.file(path);
    databases.push(database);
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    await pipeline(
      seeded.store,
      new DeterministicMockActionRunner({ "proposal-1": { ok: true } }),
      1,
    ).execute(seeded.proposal);

    database.close();
    databases.splice(databases.indexOf(database), 1);
    database = await ControlPlaneDatabase.file(path);
    databases.push(database);
    const reopened = createTestControlPlaneStore(
      database,
      ACTION_EXECUTION_TIME,
    );
    vi.setSystemTime("2026-07-13T14:00:03.000Z");
    const replayRunner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    await expect(
      pipeline(reopened, replayRunner, 1).execute(seeded.proposal),
    ).rejects.toThrow("ACTION_REPLAY_BLOCKED");
    expect(replayRunner.recordedExecutions()).toEqual([]);

    vi.setSystemTime("2026-07-13T14:00:04.000Z");
    const secondProposal = prepareStoreBoundExternalActionProposal(reopened, {
      proposalId: "proposal-2",
      actionId: "platform_api_read",
      campaignRef: seeded.campaign.id,
      accountRef: null,
      objectRef: null,
      payloadRef: null,
      approvalRef: "action-approval-2",
      operatorRef: ACTION_OPERATOR,
    });
    const secondApproval = enqueueStoreBoundExternalActionApproval(
      reopened,
      secondProposal,
    );
    decideTestApproval(reopened, {
      approvalId: secondApproval.id,
      decision: "accepted",
      userAction: "approve_store_bound_external_action",
      issuedAt: "2026-07-13T14:00:05.000Z",
    });
    vi.setSystemTime("2026-07-13T14:00:06.000Z");
    const budgetRunner = new DeterministicMockActionRunner({
      "proposal-2": { unexpected: true },
    });
    await expect(
      pipeline(reopened, budgetRunner, 1).execute(secondProposal),
    ).rejects.toThrow("ACTION_BUDGET_EXCEEDED");
    expect(budgetRunner.recordedExecutions()).toEqual([]);
    expect(reopened.listExternalActionAttempts()).toHaveLength(1);
  });

  it("revalidates campaign drift between reservation and runner", async () => {
    const database = trackedDatabase();
    const seeded = seedStoreBoundAction(database, "target_request");
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    let reads = 0;
    const killSwitch = new Phase2KillSwitch({
      readActive: () => {
        reads += 1;
        if (reads === 3)
          database.run(
            "UPDATE campaigns SET last_policy_check_at=? WHERE id=?",
            ACTION_EXECUTION_TIME,
            seeded.campaign.id,
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
    ).rejects.toThrow("ACTION_EVIDENCE_CHANGED");
    expect(runner.recordedExecutions()).toEqual([]);
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "aborted", revision: 1 },
    ]);
  });

  it.each([
    {
      name: "policy",
      expected: "ACTION_POLICY_BLOCKED",
      mutate: (
        database: ControlPlaneDatabase,
        store: ControlPlaneStoreType,
      ) => {
        store.addPolicyVersion({
          programId: "program-local",
          version: 2,
          policy: controlPlanePolicy("Drifted local simulation policy"),
          createdAt: ACTION_EXECUTION_TIME,
        });
      },
    },
    {
      name: "campaign",
      expected: "ACTION_PROPOSAL_EVIDENCE_MISMATCH",
      mutate: (database: ControlPlaneDatabase) => {
        database.run(
          "UPDATE campaigns SET revision=revision+1 WHERE id='campaign-local'",
        );
      },
    },
    {
      name: "identity",
      expected: "ACTION_PROPOSAL_EVIDENCE_MISMATCH",
      mutate: (database: ControlPlaneDatabase) => {
        database.run(
          "UPDATE test_identities SET role='Member' WHERE id='identity-owner'",
        );
      },
    },
    {
      name: "owned object",
      expected: "CONTROL_PLANE_OBJECT_NOT_ACTIVE",
      mutate: (database: ControlPlaneDatabase) => {
        database.run(
          "UPDATE owned_objects SET status='deleted' WHERE object_ref='object-local'",
        );
      },
    },
  ])("blocks $name drift before reservation", async ({ expected, mutate }) => {
    const database = trackedDatabase();
    const seeded = seedStoreBoundAction(database, "target_request");
    mutate(database, seeded.store);
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });

    await expect(
      pipeline(seeded.store, runner).execute(seeded.proposal),
    ).rejects.toThrow(expected);
    expect(runner.recordedExecutions()).toEqual([]);
    expect(seeded.store.listExternalActionAttempts()).toEqual([]);
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
  store: ControlPlaneStoreType,
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

function approvePlatformProposal(
  store: ControlPlaneStoreType,
  campaignRef: string,
  suffix: string,
  decisionTime = ACTION_DECISION_TIME,
) {
  const proposal = prepareStoreBoundExternalActionProposal(store, {
    proposalId: `proposal-${suffix}`,
    actionId: "platform_api_read",
    campaignRef,
    accountRef: null,
    objectRef: null,
    payloadRef: null,
    approvalRef: `action-approval-${suffix}`,
    operatorRef: ACTION_OPERATOR,
  });
  const approval = enqueueStoreBoundExternalActionApproval(store, proposal);
  decideTestApproval(store, {
    approvalId: approval.id,
    decision: "accepted",
    userAction: "approve_store_bound_external_action",
    issuedAt: decisionTime,
  });
  return proposal;
}
