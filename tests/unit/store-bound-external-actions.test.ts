import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../packages/control-plane/index.js";
import {
  DeterministicMockActionRunner,
  DisabledExternalActionRunner,
  ExternalActionPipeline,
  Phase2KillSwitch,
  StoreBoundExternalActionEvaluator,
  enqueueStoreBoundExternalActionApproval,
  prepareStoreBoundExternalActionProposal,
  type ExternalActionAuthorizationEvaluator,
} from "../../packages/external-actions/index.js";
import {
  resolvePhase2Runtime,
  SAFE_PHASE2_CONFIG,
} from "../../packages/phase2-config/index.js";
import {
  ACTION_DECISION_TIME,
  ACTION_EXECUTION_TIME,
  ACTION_OPERATOR,
  ACTION_TIME,
  seedStoreBoundAction,
} from "../fixtures/store-bound-action.factory.js";

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
) {
  return new ExternalActionPipeline(
    runtime(maxActions),
    runner,
    new Phase2KillSwitch({ readActive: () => store.isKillSwitchActive() }),
    new StoreBoundExternalActionEvaluator(store),
  );
}

describe("store-bound external action authorization", () => {
  let database: ControlPlaneDatabase;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(ACTION_TIME);
    database = ControlPlaneDatabase.memory();
  });

  afterEach(() => {
    database.close();
    vi.useRealTimers();
  });

  it("derives one exact authorization from persisted evidence and settles it", async () => {
    const seeded = seedStoreBoundAction(database, "target_request");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { inspected: true },
    });

    await expect(
      pipeline(seeded.store, runner).execute(seeded.proposal),
    ).resolves.toEqual({
      proposalId: "proposal-1",
      actionId: "target_request",
      result: { inspected: true },
      trace: [
        "schema",
        "policy",
        "scope",
        "ownership",
        "budget",
        "human_checkpoint",
        "runner",
      ],
    });
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      {
        proposalId: "proposal-1",
        actionId: "target_request",
        status: "succeeded",
        units: 1,
        revision: 2,
      },
    ]);
    expect(runner.recordedExecutions()[0]).toMatchObject({
      target: { scheme: "http", host: "127.0.0.1" },
      definition: { requiredSecretKind: "test_identity_session" },
    });
  });

  it.each([
    "platform_api_read",
    "test_account_register",
    "email_verification_open",
    "browser_journey_start",
    "target_request",
  ] as const)(
    "supports only persisted local evidence for %s",
    async (actionId) => {
      const seeded = seedStoreBoundAction(database, actionId);
      vi.setSystemTime(ACTION_EXECUTION_TIME);
      const runner = new DeterministicMockActionRunner({
        "proposal-1": { actionId },
      });
      await expect(
        pipeline(seeded.store, runner).execute(seeded.proposal),
      ).resolves.toMatchObject({
        actionId,
      });
      expect(runner.recordedExecutions()).toHaveLength(1);
    },
  );

  it("blocks by default without store evidence", async () => {
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    const blocked = new ExternalActionPipeline(
      runtime(),
      runner,
      new Phase2KillSwitch({ readActive: () => false }),
    );
    await expect(blocked.execute(seeded.proposal)).rejects.toThrow(
      "ACTION_STORE_EVIDENCE_REQUIRED",
    );
    expect(runner.recordedExecutions()).toHaveLength(0);
  });

  it("blocks a persisted approval until its decision timestamp", async () => {
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    vi.setSystemTime("2026-07-13T14:00:00.500Z");
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });

    await expect(
      pipeline(seeded.store, runner).execute(seeded.proposal),
    ).rejects.toThrow("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    expect(runner.recordedExecutions()).toHaveLength(0);
    expect(seeded.store.listExternalActionAttempts()).toHaveLength(0);
  });

  it("rejects callback and prototype-spoofed authorizers before invocation", () => {
    let calls = 0;
    const callback: ExternalActionAuthorizationEvaluator = {
      authorizeAndReserve: () => {
        calls += 1;
        throw new Error("unexpected");
      },
      start: () => undefined,
      abortReservation: () => undefined,
      settle: () => undefined,
    };
    const runner = new DeterministicMockActionRunner({});
    expect(
      () =>
        new ExternalActionPipeline(
          runtime(),
          runner,
          new Phase2KillSwitch({ readActive: () => false }),
          callback,
        ),
    ).toThrow("ACTION_AUTHORIZER_UNTRUSTED");
    const prototypeSpoof = Object.create(
      StoreBoundExternalActionEvaluator.prototype,
    ) as ExternalActionAuthorizationEvaluator;
    expect(
      () =>
        new ExternalActionPipeline(
          runtime(),
          runner,
          new Phase2KillSwitch({ readActive: () => false }),
          prototypeSpoof,
        ),
    ).toThrow("ACTION_AUTHORIZER_UNTRUSTED");
    expect(calls).toBe(0);
  });

  it("prevents method shadowing on trusted stores and databases", () => {
    const store = new ControlPlaneStore(database);
    expect(Object.isFrozen(database)).toBe(true);
    expect(Object.isFrozen(store)).toBe(true);
    expect(Object.isFrozen(ControlPlaneDatabase.prototype)).toBe(true);
    expect(Object.isFrozen(ControlPlaneStore.prototype)).toBe(true);

    expect(() =>
      Object.defineProperty(store, "authorizeExternalAction", {
        value: () => ({ forged: true }),
      }),
    ).toThrow(TypeError);
    expect(() =>
      Object.defineProperty(database, "transaction", {
        value: (operation: () => unknown) => operation(),
      }),
    ).toThrow(TypeError);
  });

  it("prevents post-construction replacement of the trusted pipeline chain", () => {
    const runner = new DeterministicMockActionRunner({});
    const killSwitch = new Phase2KillSwitch({ readActive: () => false });
    const actionPipeline = new ExternalActionPipeline(
      runtime(),
      runner,
      killSwitch,
    );

    expect(Object.isFrozen(killSwitch)).toBe(true);
    expect(Object.isFrozen(actionPipeline)).toBe(true);
    expect(Object.isFrozen(Phase2KillSwitch.prototype)).toBe(true);
    expect(Object.isFrozen(ExternalActionPipeline.prototype)).toBe(true);
    for (const [target, property] of [
      [actionPipeline, "runner"],
      [actionPipeline, "authorizer"],
      [actionPipeline, "killSwitch"],
      [killSwitch, "readState"],
    ] as const)
      expect(() =>
        Object.defineProperty(target, property, {
          value: { forged: true },
        }),
      ).toThrow(TypeError);
  });

  it("brands the kill switch and captures its reader without invoking accessors", () => {
    const runner = new DeterministicMockActionRunner({});
    const fake = {
      assertInactive: () => undefined,
      monitor: (operation: () => Promise<unknown>) => operation(),
    } as unknown as Phase2KillSwitch;
    expect(() => new ExternalActionPipeline(runtime(), runner, fake)).toThrow(
      "ACTION_KILL_SWITCH_UNTRUSTED",
    );

    const genuine = new Phase2KillSwitch({ readActive: () => false });
    expect(
      () =>
        new ExternalActionPipeline(runtime(), runner, new Proxy(genuine, {})),
    ).toThrow("ACTION_KILL_SWITCH_UNTRUSTED");

    const mutable = { readActive: () => true };
    const captured = new Phase2KillSwitch(mutable);
    mutable.readActive = () => false;
    expect(() => {
      captured.assertInactive();
    }).toThrow("ACTION_KILL_SWITCH");

    let getterCalls = 0;
    const accessor = Object.defineProperty({}, "readActive", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return () => false;
      },
    });
    expect(
      () =>
        new Phase2KillSwitch(
          accessor as unknown as { readonly readActive: () => boolean },
        ),
    ).toThrow("ACTION_KILL_SWITCH_READER_INVALID");
    expect(getterCalls).toBe(0);
  });

  it("binds every proposal field and persistently blocks replay", async () => {
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { ok: true },
    });
    const actionPipeline = pipeline(seeded.store, runner);
    const changed = {
      ...seeded.proposal,
      parameters: {
        ...seeded.proposal.parameters,
        scope_ref: `scope-${"f".repeat(64)}`,
      },
    };
    await expect(actionPipeline.execute(changed)).rejects.toThrow(
      "ACTION_PROPOSAL_EVIDENCE_MISMATCH",
    );
    await expect(
      actionPipeline.execute(seeded.proposal),
    ).resolves.toBeDefined();
    await expect(actionPipeline.execute(seeded.proposal)).rejects.toThrow(
      "ACTION_REPLAY_BLOCKED",
    );
    expect(runner.recordedExecutions()).toHaveLength(1);
  });

  it("persists the runtime budget across pipeline instances", async () => {
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const firstRunner = new DeterministicMockActionRunner({
      "proposal-1": { ok: 1 },
    });
    await pipeline(seeded.store, firstRunner, 1).execute(seeded.proposal);

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
    const secondRunner = new DeterministicMockActionRunner({
      "proposal-2": { unexpected: true },
    });
    await expect(
      pipeline(seeded.store, secondRunner, 1).execute(secondProposal),
    ).rejects.toThrow("ACTION_BUDGET_EXCEEDED");
    expect(secondRunner.recordedExecutions()).toHaveLength(0);
  });

  it("keeps external, report, triage and non-mock runners disabled", async () => {
    const seeded = seedStoreBoundAction(database, "platform_api_read");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const external = { ...seeded.proposal, mode: "external" };
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    await expect(
      pipeline(seeded.store, runner).execute(external),
    ).rejects.toThrow("EXTERNAL_INTEGRATIONS_DISABLED");
    for (const actionId of ["report_submit", "triage_response_send"] as const)
      expect(() =>
        prepareStoreBoundExternalActionProposal(seeded.store, {
          proposalId: `proposal-${actionId}`,
          actionId,
          campaignRef: seeded.campaign.id,
          accountRef: "identity-owner",
          objectRef: "object-local",
          payloadRef: null,
          approvalRef: `approval-${actionId}`,
          operatorRef: ACTION_OPERATOR,
        }),
      ).toThrow("ACTION_SIMULATION_NOT_SUPPORTED");
    expect(
      () =>
        new ExternalActionPipeline(
          runtime(),
          new DisabledExternalActionRunner(),
          new Phase2KillSwitch({ readActive: () => false }),
          new StoreBoundExternalActionEvaluator(seeded.store),
        ),
    ).not.toThrow();
    const disabled = new ExternalActionPipeline(
      runtime(),
      new DisabledExternalActionRunner(),
      new Phase2KillSwitch({ readActive: () => false }),
      new StoreBoundExternalActionEvaluator(seeded.store),
    );
    await expect(disabled.execute(seeded.proposal)).rejects.toThrow(
      "ACTION_RUNNER_MODE_INVALID",
    );
    expect(runner.recordedExecutions()).toHaveLength(0);
  });

  it("requires exact accepted operator evidence", () => {
    const store = new ControlPlaneStore(database);
    expect(() => new StoreBoundExternalActionEvaluator(store)).not.toThrow();
    expect(() =>
      store.decideApproval({
        id: "missing",
        expectedRevision: 0,
        expectedPayloadHash: "0".repeat(64),
        decision: "accepted",
        actor: ACTION_OPERATOR,
        userAction: "approve_store_bound_external_action",
        at: ACTION_DECISION_TIME,
      }),
    ).toThrow("APPROVAL_KILL_SWITCH");
  });
});
