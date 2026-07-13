import { describe, expect, it } from "vitest";
import {
  DeterministicSimulationGateEvaluator,
  DeterministicMockActionRunner,
  DisabledExternalActionRunner,
  ExternalActionPipeline,
  Phase2KillSwitch,
  type DeterministicActionRunner,
  type DeterministicSimulationGateDecisions,
  type ExternalActionGateEvaluator,
  type ExternalActionProposal,
} from "../../packages/external-actions/pipeline.js";
import {
  getExternalActionDefinition,
  listExternalActionDefinitions,
} from "../../packages/external-actions/registry.js";
import {
  resolvePhase2Runtime,
  SAFE_PHASE2_CONFIG,
  type Phase2RuntimeState,
} from "../../packages/phase2-config/runtime.js";

const proposal = (
  overrides: Partial<ExternalActionProposal> = {},
): ExternalActionProposal => ({
  version: 1,
  proposal_id: "proposal-1",
  action_id: "platform_api_read",
  mode: "simulation",
  parameters: {
    campaign_ref: "campaign-1",
    policy_hash_sha256: "a".repeat(64),
    scope_ref: "scope-1",
    account_ref: null,
    object_ref: null,
    payload_ref: null,
  },
  ...overrides,
});

const permissiveGates = (
  overrides: Partial<DeterministicSimulationGateDecisions> = {},
  boundProposal: ExternalActionProposal = proposal(),
): ExternalActionGateEvaluator =>
  new DeterministicSimulationGateEvaluator(boundProposal, {
    policy: true,
    scope: true,
    ownership: true,
    humanCheckpoint: true,
    ...overrides,
  });

const simulationRuntime = (maxActions = 20) =>
  resolvePhase2Runtime(
    {
      ...SAFE_PHASE2_CONFIG,
      budgets: { max_actions_total: maxActions, max_concurrency: 1 },
    },
    { secretsAvailable: false, externalAdapterAvailable: false },
  );

const clearKillSwitch = () => new Phase2KillSwitch({ readActive: () => false });

describe("trusted external action registry", () => {
  it("contains every known action as a deeply immutable blocked definition", () => {
    const definitions = listExternalActionDefinitions();
    expect(definitions.map(({ actionId }) => actionId)).toEqual([
      "platform_api_read",
      "test_account_register",
      "email_verification_open",
      "browser_journey_start",
      "target_request",
      "report_submit",
      "triage_response_send",
    ]);
    expect(Object.isFrozen(definitions)).toBe(true);
    for (const definition of definitions) {
      expect(definition).toMatchObject({
        policyDecision: "required",
        scopeCheck: "required",
        budget: { kind: "action_units", units: 1 },
        defaultState: "blocked",
        killSwitchBehavior: "block_before_and_after_runner",
      });
      expect(Object.isFrozen(definition)).toBe(true);
      expect(Object.isFrozen(definition.fixedTargetPolicy)).toBe(true);
      expect(Object.isFrozen(definition.budget)).toBe(true);
    }
  });

  it("keeps report and triage human-only with no simulation target", () => {
    for (const actionId of ["report_submit", "triage_response_send"]) {
      expect(getExternalActionDefinition(actionId)).toMatchObject({
        actionId,
        fixedTargetPolicy: { kind: "external_disabled", host: null },
        simulationSupported: false,
      });
    }
  });
});

describe("external action safety chain", () => {
  it("rejects malformed runtime budgets before constructing the pipeline", () => {
    for (const value of [Number.NaN, Number.POSITIVE_INFINITY, 0, -1, 1.5]) {
      const safe = simulationRuntime();
      const malformed = {
        ...safe,
        config: {
          ...safe.config,
          budgets: {
            ...safe.config.budgets,
            max_actions_total: value,
          },
        },
      } as Phase2RuntimeState;
      expect(
        () =>
          new ExternalActionPipeline(
            malformed,
            new DeterministicMockActionRunner({}),
            clearKillSwitch(),
            permissiveGates(),
          ),
      ).toThrow("ACTION_RUNTIME_INVALID");
    }
  });

  it("rejects kind-spoofed and prototype-spoofed runner callbacks", () => {
    let callbackCalls = 0;
    const kindSpoof: DeterministicActionRunner = {
      kind: "simulation_mock",
      run: () => {
        callbackCalls += 1;
        return Promise.resolve({ unsafe: true });
      },
    };
    expect(
      () =>
        new ExternalActionPipeline(
          simulationRuntime(),
          kindSpoof,
          clearKillSwitch(),
          permissiveGates(),
        ),
    ).toThrow("ACTION_RUNNER_UNTRUSTED");

    const prototypeSpoof = Object.create(
      DeterministicMockActionRunner.prototype,
    ) as DeterministicActionRunner;
    expect(
      () =>
        new ExternalActionPipeline(
          simulationRuntime(),
          prototypeSpoof,
          clearKillSwitch(),
          permissiveGates(),
        ),
    ).toThrow("ACTION_RUNNER_UNTRUSTED");
    expect(callbackCalls).toBe(0);
  });

  it("rejects callback-based gate evaluators before any callback can run", () => {
    let gateCalls = 0;
    const untrusted: ExternalActionGateEvaluator = {
      decidePolicy: () => {
        gateCalls += 1;
        return true;
      },
      decideScope: () => true,
      decideOwnership: () => true,
      decideHumanCheckpoint: () => true,
    };
    expect(
      () =>
        new ExternalActionPipeline(
          simulationRuntime(),
          new DeterministicMockActionRunner({}),
          clearKillSwitch(),
          untrusted,
        ),
    ).toThrow("ACTION_GATES_UNTRUSTED");
    expect(gateCalls).toBe(0);
  });

  it("rejects malformed or accessor-backed deterministic gate decisions", () => {
    expect(
      () =>
        new DeterministicSimulationGateEvaluator(proposal(), {
          policy: true,
          scope: true,
          ownership: true,
          humanCheckpoint: true,
          extra: true,
        } as DeterministicSimulationGateDecisions),
    ).toThrow("ACTION_GATES_INVALID");

    const accessorBacked = Object.defineProperty(
      {
        scope: true,
        ownership: true,
        humanCheckpoint: true,
      },
      "policy",
      { enumerable: true, get: () => true },
    );
    expect(
      () =>
        new DeterministicSimulationGateEvaluator(
          proposal(),
          accessorBacked as DeterministicSimulationGateDecisions,
        ),
    ).toThrow("ACTION_GATES_INVALID");
  });

  it("executes the exact ordered chain with only registry-derived target and secret kind", async () => {
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { programs: 2 },
    });
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      runner,
      clearKillSwitch(),
      permissiveGates(),
    );

    await expect(pipeline.execute(proposal())).resolves.toEqual({
      proposalId: "proposal-1",
      actionId: "platform_api_read",
      result: { programs: 2 },
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
    const [seen] = runner.recordedExecutions();
    expect(seen).toMatchObject({
      definition: {
        requiredSecretKind: "platform_api_token",
        targetClass: "platform_api",
      },
      target: {
        class: "platform_api",
        scheme: "http",
        host: "127.0.0.1",
      },
    });
    expect(Object.isFrozen(seen?.proposal)).toBe(true);
    expect(Object.isFrozen(seen?.proposal.parameters)).toBe(true);
  });

  it("binds deterministic gate decisions to one exact proposal", async () => {
    const bound = proposal();
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { ok: true },
      "proposal-2": { unexpected: true },
    });
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      runner,
      clearKillSwitch(),
      permissiveGates({}, bound),
    );
    await expect(pipeline.execute(bound)).resolves.toMatchObject({
      proposalId: "proposal-1",
    });
    await expect(
      pipeline.execute(
        proposal({
          proposal_id: "proposal-2",
          parameters: {
            ...proposal().parameters,
            policy_hash_sha256: "b".repeat(64),
          },
        }),
      ),
    ).rejects.toThrow("ACTION_POLICY_BLOCKED");
    expect(runner.recordedExecutions()).toHaveLength(1);
  });

  it("blocks unknown actions and attempted target or secret spoofing before gates", async () => {
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({}),
      clearKillSwitch(),
      permissiveGates(),
    );

    await expect(
      pipeline.execute(proposal({ action_id: "unknown_action" })),
    ).rejects.toThrow("ACTION_UNKNOWN");
    await expect(
      pipeline.execute({
        ...proposal(),
        target_url: "http://127.0.0.1:8123/spoofed",
      }),
    ).rejects.toThrow("ACTION_SCHEMA_INVALID");
    await expect(
      pipeline.execute({
        ...proposal(),
        required_secret_ref: "keychain://spoofed",
      }),
    ).rejects.toThrow("ACTION_SCHEMA_INVALID");
    await expect(
      pipeline.execute({
        ...proposal(),
        parameters: {
          ...proposal().parameters,
          required_secret_kind: "none",
        },
      }),
    ).rejects.toThrow("ACTION_SCHEMA_INVALID");
  });

  it("requires campaign, policy, and scope evidence before any gate", async () => {
    for (const [parameters, expected] of [
      [
        { ...proposal().parameters, campaign_ref: null },
        "ACTION_CAMPAIGN_REFERENCE_REQUIRED",
      ],
      [
        { ...proposal().parameters, policy_hash_sha256: null },
        "ACTION_POLICY_REFERENCE_REQUIRED",
      ],
      [
        { ...proposal().parameters, scope_ref: null },
        "ACTION_SCOPE_REFERENCE_REQUIRED",
      ],
    ] as const) {
      const candidate = proposal({ parameters });
      const runner = new DeterministicMockActionRunner({
        "proposal-1": { unexpected: true },
      });
      const pipeline = new ExternalActionPipeline(
        simulationRuntime(),
        runner,
        clearKillSwitch(),
        permissiveGates({}, candidate),
      );
      await expect(pipeline.execute(candidate)).rejects.toThrow(expected);
      expect(runner.recordedExecutions()).toHaveLength(0);
    }
  });

  it("blocks legal, terms, report and triage automation", async () => {
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({}),
      clearKillSwitch(),
      permissiveGates(),
    );
    for (const actionId of ["legal_accept", "terms_accept"]) {
      await expect(
        pipeline.execute(proposal({ action_id: actionId })),
      ).rejects.toThrow("ACTION_UNKNOWN");
    }
    for (const actionId of ["report_submit", "triage_response_send"]) {
      await expect(
        pipeline.execute(proposal({ action_id: actionId })),
      ).rejects.toThrow("ACTION_SIMULATION_NOT_SUPPORTED");
    }
  });

  it("requires trusted ownership evidence and a human checkpoint", async () => {
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    const ownershipPipeline = new ExternalActionPipeline(
      simulationRuntime(),
      runner,
      clearKillSwitch(),
      permissiveGates(
        {},
        proposal({
          action_id: "target_request",
          parameters: {
            ...proposal().parameters,
            account_ref: "account-1",
            object_ref: null,
          },
        }),
      ),
    );
    await expect(
      ownershipPipeline.execute(
        proposal({
          action_id: "target_request",
          parameters: {
            ...proposal().parameters,
            account_ref: "account-1",
            object_ref: null,
          },
        }),
      ),
    ).rejects.toThrow("ACTION_OWNERSHIP_REFERENCE_REQUIRED");

    const rejectedOwnership = new ExternalActionPipeline(
      simulationRuntime(),
      runner,
      clearKillSwitch(),
      permissiveGates(
        { ownership: false },
        proposal({
          action_id: "target_request",
          parameters: {
            ...proposal().parameters,
            account_ref: "account-1",
            object_ref: "object-1",
          },
        }),
      ),
    );
    await expect(
      rejectedOwnership.execute(
        proposal({
          action_id: "target_request",
          parameters: {
            ...proposal().parameters,
            account_ref: "account-1",
            object_ref: "object-1",
          },
        }),
      ),
    ).rejects.toThrow("ACTION_OWNERSHIP_BLOCKED");

    const human = new ExternalActionPipeline(
      simulationRuntime(),
      runner,
      clearKillSwitch(),
      permissiveGates(
        { humanCheckpoint: false },
        proposal({ action_id: "test_account_register" }),
      ),
    );
    await expect(
      human.execute(proposal({ action_id: "test_account_register" })),
    ).rejects.toThrow("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    expect(runner.recordedExecutions()).toHaveLength(0);
  });

  it("defaults every missing gate implementation to deny", async () => {
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({ "proposal-1": { ok: true } }),
      clearKillSwitch(),
    );
    await expect(pipeline.execute(proposal())).rejects.toThrow(
      "ACTION_POLICY_BLOCKED",
    );
  });

  it("enforces policy, scope, budget and concurrency before the runner", async () => {
    const countingRunner = new DeterministicMockActionRunner({
      "proposal-1": { ok: true },
    });
    for (const gates of [
      permissiveGates({ policy: false }),
      permissiveGates({ scope: false }),
    ]) {
      const blocked = new ExternalActionPipeline(
        simulationRuntime(),
        countingRunner,
        clearKillSwitch(),
        gates,
      );
      await expect(blocked.execute(proposal())).rejects.toThrow();
    }
    expect(countingRunner.recordedExecutions()).toHaveLength(0);

    const missingScopeProposal = proposal({
      parameters: { ...proposal().parameters, scope_ref: null },
    });
    const missingScope = new ExternalActionPipeline(
      simulationRuntime(),
      countingRunner,
      clearKillSwitch(),
      permissiveGates({}, missingScopeProposal),
    );
    await expect(missingScope.execute(missingScopeProposal)).rejects.toThrow(
      "ACTION_SCOPE_REFERENCE_REQUIRED",
    );
    expect(countingRunner.recordedExecutions()).toHaveLength(0);

    const once = new ExternalActionPipeline(
      simulationRuntime(1),
      countingRunner,
      clearKillSwitch(),
      permissiveGates(),
    );
    await once.execute(proposal());
    await expect(once.execute(proposal())).rejects.toThrow(
      "ACTION_BUDGET_EXCEEDED",
    );

    const blockingRunner = new DeterministicMockActionRunner(
      { "proposal-1": { ok: true } },
      { deferredProposalIds: ["proposal-1"] },
    );
    const concurrent = new ExternalActionPipeline(
      simulationRuntime(2),
      blockingRunner,
      clearKillSwitch(),
      permissiveGates(),
    );
    const first = concurrent.execute(proposal());
    await expect(concurrent.execute(proposal())).rejects.toThrow(
      "ACTION_CONCURRENCY_EXCEEDED",
    );
    blockingRunner.release("proposal-1");
    await first;
  });

  it("blocks on the kill switch both before and after the runner", async () => {
    const preKilledSwitch = clearKillSwitch();
    preKilledSwitch.kill();
    const preKilledRunner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    const preKilled = new ExternalActionPipeline(
      simulationRuntime(),
      preKilledRunner,
      preKilledSwitch,
      permissiveGates(),
    );
    await expect(preKilled.execute(proposal())).rejects.toThrow(
      "ACTION_KILL_SWITCH",
    );
    expect(preKilledRunner.recordedExecutions()).toHaveLength(0);

    const duringSwitch = clearKillSwitch();
    const duringRunner = new DeterministicMockActionRunner(
      { "proposal-1": { ignored: true } },
      { deferredProposalIds: ["proposal-1"] },
    );
    const killedDuringRun = new ExternalActionPipeline(
      simulationRuntime(),
      duringRunner,
      duringSwitch,
      permissiveGates(),
    );
    const pending = killedDuringRun.execute(proposal());
    duringSwitch.kill();
    await expect(pending).rejects.toThrow("ACTION_KILL_SWITCH");
  });

  it("treats missing, throwing and persistent active state readers as killed", async () => {
    const missingRunner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    const missingSwitch = new Phase2KillSwitch(undefined);
    const missing = new ExternalActionPipeline(
      simulationRuntime(),
      missingRunner,
      missingSwitch,
      permissiveGates(),
    );
    await expect(missing.execute(proposal())).rejects.toThrow(
      "ACTION_KILL_SWITCH",
    );
    expect(missingSwitch.signal.aborted).toBe(true);
    expect(missingRunner.recordedExecutions()).toHaveLength(0);

    const throwingSwitch = new Phase2KillSwitch({
      readActive: () => {
        throw new Error("PERSISTENT_STATE_UNAVAILABLE");
      },
    });
    const throwing = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({
        "proposal-1": { unexpected: true },
      }),
      throwingSwitch,
      permissiveGates(),
    );
    await expect(throwing.execute(proposal())).rejects.toThrow(
      "ACTION_KILL_SWITCH",
    );
    expect(throwingSwitch.signal.aborted).toBe(true);

    let persistentActive = false;
    const persistentSwitch = new Phase2KillSwitch({
      readActive: () => persistentActive,
    });
    const persistentRunner = new DeterministicMockActionRunner(
      { "proposal-1": { ignored: true } },
      { deferredProposalIds: ["proposal-1"] },
    );
    const persistent = new ExternalActionPipeline(
      simulationRuntime(),
      persistentRunner,
      persistentSwitch,
      permissiveGates(),
    );
    const pending = persistent.execute(proposal());
    expect(persistentRunner.recordedExecutions()).toHaveLength(1);
    persistentActive = true;
    await expect(pending).rejects.toThrow("ACTION_KILL_SWITCH");
    expect(persistentSwitch.signal.aborted).toBe(true);
  });

  it("keeps external mode disabled even when runtime capabilities say enabled", async () => {
    const runtime = resolvePhase2Runtime(
      {
        ...SAFE_PHASE2_CONFIG,
        mode: "external",
        external_integrations_enabled: true,
        allowed_platform_hosts: ["api.platform.invalid"],
      },
      { secretsAvailable: true, externalAdapterAvailable: true },
    );
    const pipeline = new ExternalActionPipeline(
      runtime,
      new DisabledExternalActionRunner(),
      clearKillSwitch(),
      permissiveGates(),
    );
    await expect(
      pipeline.execute(proposal({ mode: "external" })),
    ).rejects.toThrow("EXTERNAL_INTEGRATIONS_DISABLED");
  });
});
