import { describe, expect, it } from "vitest";
import {
  DeterministicMockActionRunner,
  DisabledExternalActionRunner,
  ExternalActionPipeline,
  Phase2KillSwitch,
  type DeterministicActionRunner,
  type ExternalActionGateEvaluator,
  type ExternalActionProposal,
  type TrustedExternalActionExecution,
} from "../../packages/external-actions/pipeline.js";
import {
  getExternalActionDefinition,
  listExternalActionDefinitions,
} from "../../packages/external-actions/registry.js";
import {
  resolvePhase2Runtime,
  SAFE_PHASE2_CONFIG,
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
  overrides: Partial<ExternalActionGateEvaluator> = {},
): ExternalActionGateEvaluator => ({
  decidePolicy: () => true,
  decideScope: () => true,
  decideOwnership: () => true,
  decideHumanCheckpoint: () => true,
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
  it("executes the exact ordered chain with only registry-derived target and secret kind", async () => {
    let seen: TrustedExternalActionExecution | undefined;
    const runner: DeterministicActionRunner = {
      kind: "simulation_mock",
      run: (execution) => {
        seen = execution;
        return Promise.resolve({ programs: 2 });
      },
    };
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      runner,
      new Phase2KillSwitch(),
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

  it("blocks unknown actions and attempted target or secret spoofing before gates", async () => {
    let gateCalls = 0;
    const gates = permissiveGates({
      decidePolicy: () => {
        gateCalls += 1;
        return true;
      },
    });
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({}),
      new Phase2KillSwitch(),
      gates,
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
    expect(gateCalls).toBe(0);
  });

  it("blocks legal, terms, report and triage automation", async () => {
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({}),
      new Phase2KillSwitch(),
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
    let calls = 0;
    const runner: DeterministicActionRunner = {
      kind: "simulation_mock",
      run: () => {
        calls += 1;
        return Promise.resolve({ unexpected: true });
      },
    };
    const ownershipPipeline = new ExternalActionPipeline(
      simulationRuntime(),
      runner,
      new Phase2KillSwitch(),
      permissiveGates(),
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
      new Phase2KillSwitch(),
      permissiveGates({ decideOwnership: () => false }),
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
      new Phase2KillSwitch(),
      permissiveGates({ decideHumanCheckpoint: () => false }),
    );
    await expect(
      human.execute(proposal({ action_id: "test_account_register" })),
    ).rejects.toThrow("ACTION_HUMAN_CHECKPOINT_REQUIRED");
    expect(calls).toBe(0);
  });

  it("defaults every missing gate implementation to deny", async () => {
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({ "proposal-1": { ok: true } }),
      new Phase2KillSwitch(),
    );
    await expect(pipeline.execute(proposal())).rejects.toThrow(
      "ACTION_POLICY_BLOCKED",
    );
  });

  it("enforces policy, scope, budget and concurrency before the runner", async () => {
    let calls = 0;
    const countingRunner: DeterministicActionRunner = {
      kind: "simulation_mock",
      run: () => {
        calls += 1;
        return Promise.resolve({ ok: true });
      },
    };
    for (const gates of [
      permissiveGates({ decidePolicy: () => false }),
      permissiveGates({ decideScope: () => false }),
    ]) {
      const blocked = new ExternalActionPipeline(
        simulationRuntime(),
        countingRunner,
        new Phase2KillSwitch(),
        gates,
      );
      await expect(blocked.execute(proposal())).rejects.toThrow();
    }
    expect(calls).toBe(0);

    const missingScope = new ExternalActionPipeline(
      simulationRuntime(),
      countingRunner,
      new Phase2KillSwitch(),
      permissiveGates(),
    );
    await expect(
      missingScope.execute(
        proposal({
          parameters: { ...proposal().parameters, scope_ref: null },
        }),
      ),
    ).rejects.toThrow("ACTION_SCOPE_REFERENCE_REQUIRED");
    expect(calls).toBe(0);

    const once = new ExternalActionPipeline(
      simulationRuntime(1),
      countingRunner,
      new Phase2KillSwitch(),
      permissiveGates(),
    );
    await once.execute(proposal());
    await expect(once.execute(proposal())).rejects.toThrow(
      "ACTION_BUDGET_EXCEEDED",
    );

    let release: (() => void) | undefined;
    const blockingRunner: DeterministicActionRunner = {
      kind: "simulation_mock",
      run: () =>
        new Promise((resolve) => {
          release = () => {
            resolve({ ok: true });
          };
        }),
    };
    const concurrent = new ExternalActionPipeline(
      simulationRuntime(2),
      blockingRunner,
      new Phase2KillSwitch(),
      permissiveGates(),
    );
    const first = concurrent.execute(proposal());
    await expect(concurrent.execute(proposal())).rejects.toThrow(
      "ACTION_CONCURRENCY_EXCEEDED",
    );
    release?.();
    await first;
  });

  it("blocks on the kill switch both before and after the runner", async () => {
    const preKilledSwitch = new Phase2KillSwitch();
    preKilledSwitch.kill();
    let calls = 0;
    const preKilled = new ExternalActionPipeline(
      simulationRuntime(),
      {
        kind: "simulation_mock",
        run: () => {
          calls += 1;
          return Promise.resolve({ unexpected: true });
        },
      },
      preKilledSwitch,
      permissiveGates(),
    );
    await expect(preKilled.execute(proposal())).rejects.toThrow(
      "ACTION_KILL_SWITCH",
    );
    expect(calls).toBe(0);

    const duringSwitch = new Phase2KillSwitch();
    const killedDuringRun = new ExternalActionPipeline(
      simulationRuntime(),
      {
        kind: "simulation_mock",
        run: () => {
          duringSwitch.kill();
          return Promise.resolve({ ignored: true });
        },
      },
      duringSwitch,
      permissiveGates(),
    );
    await expect(killedDuringRun.execute(proposal())).rejects.toThrow(
      "ACTION_KILL_SWITCH",
    );
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
      new Phase2KillSwitch(),
      permissiveGates(),
    );
    await expect(
      pipeline.execute(proposal({ mode: "external" })),
    ).rejects.toThrow("EXTERNAL_INTEGRATIONS_DISABLED");
  });
});
