import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ControlPlaneDatabase } from "../../packages/control-plane/index.js";
import {
  DeterministicMockActionRunner,
  DisabledExternalActionRunner,
  ExternalActionPipeline,
  Phase2KillSwitch,
  StoreBoundExternalActionEvaluator,
  type DeterministicActionRunner,
  type ExternalActionAuthorizationEvaluator,
  type ExternalActionProposal,
} from "../../packages/external-actions/pipeline.js";
import {
  assertHackerOneActiveTestRegistryPlanBinding,
  assertTrustedExternalActionDefinition,
  getExternalActionDefinition,
  hackerOneActiveTestRegistryDefinitionDigest,
  listExternalActionDefinitions,
  trustedExternalActionDefinitionDigest,
} from "../../packages/external-actions/registry.js";
import {
  resolvePhase2Runtime,
  SAFE_PHASE2_CONFIG,
  type Phase2RuntimeState,
} from "../../packages/phase2-config/runtime.js";
import {
  ACTION_EXECUTION_TIME,
  ACTION_TIME,
  seedStoreBoundAction,
  type SeededStoreBoundAction,
} from "../fixtures/store-bound-action.factory.js";

const simulationRuntime = (maxActions = 20) =>
  resolvePhase2Runtime(
    {
      ...SAFE_PHASE2_CONFIG,
      budgets: { max_actions_total: maxActions, max_concurrency: 1 },
    },
    { secretsAvailable: false, externalAdapterAvailable: false },
  );

function storePipeline(
  seeded: SeededStoreBoundAction,
  runner: DeterministicActionRunner,
  killSwitch = new Phase2KillSwitch({
    readActive: () => seeded.store.isKillSwitchActive(),
  }),
): ExternalActionPipeline {
  return new ExternalActionPipeline(
    simulationRuntime(),
    runner,
    killSwitch,
    new StoreBoundExternalActionEvaluator(seeded.store),
  );
}

function changeProposal(
  proposal: ExternalActionProposal,
  overrides: Partial<ExternalActionProposal>,
): ExternalActionProposal {
  return { ...proposal, ...overrides };
}

describe("trusted external action registry", () => {
  it("contains every known action as a deeply immutable blocked definition", () => {
    const definitions = listExternalActionDefinitions();
    expect(definitions.map(({ actionId }) => actionId)).toEqual([
      "hackerone_active_test",
      "hackerone_metadata_read",
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
      if (
        definition.fixedTargetPolicy.kind ===
        "hackerone_active_test_exact_scope"
      ) {
        expect(Object.isFrozen(definition.fixedTargetPolicy.testClasses)).toBe(
          true,
        );
        for (const testClass of definition.fixedTargetPolicy.testClasses)
          expect(Object.isFrozen(testClass)).toBe(true);
      }
    }
  });

  it("pins Pilot-C to its dedicated exact-scope HTTPS action definition", () => {
    const definition = getExternalActionDefinition("hackerone_active_test");
    expect(definition).toEqual({
      actionId: "hackerone_active_test",
      category: "target",
      triggerComponent: "pilot_c_active_testing_gate",
      targetClass: "program_target",
      fixedTargetPolicy: {
        kind: "hackerone_active_test_exact_scope",
        scheme: "https",
        port: 443,
        snapshotRequirement: "current_hackerone_api_authenticated",
        scopeRequirement: "exact_selected_structured_scope",
        ownershipRequirement: "selected_scope_asset_digest",
        testClasses: [
          { id: "http_headers", method: "HEAD" },
          { id: "cors_preflight", method: "OPTIONS" },
          { id: "security_txt", method: "GET" },
        ],
      },
      requiredSecretKind: "operator_signing_key",
      policyDecision: "required",
      scopeCheck: "required",
      ownershipCheck: "object",
      budget: { kind: "action_units", units: 1 },
      humanCheckpoint: "signed_active_test_plan",
      simulationSupported: false,
      defaultState: "blocked",
      killSwitchBehavior: "block_before_and_after_runner",
    });
    expect(hackerOneActiveTestRegistryDefinitionDigest()).toBe(
      trustedExternalActionDefinitionDigest("hackerone_active_test"),
    );
    expect(hackerOneActiveTestRegistryDefinitionDigest()).toMatch(
      /^[a-f0-9]{64}$/u,
    );
  });

  it("rejects absent and structurally identical untrusted registry definitions", () => {
    const definition = getExternalActionDefinition("hackerone_active_test");
    expect(() => {
      assertTrustedExternalActionDefinition(undefined, "hackerone_active_test");
    }).toThrow("ACTION_REGISTRY_DEFINITION_UNTRUSTED");
    expect(() => {
      assertTrustedExternalActionDefinition(
        Object.freeze({ ...definition }),
        "hackerone_active_test",
      );
    }).toThrow("ACTION_REGISTRY_DEFINITION_UNTRUSTED");
  });

  it("rejects method, class, scheme and port drift from the active-test registry", () => {
    expect(
      assertHackerOneActiveTestRegistryPlanBinding(
        "http_headers",
        "HEAD",
        "https",
        443,
      ),
    ).toBe(hackerOneActiveTestRegistryDefinitionDigest());
    for (const binding of [
      { testClass: "http_headers", method: "GET", scheme: "https", port: 443 },
      { testClass: "unknown", method: "HEAD", scheme: "https", port: 443 },
      { testClass: "http_headers", method: "HEAD", scheme: "http", port: 443 },
      {
        testClass: "http_headers",
        method: "HEAD",
        scheme: "https",
        port: 8443,
      },
    ]) {
      expect(() => {
        assertHackerOneActiveTestRegistryPlanBinding(
          binding.testClass,
          binding.method,
          binding.scheme,
          binding.port,
        );
      }).toThrow("ACTIVE_TEST_ACTION_REGISTRY_PLAN_MISMATCH");
    }
  });

  it("pins HackerOne metadata reads to the only permitted read-only origin", () => {
    expect(getExternalActionDefinition("hackerone_metadata_read")).toEqual({
      actionId: "hackerone_metadata_read",
      category: "platform",
      triggerComponent: "hackerone_readonly_adapter",
      requiredSecretKind: "hackerone_api_credentials",
      targetClass: "hackerone_metadata",
      fixedTargetPolicy: {
        kind: "hackerone_metadata_readonly",
        scheme: "https",
        host: "api.hackerone.com",
        port: 443,
        method: "GET",
      },
      policyDecision: "required",
      scopeCheck: "required",
      ownershipCheck: "not_applicable",
      budget: { kind: "action_units", units: 1 },
      humanCheckpoint: "hackerone_metadata_activation",
      simulationSupported: false,
      defaultState: "blocked",
      killSwitchBehavior: "block_before_and_after_runner",
    });
  });

  it("keeps report and triage human-only with no simulation target", () => {
    for (const actionId of ["report_submit", "triage_response_send"])
      expect(getExternalActionDefinition(actionId)).toMatchObject({
        actionId,
        fixedTargetPolicy: { kind: "external_disabled", host: null },
        simulationSupported: false,
      });
  });
});

describe("Phase 3 external action pipeline regressions", () => {
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

  function seed(
    actionId: Parameters<typeof seedStoreBoundAction>[1] = "platform_api_read",
  ): SeededStoreBoundAction {
    return seedStoreBoundAction(database, actionId);
  }

  it("executes the exact ordered chain from persisted evidence and a registry-derived target", async () => {
    const seeded = seed();
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { programs: 2 },
    });

    await expect(
      storePipeline(seeded, runner).execute(seeded.proposal),
    ).resolves.toEqual({
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
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "succeeded", revision: 2 },
    ]);
  });

  it("rejects malformed runtime budgets before constructing a pipeline", () => {
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
            new Phase2KillSwitch({ readActive: () => false }),
          ),
      ).toThrow("ACTION_RUNTIME_INVALID");
    }
  });

  it("rejects kind-, prototype- and callback-spoofed runners without invocation", () => {
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
          new Phase2KillSwitch({ readActive: () => false }),
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
          new Phase2KillSwitch({ readActive: () => false }),
        ),
    ).toThrow("ACTION_RUNNER_UNTRUSTED");
    expect(callbackCalls).toBe(0);
  });

  it("rejects caller callbacks, proxies and prototype-spoofed authorizers", () => {
    let calls = 0;
    const callback: ExternalActionAuthorizationEvaluator = {
      authorizeAndReserve: () => {
        calls += 1;
        throw new Error("unsafe callback invoked");
      },
      start: () => {
        calls += 1;
      },
      abortReservation: () => {
        calls += 1;
      },
      settle: () => {
        calls += 1;
      },
    };
    const runner = new DeterministicMockActionRunner({});
    for (const authorizer of [
      callback,
      Object.create(
        StoreBoundExternalActionEvaluator.prototype,
      ) as ExternalActionAuthorizationEvaluator,
    ])
      expect(
        () =>
          new ExternalActionPipeline(
            simulationRuntime(),
            runner,
            new Phase2KillSwitch({ readActive: () => false }),
            authorizer,
          ),
      ).toThrow("ACTION_AUTHORIZER_UNTRUSTED");

    const seeded = seed();
    const trusted = new StoreBoundExternalActionEvaluator(seeded.store);
    expect(
      () =>
        new ExternalActionPipeline(
          simulationRuntime(),
          runner,
          new Phase2KillSwitch({ readActive: () => false }),
          new Proxy(trusted, {}),
        ),
    ).toThrow("ACTION_AUTHORIZER_UNTRUSTED");
    expect(calls).toBe(0);
  });

  it("denies by default even when a fully approved proposal exists", async () => {
    const seeded = seed();
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    const blocked = new ExternalActionPipeline(
      simulationRuntime(),
      runner,
      new Phase2KillSwitch({ readActive: () => false }),
    );

    await expect(blocked.execute(seeded.proposal)).rejects.toThrow(
      "ACTION_STORE_EVIDENCE_REQUIRED",
    );
    expect(runner.recordedExecutions()).toHaveLength(0);
  });

  it("blocks unknown, legal, report and triage actions before authorization", async () => {
    const seeded = seed();
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    const pipeline = storePipeline(seeded, runner);

    for (const actionId of ["unknown_action", "legal_accept", "terms_accept"])
      await expect(
        pipeline.execute(
          changeProposal(seeded.proposal, { action_id: actionId }),
        ),
      ).rejects.toThrow("ACTION_UNKNOWN");
    for (const actionId of ["report_submit", "triage_response_send"])
      await expect(
        pipeline.execute(
          changeProposal(seeded.proposal, { action_id: actionId }),
        ),
      ).rejects.toThrow("ACTION_SIMULATION_NOT_SUPPORTED");
    expect(runner.recordedExecutions()).toHaveLength(0);
    expect(seeded.store.listExternalActionAttempts()).toHaveLength(0);
  });

  it("rejects v1, missing evidence and attempted target or secret injection at schema validation", async () => {
    const seeded = seed();
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    const pipeline = storePipeline(seeded, runner);
    const parametersWithoutOperator: Record<string, unknown> = {
      ...seeded.proposal.parameters,
    };
    delete parametersWithoutOperator["operator_ref"];
    const invalid: readonly unknown[] = [
      { ...seeded.proposal, version: 1 },
      { ...seeded.proposal, target_url: "http://127.0.0.1:8123/spoofed" },
      { ...seeded.proposal, required_secret_ref: "keychain://spoofed" },
      { ...seeded.proposal, parameters: parametersWithoutOperator },
      {
        ...seeded.proposal,
        parameters: {
          ...seeded.proposal.parameters,
          required_secret_kind: "none",
        },
      },
      {
        ...seeded.proposal,
        parameters: {
          ...seeded.proposal.parameters,
          campaign_ref: null,
        },
      },
    ];

    for (const candidate of invalid)
      await expect(pipeline.execute(candidate)).rejects.toThrow(
        "ACTION_SCHEMA_INVALID",
      );
    expect(runner.recordedExecutions()).toHaveLength(0);
    expect(seeded.store.listExternalActionAttempts()).toHaveLength(0);
  });

  it("requires exact ownership shapes and blocks payload references", async () => {
    const target = seed("target_request");
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const targetRunner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    await expect(
      storePipeline(target, targetRunner).execute({
        ...target.proposal,
        parameters: { ...target.proposal.parameters, object_ref: null },
      }),
    ).rejects.toThrow("ACTION_OWNERSHIP_REFERENCE_REQUIRED");
    await expect(
      storePipeline(target, targetRunner).execute({
        ...target.proposal,
        parameters: {
          ...target.proposal.parameters,
          account_role: null,
        },
      }),
    ).rejects.toThrow("ACTION_OWNERSHIP_REFERENCE_REQUIRED");
    await expect(
      storePipeline(target, targetRunner).execute({
        ...target.proposal,
        parameters: {
          ...target.proposal.parameters,
          payload_ref: "payload-forged",
        },
      }),
    ).rejects.toThrow("ACTION_PAYLOAD_REFERENCE_BLOCKED");
    expect(targetRunner.recordedExecutions()).toHaveLength(0);
    expect(target.store.listExternalActionAttempts()).toHaveLength(0);
  });

  it("keeps external mode and disabled runners fail-closed", async () => {
    const seeded = seed();
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const externalRuntime = resolvePhase2Runtime(
      {
        ...SAFE_PHASE2_CONFIG,
        mode: "external",
        external_integrations_enabled: true,
        allowed_platform_hosts: ["api.platform.invalid"],
      },
      { secretsAvailable: true, externalAdapterAvailable: true },
    );
    const disabled = new ExternalActionPipeline(
      externalRuntime,
      new DisabledExternalActionRunner(),
      new Phase2KillSwitch({
        readActive: () => seeded.store.isKillSwitchActive(),
      }),
      new StoreBoundExternalActionEvaluator(seeded.store),
    );

    await expect(
      disabled.execute(changeProposal(seeded.proposal, { mode: "external" })),
    ).rejects.toThrow("EXTERNAL_INTEGRATIONS_DISABLED");
    await expect(disabled.execute(seeded.proposal)).rejects.toThrow(
      "ACTION_RUNNER_MODE_INVALID",
    );
    expect(seeded.store.listExternalActionAttempts()).toHaveLength(0);
  });

  it("blocks before execution and aborts a deferred runner when killed", async () => {
    const seeded = seed();
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const preKilled = new Phase2KillSwitch({ readActive: () => false });
    preKilled.kill();
    const preKilledRunner = new DeterministicMockActionRunner({
      "proposal-1": { unexpected: true },
    });
    await expect(
      storePipeline(seeded, preKilledRunner, preKilled).execute(
        seeded.proposal,
      ),
    ).rejects.toThrow("ACTION_KILL_SWITCH");
    expect(preKilledRunner.recordedExecutions()).toHaveLength(0);

    const during = new Phase2KillSwitch({ readActive: () => false });
    const deferred = new DeterministicMockActionRunner(
      { "proposal-1": { ignored: true } },
      { deferredProposalIds: ["proposal-1"] },
    );
    const pending = storePipeline(seeded, deferred, during).execute(
      seeded.proposal,
    );
    expect(deferred.recordedExecutions()).toHaveLength(1);
    const killed = expect(pending).rejects.toThrow("ACTION_KILL_SWITCH");
    during.kill();
    await killed;
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "aborted", revision: 2 },
    ]);
  });

  it("treats missing, throwing and newly active persistent readers as killed", async () => {
    const seeded = seed();
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    for (const killSwitch of [
      new Phase2KillSwitch(undefined),
      new Phase2KillSwitch({
        readActive: () => {
          throw new Error("PERSISTENT_STATE_UNAVAILABLE");
        },
      }),
    ]) {
      const runner = new DeterministicMockActionRunner({
        "proposal-1": { unexpected: true },
      });
      await expect(
        storePipeline(seeded, runner, killSwitch).execute(seeded.proposal),
      ).rejects.toThrow("ACTION_KILL_SWITCH");
      expect(killSwitch.signal.aborted).toBe(true);
      expect(runner.recordedExecutions()).toHaveLength(0);
    }

    let active = false;
    const persistent = new Phase2KillSwitch({ readActive: () => active });
    const deferred = new DeterministicMockActionRunner(
      { "proposal-1": { ignored: true } },
      { deferredProposalIds: ["proposal-1"] },
    );
    const pending = storePipeline(seeded, deferred, persistent).execute(
      seeded.proposal,
    );
    expect(deferred.recordedExecutions()).toHaveLength(1);
    const killed = expect(pending).rejects.toThrow("ACTION_KILL_SWITCH");
    active = true;
    await vi.advanceTimersByTimeAsync(10);
    await killed;
    expect(persistent.signal.aborted).toBe(true);
  });

  it("clones configured mock responses and rejects unsafe response graphs", async () => {
    const seeded = seed();
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const configured = { nested: { value: 1 }, list: ["safe"] };
    const runner = new DeterministicMockActionRunner({
      "proposal-1": configured,
    });
    configured.nested.value = 99;
    configured.list[0] = "mutated";

    const result = await storePipeline(seeded, runner).execute(seeded.proposal);
    expect(result.result).toEqual({ nested: { value: 1 }, list: ["safe"] });
    const returned = result.result as {
      list: string[];
      nested: { value: number };
    };
    returned.nested.value = 77;
    returned.list[0] = "changed-result";
    const [execution] = runner.recordedExecutions();
    if (execution === undefined) throw new Error("MISSING_RECORDED_EXECUTION");
    await expect(
      runner.run(execution, new AbortController().signal),
    ).resolves.toEqual({ nested: { value: 1 }, list: ["safe"] });

    let getterCalls = 0;
    const accessor = Object.defineProperty({}, "unsafe", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "secret";
      },
    });
    const cyclic: Record<string, unknown> = {};
    cyclic["self"] = cyclic;
    for (const unsafe of [accessor, cyclic, Number.NaN])
      expect(
        () =>
          new DeterministicMockActionRunner({
            "proposal-unsafe": unsafe,
          }),
      ).toThrow("MOCK_RESPONSE_INVALID");
    expect(getterCalls).toBe(0);
    expect(
      () =>
        new DeterministicMockActionRunner(
          { "proposal-1": { ok: true } },
          { deferredProposalIds: ["unknown"] },
        ),
    ).toThrow("MOCK_DEFERRED_IDS_INVALID");
  });

  it("settles a configured runner failure without returning budget", async () => {
    const seeded = seed();
    vi.setSystemTime(ACTION_EXECUTION_TIME);
    const runner = new DeterministicMockActionRunner({});

    await expect(
      storePipeline(seeded, runner).execute(seeded.proposal),
    ).rejects.toThrow("MOCK_ACTION_NOT_CONFIGURED");
    expect(seeded.store.listExternalActionAttempts()).toMatchObject([
      { proposalId: "proposal-1", status: "failed", units: 1, revision: 2 },
    ]);
  });
});
