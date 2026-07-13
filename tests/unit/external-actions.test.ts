import { describe, expect, it } from "vitest";
import {
  DeterministicMockActionRunner,
  DisabledExternalActionRunner,
  ExternalActionPipeline,
  Phase2KillSwitch,
  type DeterministicActionRunner,
} from "../../packages/external-actions/pipeline.js";
import {
  resolvePhase2Runtime,
  SAFE_PHASE2_CONFIG,
} from "../../packages/phase2-config/runtime.js";

const proposal = () => ({
  version: 1 as const,
  proposal_id: "proposal-1",
  action: "program_read" as const,
  mode: "simulation" as const,
  platform: "local_mock" as const,
  target_url: "http://127.0.0.1:8123/programs",
  method: "GET" as const,
  required_secret_ref: null,
  human_checkpoint: "not_required" as const,
});

const simulationRuntime = (maxActions = 20) =>
  resolvePhase2Runtime(
    {
      ...SAFE_PHASE2_CONFIG,
      budgets: { max_actions_total: maxActions, max_concurrency: 1 },
    },
    { secretsAvailable: false, externalAdapterAvailable: false },
  );

describe("external action safety chain", () => {
  it("executes the complete ordered chain only through a deterministic mock", async () => {
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({ "proposal-1": { programs: 2 } }),
      new Phase2KillSwitch(),
    );
    await expect(pipeline.execute(proposal())).resolves.toEqual({
      proposalId: "proposal-1",
      result: { programs: 2 },
      trace: ["schema", "policy", "scope", "budget", "runner"],
    });
  });

  it("blocks malformed values, external mode and non-loopback simulation", async () => {
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({}),
      new Phase2KillSwitch(),
    );
    await expect(
      pipeline.execute({ ...proposal(), unknown: true }),
    ).rejects.toThrow("ACTION_SCHEMA_INVALID");
    await expect(
      pipeline.execute({
        ...proposal(),
        mode: "external",
        platform: "hackerone",
        target_url: "https://api.platform.invalid/programs",
        required_secret_ref: "keychain://platform/read-only",
      }),
    ).rejects.toThrow("EXTERNAL_INTEGRATIONS_DISABLED");
    await expect(
      pipeline.execute({
        ...proposal(),
        target_url: "http://non-loopback.invalid/programs",
      }),
    ).rejects.toThrow("ACTION_SIMULATION_LOOPBACK_REQUIRED");
  });

  it("never automates rules, terms or report decisions", async () => {
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({}),
      new Phase2KillSwitch(),
    );
    for (const action of [
      "program_rules_accept",
      "terms_accept",
      "report_submit",
    ] as const) {
      await expect(pipeline.execute({ ...proposal(), action })).rejects.toThrow(
        "ACTION_HUMAN_DECISION_REQUIRED",
      );
    }
  });

  it("enforces budget, concurrency and kill switch before the runner", async () => {
    const once = new ExternalActionPipeline(
      simulationRuntime(1),
      new DeterministicMockActionRunner({ "proposal-1": { ok: true } }),
      new Phase2KillSwitch(),
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
    );
    const first = concurrent.execute(proposal());
    await expect(concurrent.execute(proposal())).rejects.toThrow(
      "ACTION_CONCURRENCY_EXCEEDED",
    );
    release?.();
    await first;

    const kill = new Phase2KillSwitch();
    kill.kill();
    const killed = new ExternalActionPipeline(
      simulationRuntime(),
      new DeterministicMockActionRunner({ "proposal-1": { ok: true } }),
      kill,
    );
    await expect(killed.execute(proposal())).rejects.toThrow(
      "ACTION_KILL_SWITCH",
    );
  });

  it("never invokes the runner after a failed validation, policy or scope gate", async () => {
    let calls = 0;
    const runner: DeterministicActionRunner = {
      kind: "simulation_mock",
      run: () => {
        calls += 1;
        return Promise.resolve({ unexpected: true });
      },
    };
    const pipeline = new ExternalActionPipeline(
      simulationRuntime(),
      runner,
      new Phase2KillSwitch(),
    );
    for (const invalid of [
      { ...proposal(), unknown: true },
      { ...proposal(), action: "report_submit" },
      { ...proposal(), target_url: "https://outside.invalid/programs" },
    ])
      await expect(pipeline.execute(invalid)).rejects.toThrow();
    expect(calls).toBe(0);
  });

  it("keeps the real adapter fail-closed even when all gate inputs are explicit", async () => {
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
    );
    await expect(
      pipeline.execute({
        ...proposal(),
        mode: "external",
        platform: "hackerone",
        target_url: "https://api.platform.invalid/programs",
        required_secret_ref: "keychain://platform/read-only",
      }),
    ).rejects.toThrow("EXTERNAL_ADAPTER_NOT_IMPLEMENTED");
  });
});
