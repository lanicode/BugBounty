import { describe, expect, it } from "vitest";
import {
  AccountSimulationCoordinator,
  DisabledExternalAccountAdapter,
  MockLocalAccountApplication,
  type AccountSimulationAdapter,
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
  role: "Owner",
  policy_hash_sha256: POLICY_HASH,
  expected_revision: 0,
  checkpoint_ref: null,
  ...overrides,
});

const coordinator = (
  adapter: MockLocalAccountApplication,
  options: {
    maxActions?: number;
    signal?: AbortSignal;
    now?: () => Date;
    allowedAccounts?: ReadonlyMap<string, "External" | "Member" | "Owner">;
  } = {},
) =>
  new AccountSimulationCoordinator(
    adapter,
    POLICY_HASH,
    options.allowedAccounts ?? new Map([["account-a", "Owner"] as const]),
    options.maxActions ?? 20,
    options.signal ?? new AbortController().signal,
    options.now ?? (() => new Date("2026-07-13T12:00:00Z")),
  );

describe("local account workflow simulation", () => {
  it("rejects malformed runtime budgets before accepting an adapter", () => {
    for (const value of [Number.NaN, Number.POSITIVE_INFINITY, 0, -1, 1.5]) {
      expect(
        () =>
          new AccountSimulationCoordinator(
            new MockLocalAccountApplication("local-app:fixture", {}),
            POLICY_HASH,
            new Map([["account-a", "Owner"] as const]),
            value,
            new AbortController().signal,
            () => new Date("2026-07-13T12:00:00Z"),
          ),
      ).toThrow("ACCOUNT_BUDGET_INVALID");
    }
  });

  it("rejects kind-spoofed and prototype-spoofed account adapters", () => {
    let callbackCalls = 0;
    const spoofed: AccountSimulationAdapter = {
      kind: "local_mock",
      applicationRef: "local-app:fixture",
      start: () => {
        callbackCalls += 1;
        return Promise.resolve({
          kind: "complete",
          accountLocatorRef: "unsafe",
        });
      },
      observeAndContinue: () => Promise.resolve("pending"),
      retire: () => Promise.resolve(),
    };
    expect(
      () =>
        new AccountSimulationCoordinator(
          spoofed,
          POLICY_HASH,
          new Map([["account-a", "Owner"] as const]),
          1,
          new AbortController().signal,
          () => new Date("2026-07-13T12:00:00Z"),
        ),
    ).toThrow("ACCOUNT_ADAPTER_UNTRUSTED");
    expect(
      () =>
        new AccountSimulationCoordinator(
          Object.create(
            MockLocalAccountApplication.prototype,
          ) as AccountSimulationAdapter,
          POLICY_HASH,
          new Map([["account-a", "Owner"] as const]),
          1,
          new AbortController().signal,
          () => new Date("2026-07-13T12:00:00Z"),
        ),
    ).toThrow("ACCOUNT_ADAPTER_UNTRUSTED");
    expect(callbackCalls).toBe(0);
  });

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

  it("binds resume to the stored role, policy, application and account", async () => {
    const app = new MockLocalAccountApplication("local-app:fixture", {
      "account-a": ["captcha"],
    });
    const workflow = coordinator(app, {
      allowedAccounts: new Map([
        ["account-a", "Owner"] as const,
        ["account-b", "Owner"] as const,
      ]),
    });
    const paused = await workflow.execute(proposal());
    const checkpoint = paused.workflow.checkpoint?.checkpointRef;
    if (checkpoint === undefined) throw new Error("MISSING_CHECKPOINT");
    const resume = proposal({
      proposal_id: "bound-resume",
      action: "resume",
      expected_revision: 1,
      checkpoint_ref: checkpoint,
    });
    app.satisfyCheckpoint(checkpoint);

    await expect(
      workflow.execute({ ...resume, role: "Member" }),
    ).rejects.toThrow("ACCOUNT_ROLE_SCOPE_BLOCKED");
    await expect(
      workflow.execute({ ...resume, account_ref: "account-b" }),
    ).rejects.toThrow("ACCOUNT_WORKFLOW_BINDING_MISMATCH");
    await expect(
      workflow.execute({ ...resume, application_ref: "local-app:other" }),
    ).rejects.toThrow("ACCOUNT_APPLICATION_SCOPE_BLOCKED");
    await expect(
      workflow.execute({ ...resume, policy_hash_sha256: "b".repeat(64) }),
    ).rejects.toThrow("ACCOUNT_POLICY_DRIFT");

    expect(workflow.get("workflow-1")).toMatchObject({
      role: "Owner",
      accountRef: "account-a",
      applicationRef: "local-app:fixture",
      policyHash: POLICY_HASH,
      state: "PAUSED",
      revision: 1,
    });
    await expect(workflow.execute(resume)).resolves.toMatchObject({
      workflow: {
        role: "Owner",
        accountRef: "account-a",
        applicationRef: "local-app:fixture",
        policyHash: POLICY_HASH,
        state: "ACTIVE",
        revision: 2,
      },
    });
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
        new Map([["account-a", "Owner"] as const]),
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
      workflow.execute({
        ...proposal(),
        role: "Administrator" as AccountSimulationProposal["role"],
      }),
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

  it("snapshots exact account-role scope against mutation and role escalation", async () => {
    const sourceScope = new Map<string, "External" | "Member" | "Owner">([
      ["account-a", "Member"],
    ]);
    const app = new MockLocalAccountApplication("local-app:fixture", {});
    const workflow = coordinator(app, { allowedAccounts: sourceScope });
    sourceScope.set("late-account", "Owner");
    sourceScope.set("account-a", "Owner");

    await expect(
      workflow.execute(
        proposal({ account_ref: "late-account", role: "Owner" }),
      ),
    ).rejects.toThrow("ACCOUNT_NOT_APPROVED");
    await expect(workflow.execute(proposal())).rejects.toThrow(
      "ACCOUNT_ROLE_SCOPE_BLOCKED",
    );
    await expect(
      workflow.execute(proposal({ role: "Member" })),
    ).resolves.toMatchObject({
      workflow: { accountRef: "account-a", role: "Member", state: "ACTIVE" },
    });
  });
});
