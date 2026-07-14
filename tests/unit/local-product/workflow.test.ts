import { describe, expect, it } from "vitest";
import {
  LocalProductWorkflow,
  type LocalProductActionInput,
  type LocalProductDemoBinding,
  type LocalProductRuntimeContext,
  type LocalProductSnapshot,
} from "../../../packages/local-product/index.js";
import {
  LOCAL_JOURNEY_CATALOG_DIGEST_SHA256,
  LOCAL_JOURNEY_CATALOG_ID,
  LOCAL_JOURNEY_ROLE_PLANS,
} from "../../../packages/local-journey-catalog/index.js";
import { canonicalJson, sha256 } from "../../../packages/shared/canonical.js";

const TIME = "2026-07-14T12:00:00.000Z";
const DEMO_DIGEST = "a".repeat(64);

const READY_RUNTIME = Object.freeze({
  systemStatus: "ready",
  secretStoreStatus: "ready",
  demoSaasStatus: "ready",
  databaseStatus: "ready",
  demoSnapshotDigest: DEMO_DIGEST,
} satisfies LocalProductRuntimeContext);

const SETUP_RUNTIME = Object.freeze({
  ...READY_RUNTIME,
  secretStoreStatus: "setup_required",
} satisfies LocalProductRuntimeContext);

const DEMO_BINDING = Object.freeze({
  snapshotDigest: DEMO_DIGEST,
  organizationRef: "org-demo-001",
  identities: Object.freeze([
    Object.freeze({ role: "Owner", identityRef: "identity-owner-001" }),
    Object.freeze({ role: "Member", identityRef: "identity-member-001" }),
    Object.freeze({
      role: "External",
      identityRef: "identity-external-001",
    }),
  ]),
  controlledObjectRef: "object-demo-001",
  controlledByRef: "identity-owner-001",
  canaryDigest: "b".repeat(64),
  demoPolicyHash: "c".repeat(64),
} satisfies LocalProductDemoBinding);

const FLOW = Object.freeze([
  { action: "onboarding_system_check" },
  { action: "onboarding_secret_store_check" },
  { action: "onboarding_select_simulation" },
  {
    action: "onboarding_configure_testmail",
    schema: "plus_addressing_fixture",
  },
  { action: "onboarding_disable_ai", provider: "disabled" },
  { action: "onboarding_confirm_boundaries", confirmed: true },
  { action: "onboarding_initialize_demo" },
  {
    action: "create_program",
    displayName: "Local Demo Program",
    allowedAssetRefs: ["asset-local-primary"],
    excludedAssetRefs: ["asset-local-administration"],
  },
  { action: "import_policy", representation: "structured_fixture" },
  { action: "accept_policy", confirmed: true },
  {
    action: "create_campaign",
    policyVersion: 1,
    roles: ["Owner", "Member", "External"],
    riskTiers: ["tier_0_offline"],
    maxRequests: 8,
    requestsPerMinute: 2,
    maxConcurrency: 1,
  },
  { action: "approve_campaign", confirmed: true },
  { action: "prepare_identities" },
  {
    action: "start_journey",
    confirmed: true,
    journeyId: LOCAL_JOURNEY_CATALOG_ID,
    roles: ["Owner", "Member", "External"],
  },
  { action: "inspect_inventory" },
  { action: "generate_candidates" },
  { action: "verify_candidate", confirmed: true },
  { action: "open_evidence" },
  { action: "create_report" },
  { action: "queue_report_review", confirmed: true },
  { action: "approve_local_report", confirmed: true },
] satisfies readonly LocalProductActionInput[]);

const CONFIRMED_ACTIONS = Object.freeze([
  "onboarding_confirm_boundaries",
  "accept_policy",
  "approve_campaign",
  "start_journey",
  "verify_candidate",
  "queue_report_review",
  "approve_local_report",
] as const);

function workflow(): LocalProductWorkflow {
  return new LocalProductWorkflow(
    () => new Date(TIME),
    SETUP_RUNTIME,
    DEMO_BINDING,
  );
}

function runUntil(
  instance: LocalProductWorkflow,
  action: LocalProductActionInput["action"],
): void {
  const index = FLOW.findIndex((item) => item.action === action);
  if (index < 0) throw new Error("TEST_ACTION_NOT_FOUND");
  for (const item of FLOW.slice(0, index)) instance.perform(item);
}

function inputFor(
  action: LocalProductActionInput["action"],
): LocalProductActionInput {
  const input = FLOW.find((item) => item.action === action);
  if (input === undefined) throw new Error("TEST_ACTION_NOT_FOUND");
  return input;
}

function complete(instance = workflow()): LocalProductSnapshot {
  let snapshot = instance.snapshot();
  for (const action of FLOW) snapshot = instance.perform(action);
  return snapshot;
}

function expectDeepFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  for (const nested of Object.values(value)) expectDeepFrozen(nested, seen);
}

describe("local product workflow", () => {
  it("executes the fixed guided flow in exact order and projects only local artifacts", () => {
    const instance = workflow();
    expect(() => instance.perform(inputFor("create_program"))).toThrow(
      "LOCAL_PRODUCT_ACTION_OUT_OF_ORDER",
    );
    expect(instance.snapshot().revision).toBe(0);

    const snapshot = complete(instance);

    expect(snapshot.workflowStatus).toBe("completed_local_only");
    expect(snapshot.stage).toBe("complete");
    expect(snapshot.progress).toEqual({ completedSteps: 21, totalSteps: 21 });
    expect(snapshot.nextAction).toBeNull();
    expect(snapshot.availableManagementActions).toEqual([]);
    expect(snapshot.badges).toEqual({
      mode: "simulation",
      external: false,
      ai: "disabled_not_implemented",
      realSubmission: false,
    });
    expect(snapshot.runtimeContext).toEqual({
      systemStatus: "ready",
      secretStoreStatus: "setup_required",
      demoSaasStatus: "ready",
      databaseStatus: "ready",
      demoSnapshotDigest: DEMO_DIGEST,
    });
    expect(snapshot.onboarding.status).toBe("complete");
    expect(snapshot.onboarding.systemCheck).toBe("ready");
    expect(snapshot.onboarding.databaseCheck).toBe("ready");
    expect(snapshot.onboarding.credentialStorageCheck).toBe("setup_required");
    expect(snapshot.onboarding.testMailbox).toBe("plus_addressing_fixture");
    expect(snapshot.onboarding.aiProvider).toBe("disabled");
    expect(snapshot.onboarding.demo).toEqual({
      status: "ready",
      revision: 1,
      snapshotDigest: DEMO_DIGEST,
    });
    expect(snapshot.program?.lifecycle).toBe("active");
    expect(snapshot.program?.excludedAssetRefs).toEqual([
      "asset-local-administration",
    ]);
    expect(snapshot.policy?.status).toBe("accepted_local");
    expect(snapshot.policy?.importRepresentation).toBe("structured_fixture");
    expect(snapshot.policy?.diff.changed).toBe(true);
    expect(snapshot.campaign?.status).toBe("completed_local_only");
    expect(snapshot.campaign?.contract.selectedRoles).toEqual([
      "Owner",
      "Member",
      "External",
    ]);
    expect(snapshot.identities.map(({ role }) => role)).toEqual([
      "Owner",
      "Member",
      "External",
    ]);
    expect(snapshot.journey).toMatchObject({
      id: LOCAL_JOURNEY_CATALOG_ID,
      catalogDigestSha256: LOCAL_JOURNEY_CATALOG_DIGEST_SHA256,
      status: "completed_local_simulation",
      execution: "simulated_metadata_only",
      testHarnessValidated: true,
      browserStarted: false,
      networkRequests: 0,
    });
    expect(snapshot.journey?.roles).toEqual(["Owner", "Member", "External"]);
    expect(snapshot.journey?.liveSteps).toHaveLength(
      LOCAL_JOURNEY_ROLE_PLANS.Owner.length +
        LOCAL_JOURNEY_ROLE_PLANS.Member.length +
        LOCAL_JOURNEY_ROLE_PLANS.External.length,
    );
    expect(snapshot.journey?.liveSteps[0]).toMatchObject({
      sequence: 1,
      catalogIndex: 0,
      role: "Owner",
      method: "GET",
      path: LOCAL_JOURNEY_ROLE_PLANS.Owner[0]?.path,
      execution: "catalog_projection_only",
    });
    expect(snapshot.inventory?.applicationInventory).toHaveLength(1);
    expect(snapshot.inventory?.endpointInventory).toHaveLength(2);
    expect(snapshot.inventory?.roleMatrix).toHaveLength(3);
    expect(
      snapshot.inventory?.ownershipGraph.allObjectsResearcherControlled,
    ).toBe(true);
    expect(snapshot.inventory?.canary.valueExposed).toBe(false);
    expect(snapshot.inventory?.policyAssignment.status).toBe("assigned_exact");
    expect(snapshot.inventory?.campaignAssignment.status).toBe(
      "assigned_exact",
    );
    expect(snapshot.candidates).toHaveLength(1);
    expect(snapshot.candidates[0]).toMatchObject({
      hypothesis: "Role projections differ in the deterministic fixture",
      vulnerabilityClass: "authorization_boundary_metadata",
      roles: ["Owner", "Member", "External"],
      ownedObjectRefs: ["object-demo-001"],
      status: "verified_local_fixture",
      activeTestPerformed: false,
      mutation: "none_read_only",
      riskTier: "tier_0_offline",
      requestBudget: { maximum: 8, consumed: 0 },
      priority: "low",
      falsePositiveReasons: [
        "deterministic_fixture_expected_variance",
        "no_external_effect",
      ],
      privacyStatus: "redacted_metadata_only",
      verificationResult: "deterministic_fixture_difference_confirmed",
    });
    expect(snapshot.evidence?.items.map(({ kind }) => kind)).toEqual([
      "baseline",
      "test",
      "control",
    ]);
    expect(
      snapshot.evidence?.items.map(
        ({ rawPayloadStored, visualBytesStored }) => ({
          rawPayloadStored,
          visualBytesStored,
        }),
      ),
    ).toEqual([
      { rawPayloadStored: false, visualBytesStored: false },
      { rawPayloadStored: false, visualBytesStored: false },
      { rawPayloadStored: false, visualBytesStored: false },
    ]);
    expect(snapshot.evidence?.ownershipProof).toMatchObject({
      objectRef: "object-demo-001",
      controllerIdentityRef: "identity-owner-001",
      researcherControlled: true,
    });
    expect(snapshot.evidence?.ownershipProof.digest).toMatch(/^[a-f0-9]{64}$/u);
    expect(snapshot.evidence?.canaryProof).toEqual({
      digest: snapshot.inventory?.canary.digest,
      valueExposed: false,
    });
    expect(snapshot.evidence?.policyHash).toBe(snapshot.policy?.policyHash);
    expect(snapshot.evidence).toMatchObject({
      demoSnapshotDigest: DEMO_DIGEST,
      journeyId: LOCAL_JOURNEY_CATALOG_ID,
      journeyCatalogDigest: LOCAL_JOURNEY_CATALOG_DIGEST_SHA256,
      selectedRoles: ["Owner", "Member", "External"],
    });
    expect(
      snapshot.evidence?.items.map(({ metadata }) => metadata.role),
    ).toEqual(["Owner", "External", "Member"]);
    expect(snapshot.evidence?.auditReferences).toEqual([
      "guided-demo:evidence-open:no-core-audit",
    ]);
    expect(snapshot.report).toMatchObject({
      reviewStatus: "approved_local_only",
      redacted: true,
      externalSubmissionPerformed: false,
    });
    expect(snapshot.report?.artifacts.markdownDigest).toMatch(
      /^[a-f0-9]{64}$/u,
    );
    expect(snapshot.report?.artifacts.htmlDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(snapshot.report?.artifacts.jsonDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(() =>
      instance.perform({ action: "approve_local_report", confirmed: true }),
    ).toThrow("LOCAL_PRODUCT_TERMINAL");
  });

  it("projects strict local selections through every dependent artifact", () => {
    const instance = workflow();
    for (const input of FLOW) {
      switch (input.action) {
        case "onboarding_configure_testmail":
          instance.perform({
            action: input.action,
            schema: "subaddress_fixture",
          });
          break;
        case "create_program":
          instance.perform({
            action: input.action,
            displayName: "Local Demo Program Reviewed",
            allowedAssetRefs: ["asset-local-primary"],
            excludedAssetRefs: [],
          });
          break;
        case "import_policy":
          instance.perform({
            action: input.action,
            representation: "human_readable_text",
          });
          break;
        case "create_campaign":
          instance.perform({
            action: input.action,
            policyVersion: 1,
            roles: ["External", "Owner", "Member"],
            riskTiers: ["tier_0_offline"],
            maxRequests: 4,
            requestsPerMinute: 1,
            maxConcurrency: 1,
          });
          break;
        case "start_journey":
          instance.perform({
            action: input.action,
            confirmed: true,
            journeyId: LOCAL_JOURNEY_CATALOG_ID,
            roles: ["External", "Owner", "Member"],
          });
          break;
        default:
          instance.perform(input);
      }
    }

    const snapshot = instance.snapshot();
    expect(snapshot.onboarding.testMailbox).toBe("subaddress_fixture");
    expect(snapshot.program).toMatchObject({
      displayName: "Local Demo Program Reviewed",
      excludedAssetRefs: [],
      metadataEdition: "reviewed_fixed_metadata",
    });
    expect(snapshot.policy).toMatchObject({
      importRepresentation: "human_readable_text",
      rules: { excludedAssets: [] },
    });
    expect(snapshot.campaign?.contract).toMatchObject({
      selectedRoles: ["Owner", "Member", "External"],
      maxRequests: 4,
      requestsPerMinute: 1,
      maxConcurrency: 1,
    });
    expect(snapshot.identities.map(({ role }) => role)).toEqual([
      "Owner",
      "Member",
      "External",
    ]);
    expect(snapshot.journey?.roles).toEqual(["Owner", "Member", "External"]);
    expect(snapshot.journey?.liveSteps).toHaveLength(
      LOCAL_JOURNEY_ROLE_PLANS.Owner.length +
        LOCAL_JOURNEY_ROLE_PLANS.Member.length +
        LOCAL_JOURNEY_ROLE_PLANS.External.length,
    );
    expect(snapshot.inventory?.roleMatrix.map(({ role }) => role)).toEqual([
      "Owner",
      "Member",
      "External",
    ]);
    expect(snapshot.candidates[0]).toMatchObject({
      roles: ["Owner", "Member", "External"],
      requestBudget: { maximum: 4, consumed: 0 },
    });
  });

  it("cryptographically binds every evidence-bundle component", () => {
    const evidence = complete().evidence;
    if (evidence === null) throw new Error("TEST_EVIDENCE_REQUIRED");
    const bound = {
      items: evidence.items,
      ownershipProof: evidence.ownershipProof,
      canaryProof: evidence.canaryProof,
      policyHash: evidence.policyHash,
      demoPolicyHash: evidence.demoPolicyHash,
      demoSnapshotDigest: evidence.demoSnapshotDigest,
      journeyId: evidence.journeyId,
      journeyCatalogDigest: evidence.journeyCatalogDigest,
      selectedRoles: evidence.selectedRoles,
      auditReferences: evidence.auditReferences,
    };
    expect(evidence.bundleDigest).toBe(sha256(canonicalJson(bound)));

    const changedBindings = [
      {
        ...bound,
        items: [
          { ...bound.items[0], digest: "0".repeat(64) },
          ...bound.items.slice(1),
        ],
      },
      {
        ...bound,
        ownershipProof: {
          ...bound.ownershipProof,
          digest: "1".repeat(64),
        },
      },
      {
        ...bound,
        canaryProof: { ...bound.canaryProof, digest: "2".repeat(64) },
      },
      { ...bound, policyHash: "3".repeat(64) },
      { ...bound, demoPolicyHash: "4".repeat(64) },
      { ...bound, demoSnapshotDigest: "5".repeat(64) },
      { ...bound, journeyId: "changed-local-journey" },
      { ...bound, journeyCatalogDigest: "6".repeat(64) },
      { ...bound, selectedRoles: ["Owner", "External"] },
      {
        ...bound,
        auditReferences: ["guided-demo:evidence-open:changed-reference"],
      },
    ];
    for (const changed of changedBindings)
      expect(sha256(canonicalJson(changed))).not.toBe(evidence.bundleDigest);
  });

  it("rejects invalid local selections and free execution fields fail-closed", () => {
    const invalidSelections: readonly {
      readonly action: LocalProductActionInput["action"];
      readonly input: unknown;
    }[] = [
      {
        action: "onboarding_configure_testmail",
        input: {
          action: "onboarding_configure_testmail",
          schema: "external_mailbox",
        },
      },
      {
        action: "onboarding_disable_ai",
        input: { action: "onboarding_disable_ai", provider: "openai" },
      },
      {
        action: "create_program",
        input: {
          action: "create_program",
          displayName: "Arbitrary program",
          allowedAssetRefs: ["asset-local-primary"],
          excludedAssetRefs: [],
        },
      },
      {
        action: "create_program",
        input: {
          action: "create_program",
          displayName: "Local Demo Program",
          allowedAssetRefs: [],
          excludedAssetRefs: [],
        },
      },
      {
        action: "import_policy",
        input: { action: "import_policy", representation: "remote_document" },
      },
      {
        action: "create_campaign",
        input: {
          action: "create_campaign",
          policyVersion: 1,
          roles: [],
          riskTiers: ["tier_0_offline"],
          maxRequests: 4,
          requestsPerMinute: 1,
          maxConcurrency: 1,
        },
      },
      {
        action: "create_campaign",
        input: {
          action: "create_campaign",
          policyVersion: 1,
          roles: ["Owner", "Owner"],
          riskTiers: ["tier_0_offline"],
          maxRequests: 4,
          requestsPerMinute: 1,
          maxConcurrency: 1,
        },
      },
      {
        action: "create_campaign",
        input: {
          action: "create_campaign",
          policyVersion: 1,
          roles: ["Owner", "Member"],
          riskTiers: ["tier_0_offline"],
          maxRequests: 4,
          requestsPerMinute: 1,
          maxConcurrency: 1,
        },
      },
      {
        action: "create_campaign",
        input: {
          action: "create_campaign",
          policyVersion: 1,
          roles: ["Owner"],
          riskTiers: ["tier_1_network"],
          maxRequests: 5,
          requestsPerMinute: 3,
          maxConcurrency: 2,
        },
      },
      {
        action: "start_journey",
        input: {
          action: "start_journey",
          confirmed: true,
          journeyId: "arbitrary-journey",
          roles: ["Owner", "Member", "External"],
        },
      },
    ];
    for (const { action, input } of invalidSelections) {
      const instance = workflow();
      runUntil(instance, action);
      const before = JSON.stringify(instance.snapshot());
      expect(() => instance.perform(input)).toThrow(/LOCAL_PRODUCT_/u);
      expect(JSON.stringify(instance.snapshot())).toBe(before);
    }

    for (const field of ["host", "url", "locator", "script", "objectId"]) {
      const instance = workflow();
      runUntil(instance, "create_program");
      const before = JSON.stringify(instance.snapshot());
      expect(() =>
        instance.perform({ ...inputFor("create_program"), [field]: "free" }),
      ).toThrow("LOCAL_PRODUCT_ACTION_FIELDS_INVALID");
      expect(JSON.stringify(instance.snapshot())).toBe(before);
    }
  });

  it("requires the complete three-role evidence selection", () => {
    const instance = workflow();
    runUntil(instance, "start_journey");
    const before = JSON.stringify(instance.snapshot());
    expect(() =>
      instance.perform({
        action: "start_journey",
        confirmed: true,
        journeyId: LOCAL_JOURNEY_CATALOG_ID,
        roles: ["Owner", "Member"],
      }),
    ).toThrow("LOCAL_PRODUCT_ROLES_INVALID");
    expect(JSON.stringify(instance.snapshot())).toBe(before);
  });

  it("mirrors a deeply frozen redacted runtime context in onboarding", () => {
    const instance = new LocalProductWorkflow(
      () => new Date(TIME),
      READY_RUNTIME,
      DEMO_BINDING,
    );
    const snapshot = complete(instance);
    expect(snapshot.runtimeContext).toEqual(READY_RUNTIME);
    expect(snapshot.runtimeContext).not.toBe(READY_RUNTIME);
    expect(snapshot.onboarding).toMatchObject({
      systemCheck: "ready",
      databaseCheck: "ready",
      credentialStorageCheck: "ready",
      demo: {
        status: "ready",
        revision: 1,
        snapshotDigest: DEMO_DIGEST,
      },
    });
    expectDeepFrozen(snapshot.runtimeContext);
  });

  it.each([
    [
      "onboarding_system_check",
      { ...READY_RUNTIME, systemStatus: "blocked" },
      "LOCAL_PRODUCT_RUNTIME_SYSTEM_BLOCKED",
    ],
    [
      "onboarding_system_check",
      { ...READY_RUNTIME, databaseStatus: "blocked" },
      "LOCAL_PRODUCT_RUNTIME_DATABASE_BLOCKED",
    ],
    [
      "onboarding_secret_store_check",
      { ...READY_RUNTIME, secretStoreStatus: "blocked" },
      "LOCAL_PRODUCT_RUNTIME_SECRET_STORE_BLOCKED",
    ],
    [
      "onboarding_initialize_demo",
      { ...READY_RUNTIME, demoSaasStatus: "blocked" },
      "LOCAL_PRODUCT_RUNTIME_DEMO_SAAS_BLOCKED",
    ],
  ] as const)(
    "blocks %s when its redacted runtime observation is blocked",
    (action, runtimeContext, errorCode) => {
      const instance = new LocalProductWorkflow(
        () => new Date(TIME),
        runtimeContext,
        DEMO_BINDING,
      );
      runUntil(instance, action);
      const before = JSON.stringify(instance.snapshot());
      expect(() => instance.perform(inputFor(action))).toThrow(errorCode);
      expect(JSON.stringify(instance.snapshot())).toBe(before);
    },
  );

  it("rejects malformed or sensitive-shaped runtime contexts", () => {
    const accessorContext = { ...READY_RUNTIME } as Record<string, unknown>;
    Object.defineProperty(accessorContext, "systemStatus", {
      enumerable: true,
      get: () => "ready",
    });
    const invalidContexts: readonly unknown[] = [
      null,
      {},
      { ...READY_RUNTIME, statusReason: "secret detail" },
      { ...READY_RUNTIME, systemStatus: "unknown" },
      { ...READY_RUNTIME, demoSnapshotDigest: "not-a-digest" },
      accessorContext,
    ];
    for (const runtimeContext of invalidContexts)
      expect(
        () =>
          new LocalProductWorkflow(
            () => new Date(TIME),
            runtimeContext as LocalProductRuntimeContext,
            DEMO_BINDING,
          ),
      ).toThrow("LOCAL_PRODUCT_RUNTIME_CONTEXT_INVALID");
  });

  it("rejects unbound, malformed or secret-shaped Demo-SaaS projections", () => {
    expect(
      () =>
        new LocalProductWorkflow(
          () => new Date(TIME),
          { ...READY_RUNTIME, demoSnapshotDigest: "d".repeat(64) },
          DEMO_BINDING,
        ),
    ).toThrow("LOCAL_PRODUCT_DEMO_BINDING_MISMATCH");

    const invalidBindings: readonly unknown[] = [
      null,
      { ...DEMO_BINDING, organizationRef: "unknown-organization" },
      { ...DEMO_BINDING, controlledObjectRef: "unknown-object" },
      { ...DEMO_BINDING, canary: "raw-canary-material" },
      {
        ...DEMO_BINDING,
        identities: [
          DEMO_BINDING.identities[0],
          DEMO_BINDING.identities[2],
          DEMO_BINDING.identities[1],
        ],
      },
    ];
    for (const demoBinding of invalidBindings)
      expect(
        () =>
          new LocalProductWorkflow(
            () => new Date(TIME),
            READY_RUNTIME,
            demoBinding as LocalProductDemoBinding,
          ),
      ).toThrow("LOCAL_PRODUCT_DEMO_BINDING_INVALID");
  });

  it("rejects missing, additional and malformed fields before changing state", () => {
    const symbolField = { action: "onboarding_system_check" };
    Object.defineProperty(symbolField, Symbol("extra"), { value: true });
    const hiddenField = { action: "onboarding_system_check" };
    Object.defineProperty(hiddenField, "extra", { value: true });
    const accessorAction = {};
    Object.defineProperty(accessorAction, "action", {
      enumerable: true,
      get: () => "onboarding_system_check",
    });
    const invalidInputs: readonly unknown[] = [
      null,
      [],
      "onboarding_system_check",
      {},
      { action: 1 },
      { action: "unknown" },
      { action: "onboarding_system_check", confirmed: true },
      { action: "onboarding_system_check", extra: false },
      symbolField,
      hiddenField,
      accessorAction,
      Object.create(null) as unknown,
    ];
    for (const input of invalidInputs) {
      const instance = workflow();
      expect(() => instance.perform(input)).toThrow(/LOCAL_PRODUCT_/u);
      expect(instance.snapshot().revision).toBe(0);
      expect(instance.snapshot().progress.completedSteps).toBe(0);
    }
  });

  it("requires confirmed true at every human checkpoint", () => {
    for (const action of CONFIRMED_ACTIONS) {
      const missing = workflow();
      runUntil(missing, action);
      const beforeMissing = JSON.stringify(missing.snapshot());
      expect(() => missing.perform({ action })).toThrow(
        "LOCAL_PRODUCT_CONFIRMATION_REQUIRED",
      );
      expect(JSON.stringify(missing.snapshot())).toBe(beforeMissing);

      const falseConfirmation = workflow();
      runUntil(falseConfirmation, action);
      const beforeFalse = JSON.stringify(falseConfirmation.snapshot());
      expect(() =>
        falseConfirmation.perform({ action, confirmed: false }),
      ).toThrow("LOCAL_PRODUCT_CONFIRMATION_REQUIRED");
      expect(JSON.stringify(falseConfirmation.snapshot())).toBe(beforeFalse);
    }
  });

  it("allows only a fixed metadata edit and makes archival terminal", () => {
    const instance = workflow();
    runUntil(instance, "import_policy");
    const beforeEdit = instance.snapshot();
    const completedBeforeEdit = beforeEdit.progress.completedSteps;
    expect(beforeEdit.availableManagementActions).toEqual([
      "edit_program",
      "archive_program",
    ]);

    const edited = instance.perform({ action: "edit_program" });
    expect(edited.program).toMatchObject({
      displayName: "Local Demo Program Reviewed",
      metadataEdition: "reviewed_fixed_metadata",
      lifecycle: "active",
    });
    expect(edited.progress.completedSteps).toBe(completedBeforeEdit);
    expect(edited.nextAction).toBe("import_policy");
    expect(edited.availableManagementActions).toEqual(["archive_program"]);

    const archived = instance.perform({ action: "archive_program" });
    expect(archived.workflowStatus).toBe("halted_fail_closed");
    expect(archived.terminalReason).toBe("program_archived");
    expect(archived.program?.lifecycle).toBe("archived");
    expect(() => instance.perform(inputFor("import_policy"))).toThrow(
      "LOCAL_PRODUCT_TERMINAL",
    );
  });

  it("starts only fixed local identity sessions without advancing the guided flow", () => {
    const instance = workflow();
    runUntil(instance, "start_journey");
    const before = instance.snapshot();
    expect(
      before.identities.every(
        ({ sessionStatus }) => sessionStatus === "inactive",
      ),
    ).toBe(true);
    expect(before.availableManagementActions).toContain(
      "start_identity_sessions",
    );

    const started = instance.perform({ action: "start_identity_sessions" });
    expect(started.progress.completedSteps).toBe(
      before.progress.completedSteps,
    );
    expect(
      started.identities.every(
        ({ sessionStatus, sessionStartedAt }) =>
          sessionStatus === "active_local" && sessionStartedAt === TIME,
      ),
    ).toBe(true);
    expect(() =>
      instance.perform({ action: "start_identity_sessions" }),
    ).toThrow("LOCAL_PRODUCT_MANAGEMENT_STATE_INVALID");

    const journey = instance.perform(inputFor("start_journey"));
    expect(journey.journey?.browserStarted).toBe(false);
  });

  it.each([
    ["pause_campaign", "campaign_paused", "paused_fail_closed"],
    ["cancel_campaign", "campaign_cancelled", "cancelled_fail_closed"],
  ] as const)(
    "%s halts the campaign and cannot be used to bypass the guided flow",
    (action, reason, status) => {
      const instance = workflow();
      runUntil(instance, "prepare_identities");
      const snapshot = instance.perform({ action });
      expect(snapshot.workflowStatus).toBe("halted_fail_closed");
      expect(snapshot.terminalReason).toBe(reason);
      expect(snapshot.campaign?.status).toBe(status);
      expect(() => instance.perform({ action: "prepare_identities" })).toThrow(
        "LOCAL_PRODUCT_TERMINAL",
      );
    },
  );

  it.each([
    ["pause_journey", "journey_paused", "paused_fail_closed"],
    ["cancel_journey", "journey_cancelled", "cancelled_fail_closed"],
  ] as const)(
    "%s halts the journey and its campaign fail-closed",
    (action, reason, status) => {
      const instance = workflow();
      runUntil(instance, "inspect_inventory");
      const snapshot = instance.perform({ action });
      expect(snapshot.workflowStatus).toBe("halted_fail_closed");
      expect(snapshot.terminalReason).toBe(reason);
      expect(snapshot.journey?.status).toBe(status);
      expect(snapshot.campaign?.status).toBe(status);
      expect(() => instance.perform({ action: "inspect_inventory" })).toThrow(
        "LOCAL_PRODUCT_TERMINAL",
      );
    },
  );

  it("deep-freezes every projected snapshot object and array", () => {
    expectDeepFrozen(workflow().snapshot());
    expectDeepFrozen(complete());
  });

  it("never projects URLs, credential material markers or action history", () => {
    const serialized = JSON.stringify(complete());
    expect(serialized).not.toMatch(/(?:https?|wss?):\/\//iu);
    expect(serialized).not.toMatch(
      /bearer|authorization\s*:|password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|cookie|private key/iu,
    );
    expect(serialized).not.toContain("onboarding_secret_store_check");
    expect(serialized).not.toContain("locator");
    expect(serialized).not.toContain("script");
  });

  it("rejects invalid and regressing clocks without advancing", () => {
    expect(
      () =>
        new LocalProductWorkflow(
          () => new Date(Number.NaN),
          READY_RUNTIME,
          DEMO_BINDING,
        ),
    ).toThrow("LOCAL_PRODUCT_CLOCK_INVALID");
    expect(
      () =>
        new LocalProductWorkflow(
          () => "not-a-date" as unknown as Date,
          READY_RUNTIME,
          DEMO_BINDING,
        ),
    ).toThrow("LOCAL_PRODUCT_CLOCK_INVALID");

    const values = [
      new Date("2026-07-14T12:00:01.000Z"),
      new Date("2026-07-14T12:00:00.000Z"),
    ];
    const instance = new LocalProductWorkflow(
      () => {
        const next = values.shift();
        if (next === undefined) throw new Error("CLOCK_EMPTY");
        return next;
      },
      READY_RUNTIME,
      DEMO_BINDING,
    );
    expect(() =>
      instance.perform({ action: "onboarding_system_check" }),
    ).toThrow("LOCAL_PRODUCT_CLOCK_REGRESSION");
    expect(instance.snapshot().revision).toBe(0);
  });
});
