import { canonicalJson, sha256 } from "../shared/canonical.js";
import {
  JOURNEY_ROLES,
  LOCAL_JOURNEY_CATALOG_DIGEST_SHA256,
  LOCAL_JOURNEY_CATALOG_ID,
  LOCAL_JOURNEY_ROLE_PLANS,
  type JourneyCapability,
  type JourneyPath,
  type JourneyRole,
} from "../local-journey-catalog/index.js";

const GUIDED_ACTIONS = Object.freeze([
  "onboarding_system_check",
  "onboarding_secret_store_check",
  "onboarding_select_simulation",
  "onboarding_configure_testmail",
  "onboarding_disable_ai",
  "onboarding_confirm_boundaries",
  "onboarding_initialize_demo",
  "create_program",
  "import_policy",
  "accept_policy",
  "create_campaign",
  "approve_campaign",
  "prepare_identities",
  "start_journey",
  "inspect_inventory",
  "generate_candidates",
  "verify_candidate",
  "open_evidence",
  "create_report",
  "queue_report_review",
  "approve_local_report",
] as const);

const CONFIRMATION_ACTIONS = Object.freeze([
  "onboarding_confirm_boundaries",
  "accept_policy",
  "approve_campaign",
  "start_journey",
  "verify_candidate",
  "queue_report_review",
  "approve_local_report",
] as const);

const MANAGEMENT_ACTIONS = Object.freeze([
  "edit_program",
  "archive_program",
  "pause_campaign",
  "cancel_campaign",
  "pause_journey",
  "cancel_journey",
  "start_identity_sessions",
] as const);

type GuidedAction = (typeof GUIDED_ACTIONS)[number];
type ConfirmationAction = (typeof CONFIRMATION_ACTIONS)[number];
type ManagementAction = (typeof MANAGEMENT_ACTIONS)[number];
type SimpleGuidedAction = Exclude<GuidedAction, ConfirmationAction>;
type PayloadGuidedAction =
  | "create_campaign"
  | "create_program"
  | "import_policy"
  | "onboarding_configure_testmail"
  | "onboarding_disable_ai";
type ActionOnlyAction =
  Exclude<SimpleGuidedAction, PayloadGuidedAction> | ManagementAction;
type GenericConfirmationAction = Exclude<ConfirmationAction, "start_journey">;

const LOCAL_ROLES = JOURNEY_ROLES;
type LocalRole = JourneyRole;
type LocalRoles = readonly ["Owner", "Member", "External"];
type ExcludedAssetSelection =
  readonly [] | readonly ["asset-local-administration"];
type TestMailboxSchema = "plus_addressing_fixture" | "subaddress_fixture";
type PolicyRepresentation = "human_readable_text" | "structured_fixture";
type CampaignMaxRequests = 0 | 4 | 8;
type CampaignRequestsPerMinute = 0 | 1 | 2;

export type LocalProductRuntimeStatus = "blocked" | "ready" | "setup_required";

/**
 * Redacted readiness projection supplied by the local dashboard runtime.
 * It deliberately contains neither configuration values nor credentials.
 */
export interface LocalProductRuntimeContext {
  readonly systemStatus: LocalProductRuntimeStatus;
  readonly secretStoreStatus: LocalProductRuntimeStatus;
  readonly demoSaasStatus: LocalProductRuntimeStatus;
  readonly databaseStatus: LocalProductRuntimeStatus;
  readonly demoSnapshotDigest: string;
}

/**
 * Redacted, exact projection of the seeded Demo-SaaS fixture. The raw canary
 * never crosses this boundary; only its digest is retained.
 */
export interface LocalProductDemoBinding {
  readonly snapshotDigest: string;
  readonly organizationRef: "org-demo-001";
  readonly identities: readonly [
    {
      readonly role: "Owner";
      readonly identityRef: "identity-owner-001";
    },
    {
      readonly role: "Member";
      readonly identityRef: "identity-member-001";
    },
    {
      readonly role: "External";
      readonly identityRef: "identity-external-001";
    },
  ];
  readonly controlledObjectRef: "object-demo-001";
  readonly controlledByRef: "identity-owner-001";
  readonly canaryDigest: string;
  readonly demoPolicyHash: string;
}

export type LocalProductActionInput =
  | { readonly action: ActionOnlyAction }
  | {
      readonly action: "onboarding_configure_testmail";
      readonly schema: TestMailboxSchema;
    }
  | {
      readonly action: "onboarding_disable_ai";
      readonly provider: "disabled";
    }
  | {
      readonly action: "create_program";
      readonly displayName:
        "Local Demo Program" | "Local Demo Program Reviewed";
      readonly allowedAssetRefs: readonly ["asset-local-primary"];
      readonly excludedAssetRefs: ExcludedAssetSelection;
    }
  | {
      readonly action: "import_policy";
      readonly representation: PolicyRepresentation;
    }
  | {
      readonly action: "create_campaign";
      readonly policyVersion: 1;
      readonly roles: LocalRoles;
      readonly riskTiers: readonly ["tier_0_offline"];
      readonly maxRequests: CampaignMaxRequests;
      readonly requestsPerMinute: CampaignRequestsPerMinute;
      readonly maxConcurrency: 1;
    }
  | {
      readonly action: GenericConfirmationAction;
      readonly confirmed: true;
    }
  | {
      readonly action: "start_journey";
      readonly confirmed: true;
      readonly journeyId: typeof LOCAL_JOURNEY_CATALOG_ID;
      readonly roles: LocalRoles;
    };

interface SafetyBadges {
  readonly mode: "simulation";
  readonly external: false;
  readonly ai: "disabled_not_implemented";
  readonly realSubmission: false;
}

interface OnboardingSnapshot {
  readonly badges: SafetyBadges;
  readonly status: "complete" | "in_progress" | "not_started";
  readonly systemCheck: LocalProductRuntimeStatus | "pending";
  readonly databaseCheck: LocalProductRuntimeStatus | "pending";
  readonly credentialStorageCheck: LocalProductRuntimeStatus | "pending";
  readonly selectedMode: "simulation" | null;
  readonly testMailbox: TestMailboxSchema | null;
  readonly aiProvider: "disabled" | null;
  readonly aiBoundaryConfirmed: boolean;
  readonly boundariesConfirmed: boolean;
  readonly demo: {
    readonly status: LocalProductRuntimeStatus | "pending";
    readonly revision: 1 | null;
    readonly snapshotDigest: string | null;
  };
}

interface ProgramSnapshot {
  readonly badges: SafetyBadges;
  readonly id: "program-local-demo";
  readonly displayName: "Local Demo Program" | "Local Demo Program Reviewed";
  readonly platform: "local_fixture";
  readonly lifecycle: "active" | "archived";
  readonly revision: number;
  readonly metadataEdition: "initial" | "reviewed_fixed_metadata";
  readonly allowedAssetRefs: readonly ["asset-local-primary"];
  readonly excludedAssetRefs: ExcludedAssetSelection;
  readonly policyHash: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

interface PolicySnapshot {
  readonly badges: SafetyBadges;
  readonly programId: "program-local-demo";
  readonly version: 1;
  readonly status: "accepted_local" | "imported_pending_acceptance";
  readonly importRepresentation: PolicyRepresentation;
  readonly source: {
    readonly origin: "seeded_local_fixture";
    readonly preview: string;
  };
  readonly policyHash: string;
  readonly rules: {
    readonly allowedAssets: readonly ["asset-local-primary"];
    readonly excludedAssets: ExcludedAssetSelection;
    readonly allowedTestClasses: readonly ["offline_metadata_review"];
    readonly forbiddenTestClasses: readonly ["active_security_test"];
    readonly maxRequests: 8;
    readonly requestsPerMinute: 2;
    readonly maxConcurrency: 1;
  };
  readonly diff: {
    readonly changed: true;
    readonly baselineHash: string;
    readonly currentHash: string;
    readonly representationBefore: "none";
    readonly representationAfter: PolicyRepresentation;
    readonly addedAllowedAssets: readonly ["asset-local-primary"];
    readonly addedExcludedAssets: ExcludedAssetSelection;
    readonly addedAllowedTestClasses: readonly ["offline_metadata_review"];
    readonly newlyForbiddenTestClasses: readonly ["active_security_test"];
    readonly requestLimitBefore: 1;
    readonly requestLimitAfter: 8;
    readonly requestsPerMinuteBefore: 0;
    readonly requestsPerMinuteAfter: 2;
    readonly maxConcurrencyBefore: 1;
    readonly maxConcurrencyAfter: 1;
  };
  readonly importedAt: string;
  readonly acceptedAt: string | null;
}

type CampaignStatus =
  | "approved_local"
  | "awaiting_local_approval"
  | "cancelled_fail_closed"
  | "completed_local_only"
  | "paused_fail_closed"
  | "running_local_simulation";

interface CampaignSnapshot {
  readonly badges: SafetyBadges;
  readonly id: "campaign-local-demo";
  readonly programId: "program-local-demo";
  readonly policyVersion: 1;
  readonly policyHash: string;
  readonly revision: number;
  readonly status: CampaignStatus;
  readonly contract: {
    readonly allowedAssetRefs: readonly ["asset-local-primary"];
    readonly excludedAssetRefs: ExcludedAssetSelection;
    readonly allowedMethods: readonly ["GET", "HEAD"];
    readonly allowedRiskTiers: readonly ["tier_0_offline"];
    readonly selectedRoles: LocalRoles;
    readonly allowedActions: readonly ["offline_inspect"];
    readonly maxRequests: CampaignMaxRequests;
    readonly requestsPerMinute: CampaignRequestsPerMinute;
    readonly maxConcurrency: 1;
    readonly writeActionsAllowed: false;
    readonly externalActionsAllowed: false;
    readonly humanCheckpoints: readonly [
      "campaign_approval",
      "journey_start",
      "report_review",
    ];
  };
  readonly createdAt: string;
  readonly approvedAt: string | null;
  readonly updatedAt: string;
}

interface IdentitySnapshot {
  readonly badges: SafetyBadges;
  readonly id:
    "identity-external-001" | "identity-member-001" | "identity-owner-001";
  readonly role: LocalRole;
  readonly status: "ready_local_fixture";
  readonly localFixture: true;
  readonly checkpointFreeFixture: true;
  readonly humanActionRequired: false;
  readonly organizationRef: "org-demo-001";
  readonly ownedObjectRefs: readonly string[];
  readonly sessionStatus: "active_local" | "inactive";
  readonly preparedAt: string;
  readonly sessionStartedAt: string | null;
}

type JourneyStatus =
  | "cancelled_fail_closed"
  | "completed_local_simulation"
  | "paused_fail_closed"
  | "simulated_pending_inventory";

interface JourneyStepSnapshot {
  readonly sequence: number;
  readonly catalogIndex: number;
  readonly role: LocalRole;
  readonly method: "GET";
  readonly path: JourneyPath;
  readonly capability: JourneyCapability;
  readonly fromState: "ready" | "running";
  readonly successState: "completed" | "running";
  readonly execution: "catalog_projection_only";
  readonly result: "validated_fixture";
}

interface JourneySnapshot {
  readonly badges: SafetyBadges;
  readonly id: typeof LOCAL_JOURNEY_CATALOG_ID;
  readonly catalogDigestSha256: string;
  readonly campaignId: "campaign-local-demo";
  readonly status: JourneyStatus;
  readonly execution: "simulated_metadata_only";
  readonly testHarnessValidated: true;
  readonly browserStarted: false;
  readonly networkRequests: 0;
  readonly roles: LocalRoles;
  readonly liveSteps: readonly JourneyStepSnapshot[];
  readonly startedAt: string;
  readonly finishedAt: string | null;
  readonly updatedAt: string;
}

interface InventorySnapshot {
  readonly badges: SafetyBadges;
  readonly status: "inspected_local";
  readonly applicationInventory: readonly [
    {
      readonly applicationRef: "application-local-demo";
      readonly source: "deterministic_demo_fixture";
      readonly status: "available_local_fixture";
      readonly externalTransport: false;
    },
  ];
  readonly endpointInventory: readonly [
    {
      readonly endpointRef: "endpoint-project-summary";
      readonly applicationRef: "application-local-demo";
      readonly operation: "project_metadata_read";
      readonly method: "GET";
      readonly inApprovedScope: true;
    },
    {
      readonly endpointRef: "endpoint-document-summary";
      readonly applicationRef: "application-local-demo";
      readonly operation: "document_metadata_read";
      readonly method: "GET";
      readonly inApprovedScope: true;
    },
  ];
  readonly roleMatrix: readonly {
    readonly role: LocalRole;
    readonly endpointRefs: readonly (
      "endpoint-document-summary" | "endpoint-project-summary"
    )[];
    readonly expectedAccess:
      "fixture_metadata_allowed" | "fixture_metadata_restricted";
  }[];
  readonly ownershipGraph: {
    readonly identityRefs: readonly IdentitySnapshot["id"][];
    readonly objectRefs: readonly ["object-demo-001"];
    readonly edges: readonly [
      {
        readonly from: IdentitySnapshot["id"];
        readonly to: "object-demo-001";
        readonly relation: "controls";
      },
    ];
    readonly allObjectsResearcherControlled: true;
  };
  readonly canary: {
    readonly digest: string;
    readonly valueExposed: false;
    readonly verified: true;
  };
  readonly policyAssignment: {
    readonly policyHash: string;
    readonly demoSourcePolicyHash: string;
    readonly assetRef: "asset-local-primary";
    readonly status: "assigned_exact";
  };
  readonly campaignAssignment: {
    readonly campaignId: "campaign-local-demo";
    readonly assetRef: "asset-local-primary";
    readonly status: "assigned_exact";
  };
  readonly inspectedAt: string;
}

interface CandidateSnapshot {
  readonly badges: SafetyBadges;
  readonly id: "candidate-local-role-boundary";
  readonly campaignId: "campaign-local-demo";
  readonly inventoryRef: "endpoint-document-summary";
  readonly title: "Deterministic role boundary observation";
  readonly hypothesis: "Role projections differ in the deterministic fixture";
  readonly vulnerabilityClass: "authorization_boundary_metadata";
  readonly roles: LocalRoles;
  readonly ownedObjectRefs: readonly ["object-demo-001"];
  readonly mutation: "none_read_only";
  readonly riskTier: "tier_0_offline";
  readonly requestBudget: {
    readonly maximum: CampaignMaxRequests;
    readonly consumed: 0;
  };
  readonly priority: "low";
  readonly falsePositiveReasons: readonly [
    "deterministic_fixture_expected_variance",
    "no_external_effect",
  ];
  readonly privacyStatus: "redacted_metadata_only";
  readonly severity: "informational";
  readonly status: "generated" | "verified_local_fixture";
  readonly activeTestPerformed: false;
  readonly verificationResult:
    "deterministic_fixture_difference_confirmed" | null;
  readonly generatedAt: string;
  readonly verifiedAt: string | null;
}

interface EvidenceItemSnapshot {
  readonly kind: "baseline" | "control" | "test";
  readonly digest: string;
  readonly metadata: {
    readonly candidateId: "candidate-local-role-boundary";
    readonly role: LocalRole;
    readonly identityRef: IdentitySnapshot["id"];
    readonly observation: string;
    readonly projection: "metadata_only";
  };
  readonly rawPayloadStored: false;
  readonly visualBytesStored: false;
  readonly capturedAt: string;
}

interface EvidenceSnapshot {
  readonly badges: SafetyBadges;
  readonly status: "open_local_bundle";
  readonly candidateId: "candidate-local-role-boundary";
  readonly items: readonly [
    EvidenceItemSnapshot,
    EvidenceItemSnapshot,
    EvidenceItemSnapshot,
  ];
  readonly bundleDigest: string;
  readonly ownershipProof: {
    readonly objectRef: "object-demo-001";
    readonly controllerIdentityRef: "identity-owner-001";
    readonly researcherControlled: true;
    readonly digest: string;
  };
  readonly canaryProof: {
    readonly digest: string;
    readonly valueExposed: false;
  };
  readonly policyHash: string;
  readonly demoPolicyHash: string;
  readonly demoSnapshotDigest: string;
  readonly journeyId: typeof LOCAL_JOURNEY_CATALOG_ID;
  readonly journeyCatalogDigest: string;
  readonly selectedRoles: LocalRoles;
  readonly auditReferences: readonly [
    "guided-demo:evidence-open:no-core-audit",
  ];
  readonly openedAt: string;
}

interface ReportSnapshot {
  readonly badges: SafetyBadges;
  readonly id: "report-local-role-boundary";
  readonly candidateId: "candidate-local-role-boundary";
  readonly title: "Local simulation role boundary report";
  readonly reviewStatus:
    "approved_local_only" | "draft" | "queued_for_local_review";
  readonly redacted: true;
  readonly externalSubmissionPerformed: false;
  readonly artifacts: {
    readonly markdown: string;
    readonly html: string;
    readonly json: string;
    readonly markdownDigest: string;
    readonly htmlDigest: string;
    readonly jsonDigest: string;
  };
  readonly createdAt: string;
  readonly queuedAt: string | null;
  readonly approvedAt: string | null;
}

type WorkflowStage =
  | "campaign"
  | "candidates_evidence"
  | "complete"
  | "halted"
  | "identities_journey"
  | "inventory"
  | "onboarding"
  | "program_policy"
  | "reporting";

type TerminalReason =
  | "campaign_cancelled"
  | "campaign_paused"
  | "journey_cancelled"
  | "journey_paused"
  | "program_archived";

export interface LocalProductSnapshot {
  readonly version: 1;
  readonly revision: number;
  readonly workflowStatus:
    "completed_local_only" | "guided" | "halted_fail_closed";
  readonly stage: WorkflowStage;
  readonly progress: {
    readonly completedSteps: number;
    readonly totalSteps: 21;
  };
  readonly nextAction: LocalProductActionInput["action"] | null;
  readonly availableManagementActions: readonly ManagementAction[];
  readonly lastTransitionAt: string;
  readonly terminalReason: TerminalReason | null;
  readonly badges: SafetyBadges;
  readonly runtimeContext: LocalProductRuntimeContext;
  readonly onboarding: OnboardingSnapshot;
  readonly program: ProgramSnapshot | null;
  readonly policy: PolicySnapshot | null;
  readonly campaign: CampaignSnapshot | null;
  readonly identities: readonly IdentitySnapshot[];
  readonly journey: JourneySnapshot | null;
  readonly inventory: InventorySnapshot | null;
  readonly candidates: readonly CandidateSnapshot[];
  readonly evidence: EvidenceSnapshot | null;
  readonly report: ReportSnapshot | null;
}

const BADGES: SafetyBadges = Object.freeze({
  mode: "simulation",
  external: false,
  ai: "disabled_not_implemented",
  realSubmission: false,
});

const PHASE7_CATALOG_BINDING = Object.freeze({
  id: LOCAL_JOURNEY_CATALOG_ID,
  digestSha256: LOCAL_JOURNEY_CATALOG_DIGEST_SHA256,
});

const BASELINE_POLICY_HASH = sha256(
  canonicalJson({
    version: 0,
    allowedAssets: [],
    forbiddenTestClasses: [],
    maxRequests: 1,
  }),
);

const CONFIRMATION_SET: ReadonlySet<string> = new Set(CONFIRMATION_ACTIONS);
const GUIDED_SET: ReadonlySet<string> = new Set(GUIDED_ACTIONS);
const MANAGEMENT_SET: ReadonlySet<string> = new Set(MANAGEMENT_ACTIONS);

export class LocalProductWorkflow {
  readonly #clock: () => Date;
  readonly #runtimeContext: LocalProductRuntimeContext;
  readonly #demoBinding: LocalProductDemoBinding;
  #lastMilliseconds: number | undefined;
  #lastTransitionAt: string;
  #stepIndex = 0;
  #revision = 0;
  #terminalReason: TerminalReason | null = null;
  #onboarding: OnboardingSnapshot = {
    badges: BADGES,
    status: "not_started",
    systemCheck: "pending",
    databaseCheck: "pending",
    credentialStorageCheck: "pending",
    selectedMode: null,
    testMailbox: null,
    aiProvider: null,
    aiBoundaryConfirmed: false,
    boundariesConfirmed: false,
    demo: {
      status: "pending",
      revision: null,
      snapshotDigest: null,
    },
  };
  #program: ProgramSnapshot | null = null;
  #policy: PolicySnapshot | null = null;
  #campaign: CampaignSnapshot | null = null;
  #identities: readonly IdentitySnapshot[] = Object.freeze([]);
  #journey: JourneySnapshot | null = null;
  #inventory: InventorySnapshot | null = null;
  #candidates: readonly CandidateSnapshot[] = Object.freeze([]);
  #evidence: EvidenceSnapshot | null = null;
  #report: ReportSnapshot | null = null;

  public constructor(
    clock: () => Date,
    runtimeContext: LocalProductRuntimeContext,
    demoBinding: LocalProductDemoBinding,
  ) {
    if (typeof clock !== "function")
      throw new Error("LOCAL_PRODUCT_CLOCK_INVALID");
    this.#clock = clock;
    this.#runtimeContext = parseRuntimeContext(runtimeContext);
    this.#demoBinding = parseDemoBinding(demoBinding);
    if (
      this.#runtimeContext.demoSnapshotDigest !==
      this.#demoBinding.snapshotDigest
    )
      throw new Error("LOCAL_PRODUCT_DEMO_BINDING_MISMATCH");
    this.#lastTransitionAt = this.timestamp();
  }

  public perform(input: unknown): LocalProductSnapshot {
    const parsed = parseAction(input);
    if (
      this.#terminalReason !== null ||
      this.#stepIndex === GUIDED_ACTIONS.length
    )
      throw new Error("LOCAL_PRODUCT_TERMINAL");

    if (isManagementAction(parsed.action)) {
      this.assertManagementAllowed(parsed.action);
      const at = this.timestamp();
      this.applyManagement(parsed.action, at);
      this.#revision += 1;
      this.#lastTransitionAt = at;
      return this.snapshot();
    }

    const expected = GUIDED_ACTIONS[this.#stepIndex];
    if (expected === undefined || parsed.action !== expected)
      throw new Error("LOCAL_PRODUCT_ACTION_OUT_OF_ORDER");
    this.assertRuntimeAllows(parsed.action);
    const at = this.timestamp();
    this.applyGuided(parsed, at);
    this.#stepIndex += 1;
    this.#revision += 1;
    this.#lastTransitionAt = at;
    return this.snapshot();
  }

  public snapshot(): LocalProductSnapshot {
    const completed = this.#stepIndex === GUIDED_ACTIONS.length;
    return deepFreeze({
      version: 1 as const,
      revision: this.#revision,
      workflowStatus:
        this.#terminalReason !== null
          ? ("halted_fail_closed" as const)
          : completed
            ? ("completed_local_only" as const)
            : ("guided" as const),
      stage:
        this.#terminalReason !== null
          ? ("halted" as const)
          : completed
            ? ("complete" as const)
            : stageFor(this.#stepIndex),
      progress: {
        completedSteps: this.#stepIndex,
        totalSteps: 21 as const,
      },
      nextAction:
        this.#terminalReason !== null || completed
          ? null
          : (GUIDED_ACTIONS[this.#stepIndex] ?? null),
      availableManagementActions: this.availableManagementActions(),
      lastTransitionAt: this.#lastTransitionAt,
      terminalReason: this.#terminalReason,
      badges: BADGES,
      runtimeContext: this.#runtimeContext,
      onboarding: this.#onboarding,
      program: this.#program,
      policy: this.#policy,
      campaign: this.#campaign,
      identities: this.#identities,
      journey: this.#journey,
      inventory: this.#inventory,
      candidates: this.#candidates,
      evidence: this.#evidence,
      report: this.#report,
    });
  }

  private assertRuntimeAllows(action: GuidedAction): void {
    switch (action) {
      case "onboarding_system_check":
        if (this.#runtimeContext.systemStatus !== "ready")
          throw new Error("LOCAL_PRODUCT_RUNTIME_SYSTEM_BLOCKED");
        if (this.#runtimeContext.databaseStatus !== "ready")
          throw new Error("LOCAL_PRODUCT_RUNTIME_DATABASE_BLOCKED");
        return;
      case "onboarding_secret_store_check":
        if (this.#runtimeContext.secretStoreStatus === "blocked")
          throw new Error("LOCAL_PRODUCT_RUNTIME_SECRET_STORE_BLOCKED");
        return;
      case "onboarding_initialize_demo":
        if (this.#runtimeContext.demoSaasStatus !== "ready")
          throw new Error("LOCAL_PRODUCT_RUNTIME_DEMO_SAAS_BLOCKED");
        return;
      default:
        return;
    }
  }

  private applyGuided(input: LocalProductActionInput, at: string): void {
    switch (input.action) {
      case "onboarding_system_check":
        this.#onboarding = {
          ...this.#onboarding,
          status: "in_progress",
          systemCheck: this.#runtimeContext.systemStatus,
          databaseCheck: this.#runtimeContext.databaseStatus,
        };
        return;
      case "onboarding_secret_store_check":
        this.#onboarding = {
          ...this.#onboarding,
          credentialStorageCheck: this.#runtimeContext.secretStoreStatus,
        };
        return;
      case "onboarding_select_simulation":
        this.#onboarding = {
          ...this.#onboarding,
          selectedMode: "simulation",
        };
        return;
      case "onboarding_configure_testmail":
        this.#onboarding = {
          ...this.#onboarding,
          testMailbox: input.schema,
        };
        return;
      case "onboarding_disable_ai":
        this.#onboarding = {
          ...this.#onboarding,
          aiProvider: input.provider,
          aiBoundaryConfirmed: true,
        };
        return;
      case "onboarding_confirm_boundaries":
        this.#onboarding = {
          ...this.#onboarding,
          boundariesConfirmed: true,
        };
        return;
      case "onboarding_initialize_demo":
        this.#onboarding = {
          ...this.#onboarding,
          status: "complete",
          demo: {
            status: this.#runtimeContext.demoSaasStatus,
            revision: 1,
            snapshotDigest: this.#runtimeContext.demoSnapshotDigest,
          },
        };
        return;
      case "create_program":
        this.#program = {
          badges: BADGES,
          id: "program-local-demo",
          displayName: input.displayName,
          platform: "local_fixture",
          lifecycle: "active",
          revision: 0,
          metadataEdition:
            input.displayName === "Local Demo Program"
              ? "initial"
              : "reviewed_fixed_metadata",
          allowedAssetRefs: input.allowedAssetRefs,
          excludedAssetRefs: input.excludedAssetRefs,
          policyHash: null,
          createdAt: at,
          updatedAt: at,
        };
        return;
      case "import_policy": {
        const program = requireProgram(this.#program);
        const policyHash = policyHashFor(
          program.allowedAssetRefs,
          program.excludedAssetRefs,
          input.representation,
        );
        this.#policy = {
          badges: BADGES,
          programId: program.id,
          version: 1,
          status: "imported_pending_acceptance",
          importRepresentation: input.representation,
          source: {
            origin: "seeded_local_fixture",
            preview: policySourcePreview(
              input.representation,
              program.allowedAssetRefs,
              program.excludedAssetRefs,
            ),
          },
          policyHash,
          rules: {
            allowedAssets: program.allowedAssetRefs,
            excludedAssets: program.excludedAssetRefs,
            allowedTestClasses: ["offline_metadata_review"],
            forbiddenTestClasses: ["active_security_test"],
            maxRequests: 8,
            requestsPerMinute: 2,
            maxConcurrency: 1,
          },
          diff: {
            changed: true,
            baselineHash: BASELINE_POLICY_HASH,
            currentHash: policyHash,
            representationBefore: "none",
            representationAfter: input.representation,
            addedAllowedAssets: program.allowedAssetRefs,
            addedExcludedAssets: program.excludedAssetRefs,
            addedAllowedTestClasses: ["offline_metadata_review"],
            newlyForbiddenTestClasses: ["active_security_test"],
            requestLimitBefore: 1,
            requestLimitAfter: 8,
            requestsPerMinuteBefore: 0,
            requestsPerMinuteAfter: 2,
            maxConcurrencyBefore: 1,
            maxConcurrencyAfter: 1,
          },
          importedAt: at,
          acceptedAt: null,
        };
        this.#program = {
          ...program,
          revision: program.revision + 1,
          policyHash,
          updatedAt: at,
        };
        return;
      }
      case "accept_policy": {
        const policy = requirePolicy(this.#policy);
        if (policy.status !== "imported_pending_acceptance")
          throw new Error("LOCAL_PRODUCT_POLICY_STATE_INVALID");
        this.#policy = {
          ...policy,
          status: "accepted_local",
          acceptedAt: at,
        };
        return;
      }
      case "create_campaign": {
        const policy = requirePolicy(this.#policy);
        const program = requireProgram(this.#program);
        if (policy.status !== "accepted_local")
          throw new Error("LOCAL_PRODUCT_POLICY_STATE_INVALID");
        this.#campaign = {
          badges: BADGES,
          id: "campaign-local-demo",
          programId: "program-local-demo",
          policyVersion: input.policyVersion,
          policyHash: policy.policyHash,
          revision: 0,
          status: "awaiting_local_approval",
          contract: {
            allowedAssetRefs: program.allowedAssetRefs,
            excludedAssetRefs: program.excludedAssetRefs,
            allowedMethods: ["GET", "HEAD"],
            allowedRiskTiers: input.riskTiers,
            selectedRoles: input.roles,
            allowedActions: ["offline_inspect"],
            maxRequests: input.maxRequests,
            requestsPerMinute: input.requestsPerMinute,
            maxConcurrency: input.maxConcurrency,
            writeActionsAllowed: false,
            externalActionsAllowed: false,
            humanCheckpoints: [
              "campaign_approval",
              "journey_start",
              "report_review",
            ],
          },
          createdAt: at,
          approvedAt: null,
          updatedAt: at,
        };
        return;
      }
      case "approve_campaign": {
        const campaign = requireCampaign(this.#campaign);
        if (campaign.status !== "awaiting_local_approval")
          throw new Error("LOCAL_PRODUCT_CAMPAIGN_STATE_INVALID");
        this.#campaign = {
          ...campaign,
          revision: campaign.revision + 1,
          status: "approved_local",
          approvedAt: at,
          updatedAt: at,
        };
        return;
      }
      case "prepare_identities": {
        const campaign = requireCampaign(this.#campaign);
        if (campaign.status !== "approved_local")
          throw new Error("LOCAL_PRODUCT_CAMPAIGN_STATE_INVALID");
        this.#identities = makeIdentities(
          campaign.contract.selectedRoles,
          this.#demoBinding,
          at,
        );
        return;
      }
      case "start_journey": {
        const campaign = requireCampaign(this.#campaign);
        if (
          campaign.status !== "approved_local" ||
          this.#identities.length !== campaign.contract.selectedRoles.length ||
          !sameRoles(input.roles, campaign.contract.selectedRoles)
        )
          throw new Error("LOCAL_PRODUCT_JOURNEY_PREREQUISITE_INVALID");
        this.#campaign = {
          ...campaign,
          revision: campaign.revision + 1,
          status: "running_local_simulation",
          updatedAt: at,
        };
        this.#journey = makeJourney(input.journeyId, input.roles, at);
        return;
      }
      case "inspect_inventory": {
        const journey = requireJourney(this.#journey);
        const campaign = requireCampaign(this.#campaign);
        if (
          journey.status !== "simulated_pending_inventory" ||
          campaign.status !== "running_local_simulation"
        )
          throw new Error("LOCAL_PRODUCT_JOURNEY_STATE_INVALID");
        this.#journey = {
          ...journey,
          status: "completed_local_simulation",
          finishedAt: at,
          updatedAt: at,
        };
        this.#inventory = makeInventory(
          at,
          campaign.policyHash,
          campaign.contract.selectedRoles,
          this.#identities,
          this.#demoBinding,
        );
        return;
      }
      case "generate_candidates":
        if (this.#inventory === null)
          throw new Error("LOCAL_PRODUCT_INVENTORY_REQUIRED");
        this.#candidates = [
          makeCandidate(
            at,
            requireCampaign(this.#campaign).contract.selectedRoles,
            requireCampaign(this.#campaign).contract.maxRequests,
            this.#demoBinding.controlledObjectRef,
          ),
        ];
        return;
      case "verify_candidate": {
        const candidate = requireCandidate(this.#candidates);
        if (candidate.status !== "generated")
          throw new Error("LOCAL_PRODUCT_CANDIDATE_STATE_INVALID");
        this.#candidates = [
          {
            ...candidate,
            status: "verified_local_fixture",
            verificationResult: "deterministic_fixture_difference_confirmed",
            verifiedAt: at,
          },
        ];
        return;
      }
      case "open_evidence": {
        const candidate = requireCandidate(this.#candidates);
        if (candidate.status !== "verified_local_fixture")
          throw new Error("LOCAL_PRODUCT_CANDIDATE_STATE_INVALID");
        this.#evidence = makeEvidence(
          at,
          requireInventory(this.#inventory),
          requirePolicy(this.#policy).policyHash,
          requireJourney(this.#journey),
          this.#demoBinding,
        );
        return;
      }
      case "create_report":
        if (this.#evidence === null)
          throw new Error("LOCAL_PRODUCT_EVIDENCE_REQUIRED");
        this.#report = makeReport(at, this.#evidence.bundleDigest);
        return;
      case "queue_report_review": {
        const report = requireReport(this.#report);
        if (report.reviewStatus !== "draft")
          throw new Error("LOCAL_PRODUCT_REPORT_STATE_INVALID");
        this.#report = {
          ...report,
          reviewStatus: "queued_for_local_review",
          queuedAt: at,
        };
        return;
      }
      case "approve_local_report": {
        const report = requireReport(this.#report);
        const campaign = requireCampaign(this.#campaign);
        if (report.reviewStatus !== "queued_for_local_review")
          throw new Error("LOCAL_PRODUCT_REPORT_STATE_INVALID");
        this.#report = {
          ...report,
          reviewStatus: "approved_local_only",
          approvedAt: at,
        };
        this.#campaign = {
          ...campaign,
          revision: campaign.revision + 1,
          status: "completed_local_only",
          updatedAt: at,
        };
        return;
      }
    }
  }

  private assertManagementAllowed(action: ManagementAction): void {
    switch (action) {
      case "edit_program":
        if (
          this.#stepIndex !== guidedIndex("import_policy") ||
          this.#program?.lifecycle !== "active" ||
          this.#program.displayName !== "Local Demo Program" ||
          this.#policy !== null
        )
          throw new Error("LOCAL_PRODUCT_MANAGEMENT_STATE_INVALID");
        return;
      case "archive_program":
        if (
          this.#stepIndex !== guidedIndex("import_policy") ||
          this.#program?.lifecycle !== "active" ||
          this.#policy !== null
        )
          throw new Error("LOCAL_PRODUCT_MANAGEMENT_STATE_INVALID");
        return;
      case "start_identity_sessions":
        if (
          this.#stepIndex !== guidedIndex("start_journey") ||
          this.#campaign === null ||
          this.#identities.length === 0 ||
          this.#identities.length !==
            this.#campaign.contract.selectedRoles.length ||
          this.#identities.some(
            ({ sessionStatus }) => sessionStatus !== "inactive",
          )
        )
          throw new Error("LOCAL_PRODUCT_MANAGEMENT_STATE_INVALID");
        return;
      case "pause_campaign":
      case "cancel_campaign":
        if (
          this.#campaign === null ||
          (this.#campaign.status !== "approved_local" &&
            this.#campaign.status !== "running_local_simulation")
        )
          throw new Error("LOCAL_PRODUCT_MANAGEMENT_STATE_INVALID");
        return;
      case "pause_journey":
      case "cancel_journey":
        if (
          this.#stepIndex !== guidedIndex("inspect_inventory") ||
          this.#journey?.status !== "simulated_pending_inventory" ||
          this.#campaign?.status !== "running_local_simulation"
        )
          throw new Error("LOCAL_PRODUCT_MANAGEMENT_STATE_INVALID");
        return;
    }
  }

  private availableManagementActions(): readonly ManagementAction[] {
    if (
      this.#terminalReason !== null ||
      this.#stepIndex === GUIDED_ACTIONS.length
    )
      return Object.freeze([]);
    const actions: ManagementAction[] = [];
    if (
      this.#stepIndex === guidedIndex("import_policy") &&
      this.#program?.lifecycle === "active" &&
      this.#policy === null
    ) {
      if (this.#program.displayName === "Local Demo Program")
        actions.push("edit_program");
      actions.push("archive_program");
    }
    if (
      this.#stepIndex === guidedIndex("start_journey") &&
      this.#campaign !== null &&
      this.#identities.length > 0 &&
      this.#identities.length ===
        this.#campaign.contract.selectedRoles.length &&
      this.#identities.every(
        ({ sessionStatus }) => sessionStatus === "inactive",
      )
    )
      actions.push("start_identity_sessions");
    if (
      this.#campaign?.status === "approved_local" ||
      this.#campaign?.status === "running_local_simulation"
    )
      actions.push("pause_campaign", "cancel_campaign");
    if (
      this.#stepIndex === guidedIndex("inspect_inventory") &&
      this.#journey?.status === "simulated_pending_inventory" &&
      this.#campaign?.status === "running_local_simulation"
    )
      actions.push("pause_journey", "cancel_journey");
    return Object.freeze(actions);
  }

  private applyManagement(action: ManagementAction, at: string): void {
    switch (action) {
      case "edit_program": {
        const program = requireProgram(this.#program);
        this.#program = {
          ...program,
          displayName: "Local Demo Program Reviewed",
          revision: program.revision + 1,
          metadataEdition: "reviewed_fixed_metadata",
          updatedAt: at,
        };
        return;
      }
      case "archive_program": {
        const program = requireProgram(this.#program);
        this.#program = {
          ...program,
          lifecycle: "archived",
          revision: program.revision + 1,
          updatedAt: at,
        };
        this.#terminalReason = "program_archived";
        return;
      }
      case "start_identity_sessions":
        this.#identities = this.#identities.map((identity) => ({
          ...identity,
          sessionStatus: "active_local" as const,
          sessionStartedAt: at,
        }));
        return;
      case "pause_campaign":
        this.haltCampaign("paused_fail_closed", "campaign_paused", at);
        return;
      case "cancel_campaign":
        this.haltCampaign("cancelled_fail_closed", "campaign_cancelled", at);
        return;
      case "pause_journey":
        this.haltJourney("paused_fail_closed", "journey_paused", at);
        return;
      case "cancel_journey":
        this.haltJourney("cancelled_fail_closed", "journey_cancelled", at);
        return;
    }
  }

  private haltCampaign(
    status: "cancelled_fail_closed" | "paused_fail_closed",
    reason: "campaign_cancelled" | "campaign_paused",
    at: string,
  ): void {
    const campaign = requireCampaign(this.#campaign);
    this.#campaign = {
      ...campaign,
      revision: campaign.revision + 1,
      status,
      updatedAt: at,
    };
    if (this.#journey?.status === "simulated_pending_inventory") {
      this.#journey = {
        ...this.#journey,
        status:
          status === "paused_fail_closed"
            ? "paused_fail_closed"
            : "cancelled_fail_closed",
        finishedAt: at,
        updatedAt: at,
      };
    }
    this.#terminalReason = reason;
  }

  private haltJourney(
    status: "cancelled_fail_closed" | "paused_fail_closed",
    reason: "journey_cancelled" | "journey_paused",
    at: string,
  ): void {
    const journey = requireJourney(this.#journey);
    const campaign = requireCampaign(this.#campaign);
    this.#journey = {
      ...journey,
      status,
      finishedAt: at,
      updatedAt: at,
    };
    this.#campaign = {
      ...campaign,
      revision: campaign.revision + 1,
      status:
        status === "paused_fail_closed"
          ? "paused_fail_closed"
          : "cancelled_fail_closed",
      updatedAt: at,
    };
    this.#terminalReason = reason;
  }

  private timestamp(): string {
    let value: unknown;
    try {
      value = this.#clock();
    } catch {
      throw new Error("LOCAL_PRODUCT_CLOCK_INVALID");
    }
    if (!(value instanceof Date))
      throw new Error("LOCAL_PRODUCT_CLOCK_INVALID");
    let milliseconds: number;
    try {
      milliseconds = value.getTime();
    } catch {
      throw new Error("LOCAL_PRODUCT_CLOCK_INVALID");
    }
    if (!Number.isFinite(milliseconds))
      throw new Error("LOCAL_PRODUCT_CLOCK_INVALID");
    if (
      this.#lastMilliseconds !== undefined &&
      milliseconds < this.#lastMilliseconds
    )
      throw new Error("LOCAL_PRODUCT_CLOCK_REGRESSION");
    this.#lastMilliseconds = milliseconds;
    return new Date(milliseconds).toISOString();
  }
}

function parseRuntimeContext(input: unknown): LocalProductRuntimeContext {
  if (!isPlainRecord(input))
    throw new Error("LOCAL_PRODUCT_RUNTIME_CONTEXT_INVALID");
  const expectedKeys = [
    "databaseStatus",
    "demoSaasStatus",
    "demoSnapshotDigest",
    "secretStoreStatus",
    "systemStatus",
  ] as const;
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(input);
  } catch {
    throw new Error("LOCAL_PRODUCT_RUNTIME_CONTEXT_INVALID");
  }
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string") ||
    !expectedKeys.every((key) => keys.includes(key))
  )
    throw new Error("LOCAL_PRODUCT_RUNTIME_CONTEXT_INVALID");

  const systemStatus = runtimeContextField(input, "systemStatus");
  const secretStoreStatus = runtimeContextField(input, "secretStoreStatus");
  const demoSaasStatus = runtimeContextField(input, "demoSaasStatus");
  const databaseStatus = runtimeContextField(input, "databaseStatus");
  const demoSnapshotDigest = runtimeContextField(input, "demoSnapshotDigest");
  if (
    !isRuntimeStatus(systemStatus) ||
    !isRuntimeStatus(secretStoreStatus) ||
    !isRuntimeStatus(demoSaasStatus) ||
    !isRuntimeStatus(databaseStatus) ||
    typeof demoSnapshotDigest !== "string" ||
    !/^[a-f0-9]{64}$/u.test(demoSnapshotDigest)
  )
    throw new Error("LOCAL_PRODUCT_RUNTIME_CONTEXT_INVALID");

  return Object.freeze({
    systemStatus,
    secretStoreStatus,
    demoSaasStatus,
    databaseStatus,
    demoSnapshotDigest,
  });
}

function parseDemoBinding(input: unknown): LocalProductDemoBinding {
  try {
    return parseDemoBindingValue(input);
  } catch {
    throw new Error("LOCAL_PRODUCT_DEMO_BINDING_INVALID");
  }
}

function parseDemoBindingValue(input: unknown): LocalProductDemoBinding {
  if (!isPlainRecord(input))
    throw new Error("LOCAL_PRODUCT_DEMO_BINDING_INVALID");
  assertExactKeys(safeKeys(input), [
    "canaryDigest",
    "controlledByRef",
    "controlledObjectRef",
    "demoPolicyHash",
    "identities",
    "organizationRef",
    "snapshotDigest",
  ]);
  const snapshotDigest = safeDataField(input, "snapshotDigest");
  const organizationRef = safeDataField(input, "organizationRef");
  const controlledObjectRef = safeDataField(input, "controlledObjectRef");
  const controlledByRef = safeDataField(input, "controlledByRef");
  const canaryDigest = safeDataField(input, "canaryDigest");
  const demoPolicyHash = safeDataField(input, "demoPolicyHash");
  const identities = strictArrayValues(
    safeDataField(input, "identities"),
    "LOCAL_PRODUCT_DEMO_BINDING_INVALID",
  );
  const expectedIdentities = [
    ["Owner", "identity-owner-001"],
    ["Member", "identity-member-001"],
    ["External", "identity-external-001"],
  ] as const;
  if (
    typeof snapshotDigest !== "string" ||
    !/^[a-f0-9]{64}$/u.test(snapshotDigest) ||
    organizationRef !== "org-demo-001" ||
    controlledObjectRef !== "object-demo-001" ||
    controlledByRef !== "identity-owner-001" ||
    typeof canaryDigest !== "string" ||
    !/^[a-f0-9]{64}$/u.test(canaryDigest) ||
    typeof demoPolicyHash !== "string" ||
    !/^[a-f0-9]{64}$/u.test(demoPolicyHash) ||
    identities.length !== expectedIdentities.length
  )
    throw new Error("LOCAL_PRODUCT_DEMO_BINDING_INVALID");

  expectedIdentities.forEach(([expectedRole, expectedIdentityRef], index) => {
    const identity = identities[index];
    if (!isPlainRecord(identity))
      throw new Error("LOCAL_PRODUCT_DEMO_BINDING_INVALID");
    assertExactKeys(safeKeys(identity), ["identityRef", "role"]);
    if (
      safeDataField(identity, "role") !== expectedRole ||
      safeDataField(identity, "identityRef") !== expectedIdentityRef
    )
      throw new Error("LOCAL_PRODUCT_DEMO_BINDING_INVALID");
  });
  const parsedIdentities = Object.freeze([
    Object.freeze({
      role: "Owner" as const,
      identityRef: "identity-owner-001" as const,
    }),
    Object.freeze({
      role: "Member" as const,
      identityRef: "identity-member-001" as const,
    }),
    Object.freeze({
      role: "External" as const,
      identityRef: "identity-external-001" as const,
    }),
  ] as const);

  return deepFreeze({
    snapshotDigest,
    organizationRef,
    identities: parsedIdentities,
    controlledObjectRef,
    controlledByRef,
    canaryDigest,
    demoPolicyHash,
  });
}

function runtimeContextField(
  value: Readonly<Record<string, unknown>>,
  key: keyof LocalProductRuntimeContext,
): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new Error("LOCAL_PRODUCT_RUNTIME_CONTEXT_INVALID");
    return descriptor.value;
  } catch {
    throw new Error("LOCAL_PRODUCT_RUNTIME_CONTEXT_INVALID");
  }
}

function isRuntimeStatus(value: unknown): value is LocalProductRuntimeStatus {
  return value === "blocked" || value === "ready" || value === "setup_required";
}

function parseAction(input: unknown): LocalProductActionInput {
  if (!isPlainRecord(input)) throw new Error("LOCAL_PRODUCT_ACTION_INVALID");
  const record = input;
  const keys = safeKeys(record);
  const action = safeDataField(record, "action");
  if (typeof action !== "string")
    throw new Error("LOCAL_PRODUCT_ACTION_INVALID");

  switch (action) {
    case "onboarding_configure_testmail": {
      assertExactKeys(keys, ["action", "schema"]);
      const schema = safeDataField(record, "schema");
      if (
        schema !== "plus_addressing_fixture" &&
        schema !== "subaddress_fixture"
      )
        throw new Error("LOCAL_PRODUCT_TESTMAIL_SCHEMA_INVALID");
      return Object.freeze({ action, schema });
    }
    case "onboarding_disable_ai": {
      assertExactKeys(keys, ["action", "provider"]);
      const provider = safeDataField(record, "provider");
      if (provider !== "disabled")
        throw new Error("LOCAL_PRODUCT_AI_PROVIDER_INVALID");
      return Object.freeze({ action, provider });
    }
    case "create_program": {
      assertExactKeys(keys, [
        "action",
        "allowedAssetRefs",
        "displayName",
        "excludedAssetRefs",
      ]);
      const displayName = safeDataField(record, "displayName");
      if (
        displayName !== "Local Demo Program" &&
        displayName !== "Local Demo Program Reviewed"
      )
        throw new Error("LOCAL_PRODUCT_PROGRAM_SELECTION_INVALID");
      return Object.freeze({
        action,
        displayName,
        allowedAssetRefs: parseAllowedAssetRefs(
          safeDataField(record, "allowedAssetRefs"),
        ),
        excludedAssetRefs: parseExcludedAssetRefs(
          safeDataField(record, "excludedAssetRefs"),
        ),
      });
    }
    case "import_policy": {
      assertExactKeys(keys, ["action", "representation"]);
      const representation = safeDataField(record, "representation");
      if (
        representation !== "human_readable_text" &&
        representation !== "structured_fixture"
      )
        throw new Error("LOCAL_PRODUCT_POLICY_REPRESENTATION_INVALID");
      return Object.freeze({ action, representation });
    }
    case "create_campaign": {
      assertExactKeys(keys, [
        "action",
        "maxConcurrency",
        "maxRequests",
        "policyVersion",
        "requestsPerMinute",
        "riskTiers",
        "roles",
      ]);
      const policyVersion = safeDataField(record, "policyVersion");
      const maxRequests = safeDataField(record, "maxRequests");
      const requestsPerMinute = safeDataField(record, "requestsPerMinute");
      const maxConcurrency = safeDataField(record, "maxConcurrency");
      if (
        policyVersion !== 1 ||
        (maxRequests !== 0 && maxRequests !== 4 && maxRequests !== 8) ||
        (requestsPerMinute !== 0 &&
          requestsPerMinute !== 1 &&
          requestsPerMinute !== 2) ||
        maxConcurrency !== 1
      )
        throw new Error("LOCAL_PRODUCT_CAMPAIGN_SELECTION_INVALID");
      return Object.freeze({
        action,
        policyVersion,
        roles: parseRoleSelection(safeDataField(record, "roles")),
        riskTiers: parseRiskTiers(safeDataField(record, "riskTiers")),
        maxRequests,
        requestsPerMinute,
        maxConcurrency,
      });
    }
    case "start_journey": {
      assertConfirmation(record, keys);
      assertExactKeys(keys, ["action", "confirmed", "journeyId", "roles"]);
      const journeyId = safeDataField(record, "journeyId");
      if (journeyId !== LOCAL_JOURNEY_CATALOG_ID)
        throw new Error("LOCAL_PRODUCT_JOURNEY_SELECTION_INVALID");
      return Object.freeze({
        action,
        confirmed: true,
        journeyId,
        roles: parseRoleSelection(safeDataField(record, "roles")),
      });
    }
  }

  if (isGenericConfirmationAction(action)) {
    assertConfirmation(record, keys);
    assertExactKeys(keys, ["action", "confirmed"]);
    return Object.freeze({ action, confirmed: true });
  }

  if (isActionOnlyAction(action)) {
    assertExactKeys(keys, ["action"]);
    return Object.freeze({ action });
  }

  throw new Error("LOCAL_PRODUCT_ACTION_UNKNOWN");
}

function assertConfirmation(
  value: Readonly<Record<string, unknown>>,
  keys: readonly string[],
): void {
  if (!keys.includes("confirmed") || safeDataField(value, "confirmed") !== true)
    throw new Error("LOCAL_PRODUCT_CONFIRMATION_REQUIRED");
}

function parseAllowedAssetRefs(
  value: unknown,
): readonly ["asset-local-primary"] {
  const selected = parseUniqueSelection(
    value,
    ["asset-local-primary"],
    true,
    "LOCAL_PRODUCT_PROGRAM_ASSETS_INVALID",
  );
  if (selected.length !== 1 || selected[0] !== "asset-local-primary")
    throw new Error("LOCAL_PRODUCT_PROGRAM_ASSETS_INVALID");
  return Object.freeze(["asset-local-primary"]);
}

function parseExcludedAssetRefs(value: unknown): ExcludedAssetSelection {
  const selected = parseUniqueSelection(
    value,
    ["asset-local-administration"],
    false,
    "LOCAL_PRODUCT_PROGRAM_ASSETS_INVALID",
  );
  if (selected.length === 0) return Object.freeze([]);
  if (selected.length !== 1 || selected[0] !== "asset-local-administration")
    throw new Error("LOCAL_PRODUCT_PROGRAM_ASSETS_INVALID");
  return Object.freeze(["asset-local-administration"] as const);
}

function parseRiskTiers(value: unknown): readonly ["tier_0_offline"] {
  const selected = parseUniqueSelection(
    value,
    ["tier_0_offline"],
    true,
    "LOCAL_PRODUCT_CAMPAIGN_RISK_TIERS_INVALID",
  );
  if (selected.length !== 1 || selected[0] !== "tier_0_offline")
    throw new Error("LOCAL_PRODUCT_CAMPAIGN_RISK_TIERS_INVALID");
  return Object.freeze(["tier_0_offline"]);
}

function parseRoleSelection(value: unknown): LocalRoles {
  const selected = parseUniqueSelection(
    value,
    LOCAL_ROLES,
    true,
    "LOCAL_PRODUCT_ROLES_INVALID",
  );
  if (
    selected.length !== LOCAL_ROLES.length ||
    !LOCAL_ROLES.every((role, index) => selected[index] === role)
  )
    throw new Error("LOCAL_PRODUCT_ROLES_INVALID");
  return Object.freeze(["Owner", "Member", "External"]);
}

function parseUniqueSelection<const T extends string>(
  value: unknown,
  allowed: readonly T[],
  nonEmpty: boolean,
  errorCode: string,
): readonly T[] {
  const values = strictArrayValues(value, errorCode);
  if ((nonEmpty && values.length === 0) || values.length > allowed.length)
    throw new Error(errorCode);
  const selected = new Set<T>();
  for (const valueItem of values) {
    if (typeof valueItem !== "string") throw new Error(errorCode);
    const matched = allowed.find((candidate) => candidate === valueItem);
    if (matched === undefined || selected.has(matched))
      throw new Error(errorCode);
    selected.add(matched);
  }
  return Object.freeze(allowed.filter((candidate) => selected.has(candidate)));
}

function strictArrayValues(
  value: unknown,
  errorCode: string,
): readonly unknown[] {
  if (!isUnknownArray(value)) throw new Error(errorCode);
  try {
    if (Object.getPrototypeOf(value) !== Array.prototype)
      throw new Error(errorCode);
    const keys = Reflect.ownKeys(value);
    const expected = [
      ...Array.from({ length: value.length }, (_, index) => String(index)),
      "length",
    ].sort(compareAscii);
    const actual = keys
      .map((key) => (typeof key === "string" ? key : "__symbol_invalid__"))
      .sort(compareAscii);
    if (
      actual.length !== expected.length ||
      actual.some((key, index) => key !== expected[index])
    )
      throw new Error(errorCode);
    const result: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !("value" in descriptor))
        throw new Error(errorCode);
      result.push(descriptor.value);
    }
    return Object.freeze(result);
  } catch {
    throw new Error(errorCode);
  }
}

function safeKeys(value: Readonly<Record<string, unknown>>): readonly string[] {
  try {
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string"))
      throw new Error("LOCAL_PRODUCT_ACTION_FIELDS_INVALID");
    return keys.map(String).sort(compareAscii);
  } catch {
    throw new Error("LOCAL_PRODUCT_ACTION_FIELDS_INVALID");
  }
}

function safeDataField(
  value: Readonly<Record<string, unknown>>,
  field: string,
): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (descriptor === undefined || !("value" in descriptor))
      throw new Error("LOCAL_PRODUCT_ACTION_INVALID");
    return descriptor.value;
  } catch {
    throw new Error("LOCAL_PRODUCT_ACTION_INVALID");
  }
}

function assertExactKeys(
  actual: readonly string[],
  expected: readonly string[],
): void {
  const sortedExpected = [...expected].sort(compareAscii);
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  )
    throw new Error("LOCAL_PRODUCT_ACTION_FIELDS_INVALID");
}

function isGenericConfirmationAction(
  value: string,
): value is GenericConfirmationAction {
  return value !== "start_journey" && CONFIRMATION_SET.has(value);
}

function isActionOnlyAction(value: string): value is ActionOnlyAction {
  return (
    (GUIDED_SET.has(value) &&
      !CONFIRMATION_SET.has(value) &&
      value !== "onboarding_configure_testmail" &&
      value !== "onboarding_disable_ai" &&
      value !== "create_program" &&
      value !== "import_policy" &&
      value !== "create_campaign") ||
    MANAGEMENT_SET.has(value)
  );
}

function isManagementAction(value: string): value is ManagementAction {
  return MANAGEMENT_SET.has(value);
}

function isPlainRecord(
  value: unknown,
): value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  try {
    return Object.getPrototypeOf(value) === Object.prototype;
  } catch {
    return false;
  }
}

function isUnknownArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}

function stageFor(index: number): WorkflowStage {
  if (index < 7) return "onboarding";
  if (index < 10) return "program_policy";
  if (index < 12) return "campaign";
  if (index < 14) return "identities_journey";
  if (index < 15) return "inventory";
  if (index < 18) return "candidates_evidence";
  return "reporting";
}

function guidedIndex(action: GuidedAction): number {
  const index = GUIDED_ACTIONS.indexOf(action);
  if (index < 0) throw new Error("LOCAL_PRODUCT_ACTION_UNKNOWN");
  return index;
}

function policyHashFor(
  allowedAssets: readonly ["asset-local-primary"],
  excludedAssets: ExcludedAssetSelection,
  representation: PolicyRepresentation,
): string {
  return sha256(
    canonicalJson({
      version: 1,
      representation,
      allowedAssets,
      excludedAssets,
      allowedTestClasses: ["offline_metadata_review"],
      forbiddenTestClasses: ["active_security_test"],
      maxRequests: 8,
      requestsPerMinute: 2,
      maxConcurrency: 1,
    }),
  );
}

function policySourcePreview(
  representation: PolicyRepresentation,
  allowedAssets: readonly ["asset-local-primary"],
  excludedAssets: ExcludedAssetSelection,
): string {
  if (representation === "human_readable_text")
    return [
      "Lokale Fixture-Policy, Version 1.",
      `Erlaubte Assets: ${allowedAssets.join(", ")}.`,
      `Ausgeschlossene Assets: ${excludedAssets.join(", ") || "keine"}.`,
      "Erlaubte Testklasse: offline_metadata_review.",
      "Verbotene Testklasse: active_security_test.",
      "Grenzen: 8 gesamt, 2 pro Minute, Parallelität 1.",
    ].join(" ");
  return canonicalJson({
    version: 1,
    allowedAssets,
    excludedAssets,
    allowedTestClasses: ["offline_metadata_review"],
    forbiddenTestClasses: ["active_security_test"],
    requestLimits: { maximum: 8, perMinute: 2, concurrency: 1 },
  });
}

function sameRoles(
  left: readonly LocalRole[],
  right: readonly LocalRole[],
): boolean {
  return (
    left.length === right.length &&
    left.every((role, index) => role === right[index])
  );
}

function makeIdentities(
  roles: LocalRoles,
  demoBinding: LocalProductDemoBinding,
  at: string,
): readonly IdentitySnapshot[] {
  return Object.freeze(
    roles.map((role) =>
      makeIdentity(identityIdForRole(role, demoBinding), role, demoBinding, at),
    ),
  );
}

function makeIdentity(
  id: IdentitySnapshot["id"],
  role: IdentitySnapshot["role"],
  demoBinding: LocalProductDemoBinding,
  at: string,
): IdentitySnapshot {
  const controlsObject = id === demoBinding.controlledByRef;
  return {
    badges: BADGES,
    id,
    role,
    status: "ready_local_fixture",
    localFixture: true,
    checkpointFreeFixture: true,
    humanActionRequired: false,
    organizationRef: demoBinding.organizationRef,
    ownedObjectRefs: controlsObject
      ? Object.freeze([demoBinding.controlledObjectRef])
      : Object.freeze([]),
    sessionStatus: "inactive",
    preparedAt: at,
    sessionStartedAt: null,
  };
}

function identityIdForRole(
  role: LocalRole,
  demoBinding: LocalProductDemoBinding,
): IdentitySnapshot["id"] {
  const identity = demoBinding.identities.find(
    (candidate) => candidate.role === role,
  );
  if (identity === undefined)
    throw new Error("LOCAL_PRODUCT_DEMO_BINDING_INVALID");
  return identity.identityRef;
}

function makeJourney(
  id: typeof LOCAL_JOURNEY_CATALOG_ID,
  roles: LocalRoles,
  at: string,
): JourneySnapshot {
  const catalogDigestSha256 = PHASE7_CATALOG_BINDING.digestSha256;
  return {
    badges: BADGES,
    id,
    catalogDigestSha256,
    campaignId: "campaign-local-demo",
    status: "simulated_pending_inventory",
    execution: "simulated_metadata_only",
    testHarnessValidated: validatePhase7CatalogBinding(id, catalogDigestSha256),
    browserStarted: false,
    networkRequests: 0,
    roles,
    liveSteps: makeJourneySteps(roles),
    startedAt: at,
    finishedAt: null,
    updatedAt: at,
  };
}

function validatePhase7CatalogBinding(id: string, digestSha256: string): true {
  // This is a build-time catalog equality marker only. It never starts a
  // browser and does not turn the presentation workflow into a test runner.
  if (
    id !== PHASE7_CATALOG_BINDING.id ||
    digestSha256 !== LOCAL_JOURNEY_CATALOG_DIGEST_SHA256 ||
    !/^[a-f0-9]{64}$/u.test(digestSha256)
  )
    throw new Error("LOCAL_PRODUCT_JOURNEY_CATALOG_BINDING_INVALID");
  return true;
}

function makeJourneySteps(roles: LocalRoles): readonly JourneyStepSnapshot[] {
  let sequence = 0;
  return roles.flatMap((role) =>
    LOCAL_JOURNEY_ROLE_PLANS[role].map((step) => ({
      sequence: (sequence += 1),
      catalogIndex: step.index,
      role,
      method: step.method,
      path: step.path,
      capability: step.capability,
      fromState: step.fromState,
      successState: step.successState,
      execution: "catalog_projection_only" as const,
      result: "validated_fixture" as const,
    })),
  );
}

function makeInventory(
  at: string,
  policyHash: string,
  roles: LocalRoles,
  identities: readonly IdentitySnapshot[],
  demoBinding: LocalProductDemoBinding,
): InventorySnapshot {
  if (
    identities.length !== roles.length ||
    !identities.some(({ id }) => id === demoBinding.controlledByRef)
  )
    throw new Error("LOCAL_PRODUCT_INVENTORY_IDENTITIES_INVALID");
  return {
    badges: BADGES,
    status: "inspected_local",
    applicationInventory: [
      {
        applicationRef: "application-local-demo",
        source: "deterministic_demo_fixture",
        status: "available_local_fixture",
        externalTransport: false,
      },
    ],
    endpointInventory: [
      {
        endpointRef: "endpoint-project-summary",
        applicationRef: "application-local-demo",
        operation: "project_metadata_read",
        method: "GET",
        inApprovedScope: true,
      },
      {
        endpointRef: "endpoint-document-summary",
        applicationRef: "application-local-demo",
        operation: "document_metadata_read",
        method: "GET",
        inApprovedScope: true,
      },
    ],
    roleMatrix: roles.map(makeRoleMatrixEntry),
    ownershipGraph: {
      identityRefs: identities.map(({ id }) => id),
      objectRefs: [demoBinding.controlledObjectRef],
      edges: [
        {
          from: demoBinding.controlledByRef,
          to: demoBinding.controlledObjectRef,
          relation: "controls",
        },
      ],
      allObjectsResearcherControlled: true,
    },
    canary: {
      digest: demoBinding.canaryDigest,
      valueExposed: false,
      verified: true,
    },
    policyAssignment: {
      policyHash,
      demoSourcePolicyHash: demoBinding.demoPolicyHash,
      assetRef: "asset-local-primary",
      status: "assigned_exact",
    },
    campaignAssignment: {
      campaignId: "campaign-local-demo",
      assetRef: "asset-local-primary",
      status: "assigned_exact",
    },
    inspectedAt: at,
  };
}

function makeRoleMatrixEntry(
  role: LocalRole,
): InventorySnapshot["roleMatrix"][number] {
  switch (role) {
    case "Owner":
      return {
        role,
        endpointRefs: ["endpoint-project-summary", "endpoint-document-summary"],
        expectedAccess: "fixture_metadata_allowed",
      };
    case "Member":
      return {
        role,
        endpointRefs: ["endpoint-document-summary"],
        expectedAccess: "fixture_metadata_allowed",
      };
    case "External":
      return {
        role,
        endpointRefs: ["endpoint-project-summary"],
        expectedAccess: "fixture_metadata_restricted",
      };
  }
}

function makeCandidate(
  at: string,
  roles: LocalRoles,
  maximumRequests: CampaignMaxRequests,
  controlledObjectRef: LocalProductDemoBinding["controlledObjectRef"],
): CandidateSnapshot {
  return {
    badges: BADGES,
    id: "candidate-local-role-boundary",
    campaignId: "campaign-local-demo",
    inventoryRef: "endpoint-document-summary",
    title: "Deterministic role boundary observation",
    hypothesis: "Role projections differ in the deterministic fixture",
    vulnerabilityClass: "authorization_boundary_metadata",
    roles,
    ownedObjectRefs: [controlledObjectRef],
    mutation: "none_read_only",
    riskTier: "tier_0_offline",
    requestBudget: {
      maximum: maximumRequests,
      consumed: 0,
    },
    priority: "low",
    falsePositiveReasons: [
      "deterministic_fixture_expected_variance",
      "no_external_effect",
    ],
    privacyStatus: "redacted_metadata_only",
    severity: "informational",
    status: "generated",
    activeTestPerformed: false,
    verificationResult: null,
    generatedAt: at,
    verifiedAt: null,
  };
}

function makeEvidence(
  at: string,
  inventory: InventorySnapshot,
  policyHash: string,
  journey: JourneySnapshot,
  demoBinding: LocalProductDemoBinding,
): EvidenceSnapshot {
  if (
    journey.catalogDigestSha256 !== LOCAL_JOURNEY_CATALOG_DIGEST_SHA256 ||
    !sameRoles(journey.roles, LOCAL_ROLES)
  )
    throw new Error("LOCAL_PRODUCT_EVIDENCE_SOURCE_INVALID");
  const baseline = makeEvidenceItem(
    "baseline",
    "Owner",
    identityIdForRole("Owner", demoBinding),
    "owner_metadata_visible",
    at,
  );
  const test = makeEvidenceItem(
    "test",
    "External",
    identityIdForRole("External", demoBinding),
    "external_metadata_restricted",
    at,
  );
  const control = makeEvidenceItem(
    "control",
    "Member",
    identityIdForRole("Member", demoBinding),
    "member_metadata_expected",
    at,
  );
  const items = [baseline, test, control] as const;
  const objectRef = inventory.ownershipGraph.objectRefs[0];
  const ownershipProof = {
    objectRef,
    controllerIdentityRef: demoBinding.controlledByRef,
    researcherControlled: true as const,
    digest: sha256(
      canonicalJson({
        objectRef,
        controllerIdentityRef: demoBinding.controlledByRef,
        researcherControlled: true,
        policyHash,
        demoSnapshotDigest: demoBinding.snapshotDigest,
      }),
    ),
  };
  const canaryProof = {
    digest: inventory.canary.digest,
    valueExposed: false as const,
  };
  const auditReferences = ["guided-demo:evidence-open:no-core-audit"] as const;
  const demoSnapshotDigest = demoBinding.snapshotDigest;
  const demoPolicyHash = demoBinding.demoPolicyHash;
  const journeyId = journey.id;
  const journeyCatalogDigest = journey.catalogDigestSha256;
  const selectedRoles = journey.roles;
  const bundleDigest = sha256(
    canonicalJson({
      items,
      ownershipProof,
      canaryProof,
      policyHash,
      demoPolicyHash,
      demoSnapshotDigest,
      journeyId,
      journeyCatalogDigest,
      selectedRoles,
      auditReferences,
    }),
  );
  return {
    badges: BADGES,
    status: "open_local_bundle",
    candidateId: "candidate-local-role-boundary",
    items,
    bundleDigest,
    ownershipProof,
    canaryProof,
    policyHash,
    demoPolicyHash,
    demoSnapshotDigest,
    journeyId,
    journeyCatalogDigest,
    selectedRoles,
    auditReferences,
    openedAt: at,
  };
}

function makeEvidenceItem(
  kind: EvidenceItemSnapshot["kind"],
  role: LocalRole,
  identityRef: IdentitySnapshot["id"],
  observation: string,
  at: string,
): EvidenceItemSnapshot {
  const metadata = {
    candidateId: "candidate-local-role-boundary" as const,
    role,
    identityRef,
    observation,
    projection: "metadata_only" as const,
  };
  return {
    kind,
    digest: sha256(canonicalJson({ kind, metadata })),
    metadata,
    rawPayloadStored: false,
    visualBytesStored: false,
    capturedAt: at,
  };
}

function makeReport(at: string, evidenceDigest: string): ReportSnapshot {
  const markdown = [
    "# Local simulation role boundary report",
    "",
    "Scope: deterministic local fixture.",
    "Observation: role projections differ as designed.",
    "Verification: metadata comparison only.",
    "External action: none.",
  ].join("\n");
  const html =
    "<article><h1>Local simulation role boundary report</h1><p>Deterministic local fixture.</p><p>Metadata comparison only.</p><p>External action: none.</p></article>";
  const json = canonicalJson({
    version: 1,
    reportId: "report-local-role-boundary",
    candidateId: "candidate-local-role-boundary",
    evidenceDigest,
    result: "verified_local_fixture",
    redacted: true,
    externalAction: false,
  });
  return {
    badges: BADGES,
    id: "report-local-role-boundary",
    candidateId: "candidate-local-role-boundary",
    title: "Local simulation role boundary report",
    reviewStatus: "draft",
    redacted: true,
    externalSubmissionPerformed: false,
    artifacts: {
      markdown,
      html,
      json,
      markdownDigest: sha256(markdown),
      htmlDigest: sha256(html),
      jsonDigest: sha256(json),
    },
    createdAt: at,
    queuedAt: null,
    approvedAt: null,
  };
}

function requireProgram(value: ProgramSnapshot | null): ProgramSnapshot {
  if (value === null) throw new Error("LOCAL_PRODUCT_PROGRAM_REQUIRED");
  return value;
}

function requirePolicy(value: PolicySnapshot | null): PolicySnapshot {
  if (value === null) throw new Error("LOCAL_PRODUCT_POLICY_REQUIRED");
  return value;
}

function requireCampaign(value: CampaignSnapshot | null): CampaignSnapshot {
  if (value === null) throw new Error("LOCAL_PRODUCT_CAMPAIGN_REQUIRED");
  return value;
}

function requireJourney(value: JourneySnapshot | null): JourneySnapshot {
  if (value === null) throw new Error("LOCAL_PRODUCT_JOURNEY_REQUIRED");
  return value;
}

function requireCandidate(
  values: readonly CandidateSnapshot[],
): CandidateSnapshot {
  const candidate = values[0];
  if (candidate === undefined || values.length !== 1)
    throw new Error("LOCAL_PRODUCT_CANDIDATE_REQUIRED");
  return candidate;
}

function requireReport(value: ReportSnapshot | null): ReportSnapshot {
  if (value === null) throw new Error("LOCAL_PRODUCT_REPORT_REQUIRED");
  return value;
}

function requireInventory(value: InventorySnapshot | null): InventorySnapshot {
  if (value === null) throw new Error("LOCAL_PRODUCT_INVENTORY_REQUIRED");
  return value;
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.isFrozen(value) ? value : Object.freeze(value);
}
