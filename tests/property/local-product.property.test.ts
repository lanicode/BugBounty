import fc from "fast-check";
import { expect, it } from "vitest";
import {
  LocalProductWorkflow,
  type LocalProductDemoBinding,
  type LocalProductRuntimeContext,
} from "../../packages/local-product/index.js";

const DEMO_DIGEST = "a".repeat(64);
const RUNTIME = Object.freeze({
  systemStatus: "ready",
  secretStoreStatus: "setup_required",
  demoSaasStatus: "ready",
  databaseStatus: "ready",
  demoSnapshotDigest: DEMO_DIGEST,
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

const KNOWN_ACTIONS = new Set([
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
  "edit_program",
  "archive_program",
  "pause_campaign",
  "cancel_campaign",
  "pause_journey",
  "cancel_journey",
  "start_identity_sessions",
]);

function workflow(): LocalProductWorkflow {
  return new LocalProductWorkflow(
    () => new Date("2026-07-14T12:00:00.000Z"),
    RUNTIME,
    DEMO_BINDING,
  );
}

function runToCampaign(instance: LocalProductWorkflow): void {
  instance.perform({ action: "onboarding_system_check" });
  instance.perform({ action: "onboarding_secret_store_check" });
  instance.perform({ action: "onboarding_select_simulation" });
  instance.perform({
    action: "onboarding_configure_testmail",
    schema: "plus_addressing_fixture",
  });
  instance.perform({ action: "onboarding_disable_ai", provider: "disabled" });
  instance.perform({
    action: "onboarding_confirm_boundaries",
    confirmed: true,
  });
  instance.perform({ action: "onboarding_initialize_demo" });
  instance.perform({
    action: "create_program",
    displayName: "Local Demo Program",
    allowedAssetRefs: ["asset-local-primary"],
    excludedAssetRefs: [],
  });
  instance.perform({
    action: "import_policy",
    representation: "structured_fixture",
  });
  instance.perform({ action: "accept_policy", confirmed: true });
}

it("rejects arbitrary unknown action names without mutating state", () => {
  fc.assert(
    fc.property(
      fc.string().filter((action) => !KNOWN_ACTIONS.has(action)),
      (action) => {
        const instance = workflow();
        const before = JSON.stringify(instance.snapshot());
        expect(() => instance.perform({ action })).toThrow(/LOCAL_PRODUCT_/u);
        expect(JSON.stringify(instance.snapshot())).toBe(before);
      },
    ),
    { numRuns: 100 },
  );
});

it("rejects arbitrary additional fields on otherwise valid initial actions", () => {
  fc.assert(
    fc.property(fc.anything(), (unexpected) => {
      const instance = workflow();
      const before = JSON.stringify(instance.snapshot());
      expect(() =>
        instance.perform({
          action: "onboarding_system_check",
          unexpected,
        }),
      ).toThrow("LOCAL_PRODUCT_ACTION_FIELDS_INVALID");
      expect(JSON.stringify(instance.snapshot())).toBe(before);
    }),
    { numRuns: 100 },
  );
});

it("rejects arbitrary non-true confirmation values", () => {
  fc.assert(
    fc.property(
      fc.anything().filter((confirmed) => confirmed !== true),
      (confirmed) => {
        const instance = workflow();
        instance.perform({ action: "onboarding_system_check" });
        instance.perform({ action: "onboarding_secret_store_check" });
        instance.perform({ action: "onboarding_select_simulation" });
        instance.perform({
          action: "onboarding_configure_testmail",
          schema: "plus_addressing_fixture",
        });
        instance.perform({
          action: "onboarding_disable_ai",
          provider: "disabled",
        });
        const before = JSON.stringify(instance.snapshot());
        expect(() =>
          instance.perform({
            action: "onboarding_confirm_boundaries",
            confirmed,
          }),
        ).toThrow("LOCAL_PRODUCT_CONFIRMATION_REQUIRED");
        expect(JSON.stringify(instance.snapshot())).toBe(before);
      },
    ),
    { numRuns: 100 },
  );
});

it("rejects arbitrary role selections outside the complete three-role fixture", () => {
  const allowed = new Set(["Owner", "Member", "External"]);
  fc.assert(
    fc.property(
      fc
        .array(fc.string(), { maxLength: 6 })
        .filter(
          (roles) =>
            roles.length !== 3 ||
            roles.some((role) => !allowed.has(role)) ||
            new Set(roles).size !== roles.length,
        ),
      (roles) => {
        const instance = workflow();
        runToCampaign(instance);
        const before = JSON.stringify(instance.snapshot());
        expect(() =>
          instance.perform({
            action: "create_campaign",
            policyVersion: 1,
            roles,
            riskTiers: ["tier_0_offline"],
            maxRequests: 4,
            requestsPerMinute: 1,
            maxConcurrency: 1,
          }),
        ).toThrow("LOCAL_PRODUCT_ROLES_INVALID");
        expect(JSON.stringify(instance.snapshot())).toBe(before);
      },
    ),
    { numRuns: 100 },
  );
});
