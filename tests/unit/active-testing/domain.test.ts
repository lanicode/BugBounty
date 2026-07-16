import { describe, expect, it } from "vitest";
import {
  ACTIVE_TEST_RUNNER_VERSION,
  activeTestCatalogDigest,
  activeTestPlanDigest,
  createActiveTestPlan,
  isTrustedActiveTestingRuntime,
  listActiveTestCatalog,
  projectActiveTestAsset,
  resolveActiveTestingRuntime,
  validateAndFreezeActiveTestPlan,
} from "../../../packages/active-testing/index.js";
import { sha256 } from "../../../packages/shared/canonical.js";
import {
  ACTIVE_TEST_PROGRAM_REF,
  ACTIVE_TEST_TIME,
  activeTestPlanInput,
  activeTestProgram,
  activeTestScope,
  activeTestSnapshot,
} from "../../fixtures/active-testing.factory.js";

function runtime(overrides: Record<string, unknown> = {}) {
  return {
    version: 1,
    capability: "HACKERONE_ACTIVE_TEST",
    external_integrations_enabled: false,
    enabled: false,
    request_budget: {
      max_requests_total: 5,
      requests_per_minute: 1,
      max_concurrency: 1,
    },
    request_timeout_ms: 5_000,
    max_response_bytes: 32_768,
    ...overrides,
  };
}

describe("active testing runtime", () => {
  it("is disabled unless both independent external switches are true", () => {
    const disabled = resolveActiveTestingRuntime(runtime());
    const partiallyEnabled = resolveActiveTestingRuntime(
      runtime({ enabled: true }),
    );
    const enabled = resolveActiveTestingRuntime(
      runtime({ external_integrations_enabled: true, enabled: true }),
    );

    expect(disabled.configured).toBe(false);
    expect(partiallyEnabled.configured).toBe(false);
    expect(enabled).toMatchObject({
      configured: true,
      runnerVersion: ACTIVE_TEST_RUNNER_VERSION,
      requestBudget: {
        maxRequestsTotal: 5,
        requestsPerMinute: 1,
        maxConcurrency: 1,
      },
    });
    expect(isTrustedActiveTestingRuntime(enabled)).toBe(true);
    expect(isTrustedActiveTestingRuntime(Object.freeze({ ...enabled }))).toBe(
      false,
    );
  });

  it.each([
    { external_integrations_enabled: "true" },
    {
      request_budget: {
        max_requests_total: 11,
        requests_per_minute: 1,
        max_concurrency: 1,
      },
    },
    {
      request_budget: {
        max_requests_total: 1,
        requests_per_minute: 3,
        max_concurrency: 1,
      },
    },
    {
      request_budget: {
        max_requests_total: 1,
        requests_per_minute: 1,
        max_concurrency: 2,
      },
    },
    { request_timeout_ms: 10_001 },
    { max_response_bytes: 65_537 },
    { unexpected: true },
  ])("rejects invalid or expansive runtime input %#", (override) => {
    expect(() => resolveActiveTestingRuntime(runtime(override))).toThrow(
      "ACTIVE_TEST_RUNTIME_INVALID",
    );
  });
});

describe("active testing asset projection", () => {
  it("supports only exact canonical bounty-eligible HTTPS URL scopes", () => {
    expect(projectActiveTestAsset(activeTestScope())).toEqual({
      scopeId: "scope-active-001",
      assetType: "URL",
      displayIdentifier: "https://synthetic-target.bounty-safe.dev/",
      assetIdentifierDigest: sha256(
        "https://synthetic-target.bounty-safe.dev/",
      ),
      eligibleForSubmission: true,
      eligibleForBounty: true,
      supported: true,
      reasonCodes: [],
    });
  });

  it.each([
    ["https://*.invalid/", "URL", "ACTIVE_TEST_TARGET_WILDCARD_BLOCKED"],
    [
      "http://synthetic-target.bounty-safe.dev/",
      "URL",
      "ACTIVE_TEST_TARGET_NOT_HTTPS",
    ],
    [
      "https://synthetic-target.bounty-safe.dev:8443/",
      "URL",
      "ACTIVE_TEST_TARGET_PORT_BLOCKED",
    ],
    [
      "https://synthetic-target.bounty-safe.dev/?free=input",
      "URL",
      "ACTIVE_TEST_TARGET_NONCANONICAL",
    ],
    [
      "https://synthetic-target.bounty-safe.dev/a%2Fb",
      "URL",
      "ACTIVE_TEST_TARGET_PATH_UNSUPPORTED",
    ],
    [
      "https://synthetic-target.bounty-safe.dev/a//b",
      "URL",
      "ACTIVE_TEST_TARGET_PATH_UNSUPPORTED",
    ],
    [
      "https://synthetic-target.bounty-safe.dev/%2561dmin",
      "URL",
      "ACTIVE_TEST_TARGET_PATH_UNSUPPORTED",
    ],
    [
      "https://synthetic-target.bounty-safe.dev/a%00b",
      "URL",
      "ACTIVE_TEST_TARGET_PATH_UNSUPPORTED",
    ],
    ["https://foo/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://a..b/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://-a.example/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://a-.example/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://foo_bar.example/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://target.local/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://x.localhost/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://x.home.arpa/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://x.onion/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://x.invalid/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://x.test/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    ["https://x.example/", "URL", "ACTIVE_TEST_TARGET_NONCANONICAL"],
    [
      "synthetic-target.bounty-safe.dev",
      "DOMAIN",
      "ACTIVE_TEST_ASSET_TYPE_UNSUPPORTED",
    ],
  ])("blocks unsupported target %s", (identifier, type, reason) => {
    const projected = projectActiveTestAsset(
      activeTestScope({
        assetType: type,
        assetIdentifier: identifier,
        assetIdentifierDigest: sha256(identifier),
      }),
    );
    expect(projected.supported).toBe(false);
    expect(projected.reasonCodes).toContain(reason);
  });

  it("requires both submission and bounty eligibility", () => {
    expect(
      projectActiveTestAsset(
        activeTestScope({
          eligibleForSubmission: false,
          eligibleForBounty: false,
        }),
      ).reasonCodes,
    ).toEqual([
      "ACTIVE_TEST_SCOPE_SUBMISSION_INELIGIBLE",
      "ACTIVE_TEST_SCOPE_BOUNTY_INELIGIBLE",
    ]);
  });
});

describe("active test plan", () => {
  it.each([
    ["http_headers", "HEAD", "metadata_v1", "/"],
    ["cors_preflight", "OPTIONS", "cors_probe_v1", "/"],
    ["security_txt", "GET", "metadata_v1", "/.well-known/security.txt"],
  ] as const)(
    "creates a closed %s plan without caller-controlled request material",
    (testClass, method, profile, path) => {
      const plan = createActiveTestPlan(activeTestPlanInput({ testClass }));
      expect(plan).toMatchObject({
        program_ref: ACTIVE_TEST_PROGRAM_REF,
        test_class: testClass,
        runner_version: ACTIVE_TEST_RUNNER_VERSION,
        target: {
          scheme: "https",
          host: "synthetic-target.bounty-safe.dev",
          port: 443,
          path,
        },
        request: {
          method,
          header_profile: profile,
          capture_mode: "metadata_only",
          follow_redirects: false,
          retries: 0,
        },
        budget: {
          max_requests_total: 1,
          requests_per_minute: 1,
          max_concurrency: 1,
        },
      });
      expect(Object.isFrozen(plan)).toBe(true);
      expect(Object.isFrozen(plan.target)).toBe(true);
      expect(validateAndFreezeActiveTestPlan(plan)).toEqual(plan);
      expect(activeTestPlanDigest(plan)).toMatch(/^[a-f0-9]{64}$/u);
    },
  );

  it.each([
    [
      activeTestSnapshot({ source: "manual_unverified" }),
      "ACTIVE_TEST_API_SOURCE_REQUIRED",
    ],
    [
      activeTestSnapshot({
        program: activeTestProgram({
          policy: "Automated scanning is prohibited.",
        }),
      }),
      "ACTIVE_TEST_POLICY_AUTOMATION_FORBIDDEN",
    ],
    [
      activeTestSnapshot({
        program: activeTestProgram({ submissionState: "closed" }),
      }),
      "ACTIVE_TEST_PROGRAM_SUBMISSIONS_CLOSED",
    ],
  ] as const)("blocks an unsafe snapshot", (snapshot, code) => {
    expect(() =>
      createActiveTestPlan(activeTestPlanInput({ snapshot })),
    ).toThrow(code);
  });

  it("binds the exact server-side scope id and asset digest", () => {
    expect(() =>
      createActiveTestPlan(
        activeTestPlanInput({ assetIdentifierDigest: "b".repeat(64) }),
      ),
    ).toThrow("ACTIVE_TEST_SCOPE_BINDING_INVALID");
    expect(() =>
      createActiveTestPlan(activeTestPlanInput({ scopeId: "other-scope" })),
    ).toThrow("ACTIVE_TEST_SCOPE_BINDING_INVALID");
  });

  it("requires all explicit human review confirmations", () => {
    const input = activeTestPlanInput();
    expect(() =>
      createActiveTestPlan({
        ...input,
        confirmations: {
          ...input.confirmations,
          automationPermissionReviewed: false,
        },
      }),
    ).toThrow("ACTIVE_TEST_PLAN_INPUT_INVALID");
  });

  it("blocks security.txt when the selected scope is path-limited", () => {
    const scope = activeTestScope({
      assetIdentifier: "https://synthetic-target.bounty-safe.dev/application/",
      assetIdentifierDigest: sha256(
        "https://synthetic-target.bounty-safe.dev/application/",
      ),
    });
    const snapshot = activeTestSnapshot({ scopes: [scope] });
    expect(() =>
      createActiveTestPlan(
        activeTestPlanInput({ snapshot, testClass: "security_txt" }),
      ),
    ).toThrow("ACTIVE_TEST_TARGET_PATH_UNSUPPORTED");
  });

  it("rejects every caller mutation of method, redirects, budget or runner", () => {
    const plan = createActiveTestPlan(activeTestPlanInput());
    const mutations = [
      { ...plan, runner_version: "other" },
      { ...plan, request: { ...plan.request, method: "POST" } },
      { ...plan, request: { ...plan.request, follow_redirects: true } },
      { ...plan, request: { ...plan.request, retries: 1 } },
      { ...plan, budget: { ...plan.budget, max_requests_total: 2 } },
      { ...plan, unexpected: true },
    ];
    for (const mutation of mutations)
      expect(() => validateAndFreezeActiveTestPlan(mutation)).toThrow();
  });

  it("rejects proxies and accessors before schema evaluation", () => {
    const plan = createActiveTestPlan(activeTestPlanInput());
    expect(() => validateAndFreezeActiveTestPlan(new Proxy(plan, {}))).toThrow(
      "ACTIVE_TEST_PLAN_SCHEMA_INVALID",
    );
    const accessor = { ...plan } as Record<string, unknown>;
    Object.defineProperty(accessor, "plan_id", {
      enumerable: true,
      get: () => "active-plan-001",
    });
    expect(() => validateAndFreezeActiveTestPlan(accessor)).toThrow(
      "ACTIVE_TEST_PLAN_SCHEMA_INVALID",
    );
  });

  it("publishes a stable closed catalog digest", () => {
    expect(listActiveTestCatalog().map((entry) => entry.id)).toEqual([
      "http_headers",
      "cors_preflight",
      "security_txt",
    ]);
    expect(activeTestCatalogDigest()).toMatch(/^[a-f0-9]{64}$/u);
    expect(activeTestCatalogDigest()).toBe(activeTestCatalogDigest());
  });

  it("uses canonical timestamps and a ten-minute plan lifetime", () => {
    const plan = createActiveTestPlan(activeTestPlanInput());
    expect(plan.created_at).toBe(ACTIVE_TEST_TIME);
    expect(Date.parse(plan.expires_at) - Date.parse(plan.created_at)).toBe(
      10 * 60_000,
    );
  });
});
