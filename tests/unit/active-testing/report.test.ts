import { describe, expect, it } from "vitest";
import {
  activeTestObservationDigest,
  activeTestPlanDigest,
  analyzeActiveTestEvidence,
  createActiveTestPlan,
  createLocalActiveTestReportDraft,
  reconstructLocalActiveTestReportDraft,
  validateAndFreezeActiveTestObservation,
  type ActiveTestPlanV1,
  type ActiveTestRedactedResponseMetadata,
} from "../../../packages/active-testing/index.js";
import { canonicalJson, sha256 } from "../../../packages/shared/canonical.js";
import { activeTestPlanInput } from "../../fixtures/active-testing.factory.js";

const COMPLETED_AT = "2026-07-15T12:00:01.000Z";

function plan(
  testClass: ActiveTestPlanV1["test_class"] = "http_headers",
): ActiveTestPlanV1 {
  return createActiveTestPlan(activeTestPlanInput({ testClass }));
}

function metadata(
  selectedPlan: ActiveTestPlanV1,
  overrides: Partial<ActiveTestRedactedResponseMetadata> = {},
): ActiveTestRedactedResponseMetadata {
  const classSpecific =
    selectedPlan.test_class === "cors_preflight"
      ? {
          statusCode: 204,
          responseBytesObserved: 0,
          contentType: null,
          facts: {
            kind: "cors_preflight" as const,
            allowOrigin: "probe_origin" as const,
            allowCredentials: true,
          },
          responseDigest: null,
        }
      : selectedPlan.test_class === "security_txt"
        ? {
            statusCode: 200,
            responseBytesObserved: 128,
            contentType: "text/plain" as const,
            facts: {
              kind: "security_txt" as const,
              availability: "available" as const,
            },
            responseDigest: sha256("redacted-security-txt-metadata"),
          }
        : {
            statusCode: 200,
            responseBytesObserved: 0,
            contentType: "text/html" as const,
            facts: {
              kind: "http_headers" as const,
              contentSecurityPolicyPresent: false,
              strictTransportSecurityPresent: false,
              xContentTypeOptionsNosniff: false,
              insecureCookieFlagsObserved: true,
            },
            responseDigest: null,
          };
  return {
    version: 1,
    planId: selectedPlan.plan_id,
    planDigest: activeTestPlanDigest(selectedPlan),
    testClass: selectedPlan.test_class,
    durationMs: 37,
    redirectLocationPresent: false,
    tls: {
      authorized: true,
      protocol: "TLSv1.3",
      cipher: "modern",
    },
    transport: {
      kind: "production_https",
      resolutionDigest: sha256("test-production-resolution"),
    },
    redaction: {
      status: "complete",
      rawBodyStored: false,
      rawHeadersStored: false,
      cookiesStored: false,
    },
    completedAt: COMPLETED_AT,
    ...classSpecific,
    ...overrides,
  };
}

describe("active testing evidence analysis", () => {
  it("derives only fixed metadata signals and freezes the complete observation", () => {
    const selectedPlan = plan();
    const observation = analyzeActiveTestEvidence(
      selectedPlan,
      metadata(selectedPlan),
    );

    expect(observation.signals.map((signal) => signal.code)).toEqual([
      "HEADER_CONTENT_SECURITY_POLICY_MISSING",
      "HEADER_HSTS_MISSING",
      "HEADER_X_CONTENT_TYPE_OPTIONS_MISSING",
      "INSECURE_COOKIE_FLAGS_OBSERVED",
    ]);
    expect(observation).toMatchObject({
      planId: selectedPlan.plan_id,
      planDigest: activeTestPlanDigest(selectedPlan),
      testClass: "http_headers",
      rawBodyStored: false,
      rawHeadersStored: false,
      cookiesStored: false,
    });
    expect(Object.isFrozen(observation)).toBe(true);
    expect(Object.isFrozen(observation.tls)).toBe(true);
    expect(Object.isFrozen(observation.signals)).toBe(true);
    expect(observation.signals.every((signal) => Object.isFrozen(signal))).toBe(
      true,
    );
    expect(activeTestObservationDigest(observation)).toBe(
      sha256(canonicalJson(observation)),
    );
  });

  it("derives CORS findings only from closed redacted classifications", () => {
    const selectedPlan = plan("cors_preflight");
    const observation = analyzeActiveTestEvidence(
      selectedPlan,
      metadata(selectedPlan),
    );
    expect(observation.signals.map((signal) => signal.code)).toEqual([
      "CORS_CREDENTIALS_WITH_REFLECTED_ORIGIN",
      "CORS_REFLECTS_PROBE_ORIGIN",
    ]);
    expect(observation.signals.map((signal) => signal.severity)).toEqual([
      "medium",
      "low",
    ]);
  });

  it("binds signal-equivalent redacted classifications into distinct evidence", () => {
    const selectedPlan = plan("cors_preflight");
    const absent = analyzeActiveTestEvidence(
      selectedPlan,
      metadata(selectedPlan, {
        facts: {
          kind: "cors_preflight",
          allowOrigin: "absent",
          allowCredentials: false,
        },
      }),
    );
    const wildcard = analyzeActiveTestEvidence(
      selectedPlan,
      metadata(selectedPlan, {
        facts: {
          kind: "cors_preflight",
          allowOrigin: "wildcard",
          allowCredentials: false,
        },
      }),
    );

    expect(absent.signals).toEqual([]);
    expect(wildcard.signals).toEqual([]);
    expect(wildcard.metadataDigest).not.toBe(absent.metadataDigest);
    expect(activeTestObservationDigest(wildcard)).not.toBe(
      activeTestObservationDigest(absent),
    );
  });

  it("distinguishes available and missing security.txt metadata", () => {
    const selectedPlan = plan("security_txt");
    expect(
      analyzeActiveTestEvidence(selectedPlan, metadata(selectedPlan)).signals[0]
        ?.code,
    ).toBe("SECURITY_TXT_AVAILABLE");

    const missing = metadata(selectedPlan, {
      statusCode: 404,
      responseBytesObserved: 0,
      contentType: null,
      facts: { kind: "security_txt", availability: "missing" },
      responseDigest: null,
    });
    expect(
      analyzeActiveTestEvidence(selectedPlan, missing).signals[0]?.code,
    ).toBe("SECURITY_TXT_MISSING");
  });

  it("requires exact plan, digest and test-class bindings", () => {
    const selectedPlan = plan();
    const valid = metadata(selectedPlan);
    for (const candidate of [
      { ...valid, planId: "other-plan" },
      { ...valid, planDigest: "b".repeat(64) },
      { ...valid, testClass: "cors_preflight" },
    ])
      expect(() => analyzeActiveTestEvidence(selectedPlan, candidate)).toThrow(
        "ACTIVE_TEST_EVIDENCE_BINDING_INVALID",
      );
  });

  it("requires the supplied validated plan and every nested record to be frozen", () => {
    const selectedPlan = plan();
    const valid = metadata(selectedPlan);
    expect(() => analyzeActiveTestEvidence({ ...selectedPlan }, valid)).toThrow(
      "ACTIVE_TEST_EVIDENCE_PLAN_NOT_FROZEN",
    );

    const mutableTarget = Object.freeze({
      ...selectedPlan,
      target: { ...selectedPlan.target },
    });
    expect(() => analyzeActiveTestEvidence(mutableTarget, valid)).toThrow(
      "ACTIVE_TEST_EVIDENCE_PLAN_NOT_FROZEN",
    );
  });

  it("rejects proxies, accessors, symbol keys and schema expansion before analysis", () => {
    const selectedPlan = plan();
    const valid = metadata(selectedPlan);
    expect(() =>
      analyzeActiveTestEvidence(selectedPlan, new Proxy(valid, {})),
    ).toThrow("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");

    const accessor = { ...valid } as Record<string, unknown>;
    Object.defineProperty(accessor, "planDigest", {
      enumerable: true,
      get: () => activeTestPlanDigest(selectedPlan),
    });
    expect(() => analyzeActiveTestEvidence(selectedPlan, accessor)).toThrow(
      "ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID",
    );

    const nestedAccessor = { ...valid.facts } as Record<string, unknown>;
    Object.defineProperty(nestedAccessor, "contentSecurityPolicyPresent", {
      enumerable: true,
      get: () => false,
    });
    expect(() =>
      analyzeActiveTestEvidence(selectedPlan, {
        ...valid,
        facts: nestedAccessor,
      }),
    ).toThrow("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");

    expect(() =>
      analyzeActiveTestEvidence(selectedPlan, {
        ...valid,
        rawHeaders: "secret-header-value",
      }),
    ).toThrow("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");
    expect(() =>
      analyzeActiveTestEvidence(selectedPlan, {
        ...valid,
        [Symbol("unexpected")]: true,
      }),
    ).toThrow("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");
  });

  it.each([
    [
      (valid: ActiveTestRedactedResponseMetadata) => ({
        ...valid,
        redaction: { ...valid.redaction, rawHeadersStored: true },
      }),
      "ACTIVE_TEST_EVIDENCE_REDACTION_REQUIRED",
    ],
    [
      (valid: ActiveTestRedactedResponseMetadata) => ({
        ...valid,
        redirectLocationPresent: true,
      }),
      "ACTIVE_TEST_EVIDENCE_REDIRECT_BLOCKED",
    ],
    [
      (valid: ActiveTestRedactedResponseMetadata) => ({
        ...valid,
        statusCode: 302,
      }),
      "ACTIVE_TEST_EVIDENCE_REDIRECT_BLOCKED",
    ],
    [
      (valid: ActiveTestRedactedResponseMetadata) => ({
        ...valid,
        contentType: "application/octet-stream",
      }),
      "ACTIVE_TEST_EVIDENCE_CONTENT_TYPE_BLOCKED",
    ],
    [
      (valid: ActiveTestRedactedResponseMetadata) => ({
        ...valid,
        completedAt: "2026-07-15T12:10:00.001Z",
      }),
      "ACTIVE_TEST_EVIDENCE_TIME_INVALID",
    ],
  ])("blocks unsafe or unredacted metadata %#", (mutate, errorCode) => {
    const selectedPlan = plan();
    expect(() =>
      analyzeActiveTestEvidence(selectedPlan, mutate(metadata(selectedPlan))),
    ).toThrow(errorCode);
  });

  it("rejects body-like evidence for HEAD and inconsistent security.txt facts", () => {
    const headerPlan = plan();
    expect(() =>
      analyzeActiveTestEvidence(headerPlan, {
        ...metadata(headerPlan),
        responseBytesObserved: 1,
        responseDigest: sha256("forbidden-head-body"),
      }),
    ).toThrow("ACTIVE_TEST_EVIDENCE_SEMANTICS_INVALID");

    const securityTxtPlan = plan("security_txt");
    expect(() =>
      analyzeActiveTestEvidence(securityTxtPlan, {
        ...metadata(securityTxtPlan),
        responseDigest: null,
      }),
    ).toThrow("ACTIVE_TEST_EVIDENCE_SEMANTICS_INVALID");
  });

  it("strictly validates observations before computing their digest", () => {
    const selectedPlan = plan();
    const observation = analyzeActiveTestEvidence(
      selectedPlan,
      metadata(selectedPlan),
    );
    expect(() =>
      validateAndFreezeActiveTestObservation(new Proxy(observation, {})),
    ).toThrow("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
    expect(() =>
      validateAndFreezeActiveTestObservation({
        ...observation,
        unexpected: true,
      }),
    ).toThrow("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
    expect(() =>
      validateAndFreezeActiveTestObservation({
        ...observation,
        signals: observation.signals.map((signal, index) =>
          index === 0 ? { ...signal, evidence: "caller-controlled" } : signal,
        ),
      }),
    ).toThrow("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");

    const corsPlan = plan("cors_preflight");
    const corsObservation = analyzeActiveTestEvidence(
      corsPlan,
      metadata(corsPlan),
    );
    expect(() =>
      validateAndFreezeActiveTestObservation({
        ...corsObservation,
        signals: [corsObservation.signals[0]!],
      }),
    ).toThrow("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
  });
});

describe("local active testing report", () => {
  it("creates a deterministic canonical local-only draft without target or raw material", () => {
    const selectedPlan = plan();
    const response = metadata(selectedPlan);
    const first = createLocalActiveTestReportDraft(selectedPlan, response);
    const second = createLocalActiveTestReportDraft(selectedPlan, response);

    expect(first).toEqual(second);
    expect(Object.isFrozen(first)).toBe(true);
    expect(first.reviewStatus).toBe("local_draft_unsubmitted");
    expect(first.externalSubmissionPerformed).toBe(false);
    expect(first.planDigest).toBe(activeTestPlanDigest(selectedPlan));
    expect(first.markdownDigest).toBe(sha256(first.markdown));
    expect(first.jsonDigest).toBe(sha256(first.json));
    expect(first.json).toBe(canonicalJson(JSON.parse(first.json)));

    const combined = `${first.markdown}\n${first.json}`;
    expect(combined).not.toContain(selectedPlan.target.host);
    expect(combined).not.toContain("secret-header-value");
    expect(combined).not.toContain("Set-Cookie:");
    expect(combined).not.toContain("Authorization:");
    expect(combined).toContain("local_draft_unsubmitted");
    expect(combined).toContain("External submission performed: false");
  });

  it("derives the report identifier solely from canonical bound material", () => {
    const selectedPlan = plan("cors_preflight");
    const first = createLocalActiveTestReportDraft(
      selectedPlan,
      metadata(selectedPlan),
    );
    const changed = createLocalActiveTestReportDraft(
      selectedPlan,
      metadata(selectedPlan, { durationMs: 38 }),
    );
    expect(first.reportId).toMatch(/^active-report-[a-f0-9]{64}$/u);
    expect(changed.reportId).not.toBe(first.reportId);
    expect(changed.observationDigest).not.toBe(first.observationDigest);
  });

  it("rejects a schema-valid observation rebound across test classes", () => {
    const headerPlan = plan("http_headers");
    const corsPlan = plan("cors_preflight");
    const corsObservation = analyzeActiveTestEvidence(
      corsPlan,
      metadata(corsPlan),
    );
    const reboundObservation = {
      ...corsObservation,
      planId: headerPlan.plan_id,
      planDigest: activeTestPlanDigest(headerPlan),
    };

    expect(() =>
      reconstructLocalActiveTestReportDraft(headerPlan, reboundObservation),
    ).toThrow("ACTIVE_TEST_REPORT_EVIDENCE_INVALID");
  });
});
