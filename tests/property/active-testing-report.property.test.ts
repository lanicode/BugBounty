import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  activeTestObservationDigest,
  activeTestPlanDigest,
  analyzeActiveTestEvidence,
  createActiveTestPlan,
  createLocalActiveTestReportDraft,
  type ActiveTestPlanV1,
  type ActiveTestRedactedContentType,
  type ActiveTestRedactedResponseMetadata,
  type ActiveTestTlsCipherClassification,
  type ActiveTestTlsProtocol,
} from "../../packages/active-testing/index.js";
import { canonicalJson, sha256 } from "../../packages/shared/canonical.js";
import { activeTestPlanInput } from "../fixtures/active-testing.factory.js";

interface MetadataSample {
  readonly completedOffsetMs: number;
  readonly contentSecurityPolicyPresent: boolean;
  readonly contentType: ActiveTestRedactedContentType;
  readonly durationMs: number;
  readonly insecureCookieFlagsObserved: boolean;
  readonly statusCode: number;
  readonly strictTransportSecurityPresent: boolean;
  readonly tlsCipher: ActiveTestTlsCipherClassification;
  readonly tlsProtocol: ActiveTestTlsProtocol;
  readonly xContentTypeOptionsNosniff: boolean;
}

const sampleArbitrary: fc.Arbitrary<MetadataSample> = fc.record({
  completedOffsetMs: fc.integer({ min: 0, max: 10 * 60_000 }),
  contentSecurityPolicyPresent: fc.boolean(),
  contentType: fc.constantFrom(
    null,
    "application/json",
    "application/security.txt",
    "text/html",
    "text/plain",
  ),
  durationMs: fc.integer({ min: 0, max: 10_000 }),
  insecureCookieFlagsObserved: fc.boolean(),
  statusCode: fc.oneof(
    fc.integer({ min: 200, max: 299 }),
    fc.integer({ min: 400, max: 599 }),
  ),
  strictTransportSecurityPresent: fc.boolean(),
  tlsCipher: fc.constantFrom("modern", "other_redacted"),
  tlsProtocol: fc.constantFrom("TLSv1.2", "TLSv1.3"),
  xContentTypeOptionsNosniff: fc.boolean(),
});

function metadata(
  selectedPlan: ActiveTestPlanV1,
  sample: MetadataSample,
): ActiveTestRedactedResponseMetadata {
  return {
    version: 1,
    planId: selectedPlan.plan_id,
    planDigest: activeTestPlanDigest(selectedPlan),
    testClass: "http_headers",
    statusCode: sample.statusCode,
    durationMs: sample.durationMs,
    responseBytesObserved: 0,
    contentType: sample.contentType,
    redirectLocationPresent: false,
    tls: {
      authorized: true,
      protocol: sample.tlsProtocol,
      cipher: sample.tlsCipher,
    },
    transport: {
      kind: "production_https",
      resolutionDigest: sha256("property-production-resolution"),
    },
    facts: {
      kind: "http_headers",
      contentSecurityPolicyPresent: sample.contentSecurityPolicyPresent,
      strictTransportSecurityPresent: sample.strictTransportSecurityPresent,
      xContentTypeOptionsNosniff: sample.xContentTypeOptionsNosniff,
      insecureCookieFlagsObserved: sample.insecureCookieFlagsObserved,
    },
    responseDigest: null,
    redaction: {
      status: "complete",
      rawBodyStored: false,
      rawHeadersStored: false,
      cookiesStored: false,
    },
    completedAt: new Date(
      Date.parse(selectedPlan.created_at) + sample.completedOffsetMs,
    ).toISOString(),
  };
}

describe("active testing report properties", () => {
  const selectedPlan = createActiveTestPlan(activeTestPlanInput());

  it("always produces deterministic canonical local-only artifacts", () => {
    fc.assert(
      fc.property(sampleArbitrary, (sample) => {
        const response = metadata(selectedPlan, sample);
        const observation = analyzeActiveTestEvidence(selectedPlan, response);
        const report = createLocalActiveTestReportDraft(selectedPlan, response);

        expect(observation.metadataDigest).toBe(
          sha256(canonicalJson(response)),
        );
        expect(activeTestObservationDigest(observation)).toBe(
          sha256(canonicalJson(observation)),
        );
        expect(
          createLocalActiveTestReportDraft(selectedPlan, response),
        ).toEqual(report);
        expect(report.reviewStatus).toBe("local_draft_unsubmitted");
        expect(report.externalSubmissionPerformed).toBe(false);
        expect(report.responseMetadataDigest).toBe(observation.metadataDigest);
        expect(report.json).toBe(canonicalJson(JSON.parse(report.json)));
        expect(`${report.markdown}\n${report.json}`).not.toContain(
          selectedPlan.target.host,
        );
        expect(report.json).toContain('"rawBodyStored":false');
        expect(report.json).toContain('"rawHeadersStored":false');
        expect(report.json).toContain('"cookiesStored":false');
      }),
      { numRuns: 150 },
    );
  });

  it("binds every accepted metadata variation into both evidence digests", () => {
    const baselineSample: MetadataSample = {
      completedOffsetMs: 1_000,
      contentSecurityPolicyPresent: true,
      contentType: "text/html",
      durationMs: 10,
      insecureCookieFlagsObserved: false,
      statusCode: 200,
      strictTransportSecurityPresent: true,
      tlsCipher: "modern",
      tlsProtocol: "TLSv1.3",
      xContentTypeOptionsNosniff: true,
    };
    const baselineMetadata = metadata(selectedPlan, baselineSample);
    const baselineObservation = analyzeActiveTestEvidence(
      selectedPlan,
      baselineMetadata,
    );
    const baselineObservationDigest =
      activeTestObservationDigest(baselineObservation);

    fc.assert(
      fc.property(sampleArbitrary, (sample) => {
        const candidateMetadata = metadata(selectedPlan, sample);
        if (
          canonicalJson(candidateMetadata) === canonicalJson(baselineMetadata)
        )
          return;
        const candidate = analyzeActiveTestEvidence(
          selectedPlan,
          candidateMetadata,
        );
        expect(candidate.metadataDigest).not.toBe(
          baselineObservation.metadataDigest,
        );
        expect(activeTestObservationDigest(candidate)).not.toBe(
          baselineObservationDigest,
        );
      }),
      { numRuns: 150 },
    );
  });

  it("rejects every arbitrary schema expansion before inspecting its value", () => {
    const baseline: MetadataSample = {
      completedOffsetMs: 1_000,
      contentSecurityPolicyPresent: true,
      contentType: "text/html",
      durationMs: 10,
      insecureCookieFlagsObserved: false,
      statusCode: 200,
      strictTransportSecurityPresent: true,
      tlsCipher: "modern",
      tlsProtocol: "TLSv1.3",
      xContentTypeOptionsNosniff: true,
    };
    const expectedKeys = new Set(Object.keys(metadata(selectedPlan, baseline)));
    fc.assert(
      fc.property(
        fc
          .string({ minLength: 1, maxLength: 40 })
          .filter((key) => !expectedKeys.has(key)),
        fc.jsonValue(),
        (key, value) => {
          expect(() =>
            analyzeActiveTestEvidence(selectedPlan, {
              ...metadata(selectedPlan, baseline),
              [key]: value,
            }),
          ).toThrow("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");
        },
      ),
      { numRuns: 100 },
    );
  });

  it("never accepts any positive raw-retention flag", () => {
    const baseline: MetadataSample = {
      completedOffsetMs: 1_000,
      contentSecurityPolicyPresent: true,
      contentType: "text/html",
      durationMs: 10,
      insecureCookieFlagsObserved: false,
      statusCode: 200,
      strictTransportSecurityPresent: true,
      tlsCipher: "modern",
      tlsProtocol: "TLSv1.3",
      xContentTypeOptionsNosniff: true,
    };
    fc.assert(
      fc.property(
        fc.constantFrom("rawBodyStored", "rawHeadersStored", "cookiesStored"),
        (field) => {
          const response = metadata(selectedPlan, baseline);
          expect(() =>
            analyzeActiveTestEvidence(selectedPlan, {
              ...response,
              redaction: { ...response.redaction, [field]: true },
            }),
          ).toThrow("ACTIVE_TEST_EVIDENCE_REDACTION_REQUIRED");
        },
      ),
      { numRuns: 60 },
    );
  });
});
