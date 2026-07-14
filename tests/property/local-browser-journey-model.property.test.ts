import fc from "fast-check";
import { expect, it } from "vitest";
import {
  JOURNEY_ROLES,
  assertLoopbackOrigin,
  finalizeJourneyEvidence,
  isAllowedJourneyRequest,
  journeyPlan,
  type JourneyRole,
} from "../browser/support/journey-model.js";

const roleArbitrary = fc.constantFrom<JourneyRole>(...JOURNEY_ROLES);
const HEX_CHARACTERS = [
  "0",
  "1",
  "2",
  "3",
  "4",
  "5",
  "6",
  "7",
  "8",
  "9",
  "a",
  "b",
  "c",
  "d",
  "e",
  "f",
] as const;
const sha256Arbitrary = fc
  .array(fc.constantFrom(...HEX_CHARACTERS), {
    minLength: 64,
    maxLength: 64,
  })
  .map((characters) => characters.join(""));

it("accepts exactly canonical non-privileged loopback origins", () => {
  fc.assert(
    fc.property(fc.integer({ min: 1_024, max: 65_535 }), (port) => {
      const origin = `http://127.0.0.1:${String(port)}`;
      expect(assertLoopbackOrigin(origin)).toBe(origin);
      expect(() => assertLoopbackOrigin(`${origin}/`)).toThrow();
      expect(() => assertLoopbackOrigin(`${origin}?x=1`)).toThrow();
      expect(() =>
        assertLoopbackOrigin(`http://user@127.0.0.1:${String(port)}`),
      ).toThrow();
      expect(() =>
        assertLoopbackOrigin(`http://127.0.0.1:0${String(port)}`),
      ).toThrow();
    }),
    { numRuns: 200 },
  );
});

it("allows only the current fixed GET step and rejects arbitrary URL mutations", () => {
  fc.assert(
    fc.property(
      roleArbitrary,
      fc.integer({ min: 0, max: 7 }),
      fc.string(),
      fc.string(),
      (role, candidateIndex, suffix, method) => {
        const plan = journeyPlan(role);
        const index = candidateIndex % plan.length;
        const step = plan[index];
        if (step === undefined) throw new Error("JOURNEY_STEP_MISSING");
        const origin = "http://127.0.0.1:49152";
        const expected = `${origin}${step.path}`;
        expect(
          isAllowedJourneyRequest(role, index, expected, "GET", origin),
        ).toBe(true);
        const mutated = `${expected}${suffix}`;
        expect(
          isAllowedJourneyRequest(role, index, mutated, method, origin),
        ).toBe(mutated === expected && method === "GET");
        expect(
          isAllowedJourneyRequest(
            role,
            index,
            expected,
            "GET",
            "http://127.0.0.1:49153",
          ),
        ).toBe(false);
      },
    ),
    { numRuns: 500 },
  );
});

it("builds deterministic minimal evidence and binds every response digest", () => {
  fc.assert(
    fc.property(roleArbitrary, sha256Arbitrary, (role, responseDigest) => {
      const steps = journeyPlan(role).map(() => ({
        outcome: "success" as const,
        recordCount: 1,
        redactedScreenshotByteLength: 4_096,
        redactedScreenshotDigestSha256: responseDigest,
        responseDigestSha256: responseDigest,
        statusCode: 200,
      }));
      const first = finalizeJourneyEvidence({
        role,
        status: "completed",
        blockedRequestCount: 0,
        steps,
      });
      const second = finalizeJourneyEvidence({
        role,
        status: "completed",
        blockedRequestCount: 0,
        steps: steps.map((step) => ({ ...step })),
      });
      expect(second).toEqual(first);
      expect(first.observedStepCount).toBe(journeyPlan(role).length);
      expect(first.statusCodes).toEqual(journeyPlan(role).map(() => 200));
      expect(first.recordCounts).toEqual(journeyPlan(role).map(() => 1));
      expect(first.redactedScreenshotByteLengths).toEqual(
        journeyPlan(role).map(() => 4_096),
      );
      expect(first.redactedScreenshotDigestsSha256).toEqual(
        journeyPlan(role).map(() => responseDigest),
      );
      expect(JSON.stringify(first)).not.toContain("/api/");
      expect(JSON.stringify(first)).not.toContain("http://");

      const replacement = `${responseDigest.startsWith("a") ? "b" : "a"}${responseDigest.slice(1)}`;
      const changedResponse = finalizeJourneyEvidence({
        role,
        status: "completed",
        blockedRequestCount: 0,
        steps: steps.map((step, index) =>
          index === 0
            ? { ...step, responseDigestSha256: replacement }
            : { ...step },
        ),
      });
      expect(changedResponse.evidenceDigestSha256).not.toBe(
        first.evidenceDigestSha256,
      );
      expect(changedResponse.planDigestSha256).toBe(first.planDigestSha256);

      const changedScreenshot = finalizeJourneyEvidence({
        role,
        status: "completed",
        blockedRequestCount: 0,
        steps: steps.map((step, index) =>
          index === 0
            ? { ...step, redactedScreenshotDigestSha256: replacement }
            : { ...step },
        ),
      });
      expect(changedScreenshot.evidenceDigestSha256).not.toBe(
        first.evidenceDigestSha256,
      );
      expect(changedScreenshot.redactedScreenshotDigestsSha256[0]).toBe(
        replacement,
      );

      const changedCounts = finalizeJourneyEvidence({
        role,
        status: "completed",
        blockedRequestCount: 0,
        steps: steps.map((step, index) =>
          index === 0
            ? {
                ...step,
                recordCount: 2,
                redactedScreenshotByteLength: 4_097,
              }
            : { ...step },
        ),
      });
      expect(changedCounts.evidenceDigestSha256).not.toBe(
        first.evidenceDigestSha256,
      );
      expect(changedCounts.recordCounts[0]).toBe(2);
      expect(changedCounts.redactedScreenshotByteLengths[0]).toBe(4_097);
    }),
    { numRuns: 200 },
  );
});
