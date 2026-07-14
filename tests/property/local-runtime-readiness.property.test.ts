import fc from "fast-check";
import { expect, it } from "vitest";
import {
  deriveRuntimeReadiness,
  type RuntimeReadinessInput,
} from "../../packages/local-runtime/index.js";

const safeLabel = fc.stringMatching(/^[A-Za-z][A-Za-z0-9_-]{7,31}$/u);
const eventMinimum = fc.oneof(
  fc.integer({ min: 1, max: 10_000 }),
  fc.integer({ min: 1, max: 10_000 }).map(String),
);
const positiveRevision = fc.oneof(
  fc.integer({ min: 1, max: 1_000_000 }),
  fc.integer({ min: 1, max: 1_000_000 }).map(String),
);

function validInput(
  service: string,
  account: string,
  operatorId: string,
  eventKeyMinimumVersion: number | string,
  operatorKeyRevision: number | string,
): RuntimeReadinessInput {
  return {
    platform: "darwin",
    eventKeyMinimumVersion,
    operatorKeyReference: `keychain://${service}/${account}`,
    operatorId,
    operatorKeyRevision,
    secretStoreProbe: "available",
    demoSaasReady: true,
    databaseReady: true,
  };
}

function isPositiveCanonicalInteger(value: unknown, maximum: number): boolean {
  if (typeof value === "number")
    return Number.isSafeInteger(value) && value > 0 && value <= maximum;
  if (typeof value !== "string" || !/^[1-9][0-9]*$/u.test(value)) return false;
  const parsed = Number(value);
  return (
    Number.isSafeInteger(parsed) &&
    parsed > 0 &&
    parsed <= maximum &&
    String(parsed) === value
  );
}

function independentlyReady(input: RuntimeReadinessInput): boolean {
  const reference = input.operatorKeyReference;
  const referenceMatch =
    typeof reference === "string" && reference.length <= 512
      ? /^keychain:\/\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._/-]+)$/u.exec(reference)
      : null;
  return (
    input.platform === "darwin" &&
    isPositiveCanonicalInteger(input.eventKeyMinimumVersion, 10_000) &&
    referenceMatch?.[1] !== undefined &&
    referenceMatch[2] !== undefined &&
    !referenceMatch[2].includes("..") &&
    typeof input.operatorId === "string" &&
    /^[A-Za-z0-9._@-]{1,128}$/u.test(input.operatorId) &&
    isPositiveCanonicalInteger(
      input.operatorKeyRevision,
      Number.MAX_SAFE_INTEGER,
    ) &&
    input.secretStoreProbe === "available" &&
    input.demoSaasReady &&
    input.databaseReady
  );
}

it("never throws or returns a mutable projection for arbitrary inputs", () => {
  fc.assert(
    fc.property(fc.anything(), (input) => {
      expect(() => deriveRuntimeReadiness(input)).not.toThrow();
      const readiness = deriveRuntimeReadiness(input);
      expect(Object.isFrozen(readiness)).toBe(true);
      expect(Object.isFrozen(readiness.reasonCodes)).toBe(true);
      expect(readiness.ready).toBe(readiness.status === "ready");
      expect(readiness.externalIntegrationsEnabled).toBe(false);
      expect(readiness.killSwitchAssumedActive).toBe(true);
    }),
    { numRuns: 1_000 },
  );
});

it("never reports arbitrary exact field records ready unless every gate validates", () => {
  const arbitraryRecord = fc.record({
    platform: fc.anything(),
    eventKeyMinimumVersion: fc.anything(),
    operatorKeyReference: fc.anything(),
    operatorId: fc.anything(),
    operatorKeyRevision: fc.anything(),
    secretStoreProbe: fc.anything(),
    demoSaasReady: fc.anything(),
    databaseReady: fc.anything(),
  });

  fc.assert(
    fc.property(arbitraryRecord, (input) => {
      const readiness = deriveRuntimeReadiness(input);
      const typedInput: RuntimeReadinessInput = {
        platform:
          typeof input.platform === "string" ? input.platform : "invalid",
        eventKeyMinimumVersion: input.eventKeyMinimumVersion,
        operatorKeyReference: input.operatorKeyReference,
        operatorId: input.operatorId,
        operatorKeyRevision: input.operatorKeyRevision,
        secretStoreProbe:
          input.secretStoreProbe === "not_checked" ||
          input.secretStoreProbe === "available" ||
          input.secretStoreProbe === "unavailable" ||
          input.secretStoreProbe === "error"
            ? input.secretStoreProbe
            : "error",
        demoSaasReady:
          typeof input.demoSaasReady === "boolean"
            ? input.demoSaasReady
            : false,
        databaseReady:
          typeof input.databaseReady === "boolean"
            ? input.databaseReady
            : false,
      };
      const hasValidBaseTypes =
        typeof input.platform === "string" &&
        (input.secretStoreProbe === "not_checked" ||
          input.secretStoreProbe === "available" ||
          input.secretStoreProbe === "unavailable" ||
          input.secretStoreProbe === "error") &&
        typeof input.demoSaasReady === "boolean" &&
        typeof input.databaseReady === "boolean";

      expect(readiness.ready).toBe(
        hasValidBaseTypes && independentlyReady(typedInput),
      );
    }),
    { numRuns: 1_000 },
  );
});

it("returns ready only for exact validated records and blocks extra fields", () => {
  fc.assert(
    fc.property(
      safeLabel,
      safeLabel,
      safeLabel,
      eventMinimum,
      positiveRevision,
      fc.stringMatching(/^[A-Za-z][A-Za-z0-9_]{8,30}$/u),
      (
        service,
        account,
        operatorId,
        eventMinimum,
        operatorRevision,
        extraKey,
      ) => {
        const input = validInput(
          service,
          account,
          operatorId,
          eventMinimum,
          operatorRevision,
        );
        expect(deriveRuntimeReadiness(input).ready).toBe(true);

        const withExtra = { ...input, [`extra_${extraKey}`]: true };
        const blocked = deriveRuntimeReadiness(withExtra);
        expect(blocked.ready).toBe(false);
        expect(blocked.reasonCodes).toEqual(["RUNTIME_INPUT_INVALID"]);
      },
    ),
    { numRuns: 300 },
  );
});

it("does not copy arbitrary valid secret markers into JSON output", () => {
  fc.assert(
    fc.property(
      safeLabel,
      eventMinimum,
      positiveRevision,
      (marker, minimum, revision) => {
        const input = validInput(marker, marker, marker, minimum, revision);
        const readiness = deriveRuntimeReadiness(input);
        const serialized = JSON.stringify(readiness);

        expect(readiness.ready).toBe(true);
        expect(serialized).not.toContain(marker);
        expect(serialized).not.toContain("keychain://");
      },
    ),
    { numRuns: 300 },
  );
});
