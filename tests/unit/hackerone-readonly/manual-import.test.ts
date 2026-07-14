import { describe, expect, it } from "vitest";
import { sha256 } from "../../../packages/shared/canonical.js";
import { parseHackerOneManualImport } from "../../../packages/hackerone-readonly/manual-import.js";

const IMPORTED_AT = "2026-07-14T12:00:00.000Z";

function document(): Record<string, unknown> {
  return {
    version: 1,
    program: {
      hackerOneId: "manual-synthetic-program-001",
      handle: "manual_synthetic_program",
      name: "Manual Synthetic Program",
      currency: "USD",
      policy: "Locally supplied unverified policy text.",
      submissionState: "open",
      programState: "public_mode",
      offersBounties: false,
      openScope: false,
      goldStandardSafeHarbor: false,
      bookmarked: false,
      ownReportCount: 0,
      ownValidReportCount: 0,
      startedAcceptingAt: "2026-01-01T01:00:00+01:00",
      createdAt: null,
      updatedAt: "2026-07-01T12:30:00Z",
    },
    structuredScopes: [
      {
        id: "manual-scope-001",
        assetType: "URL",
        assetIdentifier: "https://manual-synthetic.invalid/metadata-only",
        eligibleForSubmission: true,
        eligibleForBounty: false,
        instruction: "Metadata only; never contact this identifier.",
        maximumSeverity: "medium",
        createdAt: null,
        updatedAt: "2026-07-01T12:30:00Z",
        confidentialityRequirement: "high",
        integrityRequirement: null,
        availabilityRequirement: null,
      },
    ],
    scopeExclusions: [
      {
        id: "manual-exclusion-001",
        category: "Synthetic exclusion",
        details: "No target requests are permitted.",
        createdAt: null,
        updatedAt: null,
      },
    ],
  };
}

function encoded(value: unknown): string {
  return JSON.stringify(value);
}

describe("HackerOne manual import", () => {
  it("normalizes only the owned schema and always marks the source unverified", () => {
    const parsed = parseHackerOneManualImport(encoded(document()), IMPORTED_AT);

    expect(parsed.program).toMatchObject({
      hackerOneId: "manual-synthetic-program-001",
      source: "manual_unverified",
      synchronizedAt: IMPORTED_AT,
      startedAcceptingAt: "2026-01-01T00:00:00.000Z",
      updatedAt: "2026-07-01T12:30:00.000Z",
    });
    expect(parsed.structuredScopes[0]).toMatchObject({
      id: "manual-scope-001",
      assetIdentifierDigest: sha256(
        "https://manual-synthetic.invalid/metadata-only",
      ),
      updatedAt: "2026-07-01T12:30:00.000Z",
    });
    expect(parsed.importedAt).toBe(IMPORTED_AT);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.program)).toBe(true);
    expect(Object.isFrozen(parsed.structuredScopes)).toBe(true);
    expect(Object.isFrozen(parsed.structuredScopes[0])).toBe(true);
  });

  it.each([
    ["top-level", (value: Record<string, unknown>) => (value["extra"] = true)],
    [
      "program source",
      (value: Record<string, unknown>) => {
        (value["program"] as Record<string, unknown>)["source"] =
          "hackerone_api_authenticated";
      },
    ],
    [
      "program raw response",
      (value: Record<string, unknown>) => {
        (value["program"] as Record<string, unknown>)["rawResponse"] = {
          authorization: "synthetic-secret",
        };
      },
    ],
    [
      "scope",
      (value: Record<string, unknown>) => {
        const scopes = value["structuredScopes"] as Record<string, unknown>[];
        scopes[0]!["navigate"] = true;
      },
    ],
    [
      "exclusion",
      (value: Record<string, unknown>) => {
        const exclusions = value["scopeExclusions"] as Record<
          string,
          unknown
        >[];
        exclusions[0]!["extra"] = true;
      },
    ],
  ])("rejects unknown %s fields without source mixing", (_label, mutate) => {
    const value = document();
    mutate(value);

    expect(() =>
      parseHackerOneManualImport(encoded(value), IMPORTED_AT),
    ).toThrow("HACKERONE_MANUAL_IMPORT_SCHEMA_INVALID");
  });

  it("rejects duplicate scope and exclusion identities independently", () => {
    const duplicateScope = document();
    const scopes = duplicateScope["structuredScopes"] as Record<
      string,
      unknown
    >[];
    scopes.push({ ...scopes[0]! });
    expect(() =>
      parseHackerOneManualImport(encoded(duplicateScope), IMPORTED_AT),
    ).toThrow("HACKERONE_MANUAL_SCOPE_DUPLICATE");

    const duplicateExclusion = document();
    const exclusions = duplicateExclusion["scopeExclusions"] as Record<
      string,
      unknown
    >[];
    exclusions.push({ ...exclusions[0]! });
    expect(() =>
      parseHackerOneManualImport(encoded(duplicateExclusion), IMPORTED_AT),
    ).toThrow("HACKERONE_MANUAL_EXCLUSION_DUPLICATE");
  });

  it("rejects ambiguous duplicate JSON keys before schema validation", () => {
    const source = encoded(document()).replace(
      '"version":1',
      '"version":1,"version":1',
    );

    expect(() => parseHackerOneManualImport(source, IMPORTED_AT)).toThrow(
      "HACKERONE_MANUAL_IMPORT_JSON_INVALID",
    );
  });

  it.each(["", "x".repeat(1_048_577)])(
    "rejects empty or oversized input before parsing",
    (source) => {
      expect(() => parseHackerOneManualImport(source, IMPORTED_AT)).toThrow(
        "HACKERONE_MANUAL_IMPORT_SIZE_INVALID",
      );
    },
  );

  it("rejects malformed JSON and a non-canonical import clock", () => {
    expect(() => parseHackerOneManualImport("{", IMPORTED_AT)).toThrow(
      "HACKERONE_MANUAL_IMPORT_JSON_INVALID",
    );
    expect(() =>
      parseHackerOneManualImport(encoded(document()), "not-a-time"),
    ).toThrow("HACKERONE_MANUAL_IMPORT_TIMESTAMP_INVALID");
  });
});
