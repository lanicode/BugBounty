import { describe, expect, it } from "vitest";
import { sha256 } from "../../../packages/shared/canonical.js";
import {
  createHackerOnePolicySnapshot,
  detectHackerOnePolicyDrift,
  evaluateHackerOneProgram,
} from "../../../packages/hackerone-readonly/snapshot.js";
import type {
  HackerOnePolicyChangeCode,
  HackerOnePolicySnapshot,
  HackerOneProgram,
  HackerOneScopeExclusion,
  HackerOneStructuredScope,
} from "../../../packages/hackerone-readonly/types.js";

const FETCHED_AT = "2026-07-14T12:00:00.000Z";

function program(overrides: Partial<HackerOneProgram> = {}): HackerOneProgram {
  return Object.freeze({
    hackerOneId: "synthetic-program-001",
    handle: "synthetic_program",
    name: "Synthetic Program",
    currency: "USD",
    policy: "Review every workflow manually before any automation.",
    submissionState: "open",
    programState: "public_mode",
    offersBounties: true,
    openScope: false,
    goldStandardSafeHarbor: true,
    bookmarked: false,
    ownReportCount: 0,
    ownValidReportCount: 0,
    startedAcceptingAt: null,
    createdAt: null,
    updatedAt: null,
    synchronizedAt: FETCHED_AT,
    source: "hackerone_api_authenticated",
    ...overrides,
  });
}

function scope(
  id: string,
  overrides: Partial<HackerOneStructuredScope> = {},
): HackerOneStructuredScope {
  const assetIdentifier =
    overrides.assetIdentifier ?? `https://${id}.invalid/metadata-only`;
  return Object.freeze({
    id,
    assetType: "URL",
    assetIdentifier,
    assetIdentifierDigest: sha256(assetIdentifier),
    eligibleForSubmission: true,
    eligibleForBounty: true,
    instruction: "Do not contact this synthetic identifier.",
    maximumSeverity: "high",
    createdAt: null,
    updatedAt: null,
    confidentialityRequirement: "high",
    integrityRequirement: null,
    availabilityRequirement: null,
    ...overrides,
  });
}

function exclusion(
  id: string,
  overrides: Partial<HackerOneScopeExclusion> = {},
): HackerOneScopeExclusion {
  return Object.freeze({
    id,
    category: "Synthetic exclusion",
    details: "Excluded from every local fixture action.",
    createdAt: null,
    updatedAt: null,
    ...overrides,
  });
}

function snapshot(
  input: {
    readonly program?: HackerOneProgram;
    readonly scopes?: readonly HackerOneStructuredScope[];
    readonly exclusions?: readonly HackerOneScopeExclusion[];
    readonly fetchedAt?: string;
    readonly previous?: string | null;
  } = {},
): HackerOnePolicySnapshot {
  return createHackerOnePolicySnapshot({
    program: input.program ?? program(),
    structuredScopes: input.scopes ?? [scope("scope-a")],
    scopeExclusions: input.exclusions ?? [exclusion("exclusion-a")],
    fetchedAt: input.fetchedAt ?? FETCHED_AT,
    previousSnapshotDigest: input.previous ?? null,
  });
}

describe("HackerOne snapshot suitability", () => {
  it("defaults ambiguous automation language to human review without a legal decision", () => {
    const result = evaluateHackerOneProgram(
      program(),
      [scope("scope-a")],
      [exclusion("exclusion-a")],
    );

    expect(result).toMatchObject({
      automationPermission: "unknown_requires_human_review",
      accountWorkflows: "manual_review_required",
      legalDecisionMade: false,
    });
    expect(result.score).toBeGreaterThan(0);
    expect(result.reasons).toEqual([
      "OPEN_SUBMISSIONS",
      "BOUNTIES_AVAILABLE",
      "POLICY_PRESENT",
      "STRUCTURED_SCOPE_CLEAR",
      "WEB_OR_API_ASSET_PRESENT",
      "SCOPE_EXCLUSIONS_PRESENT",
      "SAFE_HARBOR_PRESENT",
    ]);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.reasons)).toBe(true);
  });

  it.each([
    [
      "Automated testing is explicitly allowed for this synthetic policy.",
      "allowed",
    ],
    ["Automated scanning is prohibited.", "forbidden"],
    ["No statement about tools is present.", "unknown_requires_human_review"],
  ] as const)(
    "classifies explicit policy language conservatively",
    (policy, expected) => {
      expect(
        evaluateHackerOneProgram(program({ policy }), [], []),
      ).toHaveProperty("automationPermission", expected);
    },
  );

  it("caps weak or missing policy evidence instead of inferring permission", () => {
    const result = evaluateHackerOneProgram(
      program({
        policy: "",
        submissionState: "closed",
        offersBounties: false,
        goldStandardSafeHarbor: false,
      }),
      [],
      [],
    );

    expect(result.automationPermission).toBe("unknown_requires_human_review");
    expect(result.score).toBeLessThanOrEqual(30);
    expect(result.reasons).toContain("POLICY_MISSING");
    expect(result.reasons).toContain("STRUCTURED_SCOPE_MISSING");
    expect(result.reasons).toContain("BOUNTIES_UNAVAILABLE");
  });
});

describe("HackerOne snapshot digests and drift", () => {
  it("sorts records before hashing and produces stable deeply frozen digests", () => {
    const first = snapshot({
      scopes: [scope("scope-b"), scope("scope-a")],
      exclusions: [exclusion("exclusion-b"), exclusion("exclusion-a")],
    });
    const second = snapshot({
      scopes: [scope("scope-a"), scope("scope-b")],
      exclusions: [exclusion("exclusion-a"), exclusion("exclusion-b")],
    });

    expect(first.snapshotDigest).toBe(second.snapshotDigest);
    expect(first.policyDigest).toBe(second.policyDigest);
    expect(first.structuredScopes.map((entry) => entry.id)).toEqual([
      "scope-a",
      "scope-b",
    ]);
    expect(first.scopeExclusions.map((entry) => entry.id)).toEqual([
      "exclusion-a",
      "exclusion-b",
    ]);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.program)).toBe(true);
    expect(Object.isFrozen(first.structuredScopes)).toBe(true);
    expect(Object.isFrozen(first.structuredScopes[0])).toBe(true);
  });

  it("keeps the policy digest stable for non-policy program presentation metadata", () => {
    const before = snapshot();
    const after = snapshot({
      program: program({ name: "Renamed Synthetic Program", bookmarked: true }),
    });

    expect(after.policyDigest).toBe(before.policyDigest);
    expect(after.snapshotDigest).not.toBe(before.snapshotDigest);
    expect(detectHackerOnePolicyDrift(before, after, true)).toEqual({
      changed: false,
      changes: [],
      campaignsPaused: false,
      requiresHumanAcceptance: false,
    });
  });

  it("detects every policy-relevant field with deterministic reason codes", () => {
    const before = snapshot({
      scopes: [scope("scope-a")],
      exclusions: [exclusion("exclusion-a")],
    });
    const changedIdentifier = "https://changed-scope.invalid/metadata-only";
    const after = snapshot({
      program: program({
        policy: "Changed policy text.",
        programState: "closed_mode",
        submissionState: "closed",
        offersBounties: false,
        openScope: true,
        goldStandardSafeHarbor: false,
      }),
      scopes: [
        scope("scope-a", {
          assetIdentifier: changedIdentifier,
          assetIdentifierDigest: sha256(changedIdentifier),
          eligibleForSubmission: false,
          eligibleForBounty: false,
          instruction: "Changed instructions.",
          maximumSeverity: "medium",
        }),
      ],
      exclusions: [
        exclusion("exclusion-a", { details: "Changed exclusion details." }),
      ],
    });

    const expected: readonly HackerOnePolicyChangeCode[] = [
      "POLICY_TEXT_CHANGED",
      "PROGRAM_STATE_CHANGED",
      "OPEN_SCOPE_CHANGED",
      "SAFE_HARBOR_CHANGED",
      "SUBMISSION_ELIGIBILITY_CHANGED",
      "BOUNTY_ELIGIBILITY_CHANGED",
      "INSTRUCTIONS_CHANGED",
      "MAXIMUM_SEVERITY_CHANGED",
      "SCOPES_CHANGED",
      "SCOPE_EXCLUSIONS_CHANGED",
    ];
    expect(detectHackerOnePolicyDrift(before, after, true)).toEqual({
      changed: true,
      changes: expected,
      campaignsPaused: true,
      requiresHumanAcceptance: true,
    });
    expect(after.policyDigest).not.toBe(before.policyDigest);
  });

  it.each([
    [
      "POLICY_TEXT_CHANGED",
      () => snapshot({ program: program({ policy: "Different policy." }) }),
    ],
    [
      "PROGRAM_STATE_CHANGED",
      () => snapshot({ program: program({ programState: "closed_mode" }) }),
    ],
    [
      "OPEN_SCOPE_CHANGED",
      () => snapshot({ program: program({ openScope: true }) }),
    ],
    [
      "SAFE_HARBOR_CHANGED",
      () => snapshot({ program: program({ goldStandardSafeHarbor: false }) }),
    ],
    [
      "SUBMISSION_ELIGIBILITY_CHANGED",
      () =>
        snapshot({
          scopes: [scope("scope-a", { eligibleForSubmission: false })],
        }),
    ],
    [
      "BOUNTY_ELIGIBILITY_CHANGED",
      () =>
        snapshot({ scopes: [scope("scope-a", { eligibleForBounty: false })] }),
    ],
    [
      "INSTRUCTIONS_CHANGED",
      () =>
        snapshot({ scopes: [scope("scope-a", { instruction: "Changed." })] }),
    ],
    [
      "MAXIMUM_SEVERITY_CHANGED",
      () =>
        snapshot({ scopes: [scope("scope-a", { maximumSeverity: "low" })] }),
    ],
    [
      "SCOPES_CHANGED",
      () => snapshot({ scopes: [scope("scope-a", { assetType: "WEB" })] }),
    ],
    [
      "SCOPE_EXCLUSIONS_CHANGED",
      () => snapshot({ exclusions: [exclusion("exclusion-b")] }),
    ],
  ] as const)("isolates %s drift", (expected, candidate) => {
    expect(
      detectHackerOnePolicyDrift(snapshot(), candidate(), false).changes,
    ).toEqual([expected]);
  });

  it("requires acceptance for an initial snapshot without inventing campaign state", () => {
    expect(detectHackerOnePolicyDrift(null, snapshot(), false)).toEqual({
      changed: true,
      changes: ["POLICY_TEXT_CHANGED"],
      campaignsPaused: false,
      requiresHumanAcceptance: true,
    });
  });
});
