import { sha256 } from "../../packages/shared/canonical.js";
import type { createActiveTestPlan } from "../../packages/active-testing/catalog.js";
import {
  createHackerOnePolicySnapshot,
  type HackerOnePolicySnapshot,
  type HackerOneProgram,
  type HackerOneScopeExclusion,
  type HackerOneStructuredScope,
} from "../../packages/hackerone-readonly/index.js";

export const ACTIVE_TEST_TIME = "2026-07-15T12:00:00.000Z";
export const ACTIVE_TEST_PROGRAM_REF = `h1a_${"a".repeat(64)}`;

export function activeTestProgram(
  overrides: Partial<HackerOneProgram> = {},
): HackerOneProgram {
  return Object.freeze({
    hackerOneId: "synthetic-active-program-001",
    handle: "synthetic_active_program",
    name: "Synthetic Active Program",
    currency: "USD",
    policy:
      "Automated testing is explicitly allowed for low-risk read-only HTTPS checks.",
    submissionState: "open",
    programState: "public_mode",
    offersBounties: true,
    openScope: false,
    goldStandardSafeHarbor: true,
    bookmarked: false,
    ownReportCount: 0,
    ownValidReportCount: 0,
    startedAcceptingAt: ACTIVE_TEST_TIME,
    createdAt: ACTIVE_TEST_TIME,
    updatedAt: ACTIVE_TEST_TIME,
    synchronizedAt: ACTIVE_TEST_TIME,
    source: "hackerone_api_authenticated",
    ...overrides,
  });
}

export function activeTestScope(
  overrides: Partial<HackerOneStructuredScope> = {},
): HackerOneStructuredScope {
  const assetIdentifier =
    overrides.assetIdentifier ?? "https://synthetic-target.bounty-safe.dev/";
  return Object.freeze({
    id: "scope-active-001",
    assetType: "URL",
    assetIdentifier,
    assetIdentifierDigest: sha256(assetIdentifier),
    eligibleForSubmission: true,
    eligibleForBounty: true,
    instruction: "Only low-risk read-only checks are permitted.",
    maximumSeverity: "medium",
    createdAt: ACTIVE_TEST_TIME,
    updatedAt: ACTIVE_TEST_TIME,
    confidentialityRequirement: "low",
    integrityRequirement: "low",
    availabilityRequirement: "low",
    ...overrides,
  });
}

export function activeTestExclusion(
  overrides: Partial<HackerOneScopeExclusion> = {},
): HackerOneScopeExclusion {
  return Object.freeze({
    id: "exclusion-active-001",
    category: "Synthetic exclusion",
    details: "No authentication, writes, fuzzing or high-rate requests.",
    createdAt: ACTIVE_TEST_TIME,
    updatedAt: ACTIVE_TEST_TIME,
    ...overrides,
  });
}

export function activeTestSnapshot(
  input: {
    readonly program?: HackerOneProgram;
    readonly scopes?: readonly HackerOneStructuredScope[];
    readonly exclusions?: readonly HackerOneScopeExclusion[];
    readonly source?: "hackerone_api_authenticated" | "manual_unverified";
    readonly previousSnapshotDigest?: string | null;
    readonly fetchedAt?: string;
  } = {},
): HackerOnePolicySnapshot {
  const source = input.source ?? "hackerone_api_authenticated";
  const program = input.program ?? activeTestProgram({ source });
  return createHackerOnePolicySnapshot({
    program,
    structuredScopes: input.scopes ?? [activeTestScope()],
    scopeExclusions: input.exclusions ?? [activeTestExclusion()],
    fetchedAt: input.fetchedAt ?? ACTIVE_TEST_TIME,
    previousSnapshotDigest: input.previousSnapshotDigest ?? null,
  });
}

export function activeTestPlanInput(
  overrides: Partial<Parameters<typeof createActiveTestPlan>[0]> = {},
): Parameters<typeof createActiveTestPlan>[0] {
  const snapshot = overrides.snapshot ?? activeTestSnapshot();
  const scope = snapshot.structuredScopes[0];
  if (scope === undefined)
    throw new Error("ACTIVE_TEST_FIXTURE_SCOPE_REQUIRED");
  return {
    planId: "active-plan-001",
    programRef: ACTIVE_TEST_PROGRAM_REF,
    snapshot,
    scopeId: scope.id,
    assetIdentifierDigest: scope.assetIdentifierDigest,
    testClass: "http_headers",
    createdAt: ACTIVE_TEST_TIME,
    confirmations: {
      automationPermissionReviewed: true,
      scopeInstructionReviewed: true,
      scopeExclusionsReviewed: true,
      noSideEffectsConfirmed: true,
    },
    ...overrides,
  };
}
