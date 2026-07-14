import { canonicalJson, sha256 } from "../shared/canonical.js";
import type {
  HackerOneAutomationPermission,
  HackerOnePolicyChangeCode,
  HackerOnePolicyDrift,
  HackerOnePolicySnapshot,
  HackerOneProgram,
  HackerOneProgramSuitability,
  HackerOneScopeExclusion,
  HackerOneStructuredScope,
  HackerOneSuitabilityReason,
} from "./types.js";
import {
  HACKERONE_ADAPTER_VERSION,
  HACKERONE_SCHEMA_VERSION,
} from "./types.js";

export function createHackerOnePolicySnapshot(input: {
  readonly program: HackerOneProgram;
  readonly structuredScopes: readonly HackerOneStructuredScope[];
  readonly scopeExclusions: readonly HackerOneScopeExclusion[];
  readonly fetchedAt: string;
  readonly previousSnapshotDigest: string | null;
}): HackerOnePolicySnapshot {
  const scopes = sortScopes(input.structuredScopes);
  const exclusions = sortExclusions(input.scopeExclusions);
  const suitability = evaluateHackerOneProgram(
    input.program,
    scopes,
    exclusions,
  );
  const policyDocument = policyMaterial(input.program, scopes, exclusions);
  const policyDigest = sha256(canonicalJson(policyDocument));
  const snapshotMaterial = Object.freeze({
    program: input.program,
    structuredScopes: scopes,
    scopeExclusions: exclusions,
    fetchedAt: normalizeTime(input.fetchedAt),
    adapterVersion: HACKERONE_ADAPTER_VERSION,
    schemaVersion: HACKERONE_SCHEMA_VERSION,
    previousSnapshotDigest: input.previousSnapshotDigest,
    source: input.program.source,
  });
  return deepFreeze({
    ...snapshotMaterial,
    snapshotDigest: sha256(canonicalJson(snapshotMaterial)),
    policyDigest,
    suitability,
  });
}

export function evaluateHackerOneProgram(
  program: HackerOneProgram,
  scopes: readonly HackerOneStructuredScope[],
  exclusions: readonly HackerOneScopeExclusion[],
): HackerOneProgramSuitability {
  let score = 15;
  const reasons: HackerOneSuitabilityReason[] = [];
  if (isOpenSubmissionState(program.submissionState)) {
    score += 20;
    reasons.push("OPEN_SUBMISSIONS");
  }
  if (program.offersBounties) {
    score += 10;
    reasons.push("BOUNTIES_AVAILABLE");
  } else {
    reasons.push("BOUNTIES_UNAVAILABLE");
  }
  if (program.policy.trim().length > 0) {
    score += 15;
    reasons.push("POLICY_PRESENT");
  } else {
    score = Math.min(score, 25);
    reasons.push("POLICY_MISSING");
  }
  if (scopes.length > 0) {
    score += Math.min(15, scopes.length);
    reasons.push("STRUCTURED_SCOPE_CLEAR");
  } else {
    score = Math.min(score, 30);
    reasons.push("STRUCTURED_SCOPE_MISSING");
  }
  if (scopes.some((scope) => /(?:api|url|web)/iu.test(scope.assetType))) {
    score += 15;
    reasons.push("WEB_OR_API_ASSET_PRESENT");
  }
  if (exclusions.length > 0) {
    score += 5;
    reasons.push("SCOPE_EXCLUSIONS_PRESENT");
  }
  if (program.goldStandardSafeHarbor) {
    score += 5;
    reasons.push("SAFE_HARBOR_PRESENT");
  }
  return Object.freeze({
    score: Math.max(0, Math.min(100, score)),
    reasons: Object.freeze(reasons),
    automationPermission: automationPermission(program.policy),
    accountWorkflows: "manual_review_required" as const,
    legalDecisionMade: false as const,
  });
}

export function detectHackerOnePolicyDrift(
  previous: HackerOnePolicySnapshot | null,
  candidate: HackerOnePolicySnapshot,
  campaignsPaused: boolean,
): HackerOnePolicyDrift {
  if (previous === null)
    return Object.freeze({
      changed: true,
      changes: Object.freeze<HackerOnePolicyChangeCode[]>([
        "POLICY_TEXT_CHANGED",
      ]),
      campaignsPaused,
      requiresHumanAcceptance: true,
    });
  const changes: HackerOnePolicyChangeCode[] = [];
  if (previous.program.policy !== candidate.program.policy)
    changes.push("POLICY_TEXT_CHANGED");
  if (previous.program.programState !== candidate.program.programState)
    changes.push("PROGRAM_STATE_CHANGED");
  if (previous.program.openScope !== candidate.program.openScope)
    changes.push("OPEN_SCOPE_CHANGED");
  if (
    previous.program.goldStandardSafeHarbor !==
    candidate.program.goldStandardSafeHarbor
  )
    changes.push("SAFE_HARBOR_CHANGED");
  if (
    previous.program.submissionState !== candidate.program.submissionState ||
    scopeField(previous, candidate, "eligibleForSubmission")
  )
    changes.push("SUBMISSION_ELIGIBILITY_CHANGED");
  if (
    previous.program.offersBounties !== candidate.program.offersBounties ||
    scopeField(previous, candidate, "eligibleForBounty")
  )
    changes.push("BOUNTY_ELIGIBILITY_CHANGED");
  if (scopeField(previous, candidate, "instruction"))
    changes.push("INSTRUCTIONS_CHANGED");
  if (scopeField(previous, candidate, "maximumSeverity"))
    changes.push("MAXIMUM_SEVERITY_CHANGED");
  if (scopeIdentityMaterial(previous) !== scopeIdentityMaterial(candidate))
    changes.push("SCOPES_CHANGED");
  if (
    canonicalJson(previous.scopeExclusions) !==
    canonicalJson(candidate.scopeExclusions)
  )
    changes.push("SCOPE_EXCLUSIONS_CHANGED");
  const uniqueChanges = Object.freeze([...new Set(changes)]);
  return Object.freeze({
    changed: uniqueChanges.length > 0,
    changes: uniqueChanges,
    campaignsPaused: uniqueChanges.length > 0 && campaignsPaused,
    requiresHumanAcceptance: uniqueChanges.length > 0,
  });
}

function policyMaterial(
  program: HackerOneProgram,
  scopes: readonly HackerOneStructuredScope[],
  exclusions: readonly HackerOneScopeExclusion[],
): unknown {
  return Object.freeze({
    policy: program.policy,
    programState: program.programState,
    submissionState: program.submissionState,
    offersBounties: program.offersBounties,
    openScope: program.openScope,
    goldStandardSafeHarbor: program.goldStandardSafeHarbor,
    structuredScopes: scopes,
    scopeExclusions: exclusions,
  });
}

function automationPermission(policy: string): HackerOneAutomationPermission {
  const normalized = policy.toLocaleLowerCase("en-US");
  if (
    /(?:automated (?:testing|scanning).{0,40}(?:is |are )?(?:prohibited|forbidden|not allowed)|do not (?:use|run) automated)/u.test(
      normalized,
    )
  )
    return "forbidden";
  if (
    /automated (?:testing|scanning).{0,40}(?:is |are )?(?:explicitly )?(?:allowed|permitted)/u.test(
      normalized,
    )
  )
    return "allowed";
  return "unknown_requires_human_review";
}

function isOpenSubmissionState(value: string): boolean {
  return /^(?:open|open_for_submissions)$/u.test(value.toLowerCase());
}

function sortScopes(
  value: readonly HackerOneStructuredScope[],
): readonly HackerOneStructuredScope[] {
  return Object.freeze(
    value.map((scope) => Object.freeze({ ...scope })).sort(compareById),
  );
}

function sortExclusions(
  value: readonly HackerOneScopeExclusion[],
): readonly HackerOneScopeExclusion[] {
  return Object.freeze(
    value.map((exclusion) => Object.freeze({ ...exclusion })).sort(compareById),
  );
}

function compareById(
  left: { readonly id: string },
  right: { readonly id: string },
): number {
  return left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
}

function scopeField(
  previous: HackerOnePolicySnapshot,
  candidate: HackerOnePolicySnapshot,
  key:
    | "eligibleForBounty"
    | "eligibleForSubmission"
    | "instruction"
    | "maximumSeverity",
): boolean {
  const before = previous.structuredScopes.map((scope) => [
    scope.id,
    scope[key],
  ]);
  const after = candidate.structuredScopes.map((scope) => [
    scope.id,
    scope[key],
  ]);
  return canonicalJson(before) !== canonicalJson(after);
}

function scopeIdentityMaterial(snapshot: HackerOnePolicySnapshot): string {
  return canonicalJson(
    snapshot.structuredScopes.map((scope) => ({
      id: scope.id,
      assetType: scope.assetType,
      assetIdentifierDigest: scope.assetIdentifierDigest,
      confidentialityRequirement: scope.confidentialityRequirement,
      integrityRequirement: scope.integrityRequirement,
      availabilityRequirement: scope.availabilityRequirement,
    })),
  );
}

function normalizeTime(value: string): string {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds))
    throw new Error("HACKERONE_TIMESTAMP_INVALID");
  return new Date(milliseconds).toISOString();
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}
