import type {
  CompiledPlatformPolicy,
  SourceAcceptance,
  ValidatedProgramSnapshot,
} from "./types.js";
import type { NetworkTarget, SupportingHost } from "../config/types.js";
import { canonicalHost } from "../config/loader.js";
import { normalizeRequestPath } from "../egress-guard/normalize.js";
import { SecurityError } from "../shared/errors.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { validateProgramSnapshot } from "./fixture-source.js";

function compileTarget(target: NetworkTarget): NetworkTarget {
  const host = canonicalHost(target.host);
  const pathPrefixes = target.path_prefixes.map((prefix) => {
    if (prefix.includes("?") || prefix.includes("#"))
      throw new SecurityError("PLATFORM_SOURCE_PATH_NON_CANONICAL");
    const normalized = normalizeRequestPath(prefix);
    if (normalized !== prefix)
      throw new SecurityError("PLATFORM_SOURCE_PATH_NON_CANONICAL");
    return normalized;
  });
  return {
    scheme: target.scheme,
    host,
    ports: [...target.ports].sort((left, right) => left - right),
    path_prefixes: [...pathPrefixes].sort(),
  };
}

function compileSupporting(host: SupportingHost): SupportingHost {
  return {
    scheme: host.scheme,
    host: canonicalHost(host.host),
    ports: [...host.ports].sort((left, right) => left - right),
    allowed_methods: [...host.allowed_methods].sort(),
    capture: host.capture,
  };
}

export function compilePlatformPolicy(
  validated: ValidatedProgramSnapshot,
): CompiledPlatformPolicy {
  const checked = validateProgramSnapshot(validated.snapshot);
  if (
    checked.canonical !== validated.canonical ||
    checked.snapshotHash !== validated.snapshotHash ||
    sha256(canonicalJson(validated.snapshot)) !== validated.snapshotHash
  )
    throw new SecurityError("PLATFORM_SOURCE_INTEGRITY_INVALID");
  const { snapshot } = checked;
  const targets = snapshot.network.targets
    .map(compileTarget)
    .sort(compareHosts);
  const supportingHosts = snapshot.network.supporting_hosts
    .map(compileSupporting)
    .sort(compareHosts);
  const blockedHosts = snapshot.network.blocked_hosts.map(canonicalHost).sort();
  const targetSet = new Set(targets.map((target) => target.host));
  const supportSet = new Set(supportingHosts.map((host) => host.host));
  const blockedSet = new Set(blockedHosts);
  if (
    targetSet.size !== targets.length ||
    supportSet.size !== supportingHosts.length ||
    blockedSet.size !== blockedHosts.length
  )
    throw new SecurityError("PLATFORM_SOURCE_DUPLICATE_HOST");
  for (const host of targetSet)
    if (supportSet.has(host) || blockedSet.has(host))
      throw new SecurityError("PLATFORM_SOURCE_HOST_CLASS_OVERLAP");
  for (const host of supportSet)
    if (blockedSet.has(host))
      throw new SecurityError("PLATFORM_SOURCE_HOST_CLASS_OVERLAP");
  return Object.freeze({
    platform: snapshot.source.platform,
    handle: snapshot.program.handle,
    displayName: snapshot.program.display_name,
    sourceRevision: snapshot.source.source_revision,
    retrievedAt: snapshot.source.retrieved_at,
    upstreamPolicyHash: snapshot.policy.content_sha256,
    sourceSnapshotHash: validated.snapshotHash,
    targets: Object.freeze(
      targets.map((target) =>
        Object.freeze({
          ...target,
          ports: Object.freeze([...target.ports]),
          path_prefixes: Object.freeze([...target.path_prefixes]),
        }),
      ),
    ),
    supportingHosts: Object.freeze(
      supportingHosts.map((host) =>
        Object.freeze({
          ...host,
          ports: Object.freeze([...host.ports]),
          allowed_methods: Object.freeze([...host.allowed_methods]),
        }),
      ),
    ),
    blockedHosts: Object.freeze(blockedHosts),
    productionEligible: false,
  });
}

export function verifySourceAcceptance(
  policy: CompiledPlatformPolicy,
  acceptance: SourceAcceptance,
): void {
  if (
    !/^[A-Za-z0-9._@-]{1,128}$/u.test(acceptance.acceptedBy) ||
    !Number.isFinite(Date.parse(acceptance.acceptedAt)) ||
    Date.parse(acceptance.acceptedAt) < Date.parse(policy.retrievedAt)
  )
    throw new SecurityError("PLATFORM_ACCEPTANCE_INVALID");
  if (policy.upstreamPolicyHash !== acceptance.upstreamPolicyHash)
    throw new SecurityError("UPSTREAM_POLICY_DRIFT");
  if (policy.sourceSnapshotHash !== acceptance.sourceSnapshotHash)
    throw new SecurityError("PLATFORM_SNAPSHOT_DRIFT");
  if (policy.sourceRevision !== acceptance.sourceRevision)
    throw new SecurityError("PLATFORM_SOURCE_REVISION_DRIFT");
}

function compareHosts(
  left: { readonly host: string },
  right: { readonly host: string },
): number {
  return left.host < right.host ? -1 : left.host > right.host ? 1 : 0;
}
