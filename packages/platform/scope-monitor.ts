import type { CompiledPlatformPolicy } from "../platform-source/types.js";
import { canonicalJson } from "../shared/canonical.js";

export type ScopeChangeCode =
  | "BLOCKED_HOSTS_CHANGED"
  | "DISPLAY_NAME_CHANGED"
  | "POLICY_HASH_CHANGED"
  | "SOURCE_REVISION_CHANGED"
  | "SOURCE_SNAPSHOT_CHANGED"
  | "SUPPORTING_HOSTS_CHANGED"
  | "TARGETS_CHANGED";

export interface ScopeChangeDecision {
  readonly changed: boolean;
  readonly stopCampaign: boolean;
  readonly requiresHumanAcceptance: boolean;
  readonly changes: readonly ScopeChangeCode[];
}

export function detectScopeChange(
  accepted: CompiledPlatformPolicy,
  candidate: CompiledPlatformPolicy,
): ScopeChangeDecision {
  const changes: ScopeChangeCode[] = [];
  if (accepted.upstreamPolicyHash !== candidate.upstreamPolicyHash)
    changes.push("POLICY_HASH_CHANGED");
  if (accepted.sourceRevision !== candidate.sourceRevision)
    changes.push("SOURCE_REVISION_CHANGED");
  if (accepted.sourceSnapshotHash !== candidate.sourceSnapshotHash)
    changes.push("SOURCE_SNAPSHOT_CHANGED");
  if (accepted.displayName !== candidate.displayName)
    changes.push("DISPLAY_NAME_CHANGED");
  if (canonicalJson(accepted.targets) !== canonicalJson(candidate.targets))
    changes.push("TARGETS_CHANGED");
  if (
    canonicalJson(accepted.supportingHosts) !==
    canonicalJson(candidate.supportingHosts)
  )
    changes.push("SUPPORTING_HOSTS_CHANGED");
  if (
    canonicalJson(accepted.blockedHosts) !==
    canonicalJson(candidate.blockedHosts)
  )
    changes.push("BLOCKED_HOSTS_CHANGED");
  const changed = changes.length > 0;
  return Object.freeze({
    changed,
    stopCampaign: changed,
    requiresHumanAcceptance: changed,
    changes: Object.freeze(changes),
  });
}
