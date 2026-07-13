import type { CatalogEntry } from "./catalog.js";
import { SecurityError } from "../shared/errors.js";

export type RankingReason =
  | "ACCEPTANCE_PENDING"
  | "FRESH_SNAPSHOT"
  | "FUTURE_SNAPSHOT"
  | "NARROW_SCOPE"
  | "STALE_SNAPSHOT"
  | "SUPPORTING_HOST_PENALTY";

export interface RankedProgram {
  readonly handle: string;
  readonly score: number;
  readonly eligibleForSimulation: boolean;
  readonly reasons: readonly RankingReason[];
}

export function rankPrograms(
  entries: readonly CatalogEntry[],
  referenceTime: string,
): readonly RankedProgram[] {
  const now = Date.parse(referenceTime);
  if (!Number.isFinite(now)) throw new SecurityError("RANKING_TIME_INVALID");
  const ranked = entries.map((entry): RankedProgram => {
    const retrieved = Date.parse(entry.policy.retrievedAt);
    const reasons: RankingReason[] = [];
    if (!Number.isFinite(retrieved) || retrieved > now) {
      reasons.push("FUTURE_SNAPSHOT");
      return Object.freeze({
        handle: entry.policy.handle,
        score: 0,
        eligibleForSimulation: false,
        reasons: Object.freeze(reasons),
      });
    }
    let score = 50;
    const ageDays = Math.floor((now - retrieved) / 86_400_000);
    if (ageDays <= 30) {
      score += 20;
      reasons.push("FRESH_SNAPSHOT");
    } else {
      score -= Math.min(30, ageDays - 30);
      reasons.push("STALE_SNAPSHOT");
    }
    if (entry.policy.targets.length <= 10) {
      score += 20;
      reasons.push("NARROW_SCOPE");
    }
    if (entry.policy.supportingHosts.length > 0) {
      score -= Math.min(20, entry.policy.supportingHosts.length * 2);
      reasons.push("SUPPORTING_HOST_PENALTY");
    }
    if (entry.acceptance !== "accepted") {
      score = Math.min(score, 25);
      reasons.push("ACCEPTANCE_PENDING");
    }
    return Object.freeze({
      handle: entry.policy.handle,
      score: Math.max(0, Math.min(100, score)),
      eligibleForSimulation: entry.acceptance === "accepted",
      reasons: Object.freeze(reasons),
    });
  });
  return Object.freeze(
    ranked.sort(
      (left, right) =>
        right.score - left.score || compareText(left.handle, right.handle),
    ),
  );
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
