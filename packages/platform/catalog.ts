import type { PlatformAdapter } from "./adapters.js";
import {
  compilePlatformPolicy,
  verifySourceAcceptance,
} from "../platform-source/compiler.js";
import type {
  CompiledPlatformPolicy,
  SourceAcceptance,
} from "../platform-source/types.js";
import { SecurityError } from "../shared/errors.js";

export interface CatalogEntry {
  readonly policy: CompiledPlatformPolicy;
  readonly acceptance: "accepted" | "pending_human_acceptance";
}

export class ProgramCatalogService {
  public async synchronize(
    adapter: PlatformAdapter,
    acceptances: Readonly<Record<string, SourceAcceptance>>,
    signal: AbortSignal,
  ): Promise<readonly CatalogEntry[]> {
    assertActive(signal);
    if (adapter.kind !== "local_mock")
      throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
    const snapshots = await adapter.listProgramSnapshots(signal);
    assertActive(signal);
    const entries = snapshots.map((snapshot) => {
      const policy = compilePlatformPolicy(snapshot);
      const acceptance = acceptances[policy.handle];
      if (acceptance === undefined)
        return { policy, acceptance: "pending_human_acceptance" as const };
      try {
        verifySourceAcceptance(policy, acceptance);
        return { policy, acceptance: "accepted" as const };
      } catch {
        return { policy, acceptance: "pending_human_acceptance" as const };
      }
    });
    return Object.freeze(
      entries.sort((left, right) =>
        compareText(left.policy.handle, right.policy.handle),
      ),
    );
  }
}

function assertActive(signal: AbortSignal): void {
  if (signal.aborted) throw new SecurityError("PHASE2_GLOBAL_KILL_SWITCH");
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
