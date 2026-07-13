import type { NetworkTarget, SupportingHost } from "../config/types.js";

export interface ProgramSourceSnapshot {
  readonly schema_version: 1;
  readonly source: {
    readonly kind: "offline_fixture";
    readonly platform: "hackerone";
    readonly source_revision: string;
    readonly retrieved_at: string;
  };
  readonly program: {
    readonly handle: string;
    readonly display_name: string;
  };
  readonly policy: {
    readonly content_sha256: string;
  };
  readonly network: {
    readonly targets: readonly NetworkTarget[];
    readonly supporting_hosts: readonly SupportingHost[];
    readonly blocked_hosts: readonly string[];
  };
}

export interface ValidatedProgramSnapshot {
  readonly snapshot: ProgramSourceSnapshot;
  readonly canonical: string;
  readonly snapshotHash: string;
}

export interface ProgramSource {
  read(reference: string): Promise<ValidatedProgramSnapshot>;
}

export interface CompiledPlatformPolicy {
  readonly platform: "hackerone";
  readonly handle: string;
  readonly displayName: string;
  readonly sourceRevision: string;
  readonly retrievedAt: string;
  readonly upstreamPolicyHash: string;
  readonly sourceSnapshotHash: string;
  readonly targets: readonly NetworkTarget[];
  readonly supportingHosts: readonly SupportingHost[];
  readonly blockedHosts: readonly string[];
  readonly productionEligible: false;
}

export interface SourceAcceptance {
  readonly sourceRevision: string;
  readonly sourceSnapshotHash: string;
  readonly upstreamPolicyHash: string;
  readonly acceptedBy: string;
  readonly acceptedAt: string;
}
