import type {
  CompiledPlatformPolicy,
  ProgramSourceSnapshot,
  ValidatedProgramSnapshot,
} from "../platform-source/types.js";
import { validateProgramSnapshot } from "../platform-source/fixture-source.js";
import { compilePlatformPolicy } from "../platform-source/compiler.js";
import { SecurityError } from "../shared/errors.js";

export interface PlatformProgram {
  readonly handle: string;
  readonly displayName: string;
  readonly sourceRevision: string;
  readonly sourceSnapshotHash: string;
}

export interface PlatformPolicyRecord {
  readonly programHandle: string;
  readonly version: string;
  readonly policyHash: string;
  readonly sourceSnapshotHash: string;
}

export interface PlatformStructuredScope {
  readonly programHandle: string;
  readonly targets: CompiledPlatformPolicy["targets"];
  readonly supportingHosts: CompiledPlatformPolicy["supportingHosts"];
  readonly blockedHosts: CompiledPlatformPolicy["blockedHosts"];
}

export interface PlatformPolicyVersion {
  readonly programHandle: string;
  readonly version: string;
  readonly policyHash: string;
}

export interface CreateReportDraftInput {
  readonly reportRef: string;
  readonly programHandle: string;
  readonly title: string;
  readonly summary: string;
}

export interface PlatformReportDraft extends CreateReportDraftInput {
  readonly status: "draft";
  readonly delivery: "in_process_mock_only";
}

export interface PlatformAdapter {
  readonly kind: "external_disabled" | "local_mock";
  readonly platform: "hackerone" | "local_mock";
  listProgramSnapshots(
    signal: AbortSignal,
  ): Promise<readonly ValidatedProgramSnapshot[]>;
  listPrograms(signal: AbortSignal): Promise<readonly PlatformProgram[]>;
  getProgram(
    programHandle: string,
    signal: AbortSignal,
  ): Promise<PlatformProgram>;
  getPolicy(
    programHandle: string,
    signal: AbortSignal,
  ): Promise<PlatformPolicyRecord>;
  getStructuredScope(
    programHandle: string,
    signal: AbortSignal,
  ): Promise<PlatformStructuredScope>;
  getPolicyVersion(
    programHandle: string,
    signal: AbortSignal,
  ): Promise<PlatformPolicyVersion>;
  listReports(
    programHandle: string,
    signal: AbortSignal,
  ): Promise<readonly PlatformReportDraft[]>;
  createReportDraft(
    input: CreateReportDraftInput,
    signal: AbortSignal,
  ): Promise<PlatformReportDraft>;
  submitReport(reportRef: string, signal: AbortSignal): Promise<never>;
}

const GENUINE_MOCK_ADAPTERS = new WeakSet();

export class MockPlatformAdapter implements PlatformAdapter {
  public readonly kind = "local_mock" as const;
  public readonly platform = "local_mock" as const;
  readonly #snapshots: readonly ValidatedProgramSnapshot[];
  readonly #policies: readonly CompiledPlatformPolicy[];
  readonly #programs: readonly PlatformProgram[];
  readonly #reports = new Map<string, PlatformReportDraft>();

  public constructor(snapshots: readonly ProgramSourceSnapshot[]) {
    const validated = snapshots.map((snapshot) =>
      Object.freeze({ ...validateProgramSnapshot(snapshot) }),
    );
    const policies = validated.map(compilePlatformPolicy).sort(comparePolicies);
    const handles = new Set(policies.map((policy) => policy.handle));
    if (handles.size !== policies.length)
      throw new SecurityError("MOCK_PLATFORM_PROGRAM_DUPLICATE");
    this.#snapshots = Object.freeze(
      policies.map((policy) => {
        const snapshot = validated.find(
          (candidate) => candidate.snapshotHash === policy.sourceSnapshotHash,
        );
        if (snapshot === undefined)
          throw new SecurityError("MOCK_PLATFORM_FIXTURE_INVALID");
        return snapshot;
      }),
    );
    this.#policies = Object.freeze(policies);
    this.#programs = Object.freeze(
      policies.map((policy) =>
        Object.freeze({
          handle: policy.handle,
          displayName: policy.displayName,
          sourceRevision: policy.sourceRevision,
          sourceSnapshotHash: policy.sourceSnapshotHash,
        }),
      ),
    );
    GENUINE_MOCK_ADAPTERS.add(this);
    Object.freeze(this);
  }

  public listProgramSnapshots(
    signal: AbortSignal,
  ): Promise<readonly ValidatedProgramSnapshot[]> {
    return operation(signal, () => this.#snapshots);
  }

  public listPrograms(
    signal: AbortSignal,
  ): Promise<readonly PlatformProgram[]> {
    return operation(signal, () => this.#programs);
  }

  public getProgram(
    programHandle: string,
    signal: AbortSignal,
  ): Promise<PlatformProgram> {
    return operation(signal, () => {
      const program = this.#programs.find(
        (candidate) => candidate.handle === programHandle,
      );
      if (program === undefined)
        throw new SecurityError("MOCK_PLATFORM_PROGRAM_NOT_FOUND");
      return program;
    });
  }

  public getPolicy(
    programHandle: string,
    signal: AbortSignal,
  ): Promise<PlatformPolicyRecord> {
    return operation(signal, () => {
      const policy = this.requirePolicy(programHandle);
      return Object.freeze({
        programHandle: policy.handle,
        version: policy.sourceRevision,
        policyHash: policy.upstreamPolicyHash,
        sourceSnapshotHash: policy.sourceSnapshotHash,
      });
    });
  }

  public getStructuredScope(
    programHandle: string,
    signal: AbortSignal,
  ): Promise<PlatformStructuredScope> {
    return operation(signal, () => {
      const policy = this.requirePolicy(programHandle);
      return Object.freeze({
        programHandle: policy.handle,
        targets: policy.targets,
        supportingHosts: policy.supportingHosts,
        blockedHosts: policy.blockedHosts,
      });
    });
  }

  public getPolicyVersion(
    programHandle: string,
    signal: AbortSignal,
  ): Promise<PlatformPolicyVersion> {
    return operation(signal, () => {
      const policy = this.requirePolicy(programHandle);
      return Object.freeze({
        programHandle: policy.handle,
        version: policy.sourceRevision,
        policyHash: policy.upstreamPolicyHash,
      });
    });
  }

  public listReports(
    programHandle: string,
    signal: AbortSignal,
  ): Promise<readonly PlatformReportDraft[]> {
    return operation(signal, () => {
      this.requirePolicy(programHandle);
      return Object.freeze(
        [...this.#reports.values()]
          .filter((report) => report.programHandle === programHandle)
          .sort((left, right) => compareText(left.reportRef, right.reportRef)),
      );
    });
  }

  public createReportDraft(
    input: CreateReportDraftInput,
    signal: AbortSignal,
  ): Promise<PlatformReportDraft> {
    return operation(signal, () => {
      validateDraftInput(input);
      this.requirePolicy(input.programHandle);
      if (this.#reports.has(input.reportRef))
        throw new SecurityError("MOCK_REPORT_DRAFT_CONFLICT");
      const draft = Object.freeze({
        reportRef: input.reportRef,
        programHandle: input.programHandle,
        title: input.title,
        summary: input.summary,
        status: "draft" as const,
        delivery: "in_process_mock_only" as const,
      });
      this.#reports.set(draft.reportRef, draft);
      return draft;
    });
  }

  public submitReport(_reportRef: string, signal: AbortSignal): Promise<never> {
    return operation(signal, () => {
      throw new SecurityError("REPORT_SUBMISSION_DISABLED_PHASE2");
    });
  }

  private requirePolicy(programHandle: string): CompiledPlatformPolicy {
    if (!/^[A-Za-z0-9_-]{1,128}$/u.test(programHandle))
      throw new SecurityError("MOCK_PLATFORM_PROGRAM_REF_INVALID");
    const policy = this.#policies.find(
      (candidate) => candidate.handle === programHandle,
    );
    if (policy === undefined)
      throw new SecurityError("MOCK_PLATFORM_PROGRAM_NOT_FOUND");
    return policy;
  }
}

export class DisabledHackerOneAdapter implements PlatformAdapter {
  public readonly kind = "external_disabled" as const;
  public readonly platform = "hackerone" as const;

  public listProgramSnapshots(): Promise<readonly ValidatedProgramSnapshot[]> {
    return externalDisabled();
  }
  public listPrograms(): Promise<readonly PlatformProgram[]> {
    return externalDisabled();
  }
  public getProgram(): Promise<PlatformProgram> {
    return externalDisabled();
  }
  public getPolicy(): Promise<PlatformPolicyRecord> {
    return externalDisabled();
  }
  public getStructuredScope(): Promise<PlatformStructuredScope> {
    return externalDisabled();
  }
  public getPolicyVersion(): Promise<PlatformPolicyVersion> {
    return externalDisabled();
  }
  public listReports(): Promise<readonly PlatformReportDraft[]> {
    return externalDisabled();
  }
  public createReportDraft(): Promise<PlatformReportDraft> {
    return externalDisabled();
  }
  public submitReport(): Promise<never> {
    return externalDisabled();
  }
}

export class PlatformAdapterRegistry {
  readonly #snapshots: readonly ProgramSourceSnapshot[];

  public constructor(snapshots: readonly ProgramSourceSnapshot[]) {
    this.#snapshots = Object.freeze(
      snapshots.map((snapshot) => validateProgramSnapshot(snapshot).snapshot),
    );
    Object.freeze(this);
  }

  public create(adapterId: unknown): MockPlatformAdapter {
    if (adapterId === "local_mock")
      return new MockPlatformAdapter(this.#snapshots);
    if (adapterId === "hackerone" || adapterId === "bugcrowd")
      throw new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED");
    throw new SecurityError("PLATFORM_ADAPTER_UNKNOWN");
  }
}

export function assertGenuineMockPlatformAdapter(
  value: unknown,
): asserts value is MockPlatformAdapter {
  if (
    value === null ||
    typeof value !== "object" ||
    !GENUINE_MOCK_ADAPTERS.has(value) ||
    Object.getPrototypeOf(value) !== MockPlatformAdapter.prototype
  )
    throw new SecurityError("PLATFORM_ADAPTER_UNREGISTERED");
}

function validateDraftInput(input: CreateReportDraftInput): void {
  if (
    !/^[A-Za-z0-9_-]{1,128}$/u.test(input.reportRef) ||
    !/^[A-Za-z0-9_-]{1,128}$/u.test(input.programHandle) ||
    input.title.length < 1 ||
    input.title.length > 200 ||
    input.summary.length > 4_000 ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(
      `${input.title}${input.summary}`,
    )
  )
    throw new SecurityError("MOCK_REPORT_DRAFT_INVALID");
}

function operation<T>(signal: AbortSignal, run: () => T): Promise<T> {
  try {
    if (signal.aborted) throw new SecurityError("PHASE2_GLOBAL_KILL_SWITCH");
    return Promise.resolve(run());
  } catch (error) {
    return Promise.reject(
      error instanceof Error
        ? error
        : new SecurityError("PLATFORM_OPERATION_FAILED"),
    );
  }
}

function externalDisabled<T>(): Promise<T> {
  return Promise.reject(new SecurityError("EXTERNAL_INTEGRATIONS_DISABLED"));
}

function comparePolicies(
  left: CompiledPlatformPolicy,
  right: CompiledPlatformPolicy,
): number {
  return compareText(left.handle, right.handle);
}

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
