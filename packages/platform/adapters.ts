import type {
  ProgramSourceSnapshot,
  ValidatedProgramSnapshot,
} from "../platform-source/types.js";
import { validateProgramSnapshot } from "../platform-source/fixture-source.js";

export interface PlatformAdapter {
  readonly kind: "external_disabled" | "local_mock";
  readonly platform: "hackerone" | "local_mock";
  listProgramSnapshots(
    signal: AbortSignal,
  ): Promise<readonly ValidatedProgramSnapshot[]>;
}

export class MockPlatformAdapter implements PlatformAdapter {
  public readonly kind = "local_mock" as const;
  public readonly platform = "local_mock" as const;

  public constructor(
    private readonly snapshots: readonly ProgramSourceSnapshot[],
  ) {}

  public listProgramSnapshots(
    signal: AbortSignal,
  ): Promise<readonly ValidatedProgramSnapshot[]> {
    if (signal.aborted)
      return Promise.reject(new Error("PHASE2_GLOBAL_KILL_SWITCH"));
    return Promise.resolve(this.snapshots.map(validateProgramSnapshot));
  }
}

export class DisabledHackerOneAdapter implements PlatformAdapter {
  public readonly kind = "external_disabled" as const;
  public readonly platform = "hackerone" as const;

  public listProgramSnapshots(): Promise<readonly ValidatedProgramSnapshot[]> {
    return Promise.reject(new Error("EXTERNAL_INTEGRATIONS_DISABLED"));
  }
}
