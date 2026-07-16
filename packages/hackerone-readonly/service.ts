import { errorCode, SecurityError } from "../shared/errors.js";
import type { ApprovalRecord } from "../control-plane/types.js";
import type { HackerOneMetadataActionGate } from "../external-actions/hackerone-metadata.js";
import type { HackerOneCredentialAccess } from "./credential-vault.js";
import type { HackerOneReadOnlyClient } from "./client.js";
import {
  createHackerOnePolicySnapshot,
  detectHackerOnePolicyDrift,
} from "./snapshot.js";
import type {
  HackerOneMetadataStore,
  StoredHackerOnePolicySnapshot,
  StoredHackerOneProgram,
} from "./store.js";
import type { HackerOneMetadataReadRuntimeState } from "./runtime.js";
import type {
  HackerOneIntegrationStatus,
  HackerOneConnectionTestSummary,
  HackerOneProgramSelectionResult,
  HackerOneProgramSyncResult,
} from "./types.js";
import { parseHackerOneManualImport } from "./manual-import.js";

export interface HackerOneKillSwitchReader {
  isActive(): boolean;
}

export interface HackerOneMetadataServiceOptions {
  readonly runtime: HackerOneMetadataReadRuntimeState;
  readonly store: HackerOneMetadataStore;
  readonly credentials: HackerOneCredentialAccess;
  readonly client: HackerOneReadOnlyClient;
  readonly actionGate: HackerOneMetadataActionGate;
  readonly killSwitch: HackerOneKillSwitchReader;
  readonly now?: () => Date;
}

export class HackerOneMetadataService {
  #controller = new AbortController();
  #operationRunning = false;
  #operationCompletion: Promise<void> = Promise.resolve();

  public constructor(
    private readonly options: HackerOneMetadataServiceOptions,
  ) {
    Object.freeze(this);
  }

  public async status(): Promise<HackerOneIntegrationStatus> {
    const persisted = this.options.store.getIntegrationState();
    const presence =
      this.options.runtime.enabled &&
      this.options.runtime.externalIntegrationsEnabled &&
      this.options.runtime.configured
        ? await this.probeCredentialsFailClosed()
        : Object.freeze({
            identifierPresent: false,
            tokenPresent: false,
            tokenFingerprint: null,
            tokenBindingDigest: null,
            secretStoreAvailable: false,
          });
    const killSwitchActive = this.killSwitchActive();
    const adapterEnabled =
      this.options.runtime.enabled && persisted.adapterEnabled;
    const selected =
      persisted.selectedProgramRef === null
        ? undefined
        : this.options.store.getProgram(persisted.selectedProgramRef);
    let status: HackerOneIntegrationStatus["status"] = "deactivated";
    if (adapterEnabled) {
      if (
        persisted.lastErrorCode !== null ||
        !presence.secretStoreAvailable ||
        !presence.identifierPresent ||
        !presence.tokenPresent
      )
        status = "error";
      else if (persisted.lastConnectionResult === "connected")
        status = "connected";
      else status = "configured";
    }
    return Object.freeze({
      actionClass: "HACKERONE_METADATA_READ" as const,
      status,
      externalIntegrationsEnabled:
        this.options.runtime.externalIntegrationsEnabled,
      adapterConfigured: this.options.runtime.configured,
      adapterEnabled,
      killSwitchActive,
      identifierPresent: presence.identifierPresent,
      tokenPresent: presence.tokenPresent,
      tokenFingerprint: presence.tokenFingerprint,
      lastConnectionTestAt: persisted.lastConnectionTestAt,
      lastSuccessfulConnectionAt: persisted.lastSuccessfulConnectionAt,
      lastConnectionResult: persisted.lastConnectionResult,
      lastSynchronizationAt: persisted.lastSynchronizationAt,
      lastSynchronizationResult: persisted.lastSynchronizationResult,
      importedProgramCount: this.options.store.listPrograms().length,
      lastErrorCode: persisted.lastErrorCode,
      selectedHandle: selected?.program.handle ?? null,
      apiMode: "read_only" as const,
      targetRequestsEnabled: false as const,
      reportSubmissionEnabled: false as const,
    });
  }

  public async prepareActivationApproval(input: {
    readonly approvalId: string;
    readonly operatorId: string;
    readonly createdAt: string;
  }): Promise<ApprovalRecord> {
    return this.exclusive(async () => {
      if (!this.options.runtime.enabled)
        throw new SecurityError("HACKERONE_METADATA_CAPABILITY_DISABLED");
      const presence = await this.options.credentials.probe();
      if (
        !presence.identifierPresent ||
        !presence.tokenPresent ||
        presence.tokenBindingDigest === null ||
        !presence.secretStoreAvailable
      )
        throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
      return this.options.actionGate.prepareActivationApproval({
        ...input,
        credentialFingerprint: presence.tokenBindingDigest,
      });
    });
  }

  public completeActivation(): void {
    if (this.#operationRunning)
      throw new SecurityError("HACKERONE_OPERATION_ALREADY_RUNNING");
    if (!this.options.store.getIntegrationState().adapterEnabled)
      throw new SecurityError("HACKERONE_SIGNED_ACTIVATION_REQUIRED");
    if (this.#controller.signal.aborted)
      this.#controller = new AbortController();
  }

  public async disable(): Promise<void> {
    this.disableInternal();
    await this.waitForCurrentOperation();
  }

  public engageKillSwitch(): void {
    // The process-local abort and the durable adapter state must move
    // together. Otherwise clearing the global kill switch can leave the
    // database claiming that the adapter is enabled while its AbortController
    // remains permanently aborted. Requiring a fresh signed activation after
    // every kill-switch engagement is the conservative fail-closed state.
    this.disableInternal();
  }

  private disableInternal(): void {
    // Abort first so an in-flight request cannot outlive a failed persistence
    // update. The persisted flag remains the durable gate; the controller is
    // the immediate process-local kill switch.
    this.#controller.abort(new Error("HACKERONE_ADAPTER_DISABLED"));
    const state = this.options.store.getIntegrationState();
    if (state.adapterEnabled)
      this.options.store.setAdapterEnabled(state.revision, false);
  }

  public async storeCredentials(
    identifier: string,
    token: string,
  ): Promise<void> {
    this.disableInternal();
    await this.waitForCurrentOperation();
    return this.exclusive(async () => {
      await this.options.credentials.store(identifier, token);
    });
  }

  public async storeCredentialBytes(
    identifier: Uint8Array,
    token: Uint8Array,
  ): Promise<void> {
    this.disableInternal();
    await this.waitForCurrentOperation();
    return this.exclusive(async () => {
      await this.options.credentials.storeBytes(identifier, token);
    });
  }

  public async removeCredentials(): Promise<void> {
    this.disableInternal();
    await this.waitForCurrentOperation();
    return this.exclusive(async () => {
      await this.options.credentials.remove();
    });
  }

  public async testConnection(): Promise<HackerOneConnectionTestSummary> {
    return this.exclusive(async () => {
      const result = await this.options.client.connectionTest(
        this.currentSignal(),
      );
      const state = this.options.store.getIntegrationState();
      this.options.store.recordConnectionTest({
        expectedRevision: state.revision,
        occurredAt: timestamp(this.options.now),
        result: result.result,
        errorCode: result.result === "connected" ? null : result.redactedStatus,
      });
      return result;
    });
  }

  public async synchronizePrograms(): Promise<HackerOneProgramSyncResult> {
    return this.exclusive(async () => {
      const synchronizedAt = timestamp(this.options.now);
      try {
        this.assertActionAllowed();
        const programs = await this.options.client.listPrograms(
          this.currentSignal(),
        );
        this.assertActionAllowed();
        const state = this.options.store.getIntegrationState();
        const stored =
          this.options.store.commitAuthenticatedApiCatalogSynchronization(
            programs,
            {
              expectedRevision: state.revision,
              occurredAt: synchronizedAt,
              result: "succeeded",
              errorCode: null,
            },
          );
        return Object.freeze({
          programCount: stored.length,
          pages: Math.max(1, Math.ceil(stored.length / 100)),
          synchronizedAt,
        });
      } catch (error) {
        this.recordSynchronization(
          "failed",
          synchronizedAt,
          redactedError(error),
        );
        throw asSecurityError(error);
      }
    });
  }

  public async synchronizeSelectedProgram(
    programLocalRef: string,
  ): Promise<HackerOneProgramSelectionResult> {
    return this.exclusive(async () => {
      const synchronizedAt = timestamp(this.options.now);
      try {
        this.assertActionAllowed();
        const catalogProgram =
          this.options.store.getSyncedProgram(programLocalRef);
        const metadata = await this.options.client.readSelectedProgram(
          catalogProgram.handle,
          this.currentSignal(),
        );
        this.assertActionAllowed();
        const previous = this.options.store.getCurrentSnapshot(programLocalRef);
        const snapshot = createHackerOnePolicySnapshot({
          program: metadata.program,
          structuredScopes: metadata.structuredScopes,
          scopeExclusions: metadata.scopeExclusions,
          fetchedAt: synchronizedAt,
          previousSnapshotDigest: previous?.snapshot.snapshotDigest ?? null,
        });
        const state = this.options.store.getIntegrationState();
        const committed =
          this.options.store.commitSelectedProgramSynchronization(
            programLocalRef,
            snapshot,
            {
              expectedRevision: state.revision,
              occurredAt: synchronizedAt,
              result: "succeeded",
              errorCode: null,
            },
          );
        return Object.freeze({
          snapshot: committed.stored.snapshot,
          drift: detectHackerOnePolicyDrift(
            previous?.snapshot ?? null,
            committed.stored.snapshot,
            committed.campaignsPaused,
          ),
        });
      } catch (error) {
        this.recordSynchronization(
          "failed",
          synchronizedAt,
          redactedError(error),
        );
        throw asSecurityError(error);
      }
    });
  }

  public async importManual(
    source: string,
  ): Promise<StoredHackerOnePolicySnapshot> {
    return this.exclusive(() => {
      const importedAt = timestamp(this.options.now);
      const parsed = parseHackerOneManualImport(source, importedAt);
      const snapshot = createHackerOnePolicySnapshot({
        program: parsed.program,
        structuredScopes: parsed.structuredScopes,
        scopeExclusions: parsed.scopeExclusions,
        fetchedAt: importedAt,
        previousSnapshotDigest: null,
      });
      return this.options.store.commitManualImport(parsed.program, snapshot);
    });
  }

  public async selectProgram(programLocalRef: string | null): Promise<void> {
    return this.exclusive(() => {
      this.selectProgramInternal(programLocalRef);
    });
  }

  public async bindDependentCampaign(
    programLocalRef: string,
    campaignId: string,
  ): Promise<void> {
    return this.exclusive(() => {
      this.options.store.bindDependentCampaign(
        programLocalRef,
        campaignId,
        timestamp(this.options.now),
      );
    });
  }

  public listPrograms(): readonly StoredHackerOneProgram[] {
    return this.options.store.listPrograms();
  }

  public selectedProgramRef(): string | null {
    return this.options.store.getIntegrationState().selectedProgramRef;
  }

  public currentSnapshot(
    programLocalRef: string,
  ): StoredHackerOnePolicySnapshot | undefined {
    return this.options.store.getCurrentSnapshot(programLocalRef);
  }

  public policyVersions(
    programLocalRef: string,
  ): readonly StoredHackerOnePolicySnapshot[] {
    return this.options.store.listSnapshots(programLocalRef);
  }

  public hasPausedDependentCampaigns(programLocalRef: string): boolean {
    return this.options.store.hasPausedDependentCampaigns(programLocalRef);
  }

  public async preparePolicyAcceptanceApproval(input: {
    readonly approvalId: string;
    readonly operatorId: string;
    readonly programLocalRef: string;
    readonly snapshotDigest: string;
    readonly createdAt: string;
  }): Promise<ApprovalRecord> {
    return this.exclusive(() =>
      this.options.actionGate.preparePolicyAcceptanceApproval(input),
    );
  }

  public assertActionAllowed(): void {
    if (!this.options.runtime.enabled)
      throw new SecurityError("HACKERONE_METADATA_CAPABILITY_DISABLED");
    const state = this.options.store.getIntegrationState();
    if (!state.adapterEnabled)
      throw new SecurityError("HACKERONE_ADAPTER_DISABLED");
    if (this.killSwitchActive())
      throw new SecurityError("HACKERONE_KILL_SWITCH");
  }

  private currentSignal(): AbortSignal {
    if (this.#controller.signal.aborted)
      throw new SecurityError("HACKERONE_ADAPTER_DISABLED");
    return this.#controller.signal;
  }

  private async probeCredentialsFailClosed() {
    try {
      return await this.options.credentials.probe();
    } catch {
      return Object.freeze({
        identifierPresent: false,
        tokenPresent: false,
        tokenFingerprint: null,
        tokenBindingDigest: null,
        secretStoreAvailable: false,
      });
    }
  }

  private killSwitchActive(): boolean {
    try {
      return this.options.killSwitch.isActive();
    } catch {
      return true;
    }
  }

  private recordSynchronization(
    result: "failed" | "succeeded",
    occurredAt: string,
    error: string | null,
  ): void {
    const state = this.options.store.getIntegrationState();
    this.options.store.recordSynchronization({
      expectedRevision: state.revision,
      occurredAt,
      result,
      errorCode: error,
    });
  }

  private selectProgramInternal(programLocalRef: string | null): void {
    const state = this.options.store.getIntegrationState();
    this.options.store.selectProgram(state.revision, programLocalRef);
  }

  private async exclusive<T>(operation: () => Promise<T> | T): Promise<T> {
    if (this.#operationRunning)
      throw new SecurityError("HACKERONE_OPERATION_ALREADY_RUNNING");
    this.#operationRunning = true;
    let complete!: () => void;
    this.#operationCompletion = new Promise<void>((resolve) => {
      complete = resolve;
    });
    try {
      return await operation();
    } finally {
      this.#operationRunning = false;
      complete();
    }
  }

  private async waitForCurrentOperation(): Promise<void> {
    if (this.#operationRunning) await this.#operationCompletion;
  }
}

function redactedError(error: unknown): string {
  const code = errorCode(error);
  return /^[A-Z][A-Z0-9_]{2,127}$/u.test(code)
    ? code
    : "HACKERONE_OPERATION_FAILED";
}

function asSecurityError(error: unknown): SecurityError {
  return error instanceof SecurityError
    ? error
    : new SecurityError("HACKERONE_OPERATION_FAILED");
}

function timestamp(now: (() => Date) | undefined): string {
  const value = (now ?? (() => new Date()))();
  if (!Number.isFinite(value.getTime()))
    throw new SecurityError("HACKERONE_CLOCK_INVALID");
  return value.toISOString();
}
