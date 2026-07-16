import { randomBytes, timingSafeEqual } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { types } from "node:util";
import { ControlPlaneStore } from "../control-plane/index.js";
import {
  MacOSCoreKeychainBackend,
  type CoreKeychainInspection,
  type CoreKeychainReceipt,
  type CoreKeychainStatus,
  type CoreProvisioningStateProbe,
} from "../secret-store/index.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

const PROVISIONING_DOMAIN =
  "bugbounty-copilot:dashboard:core-provisioning:v1" as const;
const PROVISIONING_CONFIRMATION = "provision_local_security_core" as const;
const SAFE_OPERATOR_ID = /^[A-Za-z0-9._@-]{1,128}$/u;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/u;
const SHA256_HEX = /^[a-f0-9]{64}$/u;
const COMPLETE_KEYCHAIN_STATUSES = Object.freeze([
  "fresh_bundle",
  "legacy_complete",
] as const);
const trustedControllers = new WeakSet();

export type CoreProvisioningProjectionStatus =
  "blocked" | "configured" | "ready" | "restart_required" | "unavailable";

export type CoreProvisioningReasonCode =
  | "CORE_PROVISIONING_BUSY"
  | "CORE_PROVISIONING_CONFIGURED"
  | "CORE_PROVISIONING_CONFLICT"
  | "CORE_PROVISIONING_READY"
  | "CORE_PROVISIONING_RESTART_REQUIRED"
  | "CORE_PROVISIONING_STARTUP_CONFIGURATION_CONFLICT"
  | "CORE_PROVISIONING_STATE_BLOCKED"
  | "CORE_PROVISIONING_UNAVAILABLE";

export interface CoreProvisioningChallenge {
  readonly nonce: string;
  readonly contextDigestSha256: string;
}

export interface CoreProvisioningProjection {
  readonly version: 1;
  readonly status: CoreProvisioningProjectionStatus;
  readonly keychainStatus: CoreKeychainStatus | "unavailable";
  readonly proposedMode: "fresh_bundle" | "legacy_complete" | null;
  readonly operatorId: string | null;
  readonly initialEventKeyVersion: 1 | null;
  readonly operatorKeyRevision: 1 | null;
  readonly canProvision: boolean;
  readonly restartRequired: boolean;
  readonly secretInputAccepted: false;
  readonly reasonCode: CoreProvisioningReasonCode;
  readonly challenge: CoreProvisioningChallenge | null;
}

export interface LocalCoreProvisioningControllerOptions {
  readonly backend: MacOSCoreKeychainBackend;
  readonly store: ControlPlaneStore;
  readonly eventStoreDirectory: string;
  readonly operatorId: string;
  readonly startupKeychainStatus?: CoreKeychainStatus;
  readonly configurationAllowed: boolean;
}

interface ProvisioningRequest {
  readonly version: 1;
  readonly confirmation: typeof PROVISIONING_CONFIRMATION;
  readonly nonce: string;
  readonly contextDigestSha256: string;
}

interface KillSwitchBinding {
  readonly controlPlaneId: string;
  readonly expectedRevision: number;
  readonly contextDigestSha256: string;
}

interface EligibleObservation {
  readonly inspection: CoreKeychainInspection;
  readonly stateDigestSha256: string;
  readonly killSwitch: KillSwitchBinding;
}

interface InternalChallenge extends CoreProvisioningChallenge {
  readonly stateDigestSha256: string;
}

export class LocalCoreProvisioningController {
  readonly #backend: MacOSCoreKeychainBackend;
  readonly #store: ControlPlaneStore;
  readonly #stateProbe: CoreProvisioningStateProbe;
  readonly #operatorId: string;
  readonly #sessionId: string;
  readonly #startupComplete: boolean;
  readonly #configurationAllowed: boolean;
  #challenge: InternalChallenge | undefined;
  #inFlight = false;
  #completedDuringRun = false;

  public constructor(options: LocalCoreProvisioningControllerOptions) {
    if (
      types.isProxy(options) ||
      types.isProxy(options.backend) ||
      Reflect.getPrototypeOf(options.backend) !==
        MacOSCoreKeychainBackend.prototype ||
      types.isProxy(options.store) ||
      Reflect.getPrototypeOf(options.store) !== ControlPlaneStore.prototype ||
      typeof options.eventStoreDirectory !== "string" ||
      !isAbsolute(options.eventStoreDirectory) ||
      resolve(options.eventStoreDirectory) !== options.eventStoreDirectory ||
      typeof options.operatorId !== "string" ||
      !SAFE_OPERATOR_ID.test(options.operatorId) ||
      typeof options.configurationAllowed !== "boolean" ||
      (options.startupKeychainStatus !== undefined &&
        !isCoreKeychainStatus(options.startupKeychainStatus))
    )
      throw new SecurityError("CORE_PROVISIONING_CONTROLLER_INVALID");
    this.#backend = options.backend;
    this.#store = options.store;
    this.#operatorId = options.operatorId;
    this.#sessionId = randomBytes(32).toString("base64url");
    this.#startupComplete = isCompleteStatus(options.startupKeychainStatus);
    this.#configurationAllowed = options.configurationAllowed;
    this.#stateProbe = Object.freeze({
      eventStoreDirectory: options.eventStoreDirectory,
      hasOperatorCredential: () =>
        this.#store.getLocalOperatorCredential() !== undefined,
    });
    trustedControllers.add(this);
    Object.freeze(this);
  }

  public async project(): Promise<CoreProvisioningProjection> {
    assertTrustedController(this);
    if (this.#inFlight)
      return projection({
        status: "blocked",
        keychainStatus: "unavailable",
        operatorId: this.#operatorId,
        reasonCode: "CORE_PROVISIONING_BUSY",
      });
    let inspection: CoreKeychainInspection;
    try {
      inspection = await this.#backend.inspect();
    } catch {
      this.#challenge = undefined;
      return projection({
        status: "unavailable",
        keychainStatus: "unavailable",
        operatorId: this.#operatorId,
        reasonCode: "CORE_PROVISIONING_UNAVAILABLE",
      });
    }

    if (isCompleteStatus(inspection.status)) {
      this.#challenge = undefined;
      const receipt = requireReceipt(inspection);
      if (!this.#configurationAllowed)
        return projection({
          status: "blocked",
          keychainStatus: inspection.status,
          operatorId: receipt.operatorId,
          reasonCode: "CORE_PROVISIONING_STARTUP_CONFIGURATION_CONFLICT",
          initialEventKeyVersion: 1,
          operatorKeyRevision: 1,
        });
      const restartRequired =
        this.#completedDuringRun || !this.#startupComplete;
      return projection({
        status: restartRequired ? "restart_required" : "configured",
        keychainStatus: inspection.status,
        operatorId: receipt.operatorId,
        reasonCode: restartRequired
          ? "CORE_PROVISIONING_RESTART_REQUIRED"
          : "CORE_PROVISIONING_CONFIGURED",
        restartRequired,
        initialEventKeyVersion: 1,
        operatorKeyRevision: 1,
      });
    }
    if (inspection.status === "conflict") {
      this.#challenge = undefined;
      return projection({
        status: "blocked",
        keychainStatus: inspection.status,
        operatorId: this.#operatorId,
        reasonCode: "CORE_PROVISIONING_CONFLICT",
      });
    }
    if (!this.#configurationAllowed) {
      this.#challenge = undefined;
      return projection({
        status: "blocked",
        keychainStatus: inspection.status,
        operatorId: this.#operatorId,
        reasonCode: "CORE_PROVISIONING_STARTUP_CONFIGURATION_CONFLICT",
      });
    }

    let observed: EligibleObservation;
    try {
      observed = await this.observeEligibleState(inspection);
    } catch {
      this.#challenge = undefined;
      return projection({
        status: "blocked",
        keychainStatus: inspection.status,
        operatorId: this.#operatorId,
        reasonCode: "CORE_PROVISIONING_STATE_BLOCKED",
      });
    }
    const challenge = this.challengeFor(observed.stateDigestSha256);
    return projection({
      status: "ready",
      keychainStatus: inspection.status,
      proposedMode:
        inspection.status === "absent" ? "fresh_bundle" : "legacy_complete",
      operatorId: this.#operatorId,
      reasonCode: "CORE_PROVISIONING_READY",
      canProvision: true,
      challenge,
    });
  }

  public async provision(value: unknown): Promise<CoreProvisioningProjection> {
    assertTrustedController(this);
    const request = parseProvisioningRequest(value);
    if (this.#inFlight)
      throw new SecurityError("CORE_PROVISIONING_REPLAY_BLOCKED");
    const current = await this.project();
    const challenge = this.#challenge;
    if (
      current.status !== "ready" ||
      current.challenge === null ||
      challenge === undefined
    )
      throw new SecurityError("CORE_PROVISIONING_NOT_ALLOWED");
    if (
      !safeEqual(request.nonce, challenge.nonce) ||
      !safeEqual(request.contextDigestSha256, challenge.contextDigestSha256)
    )
      throw new SecurityError("CORE_PROVISIONING_CHALLENGE_INVALID");

    this.#challenge = undefined;
    this.#inFlight = true;
    try {
      const inspection = await this.#backend.inspect();
      if (
        inspection.status !== "absent" &&
        inspection.status !== "legacy_ready"
      )
        throw new SecurityError("CORE_PROVISIONING_STATE_CHANGED");
      const observed = await this.observeEligibleState(inspection);
      if (!safeEqual(observed.stateDigestSha256, challenge.stateDigestSha256))
        throw new SecurityError("CORE_PROVISIONING_STATE_CHANGED");

      const receipt =
        inspection.status === "absent"
          ? await this.#backend.provisionFresh(
              this.#operatorId,
              this.#stateProbe,
            )
          : await this.#backend.completeLegacy(
              this.#operatorId,
              this.#stateProbe,
            );
      const expectedMode =
        inspection.status === "absent" ? "fresh_bundle" : "legacy_complete";
      if (
        receipt.mode !== expectedMode ||
        receipt.operatorId !== this.#operatorId
      )
        throw new SecurityError("CORE_PROVISIONING_RECEIPT_INVALID");
      await this.assertPostProvisioningState(receipt, observed.killSwitch);
      this.#completedDuringRun = true;
    } finally {
      this.#inFlight = false;
    }
    return this.project();
  }

  private async observeEligibleState(
    inspection: CoreKeychainInspection,
  ): Promise<EligibleObservation> {
    if (
      inspection.receipt !== null ||
      (inspection.status !== "absent" && inspection.status !== "legacy_ready")
    )
      throw new SecurityError("CORE_PROVISIONING_STATE_BLOCKED");
    const before = this.killSwitchBinding();
    if (this.#store.getLocalOperatorCredential() !== undefined)
      throw new SecurityError("CORE_PROVISIONING_OPERATOR_EXISTS");
    await this.#backend.assertProvisioningPreconditions(this.#stateProbe);
    const after = this.killSwitchBinding();
    if (
      this.#store.getLocalOperatorCredential() !== undefined ||
      !sameKillSwitchBinding(before, after)
    )
      throw new SecurityError("CORE_PROVISIONING_STATE_CHANGED");
    const stateDigestSha256 = sha256(
      canonicalJson({
        version: 1,
        domain: PROVISIONING_DOMAIN,
        action: "provision",
        session_id: this.#sessionId,
        operator_id: this.#operatorId,
        keychain_status: inspection.status,
        control_plane_id: after.controlPlaneId,
        kill_switch_revision: after.expectedRevision,
        kill_switch_context_digest_sha256: after.contextDigestSha256,
        event_store_directory_sha256: sha256(
          this.#stateProbe.eventStoreDirectory,
        ),
        event_store_required_state: "absent",
        operator_credential_required_state: "absent",
      }),
    );
    return Object.freeze({ inspection, stateDigestSha256, killSwitch: after });
  }

  private killSwitchBinding(): KillSwitchBinding {
    if (!this.#store.isKillSwitchActive())
      throw new SecurityError("CORE_PROVISIONING_KILL_SWITCH_REQUIRED");
    const context = this.#store.describeKillSwitchClear();
    if (
      !Number.isSafeInteger(context.expectedRevision) ||
      context.expectedRevision < 1 ||
      !SHA256_HEX.test(context.controlPlaneId) ||
      !SHA256_HEX.test(context.contextDigestSha256)
    )
      throw new SecurityError("CORE_PROVISIONING_KILL_SWITCH_INVALID");
    return Object.freeze({
      controlPlaneId: context.controlPlaneId,
      expectedRevision: context.expectedRevision,
      contextDigestSha256: context.contextDigestSha256,
    });
  }

  private challengeFor(stateDigestSha256: string): InternalChallenge {
    const current = this.#challenge;
    if (
      current !== undefined &&
      safeEqual(current.stateDigestSha256, stateDigestSha256)
    )
      return current;
    const nonce = randomBytes(32).toString("base64url");
    const contextDigestSha256 = sha256(
      canonicalJson({
        version: 1,
        domain: PROVISIONING_DOMAIN,
        action: "provision",
        confirmation: PROVISIONING_CONFIRMATION,
        operator_id: this.#operatorId,
        state_digest_sha256: stateDigestSha256,
        nonce,
      }),
    );
    const challenge = Object.freeze({
      nonce,
      contextDigestSha256,
      stateDigestSha256,
    });
    this.#challenge = challenge;
    return challenge;
  }

  private async assertPostProvisioningState(
    receipt: CoreKeychainReceipt,
    killSwitch: KillSwitchBinding,
  ): Promise<void> {
    await this.#backend.assertProvisioningPreconditions(this.#stateProbe);
    const after = this.killSwitchBinding();
    if (!sameKillSwitchBinding(killSwitch, after))
      throw new SecurityError("CORE_PROVISIONING_STATE_CHANGED");
    const inspection = await this.#backend.inspect();
    const persisted = requireReceipt(inspection);
    if (
      persisted.mode !== receipt.mode ||
      persisted.operatorId !== receipt.operatorId ||
      !safeEqual(persisted.generation, receipt.generation)
    )
      throw new SecurityError("CORE_PROVISIONING_RECEIPT_INVALID");
  }
}

Object.freeze(LocalCoreProvisioningController.prototype);
Object.freeze(LocalCoreProvisioningController);

export function isTrustedCoreProvisioningController(
  value: unknown,
): value is LocalCoreProvisioningController {
  if (typeof value !== "object" || value === null || types.isProxy(value))
    return false;
  try {
    return (
      trustedControllers.has(value) &&
      Reflect.getPrototypeOf(value) ===
        LocalCoreProvisioningController.prototype
    );
  } catch {
    return false;
  }
}

export function unavailableCoreProvisioningProjection(): CoreProvisioningProjection {
  return projection({
    status: "unavailable",
    keychainStatus: "unavailable",
    operatorId: null,
    reasonCode: "CORE_PROVISIONING_UNAVAILABLE",
  });
}

function parseProvisioningRequest(value: unknown): ProvisioningRequest {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype
  )
    throw new SecurityError("CORE_PROVISIONING_REQUEST_INVALID");
  const expected = Object.freeze([
    "confirmation",
    "contextDigestSha256",
    "nonce",
    "version",
  ] as const);
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string") ||
    !expected.every((key) => keys.includes(key))
  )
    throw new SecurityError("CORE_PROVISIONING_REQUEST_INVALID");
  const fields = new Map<string, unknown>();
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new SecurityError("CORE_PROVISIONING_REQUEST_INVALID");
    fields.set(key, descriptor.value);
  }
  const version = fields.get("version");
  const confirmation = fields.get("confirmation");
  const nonce = fields.get("nonce");
  const contextDigestSha256 = fields.get("contextDigestSha256");
  if (
    version !== 1 ||
    confirmation !== PROVISIONING_CONFIRMATION ||
    typeof nonce !== "string" ||
    !BASE64URL_32.test(nonce) ||
    typeof contextDigestSha256 !== "string" ||
    !SHA256_HEX.test(contextDigestSha256)
  )
    throw new SecurityError("CORE_PROVISIONING_REQUEST_INVALID");
  return Object.freeze({
    version: 1,
    confirmation: PROVISIONING_CONFIRMATION,
    nonce,
    contextDigestSha256,
  });
}

function requireReceipt(
  inspection: CoreKeychainInspection,
): CoreKeychainReceipt {
  if (!isCompleteStatus(inspection.status) || inspection.receipt === null)
    throw new SecurityError("CORE_PROVISIONING_RECEIPT_INVALID");
  return inspection.receipt;
}

function sameKillSwitchBinding(
  left: KillSwitchBinding,
  right: KillSwitchBinding,
): boolean {
  return (
    left.expectedRevision === right.expectedRevision &&
    safeEqual(left.controlPlaneId, right.controlPlaneId) &&
    safeEqual(left.contextDigestSha256, right.contextDigestSha256)
  );
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  try {
    return (
      leftBytes.byteLength === rightBytes.byteLength &&
      timingSafeEqual(leftBytes, rightBytes)
    );
  } finally {
    leftBytes.fill(0);
    rightBytes.fill(0);
  }
}

function isCompleteStatus(
  value: CoreKeychainStatus | undefined,
): value is (typeof COMPLETE_KEYCHAIN_STATUSES)[number] {
  return COMPLETE_KEYCHAIN_STATUSES.some((status) => status === value);
}

function isCoreKeychainStatus(value: unknown): value is CoreKeychainStatus {
  return (
    value === "absent" ||
    value === "conflict" ||
    value === "fresh_bundle" ||
    value === "legacy_complete" ||
    value === "legacy_direct_complete" ||
    value === "legacy_ready"
  );
}

interface ProjectionParts {
  readonly status: CoreProvisioningProjectionStatus;
  readonly keychainStatus: CoreKeychainStatus | "unavailable";
  readonly operatorId: string | null;
  readonly reasonCode: CoreProvisioningReasonCode;
  readonly proposedMode?: "fresh_bundle" | "legacy_complete" | null;
  readonly initialEventKeyVersion?: 1 | null;
  readonly operatorKeyRevision?: 1 | null;
  readonly canProvision?: boolean;
  readonly restartRequired?: boolean;
  readonly challenge?: CoreProvisioningChallenge | null;
}

function projection(parts: ProjectionParts): CoreProvisioningProjection {
  return Object.freeze({
    version: 1 as const,
    status: parts.status,
    keychainStatus: parts.keychainStatus,
    proposedMode: parts.proposedMode ?? null,
    operatorId: parts.operatorId,
    initialEventKeyVersion: parts.initialEventKeyVersion ?? null,
    operatorKeyRevision: parts.operatorKeyRevision ?? null,
    canProvision: parts.canProvision ?? false,
    restartRequired: parts.restartRequired ?? false,
    secretInputAccepted: false as const,
    reasonCode: parts.reasonCode,
    challenge:
      parts.challenge === undefined || parts.challenge === null
        ? null
        : Object.freeze({
            nonce: parts.challenge.nonce,
            contextDigestSha256: parts.challenge.contextDigestSha256,
          }),
  });
}

function assertTrustedController(
  value: unknown,
): asserts value is LocalCoreProvisioningController {
  if (!isTrustedCoreProvisioningController(value))
    throw new SecurityError("CORE_PROVISIONING_CONTROLLER_UNTRUSTED");
}
