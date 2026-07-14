import type { SecretStore } from "../secret-store/store.js";

export interface EventKeyLifecycleOptions {
  readonly directory: string;
  readonly secrets: SecretStore;
  readonly keyReference: (version: number) => string;
  readonly minimumActiveKeyVersion: number;
}

export type EventKeyStateOperation =
  "initialize" | "adopt_legacy_v1" | "rotate";

export interface EventKeyStateRecord {
  readonly schemaVersion: 1;
  readonly storeId: string;
  readonly revision: number;
  readonly operation: EventKeyStateOperation;
  readonly activeKeyVersion: number;
  readonly readableKeyVersions: readonly number[];
  readonly previousRecordDigest: string;
  readonly authenticationTag: string;
}

export interface EventKeyState {
  readonly schemaVersion: 1;
  readonly storeId: string;
  readonly revision: number;
  readonly activeKeyVersion: number;
  readonly readableKeyVersions: readonly number[];
  readonly headRecordDigest: string;
}

export interface EventKeyRotationInput {
  readonly expectedActiveKeyVersion: number;
  readonly nextKeyVersion: number;
}

export interface EventKeyRotationReceipt extends EventKeyState {
  readonly previousActiveKeyVersion: number;
}

export interface EventKeyMutationRecoveryReceipt extends EventKeyState {
  readonly recoveredExistingLock: boolean;
  readonly removedEventTemporaryFiles: number;
}
