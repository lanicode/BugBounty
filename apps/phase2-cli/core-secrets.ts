import { types } from "node:util";
import {
  createKeychainOperatorSigner,
  type OperatorSigner,
} from "../../packages/operator-auth/index.js";
import {
  CORE_OPERATOR_KEY_REFERENCE,
  resolveMacOSCoreRuntimeSecretStore,
  type CoreKeychainReadBackend,
  type SecretStore,
} from "../../packages/secret-store/index.js";
import { SecurityError } from "../../packages/shared/errors.js";

const SAFE_OPERATOR_ID = /^[A-Za-z0-9._@-]{1,128}$/u;

export interface Phase2CoreSecretEnvironment {
  readonly BUGBOUNTY_OPERATOR_KEY_REFERENCE?: string;
  readonly BUGBOUNTY_OPERATOR_ID?: string;
  readonly BUGBOUNTY_OPERATOR_KEY_REVISION?: string;
}

export interface Phase2CoreSecretDependencies {
  readonly core?: CoreKeychainReadBackend;
  readonly generic?: SecretStore;
}

export interface Phase2CoreSecretContext {
  readonly secretStore: SecretStore;
  readonly operatorSigner: OperatorSigner;
  readonly storageMode: "bundled" | "legacy_direct";
}

export async function createPhase2CoreSecretContext(
  environment: Phase2CoreSecretEnvironment,
  dependencies: Phase2CoreSecretDependencies = {},
): Promise<Phase2CoreSecretContext> {
  if (types.isProxy(environment) || types.isProxy(dependencies))
    throw new SecurityError("OPERATOR_SIGNER_CONFIG_INVALID");
  const resolution = await resolveMacOSCoreRuntimeSecretStore(
    dependencies.core,
    dependencies.generic,
  );
  const configured = configuredOperator(environment);
  const operator =
    resolution.mode === "bundled"
      ? bundledOperatorConfiguration(resolution.identity.receipt, configured)
      : requiredLegacyConfiguration(configured);
  const operatorSigner = await createKeychainOperatorSigner(
    resolution.secrets,
    operator,
  );
  return Object.freeze({
    secretStore: resolution.secrets,
    operatorSigner,
    storageMode: resolution.mode,
  });
}

type ConfiguredOperator =
  | { readonly kind: "missing" }
  | {
      readonly kind: "complete";
      readonly keyReference: typeof CORE_OPERATOR_KEY_REFERENCE;
      readonly operatorId: string;
      readonly keyRevision: 1;
    };

function configuredOperator(
  environment: Phase2CoreSecretEnvironment,
): ConfiguredOperator {
  const values = [
    environment.BUGBOUNTY_OPERATOR_KEY_REFERENCE,
    environment.BUGBOUNTY_OPERATOR_ID,
    environment.BUGBOUNTY_OPERATOR_KEY_REVISION,
  ] as const;
  if (values.every((value) => value === undefined))
    return Object.freeze({ kind: "missing" as const });
  const [keyReference, operatorId, keyRevision] = values;
  if (
    keyReference !== CORE_OPERATOR_KEY_REFERENCE ||
    typeof operatorId !== "string" ||
    !SAFE_OPERATOR_ID.test(operatorId) ||
    keyRevision !== "1"
  )
    throw new SecurityError("OPERATOR_SIGNER_CONFIG_INVALID");
  return Object.freeze({
    kind: "complete" as const,
    keyReference,
    operatorId,
    keyRevision: 1 as const,
  });
}

function bundledOperatorConfiguration(
  receipt: {
    readonly operatorId: string;
    readonly operatorKeyRevision: 1;
  },
  configured: ConfiguredOperator,
): {
  readonly keyReference: typeof CORE_OPERATOR_KEY_REFERENCE;
  readonly operatorId: string;
  readonly keyRevision: 1;
} {
  if (
    configured.kind === "complete" &&
    configured.operatorId !== receipt.operatorId
  )
    throw new SecurityError("OPERATOR_SIGNER_CONFIG_INVALID");
  return Object.freeze({
    keyReference: CORE_OPERATOR_KEY_REFERENCE,
    operatorId: receipt.operatorId,
    keyRevision: 1 as const,
  });
}

function requiredLegacyConfiguration(configured: ConfiguredOperator): {
  readonly keyReference: typeof CORE_OPERATOR_KEY_REFERENCE;
  readonly operatorId: string;
  readonly keyRevision: 1;
} {
  if (configured.kind !== "complete")
    throw new SecurityError("OPERATOR_SIGNER_CONFIG_INVALID");
  return Object.freeze({
    keyReference: configured.keyReference,
    operatorId: configured.operatorId,
    keyRevision: configured.keyRevision,
  });
}
