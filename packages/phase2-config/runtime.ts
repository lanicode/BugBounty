import { readFile } from "node:fs/promises";
import Ajv2020 from "ajv/dist/2020.js";
import { parseDocument } from "yaml";
import schema from "./runtime.schema.json" with { type: "json" };
import { canonicalHost } from "../config/loader.js";

export interface Phase2RuntimeConfig {
  readonly version: 1;
  readonly mode: "external" | "simulation";
  readonly external_integrations_enabled: boolean;
  readonly allowed_platform_hosts: readonly string[];
  readonly budgets: {
    readonly max_actions_total: number;
    readonly max_concurrency: 1;
  };
  readonly human_controls: {
    readonly require_program_policy_acceptance: true;
    readonly require_terms_acceptance: true;
    readonly require_report_submission_approval: true;
  };
}

export type IntegrationDisableReason =
  | "ADAPTER_UNAVAILABLE"
  | "CONFIG_DISABLED"
  | "CONFIG_INVALID"
  | "CONFIG_MISSING"
  | "SECRETS_UNAVAILABLE"
  | "SIMULATION_MODE";

export interface Phase2RuntimeState {
  readonly config: Phase2RuntimeConfig;
  readonly externalIntegrationsEnabled: boolean;
  readonly disableReason: IntegrationDisableReason | null;
}

export const SAFE_PHASE2_CONFIG: Phase2RuntimeConfig = Object.freeze({
  version: 1,
  mode: "simulation",
  external_integrations_enabled: false,
  allowed_platform_hosts: Object.freeze([]),
  budgets: Object.freeze({ max_actions_total: 20, max_concurrency: 1 }),
  human_controls: Object.freeze({
    require_program_policy_acceptance: true,
    require_terms_acceptance: true,
    require_report_submission_approval: true,
  }),
});

const ajv = new Ajv2020({ allErrors: true, strict: true, useDefaults: false });
const validate = ajv.compile<Phase2RuntimeConfig>(schema);

export function resolvePhase2Runtime(
  value: unknown,
  capabilities: {
    readonly secretsAvailable: boolean;
    readonly externalAdapterAvailable: boolean;
  },
): Phase2RuntimeState {
  if (!validate(value)) return disabled(SAFE_PHASE2_CONFIG, "CONFIG_INVALID");
  let hosts: readonly string[];
  try {
    hosts = value.allowed_platform_hosts.map(canonicalHost);
  } catch {
    return disabled(SAFE_PHASE2_CONFIG, "CONFIG_INVALID");
  }
  const config: Phase2RuntimeConfig = {
    ...value,
    allowed_platform_hosts: hosts,
  };
  if (config.mode === "simulation") return disabled(config, "SIMULATION_MODE");
  if (!config.external_integrations_enabled)
    return disabled(config, "CONFIG_DISABLED");
  if (!capabilities.secretsAvailable)
    return disabled(config, "SECRETS_UNAVAILABLE");
  if (!capabilities.externalAdapterAvailable)
    return disabled(config, "ADAPTER_UNAVAILABLE");
  return {
    config,
    externalIntegrationsEnabled: true,
    disableReason: null,
  };
}

export async function loadPhase2Runtime(
  path: string | undefined,
  capabilities: {
    readonly secretsAvailable: boolean;
    readonly externalAdapterAvailable: boolean;
  },
): Promise<Phase2RuntimeState> {
  if (path === undefined) return disabled(SAFE_PHASE2_CONFIG, "CONFIG_MISSING");
  let value: unknown;
  try {
    const source = await readFile(path, "utf8");
    const document = parseDocument(source, { uniqueKeys: true, merge: false });
    if (document.errors.length > 0 || document.warnings.length > 0)
      return disabled(SAFE_PHASE2_CONFIG, "CONFIG_INVALID");
    value = document.toJS({ maxAliasCount: 0 }) as unknown;
  } catch {
    return disabled(SAFE_PHASE2_CONFIG, "CONFIG_MISSING");
  }
  return resolvePhase2Runtime(value, capabilities);
}

function disabled(
  config: Phase2RuntimeConfig,
  disableReason: IntegrationDisableReason,
): Phase2RuntimeState {
  return { config, externalIntegrationsEnabled: false, disableReason };
}
