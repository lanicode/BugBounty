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
  | "PHASE2_EXTERNAL_DISABLED"
  | "SECRETS_UNAVAILABLE"
  | "SIMULATION_MODE";

export interface Phase2RuntimeState {
  readonly config: Phase2RuntimeConfig;
  readonly externalIntegrationsEnabled: boolean;
  readonly disableReason: IntegrationDisableReason | null;
}

export type Phase2CapabilityProbe = boolean | (() => boolean);

export interface Phase2RuntimeCapabilities {
  readonly secretsAvailable: Phase2CapabilityProbe;
  readonly externalAdapterAvailable: Phase2CapabilityProbe;
}

export const SAFE_PHASE2_CONFIG: Phase2RuntimeConfig = freezeConfig({
  version: 1,
  mode: "simulation",
  external_integrations_enabled: false,
  allowed_platform_hosts: [],
  budgets: { max_actions_total: 20, max_concurrency: 1 },
  human_controls: {
    require_program_policy_acceptance: true,
    require_terms_acceptance: true,
    require_report_submission_approval: true,
  },
});

const ajv = new Ajv2020({ allErrors: true, strict: true, useDefaults: false });
const validate = ajv.compile<Phase2RuntimeConfig>(schema);

export function resolvePhase2Runtime(
  value: unknown,
  capabilities: Phase2RuntimeCapabilities,
): Phase2RuntimeState {
  if (!validate(value)) return disabled(SAFE_PHASE2_CONFIG, "CONFIG_INVALID");
  let hosts: readonly string[];
  try {
    hosts = value.allowed_platform_hosts.map(canonicalHost);
  } catch {
    return disabled(SAFE_PHASE2_CONFIG, "CONFIG_INVALID");
  }
  const config = freezeConfig({
    version: value.version,
    mode: value.mode,
    external_integrations_enabled: value.external_integrations_enabled,
    allowed_platform_hosts: hosts,
    budgets: value.budgets,
    human_controls: value.human_controls,
  });
  if (config.mode === "simulation") return disabled(config, "SIMULATION_MODE");
  if (!config.external_integrations_enabled)
    return disabled(config, "CONFIG_DISABLED");
  let secretsAvailable: boolean;
  try {
    secretsAvailable = probeCapability(capabilities.secretsAvailable);
  } catch {
    return disabled(config, "SECRETS_UNAVAILABLE");
  }
  if (!secretsAvailable) return disabled(config, "SECRETS_UNAVAILABLE");
  let externalAdapterAvailable: boolean;
  try {
    externalAdapterAvailable = probeCapability(
      capabilities.externalAdapterAvailable,
    );
  } catch {
    return disabled(config, "ADAPTER_UNAVAILABLE");
  }
  if (!externalAdapterAvailable) return disabled(config, "ADAPTER_UNAVAILABLE");
  return disabled(config, "PHASE2_EXTERNAL_DISABLED");
}

export async function loadPhase2Runtime(
  path: string | undefined,
  capabilities: Phase2RuntimeCapabilities,
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

function probeCapability(probe: Phase2CapabilityProbe): boolean {
  return typeof probe === "function" ? probe() : probe;
}

function disabled(
  config: Phase2RuntimeConfig,
  disableReason: IntegrationDisableReason,
): Phase2RuntimeState {
  return Object.freeze({
    config: freezeConfig(config),
    externalIntegrationsEnabled: false,
    disableReason,
  });
}

function freezeConfig(config: Phase2RuntimeConfig): Phase2RuntimeConfig {
  return Object.freeze({
    version: config.version,
    mode: config.mode,
    external_integrations_enabled: config.external_integrations_enabled,
    allowed_platform_hosts: Object.freeze([...config.allowed_platform_hosts]),
    budgets: Object.freeze({
      max_actions_total: config.budgets.max_actions_total,
      max_concurrency: config.budgets.max_concurrency,
    }),
    human_controls: Object.freeze({
      require_program_policy_acceptance:
        config.human_controls.require_program_policy_acceptance,
      require_terms_acceptance: config.human_controls.require_terms_acceptance,
      require_report_submission_approval:
        config.human_controls.require_report_submission_approval,
    }),
  });
}
