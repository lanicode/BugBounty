import { readFile } from "node:fs/promises";
import { domainToASCII } from "node:url";
import Ajv2020, { type ErrorObject } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parseDocument } from "yaml";
import schema from "./program.schema.json" with { type: "json" };
import type { ProgramConfig, ValidatedConfig } from "./types.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validateProgram = ajv.compile<ProgramConfig>(schema);
const PLACEHOLDER =
  /REPLACE(?:_|-)?ME|example\.(?:com|net|org)|REPLACE_AFTER_SYNC/i;
const SECRET_KEY =
  /(?:password|passwd|token|api[_-]?key|authorization|cookie|private[_-]?key)/i;

function safeErrors(errors: ErrorObject[] | null | undefined): string[] {
  return (errors ?? []).map(
    (error) => `CONFIG_SCHEMA:${error.instancePath || "/"}:${error.keyword}`,
  );
}

function walkForForbiddenKeys(value: unknown, path = ""): string[] {
  if (Array.isArray(value))
    return value.flatMap((item, index) =>
      walkForForbiddenKeys(item, `${path}/${String(index)}`),
    );
  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([key, child]) =>
      SECRET_KEY.test(key) && !key.endsWith("_ref")
        ? [`CONFIG_SECRET_FIELD:${path}/${key}`]
        : walkForForbiddenKeys(child, `${path}/${key}`),
    );
  }
  return [];
}

function semanticBlockers(config: ProgramConfig): string[] {
  const blockers: string[] = [];
  const serialized = canonicalJson(config);
  if (PLACEHOLDER.test(serialized)) blockers.push("CONFIG_PLACEHOLDER");
  if (config.network.targets.length === 0)
    blockers.push("CONFIG_EMPTY_TARGETS");
  if (
    config.program.policy_accepted_at === null ||
    config.program.policy_accepted_by === null
  )
    blockers.push("POLICY_NOT_ACCEPTED");
  const targetHosts = new Set(
    config.network.targets.map((target) => canonicalHost(target.host)),
  );
  const supportingHosts = new Set(
    config.network.supporting_hosts.map((host) => canonicalHost(host.host)),
  );
  const blocked = new Set(
    (config.network.blocked_hosts ?? []).map(canonicalHost),
  );
  for (const host of targetHosts)
    if (supportingHosts.has(host) || blocked.has(host))
      blockers.push("CONFIG_HOST_CLASS_OVERLAP");
  for (const host of supportingHosts)
    if (blocked.has(host)) blockers.push("CONFIG_HOST_CLASS_OVERLAP");
  return [...new Set(blockers)];
}

export function canonicalHost(host: string): string {
  const trimmed = host.trim().toLowerCase();
  if (trimmed.endsWith(".") || trimmed.includes("%"))
    throw new SecurityError("HOST_NON_CANONICAL");
  const ascii = domainToASCII(trimmed);
  if (ascii === "" || ascii !== trimmed || ascii.includes(".."))
    throw new SecurityError("HOST_NON_CANONICAL");
  return ascii;
}

export function validateConfigValue(value: unknown): ValidatedConfig {
  const secretFields = walkForForbiddenKeys(value);
  const firstSecretField = secretFields[0];
  if (firstSecretField !== undefined) throw new SecurityError(firstSecretField);
  if (!validateProgram(value))
    throw new SecurityError(safeErrors(validateProgram.errors).join("|"));
  for (const target of value.network.targets) {
    canonicalHost(target.host);
    for (const prefix of target.path_prefixes)
      if (prefix.includes("?") || prefix.includes("#"))
        throw new SecurityError("CONFIG_PATH_PREFIX_INVALID");
  }
  for (const host of value.network.supporting_hosts) canonicalHost(host.host);
  const canonical = canonicalJson(value);
  const blockers = semanticBlockers(value);
  return {
    config: value,
    canonical,
    hash: sha256(canonical),
    startable: blockers.length === 0,
    blockers,
  };
}

export async function loadProgramConfig(
  path: string,
): Promise<ValidatedConfig> {
  const source = await readFile(path, "utf8");
  const document = parseDocument(source, { uniqueKeys: true, merge: false });
  if (document.errors.length > 0 || document.warnings.length > 0)
    throw new SecurityError("CONFIG_YAML_INVALID");
  return validateConfigValue(document.toJS({ maxAliasCount: 0 }) as unknown);
}

export function verifyAcceptedPolicyHash(
  currentHash: string,
  acceptedHash: string,
): void {
  if (
    !/^[a-f0-9]{64}$/.test(currentHash) ||
    currentHash !== acceptedHash.toLowerCase()
  )
    throw new SecurityError("POLICY_DRIFT");
}
