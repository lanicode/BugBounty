#!/usr/bin/env node
import { access } from "node:fs/promises";
import { constants } from "node:fs";
import { resolve } from "node:path";
import { verifyAuditLog } from "../../packages/audit-log/audit.js";
import {
  loadProgramConfig,
  verifyAcceptedPolicyHash,
} from "../../packages/config/loader.js";
import { loadContract } from "../../packages/policy/contract.js";
import { errorCode } from "../../packages/shared/errors.js";

function option(name: string, fallback?: string): string {
  const index = process.argv.indexOf(name);
  const value = index >= 0 ? process.argv[index + 1] : fallback;
  if (value === undefined || value.startsWith("--"))
    throw new Error(`MISSING_OPTION_${name.slice(2).toUpperCase()}`);
  return resolve(value);
}

async function main(): Promise<void> {
  const command = process.argv[2];
  if (command === "doctor") {
    const checks: Record<string, boolean> = {
      node20: Number(process.versions.node.split(".")[0]) >= 20,
      keychainAdapter: false,
    };
    try {
      await access("/usr/bin/security", constants.X_OK);
      checks["keychainAdapter"] = process.platform === "darwin";
    } catch {
      checks["keychainAdapter"] = false;
    }
    process.stdout.write(
      `${JSON.stringify({ ok: Object.values(checks).every(Boolean), checks })}\n`,
    );
    if (!Object.values(checks).every(Boolean)) process.exitCode = 1;
    return;
  }
  if (command === "validate") {
    const result = await loadProgramConfig(
      option("--config", "config/program.example.yaml"),
    );
    process.stdout.write(
      `${JSON.stringify({ valid: true, startable: result.startable, configHash: result.hash, blockers: result.blockers })}\n`,
    );
    if (!result.startable) process.exitCode = 2;
    return;
  }
  if (command === "policy:hash") {
    const result = await loadProgramConfig(
      option("--config", "config/program.example.yaml"),
    );
    process.stdout.write(`${result.hash}\n`);
    return;
  }
  if (command === "policy:verify") {
    const result = await loadProgramConfig(option("--config"));
    const contract = await loadContract(option("--contract"));
    verifyAcceptedPolicyHash(result.hash, contract.policy_hash_sha256);
    process.stdout.write(
      `${JSON.stringify({ valid: true, policyHash: result.hash })}\n`,
    );
    return;
  }
  if (command === "audit:verify") {
    process.stdout.write(
      `${JSON.stringify(await verifyAuditLog(option("--audit")))}\n`,
    );
    return;
  }
  throw new Error("UNKNOWN_COMMAND");
}

main().catch((error: unknown) => {
  process.stderr.write(
    `${JSON.stringify({ ok: false, code: errorCode(error) })}\n`,
  );
  process.exitCode = 1;
});
