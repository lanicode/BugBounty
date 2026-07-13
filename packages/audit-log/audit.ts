import { open, readFile } from "node:fs/promises";
import { canonicalJson, sha256 } from "../shared/canonical.js";

export interface AuditPayload {
  readonly timestamp: string;
  readonly action: string;
  readonly decision: string;
  readonly reasonCode: string;
  readonly policyHash: string;
  readonly assetRef?: string;
  readonly accountRef?: string;
}

interface AuditRecord extends AuditPayload {
  readonly sequence: number;
  readonly previousHash: string;
  readonly hash: string;
}

const GENESIS = "0".repeat(64);
const SAFE = /^[A-Za-z0-9_.:/-]{0,256}$/u;

function validatePayload(payload: AuditPayload): void {
  if (!Number.isFinite(Date.parse(payload.timestamp)))
    throw new Error("AUDIT_TIMESTAMP_INVALID");
  for (const value of [
    payload.action,
    payload.decision,
    payload.reasonCode,
    payload.policyHash,
    payload.assetRef ?? "",
    payload.accountRef ?? "",
  ])
    if (!SAFE.test(value)) throw new Error("AUDIT_VALUE_INVALID");
  if (!/^[a-f0-9]{64}$/u.test(payload.policyHash))
    throw new Error("AUDIT_POLICY_HASH_INVALID");
}

export class AuditLog {
  #lastHash = GENESIS;
  #sequence = 0;
  public constructor(private readonly path: string) {}

  public async append(payload: AuditPayload): Promise<AuditRecord> {
    validatePayload(payload);
    const base = {
      ...payload,
      sequence: this.#sequence,
      previousHash: this.#lastHash,
    };
    const hash = sha256(canonicalJson(base));
    const record: AuditRecord = { ...base, hash };
    const handle = await open(this.path, "a", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    this.#lastHash = hash;
    this.#sequence += 1;
    return record;
  }
}

export async function verifyAuditLog(
  path: string,
): Promise<{ valid: true; entries: number }> {
  let source: string;
  try {
    source = await readFile(path, "utf8");
  } catch {
    throw new Error("AUDIT_READ_FAILED");
  }
  const lines = source.split("\n").filter(Boolean);
  let previousHash = GENESIS;
  for (let sequence = 0; sequence < lines.length; sequence += 1) {
    let value: unknown;
    const line = lines[sequence];
    if (line === undefined) throw new Error("AUDIT_CHAIN_INVALID");
    try {
      value = JSON.parse(line) as unknown;
    } catch {
      throw new Error("AUDIT_JSON_INVALID");
    }
    if (
      !isAuditRecord(value) ||
      value.sequence !== sequence ||
      value.previousHash !== previousHash
    )
      throw new Error("AUDIT_CHAIN_INVALID");
    const { hash, ...base } = value;
    if (sha256(canonicalJson(base)) !== hash)
      throw new Error("AUDIT_CHAIN_INVALID");
    previousHash = hash;
  }
  return { valid: true, entries: lines.length };
}

function isAuditRecord(value: unknown): value is AuditRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  return (
    "sequence" in value &&
    Number.isInteger(value.sequence) &&
    "timestamp" in value &&
    typeof value.timestamp === "string" &&
    "action" in value &&
    typeof value.action === "string" &&
    "decision" in value &&
    typeof value.decision === "string" &&
    "reasonCode" in value &&
    typeof value.reasonCode === "string" &&
    "policyHash" in value &&
    typeof value.policyHash === "string" &&
    "previousHash" in value &&
    typeof value.previousHash === "string" &&
    "hash" in value &&
    typeof value.hash === "string"
  );
}
