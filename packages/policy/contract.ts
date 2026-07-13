import { readFile } from "node:fs/promises";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import contractSchema from "../../schemas/test-contract.schema.json" with { type: "json" };
import { SecurityError } from "../shared/errors.js";

export type RiskTier =
  "tier_0_offline" | "tier_1_owned_read_only" | "tier_2_owned_reversible_write";

export interface TestContract {
  readonly contract_id: string;
  readonly program_handle: string;
  readonly policy_hash_sha256: string;
  readonly valid_from: string;
  readonly valid_until: string;
  readonly approved_risk_tiers: readonly RiskTier[];
  readonly account_refs: readonly string[];
  readonly asset_refs: readonly string[];
  readonly budgets: {
    readonly requests_per_minute: number;
    readonly max_concurrency: 1;
    readonly max_requests_total: number;
  };
  readonly stop_conditions: readonly string[];
  readonly approved_by: string;
  readonly signature: string;
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validate = ajv.compile<TestContract>(contractSchema);

export function validateContract(value: unknown): TestContract {
  if (!validate(value))
    throw new SecurityError(
      (validate.errors ?? [])
        .map(
          (error) =>
            `CONTRACT_SCHEMA:${error.instancePath || "/"}:${error.keyword}`,
        )
        .join("|"),
    );
  if (!/^[a-f0-9]{64}$/u.test(value.policy_hash_sha256))
    throw new SecurityError("CONTRACT_POLICY_HASH_INVALID");
  return value;
}

export async function loadContract(path: string): Promise<TestContract> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch {
    throw new SecurityError("CONTRACT_JSON_INVALID");
  }
  return validateContract(value);
}
