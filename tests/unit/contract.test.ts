import { expect, it } from "vitest";
import { validateContract } from "../../packages/policy/contract.js";
import { contract } from "../fixtures/factories.js";

it("validates campaign contracts and rejects unknown fields", () => {
  expect(validateContract(contract()).contract_id).toBe("contract-1");
  expect(() => validateContract({ ...contract(), unknown: true })).toThrow(
    /CONTRACT_SCHEMA/,
  );
  expect(() =>
    validateContract({ ...contract(), policy_hash_sha256: "invalid" }),
  ).toThrow();
});
