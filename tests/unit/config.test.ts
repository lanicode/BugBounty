import { describe, expect, it } from "vitest";
import {
  loadProgramConfig,
  validateConfigValue,
  verifyAcceptedPolicyHash,
} from "../../packages/config/loader.js";
import { programConfig } from "../fixtures/factories.js";

describe("configuration", () => {
  it("loads the complete local YAML fixture", async () => {
    await expect(
      loadProgramConfig("tests/fixtures/program.local.yaml"),
    ).resolves.toMatchObject({ startable: true });
  });
  it("canonicalizes and hashes a valid value deterministically", () => {
    const first = validateConfigValue(programConfig());
    const second = validateConfigValue(programConfig());
    expect(first.hash).toMatch(/^[a-f0-9]{64}$/);
    expect(first.hash).toBe(second.hash);
    expect(first.startable).toBe(true);
  });
  it("rejects unknown fields and embedded secret fields", () => {
    expect(() =>
      validateConfigValue({ ...programConfig(), unexpected: true }),
    ).toThrow(/CONFIG_SCHEMA/);
    expect(() =>
      validateConfigValue({ ...programConfig(), password: "do-not-persist" }),
    ).toThrow(/CONFIG_SECRET_FIELD/);
  });
  it("blocks placeholder configurations from starting", () => {
    const config = programConfig();
    expect(
      validateConfigValue({
        ...config,
        program: { ...config.program, handle: "REPLACE_ME" },
      }).startable,
    ).toBe(false);
  });
  it("stops on policy drift", () => {
    expect(() => {
      verifyAcceptedPolicyHash("a".repeat(64), "b".repeat(64));
    }).toThrow("POLICY_DRIFT");
    expect(() => {
      verifyAcceptedPolicyHash("a".repeat(64), "a".repeat(64));
    }).not.toThrow();
  });
});
