import { describe, expect, it } from "vitest";
import {
  resolveCoreStartup,
  type CoreStartupObservation,
  type LocalApplicationEnvironment,
} from "../../apps/dashboard/runtime.js";
import { CORE_OPERATOR_KEY_REFERENCE } from "../../packages/secret-store/index.js";

describe("dashboard Core startup compatibility resolution", () => {
  it("accepts canonical legacy-direct state only through generic keys and disables provisioning", () => {
    const environment: LocalApplicationEnvironment = Object.freeze({
      eventKeyMinimumVersion: "1",
      operatorKeyReference: CORE_OPERATOR_KEY_REFERENCE,
      operatorId: "legacy-operator",
      operatorKeyRevision: "1",
    });
    const resolution = resolveCoreStartup(environment, observation());

    expect(resolution).toEqual({
      environment,
      keychainMode: "legacy_direct",
      runtimeBlocked: false,
      provisioningOperatorId: "legacy-operator",
      provisioningConfigurationAllowed: false,
    });
  });

  it.each([
    {},
    { operatorId: "legacy-operator" },
    {
      operatorKeyReference: CORE_OPERATOR_KEY_REFERENCE,
      operatorId: "legacy-operator",
      operatorKeyRevision: "2",
    },
    {
      operatorKeyReference: "keychain://other/operator-ed25519-v1",
      operatorId: "legacy-operator",
      operatorKeyRevision: "1",
    },
  ] satisfies readonly LocalApplicationEnvironment[])(
    "blocks legacy-direct state for missing or mismatched environment %#",
    (environment) => {
      expect(resolveCoreStartup(environment, observation())).toMatchObject({
        keychainMode: "generic",
        runtimeBlocked: true,
        provisioningConfigurationAllowed: false,
      });
    },
  );
});

function observation(): CoreStartupObservation {
  return Object.freeze({
    state: "available" as const,
    inspection: Object.freeze({
      status: "legacy_direct_complete" as const,
      receipt: null,
    }),
  });
}
