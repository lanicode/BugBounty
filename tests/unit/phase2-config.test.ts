import { describe, expect, it } from "vitest";
import {
  loadPhase2Runtime,
  resolvePhase2Runtime,
  SAFE_PHASE2_CONFIG,
} from "../../packages/phase2-config/runtime.js";

const externalConfig = () => ({
  ...SAFE_PHASE2_CONFIG,
  mode: "external" as const,
  external_integrations_enabled: true,
  allowed_platform_hosts: ["api.platform.invalid"],
});

describe("phase 2 integration gate", () => {
  it("defaults to disabled for missing and invalid configuration", async () => {
    await expect(
      loadPhase2Runtime(undefined, {
        secretsAvailable: true,
        externalAdapterAvailable: true,
      }),
    ).resolves.toMatchObject({
      externalIntegrationsEnabled: false,
      disableReason: "CONFIG_MISSING",
    });
    expect(
      resolvePhase2Runtime(
        { external_integrations_enabled: true },
        { secretsAvailable: true, externalAdapterAvailable: true },
      ),
    ).toMatchObject({
      externalIntegrationsEnabled: false,
      disableReason: "CONFIG_INVALID",
    });
  });

  it("keeps simulation and explicitly disabled modes off", () => {
    expect(
      resolvePhase2Runtime(SAFE_PHASE2_CONFIG, {
        secretsAvailable: true,
        externalAdapterAvailable: true,
      }),
    ).toMatchObject({
      externalIntegrationsEnabled: false,
      disableReason: "SIMULATION_MODE",
    });
    expect(
      resolvePhase2Runtime(
        { ...externalConfig(), external_integrations_enabled: false },
        { secretsAvailable: true, externalAdapterAvailable: true },
      ),
    ).toMatchObject({ disableReason: "CONFIG_DISABLED" });
  });

  it("fails closed when secrets or an adapter are unavailable", () => {
    expect(
      resolvePhase2Runtime(externalConfig(), {
        secretsAvailable: false,
        externalAdapterAvailable: true,
      }),
    ).toMatchObject({ disableReason: "SECRETS_UNAVAILABLE" });
    expect(
      resolvePhase2Runtime(externalConfig(), {
        secretsAvailable: true,
        externalAdapterAvailable: false,
      }),
    ).toMatchObject({ disableReason: "ADAPTER_UNAVAILABLE" });
  });

  it("requires every enablement condition simultaneously", () => {
    expect(
      resolvePhase2Runtime(externalConfig(), {
        secretsAvailable: true,
        externalAdapterAvailable: true,
      }).externalIntegrationsEnabled,
    ).toBe(true);
  });
});
