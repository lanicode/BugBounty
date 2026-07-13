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

  it("fails closed when capability probes throw", () => {
    let adapterProbeCalls = 0;
    expect(
      resolvePhase2Runtime(externalConfig(), {
        secretsAvailable: () => {
          throw new Error("SECRET_STORE_UNAVAILABLE");
        },
        externalAdapterAvailable: () => {
          adapterProbeCalls += 1;
          return true;
        },
      }),
    ).toMatchObject({
      externalIntegrationsEnabled: false,
      disableReason: "SECRETS_UNAVAILABLE",
    });
    expect(adapterProbeCalls).toBe(0);

    expect(
      resolvePhase2Runtime(externalConfig(), {
        secretsAvailable: () => true,
        externalAdapterAvailable: () => {
          throw new Error("ADAPTER_PROBE_FAILED");
        },
      }),
    ).toMatchObject({
      externalIntegrationsEnabled: false,
      disableReason: "ADAPTER_UNAVAILABLE",
    });
  });

  it("never enables external integrations during phase 2", () => {
    for (const mode of ["simulation", "external"] as const) {
      for (const configured of [false, true]) {
        for (const secretsAvailable of [false, true]) {
          for (const externalAdapterAvailable of [false, true]) {
            const state = resolvePhase2Runtime(
              {
                ...externalConfig(),
                mode,
                external_integrations_enabled: configured,
              },
              { secretsAvailable, externalAdapterAvailable },
            );
            expect(state.externalIntegrationsEnabled).toBe(false);
          }
        }
      }
    }
    expect(
      resolvePhase2Runtime(externalConfig(), {
        secretsAvailable: true,
        externalAdapterAvailable: true,
      }),
    ).toMatchObject({
      externalIntegrationsEnabled: false,
      disableReason: "PHASE2_EXTERNAL_DISABLED",
    });
  });

  it("returns defensive deeply frozen runtime state", () => {
    const value = {
      ...externalConfig(),
      allowed_platform_hosts: ["api.platform.invalid"],
      budgets: { max_actions_total: 7, max_concurrency: 1 as const },
      human_controls: {
        require_program_policy_acceptance: true as const,
        require_terms_acceptance: true as const,
        require_report_submission_approval: true as const,
      },
    };
    const state = resolvePhase2Runtime(value, {
      secretsAvailable: true,
      externalAdapterAvailable: true,
    });
    value.allowed_platform_hosts[0] = "mutated.invalid";
    value.budgets.max_actions_total = 999;

    expect(state.config.allowed_platform_hosts).toEqual([
      "api.platform.invalid",
    ]);
    expect(state.config.budgets.max_actions_total).toBe(7);
    expect(Object.isFrozen(state)).toBe(true);
    expect(Object.isFrozen(state.config)).toBe(true);
    expect(Object.isFrozen(state.config.allowed_platform_hosts)).toBe(true);
    expect(Object.isFrozen(state.config.budgets)).toBe(true);
    expect(Object.isFrozen(state.config.human_controls)).toBe(true);
  });
});
