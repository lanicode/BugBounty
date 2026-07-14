import { describe, expect, it } from "vitest";
import {
  HACKERONE_METADATA_READ_CAPABILITY,
  isTrustedHackerOneMetadataReadRuntime,
  resolveHackerOneMetadataReadRuntime,
} from "../../../packages/hackerone-readonly/runtime.js";

function validConfig(): Record<string, unknown> {
  return {
    version: 1,
    capability: HACKERONE_METADATA_READ_CAPABILITY,
    external_integrations_enabled: true,
    enabled: true,
    request_budget: {
      max_requests_total: 250,
      requests_per_minute: 20,
      max_concurrency: 1,
    },
  };
}

describe("HackerOne read-only metadata runtime", () => {
  it("enables only the isolated explicitly configured capability", () => {
    const state = resolveHackerOneMetadataReadRuntime(validConfig());

    expect(state).toEqual({
      capability: "HACKERONE_METADATA_READ",
      configured: true,
      enabled: true,
      externalIntegrationsEnabled: true,
      disableReason: null,
      requestBudget: {
        maxRequestsTotal: 250,
        requestsPerMinute: 20,
        maxConcurrency: 1,
      },
    });
    expect(isTrustedHackerOneMetadataReadRuntime(state)).toBe(true);
    expect(Object.isFrozen(state)).toBe(true);
    expect(Object.isFrozen(state.requestBudget)).toBe(true);
  });

  it("fails closed for missing configuration with a zero budget", () => {
    const state = resolveHackerOneMetadataReadRuntime(undefined);

    expect(state.enabled).toBe(false);
    expect(state.externalIntegrationsEnabled).toBe(false);
    expect(state.disableReason).toBe("CONFIG_MISSING");
    expect(state.requestBudget).toEqual({
      maxRequestsTotal: 0,
      requestsPerMinute: 0,
      maxConcurrency: 1,
    });
    expect(isTrustedHackerOneMetadataReadRuntime(state)).toBe(true);
  });

  it("keeps the capability off when either explicit switch is false", () => {
    expect(
      resolveHackerOneMetadataReadRuntime({
        ...validConfig(),
        external_integrations_enabled: false,
      }),
    ).toMatchObject({
      configured: true,
      enabled: false,
      externalIntegrationsEnabled: false,
      disableReason: "EXTERNAL_INTEGRATIONS_DISABLED",
    });
    expect(
      resolveHackerOneMetadataReadRuntime({
        ...validConfig(),
        enabled: false,
      }),
    ).toMatchObject({
      configured: true,
      enabled: false,
      externalIntegrationsEnabled: true,
      disableReason: "CAPABILITY_DISABLED",
    });
  });

  it.each([
    null,
    {},
    { ...validConfig(), extra: true },
    { ...validConfig(), version: 2 },
    { ...validConfig(), capability: "TARGET_REQUEST" },
    { ...validConfig(), external_integrations_enabled: "true" },
    { ...validConfig(), enabled: 1 },
    {
      ...validConfig(),
      request_budget: {
        max_requests_total: 0,
        requests_per_minute: 20,
        max_concurrency: 1,
      },
    },
    {
      ...validConfig(),
      request_budget: {
        max_requests_total: 250,
        requests_per_minute: 101,
        max_concurrency: 1,
      },
    },
    {
      ...validConfig(),
      request_budget: {
        max_requests_total: 250,
        requests_per_minute: 20,
        max_concurrency: 2,
      },
    },
    {
      ...validConfig(),
      request_budget: {
        max_requests_total: 250,
        requests_per_minute: 20,
        max_concurrency: 1,
        extra: true,
      },
    },
  ])("rejects malformed configuration without throwing", (value) => {
    const state = resolveHackerOneMetadataReadRuntime(value);
    expect(state).toMatchObject({
      configured: false,
      enabled: false,
      externalIntegrationsEnabled: false,
      disableReason: "CONFIG_INVALID",
    });
    expect(state.requestBudget.maxRequestsTotal).toBe(0);
  });

  it("does not execute accessors or accept proxies", () => {
    let accessed = false;
    const accessor = validConfig();
    Object.defineProperty(accessor, "enabled", {
      enumerable: true,
      get() {
        accessed = true;
        return true;
      },
    });
    const proxied = new Proxy(validConfig(), {});

    expect(resolveHackerOneMetadataReadRuntime(accessor).enabled).toBe(false);
    expect(accessed).toBe(false);
    expect(resolveHackerOneMetadataReadRuntime(proxied).enabled).toBe(false);
  });

  it("does not trust a structurally identical caller object", () => {
    const state = resolveHackerOneMetadataReadRuntime(validConfig());
    expect(
      isTrustedHackerOneMetadataReadRuntime({
        ...state,
        requestBudget: { ...state.requestBudget },
      }),
    ).toBe(false);
  });
});
