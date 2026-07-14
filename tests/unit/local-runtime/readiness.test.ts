import { describe, expect, it } from "vitest";
import {
  deriveRuntimeReadiness,
  type RuntimeReadinessInput,
} from "../../../packages/local-runtime/index.js";

function readyInput(
  overrides: Partial<RuntimeReadinessInput> = {},
): RuntimeReadinessInput {
  return {
    platform: "darwin",
    eventKeyMinimumVersion: "1",
    operatorKeyReference: "keychain://bugbounty-copilot/operator-ed25519-v1",
    operatorId: "local-reviewer",
    operatorKeyRevision: "1",
    secretStoreProbe: "available",
    demoSaasReady: true,
    databaseReady: true,
    ...overrides,
  };
}

describe("local runtime readiness", () => {
  it.each([1, "1", 10_000, "10000"])(
    "is ready for the exact validated local runtime with event minimum %j",
    (eventKeyMinimumVersion) => {
      const readiness = deriveRuntimeReadiness(
        readyInput({ eventKeyMinimumVersion }),
      );

      expect(readiness).toEqual({
        status: "ready",
        ready: true,
        platformStatus: "ready",
        eventKeyMinimumVersionStatus: "ready",
        operatorStatus: "ready",
        secretStoreStatus: "ready",
        demoSaasStatus: "ready",
        databaseStatus: "ready",
        externalIntegrationsEnabled: false,
        aiProviderStatus: "disabled_not_implemented",
        browserWorkerStatus: "test_harness_only",
        killSwitchAssumedActive: true,
        reasonCodes: ["RUNTIME_READY"],
      });
      expect(Object.isFrozen(readiness)).toBe(true);
      expect(Object.isFrozen(readiness.reasonCodes)).toBe(true);
    },
  );

  it("requires explicit operator setup when all three operator fields are absent", () => {
    const readiness = deriveRuntimeReadiness(
      readyInput({
        operatorKeyReference: undefined,
        operatorId: undefined,
        operatorKeyRevision: undefined,
      }),
    );

    expect(readiness.status).toBe("setup_required");
    expect(readiness.ready).toBe(false);
    expect(readiness.operatorStatus).toBe("setup_required");
    expect(readiness.reasonCodes).toEqual(["RUNTIME_OPERATOR_SETUP_REQUIRED"]);
    expect(readiness.killSwitchAssumedActive).toBe(true);
  });

  it("requires setup when the event-key minimum is absent", () => {
    const readiness = deriveRuntimeReadiness(
      readyInput({ eventKeyMinimumVersion: undefined }),
    );

    expect(readiness.status).toBe("setup_required");
    expect(readiness.ready).toBe(false);
    expect(readiness.eventKeyMinimumVersionStatus).toBe("setup_required");
    expect(readiness.reasonCodes).toEqual([
      "RUNTIME_EVENT_KEY_MINIMUM_VERSION_SETUP_REQUIRED",
    ]);
  });

  it("reports all missing configuration without treating it as malformed", () => {
    const readiness = deriveRuntimeReadiness(
      readyInput({
        eventKeyMinimumVersion: undefined,
        operatorKeyReference: undefined,
        operatorId: undefined,
        operatorKeyRevision: undefined,
      }),
    );

    expect(readiness.status).toBe("setup_required");
    expect(readiness.reasonCodes).toEqual([
      "RUNTIME_EVENT_KEY_MINIMUM_VERSION_SETUP_REQUIRED",
      "RUNTIME_OPERATOR_SETUP_REQUIRED",
    ]);
  });

  it("requires an actual secret-store probe before reporting ready", () => {
    const readiness = deriveRuntimeReadiness(
      readyInput({ secretStoreProbe: "not_checked" }),
    );

    expect(readiness.status).toBe("setup_required");
    expect(readiness.ready).toBe(false);
    expect(readiness.secretStoreStatus).toBe("setup_required");
    expect(readiness.reasonCodes).toEqual([
      "RUNTIME_SECRET_STORE_SETUP_REQUIRED",
    ]);
  });

  it.each([
    { operatorKeyReference: undefined },
    { operatorId: undefined },
    { operatorKeyRevision: undefined },
    { operatorKeyReference: "secret://wrong/scheme" },
    { operatorKeyReference: "keychain://service/../account" },
    { operatorId: "contains whitespace" },
    { operatorId: "" },
    { operatorKeyRevision: 0 },
    { operatorKeyRevision: "01" },
    { operatorKeyRevision: Number.MAX_SAFE_INTEGER + 1 },
  ])("blocks partial or invalid operator configuration %j", (override) => {
    const readiness = deriveRuntimeReadiness(readyInput(override));

    expect(readiness.status).toBe("blocked");
    expect(readiness.operatorStatus).toBe("blocked");
    expect(readiness.reasonCodes).toContain(
      "RUNTIME_OPERATOR_CONFIGURATION_INVALID",
    );
  });

  it.each([
    null,
    0,
    -1,
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
    "",
    "0",
    "01",
    "+1",
    " 1",
    "1 ",
    "1.0",
    10_001,
    "10001",
    "9007199254740992",
  ])("blocks invalid event-key minimum %j without a default", (value) => {
    const readiness = deriveRuntimeReadiness(
      readyInput({ eventKeyMinimumVersion: value }),
    );

    expect(readiness.ready).toBe(false);
    expect(readiness.eventKeyMinimumVersionStatus).toBe("blocked");
    expect(readiness.reasonCodes).toContain(
      "RUNTIME_EVENT_KEY_MINIMUM_VERSION_INVALID",
    );
  });

  it.each([
    [readyInput({ platform: "linux" }), "RUNTIME_PLATFORM_UNSUPPORTED"],
    [
      readyInput({ secretStoreProbe: "unavailable" }),
      "RUNTIME_SECRET_STORE_UNAVAILABLE",
    ],
    [readyInput({ secretStoreProbe: "error" }), "RUNTIME_SECRET_STORE_ERROR"],
    [readyInput({ demoSaasReady: false }), "RUNTIME_DEMO_SAAS_NOT_READY"],
    [readyInput({ databaseReady: false }), "RUNTIME_DATABASE_NOT_READY"],
  ] as const)("blocks an unavailable runtime gate", (input, reasonCode) => {
    const readiness = deriveRuntimeReadiness(input);

    expect(readiness.status).toBe("blocked");
    expect(readiness.ready).toBe(false);
    expect(readiness.reasonCodes).toContain(reasonCode);
    expect(readiness.externalIntegrationsEnabled).toBe(false);
    expect(readiness.killSwitchAssumedActive).toBe(true);
  });

  it.each([
    null,
    undefined,
    [],
    new Date(),
    Object.create(null),
    { ...readyInput(), extra: true },
    { platform: "darwin" },
  ])("fails closed without throwing for a non-exact input %#", (input) => {
    expect(() => deriveRuntimeReadiness(input)).not.toThrow();
    expect(deriveRuntimeReadiness(input)).toMatchObject({
      status: "blocked",
      ready: false,
      killSwitchAssumedActive: true,
      reasonCodes: ["RUNTIME_INPUT_INVALID"],
    });
  });

  it.each([
    { field: "platform", value: 42 },
    { field: "secretStoreProbe", value: "unknown" },
    { field: "demoSaasReady", value: "true" },
    { field: "databaseReady", value: 1 },
  ])("blocks malformed base field $field", ({ field, value }) => {
    const input: Record<string, unknown> = { ...readyInput() };
    input[field] = value;

    expect(deriveRuntimeReadiness(input)).toMatchObject({
      status: "blocked",
      ready: false,
      reasonCodes: ["RUNTIME_INPUT_INVALID"],
    });
  });

  it("blocks symbol additions and accepts an exact frozen data record", () => {
    const frozen = Object.freeze(readyInput());
    const withSymbol = { ...readyInput(), [Symbol("extra")]: true };

    expect(deriveRuntimeReadiness(frozen).ready).toBe(true);
    expect(deriveRuntimeReadiness(withSymbol).reasonCodes).toEqual([
      "RUNTIME_INPUT_INVALID",
    ]);
  });

  it("rejects accessors without invoking them", () => {
    let accessorCalls = 0;
    const input = readyInput();
    Object.defineProperty(input, "operatorId", {
      enumerable: true,
      configurable: true,
      get: () => {
        accessorCalls += 1;
        return "sensitive-accessor-marker";
      },
    });

    const readiness = deriveRuntimeReadiness(input);

    expect(accessorCalls).toBe(0);
    expect(readiness.reasonCodes).toEqual(["RUNTIME_INPUT_INVALID"]);
  });

  it("rejects transparent and revoked proxies without throwing", () => {
    const transparent = new Proxy(readyInput(), {});
    const revocable = Proxy.revocable(readyInput(), {});
    revocable.revoke();

    for (const input of [transparent, revocable.proxy]) {
      expect(() => deriveRuntimeReadiness(input)).not.toThrow();
      expect(deriveRuntimeReadiness(input).status).toBe("blocked");
      expect(deriveRuntimeReadiness(input).reasonCodes).toEqual([
        "RUNTIME_INPUT_INVALID",
      ]);
    }
  });

  it("never projects references, identities, error text, or secret markers", () => {
    const marker = "sensitive_marker_7f31c9";
    const readiness = deriveRuntimeReadiness(
      readyInput({
        operatorKeyReference: `keychain://${marker}/${marker}`,
        operatorId: marker,
      }),
    );
    const serialized = JSON.stringify(readiness);

    expect(readiness.ready).toBe(true);
    expect(serialized).not.toContain(marker);
    expect(serialized).not.toContain("keychain://");
    expect(serialized).not.toContain("local-reviewer");
  });
});
