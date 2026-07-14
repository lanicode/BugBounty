import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256 } from "../../../packages/shared/canonical.js";
import { createInitialHackerOneMetadataRequestPlan } from "../../../packages/hackerone-readonly/request-policy.js";
import {
  HACKERONE_METADATA_READ_CAPABILITY,
  resolveHackerOneMetadataReadRuntime,
} from "../../../packages/hackerone-readonly/runtime.js";
import {
  bindAuthorizedHackerOneTransportPlan,
  HackerOneHttpsTransport,
} from "../../../packages/hackerone-readonly/transport.js";
import { createActivatedHackerOneActionHarness } from "../../fixtures/hackerone-action.factory.js";

const AT = "2026-07-14T12:00:00.000Z";
const encoder = new TextEncoder();
const TOKEN = encoder.encode("synthetic-production-transport-token");
const TOKEN_BINDING_DIGEST = sha256(TOKEN);

afterEach(() => {
  vi.useRealTimers();
});

describe("HackerOne production transport credential boundary", () => {
  it("rejects an untrusted structural pair before networking and consumes the plan", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(AT);
    const runtime = resolveHackerOneMetadataReadRuntime({
      version: 1,
      capability: "HACKERONE_METADATA_READ",
      external_integrations_enabled: true,
      enabled: true,
      request_budget: {
        max_requests_total: 4,
        requests_per_minute: 4,
        max_concurrency: 1,
      },
    });
    const actions = createActivatedHackerOneActionHarness(
      runtime,
      TOKEN_BINDING_DIGEST,
      AT,
    );
    try {
      const requestPlan = createInitialHackerOneMetadataRequestPlan(
        {
          version: 1,
          capability: HACKERONE_METADATA_READ_CAPABILITY,
          operation: "programs",
          handle: null,
          page: { number: 1, size: 1 },
        },
        runtime,
        {
          consumedRequests: 0,
          activeRequests: 0,
          requestsInCurrentMinute: 0,
        },
      );
      const authorization = actions.actionGate.authorizeAndReserve({
        operationId: "transport-credential-operation",
        proposalId: "transport-credential-proposal",
        plan: requestPlan,
        credentialFingerprint: TOKEN_BINDING_DIGEST,
      });
      const actionPlan = actions.actionGate.start(authorization);
      const transportPlan = bindAuthorizedHackerOneTransportPlan(
        actionPlan,
        TOKEN_BINDING_DIGEST,
      );
      const credentials = Object.freeze({
        identifier: encoder.encode("synthetic-production-identifier"),
        token: Uint8Array.from(TOKEN),
      });
      const transport = new HackerOneHttpsTransport();

      await expect(
        transport.get(transportPlan, credentials, new AbortController().signal),
      ).rejects.toThrow("HACKERONE_CREDENTIAL_LEASE_INVALID");
      expect(credentials.identifier.every((byte) => byte === 0)).toBe(true);
      expect(credentials.token.every((byte) => byte === 0)).toBe(true);

      const replay = Object.freeze({
        identifier: encoder.encode("synthetic-production-identifier"),
        token: Uint8Array.from(TOKEN),
      });
      await expect(
        transport.get(transportPlan, replay, new AbortController().signal),
      ).rejects.toThrow("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
      actions.actionGate.settle(authorization, "failed");
    } finally {
      TOKEN.fill(0);
      actions.close();
    }
  });
});
