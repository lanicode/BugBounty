import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, expect, it } from "vitest";
import { sha256 } from "../../../packages/shared/canonical.js";
import { SecurityError } from "../../../packages/shared/errors.js";
import {
  HackerOneReadOnlyClient,
  type HackerOneReadOnlyClientOptions,
} from "../../../packages/hackerone-readonly/client.js";
import type {
  HackerOneCredentialAccess,
  HackerOneCredentialPair,
  HackerOneCredentialPresence,
} from "../../../packages/hackerone-readonly/credential-vault.js";
import { resolveHackerOneMetadataReadRuntime } from "../../../packages/hackerone-readonly/runtime.js";
import type {
  HackerOneAuditSink,
  HackerOneTransport,
  HackerOneTransportPlan,
  HackerOneTransportResponse,
} from "../../../packages/hackerone-readonly/transport.js";
import type { HackerOneRequestAuditEvent } from "../../../packages/hackerone-readonly/types.js";
import {
  createActivatedHackerOneActionHarness,
  type ActivatedHackerOneActionHarness,
} from "../../fixtures/hackerone-action.factory.js";

const encoder = new TextEncoder();
const FIXED_TIME = "2026-07-14T12:00:00.000Z";
const SYNTHETIC_IDENTIFIER = "synthetic-client-identifier";
const SYNTHETIC_TOKEN = "synthetic-client-token";
const SYNTHETIC_BINDING_DIGEST = sha256(encoder.encode(SYNTHETIC_TOKEN));
const SYNTHETIC_FINGERPRINT = SYNTHETIC_BINDING_DIGEST.slice(0, 12);
const actionHarnesses: ActivatedHackerOneActionHarness[] = [];

afterEach(() => {
  while (actionHarnesses.length > 0) actionHarnesses.pop()?.close();
});

type TransportStep =
  | Error
  | HackerOneTransportResponse
  | ((
      plan: HackerOneTransportPlan,
      signal: AbortSignal,
    ) => Promise<HackerOneTransportResponse>);

class FakeCredentialAccess implements HackerOneCredentialAccess {
  public loadCount = 0;
  public readonly returned: HackerOneCredentialPair[] = [];
  public failure: Error | undefined;
  public tokenBindingDigest = SYNTHETIC_BINDING_DIGEST;

  public probe(): Promise<HackerOneCredentialPresence> {
    return Promise.resolve({
      identifierPresent: true,
      tokenPresent: true,
      tokenFingerprint: SYNTHETIC_FINGERPRINT,
      tokenBindingDigest: this.tokenBindingDigest,
      secretStoreAvailable: true,
    });
  }

  public load(): Promise<HackerOneCredentialPair> {
    this.loadCount += 1;
    if (this.failure !== undefined) return Promise.reject(this.failure);
    const pair = Object.freeze({
      identifier: encoder.encode(SYNTHETIC_IDENTIFIER),
      token: encoder.encode(SYNTHETIC_TOKEN),
    });
    this.returned.push(pair);
    return Promise.resolve(pair);
  }

  public store(): Promise<string> {
    return Promise.reject(new Error("SYNTHETIC_UNUSED_STORE"));
  }

  public storeBytes(): Promise<string> {
    return Promise.reject(new Error("SYNTHETIC_UNUSED_STORE_BYTES"));
  }

  public remove(): Promise<void> {
    return Promise.reject(new Error("SYNTHETIC_UNUSED_REMOVE"));
  }
}

class FakeTransport implements HackerOneTransport {
  public readonly calls: {
    readonly plan: HackerOneTransportPlan;
    readonly identifierCopy: Uint8Array;
    readonly tokenCopy: Uint8Array;
  }[] = [];
  public active = 0;
  public maximumActive = 0;

  public constructor(private readonly steps: TransportStep[]) {}

  public get(
    plan: HackerOneTransportPlan,
    credentials: HackerOneCredentialPair,
    signal: AbortSignal,
  ): Promise<HackerOneTransportResponse> {
    this.calls.push({
      plan: Object.freeze({ ...plan }),
      identifierCopy: Uint8Array.from(credentials.identifier),
      tokenCopy: Uint8Array.from(credentials.token),
    });
    this.active += 1;
    this.maximumActive = Math.max(this.maximumActive, this.active);
    const step = this.steps.shift();
    const pending =
      step === undefined
        ? Promise.reject(new Error("SYNTHETIC_TRANSPORT_STEP_MISSING"))
        : step instanceof Error
          ? Promise.reject(step)
          : typeof step === "function"
            ? step(plan, signal)
            : Promise.resolve(step);
    return pending.finally(() => {
      this.active -= 1;
    });
  }
}

function runtime(enabled = true) {
  return resolveHackerOneMetadataReadRuntime({
    version: 1,
    capability: "HACKERONE_METADATA_READ",
    external_integrations_enabled: enabled,
    enabled,
    request_budget: {
      max_requests_total: 100,
      requests_per_minute: 100,
      max_concurrency: 1,
    },
  });
}

function response(
  statusCode: number,
  value: unknown = { data: [] },
  overrides: Partial<
    Omit<HackerOneTransportResponse, "body" | "statusCode">
  > & { readonly body?: Uint8Array } = {},
): HackerOneTransportResponse {
  const body = overrides.body ?? encoder.encode(JSON.stringify(value));
  return {
    statusCode,
    body,
    contentType: overrides.contentType ?? "application/vnd.api+json",
    contentTypeCount: overrides.contentTypeCount ?? 1,
    contentEncoding: overrides.contentEncoding ?? null,
    locationPresent: overrides.locationPresent ?? false,
    durationMs: overrides.durationMs ?? 1,
    responseBytes: overrides.responseBytes ?? body.byteLength,
  };
}

function programResource(id: string, handle: string): Record<string, unknown> {
  return {
    id,
    type: "program",
    attributes: {
      handle,
      name: `Synthetic ${handle}`,
      currency: "USD",
      policy: "Synthetic local-only policy.",
      submission_state: "open",
      state: "public_mode",
      offers_bounties: true,
      open_scope: false,
      gold_standard_safe_harbor: true,
      bookmarked: false,
      number_of_reports_for_user: 0,
      number_of_valid_reports_for_user: 0,
      started_accepting_at: null,
      created_at: null,
      updated_at: null,
    },
  };
}

function harness(
  steps: TransportStep[],
  overrides: Partial<HackerOneReadOnlyClientOptions> = {},
): {
  readonly audit: HackerOneRequestAuditEvent[];
  readonly client: HackerOneReadOnlyClient;
  readonly credentials: FakeCredentialAccess;
  readonly transport: FakeTransport;
  readonly actions: ActivatedHackerOneActionHarness;
} {
  const credentials = new FakeCredentialAccess();
  const transport = new FakeTransport(steps);
  const audit: HackerOneRequestAuditEvent[] = [];
  const auditSink: HackerOneAuditSink = (event) => {
    audit.push(event);
  };
  const selectedRuntime = overrides.runtime ?? runtime();
  const actions = createActivatedHackerOneActionHarness(
    selectedRuntime,
    SYNTHETIC_BINDING_DIGEST,
  );
  actionHarnesses.push(actions);
  const client = new HackerOneReadOnlyClient({
    runtime: selectedRuntime,
    credentials,
    transport,
    actionGate: actions.actionGate,
    audit: auditSink,
    now: () => new Date(FIXED_TIME),
    minimumIntervalMs: 0,
    ...overrides,
  });
  return { audit, client, credentials, transport, actions };
}

function expectCredentialBuffersZeroed(
  credentials: FakeCredentialAccess,
): void {
  for (const pair of credentials.returned) {
    expect(pair.identifier.every((byte) => byte === 0)).toBe(true);
    expect(pair.token.every((byte) => byte === 0)).toBe(true);
  }
}

describe("HackerOne connection test", () => {
  it("performs exactly one fixed request, ignores pagination, and emits body-free audit", async () => {
    const next =
      "https://api.hackerone.com/v1/hackers/programs?page[number]=2&page[size]=1";
    const wireResponse = response(200, {
      data: [programResource("synthetic-id-1", "synthetic-one")],
      links: { next },
    });
    const context = harness([wireResponse]);

    const result = await context.client.connectionTest(
      new AbortController().signal,
    );

    expect(result).toMatchObject({
      result: "connected",
      recordCount: 1,
      schemaValid: true,
      redactedStatus: "HACKERONE_CONNECTION_OK",
    });
    expect(context.transport.calls).toHaveLength(1);
    expect(context.transport.calls[0]?.plan).toMatchObject({
      endpointClass: "programs",
      requestTarget: "/v1/hackers/programs?page[number]=1&page[size]=1",
      credentialFingerprint: SYNTHETIC_BINDING_DIGEST,
      tokenBindingDigest: SYNTHETIC_BINDING_DIGEST,
    });
    expect(context.credentials.loadCount).toBe(1);
    expectCredentialBuffersZeroed(context.credentials);
    expect(wireResponse.body.every((byte) => byte === 0)).toBe(true);
    expect(context.audit).toHaveLength(1);
    expect(context.audit[0]).toMatchObject({
      actionClass: "HACKERONE_METADATA_READ",
      endpointClass: "programs",
      outcome: "response",
      statusCode: 200,
    });
    expect(context.audit[0]?.requestId).toMatch(/^[a-f0-9]{32}$/u);
    expect(Object.keys(context.audit[0] ?? {}).sort()).toEqual([
      "actionClass",
      "durationMs",
      "endpointClass",
      "outcome",
      "requestId",
      "statusCode",
    ]);
    const serializedAudit = JSON.stringify(context.audit);
    expect(serializedAudit).not.toContain(SYNTHETIC_IDENTIFIER);
    expect(serializedAudit).not.toContain(SYNTHETIC_TOKEN);
    expect(serializedAudit).not.toContain("synthetic-one");
    expect(serializedAudit).not.toContain(next);
  });

  it.each([
    [401, "invalid_credentials"],
    [403, "unauthorized"],
    [404, "unavailable"],
    [429, "rate_limited"],
    [500, "unavailable"],
    [502, "unavailable"],
  ] as const)("maps HTTP %s to %s without retry", async (status, expected) => {
    const context = harness([response(status)]);
    const result = await context.client.connectionTest(
      new AbortController().signal,
    );
    expect(result.result).toBe(expected);
    expect(result.recordCount).toBe(0);
    expect(result.schemaValid).toBe(false);
    expect(context.transport.calls).toHaveLength(1);
    expect(context.credentials.loadCount).toBe(1);
    expectCredentialBuffersZeroed(context.credentials);
  });

  it.each([
    [
      "wrong content type",
      response(200, { data: [] }, { contentType: "text/html" }),
    ],
    [
      "duplicate content type",
      response(200, { data: [] }, { contentTypeCount: 2 }),
    ],
    [
      "invalid UTF-8",
      response(200, undefined, { body: Uint8Array.from([0xc3, 0x28]) }),
    ],
    [
      "invalid JSON",
      response(200, undefined, { body: encoder.encode("{not-json") }),
    ],
    [
      "duplicate JSON key",
      response(200, undefined, {
        body: encoder.encode('{"data":[],"data":[]}'),
      }),
    ],
    ["invalid schema", response(200, { data: [], unknown: true })],
  ])(
    "maps %s to malformed_response and zeroes the body",
    async (_label, wire) => {
      const context = harness([wire]);
      const result = await context.client.connectionTest(
        new AbortController().signal,
      );
      expect(result.result).toBe("malformed_response");
      expect(context.transport.calls).toHaveLength(1);
      expect(context.actions.actionGate.listAttempts()).toMatchObject([
        { status: "failed", revision: 2 },
      ]);
      expect(wire.body.every((byte) => byte === 0)).toBe(true);
      expectCredentialBuffersZeroed(context.credentials);
    },
  );

  it.each([
    ["redirect status", response(302, { data: [] })],
    [
      "location header signal",
      response(200, { data: [] }, { locationPresent: true }),
    ],
  ])("blocks %s without following it", async (_label, wire) => {
    const context = harness([wire]);
    const result = await context.client.connectionTest(
      new AbortController().signal,
    );
    expect(result.result).toBe("unavailable");
    expect(context.transport.calls).toHaveLength(1);
    expect(context.actions.actionGate.listAttempts()).toMatchObject([
      { status: "failed", revision: 2 },
    ]);
    expect(wire.body.every((byte) => byte === 0)).toBe(true);
  });

  it.each([
    [
      "secret store failure",
      new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE"),
      "secret_store_unavailable",
    ],
    [
      "transport size rejection",
      new SecurityError("HACKERONE_RESPONSE_TOO_LARGE"),
      "unavailable",
    ],
    [
      "transport timeout",
      new SecurityError("HACKERONE_REQUEST_TIMEOUT"),
      "unavailable",
    ],
    ["opaque transport error", new Error("SYNTHETIC_INTERNAL"), "unavailable"],
  ] as const)("maps %s to %s", async (_label, failure, expected) => {
    const context = harness([]);
    if (failure.message === "HACKERONE_SECRET_STORE_UNAVAILABLE")
      context.credentials.failure = failure;
    const actual =
      failure.message === "HACKERONE_SECRET_STORE_UNAVAILABLE"
        ? context
        : harness([failure]);
    const result = await actual.client.connectionTest(
      new AbortController().signal,
    );
    expect(result.result).toBe(expected);
    expect(actual.transport.calls).toHaveLength(
      failure.message === "HACKERONE_SECRET_STORE_UNAVAILABLE" ? 0 : 1,
    );
    expectCredentialBuffersZeroed(actual.credentials);
  });

  it("rejects a changed full token digest even when the display prefix is unchanged", async () => {
    const context = harness([response(200)]);
    context.credentials.tokenBindingDigest = `${SYNTHETIC_FINGERPRINT}${"0".repeat(52)}`;
    if (context.credentials.tokenBindingDigest === SYNTHETIC_BINDING_DIGEST)
      context.credentials.tokenBindingDigest = `${SYNTHETIC_FINGERPRINT}${"1".repeat(52)}`;

    const result = await context.client.connectionTest(
      new AbortController().signal,
    );

    expect(result.result).toBe("unavailable");
    expect(context.credentials.loadCount).toBe(0);
    expect(context.transport.calls).toHaveLength(0);
    expect(context.actions.actionGate.listAttempts()).toEqual([]);
    expectCredentialBuffersZeroed(context.credentials);
  });

  it("maps disabled runtime, kill switch, and abort to closed results before transport", async () => {
    const disabled = harness([response(200)], { runtime: runtime(false) });
    expect(
      (await disabled.client.connectionTest(new AbortController().signal))
        .result,
    ).toBe("blocked_by_policy");
    expect(disabled.transport.calls).toHaveLength(0);
    expect(disabled.credentials.loadCount).toBe(0);

    const killed = harness([response(200)]);
    killed.actions.controlPlane.setKillSwitch(
      true,
      "test-kill",
      new Date().toISOString(),
    );
    expect(
      (await killed.client.connectionTest(new AbortController().signal)).result,
    ).toBe("blocked_by_kill_switch");
    expect(killed.transport.calls).toHaveLength(0);
    expectCredentialBuffersZeroed(killed.credentials);

    const controller = new AbortController();
    controller.abort();
    const aborted = harness([response(200)]);
    expect(
      (await aborted.client.connectionTest(controller.signal)).result,
    ).toBe("blocked_by_kill_switch");
    expect(aborted.transport.calls).toHaveLength(0);
  });

  it("zeroes a received body when the kill switch closes after transport", async () => {
    const wire = response(200, { data: [] });
    const contexts: ReturnType<typeof harness>[] = [];
    const context = harness([
      () => {
        contexts[0]!.actions.controlPlane.setKillSwitch(
          true,
          "test-kill-after-transport",
          new Date().toISOString(),
        );
        return Promise.resolve(wire);
      },
    ]);
    contexts.push(context);

    const result = await context.client.connectionTest(
      new AbortController().signal,
    );

    expect(result.result).toBe("blocked_by_kill_switch");
    expect(context.transport.calls).toHaveLength(1);
    expect(wire.body.every((byte) => byte === 0)).toBe(true);
    expectCredentialBuffersZeroed(context.credentials);
  });

  it("zeroes a received body and credentials when the audit sink fails", async () => {
    const wire = response(200, { data: [] });
    const context = harness([wire], {
      audit: () => {
        throw new Error("SYNTHETIC_AUDIT_INTERNAL_DETAIL");
      },
    });

    const result = await context.client.connectionTest(
      new AbortController().signal,
    );

    expect(result.result).toBe("unavailable");
    expect(context.transport.calls).toHaveLength(1);
    expect(context.actions.actionGate.listAttempts()).toMatchObject([
      { status: "failed", revision: 2 },
    ]);
    expect(wire.body.every((byte) => byte === 0)).toBe(true);
    expectCredentialBuffersZeroed(context.credentials);
    expect(result.redactedStatus).not.toContain(
      "SYNTHETIC_AUDIT_INTERNAL_DETAIL",
    );
  });
});

describe("HackerOne pagination, retry, and serialization", () => {
  it("loads safe pages serially and follows only the validated next link", async () => {
    const first = response(200, {
      data: [programResource("synthetic-id-1", "synthetic-one")],
      links: {
        next: "https://api.hackerone.com/v1/hackers/programs?page[number]=2&page[size]=100",
      },
    });
    const second = response(200, {
      data: [programResource("synthetic-id-2", "synthetic-two")],
      links: { next: null },
    });
    const context = harness([first, second]);

    const programs = await context.client.listPrograms(
      new AbortController().signal,
    );

    expect(programs.map(({ handle }) => handle)).toEqual([
      "synthetic-one",
      "synthetic-two",
    ]);
    expect(
      context.transport.calls.map(({ plan }) => plan.requestTarget),
    ).toEqual([
      "/v1/hackers/programs?page[number]=1&page[size]=100",
      "/v1/hackers/programs?page[number]=2&page[size]=100",
    ]);
    expect(context.transport.maximumActive).toBe(1);
    expectCredentialBuffersZeroed(context.credentials);
    expect(first.body.every((byte) => byte === 0)).toBe(true);
    expect(second.body.every((byte) => byte === 0)).toBe(true);
  });

  it.each([
    [401, "HACKERONE_INVALID_CREDENTIALS"],
    [403, "HACKERONE_UNAUTHORIZED"],
    [429, "HACKERONE_RATE_LIMITED"],
  ] as const)("does not retry HTTP %s", async (status, code) => {
    const context = harness([response(status), response(200, { data: [] })]);
    await expect(
      context.client.listPrograms(new AbortController().signal),
    ).rejects.toThrow(code);
    expect(context.transport.calls).toHaveLength(1);
    expect(context.credentials.loadCount).toBe(1);
    expectCredentialBuffersZeroed(context.credentials);
  });

  it("retries HTTP 502 once and then succeeds with a fresh credential load", async () => {
    const transient = response(502);
    const success = response(200, {
      data: [programResource("synthetic-id-1", "synthetic-one")],
      links: { next: null },
    });
    const context = harness([transient, success]);

    await expect(
      context.client.listPrograms(new AbortController().signal),
    ).resolves.toHaveLength(1);
    expect(context.transport.calls).toHaveLength(2);
    expect(context.credentials.loadCount).toBe(2);
    expect(context.transport.maximumActive).toBe(1);
    expect(transient.body.every((byte) => byte === 0)).toBe(true);
    expect(success.body.every((byte) => byte === 0)).toBe(true);
    expectCredentialBuffersZeroed(context.credentials);
  });

  it("serializes overlapping top-level operations", async () => {
    const slowResponse = (): Promise<HackerOneTransportResponse> =>
      delay(10).then(() => response(200, { data: [] }));
    const context = harness([slowResponse, slowResponse]);

    const [first, second] = await Promise.all([
      context.client.connectionTest(new AbortController().signal),
      context.client.connectionTest(new AbortController().signal),
    ]);

    expect(first.result).toBe("connected");
    expect(second.result).toBe("connected");
    expect(context.transport.calls).toHaveLength(2);
    expect(context.transport.maximumActive).toBe(1);
    expectCredentialBuffersZeroed(context.credentials);
  });

  it("rejects an unsafe pagination link without issuing a second request", async () => {
    const first = response(200, {
      data: [programResource("synthetic-id-1", "synthetic-one")],
      links: {
        next: "https://synthetic.invalid/v1/hackers/programs?page[number]=2&page[size]=100",
      },
    });
    const context = harness([first]);
    await expect(
      context.client.listPrograms(new AbortController().signal),
    ).rejects.toThrow("HACKERONE_PAGINATION_BLOCKED");
    expect(context.transport.calls).toHaveLength(1);
    expectCredentialBuffersZeroed(context.credentials);
  });
});

describe("HackerOne client construction", () => {
  it.each([-1, 60_001, 1.5, Number.NaN])(
    "rejects invalid minimum interval %s",
    (minimumIntervalMs) => {
      const credentials = new FakeCredentialAccess();
      const transport = new FakeTransport([]);
      const actions = createActivatedHackerOneActionHarness(
        runtime(),
        SYNTHETIC_BINDING_DIGEST,
      );
      actionHarnesses.push(actions);
      expect(
        () =>
          new HackerOneReadOnlyClient({
            runtime: runtime(),
            credentials,
            transport,
            actionGate: actions.actionGate,
            minimumIntervalMs,
          }),
      ).toThrow("HACKERONE_RATE_LIMIT_CONFIG_INVALID");
    },
  );
});
