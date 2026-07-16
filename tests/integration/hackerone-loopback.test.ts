import {
  createServer,
  request,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { SecurityError } from "../../packages/shared/errors.js";
import { sha256 } from "../../packages/shared/canonical.js";
import { HackerOneReadOnlyClient } from "../../packages/hackerone-readonly/client.js";
import type { HackerOneProgram } from "../../packages/hackerone-readonly/types.js";
import type {
  HackerOneCredentialAccess,
  HackerOneCredentialPair,
  HackerOneCredentialPresence,
} from "../../packages/hackerone-readonly/credential-vault.js";
import { resolveHackerOneMetadataReadRuntime } from "../../packages/hackerone-readonly/runtime.js";
import {
  assertTransportPlan,
  type HackerOneTransport,
  type HackerOneTransportPlan,
  type HackerOneTransportResponse,
} from "../../packages/hackerone-readonly/transport.js";
import {
  createActivatedHackerOneActionHarness,
  type ActivatedHackerOneActionHarness,
} from "../fixtures/hackerone-action.factory.js";

const LOOPBACK = "127.0.0.1";
const TEST_MAX_RESPONSE_BYTES = 4_096;
const TEST_TIMEOUT_MS = 75;
const FIXED_TIME = "2026-07-14T12:00:00.000Z";
const SYNTHETIC_TOKEN_BYTES = Uint8Array.from([21, 22, 23]);
const SYNTHETIC_BINDING_DIGEST = sha256(SYNTHETIC_TOKEN_BYTES);
const SYNTHETIC_FINGERPRINT = SYNTHETIC_BINDING_DIGEST.slice(0, 12);
const actionHarnesses: ActivatedHackerOneActionHarness[] = [];

interface RecordedRequest {
  readonly method: string | undefined;
  readonly url: string | undefined;
}

type MockHandler = (
  request: IncomingMessage,
  response: ServerResponse,
) => void | Promise<void>;

class LoopbackMockServer {
  public readonly handlers: MockHandler[] = [];
  public readonly requests: RecordedRequest[] = [];
  public maximumActiveRequests = 0;
  public origin = "";
  private activeRequests = 0;
  private readonly server = createServer((incoming, response) => {
    this.activeRequests += 1;
    this.maximumActiveRequests = Math.max(
      this.maximumActiveRequests,
      this.activeRequests,
    );
    this.requests.push({ method: incoming.method, url: incoming.url });
    let completed = false;
    const complete = (): void => {
      if (completed) return;
      completed = true;
      this.activeRequests -= 1;
    };
    response.once("finish", complete);
    response.once("close", complete);
    const handler = this.handlers.shift();
    if (handler === undefined) {
      response.writeHead(500, {
        "content-type": "application/json",
        connection: "close",
      });
      response.end('{"error":"SYNTHETIC_HANDLER_MISSING"}');
      return;
    }
    void Promise.resolve(handler(incoming, response)).catch(() => {
      if (!response.headersSent)
        response.writeHead(500, {
          "content-type": "application/json",
          connection: "close",
        });
      response.end('{"error":"SYNTHETIC_HANDLER_FAILED"}');
    });
  });

  public async start(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error): void => {
        this.server.off("listening", onListening);
        reject(error);
      };
      const onListening = (): void => {
        this.server.off("error", onError);
        resolve();
      };
      this.server.once("error", onError);
      this.server.once("listening", onListening);
      this.server.listen(0, LOOPBACK);
    });
    const address = this.server.address();
    if (
      address === null ||
      typeof address === "string" ||
      address.address !== LOOPBACK
    )
      throw new Error("SYNTHETIC_LOOPBACK_BIND_FAILED");
    this.origin = `http://${LOOPBACK}:${String(address.port)}`;
  }

  public get port(): number {
    const address = this.server.address();
    if (address === null || typeof address === "string")
      throw new Error("SYNTHETIC_LOOPBACK_NOT_STARTED");
    return address.port;
  }

  public enqueue(handler: MockHandler): void {
    this.handlers.push(handler);
  }

  public enqueueJson(
    statusCode: number,
    value: unknown,
    headers: Readonly<Record<string, string | readonly string[]>> = {},
  ): void {
    this.enqueue((_incoming, response) => {
      response.writeHead(statusCode, {
        "content-type": "application/vnd.api+json",
        connection: "close",
        ...headers,
      });
      response.end(JSON.stringify(value));
    });
  }

  public reset(): void {
    this.handlers.splice(0);
    this.requests.splice(0);
    this.maximumActiveRequests = 0;
  }

  public close(): Promise<void> {
    if (!this.server.listening) return Promise.resolve();
    return new Promise((resolve, reject) => {
      this.server.close((error) => {
        if (error === undefined) resolve();
        else reject(error);
      });
      this.server.closeAllConnections();
    });
  }
}

/** Test-only transport: the logical plan stays HackerOne-bound, while the
 * actual socket is unconditionally mapped to one ephemeral loopback server. */
class LoopbackHackerOneTransport implements HackerOneTransport {
  public constructor(
    private readonly port: number,
    private readonly maximumBytes = TEST_MAX_RESPONSE_BYTES,
    private readonly timeoutMs = TEST_TIMEOUT_MS,
  ) {}

  public get(
    plan: HackerOneTransportPlan,
    _credentials: HackerOneCredentialPair,
    signal: AbortSignal,
  ): Promise<HackerOneTransportResponse> {
    assertTransportPlan(plan);
    if (signal.aborted)
      return Promise.reject(new SecurityError("HACKERONE_REQUEST_ABORTED"));
    return new Promise((resolve, reject) => {
      const started = performance.now();
      let settled = false;
      const chunks: Buffer[] = [];
      const finish = (
        error: Error | undefined,
        result?: HackerOneTransportResponse,
      ): void => {
        if (settled) return;
        settled = true;
        signal.removeEventListener("abort", onAbort);
        if (error === undefined && result !== undefined) resolve(result);
        else reject(error ?? new Error("SYNTHETIC_LOOPBACK_TRANSPORT_FAILED"));
      };
      const outgoing = request(
        {
          hostname: LOOPBACK,
          port: this.port,
          method: "GET",
          path: plan.requestTarget,
          agent: false,
          timeout: this.timeoutMs,
          headers: { accept: "application/vnd.api+json", connection: "close" },
        },
        (incoming) => {
          const statusCode = incoming.statusCode;
          if (statusCode === undefined) {
            incoming.destroy();
            finish(new SecurityError("HACKERONE_TRANSPORT_FAILED"));
            return;
          }
          let contentTypes: readonly string[];
          let contentEncoding: string | null;
          let locationPresent: boolean;
          let declaredLength: number | null;
          try {
            contentTypes = rawHeaderValues(incoming.rawHeaders, "content-type");
            const encodings = rawHeaderValues(
              incoming.rawHeaders,
              "content-encoding",
            );
            if (encodings.length > 1)
              throw new SecurityError("HACKERONE_RESPONSE_HEADERS_INVALID");
            contentEncoding = encodings[0] ?? null;
            locationPresent =
              rawHeaderValues(incoming.rawHeaders, "location").length > 0;
            declaredLength = contentLength(incoming.rawHeaders);
          } catch (error) {
            incoming.destroy();
            zeroChunks(chunks);
            finish(
              error instanceof Error
                ? error
                : new SecurityError("HACKERONE_RESPONSE_HEADERS_INVALID"),
            );
            return;
          }
          if (declaredLength !== null && declaredLength > this.maximumBytes) {
            incoming.destroy();
            finish(new SecurityError("HACKERONE_RESPONSE_TOO_LARGE"));
            return;
          }
          let bytes = 0;
          incoming.on("data", (chunk: unknown) => {
            if (!Buffer.isBuffer(chunk)) {
              incoming.destroy();
              zeroChunks(chunks);
              finish(new SecurityError("HACKERONE_RESPONSE_STREAM_INVALID"));
              return;
            }
            bytes += chunk.byteLength;
            if (bytes > this.maximumBytes) {
              chunk.fill(0);
              zeroChunks(chunks);
              incoming.destroy();
              finish(new SecurityError("HACKERONE_RESPONSE_TOO_LARGE"));
              return;
            }
            chunks.push(chunk);
          });
          incoming.once("aborted", () => {
            zeroChunks(chunks);
            finish(new SecurityError("HACKERONE_RESPONSE_ABORTED"));
          });
          incoming.once("error", () => {
            zeroChunks(chunks);
            finish(new SecurityError("HACKERONE_TRANSPORT_UNAVAILABLE"));
          });
          incoming.once("end", () => {
            const combined = Buffer.concat(chunks, bytes);
            zeroChunks(chunks);
            const body = Uint8Array.from(combined);
            combined.fill(0);
            finish(undefined, {
              statusCode,
              body,
              contentType: contentTypes[0] ?? null,
              contentTypeCount: contentTypes.length,
              contentEncoding,
              locationPresent,
              durationMs: Math.max(0, Math.round(performance.now() - started)),
              responseBytes: bytes,
            });
          });
        },
      );
      const onAbort = (): void => {
        outgoing.destroy();
        zeroChunks(chunks);
        finish(new SecurityError("HACKERONE_REQUEST_ABORTED"));
      };
      signal.addEventListener("abort", onAbort, { once: true });
      outgoing.once("timeout", () => {
        outgoing.destroy();
        zeroChunks(chunks);
        finish(new SecurityError("HACKERONE_REQUEST_TIMEOUT"));
      });
      outgoing.once("error", () => {
        zeroChunks(chunks);
        finish(new SecurityError("HACKERONE_TRANSPORT_UNAVAILABLE"));
      });
      outgoing.end();
    });
  }
}

class SyntheticCredentialAccess implements HackerOneCredentialAccess {
  public probe(): Promise<HackerOneCredentialPresence> {
    return Promise.resolve({
      identifierPresent: true,
      tokenPresent: true,
      tokenFingerprint: SYNTHETIC_FINGERPRINT,
      tokenBindingDigest: SYNTHETIC_BINDING_DIGEST,
      secretStoreAvailable: true,
    });
  }

  public load(): Promise<HackerOneCredentialPair> {
    return Promise.resolve(
      Object.freeze({
        identifier: Uint8Array.from([11, 12, 13]),
        token: Uint8Array.from(SYNTHETIC_TOKEN_BYTES),
      }),
    );
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

function client(server: LoopbackMockServer): HackerOneReadOnlyClient {
  const runtime = resolveHackerOneMetadataReadRuntime({
    version: 1,
    capability: "HACKERONE_METADATA_READ",
    external_integrations_enabled: true,
    enabled: true,
    request_budget: {
      max_requests_total: 100,
      requests_per_minute: 100,
      max_concurrency: 1,
    },
  });
  const actions = createActivatedHackerOneActionHarness(
    runtime,
    SYNTHETIC_BINDING_DIGEST,
  );
  actions.metadata.replaceAuthenticatedApiCatalog([
    synchronizedProgram("synthetic-id-1", "synthetic-one"),
  ]);
  actionHarnesses.push(actions);
  return new HackerOneReadOnlyClient({
    runtime,
    credentials: new SyntheticCredentialAccess(),
    transport: new LoopbackHackerOneTransport(server.port),
    actionGate: actions.actionGate,
    now: () => new Date(FIXED_TIME),
    minimumIntervalMs: 0,
  });
}

function synchronizedProgram(id: string, handle: string): HackerOneProgram {
  return Object.freeze({
    hackerOneId: id,
    handle,
    name: `Synthetic ${handle}`,
    currency: "USD",
    policy: "Synthetic loopback-only policy.",
    submissionState: "open",
    programState: "public_mode",
    offersBounties: true,
    openScope: false,
    goldStandardSafeHarbor: true,
    bookmarked: false,
    ownReportCount: 0,
    ownValidReportCount: 0,
    startedAcceptingAt: null,
    createdAt: null,
    updatedAt: null,
    synchronizedAt: FIXED_TIME,
    source: "hackerone_api_authenticated",
  });
}

function programResource(
  id: string | number,
  handle: string,
): Record<string, unknown> {
  return {
    id,
    type: "program",
    attributes: {
      handle,
      name: `Synthetic ${handle}`,
      currency: "USD",
      policy: "Synthetic loopback-only policy.",
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

function rawHeaderValues(
  rawHeaders: readonly string[],
  name: string,
): readonly string[] {
  const values: string[] = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    if (rawHeaders[index]?.toLowerCase() === name) {
      const value = rawHeaders[index + 1];
      if (value !== undefined) values.push(value);
    }
  }
  return values;
}

function contentLength(rawHeaders: readonly string[]): number | null {
  const values = rawHeaderValues(rawHeaders, "content-length");
  if (values.length === 0) return null;
  if (values.length !== 1 || !/^(?:0|[1-9][0-9]*)$/u.test(values[0] ?? ""))
    throw new SecurityError("HACKERONE_RESPONSE_HEADERS_INVALID");
  const value = Number(values[0]);
  if (!Number.isSafeInteger(value))
    throw new SecurityError("HACKERONE_RESPONSE_HEADERS_INVALID");
  return value;
}

function zeroChunks(chunks: readonly Buffer[]): void {
  for (const chunk of chunks) chunk.fill(0);
}

const primary = new LoopbackMockServer();
const secondary = new LoopbackMockServer();

beforeAll(async () => {
  await primary.start();
  await secondary.start();
});

afterEach(() => {
  primary.reset();
  secondary.reset();
  while (actionHarnesses.length > 0) actionHarnesses.pop()?.close();
});

afterAll(async () => {
  await Promise.all([primary.close(), secondary.close()]);
});

describe("HackerOne read-only client over test-only loopback transport", () => {
  it("completes the exact single-request connection test", async () => {
    primary.enqueueJson(200, {
      data: [programResource("synthetic-id-1", "synthetic-one")],
      links: {
        next: "https://api.hackerone.com/v1/hackers/programs?page[number]=2&page[size]=1",
      },
    });

    const result = await client(primary).connectionTest(
      new AbortController().signal,
    );

    expect(result).toMatchObject({
      result: "connected",
      recordCount: 1,
      schemaValid: true,
    });
    expect(primary.requests).toEqual([
      {
        method: "GET",
        url: "/v1/hackers/programs?page[number]=1&page[size]=1",
      },
    ]);
    expect(secondary.requests).toHaveLength(0);
  });

  it.each([
    [401, "invalid_credentials"],
    [403, "unauthorized"],
    [404, "unavailable"],
    [429, "rate_limited"],
    [500, "unavailable"],
  ] as const)("maps loopback HTTP %s to %s", async (status, expected) => {
    primary.enqueueJson(status, { errors: [{ status: String(status) }] });
    const result = await client(primary).connectionTest(
      new AbortController().signal,
    );
    expect(result.result).toBe(expected);
    expect(primary.requests).toHaveLength(1);
    expect(primary.requests[0]?.method).toBe("GET");
  });

  it("maps a loopback timeout without issuing a retry", async () => {
    primary.enqueue((_incoming, response) => {
      response.once("close", () => undefined);
    });
    const result = await client(primary).connectionTest(
      new AbortController().signal,
    );
    expect(result.result).toBe("unavailable");
    expect(primary.requests).toHaveLength(1);
  });

  it.each(["same-origin", "cross-origin"] as const)(
    "does not follow a %s loopback redirect",
    async (kind) => {
      const location =
        kind === "same-origin"
          ? `${primary.origin}/redirect-target`
          : `${secondary.origin}/redirect-target`;
      primary.enqueue((_incoming, response) => {
        response.writeHead(302, {
          location,
          "content-type": "application/json",
          connection: "close",
        });
        response.end("{}");
      });
      const result = await client(primary).connectionTest(
        new AbortController().signal,
      );
      expect(result.result).toBe("unavailable");
      expect(primary.requests).toHaveLength(1);
      expect(secondary.requests).toHaveLength(0);
    },
  );

  it("rejects wrong and duplicate content types", async () => {
    primary.enqueueJson(200, { data: [] }, { "content-type": "text/html" });
    expect(
      (await client(primary).connectionTest(new AbortController().signal))
        .result,
    ).toBe("malformed_response");

    primary.enqueueJson(
      200,
      { data: [] },
      {
        "content-type": ["application/json", "application/vnd.api+json"],
      },
    );
    expect(
      (await client(primary).connectionTest(new AbortController().signal))
        .result,
    ).toBe("malformed_response");
    expect(primary.requests).toHaveLength(2);
  });

  it("blocks a declared oversized response before buffering", async () => {
    primary.enqueue((_incoming, response) => {
      response.writeHead(200, {
        "content-type": "application/json",
        "content-length": String(TEST_MAX_RESPONSE_BYTES + 1),
        connection: "close",
      });
      response.end();
    });
    const result = await client(primary).connectionTest(
      new AbortController().signal,
    );
    expect(result.result).toBe("unavailable");
    expect(primary.requests).toHaveLength(1);
  });

  it("blocks a chunked response as soon as its accumulated size exceeds the limit", async () => {
    primary.enqueue((_incoming, response) => {
      response.writeHead(200, {
        "content-type": "application/json",
        connection: "close",
      });
      response.write(Buffer.alloc(3_000, 0x61));
      response.end(Buffer.alloc(2_000, 0x62));
    });
    const result = await client(primary).connectionTest(
      new AbortController().signal,
    );
    expect(result.result).toBe("unavailable");
    expect(primary.requests).toHaveLength(1);
  });

  it.each([
    ["invalid JSON", "{not-json"],
    ["invalid schema", '{"data":"not-an-array"}'],
  ])("rejects %s without another request", async (_label, body) => {
    primary.enqueue((_incoming, response) => {
      response.writeHead(200, {
        "content-type": "application/vnd.api+json",
        connection: "close",
      });
      response.end(body);
    });
    const result = await client(primary).connectionTest(
      new AbortController().signal,
    );
    expect(result.result).toBe("malformed_response");
    expect(primary.requests).toHaveLength(1);
  });

  it("accepts bounded additive API extensions without another request", async () => {
    primary.enqueueJson(200, {
      data: [
        {
          ...programResource("synthetic-extension-id", "synthetic-extension"),
          extension_resource: "RESOURCE_EXTENSION_CANARY",
        },
      ],
      links: { next: null, extension_link: "LINK_EXTENSION_CANARY" },
      meta: { current_page: 1, extension_meta: "META_EXTENSION_CANARY" },
      extension_top: "TOP_EXTENSION_CANARY",
    });

    const result = await client(primary).connectionTest(
      new AbortController().signal,
    );

    expect(result).toMatchObject({ result: "connected", schemaValid: true });
    expect(JSON.stringify(result)).not.toContain("EXTENSION_CANARY");
    expect(primary.requests).toHaveLength(1);
    expect(secondary.requests).toHaveLength(0);
  });

  it("imports incomplete catalog summaries with conservative blocked defaults", async () => {
    primary.enqueueJson(200, {
      data: [
        {
          id: "synthetic-minimal-id",
          type: "program",
          attributes: { handle: "synthetic-minimal" },
        },
        {
          id: "synthetic-nullable-id",
          type: "program",
          attributes: {
            handle: "synthetic-nullable",
            name: null,
            currency: null,
            policy: null,
            submission_state: null,
            state: null,
            offers_bounties: null,
            open_scope: null,
            gold_standard_safe_harbor: null,
            bookmarked: null,
            number_of_reports_for_user: null,
            number_of_valid_reports_for_user: null,
          },
        },
      ],
      links: { next: null },
    });

    const programs = await client(primary).listPrograms(
      new AbortController().signal,
    );

    expect(programs).toHaveLength(2);
    for (const program of programs)
      expect(program).toMatchObject({
        currency: "UNKNOWN",
        policy: "",
        submissionState: "unknown",
        programState: "unknown",
        offersBounties: false,
        openScope: false,
        goldStandardSafeHarbor: false,
      });
    expect(primary.requests).toHaveLength(1);
    expect(secondary.requests).toHaveLength(0);
  });

  it("follows only a canonical serial pagination chain", async () => {
    primary.enqueueJson(200, {
      data: [programResource("synthetic-id-1", "synthetic-one")],
      links: {
        next: "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=100&page%5Bnumber%5D=2",
      },
    });
    primary.enqueueJson(200, {
      data: [programResource("synthetic-id-2", "synthetic-two")],
      links: { next: null },
    });

    const programs = await client(primary).listPrograms(
      new AbortController().signal,
    );

    expect(programs.map(({ handle }) => handle)).toEqual([
      "synthetic-one",
      "synthetic-two",
    ]);
    expect(primary.requests).toEqual([
      {
        method: "GET",
        url: "/v1/hackers/programs?page[number]=1&page[size]=100",
      },
      {
        method: "GET",
        url: "/v1/hackers/programs?page[number]=2&page[size]=100",
      },
    ]);
    expect(primary.maximumActiveRequests).toBe(1);
  });

  it("rejects a mutated pagination host before a second socket", async () => {
    primary.enqueueJson(200, {
      data: [programResource("synthetic-id-1", "synthetic-one")],
      links: {
        next: "https://synthetic.invalid/v1/hackers/programs?page[number]=2&page[size]=100",
      },
    });
    await expect(
      client(primary).listPrograms(new AbortController().signal),
    ).rejects.toThrow("HACKERONE_PAGINATION_BLOCKED");
    expect(primary.requests).toHaveLength(1);
    expect(secondary.requests).toHaveLength(0);
  });

  it("serializes concurrent client operations at the socket boundary", async () => {
    const delayedResponse: MockHandler = async (_incoming, response) => {
      await delay(15);
      response.writeHead(200, {
        "content-type": "application/vnd.api+json",
        connection: "close",
      });
      response.end('{"data":[]}');
    };
    primary.enqueue(delayedResponse);
    primary.enqueue(delayedResponse);
    const instance = client(primary);
    const results = await Promise.all([
      instance.connectionTest(new AbortController().signal),
      instance.connectionTest(new AbortController().signal),
    ]);
    expect(results.map(({ result }) => result)).toEqual([
      "connected",
      "connected",
    ]);
    expect(primary.requests).toHaveLength(2);
    expect(primary.maximumActiveRequests).toBe(1);
  });

  it("treats scope asset identifiers as metadata and uses GET only", async () => {
    const assetIdentifier = `${secondary.origin}/must-never-be-requested`;
    primary.enqueueJson(200, programResource(9, "synthetic-one"));
    primary.enqueueJson(200, {
      data: [
        {
          id: "synthetic-scope-1",
          type: "structured-scope",
          attributes: {
            asset_type: "URL",
            asset_identifier: assetIdentifier,
            eligible_for_submission: true,
            eligible_for_bounty: false,
            instruction: "Metadata only.",
            max_severity: "high",
            created_at: null,
            updated_at: null,
            confidentiality_requirement: null,
            integrity_requirement: null,
            availability_requirement: null,
          },
        },
      ],
      links: { next: null },
    });
    primary.enqueueJson(200, {
      data: [
        {
          id: "synthetic-exclusion-1",
          type: "scope-exclusion",
          attributes: {
            category: "Synthetic exclusion",
            details: "Never request the asset identifier.",
            created_at: null,
            updated_at: null,
          },
        },
      ],
      links: { next: null },
    });

    const selected = await client(primary).readSelectedProgram(
      "synthetic-one",
      new AbortController().signal,
    );

    expect(selected.structuredScopes[0]?.assetIdentifier).toBe(assetIdentifier);
    expect(selected.program.hackerOneId).toBe("9");
    expect(secondary.requests).toHaveLength(0);
    expect(primary.requests.map(({ method }) => method)).toEqual([
      "GET",
      "GET",
      "GET",
    ]);
    expect(primary.requests.map(({ url }) => url)).toEqual([
      "/v1/hackers/programs/synthetic-one",
      "/v1/hackers/programs/synthetic-one/structured_scopes?page[number]=1&page[size]=100",
      "/v1/hackers/programs/synthetic-one/scope_exclusions?page[number]=1&page[size]=100",
    ]);
  });
});
