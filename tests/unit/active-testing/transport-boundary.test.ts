import { readFile } from "node:fs/promises";
import { request } from "node:https";
import {
  createServer as createNetServer,
  type AddressInfo,
  Socket,
} from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  activeTestBoundedDurationMs,
  activeTestRemainingTimeoutMs,
  awaitActiveTestTransportOperation,
} from "../../../packages/active-testing/transport-deadline.js";
import { ProductionActiveTestTransport } from "../../../packages/active-testing/transport.js";
import {
  ControlPlaneDatabase,
  ControlPlaneStore,
} from "../../../packages/control-plane/index.js";

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("active testing transport boundary", () => {
  it("rejects untrusted stores and forged runner plans before any resolver can run", async () => {
    const socketConnect = vi.spyOn(Socket.prototype, "connect");
    expect(() => {
      Reflect.construct(ProductionActiveTestTransport, [Object.freeze({})]);
    }).toThrow("ACTIVE_TEST_TRANSPORT_STORE_UNTRUSTED");

    const database = ControlPlaneDatabase.memory();
    try {
      const transport = new ProductionActiveTestTransport(
        new ControlPlaneStore(
          database,
          () => new Date("2026-07-15T12:00:00.000Z"),
        ),
      );
      const run = transport.run.bind(transport);
      await expect(
        Reflect.apply(run, undefined, [
          Object.freeze({ target: "https://must-not-resolve.invalid/" }),
        ]),
      ).rejects.toThrow("ACTIVE_TEST_TRANSPORT_AUTHORIZATION_REQUIRED");
      expect(socketConnect).not.toHaveBeenCalled();
    } finally {
      database.close();
    }
  });

  it("excludes the loopback HTTP engine and mock transport from production sources and exports", async () => {
    const [
      buildConfig,
      barrel,
      transport,
      testTransport,
      publicModule,
      transportModule,
    ] = await Promise.all([
      readFile("tsconfig.build.json", "utf8"),
      readFile("packages/active-testing/index.ts", "utf8"),
      readFile("packages/active-testing/transport.ts", "utf8"),
      readFile("tests/support/active-testing-loopback-transport.ts", "utf8"),
      import("../../../packages/active-testing/index.js"),
      import("../../../packages/active-testing/transport.js"),
    ]);
    const parsedBuild = JSON.parse(buildConfig) as {
      readonly exclude?: readonly string[];
    };

    expect(parsedBuild.exclude).toContain("tests");
    expect(barrel).not.toMatch(
      /LoopbackActiveTestMockTransport|runLoopbackActiveTestMockRequest|captureLoopbackActiveTestMockEndpoint/u,
    );
    expect(transport).not.toMatch(
      /LoopbackActiveTestMockTransport|runLoopbackActiveTestMockRequest|captureLoopbackActiveTestMockEndpoint/u,
    );
    expect(transport).not.toMatch(
      /import\s*\{[^}]*\brequest\b[^}]*\}\s*from\s*"node:http"/su,
    );
    expect(testTransport).toContain('from "node:http"');
    expect(testTransport).toContain("class LoopbackActiveTestMockTransport");
    expect(testTransport).not.toMatch(
      /export function (?:run|capture)LoopbackActiveTestMock/u,
    );
    for (const productionModule of [publicModule, transportModule]) {
      expect(productionModule).not.toHaveProperty(
        "LoopbackActiveTestMockTransport",
      );
      expect(productionModule).not.toHaveProperty(
        "runLoopbackActiveTestMockRequest",
      );
      expect(productionModule).not.toHaveProperty(
        "captureLoopbackActiveTestMockEndpoint",
      );
    }
  });

  it("does not expose any transport-evidence issuer or registrar", async () => {
    const transportModule: Record<string, unknown> =
      await import("../../../packages/active-testing/transport.js");
    expect(transportModule).not.toHaveProperty(
      "issueActiveTestTransportEvidence",
    );
    expect(transportModule).not.toHaveProperty(
      "registerActiveTestTransportIssuer",
    );
    expect(transportModule).toHaveProperty(
      "captureActiveTestTransportEvidence",
    );
    expect(() =>
      Reflect.apply(
        transportModule["captureActiveTestTransportEvidence"] as (
          ...args: unknown[]
        ) => unknown,
        undefined,
        [
          Object.freeze({
            version: 1,
            receiptDigest: "f".repeat(64),
          }),
          Object.freeze({}),
        ],
      ),
    ).toThrow("ACTIVE_TEST_TRANSPORT_EVIDENCE_REQUIRED");
  });

  it("keeps network primitives in the deterministic transport and out of domain/report code", async () => {
    const [catalog, gate, plan, report, runtime, transport] = await Promise.all(
      ["catalog", "gate", "plan", "report", "runtime", "transport"].map(
        (name) => readFile(`packages/active-testing/${name}.ts`, "utf8"),
      ),
    );
    for (const source of [catalog, gate, plan, report, runtime]) {
      expect(source).not.toMatch(
        /node:(?:child_process|dns|http|https|net|tls)|playwright|puppeteer|openai|anthropic/iu,
      );
    }
    expect(transport).toContain('from "node:dns/promises"');
    expect(transport).toContain('from "node:https"');
    expect(transport).toContain("rejectUnauthorized: true");
    expect(transport).toContain('minVersion: "TLSv1.2"');
    expect(transport).toContain("agent: false");
    expect(transport).toContain("if (options.all === true)");
    expect(transport).toContain("address: resolved.selectedAddress");
    expect(transport).toContain("family: resolved.family");
    expect(transport).toContain("ACTIVE_TEST_REDIRECT_BLOCKED");
    expect(
      (transport ?? "").indexOf("canonicalizeActiveTestDnsHost(host)"),
    ).toBeLessThan((transport ?? "").indexOf("`${canonicalHost}.`"));
    expect(transport).toContain(
      "lookup(absoluteLookupHost, { all: true, verbatim: true })",
    );
    expect(transport).toContain("host: canonicalHost");
    expect(transport).not.toContain("lookup(host,");
    expect(transport).not.toContain("registerActiveTestTransportIssuer");
    expect(transport).not.toMatch(
      /\b(?:POST|PUT|PATCH|DELETE|CONNECT|TRACE)\b/u,
    );
  });

  it("satisfies Node 24 array lookup with exactly one pinned address", async () => {
    const server = createNetServer((socket) => {
      socket.destroy();
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    try {
      const address = server.address() as AddressInfo;
      let allAddressesRequested = false;
      await new Promise<void>((resolve) => {
        const client = request({
          hostname: "pinned-transport.invalid",
          port: address.port,
          method: "HEAD",
          rejectUnauthorized: true,
          lookup: (_hostname, options, callback) => {
            allAddressesRequested = options.all === true;
            if (options.all === true) {
              callback(null, [{ address: "127.0.0.1", family: 4 }]);
              return;
            }
            callback(null, "127.0.0.1", 4);
          },
        });
        client.once("socket", (socket) => {
          socket.once("error", () => undefined);
        });
        client.once("error", () => {
          resolve();
        });
        client.end();
      });
      expect(allAddressesRequested).toBe(true);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) resolve();
          else reject(error);
        });
      });
    }
  });

  it("places a pending DNS-like prerequisite under timeout and kill-switch polling", async () => {
    vi.useFakeTimers();
    const never = new Promise<readonly []>(() => undefined);
    const timedOut = awaitActiveTestTransportOperation(
      () => never,
      250,
      () => undefined,
      "ACTIVE_TEST_DNS_RESOLUTION_FAILED",
    );
    const timeoutAssertion = expect(timedOut).rejects.toThrow(
      "ACTIVE_TEST_REQUEST_TIMEOUT",
    );
    await vi.advanceTimersByTimeAsync(250);
    await timeoutAssertion;

    let killed = false;
    const interrupted = awaitActiveTestTransportOperation(
      () => never,
      1_000,
      () => {
        if (killed) throw new Error("kill switch active");
      },
      "ACTIVE_TEST_DNS_RESOLUTION_FAILED",
    );
    const killAssertion = expect(interrupted).rejects.toThrow(
      "ACTIVE_TEST_KILL_SWITCH",
    );
    killed = true;
    await vi.advanceTimersByTimeAsync(100);
    await killAssertion;
  });

  it("maps resolver failure and rejects invalid deadline parameters fail closed", async () => {
    await expect(
      awaitActiveTestTransportOperation(
        () => Promise.reject(new Error("redacted resolver failure")),
        1_000,
        () => undefined,
        "ACTIVE_TEST_DNS_RESOLUTION_FAILED",
      ),
    ).rejects.toThrow("ACTIVE_TEST_DNS_RESOLUTION_FAILED");
    await expect(
      awaitActiveTestTransportOperation(
        () => Promise.resolve([]),
        0,
        () => undefined,
        "ACTIVE_TEST_DNS_RESOLUTION_FAILED",
      ),
    ).rejects.toThrow("ACTIVE_TEST_TRANSPORT_DEADLINE_INVALID");
  });

  it("uses a capped monotonic remainder that wall-clock rollback cannot extend", () => {
    expect(activeTestRemainingTimeoutMs(5_000, 0)).toBe(5_000);
    expect(activeTestRemainingTimeoutMs(5_000, 1_250.25)).toBe(3_749);
    expect(activeTestRemainingTimeoutMs(5_000, 5_001)).toBe(0);
    expect(() => activeTestRemainingTimeoutMs(5_000, -1)).toThrow(
      "ACTIVE_TEST_TRANSPORT_DEADLINE_INVALID",
    );
    expect(() => activeTestRemainingTimeoutMs(5_000, Number.NaN)).toThrow(
      "ACTIVE_TEST_TRANSPORT_DEADLINE_INVALID",
    );
    expect(activeTestBoundedDurationMs(5_000, 1_250.75)).toBe(1_250);
    expect(activeTestBoundedDurationMs(5_000, 6_000)).toBe(5_000);
    expect(Number.isSafeInteger(activeTestBoundedDurationMs(5_000, 0.5))).toBe(
      true,
    );
  });

  it("never starts a DNS-like operation when the kill switch is already active", async () => {
    let resolverStarts = 0;
    await expect(
      awaitActiveTestTransportOperation(
        () => {
          resolverStarts += 1;
          return Promise.resolve([]);
        },
        1_000,
        () => {
          throw new Error("kill switch active");
        },
        "ACTIVE_TEST_DNS_RESOLUTION_FAILED",
      ),
    ).rejects.toThrow("ACTIVE_TEST_KILL_SWITCH");
    expect(resolverStarts).toBe(0);
  });
});
