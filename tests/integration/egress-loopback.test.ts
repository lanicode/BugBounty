import { createServer } from "node:http";
import { once } from "node:events";
import { afterEach, describe, expect, it } from "vitest";
import { decideEgress } from "../../packages/egress-guard/guard.js";
import { programConfig } from "../fixtures/factories.js";

const servers: ReturnType<typeof createServer>[] = [];
afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(async (server) => {
      server.close();
      await once(server, "close");
    }),
  );
});

async function localServer(): Promise<{ origin: string; hits: () => number }> {
  let hitCount = 0;
  const server = createServer((request, response) => {
    hitCount += 1;
    if (request.url === "/api/redirect") {
      response.writeHead(302, { location: "/api/final" });
      response.end();
    } else {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"ok":true}');
    }
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("LOCAL_SERVER_ADDRESS");
  return { origin: `http://127.0.0.1:${address.port}`, hits: () => hitCount };
}

describe("loopback-only integration", () => {
  it("decides before performing an allowed local request", async () => {
    const local = await localServer();
    const port = Number(new URL(local.origin).port);
    const policy = {
      config: programConfig({ host: "127.0.0.1", port, allowHttp: true }),
      localTestMode: true,
    };
    const decision = decideEgress(policy, {
      url: `${local.origin}/api/data`,
      method: "GET",
      captureMode: "redacted",
      resourceKind: "fetch",
      isRedirect: false,
    });
    expect(local.hits()).toBe(0);
    expect(decision.allow).toBe(true);
    const response = await fetch(`${local.origin}/api/data`, {
      redirect: "manual",
    });
    expect(response.status).toBe(200);
    expect(local.hits()).toBe(1);
  });
  it("blocks redirect follow-up before a second request", async () => {
    const local = await localServer();
    const port = Number(new URL(local.origin).port);
    const policy = {
      config: programConfig({ host: "127.0.0.1", port, allowHttp: true }),
      localTestMode: true,
    };
    const first = await fetch(`${local.origin}/api/redirect`, {
      redirect: "manual",
    });
    expect(first.status).toBe(302);
    expect(local.hits()).toBe(1);
    const redirect = decideEgress(policy, {
      url: `${local.origin}/api/final`,
      method: "GET",
      captureMode: "redacted",
      resourceKind: "navigation",
      isRedirect: true,
    });
    expect(redirect.reason).toBe("BLOCK_REDIRECT");
    expect(local.hits()).toBe(1);
  });
});
