import { createServer, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import type { DemoSaas, DemoSaasSnapshot } from "./domain.js";

const LOOPBACK_HOST = "127.0.0.1";
const SECURITY_HEADERS = Object.freeze({
  "cache-control": "no-store",
  "content-security-policy":
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), geolocation=(), microphone=()",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
});

export interface RunningDemoSaasServer {
  readonly host: "127.0.0.1";
  readonly port: number;
  readonly origin: string;
  close(): Promise<void>;
}

export async function startDemoSaasServer(
  demo: DemoSaas,
  port = 0,
): Promise<RunningDemoSaasServer> {
  if (!Number.isInteger(port) || port < 0 || port > 65_535)
    throw new Error("DEMO_SERVER_PORT_INVALID");

  const binding: { expectedHost?: string } = {};
  const server = createServer(
    {
      headersTimeout: 5_000,
      keepAliveTimeout: 1_000,
      maxHeaderSize: 8_192,
      requestTimeout: 5_000,
    },
    (request, response) => {
      applySecurityHeaders(response);
      const expectedHost = binding.expectedHost;
      if (!isLoopbackPeer(request.socket.remoteAddress)) {
        sendJson(response, 403, { error: "DEMO_REMOTE_ADDRESS_BLOCKED" });
        return;
      }
      if (expectedHost === undefined || request.headers.host !== expectedHost) {
        sendJson(response, 403, { error: "DEMO_HOST_BLOCKED" });
        return;
      }
      if (request.method !== "GET") {
        response.setHeader("allow", "GET");
        sendJson(response, 405, { error: "DEMO_METHOD_BLOCKED" });
        return;
      }
      const rawUrl = request.url;
      if (
        rawUrl === undefined ||
        !rawUrl.startsWith("/") ||
        rawUrl.startsWith("//")
      ) {
        sendJson(response, 400, { error: "DEMO_URL_INVALID" });
        return;
      }
      let url: URL;
      try {
        url = new URL(rawUrl, `http://${expectedHost}`);
      } catch {
        sendJson(response, 400, { error: "DEMO_URL_INVALID" });
        return;
      }
      if (url.search !== "" || url.hash !== "" || url.pathname !== rawUrl) {
        sendJson(response, 404, { error: "DEMO_ROUTE_NOT_FOUND" });
        return;
      }
      serveRoute(response, url.pathname, demo.snapshot());
    },
  );
  server.on("upgrade", (_request, socket) => {
    socket.destroy();
  });
  server.on("clientError", (_error, socket) => {
    socket.destroy();
  });

  await listen(server, port);
  const address = server.address();
  if (!isLoopbackAddress(address)) {
    await closeServer(server);
    throw new Error("DEMO_SERVER_BIND_INVALID");
  }
  binding.expectedHost = `${LOOPBACK_HOST}:${address.port}`;
  const origin = `http://${binding.expectedHost}`;
  let closePromise: Promise<void> | undefined;

  return Object.freeze({
    host: LOOPBACK_HOST,
    port: address.port,
    origin,
    close: () => {
      closePromise ??= closeServer(server);
      return closePromise;
    },
  });
}

function serveRoute(
  response: ServerResponse,
  pathname: string,
  snapshot: DemoSaasSnapshot,
): void {
  switch (pathname) {
    case "/":
      sendJson(response, 200, {
        service: "bug-bounty-copilot-demo-saas",
        mode: snapshot.mode,
        externalIntegrationsEnabled: snapshot.externalIntegrationsEnabled,
        routes: [
          "/health",
          "/api/v1/state",
          "/api/v1/organization",
          "/api/v1/projects",
          "/api/v1/documents",
          "/api/v1/invitations",
          "/api/v1/test-objects",
          "/api/v1/policy",
        ],
      });
      return;
    case "/health":
      sendJson(response, 200, {
        status: "ok",
        mode: snapshot.mode,
        externalIntegrationsEnabled: snapshot.externalIntegrationsEnabled,
      });
      return;
    case "/api/v1/state":
      sendJson(response, 200, snapshot);
      return;
    case "/api/v1/organization":
      sendJson(response, 200, snapshot.organization);
      return;
    case "/api/v1/projects":
      sendJson(response, 200, { projects: snapshot.projects });
      return;
    case "/api/v1/documents":
      sendJson(response, 200, { documents: snapshot.documents });
      return;
    case "/api/v1/invitations":
      sendJson(response, 200, { invitations: snapshot.invitations });
      return;
    case "/api/v1/test-objects":
      sendJson(response, 200, { testObjects: snapshot.testObjects });
      return;
    case "/api/v1/policy":
      sendJson(response, 200, {
        currentPolicy: snapshot.currentPolicy,
        policyVersions: snapshot.policyVersions,
        lastPolicyDrift: snapshot.lastPolicyDrift,
      });
      return;
    default:
      sendJson(response, 404, { error: "DEMO_ROUTE_NOT_FOUND" });
  }
}

function applySecurityHeaders(response: ServerResponse): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS))
    response.setHeader(name, value);
}

function sendJson(
  response: ServerResponse,
  statusCode: number,
  value: unknown,
): void {
  const body = JSON.stringify(value);
  response.statusCode = statusCode;
  response.setHeader("connection", "close");
  response.setHeader("content-length", Buffer.byteLength(body));
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.end(body);
}

function isLoopbackPeer(address: string | undefined): boolean {
  return address === LOOPBACK_HOST;
}

function isLoopbackAddress(
  address: string | AddressInfo | null,
): address is AddressInfo {
  return (
    address !== null &&
    typeof address !== "string" &&
    address.address === LOOPBACK_HOST &&
    address.family === "IPv4"
  );
}

function listen(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolve();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ exclusive: true, host: LOOPBACK_HOST, port });
  });
}

function closeServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve();
      else reject(error);
    });
    server.closeIdleConnections();
  });
}
