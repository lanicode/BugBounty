import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import {
  assertTransportPlan,
  HackerOneHttpsTransport,
  type HackerOneEndpointClass,
} from "../../../packages/hackerone-readonly/transport.js";

function plan(endpointClass: HackerOneEndpointClass, requestTarget: string) {
  return { endpointClass, requestTarget };
}

describe("HackerOne HTTPS transport plan policy", () => {
  it.each([
    ["programs", "/v1/hackers/programs"],
    ["programs", "/v1/hackers/programs?page[number]=1&page[size]=100"],
    ["program", "/v1/hackers/programs/synthetic-program"],
    [
      "structured_scopes",
      "/v1/hackers/programs/synthetic-program/structured_scopes?page[number]=2&page[size]=10",
    ],
    [
      "scope_exclusions",
      "/v1/hackers/programs/synthetic-program/scope_exclusions?page[number]=2&page[size]=10",
    ],
  ] as const)("accepts the exact %s target %s", (endpointClass, target) => {
    expect(() => {
      assertTransportPlan(plan(endpointClass, target));
    }).not.toThrow();
  });

  it.each([
    "",
    "/",
    "https://api.hackerone.com/v1/hackers/programs",
    "//api.hackerone.com/v1/hackers/programs",
    "/v1/hackers/programs/",
    "/v1/hackers/programs/../reports",
    "/v1/hackers/programs/synthetic%2fprogram",
    "/v1/hackers/programs/synthetic-program/weaknesses",
    "/v1/hackers/reports",
    "/v1/customer/programs",
    "/v1/hackers/programs?page[number]=0&page[size]=1",
    "/v1/hackers/programs?page[number]=01&page[size]=1",
    "/v1/hackers/programs?page[number]=1&page[size]=0",
    "/v1/hackers/programs?page[number]=1&page[size]=101",
    "/v1/hackers/programs?page[size]=1&page[number]=1",
    "/v1/hackers/programs?page[number]=1&page[size]=1&extra=1",
    "/v1/hackers/programs?page[number]=1&page[size]=1#synthetic",
    "/v1/hackers/programs?method=POST",
  ])("blocks the non-allowlisted request target %s", (requestTarget) => {
    expect(() => {
      assertTransportPlan(plan("programs", requestTarget));
    }).toThrow("HACKERONE_ENDPOINT_BLOCKED");
  });

  it.each([
    ["program", "/v1/hackers/programs"],
    ["programs", "/v1/hackers/programs/synthetic-program"],
    [
      "scope_exclusions",
      "/v1/hackers/programs/synthetic-program/structured_scopes",
    ],
    [
      "structured_scopes",
      "/v1/hackers/programs/synthetic-program/scope_exclusions",
    ],
  ] as const)(
    "blocks endpoint-class confusion for %s and %s",
    (endpointClass, requestTarget) => {
      expect(() => {
        assertTransportPlan(plan(endpointClass, requestTarget));
      }).toThrow("HACKERONE_ENDPOINT_CLASS_MISMATCH");
    },
  );

  it("rejects an unbound structural plan before node:https", async () => {
    const controller = new AbortController();
    controller.abort();
    const identifier = Uint8Array.from([11, 12, 13]);
    const token = Uint8Array.from([21, 22, 23]);
    const transport = new HackerOneHttpsTransport();

    await expect(
      transport.get(
        plan(
          "programs",
          "/v1/hackers/programs?page[number]=1&page[size]=1",
        ) as never,
        { identifier, token },
        controller.signal,
      ),
    ).rejects.toThrow("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
    expect(identifier).toEqual(Uint8Array.from([11, 12, 13]));
    expect(token).toEqual(Uint8Array.from([21, 22, 23]));
    identifier.fill(0);
    token.fill(0);
  });

  it("pins GET, TLS verification, identity encoding, and the official origin in source", async () => {
    const source = await readFile(
      new URL(
        "../../../packages/hackerone-readonly/transport.ts",
        import.meta.url,
      ),
      "utf8",
    );
    expect(source).toContain('from "node:https"');
    expect(source).toContain('protocol: "https:"');
    expect(source).toContain("hostname: HACKERONE_API_HOST");
    expect(source).toContain("servername: HACKERONE_API_HOST");
    expect(source).toContain("port: HACKERONE_API_PORT");
    expect(source).toContain('method: "GET"');
    expect(source).toContain("rejectUnauthorized: true");
    expect(source).toContain('"accept-encoding": "identity"');
    expect(source).toContain("agent: false");
    expect(source).toContain("const deadline = setTimeout");
    expect(source).toContain("clearTimeout(deadline)");
    expect(source).toContain(
      'outgoing.destroy(new SecurityError("HACKERONE_REQUEST_TIMEOUT"))',
    );
    expect(source).not.toContain('method: "POST"');
    expect(source).not.toContain('method: "PUT"');
    expect(source).not.toContain('method: "PATCH"');
    expect(source).not.toContain('method: "DELETE"');
    expect(source).not.toContain("fetch(");
  });
});
