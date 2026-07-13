import { describe, expect, it } from "vitest";
import { decideEgress } from "../../../packages/egress-guard/guard.js";
import {
  normalizeRequestPath,
  normalizeUrl,
} from "../../../packages/egress-guard/normalize.js";
import { secureContextOptions } from "../../../packages/egress-guard/playwright.js";
import { programConfig } from "../../fixtures/factories.js";

const request = (
  url: string,
  method = "GET",
  captureMode: "metadata_only" | "none" | "redacted" = "redacted",
  isRedirect = false,
) => ({ url, method, captureMode, resourceKind: "fetch" as const, isRedirect });

describe("egress guard", () => {
  it("allows an exact target and blocks suffix/userinfo tricks", () => {
    const policy = { config: programConfig() };
    expect(
      decideEgress(policy, request("https://api.example.test/api/items"))
        .reason,
    ).toBe("ALLOW_TARGET");
    expect(
      decideEgress(policy, request("https://api.example.test.evil.test/api/"))
        .reason,
    ).toBe("BLOCK_HOST");
    expect(
      decideEgress(policy, request("https://api.example.test@evil.test/"))
        .reason,
    ).toBe("BLOCK_USERINFO");
  });

  it("normalizes default ports and blocks unapproved ports", () => {
    const policy = { config: programConfig() };
    expect(
      decideEgress(policy, request("https://api.example.test:443/api/")).allow,
    ).toBe(true);
    expect(
      decideEgress(policy, request("https://api.example.test:444/api/")).reason,
    ).toBe("BLOCK_PORT");
  });

  it("permits HTTP only for explicitly configured loopback test mode", () => {
    expect(
      decideEgress(
        {
          config: programConfig({
            host: "127.0.0.1",
            port: 8080,
            allowHttp: true,
          }),
          localTestMode: true,
        },
        request("http://127.0.0.1:8080/api/"),
      ).allow,
    ).toBe(true);
    expect(
      decideEgress(
        {
          config: programConfig({
            host: "api.example.test",
            port: 80,
            allowHttp: true,
          }),
          localTestMode: true,
        },
        request("http://api.example.test/api/"),
      ).reason,
    ).toBe("BLOCK_HTTP");
  });

  it("fails closed on host ambiguity and traversal variants", () => {
    expect(() => normalizeUrl("https://api.example.test./api/")).toThrow();
    expect(() => normalizeUrl("https://bücher.example/api/")).toThrow();
    expect(normalizeUrl("HTTPS://API.EXAMPLE.TEST/api/").host).toBe(
      "api.example.test",
    );
    for (const path of [
      "/api/%2e%2e/admin",
      "/api/%252e%252e/admin",
      "/api/%25252e%25252e/admin",
    ])
      expect(() => normalizeRequestPath(path)).toThrow();
  });

  it("enforces paths, methods, redirect and supporting capture mode", () => {
    const policy = { config: programConfig() };
    expect(
      decideEgress(policy, request("https://api.example.test/admin")).reason,
    ).toBe("BLOCK_PATH");
    expect(
      decideEgress(policy, request("https://api.example.test/api/", "POST"))
        .reason,
    ).toBe("BLOCK_METHOD");
    expect(
      decideEgress(
        policy,
        request("https://api.example.test/api/", "GET", "redacted", true),
      ).reason,
    ).toBe("BLOCK_REDIRECT");
    expect(
      decideEgress(
        policy,
        request("https://cdn.example.test/", "GET", "metadata_only"),
      ).reason,
    ).toBe("ALLOW_SUPPORTING_HOST");
    expect(
      decideEgress(
        policy,
        request("https://cdn.example.test/", "POST", "metadata_only"),
      ).reason,
    ).toBe("BLOCK_METHOD");
    expect(
      decideEgress(
        policy,
        request("https://cdn.example.test/", "GET", "redacted"),
      ).reason,
    ).toBe("BLOCK_CAPTURE_MODE");
  });

  it("applies the same decision to every browser-originated resource kind", () => {
    const kinds = [
      "document",
      "fetch",
      "form",
      "frame",
      "navigation",
      "other",
      "popup",
      "xhr",
    ] as const;
    for (const resourceKind of kinds)
      expect(
        decideEgress(
          { config: programConfig() },
          { ...request("https://evil.test/"), resourceKind },
        ).allow,
      ).toBe(false);
    expect(secureContextOptions()).toMatchObject({
      serviceWorkers: "block",
      acceptDownloads: false,
    });
  });
});
