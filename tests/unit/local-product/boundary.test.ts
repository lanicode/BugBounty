import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("Phase-8 local-product boundaries", () => {
  it("keeps the guided workflow and readiness derivation free of I/O transports", async () => {
    const source = (
      await Promise.all(
        [
          "packages/local-product/workflow.ts",
          "packages/local-runtime/readiness.ts",
        ].map((path) => readFile(path, "utf8")),
      )
    ).join("\n");
    for (const forbidden of [
      "node:http",
      "node:https",
      "node:http2",
      "node:net",
      "node:tls",
      "node:dns",
      "node:fs",
      "node:child_process",
      "undici",
      "playwright",
      "fetch(",
      "XMLHttpRequest",
      "WebSocket",
      "EventSource",
      "openai",
      "anthropic",
      "gemini",
    ])
      expect(source).not.toContain(forbidden);
  });

  it("offers only fixed same-origin dashboard actions and no secret inputs", async () => {
    const [htmlAndLegacyScript, phase8Script] = await Promise.all([
      readFile("packages/dashboard/assets.ts", "utf8"),
      readFile("packages/dashboard/phase8-assets.ts", "utf8"),
    ]);
    expect(htmlAndLegacyScript).toContain(">KEINE REALE REPORT-EINREICHUNG<");
    expect(htmlAndLegacyScript).not.toMatch(/type=["']password["']/iu);
    expect(htmlAndLegacyScript).not.toMatch(
      /(?:api[_-]?key|access[_-]?token|refresh[_-]?token|totp|cookie)["']?\s*>/iu,
    );
    expect(phase8Script).not.toContain("innerHTML");
    expect(phase8Script).not.toContain("window.open");
    expect(phase8Script).not.toContain("WebSocket");
    expect(phase8Script).not.toContain("EventSource");
    expect(phase8Script).not.toContain("Worker(");
    expect(phase8Script).not.toContain("location.href");
    expect(phase8Script).not.toMatch(/(?:https?|wss?):\/\//u);
    const fetchTargets = [...phase8Script.matchAll(/fetch\("([^"]+)"/gu)].map(
      (match) => match[1],
    );
    expect(fetchTargets).toEqual(["/api/state", "/api/local-product/action"]);
  });

  it("uses only the OS keychain in the productive Phase-8 composition root", async () => {
    const source = await readFile("apps/dashboard/runtime.ts", "utf8");
    expect(source).toContain("MacOSKeychainSecretStore");
    expect(source).not.toContain("InMemorySecretStore");
    expect(source).not.toContain("tests/browser");
    expect(source).not.toMatch(/\b(?:chromium|firefox|webkit)\.launch\s*\(/u);
    expect(source).not.toContain("external_integrations_enabled: true");
  });
});
