import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";

it("keeps event-key lifecycle and admin paths free of network, browser, and LLM transports", async () => {
  const source = (
    await Promise.all(
      [
        "apps/event-key-cli/index.ts",
        "packages/event-key-lifecycle/config.ts",
        "packages/event-key-lifecycle/index.ts",
        "packages/event-key-lifecycle/lifecycle.ts",
        "packages/event-key-lifecycle/types.ts",
      ].map((file) => readFile(file, "utf8")),
    )
  ).join("\n");
  for (const forbidden of [
    "node:http",
    "node:https",
    "node:http2",
    "node:net",
    "node:tls",
    "node:dgram",
    "node:dns",
    "node:child_process",
    "undici",
    "playwright",
    "fetch(",
    "globalThis.fetch",
    "XMLHttpRequest",
    "WebSocket",
    "axios",
    "openai",
    "anthropic",
    "gemini",
  ])
    expect(source).not.toContain(forbidden);
});
