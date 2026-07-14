import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";

it("keeps operator authentication free of transport, browser, process, and LLM clients", async () => {
  const source = (
    await Promise.all(
      [
        "packages/operator-auth/envelope.ts",
        "packages/operator-auth/index.ts",
        "packages/operator-auth/signer.ts",
        "packages/operator-auth/types.ts",
        "packages/operator-auth/verifier.ts",
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
    "process.env",
    "readFile(",
    "writeFile(",
  ])
    expect(source).not.toContain(forbidden);
});
