import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("simulation domain import boundary", () => {
  it("contains no network, browser, process, or LLM client", async () => {
    const source = await readFile(
      new URL("../../packages/simulation/orchestrator.ts", import.meta.url),
      "utf8",
    );
    for (const forbidden of [
      "node:http",
      "node:https",
      "node:http2",
      "node:net",
      "node:tls",
      "node:dns",
      "undici",
      "playwright",
      "child_process",
      "fetch(",
      "openai",
    ])
      expect(source).not.toContain(forbidden);
  });
});
