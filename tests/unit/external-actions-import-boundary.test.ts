import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";

it("does not contain a general HTTP, browser or LLM-controlled runner", async () => {
  const source = (
    await Promise.all(
      [
        "packages/control-plane/external-action-evidence.ts",
        "packages/control-plane/external-action-store.ts",
        "packages/control-plane/database.ts",
        "packages/control-plane/index.ts",
        "packages/control-plane/store.ts",
        "packages/control-plane/types.ts",
        "packages/external-actions/index.ts",
        "packages/external-actions/pipeline.ts",
        "packages/external-actions/proposal.ts",
        "packages/external-actions/proposal.schema.json",
        "packages/external-actions/registry.ts",
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
    "fetch (",
    "globalThis.fetch",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "axios",
    "openai",
    "anthropic",
    "gemini",
  ])
    expect(source).not.toContain(forbidden);
  for (const proposalControlledField of ["target_url", "required_secret_ref"])
    expect(source).not.toContain(proposalControlledField);
});
