import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";

it("does not contain a general HTTP, browser or LLM-controlled runner", async () => {
  const source = await readFile(
    "packages/external-actions/pipeline.ts",
    "utf8",
  );
  for (const forbidden of [
    "node:http",
    "node:https",
    "playwright",
    "fetch(",
    "axios",
    "openai",
  ])
    expect(source).not.toContain(forbidden);
});
