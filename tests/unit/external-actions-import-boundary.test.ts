import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";

it("does not contain a general HTTP, browser or LLM-controlled runner", async () => {
  const source = (
    await Promise.all(
      ["pipeline.ts", "registry.ts"].map((file) =>
        readFile(`packages/external-actions/${file}`, "utf8"),
      ),
    )
  ).join("\n");
  for (const forbidden of [
    "node:http",
    "node:https",
    "playwright",
    "fetch(",
    "axios",
    "openai",
  ])
    expect(source).not.toContain(forbidden);
  for (const proposalControlledField of ["target_url", "required_secret_ref"])
    expect(source).not.toContain(proposalControlledField);
});
