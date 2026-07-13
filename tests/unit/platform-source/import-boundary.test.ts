import { readFile } from "node:fs/promises";
import { expect, it } from "vitest";

it("contains no network, browser or generic request implementation", async () => {
  const files = [
    "packages/platform-source/fixture-source.ts",
    "packages/platform-source/compiler.ts",
  ];
  const source = (
    await Promise.all(files.map((path) => readFile(path, "utf8")))
  ).join("\n");
  for (const forbidden of [
    "node:http",
    "node:https",
    "node:dns",
    "playwright",
    "fetch(",
    "request(",
  ])
    expect(source).not.toContain(forbidden);
});
