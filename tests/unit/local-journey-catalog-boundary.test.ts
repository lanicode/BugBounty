import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";

describe("local journey catalog boundary", () => {
  it("contains no I/O, network, browser or test-harness dependency", async () => {
    const [catalog, index] = await Promise.all([
      readFile("packages/local-journey-catalog/catalog.ts", "utf8"),
      readFile("packages/local-journey-catalog/index.ts", "utf8"),
    ]);
    const source = `${catalog}\n${index}`;

    expect(source).not.toMatch(
      /node:(?:child_process|dns|fs|http|https|net|tls|worker_threads)/u,
    );
    expect(source).not.toMatch(
      /\b(?:EventSource|WebSocket|Worker|XMLHttpRequest|fetch)\b/u,
    );
    expect(source).not.toMatch(/\bplaywright\b/u);
    expect(source).not.toContain("tests/browser");

    const imports = [...catalog.matchAll(/from "([^"]+)"/gu)].map(
      (match) => match[1],
    );
    expect(imports).toEqual(["../shared/canonical.js"]);
    expect(index.trim()).toBe('export * from "./catalog.js";');
  });
});
