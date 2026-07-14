import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();

describe("Phase-7 browser import and artifact boundary", () => {
  it("keeps browser launch and Playwright Test out of productive source paths", async () => {
    const files = [
      ...(await typescriptFiles(join(ROOT, "apps"))),
      ...(await typescriptFiles(join(ROOT, "packages"))),
    ];
    const forbidden = [
      /\bchromium\.launch\s*\(/u,
      /\bfirefox\.launch\s*\(/u,
      /\bwebkit\.launch\s*\(/u,
      /\blaunchPersistentContext\s*\(/u,
      /\bconnectOverCDP\s*\(/u,
      /from\s+["']playwright\/test["']/u,
    ];
    for (const path of files) {
      const source = await readFile(path, "utf8");
      for (const pattern of forbidden)
        expect(
          source,
          `${relative(ROOT, path)} contains ${String(pattern)}`,
        ).not.toMatch(pattern);
    }
  });

  it("exposes the browser only through the local fixture and disables automatic artifacts", async () => {
    const [spec, harness, config, packageJson] = await Promise.all([
      readFile(join(ROOT, "tests/browser/demo-saas-journey.spec.ts"), "utf8"),
      readFile(
        join(ROOT, "tests/browser/support/local-demo-harness.ts"),
        "utf8",
      ),
      readFile(join(ROOT, "playwright.config.ts"), "utf8"),
      readFile(join(ROOT, "package.json"), "utf8"),
    ]);
    expect(spec).toContain('from "./fixtures/local-demo.js"');
    expect(spec).not.toMatch(/from\s+["']playwright(?:\/test)?["']/u);
    expect(harness).not.toContain("packages/external-actions");
    expect(harness).not.toContain("packages/control-plane");
    expect(harness).not.toContain("toHaveScreenshot");
    expect(config).toContain('trace: "off"');
    expect(config).toContain('screenshot: "off"');
    expect(config).toContain('video: "off"');
    expect(config).toContain('preserveOutput: "never"');
    expect(config).toContain('process.env["PLAYWRIGHT_NO_COPY_PROMPT"] = "1"');
    expect(config).toContain("workers: 1");
    expect(config).toContain("retries: 0");
    expect(packageJson).toContain("PLAYWRIGHT_NO_COPY_PROMPT=1");
  });
});

async function typescriptFiles(directory: string): Promise<readonly string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths: string[] = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) paths.push(...(await typescriptFiles(path)));
    else if (entry.isFile() && extname(entry.name) === ".ts") paths.push(path);
  }
  return paths.sort();
}
