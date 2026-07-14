import { defineConfig } from "playwright/test";

const copyPromptSetting = process.env["PLAYWRIGHT_NO_COPY_PROMPT"];
if (copyPromptSetting !== undefined && copyPromptSetting !== "1")
  throw new Error("LOCAL_BROWSER_PAGE_SNAPSHOT_SETTING_INVALID");
process.env["PLAYWRIGHT_NO_COPY_PROMPT"] = "1";

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "**/*.spec.ts",
  outputDir: ".local/phase7-playwright/results",
  preserveOutput: "never",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  maxFailures: 1,
  forbidOnly: true,
  timeout: 20_000,
  globalTimeout: 120_000,
  expect: { timeout: 5_000 },
  reporter: [["line"]],
  use: {
    headless: true,
    viewport: { width: 1_280, height: 720 },
    deviceScaleFactor: 1,
    locale: "de-DE",
    timezoneId: "UTC",
    colorScheme: "light",
    acceptDownloads: false,
    serviceWorkers: "block",
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  projects: [
    { name: "phase7-local-chromium", use: { browserName: "chromium" } },
  ],
});
