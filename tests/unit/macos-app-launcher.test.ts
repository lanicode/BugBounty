import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { PassThrough, Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  acquireMacOSLauncherLease,
  buildMacOSDashboardEnvironment,
  loadMacOSLaunchConfiguration,
  MACOS_LAUNCHER_ALREADY_RUNNING_EXIT_CODE,
  MACOS_LAUNCHER_STARTUP_TIMEOUT_EXIT_CODE,
  MACOS_LAUNCHER_STARTUP_TIMEOUT_MS,
  MacOSLauncherError,
  macOSLauncherProcessExitCode,
  terminateMacOSDashboardChild,
  validateLocalDashboardOrigin,
  waitForLocalDashboardOrigin,
} from "../../apps/macos-launcher/index.js";

const ROOT = resolve(fileURLToPath(new URL("../..", import.meta.url)));

describe("macOS app launcher", () => {
  it("accepts only canonical uncredentialed 127.0.0.1 dashboard origins", () => {
    expect(validateLocalDashboardOrigin("http://127.0.0.1:4173")).toBe(
      "http://127.0.0.1:4173",
    );
    expect(validateLocalDashboardOrigin("http://127.0.0.1:49152")).toBe(
      "http://127.0.0.1:49152",
    );

    for (const value of [
      "http://localhost:4173",
      "http://[::1]:4173",
      "https://127.0.0.1:4173",
      "http://127.0.0.1:80",
      "http://127.0.0.1:04173",
      "http://user@127.0.0.1:4173",
      "http://127.0.0.1:4173/other",
      "http://127.0.0.1:4173?next=https://target.invalid",
      "http://127.0.0.1:4173#fragment",
      "https://target.invalid",
    ]) {
      expect(() => validateLocalDashboardOrigin(value)).toThrow(
        expect.objectContaining({
          code: "MACOS_LAUNCHER_DASHBOARD_OUTPUT_INVALID",
        }),
      );
    }
  });

  it("extracts only the explicit bounded dashboard startup line", async () => {
    const stream = Readable.from([
      "Bug Bounty Copilot läuft ausschließlich lokal.\nDash",
      "board-URL: http://127.0.0.1:4173\n",
      "External-Integrationen: deaktiviert\n",
    ]);
    await expect(waitForLocalDashboardOrigin(stream)).resolves.toBe(
      "http://127.0.0.1:4173",
    );

    await expect(
      waitForLocalDashboardOrigin(
        Readable.from(["Dashboard-URL: https://target.invalid\n"]),
      ),
    ).rejects.toMatchObject({
      code: "MACOS_LAUNCHER_DASHBOARD_OUTPUT_INVALID",
    });
    await expect(
      waitForLocalDashboardOrigin(Readable.from(["x".repeat(16_385)])),
    ).rejects.toMatchObject({
      code: "MACOS_LAUNCHER_DASHBOARD_OUTPUT_INVALID",
    });

    const neverEnding = new PassThrough();
    try {
      await expect(
        waitForLocalDashboardOrigin(neverEnding, 25),
      ).rejects.toMatchObject({ code: "MACOS_LAUNCHER_STARTUP_TIMEOUT" });
    } finally {
      neverEnding.destroy();
    }
  });

  it("loads only private single-line absolute configuration paths", async () => {
    const fixture = await launcherFixture();
    await expect(
      loadMacOSLaunchConfiguration(fixture.resources),
    ).resolves.toEqual({
      repositoryRoot: fixture.repository,
      nodeExecutable: "/usr/bin/true",
      tsxEntry: join(fixture.repository, "node_modules/tsx/dist/cli.mjs"),
      dashboardEntry: join(fixture.repository, "apps/dashboard/index.ts"),
      hackerOneReadonlyEnabled: false,
    });

    await writeFile(
      join(fixture.resources, "repository-path"),
      `${fixture.repository}\n/tmp/other\n`,
      { mode: 0o600 },
    );
    await expect(
      loadMacOSLaunchConfiguration(fixture.resources),
    ).rejects.toMatchObject({ code: "MACOS_LAUNCHER_CONFIG_INVALID" });

    await writeFile(
      join(fixture.resources, "repository-path"),
      `${fixture.repository}\n`,
      { mode: 0o600 },
    );
    const nodeLink = join(fixture.resources, "node-link");
    await symlink("/usr/bin/true", nodeLink);
    await writeFile(join(fixture.resources, "node-path"), `${nodeLink}\n`, {
      mode: 0o600,
    });
    await expect(
      loadMacOSLaunchConfiguration(fixture.resources),
    ).rejects.toMatchObject({ code: "MACOS_LAUNCHER_DEPENDENCY_MISSING" });

    await writeFile(join(fixture.resources, "node-path"), "/usr/bin/true\n", {
      mode: 0o600,
    });
    await chmod(join(fixture.resources, "repository-path"), 0o644);
    await expect(
      loadMacOSLaunchConfiguration(fixture.resources),
    ).rejects.toMatchObject({ code: "MACOS_LAUNCHER_CONFIG_INVALID" });

    await chmod(join(fixture.resources, "repository-path"), 0o600);
    await writeFile(
      join(fixture.resources, "integration-mode"),
      "external-everything\n",
      { mode: 0o600 },
    );
    await expect(
      loadMacOSLaunchConfiguration(fixture.resources),
    ).rejects.toMatchObject({ code: "MACOS_LAUNCHER_CONFIG_INVALID" });
  });

  it("loads canonical nonsecret core metadata and constructs a minimal environment", async () => {
    const fixture = await launcherFixture();
    await writeFile(
      join(fixture.resources, "event-key-minimum-version"),
      "1\n",
      { mode: 0o600 },
    );
    await writeFile(
      join(fixture.resources, "operator-key-reference"),
      "keychain://bugbounty-copilot/operator-ed25519-v1\n",
      { mode: 0o600 },
    );
    await writeFile(join(fixture.resources, "operator-id"), "local.admin\n", {
      mode: 0o600,
    });
    await writeFile(join(fixture.resources, "operator-key-revision"), "1\n", {
      mode: 0o600,
    });
    await writeFile(
      join(fixture.resources, "integration-mode"),
      "hackerone-readonly\n",
      { mode: 0o600 },
    );

    const configuration = await loadMacOSLaunchConfiguration(fixture.resources);
    expect(configuration).toMatchObject({
      eventKeyMinimumVersion: "1",
      operatorKeyReference: "keychain://bugbounty-copilot/operator-ed25519-v1",
      operatorId: "local.admin",
      operatorKeyRevision: "1",
      hackerOneReadonlyEnabled: true,
    });
    const environment = buildMacOSDashboardEnvironment(configuration);
    expect(environment).toEqual({
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
      BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED: "true",
      BUGBOUNTY_HACKERONE_READONLY_ENABLED: "true",
      BUGBOUNTY_EVENT_KEY_MIN_VERSION: "1",
      BUGBOUNTY_OPERATOR_KEY_REFERENCE:
        "keychain://bugbounty-copilot/operator-ed25519-v1",
      BUGBOUNTY_OPERATOR_ID: "local.admin",
      BUGBOUNTY_OPERATOR_KEY_REVISION: "1",
    });
    expect(environment["NODE_OPTIONS"]).toBeUndefined();
    expect(environment["DYLD_INSERT_LIBRARIES"]).toBeUndefined();

    await writeFile(
      join(fixture.resources, "operator-key-revision"),
      "unset\n",
      { mode: 0o600 },
    );
    await expect(
      loadMacOSLaunchConfiguration(fixture.resources),
    ).rejects.toMatchObject({ code: "MACOS_LAUNCHER_CONFIG_INVALID" });

    await writeFile(join(fixture.resources, "operator-key-revision"), "01\n", {
      mode: 0o600,
    });
    await expect(
      loadMacOSLaunchConfiguration(fixture.resources),
    ).rejects.toMatchObject({ code: "MACOS_LAUNCHER_CONFIG_INVALID" });

    await writeFile(join(fixture.resources, "operator-key-revision"), "1\n", {
      mode: 0o600,
    });
    await writeFile(join(fixture.resources, "operator-id"), "unset\n", {
      mode: 0o600,
    });
    await expect(
      loadMacOSLaunchConfiguration(fixture.resources),
    ).rejects.toMatchObject({ code: "MACOS_LAUNCHER_CONFIG_INVALID" });
  });

  it("holds a single-instance lease only on loopback and releases it", async () => {
    const first = await acquireMacOSLauncherLease(0);
    try {
      await expect(acquireMacOSLauncherLease(first.port)).rejects.toMatchObject(
        { code: "MACOS_LAUNCHER_ALREADY_RUNNING" },
      );
      expect(
        macOSLauncherProcessExitCode(
          new MacOSLauncherError("MACOS_LAUNCHER_ALREADY_RUNNING"),
        ),
      ).toBe(MACOS_LAUNCHER_ALREADY_RUNNING_EXIT_CODE);
      expect(
        macOSLauncherProcessExitCode(
          new MacOSLauncherError("MACOS_LAUNCHER_LEASE_FAILED"),
        ),
      ).toBe(1);
      expect(
        macOSLauncherProcessExitCode(
          new MacOSLauncherError("MACOS_LAUNCHER_STARTUP_TIMEOUT"),
        ),
      ).toBe(MACOS_LAUNCHER_STARTUP_TIMEOUT_EXIT_CODE);
      expect(MACOS_LAUNCHER_ALREADY_RUNNING_EXIT_CODE).toBe(73);
      expect(MACOS_LAUNCHER_STARTUP_TIMEOUT_EXIT_CODE).toBe(74);
      expect(MACOS_LAUNCHER_STARTUP_TIMEOUT_MS).toBe(30_000);
    } finally {
      await first.close();
    }

    const afterRelease = await acquireMacOSLauncherLease(first.port);
    await afterRelease.close();
  });

  it("reaps an unresponsive dashboard before launcher cleanup continues", async () => {
    const child = spawn(
      process.execPath,
      [
        "-e",
        'process.on("SIGTERM",()=>{});process.stdout.write("ready\\n");setInterval(()=>{},1000)',
      ],
      {
        env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
    try {
      await new Promise<void>((resolvePromise, rejectPromise) => {
        child.once("error", rejectPromise);
        child.stdout.once("data", () => {
          child.removeListener("error", rejectPromise);
          resolvePromise();
        });
      });
      await terminateMacOSDashboardChild(child, 25);
      expect(child.signalCode).toBe("SIGKILL");
    } finally {
      if (child.exitCode === null && child.signalCode === null)
        child.kill("SIGKILL");
    }
  });

  it.runIf(process.platform === "darwin")(
    "installs a private local app bundle without embedding secrets or hosts",
    async () => {
      const target = await mkdtemp(join(tmpdir(), "bugbounty-app-target-"));
      const result = await runInstaller(target);
      expect(result.code).toBe(0);
      expect(result.stderr).toBe("");

      const app = join(target, "Bug Bounty Copilot.app");
      const resources = join(app, "Contents/Resources");
      expect(await readFile(join(resources, "repository-path"), "utf8")).toBe(
        `${ROOT}\n`,
      );
      const nodePath = (
        await readFile(join(resources, "node-path"), "utf8")
      ).trim();
      expect(nodePath.startsWith("/")).toBe(true);
      expect((await stat(nodePath)).isFile()).toBe(true);
      expect((await lstat(nodePath)).isSymbolicLink()).toBe(false);
      expect(await realpath(nodePath)).toBe(nodePath);
      expect(
        (await stat(join(resources, "repository-path"))).mode & 0o077,
      ).toBe(0);
      expect((await stat(join(resources, "node-path"))).mode & 0o077).toBe(0);
      const tsxPath = (
        await readFile(join(resources, "tsx-path"), "utf8")
      ).trim();
      expect(tsxPath.startsWith(`${ROOT}/`)).toBe(true);
      expect((await stat(tsxPath)).isFile()).toBe(true);
      expect((await lstat(tsxPath)).isSymbolicLink()).toBe(false);
      expect(await realpath(tsxPath)).toBe(tsxPath);
      expect((await stat(join(resources, "tsx-path"))).mode & 0o077).toBe(0);
      expect(await readFile(join(resources, "integration-mode"), "utf8")).toBe(
        "local-only\n",
      );
      expect(
        (await stat(join(resources, "integration-mode"))).mode & 0o077,
      ).toBe(0);
      for (const filename of [
        "event-key-minimum-version",
        "operator-key-reference",
        "operator-id",
        "operator-key-revision",
      ]) {
        expect(await readFile(join(resources, filename), "utf8")).toBe(
          "unset\n",
        );
        expect((await stat(join(resources, filename))).mode & 0o077).toBe(0);
      }
      expect((await readdir(resources)).sort()).toEqual(
        [
          "event-key-minimum-version",
          "integration-mode",
          "node-path",
          "operator-id",
          "operator-key-reference",
          "operator-key-revision",
          "repository-path",
          "tsx-path",
        ].sort(),
      );

      const executablePath = join(
        app,
        "Contents/MacOS/BugBountyCopilotLauncher",
      );
      const executable = await readFile(executablePath);
      expect([...executable.subarray(0, 4)]).toEqual([0xcf, 0xfa, 0xed, 0xfe]);
      expect((await stat(executablePath)).isFile()).toBe(true);
      expect((await lstat(executablePath)).isSymbolicLink()).toBe(false);
      expect((await stat(executablePath)).mode & 0o077).toBe(0);
      expect(executable.includes(Buffer.from(ROOT))).toBe(false);
      expect(executable.includes(Buffer.from("hackerone.com"))).toBe(false);
      expect(executable.includes(Buffer.from("api.hackerone.com"))).toBe(false);

      const nativeSource = await readFile(
        join(ROOT, "apps/macos-launcher/native/BugBountyCopilotLauncher.m"),
        "utf8",
      );
      expect(nativeSource).toContain("<NSApplicationDelegate>");
      expect(nativeSource).toContain("[application run]");
      expect(nativeSource).toContain("posix_spawn(");
      expect(nativeSource).toContain("POSIX_SPAWN_SETPGROUP");
      expect(nativeSource).toContain("waitpid(child");
      expect(nativeSource).toContain("kAlreadyRunningExitCode = 73");
      expect(nativeSource).toContain("kStartupTimeoutExitCode = 74");
      expect(nativeSource).not.toContain("hackerone.com");
      expect(nativeSource).not.toContain("api.hackerone.com");
      expect(nativeSource).not.toContain("https://");
      expect(nativeSource).not.toMatch(/\b(?:curl|npm|npx|pnpm)\b/u);
      expect(nativeSource).not.toMatch(/\b(?:system|popen|NSLog)\s*\(/u);

      const signature = await runCommand("/usr/bin/codesign", [
        "--verify",
        "--strict",
        app,
      ]);
      expect(signature.code).toBe(0);
      expect(signature.stdout).toBe("");
      expect(signature.stderr).toBe("");

      const signatureDetails = await runCommand("/usr/bin/codesign", [
        "-dv",
        "--verbose=4",
        app,
      ]);
      expect(signatureDetails.code).toBe(0);
      expect(signatureDetails.stdout).toBe("");
      expect(signatureDetails.stderr).toContain(
        "Identifier=dev.local.bugbounty-copilot.launcher",
      );
      expect(signatureDetails.stderr).toContain("Signature=adhoc");
      expect(signatureDetails.stderr).toContain("Sealed Resources version=2");
      expect(signatureDetails.stderr).toContain("files=8");

      const entitlements = await runCommand("/usr/bin/codesign", [
        "-d",
        "--entitlements",
        "-",
        app,
      ]);
      expect(entitlements.code).toBe(0);
      expect(entitlements.stdout).toBe("");
      expect(entitlements.stderr).not.toContain("<key>");

      for (const [key, expected] of [
        ["CFBundleExecutable", "BugBountyCopilotLauncher"],
        ["CFBundleIdentifier", "dev.local.bugbounty-copilot.launcher"],
        ["CFBundleShortVersionString", "0.1.1"],
        ["CFBundleVersion", "2"],
        ["LSMinimumSystemVersion", "13.0"],
        ["LSUIElement", "true"],
        ["LSMultipleInstancesProhibited", "true"],
        [
          "NSDownloadsFolderUsageDescription",
          "Bug Bounty Copilot benötigt Zugriff auf das lokale Repository im Downloads-Ordner, um die Anwendung ohne Terminal zu starten.",
        ],
      ] as const) {
        const value = await runCommand("/usr/bin/plutil", [
          "-extract",
          key,
          "raw",
          "--",
          join(app, "Contents/Info.plist"),
        ]);
        expect(value.code).toBe(0);
        expect(value.stdout.trim()).toBe(expected);
        expect(value.stderr).toBe("");
      }

      const dependencies = await runCommand("/usr/bin/otool", [
        "-L",
        executablePath,
      ]);
      expect(dependencies.code).toBe(0);
      expect(dependencies.stderr).toBe("");
      for (const dependency of dependencies.stdout.split("\n").slice(1)) {
        if (dependency.trim() === "") continue;
        expect(dependency.trim()).toMatch(/^\/(?:System\/Library|usr\/lib)\//u);
      }

      const undefinedSymbols = await runCommand("/usr/bin/nm", [
        "-u",
        executablePath,
      ]);
      expect(undefinedSymbols.code).toBe(0);
      expect(undefinedSymbols.stdout).not.toMatch(
        /\b_(?:connect|getaddrinfo|socket)\b|NSURLSession/u,
      );

      const loadCommands = await runCommand("/usr/bin/otool", [
        "-l",
        executablePath,
      ]);
      expect(loadCommands.code).toBe(0);
      expect(loadCommands.stdout).toMatch(/\bminos 13\.0\b/u);

      const second = await runInstaller(target);
      expect(second.code).toBe(0);
      expect(second.stderr).toBe("");

      const hostileToolchainEnvironment = await runInstaller(target, false, {
        DEVELOPER_DIR: "/private/tmp/untrusted-developer-directory",
        SDKROOT: "/private/tmp/untrusted-sdk",
      });
      expect(hostileToolchainEnvironment.code).toBe(0);
      expect(hostileToolchainEnvironment.stderr).toBe("");

      const explicitHackerOne = await runInstaller(target, true, {
        BUGBOUNTY_EVENT_KEY_MIN_VERSION: "1",
        BUGBOUNTY_OPERATOR_KEY_REFERENCE:
          "keychain://bugbounty-copilot/operator-ed25519-v1",
        BUGBOUNTY_OPERATOR_ID: "local.admin",
        BUGBOUNTY_OPERATOR_KEY_REVISION: "1",
      });
      expect(explicitHackerOne.code).toBe(0);
      expect(explicitHackerOne.stderr).toBe("");
      expect(await readFile(join(resources, "integration-mode"), "utf8")).toBe(
        "hackerone-readonly\n",
      );
      expect(
        await readFile(join(resources, "event-key-minimum-version"), "utf8"),
      ).toBe("1\n");
      expect(
        await readFile(join(resources, "operator-key-reference"), "utf8"),
      ).toBe("keychain://bugbounty-copilot/operator-ed25519-v1\n");
      expect(await readFile(join(resources, "operator-id"), "utf8")).toBe(
        "local.admin\n",
      );
      expect(
        await readFile(join(resources, "operator-key-revision"), "utf8"),
      ).toBe("1\n");
      await expect(
        loadMacOSLaunchConfiguration(await realpath(resources)),
      ).resolves.toMatchObject({ hackerOneReadonlyEnabled: true });

      const partialOperator = await runInstaller(target, true, {
        BUGBOUNTY_OPERATOR_ID: "local.admin",
      });
      expect(partialOperator.code).toBe(1);
      expect(partialOperator.stderr).toContain(
        "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID",
      );

      const sentinelCollision = await runInstaller(target, true, {
        BUGBOUNTY_OPERATOR_KEY_REFERENCE:
          "keychain://bugbounty-copilot/operator-ed25519-v1",
        BUGBOUNTY_OPERATOR_ID: "unset",
        BUGBOUNTY_OPERATOR_KEY_REVISION: "1",
      });
      expect(sentinelCollision.code).toBe(1);
      expect(sentinelCollision.stderr).toContain(
        "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID",
      );

      const infoPlist = join(app, "Contents/Info.plist");
      const foreignPlist = `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>example.foreign.app</string><key>Comment</key><string>dev.local.bugbounty-copilot.launcher</string></dict></plist>\n`;
      await writeFile(infoPlist, foreignPlist, { mode: 0o600 });
      const blockedOverwrite = await runInstaller(target);
      expect(blockedOverwrite.code).toBe(1);
      expect(blockedOverwrite.stderr).toContain(
        "MACOS_LAUNCHER_INSTALL_EXISTING_APP_BLOCKED",
      );
      expect(await readFile(infoPlist, "utf8")).toBe(foreignPlist);
    },
  );

  it.runIf(process.platform === "darwin")(
    "preserves an existing app and removes staging after native compilation fails",
    async () => {
      const fixture = await realpath(
        await mkdtemp(join(tmpdir(), "bugbounty-broken-installer-")),
      );
      await mkdir(join(fixture, "apps/macos-launcher/native"), {
        recursive: true,
      });
      await mkdir(join(fixture, "apps/macos-launcher/bundle"), {
        recursive: true,
      });
      await mkdir(join(fixture, "apps/dashboard"), { recursive: true });
      await mkdir(join(fixture, "node_modules/tsx/dist"), { recursive: true });
      await copyFile(
        join(ROOT, "apps/macos-launcher/install.sh"),
        join(fixture, "apps/macos-launcher/install.sh"),
      );
      await copyFile(
        join(ROOT, "apps/macos-launcher/bundle/Info.plist"),
        join(fixture, "apps/macos-launcher/bundle/Info.plist"),
      );
      await writeFile(join(fixture, "package.json"), "{}\n");
      await writeFile(join(fixture, "apps/dashboard/index.ts"), "fixture\n");
      await writeFile(
        join(fixture, "apps/macos-launcher/index.ts"),
        "fixture\n",
      );
      await writeFile(
        join(fixture, "node_modules/tsx/dist/cli.mjs"),
        "fixture\n",
      );
      await writeFile(
        join(fixture, "apps/macos-launcher/native/BugBountyCopilotLauncher.m"),
        "this is deliberately not Objective-C\n",
        { mode: 0o600 },
      );

      const target = await realpath(
        await mkdtemp(join(tmpdir(), "bugbounty-existing-app-")),
      );
      const app = join(target, "Bug Bounty Copilot.app");
      await mkdir(join(app, "Contents"), { recursive: true, mode: 0o700 });
      await chmod(app, 0o700);
      await chmod(join(app, "Contents"), 0o700);
      await copyFile(
        join(ROOT, "apps/macos-launcher/bundle/Info.plist"),
        join(app, "Contents/Info.plist"),
      );
      await chmod(join(app, "Contents/Info.plist"), 0o600);
      await mkdir(join(app, "Contents/MacOS"), { mode: 0o700 });
      await writeFile(
        join(app, "Contents/MacOS/BugBountyCopilotLauncher"),
        "existing fixture executable\n",
        { mode: 0o700 },
      );
      await writeFile(join(app, "sentinel"), "preserve me\n", { mode: 0o600 });

      const result = await runInstaller(target, false, {}, fixture);
      expect(result.code).toBe(1);
      expect(result.stderr).toContain("MACOS_LAUNCHER_INSTALL_COMPILE_FAILED");
      expect(await readFile(join(app, "sentinel"), "utf8")).toBe(
        "preserve me\n",
      );
      expect(await readdir(target)).toEqual(["Bug Bounty Copilot.app"]);
    },
  );
});

async function launcherFixture(): Promise<{
  readonly repository: string;
  readonly resources: string;
}> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "bugbounty launcher test-")),
  );
  const repository = join(root, "repository");
  const resources = join(root, "resources");
  await mkdir(join(repository, "apps/dashboard"), { recursive: true });
  await mkdir(join(repository, "node_modules/tsx/dist"), { recursive: true });
  await mkdir(resources);
  await writeFile(
    join(repository, "package.json"),
    JSON.stringify({
      name: "bugbounty-copilot-security-core",
      scripts: { app: "tsx apps/dashboard/index.ts" },
    }),
  );
  await writeFile(join(repository, "apps/dashboard/index.ts"), "");
  await writeFile(join(repository, "node_modules/tsx/dist/cli.mjs"), "");
  await writeFile(join(resources, "repository-path"), `${repository}\n`, {
    mode: 0o600,
  });
  await writeFile(join(resources, "node-path"), "/usr/bin/true\n", {
    mode: 0o600,
  });
  await writeFile(join(resources, "integration-mode"), "local-only\n", {
    mode: 0o600,
  });
  for (const filename of [
    "event-key-minimum-version",
    "operator-key-reference",
    "operator-id",
    "operator-key-revision",
  ]) {
    await writeFile(join(resources, filename), "unset\n", { mode: 0o600 });
  }
  return { repository, resources };
}

function runInstaller(
  target: string,
  enableHackerOne = false,
  coreMetadata: Readonly<Record<string, string>> = {},
  repositoryRoot = ROOT,
): Promise<{
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}> {
  return new Promise((resolvePromise, rejectPromise) => {
    const excluded = new Set([
      "BUGBOUNTY_EVENT_KEY_MIN_VERSION",
      "BUGBOUNTY_OPERATOR_KEY_REFERENCE",
      "BUGBOUNTY_OPERATOR_ID",
      "BUGBOUNTY_OPERATOR_KEY_REVISION",
    ]);
    const environment: NodeJS.ProcessEnv = Object.fromEntries(
      Object.entries(process.env).filter(([name]) => !excluded.has(name)),
    );
    Object.assign(environment, coreMetadata);
    const child = spawn(
      "/bin/bash",
      [
        "apps/macos-launcher/install.sh",
        ...(enableHackerOne ? ["--enable-hackerone-readonly"] : []),
        target,
      ],
      {
        cwd: repositoryRoot,
        env: environment,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("error", rejectPromise);
    child.once("close", (code) => {
      resolvePromise({ code, stdout, stderr });
    });
  });
}

function runCommand(
  command: string,
  arguments_: readonly string[],
): Promise<{
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, arguments_, {
      env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.once("error", rejectPromise);
    child.once("close", (code) => {
      resolvePromise({ code, stdout, stderr });
    });
  });
}
