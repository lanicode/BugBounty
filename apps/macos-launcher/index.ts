import { access, lstat, readFile, realpath, stat } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:net";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Readable } from "node:stream";

const PACKAGE_NAME = "bugbounty-copilot-security-core";
const APP_SCRIPT = "tsx apps/dashboard/index.ts";
const DASHBOARD_ENTRY = join("apps", "dashboard", "index.ts");
const TSX_ENTRY = join("node_modules", "tsx", "dist", "cli.mjs");
const CONFIG_FILE_MODE_MASK = 0o077;
const MAX_CONFIG_BYTES = 4_096;
const MAX_STARTUP_OUTPUT_BYTES = 16_384;
const MINIMUM_DASHBOARD_PORT = 1_024;
export const MACOS_LAUNCHER_STARTUP_TIMEOUT_MS = 30_000;
const MAX_STARTUP_TIMEOUT_MS = 60_000;
const DEFAULT_TERMINATION_GRACE_MS = 2_000;
const MAX_TERMINATION_GRACE_MS = 10_000;
const LOOPBACK_HOST = "127.0.0.1";
const MINIMAL_PATH = "/usr/bin:/bin:/usr/sbin:/sbin";
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/u;
const OPERATOR_ID = /^[A-Za-z0-9._@-]{1,128}$/u;
const KEYCHAIN_REFERENCE =
  /^keychain:\/\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._/-]+)$/u;
const MAX_EVENT_KEY_VERSION = 10_000;
export const MACOS_LAUNCHER_LEASE_PORT = 43_917;
export const MACOS_LAUNCHER_ALREADY_RUNNING_EXIT_CODE = 73;
export const MACOS_LAUNCHER_STARTUP_TIMEOUT_EXIT_CODE = 74;

export type MacOSLauncherErrorCode =
  | "MACOS_LAUNCHER_CONFIG_INVALID"
  | "MACOS_LAUNCHER_DASHBOARD_EXITED"
  | "MACOS_LAUNCHER_DASHBOARD_OUTPUT_INVALID"
  | "MACOS_LAUNCHER_DEPENDENCY_MISSING"
  | "MACOS_LAUNCHER_ALREADY_RUNNING"
  | "MACOS_LAUNCHER_LEASE_FAILED"
  | "MACOS_LAUNCHER_OPEN_FAILED"
  | "MACOS_LAUNCHER_PLATFORM_BLOCKED"
  | "MACOS_LAUNCHER_STARTUP_TIMEOUT";

export class MacOSLauncherError extends Error {
  public constructor(public readonly code: MacOSLauncherErrorCode) {
    super(code);
    this.name = "MacOSLauncherError";
  }
}

export function macOSLauncherProcessExitCode(error: unknown): number {
  if (!(error instanceof MacOSLauncherError)) return 1;
  if (error.code === "MACOS_LAUNCHER_ALREADY_RUNNING")
    return MACOS_LAUNCHER_ALREADY_RUNNING_EXIT_CODE;
  if (error.code === "MACOS_LAUNCHER_STARTUP_TIMEOUT")
    return MACOS_LAUNCHER_STARTUP_TIMEOUT_EXIT_CODE;
  return 1;
}

export interface MacOSLaunchConfiguration {
  readonly repositoryRoot: string;
  readonly nodeExecutable: string;
  readonly tsxEntry: string;
  readonly dashboardEntry: string;
  readonly hackerOneReadonlyEnabled: boolean;
  readonly eventKeyMinimumVersion?: string;
  readonly operatorKeyReference?: string;
  readonly operatorId?: string;
  readonly operatorKeyRevision?: string;
}

export interface MacOSLauncherLease {
  readonly port: number;
  close(): Promise<void>;
}

export async function loadMacOSLaunchConfiguration(
  resourcesDirectory: string,
): Promise<MacOSLaunchConfiguration> {
  if (!isAbsolute(resourcesDirectory)) fail("MACOS_LAUNCHER_CONFIG_INVALID");
  const resourcesRoot = await exactRealDirectory(resourcesDirectory);
  const repositoryRoot = await readPrivatePath(
    join(resourcesRoot, "repository-path"),
  );
  const nodeExecutable = await readPrivatePath(
    join(resourcesRoot, "node-path"),
  );
  const integrationMode = await readPrivateSetting(
    join(resourcesRoot, "integration-mode"),
  );
  if (
    integrationMode !== "local-only" &&
    integrationMode !== "hackerone-readonly"
  )
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
  const eventKeyMinimumVersion = await readOptionalPrivateSetting(
    join(resourcesRoot, "event-key-minimum-version"),
  );
  const operatorKeyReference = await readOptionalPrivateSetting(
    join(resourcesRoot, "operator-key-reference"),
  );
  const operatorId = await readOptionalPrivateSetting(
    join(resourcesRoot, "operator-id"),
  );
  const operatorKeyRevision = await readOptionalPrivateSetting(
    join(resourcesRoot, "operator-key-revision"),
  );
  validateCoreMetadata({
    eventKeyMinimumVersion,
    operatorKeyReference,
    operatorId,
    operatorKeyRevision,
  });

  await exactRealDirectory(repositoryRoot);
  await executableFile(nodeExecutable);

  const packagePath = join(repositoryRoot, "package.json");
  const dashboardEntry = join(repositoryRoot, DASHBOARD_ENTRY);
  const tsxEntry = join(repositoryRoot, TSX_ENTRY);
  await regularFile(packagePath);
  await regularFile(dashboardEntry);
  await regularFile(tsxEntry);
  await validateManifest(packagePath);

  return Object.freeze({
    repositoryRoot,
    nodeExecutable,
    tsxEntry,
    dashboardEntry,
    hackerOneReadonlyEnabled: integrationMode === "hackerone-readonly",
    ...(eventKeyMinimumVersion === undefined ? {} : { eventKeyMinimumVersion }),
    ...(operatorKeyReference === undefined ? {} : { operatorKeyReference }),
    ...(operatorId === undefined ? {} : { operatorId }),
    ...(operatorKeyRevision === undefined ? {} : { operatorKeyRevision }),
  });
}

export function validateLocalDashboardOrigin(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    fail("MACOS_LAUNCHER_DASHBOARD_OUTPUT_INVALID");
  }
  const port = Number(parsed.port);
  if (
    parsed.protocol !== "http:" ||
    parsed.hostname !== "127.0.0.1" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.port === "" ||
    !Number.isSafeInteger(port) ||
    port < MINIMUM_DASHBOARD_PORT ||
    port > 65_535 ||
    parsed.origin !== value
  )
    fail("MACOS_LAUNCHER_DASHBOARD_OUTPUT_INVALID");
  return parsed.origin;
}

export function waitForLocalDashboardOrigin(
  stream: Readable,
  timeoutMs = MACOS_LAUNCHER_STARTUP_TIMEOUT_MS,
): Promise<string> {
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > MAX_STARTUP_TIMEOUT_MS
  )
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
  return new Promise((resolvePromise, rejectPromise) => {
    let buffered = "";
    let bytes = 0;
    let settled = false;
    const timeout = setTimeout(() => {
      settleError("MACOS_LAUNCHER_STARTUP_TIMEOUT");
    }, timeoutMs);
    stream.setEncoding("utf8");
    const cleanup = (): void => {
      clearTimeout(timeout);
      stream.removeListener("data", onData);
      stream.removeListener("end", onEnd);
      stream.removeListener("error", onError);
    };
    const settleError = (code: MacOSLauncherErrorCode): void => {
      if (settled) return;
      settled = true;
      cleanup();
      buffered = "";
      rejectPromise(new MacOSLauncherError(code));
    };
    const inspectLine = (line: string): boolean => {
      const prefix = "Dashboard-URL: ";
      if (!line.startsWith(prefix)) return false;
      try {
        const origin = validateLocalDashboardOrigin(line.slice(prefix.length));
        settled = true;
        cleanup();
        buffered = "";
        stream.resume();
        resolvePromise(origin);
      } catch {
        settleError("MACOS_LAUNCHER_DASHBOARD_OUTPUT_INVALID");
      }
      return true;
    };
    const inspectCompleteLines = (): void => {
      let newline = buffered.indexOf("\n");
      while (newline >= 0) {
        const line = buffered.slice(0, newline).replace(/\r$/u, "");
        buffered = buffered.slice(newline + 1);
        if (inspectLine(line)) return;
        newline = buffered.indexOf("\n");
      }
    };
    const onData = (chunk: string): void => {
      bytes += Buffer.byteLength(chunk, "utf8");
      if (bytes > MAX_STARTUP_OUTPUT_BYTES) {
        settleError("MACOS_LAUNCHER_DASHBOARD_OUTPUT_INVALID");
        return;
      }
      buffered += chunk;
      inspectCompleteLines();
    };
    const onEnd = (): void => {
      if (settled) return;
      if (buffered !== "" && inspectLine(buffered.replace(/\r$/u, ""))) return;
      settleError("MACOS_LAUNCHER_DASHBOARD_EXITED");
    };
    const onError = (): void => {
      settleError("MACOS_LAUNCHER_DASHBOARD_EXITED");
    };

    stream.on("data", onData);
    stream.once("end", onEnd);
    stream.once("error", onError);
  });
}

export async function runMacOSLauncher(
  resourcesDirectory: string,
  platform: NodeJS.Platform = process.platform,
): Promise<void> {
  if (platform !== "darwin") fail("MACOS_LAUNCHER_PLATFORM_BLOCKED");
  const lease = await acquireMacOSLauncherLease();
  let dashboard: ChildProcess | undefined;
  let shutdownRequested = false;
  let terminationPromise: Promise<void> | undefined;
  let terminationFailed = false;
  const wasShutdownRequested = (): boolean => shutdownRequested;
  const didTerminationFail = (): boolean => terminationFailed;
  const beginDashboardTermination = (): Promise<void> => {
    if (dashboard === undefined) return Promise.resolve();
    terminationPromise ??= terminateMacOSDashboardChild(dashboard).catch(() => {
      terminationFailed = true;
    });
    return terminationPromise;
  };
  const requestShutdown = (): void => {
    shutdownRequested = true;
    void beginDashboardTermination();
  };
  process.once("SIGINT", requestShutdown);
  process.once("SIGTERM", requestShutdown);

  try {
    const configuration =
      await loadMacOSLaunchConfiguration(resourcesDirectory);
    if (wasShutdownRequested()) return;
    dashboard = spawn(
      configuration.nodeExecutable,
      [configuration.tsxEntry, configuration.dashboardEntry],
      {
        cwd: configuration.repositoryRoot,
        env: buildMacOSDashboardEnvironment(configuration),
        shell: false,
        stdio: ["ignore", "pipe", "ignore"],
        windowsHide: true,
      },
    );
    await childSpawned(dashboard);
    if (wasShutdownRequested()) {
      await beginDashboardTermination();
      if (didTerminationFail()) fail("MACOS_LAUNCHER_LEASE_FAILED");
      return;
    }
    if (dashboard.stdout === null)
      fail("MACOS_LAUNCHER_DASHBOARD_OUTPUT_INVALID");
    const origin = await waitForLocalDashboardOrigin(dashboard.stdout);
    await openLocalDashboard(origin);
    await waitForDashboardExit(dashboard);
  } catch (error) {
    await beginDashboardTermination();
    if (didTerminationFail()) fail("MACOS_LAUNCHER_LEASE_FAILED");
    if (wasShutdownRequested()) return;
    if (error instanceof MacOSLauncherError) throw error;
    fail("MACOS_LAUNCHER_DASHBOARD_EXITED");
  } finally {
    process.removeListener("SIGINT", requestShutdown);
    process.removeListener("SIGTERM", requestShutdown);
    if (terminationPromise !== undefined) await terminationPromise;
    await lease.close();
  }
}

export async function terminateMacOSDashboardChild(
  child: ChildProcess,
  graceMs = DEFAULT_TERMINATION_GRACE_MS,
): Promise<void> {
  if (
    !Number.isSafeInteger(graceMs) ||
    graceMs < 1 ||
    graceMs > MAX_TERMINATION_GRACE_MS
  )
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
  if (child.exitCode !== null || child.signalCode !== null) return;

  const reaped = childReaped(child);
  terminateChild(child);
  if (await promiseSettledWithin(reaped, graceMs)) return;
  child.kill("SIGKILL");
  await reaped;
}

export function buildMacOSDashboardEnvironment(
  configuration: MacOSLaunchConfiguration,
): NodeJS.ProcessEnv {
  if (typeof configuration.hackerOneReadonlyEnabled !== "boolean")
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
  validateCoreMetadata(configuration);
  return Object.freeze({
    PATH: MINIMAL_PATH,
    BUGBOUNTY_EXTERNAL_INTEGRATIONS_ENABLED:
      configuration.hackerOneReadonlyEnabled ? "true" : "false",
    BUGBOUNTY_HACKERONE_READONLY_ENABLED: configuration.hackerOneReadonlyEnabled
      ? "true"
      : "false",
    ...(configuration.eventKeyMinimumVersion === undefined
      ? {}
      : {
          BUGBOUNTY_EVENT_KEY_MIN_VERSION: configuration.eventKeyMinimumVersion,
        }),
    ...(configuration.operatorKeyReference === undefined
      ? {}
      : {
          BUGBOUNTY_OPERATOR_KEY_REFERENCE: configuration.operatorKeyReference,
          BUGBOUNTY_OPERATOR_ID: configuration.operatorId,
          BUGBOUNTY_OPERATOR_KEY_REVISION: configuration.operatorKeyRevision,
        }),
  });
}

export async function acquireMacOSLauncherLease(
  port = MACOS_LAUNCHER_LEASE_PORT,
): Promise<MacOSLauncherLease> {
  if (
    !Number.isSafeInteger(port) ||
    (port !== 0 && (port < MINIMUM_DASHBOARD_PORT || port > 65_535))
  )
    fail("MACOS_LAUNCHER_CONFIG_INVALID");

  const server = createServer((socket) => {
    socket.destroy();
  });
  try {
    await listenForLease(server, port);
  } catch (error) {
    if (errorCode(error) === "EADDRINUSE")
      fail("MACOS_LAUNCHER_ALREADY_RUNNING");
    fail("MACOS_LAUNCHER_LEASE_FAILED");
  }
  const address = server.address();
  if (
    address === null ||
    typeof address === "string" ||
    address.address !== LOOPBACK_HOST ||
    address.family !== "IPv4" ||
    !Number.isSafeInteger(address.port) ||
    address.port < MINIMUM_DASHBOARD_PORT ||
    address.port > 65_535
  ) {
    await closeLeaseServer(server).catch(() => undefined);
    fail("MACOS_LAUNCHER_LEASE_FAILED");
  }

  let closePromise: Promise<void> | undefined;
  return Object.freeze({
    port: address.port,
    close(): Promise<void> {
      closePromise ??= closeLeaseServer(server);
      return closePromise;
    },
  });
}

async function readPrivatePath(path: string): Promise<string> {
  const value = await readPrivateSetting(path);
  if (!isAbsolute(value)) fail("MACOS_LAUNCHER_CONFIG_INVALID");
  return value;
}

async function readOptionalPrivateSetting(
  path: string,
): Promise<string | undefined> {
  const value = await readPrivateSetting(path);
  return value === "unset" ? undefined : value;
}

async function readPrivateSetting(path: string): Promise<string> {
  const metadata = await lstat(path).catch(() => undefined);
  if (
    metadata === undefined ||
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    (metadata.mode & CONFIG_FILE_MODE_MASK) !== 0 ||
    metadata.size < 2 ||
    metadata.size > MAX_CONFIG_BYTES ||
    (typeof process.getuid === "function" && metadata.uid !== process.getuid())
  )
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
  const content = await readFile(path, "utf8").catch(() => undefined);
  if (
    content === undefined ||
    !content.endsWith("\n") ||
    content.slice(0, -1).includes("\n") ||
    content.includes("\r") ||
    content.includes("\0")
  )
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
  const value = content.slice(0, -1);
  if (value === "") fail("MACOS_LAUNCHER_CONFIG_INVALID");
  return value;
}

async function exactRealDirectory(path: string): Promise<string> {
  const metadata = await lstat(path).catch(() => undefined);
  if (
    metadata === undefined ||
    !metadata.isDirectory() ||
    metadata.isSymbolicLink()
  )
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
  const canonical = await realpath(path).catch(() => undefined);
  if (canonical === undefined || canonical !== path)
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
  return canonical;
}

async function regularFile(path: string): Promise<void> {
  const metadata = await stat(path).catch(() => undefined);
  if (!metadata?.isFile()) fail("MACOS_LAUNCHER_DEPENDENCY_MISSING");
}

async function executableFile(path: string): Promise<void> {
  const metadata = await lstat(path).catch(() => undefined);
  if (metadata === undefined || !metadata.isFile() || metadata.isSymbolicLink())
    fail("MACOS_LAUNCHER_DEPENDENCY_MISSING");
  const canonical = await realpath(path).catch(() => undefined);
  if (canonical === undefined || canonical !== path)
    fail("MACOS_LAUNCHER_DEPENDENCY_MISSING");
  await access(path, fsConstants.X_OK).catch(() =>
    fail("MACOS_LAUNCHER_DEPENDENCY_MISSING"),
  );
}

async function validateManifest(path: string): Promise<void> {
  let value: unknown;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch {
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
  }
  if (!isRecord(value) || value["name"] !== PACKAGE_NAME)
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
  const scripts = value["scripts"];
  if (!isRecord(scripts) || scripts["app"] !== APP_SCRIPT)
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
}

function validateCoreMetadata(configuration: {
  readonly eventKeyMinimumVersion?: string | undefined;
  readonly operatorKeyReference?: string | undefined;
  readonly operatorId?: string | undefined;
  readonly operatorKeyRevision?: string | undefined;
}): void {
  if (
    configuration.eventKeyMinimumVersion !== undefined &&
    !isCanonicalPositiveInteger(
      configuration.eventKeyMinimumVersion,
      MAX_EVENT_KEY_VERSION,
    )
  )
    fail("MACOS_LAUNCHER_CONFIG_INVALID");

  const operatorValues = [
    configuration.operatorKeyReference,
    configuration.operatorId,
    configuration.operatorKeyRevision,
  ];
  const configuredCount = operatorValues.filter(
    (value) => value !== undefined,
  ).length;
  if (configuredCount === 0) return;
  if (configuredCount !== operatorValues.length)
    fail("MACOS_LAUNCHER_CONFIG_INVALID");

  const reference = configuration.operatorKeyReference;
  const operatorId = configuration.operatorId;
  const revision = configuration.operatorKeyRevision;
  if (
    reference === undefined ||
    operatorId === undefined ||
    revision === undefined ||
    reference.length > 512 ||
    !isCanonicalKeychainReference(reference) ||
    !OPERATOR_ID.test(operatorId) ||
    !isCanonicalPositiveInteger(revision, Number.MAX_SAFE_INTEGER)
  )
    fail("MACOS_LAUNCHER_CONFIG_INVALID");
}

function isCanonicalPositiveInteger(value: string, maximum: number): boolean {
  if (value.length === 0 || value.length > 16 || !POSITIVE_DECIMAL.test(value))
    return false;
  const parsed = Number(value);
  return (
    Number.isSafeInteger(parsed) &&
    parsed > 0 &&
    parsed <= maximum &&
    String(parsed) === value
  );
}

function isCanonicalKeychainReference(value: string): boolean {
  const match = KEYCHAIN_REFERENCE.exec(value);
  return (
    match?.[1] !== undefined &&
    match[2] !== undefined &&
    !match[2].includes("..")
  );
}

function listenForLease(server: Server, port: number): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    const cleanup = (): void => {
      server.removeListener("error", onError);
      server.removeListener("listening", onListening);
    };
    const onError = (error: Error): void => {
      cleanup();
      rejectPromise(error);
    };
    const onListening = (): void => {
      cleanup();
      resolvePromise();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen({ exclusive: true, host: LOOPBACK_HOST, port });
  });
}

function closeLeaseServer(server: Server): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    if (!server.listening) {
      resolvePromise();
      return;
    }
    server.close((error) => {
      if (error === undefined) resolvePromise();
      else rejectPromise(error);
    });
  });
}

function errorCode(error: unknown): string | undefined {
  if (error === null || typeof error !== "object") return undefined;
  try {
    const code: unknown = Object.getOwnPropertyDescriptor(error, "code")?.value;
    return typeof code === "string" ? code : undefined;
  } catch {
    return undefined;
  }
}

function childSpawned(child: ChildProcess): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    const onSpawn = (): void => {
      child.removeListener("error", onError);
      resolvePromise();
    };
    const onError = (): void => {
      child.removeListener("spawn", onSpawn);
      rejectPromise(
        new MacOSLauncherError("MACOS_LAUNCHER_DEPENDENCY_MISSING"),
      );
    };
    child.once("spawn", onSpawn);
    child.once("error", onError);
  });
}

function openLocalDashboard(origin: string): Promise<void> {
  const validatedOrigin = validateLocalDashboardOrigin(origin);
  const opener = spawn("/usr/bin/open", [validatedOrigin], {
    shell: false,
    stdio: "ignore",
    windowsHide: true,
  });
  return new Promise((resolvePromise, rejectPromise) => {
    opener.once("error", () => {
      rejectPromise(new MacOSLauncherError("MACOS_LAUNCHER_OPEN_FAILED"));
    });
    opener.once("close", (code) => {
      if (code === 0) resolvePromise();
      else rejectPromise(new MacOSLauncherError("MACOS_LAUNCHER_OPEN_FAILED"));
    });
  });
}

function waitForDashboardExit(dashboard: ChildProcess): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    if (dashboard.exitCode !== null || dashboard.signalCode !== null) {
      if (dashboard.exitCode === 0 && dashboard.signalCode === null)
        resolvePromise();
      else
        rejectPromise(
          new MacOSLauncherError("MACOS_LAUNCHER_DASHBOARD_EXITED"),
        );
      return;
    }
    dashboard.once("error", () => {
      rejectPromise(new MacOSLauncherError("MACOS_LAUNCHER_DASHBOARD_EXITED"));
    });
    dashboard.once("close", (code, signal) => {
      if (code === 0 && signal === null) resolvePromise();
      else
        rejectPromise(
          new MacOSLauncherError("MACOS_LAUNCHER_DASHBOARD_EXITED"),
        );
    });
  });
}

function childReaped(child: ChildProcess): Promise<void> {
  return new Promise((resolvePromise) => {
    const cleanup = (): void => {
      child.removeListener("close", onReaped);
      child.removeListener("error", onReaped);
    };
    const onReaped = (): void => {
      cleanup();
      resolvePromise();
    };
    child.once("close", onReaped);
    child.once("error", onReaped);
    if (child.exitCode !== null || child.signalCode !== null) onReaped();
  });
}

async function promiseSettledWithin(
  promise: Promise<void>,
  timeoutMs: number,
): Promise<boolean> {
  let timeout: NodeJS.Timeout | undefined;
  const timedOut = new Promise<false>((resolvePromise) => {
    timeout = setTimeout(() => {
      resolvePromise(false);
    }, timeoutMs);
  });
  const result = await Promise.race([
    promise.then(() => true as const),
    timedOut,
  ]);
  if (timeout !== undefined) clearTimeout(timeout);
  return result;
}

function terminateChild(child: ChildProcess): void {
  if (child.exitCode === null && child.signalCode === null)
    child.kill("SIGTERM");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function fail(code: MacOSLauncherErrorCode): never {
  throw new MacOSLauncherError(code);
}

async function main(): Promise<void> {
  const resourcesDirectory = process.argv[2];
  if (resourcesDirectory === undefined) fail("MACOS_LAUNCHER_CONFIG_INVALID");
  await runMacOSLauncher(resourcesDirectory);
}

const invokedPath = process.argv[1];
if (
  invokedPath !== undefined &&
  resolve(invokedPath) === resolve(fileURLToPath(import.meta.url))
)
  void main().catch((error: unknown) => {
    process.exitCode = macOSLauncherProcessExitCode(error);
    if (error instanceof MacOSLauncherError)
      process.stderr.write(`${error.code}\n`);
    else process.stderr.write("MACOS_LAUNCHER_DASHBOARD_EXITED\n");
  });
