import { randomBytes } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import type { SecretStore } from "../../packages/secret-store/index.js";
import { HackerOneReadOnlyClient } from "../../packages/hackerone-readonly/client.js";
import {
  HackerOneCredentialVault,
  type HackerOneCredentialPair,
  type HackerOneKeychainMutationBackend,
} from "../../packages/hackerone-readonly/credential-vault.js";
import { resolveHackerOneMetadataReadRuntime } from "../../packages/hackerone-readonly/runtime.js";
import type {
  HackerOneTransport,
  HackerOneTransportPlan,
  HackerOneTransportResponse,
} from "../../packages/hackerone-readonly/transport.js";
import {
  HACKERONE_IDENTIFIER_REFERENCE,
  HACKERONE_TOKEN_REFERENCE,
  type HackerOneRequestAuditEvent,
} from "../../packages/hackerone-readonly/types.js";
import { createActivatedHackerOneActionHarness } from "../fixtures/hackerone-action.factory.js";

const ROOT = process.cwd();

class LeakProbeSecretStore
  implements SecretStore, HackerOneKeychainMutationBackend
{
  public readonly returned: Uint8Array[] = [];
  private identifier: Uint8Array | undefined;
  private token: Uint8Array | undefined;

  public get(reference: string): Promise<Uint8Array> {
    const source =
      reference === HACKERONE_IDENTIFIER_REFERENCE
        ? this.identifier
        : reference === HACKERONE_TOKEN_REFERENCE
          ? this.token
          : undefined;
    if (source === undefined)
      return Promise.reject(new Error("SYNTHETIC_REFERENCE_BLOCKED"));
    const value = Uint8Array.from(source);
    this.returned.push(value);
    return Promise.resolve(value);
  }

  public storeIdentifier(value: Uint8Array): Promise<void> {
    this.identifier?.fill(0);
    this.identifier = Uint8Array.from(value);
    return Promise.resolve();
  }

  public storeToken(value: Uint8Array): Promise<void> {
    this.token?.fill(0);
    this.token = Uint8Array.from(value);
    return Promise.resolve();
  }

  public deleteIdentifier(): Promise<void> {
    this.identifier?.fill(0);
    this.identifier = undefined;
    return Promise.resolve();
  }

  public deleteToken(): Promise<void> {
    this.token?.fill(0);
    this.token = undefined;
    return Promise.resolve();
  }
}

class SecretEchoingFailureTransport implements HackerOneTransport {
  public readonly credentialReferences: HackerOneCredentialPair[] = [];

  public get(
    _plan: HackerOneTransportPlan,
    credentials: HackerOneCredentialPair,
    signal: AbortSignal,
  ): Promise<HackerOneTransportResponse> {
    if (signal.aborted) return Promise.reject(new Error("SYNTHETIC_ABORTED"));
    this.credentialReferences.push(credentials);
    const decoder = new TextDecoder();
    return Promise.reject(
      new Error(
        `${decoder.decode(credentials.identifier)}:${decoder.decode(credentials.token)}`,
      ),
    );
  }
}

describe("HackerOne static secret and transport boundary", () => {
  it("keeps credential acquisition out of environment variables, argv, storage, and logs", async () => {
    const packageFiles = await typescriptFiles(
      join(ROOT, "packages", "hackerone-readonly"),
    );
    const cliFiles = await typescriptFiles(join(ROOT, "apps", "hackerone-cli"));
    const sources = await Promise.all(
      [...packageFiles, ...cliFiles].map(async (path) => ({
        path,
        source: await readFile(path, "utf8"),
      })),
    );

    for (const { path, source } of sources) {
      const label = relative(ROOT, path);
      expect(source, label).not.toMatch(
        /process\.env\[["'][^"']*(?:TOKEN|IDENTIFIER|PASSWORD|COOKIE|TOTP)[^"']*["']\]/iu,
      );
      expect(source, label).not.toContain("process.argv");
      expect(source, label).not.toContain("localStorage");
      expect(source, label).not.toContain("sessionStorage");
      expect(source, label).not.toMatch(
        /console\.(?:debug|error|info|log|warn)/u,
      );
      expect(source, label).not.toMatch(
        /JSON\.stringify\s*\(\s*(?:credentials|identifier|token)/u,
      );
    }
  });

  it("keeps credential values out of argv and uses only bounded binary dashboard framing", async () => {
    const [adminSource, dashboardSource] = await Promise.all([
      readFile(
        join(ROOT, "apps", "hackerone-credentials-cli", "index.ts"),
        "utf8",
      ),
      readFile(join(ROOT, "packages", "dashboard", "server.ts"), "utf8"),
    ]);

    expect(adminSource).toContain("readHiddenCredential");
    expect(adminSource).toContain("vault.storeBytes(identifier, token)");
    expect(adminSource).toContain("parseCommand(process.argv.slice(2))");
    expect(adminSource).not.toMatch(
      /process\.env\[[^\]]*(?:TOKEN|IDENTIFIER|PASSWORD|COOKIE|TOTP)/iu,
    );
    expect(adminSource).not.toMatch(
      /(?:identifier|token)\s*=\s*process\.argv/iu,
    );
    expect(dashboardSource).toContain("/api/hackerone/credentials/store");
    expect(dashboardSource).toContain("application/octet-stream");
    expect(dashboardSource).toContain("parseHackerOneCredentialFrame");
    expect(dashboardSource).toContain("payload.fill(0)");
    expect(dashboardSource).not.toContain("parseHackerOneCredentials");
    expect(dashboardSource).not.toMatch(
      /JSON\.parse\([^)]*(?:identifier|token)/u,
    );
  });

  it("isolates network primitives to the dedicated transport and keeps asset identifiers out of it", async () => {
    const files = await typescriptFiles(
      join(ROOT, "packages", "hackerone-readonly"),
    );
    for (const path of files) {
      const source = await readFile(path, "utf8");
      const label = relative(ROOT, path);
      if (path.endsWith("transport.ts")) {
        expect(source, label).toContain('from "node:https"');
        expect(source, label).not.toContain("assetIdentifier");
        continue;
      }
      for (const forbidden of [
        "node:http",
        "node:https",
        "node:http2",
        "node:net",
        "node:tls",
        "node:dns",
        "undici",
        "playwright",
        "fetch(",
        "XMLHttpRequest",
        "WebSocket",
      ])
        expect(source, `${label}: ${forbidden}`).not.toContain(forbidden);
    }
  });

  it("keeps audit projection structurally body-, credential-, path-, and asset-free", async () => {
    const [clientSource, typeSource] = await Promise.all([
      readFile(
        join(ROOT, "packages", "hackerone-readonly", "client.ts"),
        "utf8",
      ),
      readFile(
        join(ROOT, "packages", "hackerone-readonly", "types.ts"),
        "utf8",
      ),
    ]);
    const auditMethod = clientSource.slice(
      clientSource.indexOf("  private audit("),
      clientSource.indexOf("  private async exclusive"),
    );
    expect(auditMethod).toContain('actionClass: "HACKERONE_METADATA_READ"');
    for (const forbidden of [
      "credentials",
      "identifier",
      "token",
      "authorization",
      "body",
      "requestTarget",
      "assetIdentifier",
      "path:",
      "url:",
    ])
      expect(auditMethod).not.toContain(forbidden);

    const auditInterface = typeSource.slice(
      typeSource.indexOf("export interface HackerOneRequestAuditEvent"),
      typeSource.indexOf("export interface HackerOneConnectionTestSummary"),
    );
    for (const forbidden of [
      "credential",
      "identifier",
      "token",
      "authorization",
      "body",
      "asset",
      "path",
      "url",
    ])
      expect(auditInterface.toLowerCase()).not.toContain(forbidden);
  });
});

describe("HackerOne dynamic secret leak resistance", () => {
  it("redacts hostile transport errors and zeroes every loaded credential buffer", async () => {
    const identifier = `synthetic-id-${randomBytes(16).toString("hex")}`;
    const token = `synthetic-token-${randomBytes(24).toString("hex")}`;
    const secrets = new LeakProbeSecretStore();
    const credentials = new HackerOneCredentialVault(secrets, secrets);
    await credentials.store(identifier, token);
    const transport = new SecretEchoingFailureTransport();
    const audit: HackerOneRequestAuditEvent[] = [];
    const runtime = resolveHackerOneMetadataReadRuntime({
      version: 1,
      capability: "HACKERONE_METADATA_READ",
      external_integrations_enabled: true,
      enabled: true,
      request_budget: {
        max_requests_total: 1,
        requests_per_minute: 1,
        max_concurrency: 1,
      },
    });
    const presence = await credentials.probe();
    if (presence.tokenBindingDigest === null)
      throw new Error("SYNTHETIC_FINGERPRINT_MISSING");
    const actions = createActivatedHackerOneActionHarness(
      runtime,
      presence.tokenBindingDigest,
    );
    const client = new HackerOneReadOnlyClient({
      runtime,
      credentials,
      transport,
      actionGate: actions.actionGate,
      audit: (event) => {
        audit.push(event);
      },
      minimumIntervalMs: 0,
    });

    const result = await client.connectionTest(new AbortController().signal);
    const observable = JSON.stringify({ presence, result, audit });

    expect(result).toMatchObject({
      result: "unavailable",
      recordCount: 0,
      schemaValid: false,
      redactedStatus: "HACKERONE_CONNECTION_UNAVAILABLE",
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]?.outcome).toBe("INTERNAL_SECURITY_ERROR");
    expect(observable).not.toContain(identifier);
    expect(observable).not.toContain(token);
    expect(observable).not.toContain(`${identifier}:${token}`);
    expect(presence.tokenFingerprint).not.toBe(token);
    expect(transport.credentialReferences).toHaveLength(1);
    for (const pair of transport.credentialReferences) {
      expect(pair.identifier.every((byte) => byte === 0)).toBe(true);
      expect(pair.token.every((byte) => byte === 0)).toBe(true);
    }
    for (const value of secrets.returned)
      expect(value.every((byte) => byte === 0)).toBe(true);
    actions.close();
  });
});

async function typescriptFiles(directory: string): Promise<readonly string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const result: string[] = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...(await typescriptFiles(path)));
    else if (entry.isFile() && extname(entry.name) === ".ts") result.push(path);
  }
  return result.sort();
}
