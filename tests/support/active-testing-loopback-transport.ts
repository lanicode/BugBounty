import { createHash } from "node:crypto";
import {
  request,
  type ClientRequest,
  type IncomingHttpHeaders,
  type IncomingMessage,
} from "node:http";
import { types } from "node:util";
import { canonicalJson, sha256 } from "../../packages/shared/canonical.js";
import { SecurityError } from "../../packages/shared/errors.js";
import type {
  AuthorizedActiveTestTransportPlan,
  StoreBoundActiveTestAuthorization,
} from "../../packages/active-testing/gate.js";
import type {
  ActiveTestRedactedContentType,
  ActiveTestRedactedResponseMetadata,
  ActiveTestResponseFacts,
  ActiveTestTransportKind,
  UnattestedActiveTestResponseMetadata,
} from "../../packages/active-testing/types.js";
import type {
  ActiveTestTransport,
  ActiveTestTransportEvidence,
} from "../../packages/active-testing/transport.js";

const PROBE_ORIGIN = "https://bugbounty-copilot.invalid" as const;
const USER_AGENT = "BugBounty-Copilot/active-test-loopback-mock-v1" as const;
const MAX_HEADER_BYTES = 16_384;
const DIGEST = /^[a-f0-9]{64}$/u;
const trustedLoopbackTransports = new WeakSet();
const trustedEvidence = new WeakMap<
  object,
  Readonly<{
    authorizationId: string;
    proposalDigest: string;
    planId: string;
    planDigest: string;
    transportKind: ActiveTestTransportKind;
    resolutionDigest: string;
    metadata: ActiveTestRedactedResponseMetadata;
  }>
>();

export interface LoopbackActiveTestMockTransportOptions {
  /** Canonical HTTP origin with an explicit port and no trailing slash. */
  readonly origin: string;
}

/**
 * Runtime-shape placeholder required by the production barrel's static
 * re-export while this module replaces the production transport in Vitest.
 * It can never create a transport and is never trusted by this harness.
 */
export function ProductionActiveTestTransport(): never {
  throw new SecurityError("ACTIVE_TEST_PRODUCTION_TRANSPORT_NOT_AVAILABLE");
}

/**
 * Test-only loopback transport. This source lives below tests/ and is excluded
 * from tsconfig.build.json. Its evidence registry replaces the complete
 * production transport module only inside the two explicit loopback suites.
 */
export class LoopbackActiveTestMockTransport implements ActiveTestTransport {
  readonly #host: "127.0.0.1" | "::1";
  readonly #family: 4 | 6;
  readonly #port: number;

  public constructor(value: LoopbackActiveTestMockTransportOptions) {
    assertVitestRuntime();
    const endpoint = captureLoopbackActiveTestMockEndpoint(value);
    this.#host = endpoint.host;
    this.#family = endpoint.family;
    this.#port = endpoint.port;
    trustedLoopbackTransports.add(this);
    Object.freeze(this);
  }

  public async run(
    value: AuthorizedActiveTestTransportPlan,
  ): Promise<ActiveTestTransportEvidence> {
    assertVitestRuntime();
    // Lazy import avoids a module-initialization cycle: the gate imports the
    // mocked evidence consumer while Vitest initializes this test module.
    const { captureAuthorizedActiveTestTransportPlan } =
      await import("../../packages/active-testing/gate.js");
    const plan = captureAuthorizedActiveTestTransportPlan(value);
    const metadata = await runLoopbackActiveTestMockRequest(
      plan,
      this.#host,
      this.#family,
      this.#port,
    );
    return issueLoopbackEvidence(
      this,
      plan,
      sha256(
        canonicalJson({
          version: 1,
          kind: "loopback_test",
          host: this.#host,
          family: this.#family,
          port: this.#port,
        }),
      ),
      metadata,
    );
  }
}

export function isTrustedActiveTestTransport(
  value: unknown,
): value is ActiveTestTransport {
  if (value === null || typeof value !== "object") return false;
  try {
    return (
      !types.isProxy(value) &&
      Reflect.getPrototypeOf(value) ===
        LoopbackActiveTestMockTransport.prototype &&
      trustedLoopbackTransports.has(value)
    );
  } catch {
    return false;
  }
}

export function captureActiveTestTransportEvidence(
  value: unknown,
  authorization: StoreBoundActiveTestAuthorization,
): Readonly<{
  metadata: ActiveTestRedactedResponseMetadata;
  transportKind: ActiveTestTransportKind;
  resolutionDigest: string;
}> {
  if (value === null || typeof value !== "object")
    throw new SecurityError("ACTIVE_TEST_TRANSPORT_EVIDENCE_REQUIRED");
  try {
    if (
      types.isProxy(value) ||
      Reflect.getPrototypeOf(value) !== Object.prototype ||
      !Object.isFrozen(value)
    )
      throw new Error("invalid");
    const record = trustedEvidence.get(value);
    if (record === undefined) throw new Error("invalid");
    trustedEvidence.delete(value);
    if (
      record.authorizationId !== authorization.authorizationId ||
      record.proposalDigest !== authorization.proposalDigest ||
      record.planId !== authorization.planId ||
      record.planDigest !== authorization.planDigest
    )
      throw new Error("invalid");
    return Object.freeze({
      metadata: record.metadata,
      transportKind: record.transportKind,
      resolutionDigest: record.resolutionDigest,
    });
  } catch {
    throw new SecurityError("ACTIVE_TEST_TRANSPORT_EVIDENCE_REQUIRED");
  }
}

function issueLoopbackEvidence(
  issuer: LoopbackActiveTestMockTransport,
  binding: AuthorizedActiveTestTransportPlan,
  resolutionDigest: string,
  unattestedMetadata: UnattestedActiveTestResponseMetadata,
): ActiveTestTransportEvidence {
  if (
    Reflect.getPrototypeOf(issuer) !==
      LoopbackActiveTestMockTransport.prototype ||
    !trustedLoopbackTransports.has(issuer) ||
    !DIGEST.test(resolutionDigest)
  )
    throw new SecurityError("ACTIVE_TEST_TRANSPORT_EVIDENCE_INVALID");
  const transportKind = "loopback_test" as const;
  const metadata = Object.freeze({
    ...unattestedMetadata,
    transport: Object.freeze({ kind: transportKind, resolutionDigest }),
  });
  const record = Object.freeze({
    authorizationId: binding.authorizationId,
    proposalDigest: binding.proposalDigest,
    planId: binding.planId,
    planDigest: binding.planDigest,
    transportKind,
    resolutionDigest,
    metadata,
  });
  const evidence = Object.freeze({
    version: 1 as const,
    receiptDigest: sha256(
      canonicalJson({
        version: 1,
        authorizationId: record.authorizationId,
        proposalDigest: record.proposalDigest,
        planId: record.planId,
        planDigest: record.planDigest,
        transportKind,
        resolutionDigest,
        metadataDigest: sha256(canonicalJson(metadata)),
      }),
    ),
  });
  trustedEvidence.set(evidence, record);
  return evidence;
}

function assertVitestRuntime(): void {
  if (process.env["VITEST"] !== "true")
    throw new SecurityError("ACTIVE_TEST_TEST_TRANSPORT_ENV_REQUIRED");
}

function captureLoopbackActiveTestMockEndpoint(value: unknown): Readonly<{
  host: "127.0.0.1" | "::1";
  family: 4 | 6;
  port: number;
}> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== 1
  )
    throw new SecurityError("ACTIVE_TEST_LOOPBACK_ENDPOINT_INVALID");
  const descriptor = Object.getOwnPropertyDescriptor(value, "origin");
  if (
    descriptor === undefined ||
    !("value" in descriptor) ||
    !descriptor.enumerable ||
    typeof descriptor.value !== "string"
  )
    throw new SecurityError("ACTIVE_TEST_LOOPBACK_ENDPOINT_INVALID");
  let parsed: URL;
  try {
    parsed = new URL(descriptor.value);
  } catch {
    throw new SecurityError("ACTIVE_TEST_LOOPBACK_ENDPOINT_INVALID");
  }
  const host =
    parsed.hostname === "127.0.0.1"
      ? ("127.0.0.1" as const)
      : parsed.hostname === "[::1]"
        ? ("::1" as const)
        : null;
  const port = Number(parsed.port);
  if (
    parsed.protocol !== "http:" ||
    host === null ||
    parsed.port === "" ||
    !Number.isSafeInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    descriptor.value !== parsed.origin
  )
    throw new SecurityError("ACTIVE_TEST_LOOPBACK_ENDPOINT_INVALID");
  return Object.freeze({
    host,
    family: host === "127.0.0.1" ? (4 as const) : (6 as const),
    port,
  });
}

function runLoopbackActiveTestMockRequest(
  plan: AuthorizedActiveTestTransportPlan,
  host: "127.0.0.1" | "::1",
  family: 4 | 6,
  port: number,
): Promise<UnattestedActiveTestResponseMetadata> {
  return new Promise((resolvePromise, rejectPromise) => {
    const startedAt = Date.now();
    let settled = false;
    let client: ClientRequest | undefined;
    let response: IncomingMessage | undefined;
    const finishError = (code: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      response?.destroy();
      client?.destroy();
      rejectPromise(new SecurityError(code));
    };
    const finishSuccess = (
      result: UnattestedActiveTestResponseMetadata,
    ): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      client?.destroy();
      resolvePromise(result);
    };
    const fixedHeaders: Readonly<Record<string, string>> = Object.freeze({
      Accept:
        plan.testClass === "security_txt"
          ? "text/plain, application/security.txt"
          : "*/*",
      "Accept-Encoding": "identity",
      Connection: "close",
      "User-Agent": USER_AGENT,
      ...(plan.testClass === "cors_preflight"
        ? {
            Origin: PROBE_ORIGIN,
            "Access-Control-Request-Method": "GET",
          }
        : {}),
    });
    const deadline = setTimeout(() => {
      finishError("ACTIVE_TEST_REQUEST_TIMEOUT");
    }, plan.timeoutMs);
    deadline.unref();
    try {
      client = request({
        protocol: "http:",
        hostname: host,
        family,
        port,
        path: plan.target.path,
        method: plan.request.method,
        headers: fixedHeaders,
        agent: false,
        maxHeaderSize: MAX_HEADER_BYTES,
      });
    } catch {
      finishError("ACTIVE_TEST_LOOPBACK_REQUEST_FAILED");
      return;
    }
    client.once("socket", (socket) => {
      socket.once("connect", () => {
        if (socket.remoteAddress !== host)
          finishError("ACTIVE_TEST_LOOPBACK_REMOTE_ADDRESS_MISMATCH");
      });
    });
    client.once("upgrade", () => {
      finishError("ACTIVE_TEST_UPGRADE_BLOCKED");
    });
    client.once("error", () => {
      finishError("ACTIVE_TEST_LOOPBACK_REQUEST_FAILED");
    });
    client.once("response", (incoming) => {
      response = incoming;
      try {
        consumeLoopbackResponse(
          plan,
          incoming,
          startedAt,
          finishSuccess,
          finishError,
        );
      } catch (error) {
        finishError(errorCode(error, "ACTIVE_TEST_RESPONSE_BLOCKED"));
      }
    });
    client.end();
  });
}

function consumeLoopbackResponse(
  plan: AuthorizedActiveTestTransportPlan,
  response: IncomingMessage,
  startedAt: number,
  finishSuccess: (result: UnattestedActiveTestResponseMetadata) => void,
  finishError: (code: string) => void,
): void {
  const statusCode = response.statusCode;
  if (statusCode === undefined || statusCode < 200 || statusCode > 599)
    throw new SecurityError("ACTIVE_TEST_STATUS_BLOCKED");
  if (statusCode >= 300 && statusCode <= 399)
    throw new SecurityError("ACTIVE_TEST_REDIRECT_BLOCKED");
  if (headerPresent(response.headers, "location"))
    throw new SecurityError("ACTIVE_TEST_REDIRECT_BLOCKED");
  const contentEncoding = singleHeader(response.headers, "content-encoding");
  if (
    contentEncoding !== null &&
    contentEncoding.trim().toLowerCase() !== "identity"
  )
    throw new SecurityError("ACTIVE_TEST_CONTENT_ENCODING_BLOCKED");
  const contentType = classifyContentType(
    singleHeader(response.headers, "content-type"),
  );
  const facts = classifyFacts(plan, response.headers, statusCode, contentType);
  const digest = createHash("sha256");
  let byteCount = 0;
  response.on("data", (chunk: unknown) => {
    try {
      if (!(typeof chunk === "string" || chunk instanceof Uint8Array))
        throw new SecurityError("ACTIVE_TEST_RESPONSE_BLOCKED");
      const bytes = Buffer.byteLength(chunk);
      if (plan.request.method === "HEAD" && bytes > 0)
        throw new SecurityError("ACTIVE_TEST_HEAD_BODY_BLOCKED");
      byteCount += bytes;
      if (byteCount > plan.maxResponseBytes)
        throw new SecurityError("ACTIVE_TEST_RESPONSE_TOO_LARGE");
      digest.update(chunk);
    } catch (error) {
      finishError(errorCode(error, "ACTIVE_TEST_RESPONSE_BLOCKED"));
    }
  });
  response.once("aborted", () => {
    finishError("ACTIVE_TEST_RESPONSE_ABORTED");
  });
  response.once("error", () => {
    finishError("ACTIVE_TEST_RESPONSE_FAILED");
  });
  response.once("end", () => {
    try {
      if (plan.testClass === "security_txt") {
        const availability =
          facts.kind === "security_txt" ? facts.availability : "missing";
        if (availability === "available" && byteCount === 0)
          throw new SecurityError("ACTIVE_TEST_SECURITY_TXT_EMPTY");
      }
      const durationMs = Math.max(
        0,
        Math.min(plan.timeoutMs, Date.now() - startedAt),
      );
      finishSuccess(
        Object.freeze({
          version: 1 as const,
          planId: plan.planId,
          planDigest: plan.planDigest,
          testClass: plan.testClass,
          statusCode,
          durationMs,
          responseBytesObserved: byteCount,
          contentType,
          redirectLocationPresent: false as const,
          tls: Object.freeze({
            authorized: true as const,
            protocol: "TLSv1.3" as const,
            cipher: "modern" as const,
          }),
          facts,
          responseDigest: byteCount === 0 ? null : digest.digest("hex"),
          redaction: Object.freeze({
            status: "complete" as const,
            rawBodyStored: false as const,
            rawHeadersStored: false as const,
            cookiesStored: false as const,
          }),
          completedAt: new Date().toISOString(),
        }),
      );
    } catch (error) {
      finishError(errorCode(error, "ACTIVE_TEST_RESPONSE_BLOCKED"));
    }
  });
}

function classifyContentType(
  value: string | null,
): ActiveTestRedactedContentType {
  if (value === null) return null;
  const normalized = value.split(";", 1)[0]?.trim().toLowerCase();
  if (
    normalized === "application/json" ||
    normalized === "application/security.txt" ||
    normalized === "text/html" ||
    normalized === "text/plain"
  )
    return normalized;
  throw new SecurityError("ACTIVE_TEST_CONTENT_TYPE_BLOCKED");
}

function classifyFacts(
  plan: AuthorizedActiveTestTransportPlan,
  headers: IncomingHttpHeaders,
  statusCode: number,
  contentType: ActiveTestRedactedContentType,
): ActiveTestResponseFacts {
  if (plan.testClass === "cors_preflight") {
    const origin = singleHeader(headers, "access-control-allow-origin");
    const normalized = origin?.trim() ?? null;
    return Object.freeze({
      kind: "cors_preflight" as const,
      allowOrigin:
        normalized === null
          ? ("absent" as const)
          : normalized === PROBE_ORIGIN
            ? ("probe_origin" as const)
            : normalized === "*"
              ? ("wildcard" as const)
              : ("other_redacted" as const),
      allowCredentials:
        singleHeader(headers, "access-control-allow-credentials")
          ?.trim()
          .toLowerCase() === "true",
    });
  }
  if (plan.testClass === "http_headers") {
    return Object.freeze({
      kind: "http_headers" as const,
      contentSecurityPolicyPresent: headerPresent(
        headers,
        "content-security-policy",
      ),
      strictTransportSecurityPresent: headerPresent(
        headers,
        "strict-transport-security",
      ),
      xContentTypeOptionsNosniff:
        singleHeader(headers, "x-content-type-options")
          ?.trim()
          .toLowerCase() === "nosniff",
      insecureCookieFlagsObserved: hasInsecureCookieFlags(
        headers["set-cookie"],
      ),
    });
  }
  const available =
    statusCode >= 200 &&
    statusCode <= 299 &&
    (contentType === "text/plain" ||
      contentType === "application/security.txt");
  if (!available && statusCode < 400)
    throw new SecurityError("ACTIVE_TEST_SECURITY_TXT_RESPONSE_BLOCKED");
  return Object.freeze({
    kind: "security_txt" as const,
    availability: available ? ("available" as const) : ("missing" as const),
  });
}

function hasInsecureCookieFlags(value: string[] | undefined): boolean {
  if (value === undefined) return false;
  return value.some((cookie) => {
    const normalized = cookie.toLowerCase();
    return (
      !/(?:^|;)\s*secure(?:;|$)/u.test(normalized) ||
      !/(?:^|;)\s*httponly(?:;|$)/u.test(normalized) ||
      !/(?:^|;)\s*samesite=(?:lax|strict|none)(?:;|$)/u.test(normalized)
    );
  });
}

function headerPresent(headers: IncomingHttpHeaders, name: string): boolean {
  const value = headers[name];
  return value !== undefined;
}

function singleHeader(
  headers: IncomingHttpHeaders,
  name: string,
): string | null {
  const value = headers[name];
  if (value === undefined) return null;
  if (Array.isArray(value))
    throw new SecurityError("ACTIVE_TEST_DUPLICATE_HEADER_BLOCKED");
  return value;
}

function errorCode(error: unknown, fallback: string): string {
  return error instanceof SecurityError ? error.code : fallback;
}
