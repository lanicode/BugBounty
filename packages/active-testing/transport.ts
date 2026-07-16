import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { request } from "node:https";
import { BlockList } from "node:net";
import { performance } from "node:perf_hooks";
import type { IncomingHttpHeaders, IncomingMessage } from "node:http";
import { TLSSocket } from "node:tls";
import { types } from "node:util";
import {
  isTrustedControlPlaneStore,
  type ControlPlaneStore,
} from "../control-plane/store.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import {
  captureAuthorizedActiveTestTransportPlan,
  type AuthorizedActiveTestTransportPlan,
  type StoreBoundActiveTestAuthorization,
} from "./gate.js";
import {
  authorizeActiveTestResolvedEgress,
  canonicalizeActiveTestDnsHost,
  type ActiveTestResolvedEgressAuthorization,
} from "./resolved-egress.js";
import type {
  ActiveTestRedactedContentType,
  ActiveTestRedactedResponseMetadata,
  ActiveTestResponseFacts,
  ActiveTestTlsCipherClassification,
  ActiveTestTlsProtocol,
  ActiveTestTransportKind,
  UnattestedActiveTestResponseMetadata,
} from "./types.js";
import {
  activeTestBoundedDurationMs,
  activeTestRemainingTimeoutMs,
  awaitActiveTestTransportOperation,
} from "./transport-deadline.js";

const PROBE_ORIGIN = "https://bugbounty-copilot.invalid" as const;
const USER_AGENT = "BugBounty-Copilot/active-test-v1" as const;
const MAX_HEADER_BYTES = 16_384;
const DIGEST = /^[a-f0-9]{64}$/u;
const trustedProductionTransports = new WeakSet();
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

export interface ActiveTestTransportEvidence {
  readonly version: 1;
  readonly receiptDigest: string;
}

export interface ActiveTestTransport {
  run(
    plan: AuthorizedActiveTestTransportPlan,
  ): Promise<ActiveTestTransportEvidence>;
}

export class ProductionActiveTestTransport implements ActiveTestTransport {
  public constructor(private readonly controlPlane: ControlPlaneStore) {
    if (!isTrustedControlPlaneStore(controlPlane))
      throw new SecurityError("ACTIVE_TEST_TRANSPORT_STORE_UNTRUSTED");
    trustedProductionTransports.add(this);
    Object.freeze(this);
  }

  public async run(
    value: AuthorizedActiveTestTransportPlan,
  ): Promise<ActiveTestTransportEvidence> {
    const plan = captureAuthorizedActiveTestTransportPlan(value);
    const startedAt = performance.now();
    this.assertKillSwitchClear();
    const resolved = await resolveAndAuthorize(
      plan.target.host,
      plan.timeoutMs,
      () => {
        this.assertKillSwitchClear();
      },
    );
    this.assertKillSwitchClear();
    const remainingMs = activeTestRemainingTimeoutMs(
      plan.timeoutMs,
      performance.now() - startedAt,
    );
    if (remainingMs < 1) throw new SecurityError("ACTIVE_TEST_REQUEST_TIMEOUT");
    const metadata = await runPinnedRequest(
      plan,
      resolved,
      () => {
        this.assertKillSwitchClear();
      },
      startedAt,
      remainingMs,
    );
    return issueActiveTestTransportEvidence(
      this,
      plan,
      resolved.resolutionDigest,
      metadata,
    );
  }

  private assertKillSwitchClear(): void {
    if (this.controlPlane.isKillSwitchActive())
      throw new SecurityError("ACTIVE_TEST_KILL_SWITCH");
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
        ProductionActiveTestTransport.prototype &&
      trustedProductionTransports.has(value)
    );
  } catch {
    return false;
  }
}

/**
 * Consumes one privately issued transport receipt. Only the concrete
 * production class above can reach the module-private issuer, so a deep importer cannot
 * register a fake transport or mint successful response evidence.
 */
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

function issueActiveTestTransportEvidence(
  issuer: ProductionActiveTestTransport,
  binding: AuthorizedActiveTestTransportPlan,
  resolutionDigest: string,
  unattestedMetadata: UnattestedActiveTestResponseMetadata,
): ActiveTestTransportEvidence {
  const transportKind = transportKindForPrivateIssuer(issuer);
  if (!DIGEST.test(resolutionDigest))
    throw new SecurityError("ACTIVE_TEST_TRANSPORT_EVIDENCE_INVALID");
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

function transportKindForPrivateIssuer(
  issuer: ProductionActiveTestTransport,
): ActiveTestTransportKind {
  if (
    Reflect.getPrototypeOf(issuer) ===
      ProductionActiveTestTransport.prototype &&
    trustedProductionTransports.has(issuer)
  )
    return "production_https";
  throw new SecurityError("ACTIVE_TEST_TRANSPORT_EVIDENCE_INVALID");
}

async function resolveAndAuthorize(
  host: string,
  timeoutMs: number,
  assertKillSwitchClear: () => void,
): Promise<ActiveTestResolvedEgressAuthorization> {
  const canonicalHost = canonicalizeActiveTestDnsHost(host);
  const absoluteLookupHost = `${canonicalHost}.`;
  const answers = await awaitActiveTestTransportOperation(
    () => lookup(absoluteLookupHost, { all: true, verbatim: true }),
    timeoutMs,
    assertKillSwitchClear,
    "ACTIVE_TEST_DNS_RESOLUTION_FAILED",
  );
  try {
    return authorizeActiveTestResolvedEgress({
      host: canonicalHost,
      port: 443,
      addresses: answers.map((answer) => ({
        address: answer.address,
        family: answer.family,
      })),
    });
  } catch (error) {
    throw new SecurityError(
      errorCode(error, "ACTIVE_TEST_DNS_RESOLUTION_FAILED"),
    );
  }
}

function runPinnedRequest(
  plan: AuthorizedActiveTestTransportPlan,
  resolved: ActiveTestResolvedEgressAuthorization,
  assertKillSwitchClear: () => void,
  startedAt: number,
  timeoutMs: number,
): Promise<UnattestedActiveTestResponseMetadata> {
  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let requestEnded = false;
    let tlsProtocol: ActiveTestTlsProtocol | undefined;
    let tlsCipher: ActiveTestTlsCipherClassification | undefined;
    let response: IncomingMessage | undefined;
    const finishError = (code: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      clearInterval(killSwitchPoll);
      response?.destroy();
      client.destroy();
      rejectPromise(new SecurityError(code));
    };
    const finishSuccess = (
      result: UnattestedActiveTestResponseMetadata,
    ): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      clearInterval(killSwitchPoll);
      client.destroy();
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
    const client = request({
      protocol: "https:",
      hostname: plan.target.host,
      port: 443,
      path: plan.target.path,
      method: plan.request.method,
      headers: fixedHeaders,
      agent: false,
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
      maxVersion: "TLSv1.3",
      maxHeaderSize: MAX_HEADER_BYTES,
      servername: plan.target.host,
      // Node 24 requests the array lookup contract (`all: true`) while older
      // runtimes may request the scalar contract. Both branches return only
      // the one address already selected by the trusted egress authorization;
      // no caller-controlled fallback address or retry is introduced.
      lookup: (_hostname, options, callback) => {
        if (options.all === true) {
          callback(null, [
            {
              address: resolved.selectedAddress,
              family: resolved.family,
            },
          ]);
          return;
        }
        callback(null, resolved.selectedAddress, resolved.family);
      },
    });
    const deadline = setTimeout(() => {
      finishError("ACTIVE_TEST_REQUEST_TIMEOUT");
    }, timeoutMs);
    deadline.unref();
    const killSwitchPoll = setInterval(() => {
      try {
        assertKillSwitchClear();
      } catch {
        finishError("ACTIVE_TEST_KILL_SWITCH");
      }
    }, 100);
    killSwitchPoll.unref();

    client.once("socket", (plainSocket) => {
      if (!(plainSocket instanceof TLSSocket)) {
        finishError("ACTIVE_TEST_TLS_VALIDATION_FAILED");
        return;
      }
      const socket = plainSocket;
      socket.once("secureConnect", () => {
        try {
          assertKillSwitchClear();
          assertPinnedSocket(socket, resolved);
          tlsProtocol = classifyTlsProtocol(socket.getProtocol());
          tlsCipher = classifyCipher(socket.getCipher().name);
          requestEnded = true;
          client.end();
        } catch (error) {
          finishError(errorCode(error, "ACTIVE_TEST_TLS_VALIDATION_FAILED"));
        }
      });
    });
    client.once("upgrade", () => {
      finishError("ACTIVE_TEST_UPGRADE_BLOCKED");
    });
    client.once("error", () => {
      finishError(
        requestEnded
          ? "ACTIVE_TEST_REQUEST_FAILED"
          : "ACTIVE_TEST_TLS_VALIDATION_FAILED",
      );
    });
    client.once("response", (incoming) => {
      response = incoming;
      try {
        assertKillSwitchClear();
        if (tlsProtocol === undefined || tlsCipher === undefined)
          throw new SecurityError("ACTIVE_TEST_TLS_VALIDATION_FAILED");
        consumeResponse(
          plan,
          incoming,
          startedAt,
          tlsProtocol,
          tlsCipher,
          assertKillSwitchClear,
          finishSuccess,
          finishError,
        );
      } catch (error) {
        finishError(errorCode(error, "ACTIVE_TEST_RESPONSE_BLOCKED"));
      }
    });
  });
}

function consumeResponse(
  plan: AuthorizedActiveTestTransportPlan,
  response: IncomingMessage,
  startedAt: number,
  tlsProtocol: ActiveTestTlsProtocol,
  tlsCipher: ActiveTestTlsCipherClassification,
  assertKillSwitchClear: () => void,
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
      assertKillSwitchClear();
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
      assertKillSwitchClear();
      if (plan.testClass === "security_txt") {
        const availability =
          facts.kind === "security_txt" ? facts.availability : "missing";
        if (availability === "available" && byteCount === 0)
          throw new SecurityError("ACTIVE_TEST_SECURITY_TXT_EMPTY");
      }
      const durationMs = activeTestBoundedDurationMs(
        plan.timeoutMs,
        performance.now() - startedAt,
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
            protocol: tlsProtocol,
            cipher: tlsCipher,
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

function assertPinnedSocket(
  socket: TLSSocket,
  resolved: ActiveTestResolvedEgressAuthorization,
): void {
  if (!socket.authorized)
    throw new SecurityError("ACTIVE_TEST_TLS_UNAUTHORIZED");
  const remoteAddress = socket.remoteAddress;
  if (remoteAddress === undefined)
    throw new SecurityError("ACTIVE_TEST_REMOTE_ADDRESS_MISMATCH");
  const family = resolved.family === 4 ? "ipv4" : "ipv6";
  const list = new BlockList();
  list.addAddress(resolved.selectedAddress, family);
  if (!list.check(remoteAddress, family))
    throw new SecurityError("ACTIVE_TEST_REMOTE_ADDRESS_MISMATCH");
  if (socket.alpnProtocol !== false && socket.alpnProtocol !== "http/1.1")
    throw new SecurityError("ACTIVE_TEST_ALPN_BLOCKED");
}

function classifyTlsProtocol(value: string | null): ActiveTestTlsProtocol {
  if (value === "TLSv1.2" || value === "TLSv1.3") return value;
  throw new SecurityError("ACTIVE_TEST_TLS_PROTOCOL_BLOCKED");
}

function classifyCipher(value: string): ActiveTestTlsCipherClassification {
  return /(?:AES.*GCM|CHACHA20|TLS_AES|TLS_CHACHA)/iu.test(value)
    ? "modern"
    : "other_redacted";
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
