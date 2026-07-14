import { request, type RequestOptions } from "node:https";
import { decideEgress } from "../egress-guard/index.js";
import {
  captureAuthorizedHackerOneMetadataTransportPlan,
  type AuthorizedHackerOneMetadataTransportPlan,
} from "../external-actions/hackerone-metadata.js";
import { SecurityError } from "../shared/errors.js";
import {
  consumeHackerOneCredentialLease,
  type HackerOneCredentialPair,
} from "./credential-vault.js";
import {
  HACKERONE_API_HOST,
  HACKERONE_API_ORIGIN,
  HACKERONE_API_PORT,
  type HackerOneRequestAuditEvent,
} from "./types.js";

export type HackerOneEndpointClass =
  "program" | "programs" | "scope_exclusions" | "structured_scopes";

export interface HackerOneTransportPlan extends AuthorizedHackerOneMetadataTransportPlan {
  readonly tokenBindingDigest: string;
}

interface TrustedCredentialBoundPlan {
  readonly plan: HackerOneTransportPlan;
}

const FULL_DIGEST = /^[0-9a-f]{64}$/u;
const trustedCredentialBoundPlans = new WeakMap<
  object,
  TrustedCredentialBoundPlan
>();

export interface HackerOneTransportTarget {
  readonly endpointClass: HackerOneEndpointClass;
  readonly requestTarget: string;
}

export interface HackerOneTransportResponse {
  readonly statusCode: number;
  readonly body: Uint8Array;
  readonly contentType: string | null;
  readonly contentTypeCount: number;
  readonly contentEncoding: string | null;
  readonly locationPresent: boolean;
  readonly durationMs: number;
  readonly responseBytes: number;
}

export interface HackerOneTransport {
  get(
    plan: HackerOneTransportPlan,
    credentials: HackerOneCredentialPair,
    signal: AbortSignal,
  ): Promise<HackerOneTransportResponse>;
}

export type HackerOneAuditSink = (event: HackerOneRequestAuditEvent) => void;

export function bindAuthorizedHackerOneTransportPlan(
  authorizationPlan: AuthorizedHackerOneMetadataTransportPlan,
  tokenBindingDigest: string,
): HackerOneTransportPlan {
  try {
    if (!FULL_DIGEST.test(tokenBindingDigest)) throw new Error("invalid");
    const captured =
      captureAuthorizedHackerOneMetadataTransportPlan(authorizationPlan);
    if (captured.credentialFingerprint !== tokenBindingDigest)
      throw new Error("credential-mismatch");
    const plan = Object.freeze({
      authorizationId: captured.authorizationId,
      proposalDigest: captured.proposalDigest,
      credentialFingerprint: captured.credentialFingerprint,
      endpointClass: captured.endpointClass,
      requestTarget: captured.requestTarget,
      tokenBindingDigest,
    });
    trustedCredentialBoundPlans.set(plan, { plan });
    return plan;
  } catch {
    throw new SecurityError("HACKERONE_CREDENTIAL_PLAN_BINDING_INVALID");
  }
}

const MAX_RESPONSE_BYTES = 1_048_576;
const REQUEST_TIMEOUT_MS = 10_000;
const HANDLE = "[A-Za-z0-9_-]{1,128}";
const PAGE_QUERY =
  "\\?page\\[number\\]=[1-9][0-9]{0,5}&page\\[size\\]=(?:[1-9]|[1-9][0-9]|100)";
const ALLOWED_TARGET = new RegExp(
  `^/v1/hackers/programs(?:/${HANDLE}(?:/(?:structured_scopes|scope_exclusions))?)?(?:${PAGE_QUERY})?$`,
  "u",
);

const EGRESS_POLICY = Object.freeze({
  config: Object.freeze({
    version: 2 as const,
    program: Object.freeze({
      platform: "hackerone_metadata",
      handle: "fixed-metadata-origin",
      display_name: "HackerOne metadata read-only",
      policy_source: "internal-fixed-policy",
      policy_hash_sha256: "0".repeat(64),
      policy_accepted_at: "1970-01-01T00:00:00.000Z",
      policy_accepted_by: "system-fixed-policy",
    }),
    network: Object.freeze({
      targets: Object.freeze([]),
      supporting_hosts: Object.freeze([
        Object.freeze({
          scheme: "https" as const,
          host: HACKERONE_API_HOST,
          ports: Object.freeze([HACKERONE_API_PORT]),
          allowed_methods: Object.freeze(["GET" as const]),
          capture: "metadata_only" as const,
        }),
      ]),
      blocked_hosts: Object.freeze([]),
      deny_by_default: true as const,
      allow_plain_http: false,
      follow_redirects: false as const,
      block_service_workers_during_capture: true as const,
    }),
    capture: Object.freeze({
      persist_unredacted_traffic: false as const,
      persist_response_bodies: "selective" as const,
      allowed_body_content_types: Object.freeze([
        "application/vnd.api+json",
        "application/json",
      ]),
      max_body_bytes: MAX_RESPONSE_BYTES,
      binary_handling: "hash_only" as const,
      websocket_capture: "disabled",
      stable_pseudonyms: true as const,
      local_hmac_key_ref: "keychain://bugbounty-copilot/metadata-audit",
      quarantine_unknown_identity_data: true as const,
    }),
    accounts: Object.freeze([]),
    budgets: Object.freeze({
      global_requests_per_minute: 30,
      max_concurrency: 1 as const,
      max_requests_per_candidate: 50,
      max_state_changes_per_candidate: 0,
      stop_after_first_positive_signal: true as const,
      cool_down_seconds_after_error: 1,
      stop_statuses: Object.freeze([401, 403, 429]),
    }),
    forbidden: Object.freeze([
      "target_requests",
      "report_submission",
      "write_methods",
    ]),
    policy_drift: Object.freeze({
      block_campaign_when_policy_hash_changes: true as const,
      require_new_acceptance: true as const,
    }),
  }),
});

export class HackerOneHttpsTransport implements HackerOneTransport {
  public constructor() {
    Object.freeze(this);
  }

  public get(
    plan: HackerOneTransportPlan,
    credentials: HackerOneCredentialPair,
    signal: AbortSignal,
  ): Promise<HackerOneTransportResponse> {
    let captured: HackerOneTransportPlan;
    try {
      captured = captureCredentialBoundTransportPlan(plan);
      assertTransportPlan(captured);
    } catch (error) {
      return Promise.reject(
        error instanceof Error
          ? error
          : new SecurityError("HACKERONE_REQUEST_PLAN_INVALID"),
      );
    }
    try {
      consumeHackerOneCredentialLease(credentials, captured.tokenBindingDigest);
      if (signal.aborted) throw new SecurityError("HACKERONE_REQUEST_ABORTED");
      const absoluteUrl = `${HACKERONE_API_ORIGIN}${captured.requestTarget}`;
      const egress = decideEgress(EGRESS_POLICY, {
        url: absoluteUrl,
        method: "GET",
        captureMode: "metadata_only",
        resourceKind: "fetch",
        isRedirect: false,
      });
      if (!egress.allow || egress.reason !== "ALLOW_SUPPORTING_HOST")
        throw new SecurityError("HACKERONE_EGRESS_BLOCKED");
      return performGet(captured, credentials, signal);
    } catch (error) {
      credentials.identifier.fill(0);
      credentials.token.fill(0);
      return Promise.reject(
        error instanceof Error
          ? error
          : new SecurityError("HACKERONE_CREDENTIAL_LEASE_INVALID"),
      );
    }
  }
}

function captureCredentialBoundTransportPlan(
  value: HackerOneTransportPlan,
): HackerOneTransportPlan {
  try {
    const binding = trustedCredentialBoundPlans.get(value);
    trustedCredentialBoundPlans.delete(value);
    if (binding?.plan !== value) throw new Error("invalid");
    if (
      !FULL_DIGEST.test(binding.plan.tokenBindingDigest) ||
      binding.plan.credentialFingerprint !== binding.plan.tokenBindingDigest
    )
      throw new Error("invalid");
    return Object.freeze({ ...binding.plan });
  } catch {
    throw new SecurityError("HACKERONE_ACTION_AUTHORIZATION_REQUIRED");
  }
}

function performGet(
  plan: HackerOneTransportPlan,
  credentials: HackerOneCredentialPair,
  signal: AbortSignal,
): Promise<HackerOneTransportResponse> {
  return new Promise((resolve, reject) => {
    const startedAt = performance.now();
    let settled = false;
    let authorization: string;
    try {
      authorization = basicAuthorization(credentials);
    } finally {
      credentials.identifier.fill(0);
      credentials.token.fill(0);
    }
    const options: RequestOptions = {
      protocol: "https:",
      hostname: HACKERONE_API_HOST,
      servername: HACKERONE_API_HOST,
      port: HACKERONE_API_PORT,
      method: "GET",
      path: plan.requestTarget,
      rejectUnauthorized: true,
      agent: false,
      timeout: REQUEST_TIMEOUT_MS,
      headers: Object.freeze({
        accept: "application/vnd.api+json, application/json;q=0.9",
        "accept-encoding": "identity",
        authorization,
        "user-agent": "BugBountyCopilot-HackerOne-ReadOnly/1",
      }),
    };
    const finish = (
      error: Error | undefined,
      response?: HackerOneTransportResponse,
    ): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      authorization = "";
      signal.removeEventListener("abort", onAbort);
      if (error !== undefined) reject(error);
      else if (response !== undefined) resolve(response);
      else reject(new SecurityError("HACKERONE_TRANSPORT_FAILED"));
    };
    const outgoing = request(options, (incoming) => {
      let statusCode: number;
      let rawContentTypes: readonly string[];
      let contentEncoding: string | null;
      let locationPresent: boolean;
      let declaredLength: number | null;
      try {
        if (incoming.statusCode === undefined)
          throw new SecurityError("HACKERONE_TRANSPORT_FAILED");
        statusCode = incoming.statusCode;
        rawContentTypes = headerValues(incoming.rawHeaders, "content-type");
        contentEncoding = singleHeader(
          headerValues(incoming.rawHeaders, "content-encoding"),
        );
        locationPresent =
          headerValues(incoming.rawHeaders, "location").length > 0;
        declaredLength = parseContentLength(
          headerValues(incoming.rawHeaders, "content-length"),
        );
      } catch {
        incoming.destroy();
        finish(new SecurityError("HACKERONE_RESPONSE_HEADERS_INVALID"));
        return;
      }
      if (declaredLength !== null && declaredLength > MAX_RESPONSE_BYTES) {
        incoming.destroy();
        finish(new SecurityError("HACKERONE_RESPONSE_TOO_LARGE"));
        return;
      }
      if (
        contentEncoding !== null &&
        contentEncoding.trim().toLowerCase() !== "identity"
      ) {
        incoming.destroy();
        finish(new SecurityError("HACKERONE_CONTENT_ENCODING_BLOCKED"));
        return;
      }
      const chunks: Buffer[] = [];
      let bytes = 0;
      incoming.on("data", (chunk: unknown) => {
        if (!Buffer.isBuffer(chunk)) {
          incoming.destroy();
          finish(new SecurityError("HACKERONE_RESPONSE_STREAM_INVALID"));
          return;
        }
        bytes += chunk.byteLength;
        if (bytes > MAX_RESPONSE_BYTES) {
          chunk.fill(0);
          zeroChunks(chunks);
          incoming.destroy();
          finish(new SecurityError("HACKERONE_RESPONSE_TOO_LARGE"));
          return;
        }
        chunks.push(chunk);
      });
      incoming.once("aborted", () => {
        zeroChunks(chunks);
        finish(new SecurityError("HACKERONE_RESPONSE_ABORTED"));
      });
      incoming.once("error", () => {
        zeroChunks(chunks);
        finish(new SecurityError("HACKERONE_TRANSPORT_FAILED"));
      });
      incoming.once("end", () => {
        const body = Buffer.concat(chunks, bytes);
        zeroChunks(chunks);
        finish(undefined, {
          statusCode,
          body: Uint8Array.from(body),
          contentType: rawContentTypes[0] ?? null,
          contentTypeCount: rawContentTypes.length,
          contentEncoding,
          locationPresent,
          durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
          responseBytes: bytes,
        });
        body.fill(0);
      });
    });
    const onAbort = (): void => {
      outgoing.destroy(new SecurityError("HACKERONE_REQUEST_ABORTED"));
      finish(new SecurityError("HACKERONE_REQUEST_ABORTED"));
    };
    const deadline = setTimeout(() => {
      outgoing.destroy(new SecurityError("HACKERONE_REQUEST_TIMEOUT"));
      finish(new SecurityError("HACKERONE_REQUEST_TIMEOUT"));
    }, REQUEST_TIMEOUT_MS);
    deadline.unref();
    signal.addEventListener("abort", onAbort, { once: true });
    outgoing.once("timeout", () => {
      outgoing.destroy(new SecurityError("HACKERONE_REQUEST_TIMEOUT"));
      finish(new SecurityError("HACKERONE_REQUEST_TIMEOUT"));
    });
    outgoing.once("error", () => {
      finish(new SecurityError("HACKERONE_TRANSPORT_UNAVAILABLE"));
    });
    outgoing.end();
  });
}

function basicAuthorization(credentials: HackerOneCredentialPair): string {
  const combined = Buffer.alloc(
    credentials.identifier.byteLength + credentials.token.byteLength + 1,
  );
  combined.set(credentials.identifier, 0);
  combined[credentials.identifier.byteLength] = 58;
  combined.set(credentials.token, credentials.identifier.byteLength + 1);
  try {
    return `Basic ${combined.toString("base64")}`;
  } finally {
    combined.fill(0);
  }
}

export function assertTransportPlan(plan: HackerOneTransportTarget): void {
  if (!ALLOWED_TARGET.test(plan.requestTarget))
    throw new SecurityError("HACKERONE_ENDPOINT_BLOCKED");
  const [path = "", query] = plan.requestTarget.split("?", 2);
  const expected = endpointClassForPath(path);
  const paginationQueryValid =
    query !== undefined &&
    /^page\[number\]=[1-9][0-9]{0,5}&page\[size\]=(?:[1-9]|[1-9][0-9]|100)$/u.test(
      query,
    );
  if (
    expected !== plan.endpointClass ||
    (expected === "program" && query !== undefined) ||
    (expected === "programs" && query !== undefined && !paginationQueryValid) ||
    ((expected === "structured_scopes" || expected === "scope_exclusions") &&
      !paginationQueryValid)
  )
    throw new SecurityError("HACKERONE_ENDPOINT_CLASS_MISMATCH");
}

function endpointClassForPath(path: string): HackerOneEndpointClass {
  if (path === "/v1/hackers/programs") return "programs";
  if (path.endsWith("/structured_scopes")) return "structured_scopes";
  if (path.endsWith("/scope_exclusions")) return "scope_exclusions";
  if (new RegExp(`^/v1/hackers/programs/${HANDLE}$`, "u").test(path))
    return "program";
  throw new SecurityError("HACKERONE_ENDPOINT_BLOCKED");
}

function headerValues(rawHeaders: readonly string[], name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const candidateName = rawHeaders[index];
    const candidateValue = rawHeaders[index + 1];
    if (candidateName?.toLowerCase() === name && candidateValue !== undefined)
      values.push(candidateValue);
  }
  return values;
}

function singleHeader(values: readonly string[]): string | null {
  if (values.length === 0) return null;
  if (values.length !== 1)
    throw new SecurityError("HACKERONE_RESPONSE_HEADERS_INVALID");
  return values[0] ?? null;
}

function parseContentLength(values: readonly string[]): number | null {
  if (values.length === 0) return null;
  if (values.length !== 1 || !/^(?:0|[1-9][0-9]*)$/u.test(values[0] ?? ""))
    throw new SecurityError("HACKERONE_RESPONSE_HEADERS_INVALID");
  const value = Number(values[0]);
  if (!Number.isSafeInteger(value))
    throw new SecurityError("HACKERONE_RESPONSE_HEADERS_INVALID");
  return value;
}

function zeroChunks(chunks: readonly Buffer[]): void {
  for (const chunk of chunks) chunk.fill(0);
}
