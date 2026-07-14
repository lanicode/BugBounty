import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { parseDocument } from "yaml";
import {
  isTrustedHackerOneMetadataActionGate,
  type HackerOneMetadataActionGate,
  type StoreBoundHackerOneMetadataAuthorization,
} from "../external-actions/hackerone-metadata.js";
import { sha256 } from "../shared/canonical.js";
import { errorCode, SecurityError } from "../shared/errors.js";
import type { HackerOneCredentialAccess } from "./credential-vault.js";
import {
  createInitialHackerOneMetadataRequestPlan,
  createNextHackerOneMetadataRequestPlan,
  type HackerOneMetadataOperation,
  type HackerOneMetadataRequestPlan,
} from "./request-policy.js";
import type { HackerOneMetadataReadRuntimeState } from "./runtime.js";
import {
  bindAuthorizedHackerOneTransportPlan,
  type HackerOneAuditSink,
  type HackerOneEndpointClass,
  type HackerOneTransport,
  type HackerOneTransportResponse,
} from "./transport.js";
import type {
  HackerOneConnectionResult,
  HackerOneConnectionTestSummary,
  HackerOneProgram,
  HackerOneScopeExclusion,
  HackerOneStructuredScope,
} from "./types.js";
import {
  validateProgramDocument,
  validateProgramPage,
  validateScopeExclusionPage,
  validateStructuredScopePage,
  type ValidatedPage,
} from "./validation.js";

const PROGRAM_PAGE_SIZE = 100;
const DETAIL_PAGE_SIZE = 100;
const MAX_PROGRAMS = 1_000;
const MAX_SCOPES = 2_000;
const MAX_EXCLUSIONS = 2_000;
const MAX_PAGES = 20;
const MAX_TRANSIENT_RETRIES = 2;
const RETRY_STATUS = new Set([502, 503, 504]);
const JSON_MEDIA_TYPES = new Set([
  "application/json",
  "application/vnd.api+json",
]);
const ZERO_BUDGET_OBSERVATION = Object.freeze({
  consumedRequests: 0,
  activeRequests: 0,
  requestsInCurrentMinute: 0,
});

export interface HackerOneReadOnlyClientOptions {
  readonly runtime: HackerOneMetadataReadRuntimeState;
  readonly credentials: HackerOneCredentialAccess;
  readonly transport: HackerOneTransport;
  readonly actionGate: HackerOneMetadataActionGate;
  readonly audit?: HackerOneAuditSink;
  readonly now?: () => Date;
  readonly minimumIntervalMs?: number;
}

export interface HackerOneSelectedProgramMetadata {
  readonly program: HackerOneProgram;
  readonly structuredScopes: readonly HackerOneStructuredScope[];
  readonly scopeExclusions: readonly HackerOneScopeExclusion[];
}

export class HackerOneReadOnlyClient {
  readonly #operationState = {
    tail: Promise.resolve(),
    lastRequestStartedAt: 0,
  };

  public constructor(private readonly options: HackerOneReadOnlyClientOptions) {
    if (!isTrustedHackerOneMetadataActionGate(options.actionGate))
      throw new SecurityError("HACKERONE_ACTION_GATE_UNTRUSTED");
    if (
      options.minimumIntervalMs !== undefined &&
      (!Number.isSafeInteger(options.minimumIntervalMs) ||
        options.minimumIntervalMs < 0 ||
        options.minimumIntervalMs > 60_000)
    )
      throw new SecurityError("HACKERONE_RATE_LIMIT_CONFIG_INVALID");
    Object.freeze(this);
  }

  public connectionTest(
    signal: AbortSignal,
  ): Promise<HackerOneConnectionTestSummary> {
    return this.exclusive(async () => {
      const started = performance.now();
      try {
        const operationId = operationIdentifier();
        const plan = initialPlan("programs", null, 1, this.options.runtime);
        const page = await this.executeJson(
          plan,
          operationId,
          signal,
          0,
          (value) => {
            const validated = validateProgramPage(
              value,
              timestamp(this.options.now),
            );
            if (validated.records.length > 1)
              throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
            return validated;
          },
        );
        return Object.freeze({
          result: "connected" as const,
          recordCount: page.records.length,
          schemaValid: true,
          durationMs: elapsed(started),
          redactedStatus: "HACKERONE_CONNECTION_OK",
        });
      } catch (error) {
        const result = connectionResult(error);
        return Object.freeze({
          result,
          recordCount: 0,
          schemaValid: false,
          durationMs: elapsed(started),
          redactedStatus: connectionStatus(result),
        });
      }
    });
  }

  public listPrograms(
    signal: AbortSignal,
  ): Promise<readonly HackerOneProgram[]> {
    return this.exclusive(async () => {
      const operationId = operationIdentifier();
      const synchronizedAt = timestamp(this.options.now);
      const initial = initialPlan(
        "programs",
        null,
        PROGRAM_PAGE_SIZE,
        this.options.runtime,
      );
      return this.collectPages(
        initial,
        operationId,
        signal,
        MAX_PROGRAMS,
        (value) => validateProgramPage(value, synchronizedAt),
      );
    });
  }

  public readSelectedProgram(
    synchronizedHandle: string,
    signal: AbortSignal,
  ): Promise<HackerOneSelectedProgramMetadata> {
    return this.exclusive(async () => {
      const operationId = operationIdentifier();
      const synchronizedAt = timestamp(this.options.now);
      const detailPlan = initialPlan(
        "program",
        synchronizedHandle,
        null,
        this.options.runtime,
      );
      const program = await this.executeJson(
        detailPlan,
        operationId,
        signal,
        MAX_TRANSIENT_RETRIES,
        (value) => validateProgramDocument(value, synchronizedAt),
      );
      if (program.handle !== synchronizedHandle)
        throw new SecurityError("HACKERONE_PROGRAM_HANDLE_MISMATCH");

      const scopes = await this.collectPages(
        initialPlan(
          "structured_scopes",
          synchronizedHandle,
          DETAIL_PAGE_SIZE,
          this.options.runtime,
        ),
        operationId,
        signal,
        MAX_SCOPES,
        validateStructuredScopePage,
      );
      const exclusions = await this.collectPages(
        initialPlan(
          "scope_exclusions",
          synchronizedHandle,
          DETAIL_PAGE_SIZE,
          this.options.runtime,
        ),
        operationId,
        signal,
        MAX_EXCLUSIONS,
        validateScopeExclusionPage,
      );
      return Object.freeze({
        program,
        structuredScopes: scopes,
        scopeExclusions: exclusions,
      });
    });
  }

  private async collectPages<T>(
    initial: HackerOneMetadataRequestPlan,
    operationId: string,
    signal: AbortSignal,
    maximumRecords: number,
    validate: (value: unknown) => ValidatedPage<T>,
  ): Promise<readonly T[]> {
    let plan = initial;
    const records: T[] = [];
    const unique = new Set<string>();
    for (let pageNumber = 1; pageNumber <= MAX_PAGES; pageNumber += 1) {
      const page = await this.executeJson(
        plan,
        operationId,
        signal,
        MAX_TRANSIENT_RETRIES,
        validate,
      );
      if (records.length + page.records.length > maximumRecords)
        throw new SecurityError("HACKERONE_RECORD_LIMIT_EXCEEDED");
      for (const record of page.records) {
        const identity = recordIdentity(record);
        if (unique.has(identity))
          throw new SecurityError("HACKERONE_RESPONSE_DUPLICATE_RECORD");
        unique.add(identity);
        records.push(record);
      }
      const next = createNextHackerOneMetadataRequestPlan(
        plan,
        page.next,
        this.options.runtime,
        ZERO_BUDGET_OBSERVATION,
      );
      if (next === null) return Object.freeze(records);
      plan = next;
    }
    throw new SecurityError("HACKERONE_PAGE_LIMIT_EXCEEDED");
  }

  private async executeJson<T>(
    plan: HackerOneMetadataRequestPlan,
    operationId: string,
    signal: AbortSignal,
    maximumRetries: number,
    validate: (value: unknown) => T,
  ): Promise<T> {
    for (let attempt = 0; attempt <= maximumRetries; attempt += 1) {
      if (
        !this.options.runtime.enabled ||
        !this.options.runtime.externalIntegrationsEnabled
      )
        throw new SecurityError("HACKERONE_METADATA_CAPABILITY_DISABLED");
      if (signal.aborted) throw new SecurityError("HACKERONE_REQUEST_ABORTED");
      await this.waitForRateLimit(signal);
      const requestId = randomBytes(16).toString("hex");
      const started = performance.now();
      let credentials;
      let response: HackerOneTransportResponse | undefined;
      let authorization: StoreBoundHackerOneMetadataAuthorization | undefined;
      let actionStarted = false;
      let actionSettled = false;
      try {
        const presence = await this.options.credentials.probe();
        if (
          !presence.secretStoreAvailable ||
          !presence.identifierPresent ||
          !presence.tokenPresent ||
          presence.tokenFingerprint === null ||
          presence.tokenBindingDigest?.slice(0, 12) !==
            presence.tokenFingerprint
        )
          throw new SecurityError("HACKERONE_SECRET_STORE_UNAVAILABLE");
        authorization = this.options.actionGate.authorizeAndReserve({
          operationId,
          proposalId: `h1proposal-${requestId}`,
          plan,
          credentialFingerprint: presence.tokenBindingDigest,
        });
        credentials = await this.options.credentials.load();
        if (sha256(credentials.token) !== presence.tokenBindingDigest)
          throw new SecurityError("HACKERONE_CREDENTIAL_PAIR_CHANGED");
        const actionAuthorizedPlan =
          this.options.actionGate.start(authorization);
        actionStarted = true;
        const authorizedPlan = bindAuthorizedHackerOneTransportPlan(
          actionAuthorizedPlan,
          presence.tokenBindingDigest,
        );
        response = await this.options.transport.get(
          authorizedPlan,
          credentials,
          signal,
        );
        this.audit(plan, requestId, response.statusCode, "response", started);
        if (RETRY_STATUS.has(response.statusCode) && attempt < maximumRetries) {
          this.options.actionGate.settle(authorization, "failed");
          actionSettled = true;
          response.body.fill(0);
          await backoff(attempt, signal);
          continue;
        }
        const parsed = parseSuccessfulResponse(response);
        const validated = validate(parsed);
        this.options.actionGate.settle(authorization, "succeeded");
        actionSettled = true;
        return validated;
      } catch (error) {
        let failure = error;
        if (errorCode(error) !== "HACKERONE_AUDIT_FAILED") {
          try {
            this.audit(plan, requestId, null, errorCode(error), started);
          } catch (auditError) {
            failure = auditError;
          }
        }
        if (authorization !== undefined && !actionSettled) {
          try {
            if (actionStarted)
              this.options.actionGate.settle(
                authorization,
                isAbortError(failure) ? "aborted" : "failed",
              );
            else this.options.actionGate.abortReservation(authorization);
            actionSettled = true;
          } catch (settlementError) {
            failure = settlementError;
          }
        }
        throw redactTransportError(failure);
      } finally {
        credentials?.identifier.fill(0);
        credentials?.token.fill(0);
        response?.body.fill(0);
      }
    }
    throw new SecurityError("HACKERONE_TRANSPORT_UNAVAILABLE");
  }

  private async waitForRateLimit(signal: AbortSignal): Promise<void> {
    const minimum = this.options.minimumIntervalMs ?? 100;
    const current = Date.now();
    if (this.#operationState.lastRequestStartedAt > current)
      throw new SecurityError("HACKERONE_RATE_CLOCK_ROLLBACK");
    const remaining =
      this.#operationState.lastRequestStartedAt + minimum - current;
    if (remaining > 0) {
      try {
        await delay(remaining, undefined, { signal });
      } catch {
        throw new SecurityError("HACKERONE_REQUEST_ABORTED");
      }
    }
    this.#operationState.lastRequestStartedAt = Date.now();
  }

  private audit(
    plan: HackerOneMetadataRequestPlan,
    requestId: string,
    statusCode: number | null,
    outcome: string,
    started: number,
  ): void {
    try {
      this.options.audit?.(
        Object.freeze({
          requestId,
          actionClass: "HACKERONE_METADATA_READ" as const,
          endpointClass: endpointClass(plan.operation),
          outcome,
          statusCode,
          durationMs: elapsed(started),
        }),
      );
    } catch {
      throw new SecurityError("HACKERONE_AUDIT_FAILED");
    }
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.#operationState.tail;
    let release = (): void => undefined;
    this.#operationState.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

function initialPlan(
  operation: HackerOneMetadataOperation,
  handle: string | null,
  pageSize: number | null,
  runtime: HackerOneMetadataReadRuntimeState,
): HackerOneMetadataRequestPlan {
  return createInitialHackerOneMetadataRequestPlan(
    {
      version: 1,
      capability: "HACKERONE_METADATA_READ",
      operation,
      handle,
      page: pageSize === null ? null : { number: 1, size: pageSize },
    },
    runtime,
    ZERO_BUDGET_OBSERVATION,
  );
}

function endpointClass(
  operation: HackerOneMetadataOperation,
): HackerOneEndpointClass {
  return operation;
}

function operationIdentifier(): string {
  return `h1operation-${randomBytes(16).toString("hex")}`;
}

function isAbortError(error: unknown): boolean {
  const code = errorCode(error);
  return (
    code === "HACKERONE_KILL_SWITCH" ||
    code === "HACKERONE_REQUEST_ABORTED" ||
    code === "HACKERONE_ADAPTER_DISABLED"
  );
}

function parseSuccessfulResponse(
  response: HackerOneTransportResponse,
): unknown {
  try {
    if (response.statusCode >= 300 && response.statusCode < 400)
      throw new SecurityError("HACKERONE_REDIRECT_BLOCKED");
    if (response.locationPresent)
      throw new SecurityError("HACKERONE_REDIRECT_BLOCKED");
    switch (response.statusCode) {
      case 200:
        break;
      case 401:
        throw new SecurityError("HACKERONE_INVALID_CREDENTIALS");
      case 403:
        throw new SecurityError("HACKERONE_UNAUTHORIZED");
      case 429:
        throw new SecurityError("HACKERONE_RATE_LIMITED");
      default:
        throw new SecurityError("HACKERONE_API_UNAVAILABLE");
    }
    if (
      response.contentTypeCount !== 1 ||
      !allowedContentType(response.contentType)
    )
      throw new SecurityError("HACKERONE_RESPONSE_CONTENT_TYPE_INVALID");
    const source = decodeResponse(response.body);
    assertUnambiguousJson(source);
    try {
      return JSON.parse(source) as unknown;
    } catch {
      throw new SecurityError("HACKERONE_RESPONSE_JSON_INVALID");
    }
  } finally {
    response.body.fill(0);
  }
}

function decodeResponse(body: Uint8Array): string {
  try {
    const source = new TextDecoder("utf-8", { fatal: true }).decode(body);
    if (source.startsWith("\uFEFF"))
      throw new SecurityError("HACKERONE_RESPONSE_JSON_INVALID");
    return source;
  } catch (error) {
    if (error instanceof SecurityError) throw error;
    throw new SecurityError("HACKERONE_RESPONSE_UTF8_INVALID");
  }
}

function assertUnambiguousJson(source: string): void {
  const document = parseDocument(source, {
    merge: false,
    uniqueKeys: true,
    version: "1.2",
  });
  if (document.errors.length > 0 || document.warnings.length > 0)
    throw new SecurityError("HACKERONE_RESPONSE_JSON_INVALID");
}

function allowedContentType(value: string | null): boolean {
  if (value === null) return false;
  const parts = value.split(";").map((part) => part.trim().toLowerCase());
  const mediaType = parts.shift();
  if (mediaType === undefined || !JSON_MEDIA_TYPES.has(mediaType)) return false;
  return (
    parts.length === 0 || (parts.length === 1 && parts[0] === "charset=utf-8")
  );
}

function recordIdentity(value: unknown): string {
  if (value === null || typeof value !== "object")
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  const directId: unknown = Reflect.get(value, "id");
  const fallbackId: unknown = Reflect.get(value, "hackerOneId");
  const id = directId ?? fallbackId;
  if (typeof id !== "string")
    throw new SecurityError("HACKERONE_RESPONSE_SCHEMA_INVALID");
  return id;
}

function redactTransportError(error: unknown): SecurityError {
  if (error instanceof SecurityError) return error;
  return new SecurityError("HACKERONE_TRANSPORT_UNAVAILABLE");
}

function connectionResult(error: unknown): HackerOneConnectionResult {
  const code = errorCode(error);
  switch (code) {
    case "HACKERONE_INVALID_CREDENTIALS":
      return "invalid_credentials";
    case "HACKERONE_UNAUTHORIZED":
      return "unauthorized";
    case "HACKERONE_RATE_LIMITED":
      return "rate_limited";
    case "HACKERONE_KILL_SWITCH":
    case "HACKERONE_REQUEST_ABORTED":
      return "blocked_by_kill_switch";
    case "HACKERONE_SECRET_STORE_UNAVAILABLE":
    case "HACKERONE_CREDENTIAL_PAIR_CHANGED":
    case "HACKERONE_CREDENTIAL_LEASE_INVALID":
    case "HACKERONE_CREDENTIAL_PLAN_BINDING_INVALID":
      return "secret_store_unavailable";
    case "HACKERONE_RESPONSE_CONTENT_TYPE_INVALID":
    case "HACKERONE_RESPONSE_JSON_INVALID":
    case "HACKERONE_RESPONSE_SCHEMA_INVALID":
    case "HACKERONE_RESPONSE_UTF8_INVALID":
      return "malformed_response";
    case "HACKERONE_METADATA_CAPABILITY_DISABLED":
    case "HACKERONE_ADAPTER_DISABLED":
    case "HACKERONE_EGRESS_BLOCKED":
    case "HACKERONE_REQUEST_BUDGET_EXCEEDED":
      return "blocked_by_policy";
    default:
      return "unavailable";
  }
}

function connectionStatus(result: HackerOneConnectionResult): string {
  return `HACKERONE_CONNECTION_${result.toUpperCase()}`;
}

function timestamp(now: (() => Date) | undefined): string {
  const date = (now ?? (() => new Date()))();
  if (!Number.isFinite(date.getTime()))
    throw new SecurityError("HACKERONE_CLOCK_INVALID");
  return date.toISOString();
}

function elapsed(started: number): number {
  return Math.max(0, Math.round(performance.now() - started));
}

async function backoff(attempt: number, signal: AbortSignal): Promise<void> {
  try {
    await delay(50 * 2 ** attempt, undefined, { signal });
  } catch {
    throw new SecurityError("HACKERONE_REQUEST_ABORTED");
  }
}
