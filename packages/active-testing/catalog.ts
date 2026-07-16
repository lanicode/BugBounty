import { types } from "node:util";
import { domainToASCII } from "node:url";
import { decideEgress } from "../egress-guard/index.js";
import { normalizeRequestPath } from "../egress-guard/normalize.js";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import type { HackerOneStructuredScope } from "../hackerone-readonly/index.js";
import { canonicalizeActiveTestDnsHost } from "./resolved-egress.js";
import {
  ACTIVE_TEST_PLAN_VERSION,
  ACTIVE_TEST_RUNNER_VERSION,
  type ActiveTestAssetCandidate,
  type ActiveTestAssetReasonCode,
  type ActiveTestCatalogEntry,
  type ActiveTestClass,
  type ActiveTestPlanV1,
  type CreateActiveTestPlanInput,
} from "./types.js";

const PLAN_LIFETIME_MS = 10 * 60_000;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]{1,128}$/u;
const PROGRAM_REF_PATTERN = /^h1a_[a-f0-9]{64}$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const FORBIDDEN_AUTOMATION =
  /(?:automated (?:testing|scanning).{0,40}(?:prohibited|forbidden|not allowed)|do not (?:use|run) automated)/iu;

const CATALOG: Readonly<Record<ActiveTestClass, ActiveTestCatalogEntry>> =
  Object.freeze({
    http_headers: Object.freeze({
      id: "http_headers",
      displayName: "HTTP-Sicherheitsheader",
      description:
        "Ein einzelner HEAD-Request prüft ausschließlich redigierte Header-Metadaten.",
      method: "HEAD",
      headerProfile: "metadata_v1",
      pathMode: "exact_scope_path",
      captureMode: "metadata_only",
      maximumRequests: 1,
      riskTier: "tier_1_public_read_only",
    }),
    cors_preflight: Object.freeze({
      id: "cors_preflight",
      displayName: "CORS-Preflight",
      description:
        "Ein einzelner OPTIONS-Request verwendet einen festen, nicht vertrauenswürdigen Probe-Origin.",
      method: "OPTIONS",
      headerProfile: "cors_probe_v1",
      pathMode: "exact_scope_path",
      captureMode: "metadata_only",
      maximumRequests: 1,
      riskTier: "tier_1_public_read_only",
    }),
    security_txt: Object.freeze({
      id: "security_txt",
      displayName: "security.txt-Metadaten",
      description:
        "Ein einzelner GET-Request prüft die standardisierte Root-Metadatei ohne Rohbody-Persistenz.",
      method: "GET",
      headerProfile: "metadata_v1",
      pathMode: "security_txt_root",
      captureMode: "metadata_only",
      maximumRequests: 1,
      riskTier: "tier_1_public_read_only",
    }),
  });

export function listActiveTestCatalog(): readonly ActiveTestCatalogEntry[] {
  return Object.freeze([
    CATALOG.http_headers,
    CATALOG.cors_preflight,
    CATALOG.security_txt,
  ]);
}

export function activeTestCatalogDigest(): string {
  return sha256(canonicalJson(listActiveTestCatalog()));
}

export function projectActiveTestAsset(
  scope: HackerOneStructuredScope,
): ActiveTestAssetCandidate {
  const reasonCodes: ActiveTestAssetReasonCode[] = [];
  if (scope.assetType !== "URL")
    reasonCodes.push("ACTIVE_TEST_ASSET_TYPE_UNSUPPORTED");
  if (!scope.eligibleForSubmission)
    reasonCodes.push("ACTIVE_TEST_SCOPE_SUBMISSION_INELIGIBLE");
  if (!scope.eligibleForBounty)
    reasonCodes.push("ACTIVE_TEST_SCOPE_BOUNTY_INELIGIBLE");
  try {
    compileExactHttpsTarget(scope.assetIdentifier);
  } catch (error) {
    const code =
      error instanceof SecurityError && isAssetReasonCode(error.code)
        ? error.code
        : "ACTIVE_TEST_ASSET_IDENTIFIER_INVALID";
    reasonCodes.push(code);
  }
  const unique = Object.freeze([...new Set(reasonCodes)]);
  return Object.freeze({
    scopeId: scope.id,
    assetType: scope.assetType,
    displayIdentifier: scope.assetIdentifier,
    assetIdentifierDigest: scope.assetIdentifierDigest,
    eligibleForSubmission: scope.eligibleForSubmission,
    eligibleForBounty: scope.eligibleForBounty,
    supported: unique.length === 0,
    reasonCodes: unique,
  });
}

export function createActiveTestPlan(
  input: CreateActiveTestPlanInput,
): ActiveTestPlanV1 {
  capturePlanInput(input);
  if (input.snapshot.source !== "hackerone_api_authenticated")
    throw new SecurityError("ACTIVE_TEST_API_SOURCE_REQUIRED");
  if (FORBIDDEN_AUTOMATION.test(input.snapshot.program.policy))
    throw new SecurityError("ACTIVE_TEST_POLICY_AUTOMATION_FORBIDDEN");
  if (
    input.snapshot.program.submissionState.toLowerCase() !== "open" &&
    input.snapshot.program.submissionState.toLowerCase() !==
      "open_for_submissions"
  )
    throw new SecurityError("ACTIVE_TEST_PROGRAM_SUBMISSIONS_CLOSED");
  const scope = input.snapshot.structuredScopes.find(
    (candidate) => candidate.id === input.scopeId,
  );
  if (scope?.assetIdentifierDigest !== input.assetIdentifierDigest)
    throw new SecurityError("ACTIVE_TEST_SCOPE_BINDING_INVALID");
  const projection = projectActiveTestAsset(scope);
  if (!projection.supported)
    throw new SecurityError(
      projection.reasonCodes[0] ?? "ACTIVE_TEST_SCOPE_BLOCKED",
    );
  const target = compileExactHttpsTarget(scope.assetIdentifier);
  const catalog = CATALOG[input.testClass];
  const path =
    catalog.pathMode === "security_txt_root"
      ? requireSecurityTxtPath(target.path)
      : target.path;
  assertEgressDecision(target.host, path, catalog.method);
  const created = canonicalTimestamp(input.createdAt);
  const expires = new Date(
    Date.parse(created) + PLAN_LIFETIME_MS,
  ).toISOString();
  return Object.freeze({
    version: ACTIVE_TEST_PLAN_VERSION,
    plan_id: input.planId,
    program_ref: input.programRef,
    program_handle: input.snapshot.program.handle,
    snapshot_digest: input.snapshot.snapshotDigest,
    policy_digest: input.snapshot.policyDigest,
    scope_id: scope.id,
    asset_identifier_digest: scope.assetIdentifierDigest,
    test_class: input.testClass,
    runner_version: ACTIVE_TEST_RUNNER_VERSION,
    target: Object.freeze({
      scheme: "https" as const,
      host: target.host,
      port: 443 as const,
      path,
    }),
    request: Object.freeze({
      method: catalog.method,
      header_profile: catalog.headerProfile,
      capture_mode: "metadata_only" as const,
      follow_redirects: false as const,
      retries: 0 as const,
    }),
    budget: Object.freeze({
      max_requests_total: 1 as const,
      requests_per_minute: 1 as const,
      max_concurrency: 1 as const,
    }),
    confirmations: Object.freeze({
      automation_permission_reviewed: true as const,
      scope_instruction_reviewed: true as const,
      scope_exclusions_reviewed: true as const,
      no_side_effects_confirmed: true as const,
    }),
    created_at: created,
    expires_at: expires,
  });
}

function capturePlanInput(
  input: Parameters<typeof createActiveTestPlan>[0],
): void {
  if (
    types.isProxy(input) ||
    Reflect.getPrototypeOf(input) !== Object.prototype ||
    !IDENTIFIER_PATTERN.test(input.planId) ||
    !PROGRAM_REF_PATTERN.test(input.programRef) ||
    !IDENTIFIER_PATTERN.test(input.scopeId) ||
    !DIGEST_PATTERN.test(input.assetIdentifierDigest) ||
    !(input.testClass in CATALOG) ||
    !input.confirmations.automationPermissionReviewed ||
    !input.confirmations.scopeInstructionReviewed ||
    !input.confirmations.scopeExclusionsReviewed ||
    !input.confirmations.noSideEffectsConfirmed
  )
    throw new SecurityError("ACTIVE_TEST_PLAN_INPUT_INVALID");
}

function compileExactHttpsTarget(identifier: string): {
  readonly host: string;
  readonly path: string;
} {
  if (identifier.includes("*"))
    throw new SecurityError("ACTIVE_TEST_TARGET_WILDCARD_BLOCKED");
  let parsed: URL;
  try {
    parsed = new URL(identifier);
  } catch {
    throw new SecurityError("ACTIVE_TEST_ASSET_IDENTIFIER_INVALID");
  }
  if (parsed.protocol !== "https:")
    throw new SecurityError("ACTIVE_TEST_TARGET_NOT_HTTPS");
  if (parsed.port !== "" && parsed.port !== "443")
    throw new SecurityError("ACTIVE_TEST_TARGET_PORT_BLOCKED");
  if (
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  )
    throw new SecurityError("ACTIVE_TEST_TARGET_NONCANONICAL");
  const host = parsed.hostname.toLowerCase();
  if (
    host === "" ||
    host.endsWith(".") ||
    host.includes("%") ||
    host.includes(":") ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(host) ||
    domainToASCII(host) !== host
  )
    throw new SecurityError("ACTIVE_TEST_TARGET_NONCANONICAL");
  try {
    canonicalizeActiveTestDnsHost(host);
  } catch {
    throw new SecurityError("ACTIVE_TEST_TARGET_NONCANONICAL");
  }
  const canonical = `https://${host}${parsed.pathname || "/"}`;
  if (parsed.port === "443" || identifier !== canonical)
    throw new SecurityError("ACTIVE_TEST_TARGET_NONCANONICAL");
  let path: string;
  try {
    path = normalizeRequestPath(parsed.pathname || "/");
  } catch {
    throw new SecurityError("ACTIVE_TEST_TARGET_PATH_UNSUPPORTED");
  }
  if (path !== (parsed.pathname || "/"))
    throw new SecurityError("ACTIVE_TEST_TARGET_PATH_UNSUPPORTED");
  return Object.freeze({ host, path });
}

function requireSecurityTxtPath(
  scopePath: string,
): "/.well-known/security.txt" {
  if (scopePath !== "/")
    throw new SecurityError("ACTIVE_TEST_TARGET_PATH_UNSUPPORTED");
  return "/.well-known/security.txt";
}

function assertEgressDecision(
  host: string,
  path: string,
  method: "GET" | "HEAD" | "OPTIONS",
): void {
  const decision = decideEgress(
    {
      config: {
        version: 2,
        program: {
          platform: "hackerone",
          handle: "scope-bound",
          display_name: "Scope-bound active test",
          policy_source: "hackerone_api_authenticated",
          policy_hash_sha256: "0".repeat(64),
          policy_accepted_at: "1970-01-01T00:00:00.000Z",
          policy_accepted_by: "local.operator",
        },
        network: {
          targets: [
            { scheme: "https", host, ports: [443], path_prefixes: [path] },
          ],
          supporting_hosts: [],
          blocked_hosts: [],
          deny_by_default: true,
          allow_plain_http: false,
          follow_redirects: false,
          block_service_workers_during_capture: true,
        },
        capture: {
          persist_unredacted_traffic: false,
          persist_response_bodies: "selective",
          allowed_body_content_types: ["text/plain", "text/html"],
          max_body_bytes: 65_536,
          binary_handling: "hash_only",
          websocket_capture: "disabled",
          stable_pseudonyms: true,
          local_hmac_key_ref: "keychain://bugbounty-copilot/event-store-v1",
          quarantine_unknown_identity_data: true,
        },
        accounts: [
          {
            id: "public-probe-a",
            role: "Unauthenticated",
            secret_ref: "keychain://bugbounty-copilot/not-used-a",
            email_alias_ref: "keychain://bugbounty-copilot/not-used-a",
          },
          {
            id: "public-probe-b",
            role: "UnauthenticatedControl",
            secret_ref: "keychain://bugbounty-copilot/not-used-b",
            email_alias_ref: "keychain://bugbounty-copilot/not-used-b",
          },
        ],
        budgets: {
          global_requests_per_minute: 1,
          max_concurrency: 1,
          max_requests_per_candidate: 1,
          max_state_changes_per_candidate: 0,
          stop_after_first_positive_signal: true,
          cool_down_seconds_after_error: 60,
          stop_statuses: [301, 302, 303, 307, 308, 429],
        },
        forbidden: ["write_methods", "redirects", "retries", "credentials"],
        policy_drift: {
          block_campaign_when_policy_hash_changes: true,
          require_new_acceptance: true,
        },
      },
    },
    {
      url: `https://${host}${path}`,
      method,
      captureMode: "metadata_only",
      resourceKind: "fetch",
      isRedirect: false,
    },
  );
  if (!decision.allow || decision.reason !== "ALLOW_TARGET")
    throw new SecurityError("ACTIVE_TEST_EGRESS_BLOCKED");
}

function canonicalTimestamp(value: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed))
    throw new SecurityError("ACTIVE_TEST_PLAN_TIME_INVALID");
  const canonical = new Date(parsed).toISOString();
  if (canonical !== value)
    throw new SecurityError("ACTIVE_TEST_PLAN_TIME_INVALID");
  return canonical;
}

function isAssetReasonCode(value: string): value is ActiveTestAssetReasonCode {
  return value.startsWith("ACTIVE_TEST_");
}
