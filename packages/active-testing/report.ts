import { types } from "node:util";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";
import {
  activeTestPlanDigest,
  validateAndFreezeActiveTestPlan,
} from "./plan.js";
import type {
  ActiveTestClass,
  ActiveTestObservation,
  ActiveTestPlanV1,
  ActiveTestRedactedContentType,
  ActiveTestRedactedResponseMetadata,
  ActiveTestReportDraft,
  ActiveTestResponseFacts,
  ActiveTestSignal,
  ActiveTestTlsCipherClassification,
  ActiveTestTlsProtocol,
} from "./types.js";

const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]{1,128}$/u;
const MAX_DURATION_MS = 10_000;
const MAX_RESPONSE_BYTES = 65_536;
const PLAN_KEYS = Object.freeze([
  "asset_identifier_digest",
  "budget",
  "confirmations",
  "created_at",
  "expires_at",
  "plan_id",
  "policy_digest",
  "program_handle",
  "program_ref",
  "request",
  "runner_version",
  "scope_id",
  "snapshot_digest",
  "target",
  "test_class",
  "version",
]);

type SignalCode = ActiveTestSignal["code"];

const SIGNAL_DEFINITIONS = Object.freeze({
  CORS_CREDENTIALS_WITH_REFLECTED_ORIGIN: Object.freeze({
    severity: "medium" as const,
    evidence:
      "Redacted metadata classified credentials as enabled with the fixed probe origin reflected.",
  }),
  CORS_REFLECTS_PROBE_ORIGIN: Object.freeze({
    severity: "low" as const,
    evidence:
      "Redacted metadata classified the fixed probe origin as reflected.",
  }),
  HEADER_CONTENT_SECURITY_POLICY_MISSING: Object.freeze({
    severity: "low" as const,
    evidence: "Redacted metadata classified Content-Security-Policy as absent.",
  }),
  HEADER_HSTS_MISSING: Object.freeze({
    severity: "low" as const,
    evidence:
      "Redacted metadata classified Strict-Transport-Security as absent.",
  }),
  HEADER_X_CONTENT_TYPE_OPTIONS_MISSING: Object.freeze({
    severity: "low" as const,
    evidence:
      "Redacted metadata did not classify X-Content-Type-Options as nosniff.",
  }),
  INSECURE_COOKIE_FLAGS_OBSERVED: Object.freeze({
    severity: "medium" as const,
    evidence:
      "Redacted metadata classified one or more cookie flag combinations as insecure; no cookie value was retained.",
  }),
  SECURITY_TXT_AVAILABLE: Object.freeze({
    severity: "informational" as const,
    evidence:
      "Redacted metadata classified the scoped security.txt resource as available.",
  }),
  SECURITY_TXT_MISSING: Object.freeze({
    severity: "informational" as const,
    evidence:
      "Redacted metadata classified the scoped security.txt resource as missing.",
  }),
}) satisfies Readonly<
  Record<
    SignalCode,
    {
      readonly severity: ActiveTestSignal["severity"];
      readonly evidence: string;
    }
  >
>;

const SIGNAL_ORDER = Object.freeze<readonly SignalCode[]>([
  "CORS_CREDENTIALS_WITH_REFLECTED_ORIGIN",
  "CORS_REFLECTS_PROBE_ORIGIN",
  "HEADER_CONTENT_SECURITY_POLICY_MISSING",
  "HEADER_HSTS_MISSING",
  "HEADER_X_CONTENT_TYPE_OPTIONS_MISSING",
  "INSECURE_COOKIE_FLAGS_OBSERVED",
  "SECURITY_TXT_AVAILABLE",
  "SECURITY_TXT_MISSING",
]);

interface FrozenPlanBinding {
  readonly plan: ActiveTestPlanV1;
  readonly digest: string;
}

export function analyzeActiveTestEvidence(
  plan: ActiveTestPlanV1,
  responseMetadata: unknown,
): ActiveTestObservation {
  const binding = requireValidatedFrozenPlan(plan);
  const metadata = captureResponseMetadata(binding, responseMetadata);
  return buildObservation(binding, metadata);
}

export function validateAndFreezeActiveTestObservation(
  value: unknown,
): ActiveTestObservation {
  const top = exactRecord(
    value,
    [
      "completedAt",
      "contentType",
      "cookiesStored",
      "durationMs",
      "metadataDigest",
      "planDigest",
      "planId",
      "rawBodyStored",
      "rawHeadersStored",
      "redirectLocationPresent",
      "resolutionDigest",
      "responseBytesObserved",
      "responseDigest",
      "signals",
      "statusCode",
      "testClass",
      "tls",
      "transportKind",
      "version",
    ],
    "ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID",
  );
  const planId = top["planId"];
  const planDigest = top["planDigest"];
  const metadataDigest = top["metadataDigest"];
  const testClass = top["testClass"];
  const statusCode = top["statusCode"];
  const durationMs = top["durationMs"];
  const responseBytesObserved = top["responseBytesObserved"];
  const contentType = top["contentType"];
  const responseDigest = top["responseDigest"];
  const resolutionDigest = top["resolutionDigest"];
  const transportKind = top["transportKind"];
  if (
    top["version"] !== 1 ||
    typeof planId !== "string" ||
    !IDENTIFIER_PATTERN.test(planId) ||
    typeof planDigest !== "string" ||
    !DIGEST_PATTERN.test(planDigest) ||
    typeof metadataDigest !== "string" ||
    !DIGEST_PATTERN.test(metadataDigest) ||
    typeof resolutionDigest !== "string" ||
    !DIGEST_PATTERN.test(resolutionDigest) ||
    !isTransportKind(transportKind) ||
    !isActiveTestClass(testClass) ||
    !isIntegerBetween(statusCode, 200, 599) ||
    !isIntegerBetween(durationMs, 0, MAX_DURATION_MS) ||
    !isIntegerBetween(responseBytesObserved, 0, MAX_RESPONSE_BYTES) ||
    !isRedactedContentType(contentType) ||
    (responseDigest !== null &&
      (typeof responseDigest !== "string" ||
        !DIGEST_PATTERN.test(responseDigest))) ||
    top["redirectLocationPresent"] !== false ||
    top["rawBodyStored"] !== false ||
    top["rawHeadersStored"] !== false ||
    top["cookiesStored"] !== false
  )
    throw new SecurityError("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
  if (statusCode >= 300 && statusCode <= 399)
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_REDIRECT_BLOCKED");
  const tls = captureTls(top["tls"], "ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
  const signals = captureSignals(top["signals"], testClass);
  const completedAt = canonicalTimestamp(
    top["completedAt"],
    "ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID",
  );
  assertObservationSemantics({
    contentType,
    responseBytesObserved,
    responseDigest,
    signals,
    statusCode,
    testClass,
  });
  return Object.freeze({
    version: 1 as const,
    planId,
    planDigest,
    metadataDigest,
    testClass,
    statusCode,
    durationMs,
    responseBytesObserved,
    contentType,
    redirectLocationPresent: false as const,
    tls,
    transportKind,
    resolutionDigest,
    signals,
    responseDigest,
    rawBodyStored: false as const,
    rawHeadersStored: false as const,
    cookiesStored: false as const,
    completedAt,
  });
}

export function activeTestObservationDigest(value: unknown): string {
  return sha256(canonicalJson(validateAndFreezeActiveTestObservation(value)));
}

export function createLocalActiveTestReportDraft(
  plan: ActiveTestPlanV1,
  responseMetadata: unknown,
): ActiveTestReportDraft {
  const binding = requireValidatedFrozenPlan(plan);
  const metadata = captureResponseMetadata(binding, responseMetadata);
  const observation = buildObservation(binding, metadata);
  return buildLocalActiveTestReportDraft(binding, observation);
}

/** Reconstructs the only valid report representation during durable reopen. */
export function reconstructLocalActiveTestReportDraft(
  plan: ActiveTestPlanV1,
  value: unknown,
): ActiveTestReportDraft {
  const binding = requireValidatedFrozenPlan(plan);
  const observation = validateAndFreezeActiveTestObservation(value);
  if (
    observation.planId !== binding.plan.plan_id ||
    observation.planDigest !== binding.digest ||
    observation.testClass !== binding.plan.test_class ||
    Date.parse(observation.completedAt) < Date.parse(binding.plan.created_at) ||
    Date.parse(observation.completedAt) > Date.parse(binding.plan.expires_at)
  )
    throw new SecurityError("ACTIVE_TEST_REPORT_EVIDENCE_INVALID");
  return buildLocalActiveTestReportDraft(binding, observation);
}

function buildLocalActiveTestReportDraft(
  binding: FrozenPlanBinding,
  observation: ActiveTestObservation,
): ActiveTestReportDraft {
  const observationDigest = activeTestObservationDigest(observation);
  const reportMaterialDigest = sha256(
    canonicalJson({
      kind: "active_test_local_report_v1",
      observationDigest,
      planDigest: binding.digest,
      createdAt: observation.completedAt,
    }),
  );
  const reportId = `active-report-${reportMaterialDigest}`;
  const document = {
    version: 1,
    reportId,
    reviewStatus: "local_draft_unsubmitted",
    externalSubmissionPerformed: false,
    bindings: {
      planId: binding.plan.plan_id,
      planDigest: binding.digest,
      snapshotDigest: binding.plan.snapshot_digest,
      policyDigest: binding.plan.policy_digest,
      assetIdentifierDigest: binding.plan.asset_identifier_digest,
      responseMetadataDigest: observation.metadataDigest,
      observationDigest,
      transportKind: observation.transportKind,
      resolutionDigest: observation.resolutionDigest,
    },
    execution: {
      testClass: observation.testClass,
      method: binding.plan.request.method,
      statusCode: observation.statusCode,
      durationMs: observation.durationMs,
      responseBytesObserved: observation.responseBytesObserved,
      contentType: observation.contentType,
      redirectLocationPresent: false,
      tlsAuthorized: true,
      tlsProtocol: observation.tls.protocol,
      tlsCipherClassification: observation.tls.cipher,
      transportKind: observation.transportKind,
      resolutionDigest: observation.resolutionDigest,
      responseDigest: observation.responseDigest,
      completedAt: observation.completedAt,
    },
    retention: {
      rawBodyStored: false,
      rawHeadersStored: false,
      cookiesStored: false,
    },
    signals: observation.signals,
  } as const;
  const json = canonicalJson(document);
  const markdown = renderMarkdown({
    reportId,
    plan: binding.plan,
    planDigest: binding.digest,
    observation,
    observationDigest,
  });
  return Object.freeze({
    version: 1 as const,
    reportId,
    planId: binding.plan.plan_id,
    planDigest: binding.digest,
    snapshotDigest: binding.plan.snapshot_digest,
    policyDigest: binding.plan.policy_digest,
    assetIdentifierDigest: binding.plan.asset_identifier_digest,
    responseMetadataDigest: observation.metadataDigest,
    observationDigest,
    transportKind: observation.transportKind,
    resolutionDigest: observation.resolutionDigest,
    reviewStatus: "local_draft_unsubmitted" as const,
    externalSubmissionPerformed: false as const,
    markdown,
    markdownDigest: sha256(markdown),
    json,
    jsonDigest: sha256(json),
    createdAt: observation.completedAt,
  });
}

function requireValidatedFrozenPlan(value: unknown): FrozenPlanBinding {
  const top = exactRecord(
    value,
    PLAN_KEYS,
    "ACTIVE_TEST_EVIDENCE_PLAN_INVALID",
  );
  if (
    !Object.isFrozen(value) ||
    !isFrozenPlainRecord(top["target"]) ||
    !isFrozenPlainRecord(top["request"]) ||
    !isFrozenPlainRecord(top["budget"]) ||
    !isFrozenPlainRecord(top["confirmations"])
  )
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_PLAN_NOT_FROZEN");
  try {
    const plan = validateAndFreezeActiveTestPlan(value);
    return Object.freeze({ plan, digest: activeTestPlanDigest(plan) });
  } catch {
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_PLAN_INVALID");
  }
}

function captureResponseMetadata(
  binding: FrozenPlanBinding,
  value: unknown,
): ActiveTestRedactedResponseMetadata {
  const top = exactRecord(
    value,
    [
      "completedAt",
      "contentType",
      "durationMs",
      "facts",
      "planDigest",
      "planId",
      "redaction",
      "redirectLocationPresent",
      "responseBytesObserved",
      "responseDigest",
      "statusCode",
      "testClass",
      "tls",
      "transport",
      "version",
    ],
    "ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID",
  );
  const planId = top["planId"];
  const planDigest = top["planDigest"];
  const testClass = top["testClass"];
  const statusCode = top["statusCode"];
  const durationMs = top["durationMs"];
  const responseBytesObserved = top["responseBytesObserved"];
  const contentType = top["contentType"];
  const responseDigest = top["responseDigest"];
  if (
    top["version"] !== 1 ||
    typeof planId !== "string" ||
    !IDENTIFIER_PATTERN.test(planId) ||
    typeof planDigest !== "string" ||
    !DIGEST_PATTERN.test(planDigest) ||
    !isActiveTestClass(testClass) ||
    !isIntegerBetween(statusCode, 200, 599) ||
    !isIntegerBetween(durationMs, 0, MAX_DURATION_MS) ||
    !isIntegerBetween(responseBytesObserved, 0, MAX_RESPONSE_BYTES) ||
    (responseDigest !== null &&
      (typeof responseDigest !== "string" ||
        !DIGEST_PATTERN.test(responseDigest)))
  )
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");
  if (!isRedactedContentType(contentType))
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_CONTENT_TYPE_BLOCKED");
  if (
    top["redirectLocationPresent"] === true ||
    (statusCode >= 300 && statusCode <= 399)
  )
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_REDIRECT_BLOCKED");
  if (top["redirectLocationPresent"] !== false)
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");
  if (
    planId !== binding.plan.plan_id ||
    planDigest !== binding.digest ||
    testClass !== binding.plan.test_class
  )
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_BINDING_INVALID");
  const tls = captureTls(top["tls"], "ACTIVE_TEST_EVIDENCE_TLS_INVALID");
  const transport = captureTransport(top["transport"]);
  const redaction = captureRedaction(top["redaction"]);
  const facts = captureFacts(top["facts"], testClass);
  const completedAt = canonicalTimestamp(
    top["completedAt"],
    "ACTIVE_TEST_EVIDENCE_TIME_INVALID",
  );
  if (
    Date.parse(completedAt) < Date.parse(binding.plan.created_at) ||
    Date.parse(completedAt) > Date.parse(binding.plan.expires_at)
  )
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_TIME_INVALID");
  assertMetadataSemantics({
    contentType,
    facts,
    responseBytesObserved,
    responseDigest,
    statusCode,
    testClass,
  });
  return Object.freeze({
    version: 1 as const,
    planId,
    planDigest,
    testClass,
    statusCode,
    durationMs,
    responseBytesObserved,
    contentType,
    redirectLocationPresent: false as const,
    tls,
    transport,
    facts,
    responseDigest,
    redaction,
    completedAt,
  });
}

function captureTls(
  value: unknown,
  errorCode: string,
): ActiveTestRedactedResponseMetadata["tls"] {
  const tls = exactRecord(
    value,
    ["authorized", "cipher", "protocol"],
    errorCode,
  );
  const protocol = tls["protocol"];
  const cipher = tls["cipher"];
  if (
    tls["authorized"] !== true ||
    !isTlsProtocol(protocol) ||
    !isTlsCipherClassification(cipher)
  )
    throw new SecurityError(errorCode);
  return Object.freeze({ authorized: true as const, protocol, cipher });
}

function captureTransport(
  value: unknown,
): ActiveTestRedactedResponseMetadata["transport"] {
  const transport = exactRecord(
    value,
    ["kind", "resolutionDigest"],
    "ACTIVE_TEST_EVIDENCE_TRANSPORT_INVALID",
  );
  const kind = transport["kind"];
  const resolutionDigest = transport["resolutionDigest"];
  if (
    !isTransportKind(kind) ||
    typeof resolutionDigest !== "string" ||
    !DIGEST_PATTERN.test(resolutionDigest)
  )
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_TRANSPORT_INVALID");
  return Object.freeze({ kind, resolutionDigest });
}

function captureRedaction(
  value: unknown,
): ActiveTestRedactedResponseMetadata["redaction"] {
  const redaction = exactRecord(
    value,
    ["cookiesStored", "rawBodyStored", "rawHeadersStored", "status"],
    "ACTIVE_TEST_EVIDENCE_REDACTION_REQUIRED",
  );
  if (
    redaction["status"] !== "complete" ||
    redaction["rawBodyStored"] !== false ||
    redaction["rawHeadersStored"] !== false ||
    redaction["cookiesStored"] !== false
  )
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_REDACTION_REQUIRED");
  return Object.freeze({
    status: "complete" as const,
    rawBodyStored: false as const,
    rawHeadersStored: false as const,
    cookiesStored: false as const,
  });
}

function captureFacts(
  value: unknown,
  testClass: ActiveTestClass,
): ActiveTestResponseFacts {
  if (testClass === "cors_preflight") {
    const facts = exactRecord(
      value,
      ["allowCredentials", "allowOrigin", "kind"],
      "ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID",
    );
    const allowOrigin = facts["allowOrigin"];
    const allowCredentials = facts["allowCredentials"];
    if (
      facts["kind"] !== "cors_preflight" ||
      !isCorsOriginClassification(allowOrigin) ||
      typeof allowCredentials !== "boolean"
    )
      throw new SecurityError("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");
    return Object.freeze({
      kind: "cors_preflight" as const,
      allowOrigin,
      allowCredentials,
    });
  }
  if (testClass === "http_headers") {
    const facts = exactRecord(
      value,
      [
        "contentSecurityPolicyPresent",
        "insecureCookieFlagsObserved",
        "kind",
        "strictTransportSecurityPresent",
        "xContentTypeOptionsNosniff",
      ],
      "ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID",
    );
    const contentSecurityPolicyPresent = facts["contentSecurityPolicyPresent"];
    const insecureCookieFlagsObserved = facts["insecureCookieFlagsObserved"];
    const strictTransportSecurityPresent =
      facts["strictTransportSecurityPresent"];
    const xContentTypeOptionsNosniff = facts["xContentTypeOptionsNosniff"];
    if (
      facts["kind"] !== "http_headers" ||
      typeof contentSecurityPolicyPresent !== "boolean" ||
      typeof insecureCookieFlagsObserved !== "boolean" ||
      typeof strictTransportSecurityPresent !== "boolean" ||
      typeof xContentTypeOptionsNosniff !== "boolean"
    )
      throw new SecurityError("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");
    return Object.freeze({
      kind: "http_headers" as const,
      contentSecurityPolicyPresent,
      strictTransportSecurityPresent,
      xContentTypeOptionsNosniff,
      insecureCookieFlagsObserved,
    });
  }
  const facts = exactRecord(
    value,
    ["availability", "kind"],
    "ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID",
  );
  const availability = facts["availability"];
  if (
    facts["kind"] !== "security_txt" ||
    (availability !== "available" && availability !== "missing")
  )
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");
  return Object.freeze({
    kind: "security_txt" as const,
    availability,
  });
}

function buildObservation(
  binding: FrozenPlanBinding,
  metadata: ActiveTestRedactedResponseMetadata,
): ActiveTestObservation {
  return validateAndFreezeActiveTestObservation({
    version: 1,
    planId: binding.plan.plan_id,
    planDigest: binding.digest,
    metadataDigest: sha256(canonicalJson(metadata)),
    testClass: binding.plan.test_class,
    statusCode: metadata.statusCode,
    durationMs: metadata.durationMs,
    responseBytesObserved: metadata.responseBytesObserved,
    contentType: metadata.contentType,
    redirectLocationPresent: false,
    tls: metadata.tls,
    transportKind: metadata.transport.kind,
    resolutionDigest: metadata.transport.resolutionDigest,
    signals: analyzeFacts(metadata.facts),
    responseDigest: metadata.responseDigest,
    rawBodyStored: false,
    rawHeadersStored: false,
    cookiesStored: false,
    completedAt: metadata.completedAt,
  });
}

function analyzeFacts(
  facts: ActiveTestResponseFacts,
): readonly ActiveTestSignal[] {
  const signals: ActiveTestSignal[] = [];
  if (facts.kind === "cors_preflight") {
    if (facts.allowOrigin === "probe_origin" && facts.allowCredentials)
      signals.push(makeSignal("CORS_CREDENTIALS_WITH_REFLECTED_ORIGIN"));
    if (facts.allowOrigin === "probe_origin")
      signals.push(makeSignal("CORS_REFLECTS_PROBE_ORIGIN"));
  } else if (facts.kind === "http_headers") {
    if (!facts.contentSecurityPolicyPresent)
      signals.push(makeSignal("HEADER_CONTENT_SECURITY_POLICY_MISSING"));
    if (!facts.strictTransportSecurityPresent)
      signals.push(makeSignal("HEADER_HSTS_MISSING"));
    if (!facts.xContentTypeOptionsNosniff)
      signals.push(makeSignal("HEADER_X_CONTENT_TYPE_OPTIONS_MISSING"));
    if (facts.insecureCookieFlagsObserved)
      signals.push(makeSignal("INSECURE_COOKIE_FLAGS_OBSERVED"));
  } else {
    signals.push(
      makeSignal(
        facts.availability === "available"
          ? "SECURITY_TXT_AVAILABLE"
          : "SECURITY_TXT_MISSING",
      ),
    );
  }
  return Object.freeze(signals);
}

function makeSignal(code: SignalCode): ActiveTestSignal {
  const definition = SIGNAL_DEFINITIONS[code];
  return Object.freeze({
    code,
    severity: definition.severity,
    evidence: definition.evidence,
  });
}

function captureSignals(
  value: unknown,
  testClass: ActiveTestClass,
): readonly ActiveTestSignal[] {
  const entries = exactArray(
    value,
    SIGNAL_ORDER.length,
    "ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID",
  );
  const signals: ActiveTestSignal[] = [];
  let previousOrder = -1;
  for (const entry of entries) {
    const signal = exactRecord(
      entry,
      ["code", "evidence", "severity"],
      "ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID",
    );
    const code = signal["code"];
    if (!isSignalCode(code) || !signalAllowedForClass(code, testClass))
      throw new SecurityError("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
    const order = SIGNAL_ORDER.indexOf(code);
    const definition = SIGNAL_DEFINITIONS[code];
    if (
      order <= previousOrder ||
      signal["severity"] !== definition.severity ||
      signal["evidence"] !== definition.evidence
    )
      throw new SecurityError("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
    previousOrder = order;
    signals.push(makeSignal(code));
  }
  if (testClass === "security_txt" && signals.length !== 1)
    throw new SecurityError("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
  if (
    testClass === "cors_preflight" &&
    signals.some(
      (signal) => signal.code === "CORS_CREDENTIALS_WITH_REFLECTED_ORIGIN",
    ) &&
    !signals.some((signal) => signal.code === "CORS_REFLECTS_PROBE_ORIGIN")
  )
    throw new SecurityError("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
  return Object.freeze(signals);
}

function assertMetadataSemantics(input: {
  readonly contentType: ActiveTestRedactedContentType;
  readonly facts: ActiveTestResponseFacts;
  readonly responseBytesObserved: number;
  readonly responseDigest: string | null;
  readonly statusCode: number;
  readonly testClass: ActiveTestClass;
}): void {
  if (input.facts.kind !== input.testClass)
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_SCHEMA_INVALID");
  if (
    input.testClass === "http_headers" &&
    (input.responseBytesObserved !== 0 || input.responseDigest !== null)
  )
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_SEMANTICS_INVALID");
  if (input.testClass !== "security_txt") return;
  if (
    input.facts.kind === "security_txt" &&
    input.facts.availability === "available"
  ) {
    if (
      input.statusCode < 200 ||
      input.statusCode > 299 ||
      input.responseBytesObserved < 1 ||
      input.responseDigest === null ||
      (input.contentType !== "text/plain" &&
        input.contentType !== "application/security.txt")
    )
      throw new SecurityError("ACTIVE_TEST_EVIDENCE_SEMANTICS_INVALID");
  } else if (input.statusCode < 400) {
    throw new SecurityError("ACTIVE_TEST_EVIDENCE_SEMANTICS_INVALID");
  }
}

function assertObservationSemantics(input: {
  readonly contentType: ActiveTestRedactedContentType;
  readonly responseBytesObserved: number;
  readonly responseDigest: string | null;
  readonly signals: readonly ActiveTestSignal[];
  readonly statusCode: number;
  readonly testClass: ActiveTestClass;
}): void {
  if (
    input.testClass === "http_headers" &&
    (input.responseBytesObserved !== 0 || input.responseDigest !== null)
  )
    throw new SecurityError("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
  if (input.testClass !== "security_txt") return;
  const code = input.signals[0]?.code;
  if (
    code === "SECURITY_TXT_AVAILABLE" &&
    (input.statusCode < 200 ||
      input.statusCode > 299 ||
      input.responseBytesObserved < 1 ||
      input.responseDigest === null ||
      (input.contentType !== "text/plain" &&
        input.contentType !== "application/security.txt"))
  )
    throw new SecurityError("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
  if (code === "SECURITY_TXT_MISSING" && input.statusCode < 400)
    throw new SecurityError("ACTIVE_TEST_OBSERVATION_SCHEMA_INVALID");
}

function renderMarkdown(input: {
  readonly reportId: string;
  readonly plan: ActiveTestPlanV1;
  readonly planDigest: string;
  readonly observation: ActiveTestObservation;
  readonly observationDigest: string;
}): string {
  const signalLines =
    input.observation.signals.length === 0
      ? ["- No deterministic signal was derived."]
      : input.observation.signals.map(
          (signal) =>
            `- ${signal.code} (${signal.severity}): ${signal.evidence}`,
        );
  return [
    "# Local active-testing evidence draft",
    "",
    `- Report ID: ${input.reportId}`,
    "- Review status: local_draft_unsubmitted",
    "- External submission performed: false",
    `- Plan ID: ${input.plan.plan_id}`,
    `- Plan digest: ${input.planDigest}`,
    `- Snapshot digest: ${input.plan.snapshot_digest}`,
    `- Policy digest: ${input.plan.policy_digest}`,
    `- Asset identifier digest: ${input.plan.asset_identifier_digest}`,
    `- Response metadata digest: ${input.observation.metadataDigest}`,
    `- Observation digest: ${input.observationDigest}`,
    `- Test class: ${input.observation.testClass}`,
    `- Request method: ${input.plan.request.method}`,
    `- HTTP status: ${input.observation.statusCode}`,
    `- Duration (ms): ${input.observation.durationMs}`,
    `- Observed response bytes: ${input.observation.responseBytesObserved}`,
    `- Normalized content type: ${input.observation.contentType ?? "not_observed"}`,
    "- Redirect location present: false",
    "- TLS authorized: true",
    `- TLS protocol: ${input.observation.tls.protocol}`,
    `- TLS cipher classification: ${input.observation.tls.cipher}`,
    `- Transport kind: ${input.observation.transportKind}`,
    `- Resolution digest: ${input.observation.resolutionDigest}`,
    `- Response digest: ${input.observation.responseDigest ?? "not_available"}`,
    "- Raw body stored: false",
    "- Raw headers stored: false",
    "- Cookies stored: false",
    `- Completed at: ${input.observation.completedAt}`,
    "",
    "## Deterministic signals",
    "",
    ...signalLines,
    "",
    "This artifact is a local draft and must not be submitted automatically.",
  ].join("\n");
}

function exactRecord(
  value: unknown,
  expectedKeys: readonly string[],
  errorCode: string,
): Record<string, unknown> {
  if (!isPlainRecord(value)) throw new SecurityError(errorCode);
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string") ||
    !expectedKeys.every((key) => keys.includes(key))
  )
    throw new SecurityError(errorCode);
  const result: Record<string, unknown> = {};
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new SecurityError(errorCode);
    result[key] = descriptor.value;
  }
  return result;
}

function exactArray(
  value: unknown,
  maximumLength: number,
  errorCode: string,
): readonly unknown[] {
  if (
    !Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Array.prototype ||
    !Number.isSafeInteger(value.length) ||
    value.length > maximumLength
  )
    throw new SecurityError(errorCode);
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== value.length + 1 ||
    keys.some(
      (key) =>
        typeof key !== "string" ||
        (key !== "length" && !/^(?:0|[1-9][0-9]*)$/u.test(key)),
    )
  )
    throw new SecurityError(errorCode);
  const result: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new SecurityError(errorCode);
    result.push(descriptor.value);
  }
  return result;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    !types.isProxy(value) &&
    Reflect.getPrototypeOf(value) === Object.prototype
  );
}

function isFrozenPlainRecord(value: unknown): boolean {
  return isPlainRecord(value) && Object.isFrozen(value);
}

function isIntegerBetween(
  value: unknown,
  minimum: number,
  maximum: number,
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= minimum &&
    value <= maximum
  );
}

function canonicalTimestamp(value: unknown, errorCode: string): string {
  if (typeof value !== "string") throw new SecurityError(errorCode);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value)
    throw new SecurityError(errorCode);
  return value;
}

function isActiveTestClass(value: unknown): value is ActiveTestClass {
  return (
    value === "cors_preflight" ||
    value === "http_headers" ||
    value === "security_txt"
  );
}

function isRedactedContentType(
  value: unknown,
): value is ActiveTestRedactedContentType {
  return (
    value === null ||
    value === "application/json" ||
    value === "application/security.txt" ||
    value === "text/html" ||
    value === "text/plain"
  );
}

function isTlsProtocol(value: unknown): value is ActiveTestTlsProtocol {
  return value === "TLSv1.2" || value === "TLSv1.3";
}

function isTlsCipherClassification(
  value: unknown,
): value is ActiveTestTlsCipherClassification {
  return value === "modern" || value === "other_redacted";
}

function isTransportKind(
  value: unknown,
): value is ActiveTestRedactedResponseMetadata["transport"]["kind"] {
  return value === "production_https" || value === "loopback_test";
}

function isCorsOriginClassification(
  value: unknown,
): value is Extract<
  ActiveTestResponseFacts,
  { readonly kind: "cors_preflight" }
>["allowOrigin"] {
  return (
    value === "absent" ||
    value === "other_redacted" ||
    value === "probe_origin" ||
    value === "wildcard"
  );
}

function isSignalCode(value: unknown): value is SignalCode {
  return (
    value === "CORS_CREDENTIALS_WITH_REFLECTED_ORIGIN" ||
    value === "CORS_REFLECTS_PROBE_ORIGIN" ||
    value === "HEADER_CONTENT_SECURITY_POLICY_MISSING" ||
    value === "HEADER_HSTS_MISSING" ||
    value === "HEADER_X_CONTENT_TYPE_OPTIONS_MISSING" ||
    value === "INSECURE_COOKIE_FLAGS_OBSERVED" ||
    value === "SECURITY_TXT_AVAILABLE" ||
    value === "SECURITY_TXT_MISSING"
  );
}

function signalAllowedForClass(
  code: SignalCode,
  testClass: ActiveTestClass,
): boolean {
  if (testClass === "cors_preflight") return code.startsWith("CORS_");
  if (testClass === "http_headers")
    return (
      code.startsWith("HEADER_") || code === "INSECURE_COOKIE_FLAGS_OBSERVED"
    );
  return code === "SECURITY_TXT_AVAILABLE" || code === "SECURITY_TXT_MISSING";
}
