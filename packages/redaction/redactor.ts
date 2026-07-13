import { createHmac } from "node:crypto";
import { sha256, type JsonValue } from "../shared/canonical.js";

const SENSITIVE_NAMES =
  /^(?:authorization|cookie|set-cookie|proxy-authorization|x-api-key)$/i;
const SENSITIVE_FIELDS =
  /(?:pass(?:word|wd)?|secret|token|api[_-]?key|authorization|cookie|session|credential|email|phone)/i;
const SENSITIVE_QUERY =
  /^(?:token|access_token|refresh_token|api_key|key|code|password|session|auth)$/i;
const EMAIL = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]+/giu;
const ALLOWED_HEADERS = new Set([
  "accept",
  "accept-language",
  "content-length",
  "content-type",
  "origin",
  "referer",
  "user-agent",
]);

export interface RedactedBody {
  readonly disposition: "metadata_only" | "quarantine" | "redacted";
  readonly byteLength: number;
  readonly sha256: string;
  readonly contentType?: string;
  readonly text?: string;
  readonly json?: JsonValue;
  readonly reason?: string;
}

export class Pseudonymizer {
  public constructor(private readonly key: Uint8Array) {
    if (key.byteLength < 32) throw new Error("PSEUDONYM_KEY_TOO_SHORT");
  }

  public pseudonym(value: string): string {
    return `p:${createHmac("sha256", this.key).update(value.normalize("NFKC")).digest("hex").slice(0, 24)}`;
  }
}

export function redactText(text: string, pseudonymizer: Pseudonymizer): string {
  return text
    .replace(BEARER, "[REDACTED]")
    .replace(EMAIL, (email) => pseudonymizer.pseudonym(email.toLowerCase()));
}

export function redactJson(
  value: JsonValue,
  pseudonymizer: Pseudonymizer,
): JsonValue {
  if (Array.isArray(value))
    return value.map((item) => redactJson(item, pseudonymizer));
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [
        key,
        SENSITIVE_FIELDS.test(key)
          ? "[REDACTED]"
          : redactJson(child, pseudonymizer),
      ]),
    );
  }
  return typeof value === "string" ? redactText(value, pseudonymizer) : value;
}

export function redactHeaders(
  headers: Readonly<Record<string, string>>,
): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  for (const [rawName, value] of Object.entries(headers)) {
    const name = rawName.toLowerCase();
    if (SENSITIVE_NAMES.test(name) || !ALLOWED_HEADERS.has(name)) continue;
    result[name] =
      SENSITIVE_FIELDS.test(value) || BEARER.test(value)
        ? "[REDACTED]"
        : value.slice(0, 1024);
    BEARER.lastIndex = 0;
  }
  return result;
}

export function redactUrl(raw: string): string {
  const url = new URL(raw);
  for (const key of [...url.searchParams.keys()])
    if (SENSITIVE_QUERY.test(key)) url.searchParams.set(key, "[REDACTED]");
  url.username = "";
  url.password = "";
  url.hash = "";
  return url.toString();
}

function containsUnknownIdentity(value: JsonValue): boolean {
  if (Array.isArray(value)) return value.some(containsUnknownIdentity);
  if (value !== null && typeof value === "object")
    return Object.entries(value).some(
      ([key, child]) =>
        /(?:ssn|passport|credit_card|iban|tenant_id|user_id)/i.test(key) ||
        containsUnknownIdentity(child),
    );
  return false;
}

export function processBody(
  body: Uint8Array,
  headers: Readonly<Record<string, string>>,
  options: {
    readonly maxBytes: number;
    readonly allowedContentTypes: readonly string[];
    readonly pseudonymizer: Pseudonymizer;
  },
): RedactedBody {
  const digest = sha256(body);
  const contentType = Object.entries(headers)
    .find(([key]) => key.toLowerCase() === "content-type")?.[1]
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase();
  const encoding = Object.entries(headers).find(
    ([key]) => key.toLowerCase() === "content-encoding",
  )?.[1];
  const metadata = (
    reason: string,
    disposition: "metadata_only" | "quarantine" = "metadata_only",
  ): RedactedBody => ({
    disposition,
    byteLength: body.byteLength,
    sha256: digest,
    ...(contentType === undefined ? {} : { contentType }),
    reason,
  });
  if (body.byteLength > options.maxBytes) return metadata("BODY_TOO_LARGE");
  if (encoding !== undefined && encoding.toLowerCase() !== "identity")
    return metadata("BODY_COMPRESSED");
  if (
    contentType === undefined ||
    !options.allowedContentTypes.includes(contentType)
  )
    return metadata("BODY_CONTENT_TYPE_BLOCKED");
  if (
    contentType.startsWith("multipart/") ||
    contentType === "application/x-www-form-urlencoded"
  )
    return metadata("BODY_FORM_BLOCKED");
  const decoded = new TextDecoder("utf-8", { fatal: true });
  let text: string;
  try {
    text = decoded.decode(body);
  } catch {
    return metadata("BODY_BINARY");
  }
  if (contentType === "application/json" || contentType.endsWith("+json")) {
    let unknownParsed: unknown;
    try {
      unknownParsed = JSON.parse(text) as unknown;
    } catch {
      return metadata("BODY_JSON_INVALID");
    }
    if (!isJsonValue(unknownParsed)) return metadata("BODY_JSON_INVALID");
    const parsed: JsonValue = unknownParsed;
    if (containsUnknownIdentity(parsed))
      return metadata("UNKNOWN_IDENTITY", "quarantine");
    return {
      disposition: "redacted",
      byteLength: body.byteLength,
      sha256: digest,
      contentType,
      json: redactJson(parsed, options.pseudonymizer),
    };
  }
  return {
    disposition: "redacted",
    byteLength: body.byteLength,
    sha256: digest,
    contentType,
    text: redactText(text, options.pseudonymizer).slice(0, options.maxBytes),
  };
}

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (typeof value === "object") return Object.values(value).every(isJsonValue);
  return false;
}
