import { SecurityError } from "../shared/errors.js";

const SENSITIVE_MATERIAL = Object.freeze([
  /\b(?:bearer|basic)\s+[A-Za-z0-9+/_=.:-]{8,}\b/iu,
  /\bauthorization\s*:\s*[^\r\n]{4,}/iu,
  /\b(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|x-api-key|token|access[_-]?token|refresh[_-]?token|private[_-]?token|session[_-]?cookie)\s*[:=]\s*["']?[^\s"',;]{4,}/iu,
  /\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|h1_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b/u,
  /\b(?:cookie|set-cookie)\s*:\s*[^\r\n=;]{1,128}=[^\s;,]{4,}/iu,
  /\b(?:session|sessionid|sid)\s*=\s*[^\s;,]{4,}/iu,
  /\botpauth:\/\/[^\s]+/iu,
  /\b(?:totp|otp[_-]?secret)\s*[:=]\s*[^\s;,]{4,}/iu,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
]);

export function assertNoSensitiveMaterial(
  values: readonly string[],
  code: string,
): void {
  if (
    values.some((value) =>
      SENSITIVE_MATERIAL.some((pattern) => pattern.test(value)),
    )
  )
    throw new SecurityError(code);
}
