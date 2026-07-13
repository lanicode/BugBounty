import type { EgressDecision, EgressPolicy, EgressRequest } from "./types.js";
import { isLoopback, normalizeUrl, pathMatchesPrefix } from "./normalize.js";

function blocked(reason: EgressDecision["reason"]): EgressDecision {
  return { allow: false, reason, assetKind: "none" };
}

export function decideEgress(
  policy: EgressPolicy,
  request: EgressRequest,
): EgressDecision {
  if (request.isRedirect) return blocked("BLOCK_REDIRECT");
  let normalized: ReturnType<typeof normalizeUrl>;
  try {
    normalized = normalizeUrl(request.url);
  } catch (error) {
    return blocked(
      error instanceof Error && error.message === "URL_USERINFO"
        ? "BLOCK_USERINFO"
        : error instanceof Error && error.message === "URL_SCHEME"
          ? "BLOCK_SCHEME"
          : "BLOCK_BAD_URL",
    );
  }
  const method = request.method.toUpperCase();
  const details = { ...normalized, method };
  if (
    normalized.scheme === "http" &&
    !(
      policy.localTestMode === true &&
      policy.config.network.allow_plain_http &&
      isLoopback(normalized.host)
    )
  )
    return blocked("BLOCK_HTTP");
  if ((policy.config.network.blocked_hosts ?? []).includes(normalized.host))
    return blocked("BLOCK_HOST");

  const target = policy.config.network.targets.find(
    (entry) =>
      entry.host === normalized.host && entry.scheme === normalized.scheme,
  );
  if (target !== undefined) {
    if (!target.ports.includes(normalized.port)) return blocked("BLOCK_PORT");
    if (
      !target.path_prefixes.some((prefix) =>
        pathMatchesPrefix(normalized.path, prefix),
      )
    )
      return blocked("BLOCK_PATH");
    if (!["GET", "HEAD", "OPTIONS"].includes(method))
      return blocked("BLOCK_METHOD");
    if (
      request.captureMode !== "redacted" &&
      request.captureMode !== "metadata_only"
    )
      return blocked("BLOCK_CAPTURE_MODE");
    return {
      allow: true,
      reason: "ALLOW_TARGET",
      assetKind: "target",
      normalized: details,
    };
  }

  const supporting = policy.config.network.supporting_hosts.find(
    (entry) =>
      entry.host === normalized.host && entry.scheme === normalized.scheme,
  );
  if (supporting === undefined) return blocked("BLOCK_HOST");
  if (!supporting.ports.includes(normalized.port)) return blocked("BLOCK_PORT");
  if (
    !isSupportingMethod(method) ||
    !supporting.allowed_methods.includes(method)
  )
    return blocked("BLOCK_METHOD");
  if (request.captureMode !== supporting.capture)
    return blocked("BLOCK_CAPTURE_MODE");
  return {
    allow: true,
    reason: "ALLOW_SUPPORTING_HOST",
    assetKind: "supporting",
    normalized: details,
  };
}

function isSupportingMethod(
  method: string,
): method is "GET" | "HEAD" | "OPTIONS" | "POST" {
  return (
    method === "GET" ||
    method === "HEAD" ||
    method === "OPTIONS" ||
    method === "POST"
  );
}
