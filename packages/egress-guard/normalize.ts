import { domainToASCII } from "node:url";
import { SecurityError } from "../shared/errors.js";

const MAX_DECODE_PASSES = 4;

export function normalizeRequestPath(input: string): string {
  let decoded = input;
  for (let pass = 0; pass < MAX_DECODE_PASSES; pass += 1) {
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      throw new SecurityError("PATH_ENCODING_INVALID");
    }
    if (next === decoded) break;
    decoded = next;
    if (pass === MAX_DECODE_PASSES - 1 && /%[0-9a-f]{2}/i.test(decoded))
      throw new SecurityError("PATH_ENCODING_AMBIGUOUS");
  }
  if (
    decoded.includes("\\") ||
    decoded.includes("\0") ||
    /[\u0000-\u001f\u007f]/u.test(decoded)
  )
    throw new SecurityError("PATH_CHARACTER_INVALID");
  const segments = decoded.split("/");
  if (segments.some((segment) => segment === "." || segment === ".."))
    throw new SecurityError("PATH_TRAVERSAL");
  const collapsed = `/${segments.filter(Boolean).join("/")}`;
  return decoded.endsWith("/") && collapsed !== "/"
    ? `${collapsed}/`
    : collapsed;
}

export function normalizeUrl(raw: string): {
  scheme: "http" | "https";
  host: string;
  port: number;
  path: string;
} {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SecurityError("URL_INVALID");
  }
  if (url.username !== "" || url.password !== "")
    throw new SecurityError("URL_USERINFO");
  if (url.hash !== "") throw new SecurityError("URL_FRAGMENT");
  if (url.protocol !== "https:" && url.protocol !== "http:")
    throw new SecurityError("URL_SCHEME");
  const scheme: "http" | "https" = url.protocol === "https:" ? "https" : "http";
  const rawAuthority =
    raw.slice(raw.indexOf("//") + 2).split(/[/?#]/u, 1)[0] ?? "";
  if (
    rawAuthority.endsWith(".") ||
    rawAuthority.includes("%") ||
    /[^\x00-\x7f]/u.test(rawAuthority)
  )
    throw new SecurityError("HOST_NON_CANONICAL");
  const host = url.hostname.toLowerCase();
  const ascii = domainToASCII(host);
  if (
    ascii === "" ||
    ascii !== host ||
    host.endsWith(".") ||
    host.includes("%")
  )
    throw new SecurityError("HOST_NON_CANONICAL");
  if (host.includes(":") && !rawAuthority.startsWith("["))
    throw new SecurityError("HOST_IPV6_AMBIGUOUS");
  const port =
    url.port === "" ? (scheme === "https" ? 443 : 80) : Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new SecurityError("PORT_INVALID");
  const afterAuthority = raw.slice(raw.indexOf("//") + 2 + rawAuthority.length);
  const rawPath = (afterAuthority.split(/[?#]/u, 1)[0] ?? "") || "/";
  return { scheme, host, port, path: normalizeRequestPath(rawPath) };
}

export function isLoopback(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

export function pathMatchesPrefix(path: string, rawPrefix: string): boolean {
  const prefix = normalizeRequestPath(rawPrefix);
  if (prefix === "/") return true;
  if (prefix.endsWith("/")) return path.startsWith(prefix);
  return path === prefix || path.startsWith(`${prefix}/`);
}
