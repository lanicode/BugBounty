import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { types } from "node:util";
import { canonicalJson, sha256 } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

export const ACTIVE_TEST_RESOLVED_EGRESS_VERSION = 1 as const;
export const ACTIVE_TEST_MAX_RESOLVED_ADDRESSES = 16 as const;

export type ActiveTestAddressFamily = 4 | 6;

export interface ActiveTestResolvedAddress {
  readonly address: string;
  readonly family: ActiveTestAddressFamily;
}

export interface ActiveTestResolvedEgressInput {
  readonly host: string;
  readonly port: 443;
  readonly addresses: readonly ActiveTestResolvedAddress[];
}

export interface ActiveTestResolvedEgressAuthorization {
  readonly version: typeof ACTIVE_TEST_RESOLVED_EGRESS_VERSION;
  readonly host: string;
  readonly port: 443;
  readonly family: ActiveTestAddressFamily;
  readonly addresses: readonly string[];
  readonly selectedAddress: string;
  readonly selectionPolicy: "prefer_ipv4_then_lowest_v1";
  readonly resolutionDigest: string;
}

export type ActiveTestAddressBlockReason =
  | "ACTIVE_TEST_RESOLUTION_CGNAT_BLOCKED"
  | "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"
  | "ACTIVE_TEST_RESOLUTION_IPV4_MAPPED_BLOCKED"
  | "ACTIVE_TEST_RESOLUTION_LINK_LOCAL_BLOCKED"
  | "ACTIVE_TEST_RESOLUTION_LOOPBACK_BLOCKED"
  | "ACTIVE_TEST_RESOLUTION_MULTICAST_BLOCKED"
  | "ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED"
  | "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED";

interface ParsedAddress {
  readonly canonical: string;
  readonly family: ActiveTestAddressFamily;
  readonly numeric: bigint;
}

interface AddressRange {
  readonly base: bigint;
  readonly prefix: number;
  readonly reason: ActiveTestAddressBlockReason;
}

const trustedAuthorizations = new WeakSet();
const SPECIAL_USE_HOST_SUFFIXES = Object.freeze([
  "alt",
  "arpa",
  "corp",
  "example",
  "home",
  "home.arpa",
  "internal",
  "invalid",
  "lan",
  "local",
  "localdomain",
  "localhost",
  "onion",
  "test",
]);
const RESERVED_EXAMPLE_DOMAINS = Object.freeze([
  "example.com",
  "example.net",
  "example.org",
]);

const IPV4_RANGES: readonly AddressRange[] = Object.freeze([
  range4("0.0.0.0", 8, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range4("10.0.0.0", 8, "ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED"),
  range4("100.64.0.0", 10, "ACTIVE_TEST_RESOLUTION_CGNAT_BLOCKED"),
  range4("127.0.0.0", 8, "ACTIVE_TEST_RESOLUTION_LOOPBACK_BLOCKED"),
  range4("169.254.0.0", 16, "ACTIVE_TEST_RESOLUTION_LINK_LOCAL_BLOCKED"),
  range4("172.16.0.0", 12, "ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED"),
  range4("192.0.0.0", 24, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range4("192.0.2.0", 24, "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"),
  range4("192.31.196.0", 24, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range4("192.52.193.0", 24, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range4("192.88.99.0", 24, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range4("192.168.0.0", 16, "ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED"),
  range4("192.175.48.0", 24, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range4("198.18.0.0", 15, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range4("198.51.100.0", 24, "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"),
  range4("203.0.113.0", 24, "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"),
  range4("224.0.0.0", 4, "ACTIVE_TEST_RESOLUTION_MULTICAST_BLOCKED"),
  range4("240.0.0.0", 4, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
]);

const IPV6_RANGES: readonly AddressRange[] = Object.freeze([
  range6("::", 96, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range6("64:ff9b::", 96, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range6("64:ff9b:1::", 48, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range6("100::", 64, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range6("2001::", 23, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range6("2001:db8::", 32, "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"),
  range6("2002::", 16, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range6("2620:4f:8000::", 48, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range6("3fff::", 20, "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"),
  range6("fc00::", 7, "ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED"),
  range6("fe80::", 10, "ACTIVE_TEST_RESOLUTION_LINK_LOCAL_BLOCKED"),
  range6("fec0::", 10, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"),
  range6("ff00::", 8, "ACTIVE_TEST_RESOLUTION_MULTICAST_BLOCKED"),
]);

/**
 * Validates already-resolved DNS answers without performing DNS or any other
 * I/O. Every answer must be public. A single blocked, duplicate, or malformed
 * answer rejects the complete set. Dual-stack answers remain fully bound in
 * the digest; the runner deterministically prefers IPv4, then the numerically
 * lowest address, so callers may never select a permissive subset themselves.
 */
export function authorizeActiveTestResolvedEgress(
  value: unknown,
): ActiveTestResolvedEgressAuthorization {
  const input = captureInput(value);
  const parsed = input.addresses.map(parseAddress);
  for (const address of parsed) assertPublic(address);

  const ordered = [...parsed].sort((left, right) => {
    if (left.family !== right.family) return left.family - right.family;
    return left.numeric < right.numeric
      ? -1
      : left.numeric > right.numeric
        ? 1
        : 0;
  });
  const addresses = Object.freeze(ordered.map(({ canonical }) => canonical));
  if (new Set(addresses).size !== addresses.length)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_DUPLICATE_BLOCKED");

  const selected = ordered.find(({ family }) => family === 4) ?? ordered[0];
  const family = requiredFamily(selected?.family);
  const selectedAddress = requiredAddress(selected?.canonical);
  const material = Object.freeze({
    version: ACTIVE_TEST_RESOLVED_EGRESS_VERSION,
    host: input.host,
    port: 443 as const,
    family,
    addresses,
    selectedAddress,
    selectionPolicy: "prefer_ipv4_then_lowest_v1" as const,
  });
  const authorization = Object.freeze({
    ...material,
    resolutionDigest: sha256(canonicalJson(material)),
  });
  trustedAuthorizations.add(authorization);
  return authorization;
}

export function isTrustedActiveTestResolvedEgressAuthorization(
  value: unknown,
): value is ActiveTestResolvedEgressAuthorization {
  if (typeof value !== "object" || value === null) return false;
  try {
    return (
      !types.isProxy(value) &&
      Reflect.getPrototypeOf(value) === Object.prototype &&
      Object.isFrozen(value) &&
      trustedAuthorizations.has(value)
    );
  } catch {
    return false;
  }
}

function captureInput(value: unknown): ActiveTestResolvedEgressInput {
  const record = exactDataRecord(value, ["addresses", "host", "port"]);
  const host = canonicalizeActiveTestDnsHost(record["host"]);
  if (record["port"] !== 443)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_PORT_BLOCKED");
  const addresses = captureAddressArray(record["addresses"]);
  return Object.freeze({ host, port: 443, addresses });
}

function captureAddressArray(
  value: unknown,
): readonly ActiveTestResolvedAddress[] {
  if (
    !Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Array.prototype
  )
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_INPUT_INVALID");
  if (value.length === 0)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_EMPTY");
  if (value.length > ACTIVE_TEST_MAX_RESOLVED_ADDRESSES)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_LIMIT_EXCEEDED");
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== value.length + 1 ||
    keys.some(
      (key) =>
        typeof key !== "string" ||
        (key !== "length" && !/^(?:0|[1-9][0-9]*)$/u.test(key)),
    )
  )
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_INPUT_INVALID");
  const captured: ActiveTestResolvedAddress[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new SecurityError("ACTIVE_TEST_RESOLUTION_INPUT_INVALID");
    const record = exactDataRecord(descriptor.value, ["address", "family"]);
    const address = record["address"];
    const family = record["family"];
    if (typeof address !== "string" || (family !== 4 && family !== 6))
      throw new SecurityError("ACTIVE_TEST_RESOLUTION_ADDRESS_INVALID");
    captured.push(Object.freeze({ address, family }));
  }
  return Object.freeze(captured);
}

/** Pure pre-DNS host validation shared by planning and production transport. */
export function canonicalizeActiveTestDnsHost(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 3 ||
    value.length > 253 ||
    value !== value.toLowerCase() ||
    value.endsWith(".") ||
    value.includes("%") ||
    /[^\x00-\x7f]/u.test(value) ||
    isIP(value) !== 0 ||
    domainToASCII(value) !== value
  )
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_HOST_INVALID");
  const labels = value.split(".");
  if (
    labels.length < 2 ||
    labels.some(
      (label) =>
        label.length < 1 ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label),
    )
  )
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_HOST_INVALID");
  if (
    SPECIAL_USE_HOST_SUFFIXES.some(
      (suffix) => value === suffix || value.endsWith(`.${suffix}`),
    ) ||
    RESERVED_EXAMPLE_DOMAINS.some(
      (domain) => value === domain || value.endsWith(`.${domain}`),
    )
  )
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_HOST_SPECIAL_USE_BLOCKED");
  return value;
}

function parseAddress(value: ActiveTestResolvedAddress): ParsedAddress {
  if (value.address.includes("%"))
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_ZONE_ID_BLOCKED");
  const detected = isIP(value.address);
  if (detected !== value.family)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_FAMILY_MISMATCH");
  if (value.family === 4) {
    const parsed = parseIpv4(value.address);
    return Object.freeze({ ...parsed, family: 4 as const });
  }
  const parsed = parseIpv6(value.address);
  return Object.freeze({ ...parsed, family: 6 as const });
}

function assertPublic(address: ParsedAddress): void {
  if (address.family === 4) {
    const blocked = matchingRange(address.numeric, IPV4_RANGES, 32);
    if (blocked !== undefined) throw new SecurityError(blocked.reason);
    return;
  }
  if (address.numeric >> 32n === 0xffffn)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_IPV4_MAPPED_BLOCKED");
  if (address.numeric === 0n)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED");
  if (address.numeric === 1n)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_LOOPBACK_BLOCKED");
  const blocked = matchingRange(address.numeric, IPV6_RANGES, 128);
  if (blocked !== undefined) throw new SecurityError(blocked.reason);
  if (!inPrefix(address.numeric, parseIpv6("2000::").numeric, 3, 128))
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED");
}

function parseIpv4(value: string): {
  readonly canonical: string;
  readonly numeric: bigint;
} {
  const parts = value.split(".");
  if (
    parts.length !== 4 ||
    parts.some(
      (part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part) || Number(part) > 255,
    )
  )
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_ADDRESS_INVALID");
  const numbers = parts.map(Number);
  let numeric = 0n;
  for (const part of numbers) numeric = (numeric << 8n) | BigInt(part);
  return Object.freeze({
    canonical: numbers.join("."),
    numeric,
  });
}

function parseIpv6(value: string): {
  readonly canonical: string;
  readonly numeric: bigint;
} {
  if (value.includes("%"))
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_ZONE_ID_BLOCKED");
  let source = value.toLowerCase();
  if (source.includes(".")) {
    const separator = source.lastIndexOf(":");
    if (separator < 0)
      throw new SecurityError("ACTIVE_TEST_RESOLUTION_ADDRESS_INVALID");
    const ipv4 = parseIpv4(source.slice(separator + 1));
    const upper = Number((ipv4.numeric >> 16n) & 0xffffn).toString(16);
    const lower = Number(ipv4.numeric & 0xffffn).toString(16);
    source = `${source.slice(0, separator)}:${upper}:${lower}`;
  }
  const halves = source.split("::");
  if (halves.length > 2)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_ADDRESS_INVALID");
  const left = splitHextets(halves[0] ?? "");
  const right = splitHextets(halves[1] ?? "");
  const omitted = 8 - left.length - right.length;
  if (
    (halves.length === 1 && omitted !== 0) ||
    (halves.length === 2 && omitted < 1)
  )
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_ADDRESS_INVALID");
  const hextets = [
    ...left,
    ...Array.from({ length: omitted }, () => 0),
    ...right,
  ];
  if (hextets.length !== 8)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_ADDRESS_INVALID");
  let numeric = 0n;
  for (const hextet of hextets) numeric = (numeric << 16n) | BigInt(hextet);
  return Object.freeze({ canonical: canonicalIpv6(hextets), numeric });
}

function splitHextets(value: string): number[] {
  if (value === "") return [];
  const parts = value.split(":");
  if (
    parts.some(
      (part) =>
        !/^[0-9a-f]{1,4}$/u.test(part) || Number.parseInt(part, 16) > 0xffff,
    )
  )
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_ADDRESS_INVALID");
  return parts.map((part) => Number.parseInt(part, 16));
}

function canonicalIpv6(hextets: readonly number[]): string {
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < hextets.length;) {
    if (hextets[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < hextets.length && hextets[end] === 0) end += 1;
    const length = end - index;
    if (length >= 2 && length > bestLength) {
      bestStart = index;
      bestLength = length;
    }
    index = end;
  }
  if (bestStart < 0) return hextets.map((part) => part.toString(16)).join(":");
  const before = hextets
    .slice(0, bestStart)
    .map((part) => part.toString(16))
    .join(":");
  const after = hextets
    .slice(bestStart + bestLength)
    .map((part) => part.toString(16))
    .join(":");
  return `${before}::${after}`;
}

function matchingRange(
  value: bigint,
  ranges: readonly AddressRange[],
  bits: number,
): AddressRange | undefined {
  return ranges.find(({ base, prefix }) => inPrefix(value, base, prefix, bits));
}

function inPrefix(
  value: bigint,
  base: bigint,
  prefix: number,
  bits: number,
): boolean {
  const shift = BigInt(bits - prefix);
  return value >> shift === base >> shift;
}

function range4(
  base: string,
  prefix: number,
  reason: ActiveTestAddressBlockReason,
): AddressRange {
  return Object.freeze({ base: parseIpv4(base).numeric, prefix, reason });
}

function range6(
  base: string,
  prefix: number,
  reason: ActiveTestAddressBlockReason,
): AddressRange {
  return Object.freeze({ base: parseIpv6(base).numeric, prefix, reason });
}

function exactDataRecord(
  value: unknown,
  expectedKeys: readonly string[],
): Readonly<Record<string, unknown>> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    types.isProxy(value) ||
    Reflect.getPrototypeOf(value) !== Object.prototype
  )
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_INPUT_INVALID");
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key) => typeof key !== "string") ||
    !expectedKeys.every((key) => keys.includes(key))
  )
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_INPUT_INVALID");
  const result: Record<string, unknown> = {};
  for (const key of expectedKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    )
      throw new SecurityError("ACTIVE_TEST_RESOLUTION_INPUT_INVALID");
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function requiredFamily(
  value: ActiveTestAddressFamily | undefined,
): ActiveTestAddressFamily {
  if (value !== 4 && value !== 6)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_EMPTY");
  return value;
}

function requiredAddress(value: string | undefined): string {
  if (value === undefined)
    throw new SecurityError("ACTIVE_TEST_RESOLUTION_EMPTY");
  return value;
}
