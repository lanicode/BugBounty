import { describe, expect, it } from "vitest";
import {
  ACTIVE_TEST_MAX_RESOLVED_ADDRESSES,
  authorizeActiveTestResolvedEgress,
  canonicalizeActiveTestDnsHost,
  isTrustedActiveTestResolvedEgressAuthorization,
} from "../../../packages/active-testing/resolved-egress.js";

const input = (
  addresses: readonly { readonly address: string; readonly family: 4 | 6 }[],
) => ({
  host: "synthetic-target.bounty-safe.dev",
  port: 443 as const,
  addresses,
});

describe("active-test resolved egress", () => {
  it("authorizes, canonicalizes and deterministically selects public IPv4", () => {
    const first = authorizeActiveTestResolvedEgress(
      input([
        { address: "8.8.8.8", family: 4 },
        { address: "1.1.1.1", family: 4 },
      ]),
    );
    const reordered = authorizeActiveTestResolvedEgress(
      input([
        { address: "1.1.1.1", family: 4 },
        { address: "8.8.8.8", family: 4 },
      ]),
    );

    expect(first).toMatchObject({
      version: 1,
      host: "synthetic-target.bounty-safe.dev",
      port: 443,
      family: 4,
      addresses: ["1.1.1.1", "8.8.8.8"],
      selectedAddress: "1.1.1.1",
      selectionPolicy: "prefer_ipv4_then_lowest_v1",
    });
    expect(first.resolutionDigest).toBe(reordered.resolutionDigest);
    expect(first.resolutionDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.addresses)).toBe(true);
    expect(isTrustedActiveTestResolvedEgressAuthorization(first)).toBe(true);
    expect(
      isTrustedActiveTestResolvedEgressAuthorization(
        Object.freeze({ ...first }),
      ),
    ).toBe(false);
  });

  it("canonicalizes equivalent public IPv6 answers before hashing", () => {
    const expanded = authorizeActiveTestResolvedEgress(
      input([
        {
          address: "2606:4700:4700:0000:0000:0000:0000:1111",
          family: 6,
        },
        { address: "2001:4860:4860::8888", family: 6 },
      ]),
    );
    const compressed = authorizeActiveTestResolvedEgress(
      input([
        { address: "2606:4700:4700::1111", family: 6 },
        { address: "2001:4860:4860:0:0:0:0:8888", family: 6 },
      ]),
    );

    expect(expanded.addresses).toEqual([
      "2001:4860:4860::8888",
      "2606:4700:4700::1111",
    ]);
    expect(expanded.selectedAddress).toBe("2001:4860:4860::8888");
    expect(expanded.resolutionDigest).toBe(compressed.resolutionDigest);
  });

  it.each([
    ["0.1.2.3", 4, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"],
    ["10.0.0.1", 4, "ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED"],
    ["100.64.0.1", 4, "ACTIVE_TEST_RESOLUTION_CGNAT_BLOCKED"],
    ["127.0.0.1", 4, "ACTIVE_TEST_RESOLUTION_LOOPBACK_BLOCKED"],
    ["169.254.1.1", 4, "ACTIVE_TEST_RESOLUTION_LINK_LOCAL_BLOCKED"],
    ["172.31.255.255", 4, "ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED"],
    ["192.0.0.9", 4, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"],
    ["192.0.2.1", 4, "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"],
    ["192.168.1.1", 4, "ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED"],
    ["198.18.0.1", 4, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"],
    ["198.51.100.1", 4, "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"],
    ["203.0.113.1", 4, "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"],
    ["224.0.0.1", 4, "ACTIVE_TEST_RESOLUTION_MULTICAST_BLOCKED"],
    ["255.255.255.255", 4, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"],
    ["::", 6, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"],
    ["::1", 6, "ACTIVE_TEST_RESOLUTION_LOOPBACK_BLOCKED"],
    ["::ffff:192.0.2.1", 6, "ACTIVE_TEST_RESOLUTION_IPV4_MAPPED_BLOCKED"],
    ["64:ff9b::808:808", 6, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"],
    ["100::1", 6, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"],
    ["2001::1", 6, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"],
    ["2001:db8::1", 6, "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"],
    ["2002::1", 6, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"],
    ["3fff::1", 6, "ACTIVE_TEST_RESOLUTION_DOCUMENTATION_BLOCKED"],
    ["fc00::1", 6, "ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED"],
    ["fdff::1", 6, "ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED"],
    ["fe80::1", 6, "ACTIVE_TEST_RESOLUTION_LINK_LOCAL_BLOCKED"],
    ["fec0::1", 6, "ACTIVE_TEST_RESOLUTION_RESERVED_BLOCKED"],
    ["ff02::1", 6, "ACTIVE_TEST_RESOLUTION_MULTICAST_BLOCKED"],
  ] as const)("blocks non-public address %s", (address, family, code) => {
    expect(() =>
      authorizeActiveTestResolvedEgress(input([{ address, family }])),
    ).toThrow(code);
  });

  it("rejects zone ids and mixed public/private sets while binding safe dual stack", () => {
    expect(() =>
      authorizeActiveTestResolvedEgress(
        input([{ address: "fe80::1%lo0", family: 6 }]),
      ),
    ).toThrow("ACTIVE_TEST_RESOLUTION_ZONE_ID_BLOCKED");
    expect(
      authorizeActiveTestResolvedEgress(
        input([
          { address: "2606:4700:4700::1111", family: 6 },
          { address: "1.1.1.1", family: 4 },
        ]),
      ),
    ).toMatchObject({
      family: 4,
      selectedAddress: "1.1.1.1",
      addresses: ["1.1.1.1", "2606:4700:4700::1111"],
      selectionPolicy: "prefer_ipv4_then_lowest_v1",
    });
    expect(() =>
      authorizeActiveTestResolvedEgress(
        input([
          { address: "1.1.1.1", family: 4 },
          { address: "10.0.0.1", family: 4 },
        ]),
      ),
    ).toThrow("ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED");
  });

  it("rejects empty, duplicate, oversized, malformed and mismatched sets", () => {
    expect(() => authorizeActiveTestResolvedEgress(input([]))).toThrow(
      "ACTIVE_TEST_RESOLUTION_EMPTY",
    );
    expect(() =>
      authorizeActiveTestResolvedEgress(
        input([
          { address: "1.1.1.1", family: 4 },
          { address: "1.1.1.1", family: 4 },
        ]),
      ),
    ).toThrow("ACTIVE_TEST_RESOLUTION_DUPLICATE_BLOCKED");
    expect(() =>
      authorizeActiveTestResolvedEgress(
        input(
          Array.from(
            { length: ACTIVE_TEST_MAX_RESOLVED_ADDRESSES + 1 },
            (_, index) => ({
              address: `8.8.8.${String(index + 1)}`,
              family: 4,
            }),
          ),
        ),
      ),
    ).toThrow("ACTIVE_TEST_RESOLUTION_LIMIT_EXCEEDED");
    expect(() =>
      authorizeActiveTestResolvedEgress(
        input([{ address: "999.1.1.1", family: 4 }]),
      ),
    ).toThrow("ACTIVE_TEST_RESOLUTION_FAMILY_MISMATCH");
    expect(() =>
      authorizeActiveTestResolvedEgress(
        input([{ address: "1.1.1.1", family: 6 }]),
      ),
    ).toThrow("ACTIVE_TEST_RESOLUTION_FAMILY_MISMATCH");
  });

  it("accepts exactly sixteen unique public answers", () => {
    const addresses = Array.from({ length: 16 }, (_, index) => ({
      address: `8.8.8.${String(index + 1)}`,
      family: 4 as const,
    }));
    expect(
      authorizeActiveTestResolvedEgress(input(addresses)).addresses,
    ).toHaveLength(16);
  });

  it("rejects noncanonical hosts, non-443 ports, proxies and accessors", () => {
    const addresses = [{ address: "1.1.1.1", family: 4 as const }];
    for (const host of [
      "Scope-Target.example",
      "synthetic-target.bounty-safe.dev.",
      "scope_target.example",
      "127.0.0.1",
      "localhost",
      "bücher.example",
      "foo",
      "a..b",
      "-a.example",
      "a-.example",
      "foo_bar.example",
    ])
      expect(() =>
        authorizeActiveTestResolvedEgress({ host, port: 443, addresses }),
      ).toThrow("ACTIVE_TEST_RESOLUTION_HOST_INVALID");
    expect(() =>
      authorizeActiveTestResolvedEgress({
        host: "synthetic-target.bounty-safe.dev",
        port: 8443,
        addresses,
      }),
    ).toThrow("ACTIVE_TEST_RESOLUTION_PORT_BLOCKED");
    expect(() =>
      authorizeActiveTestResolvedEgress(new Proxy(input(addresses), {})),
    ).toThrow("ACTIVE_TEST_RESOLUTION_INPUT_INVALID");
    const accessor = input(addresses) as Record<string, unknown>;
    Object.defineProperty(accessor, "host", {
      enumerable: true,
      get: () => "synthetic-target.bounty-safe.dev",
    });
    expect(() => authorizeActiveTestResolvedEgress(accessor)).toThrow(
      "ACTIVE_TEST_RESOLUTION_INPUT_INVALID",
    );
  });

  it("blocks unsafe host syntax in the pure pre-DNS boundary", () => {
    expect(
      canonicalizeActiveTestDnsHost("synthetic-target.bounty-safe.dev"),
    ).toBe("synthetic-target.bounty-safe.dev");
    for (const host of [
      "foo",
      "a..b",
      "-a.example",
      "a-.example",
      "foo_bar.example",
      "127.0.0.1",
      "localhost",
    ])
      expect(() => canonicalizeActiveTestDnsHost(host)).toThrow(
        "ACTIVE_TEST_RESOLUTION_HOST_INVALID",
      );
  });

  it.each([
    "foo.alt",
    "foo.local",
    "foo.localdomain",
    "x.localhost",
    "x.home.arpa",
    "x.onion",
    "x.invalid",
    "x.test",
    "x.example",
    "x.internal",
    "x.lan",
    "x.corp",
    "example.com",
    "sub.example.net",
    "example.org",
  ])("blocks special-use host %s before DNS", (host) => {
    expect(() => canonicalizeActiveTestDnsHost(host)).toThrow(
      "ACTIVE_TEST_RESOLUTION_HOST_SPECIAL_USE_BLOCKED",
    );
  });

  it("captures input data and does not observe later caller mutation", () => {
    const addresses = [{ address: "8.8.8.8", family: 4 as const }];
    const authorization = authorizeActiveTestResolvedEgress(input(addresses));
    addresses[0] = { address: "10.0.0.1", family: 4 };
    expect(authorization.addresses).toEqual(["8.8.8.8"]);
  });
});
