import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { authorizeActiveTestResolvedEgress } from "../../packages/active-testing/resolved-egress.js";

const input = (
  addresses: readonly { readonly address: string; readonly family: 4 | 6 }[],
) => ({
  host: "synthetic-target.bounty-safe.dev",
  port: 443 as const,
  addresses,
});

const octet = fc.integer({ min: 0, max: 255 });
const hextet = fc
  .integer({ min: 0, max: 0xffff })
  .map((value) => value.toString(16));

describe("active-test resolved egress properties", () => {
  it("rejects every generated RFC1918 IPv4 address", () => {
    const privateAddress = fc.oneof(
      fc.tuple(octet, octet, octet).map(([a, b, c]) => `10.${a}.${b}.${c}`),
      fc
        .tuple(fc.integer({ min: 16, max: 31 }), octet, octet)
        .map(([a, b, c]) => `172.${a}.${b}.${c}`),
      fc.tuple(octet, octet).map(([a, b]) => `192.168.${a}.${b}`),
    );
    fc.assert(
      fc.property(privateAddress, (address) => {
        expect(() =>
          authorizeActiveTestResolvedEgress(input([{ address, family: 4 }])),
        ).toThrow("ACTIVE_TEST_RESOLUTION_PRIVATE_BLOCKED");
      }),
      { numRuns: 300 },
    );
  });

  it("rejects every generated CGNAT and documentation IPv4 address", () => {
    const special = fc.oneof(
      fc
        .tuple(fc.integer({ min: 64, max: 127 }), octet, octet)
        .map(([a, b, c]) => ({ address: `100.${a}.${b}.${c}`, code: "CGNAT" })),
      fc.tuple(octet).map(([last]) => ({
        address: `192.0.2.${last}`,
        code: "DOCUMENTATION",
      })),
      fc.tuple(octet).map(([last]) => ({
        address: `198.51.100.${last}`,
        code: "DOCUMENTATION",
      })),
      fc.tuple(octet).map(([last]) => ({
        address: `203.0.113.${last}`,
        code: "DOCUMENTATION",
      })),
    );
    fc.assert(
      fc.property(special, ({ address, code }) => {
        expect(() =>
          authorizeActiveTestResolvedEgress(input([{ address, family: 4 }])),
        ).toThrow(`ACTIVE_TEST_RESOLUTION_${code}_BLOCKED`);
      }),
      { numRuns: 250 },
    );
  });

  it("rejects generated IPv4-mapped, ULA, link-local and multicast IPv6", () => {
    const blocked = fc.oneof(
      fc.tuple(octet, octet, octet, octet).map((parts) => ({
        address: `::ffff:${parts.join(".")}`,
        code: "IPV4_MAPPED",
      })),
      fc.tuple(hextet, hextet, hextet).map((parts) => ({
        address: `fd00:${parts.join(":")}::1`,
        code: "PRIVATE",
      })),
      fc.tuple(hextet, hextet, hextet).map((parts) => ({
        address: `fe80:${parts.join(":")}::1`,
        code: "LINK_LOCAL",
      })),
      fc.tuple(hextet, hextet, hextet).map((parts) => ({
        address: `ff02:${parts.join(":")}::1`,
        code: "MULTICAST",
      })),
    );
    fc.assert(
      fc.property(blocked, ({ address, code }) => {
        expect(() =>
          authorizeActiveTestResolvedEgress(input([{ address, family: 6 }])),
        ).toThrow(`ACTIVE_TEST_RESOLUTION_${code}_BLOCKED`);
      }),
      { numRuns: 250 },
    );
  });

  it("is order-independent and selects the numerically lowest answer", () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.integer({ min: 1, max: 220 }), {
          minLength: 1,
          maxLength: 16,
        }),
        (lastOctets) => {
          const addresses = lastOctets.map((last) => ({
            address: `8.8.8.${String(last)}`,
            family: 4 as const,
          }));
          const reversed = [...addresses].reverse();
          const left = authorizeActiveTestResolvedEgress(input(addresses));
          const right = authorizeActiveTestResolvedEgress(input(reversed));
          expect(left.resolutionDigest).toBe(right.resolutionDigest);
          expect(left.selectedAddress).toBe(
            `8.8.8.${String(Math.min(...lastOctets))}`,
          );
        },
      ),
      { numRuns: 200 },
    );
  });

  it("binds every public dual-stack set and deterministically prefers IPv4", () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 220 }), hextet, (last, suffix) => {
        const addresses = [
          { address: `8.8.8.${String(last)}`, family: 4 as const },
          { address: `2606:4700:4700::${suffix}`, family: 6 as const },
        ];
        const left = authorizeActiveTestResolvedEgress(input(addresses));
        const right = authorizeActiveTestResolvedEgress(
          input([...addresses].reverse()),
        );
        expect(left.family).toBe(4);
        expect(left.selectedAddress).toBe(`8.8.8.${String(last)}`);
        expect(left.resolutionDigest).toBe(right.resolutionDigest);
      }),
      { numRuns: 150 },
    );
  });
});
