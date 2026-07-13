import { describe, expect, it } from "vitest";
import {
  compilePlatformPolicy,
  verifySourceAcceptance,
} from "../../../packages/platform-source/compiler.js";
import { validateProgramSnapshot } from "../../../packages/platform-source/fixture-source.js";
import { snapshotValue } from "../../fixtures/platform-source.factory.js";

describe("platform policy compiler", () => {
  it("maps and sorts a strict non-production platform policy", () => {
    const policy = compilePlatformPolicy(
      validateProgramSnapshot(snapshotValue()),
    );
    expect(policy.productionEligible).toBe(false);
    expect(policy.targets.map((target) => target.host)).toEqual([
      "api.example.test",
      "app.example.test",
    ]);
    expect(policy.supportingHosts[0]?.allowed_methods).toEqual(["GET", "HEAD"]);
  });

  it("rejects host class overlap and non-canonical paths", () => {
    const base = snapshotValue();
    expect(() =>
      compilePlatformPolicy(
        validateProgramSnapshot({
          ...base,
          network: {
            ...base.network,
            blocked_hosts: ["api.example.test"],
          },
        }),
      ),
    ).toThrow("PLATFORM_SOURCE_HOST_CLASS_OVERLAP");
    expect(() =>
      compilePlatformPolicy(
        validateProgramSnapshot({
          ...base,
          network: {
            ...base.network,
            targets: [
              {
                ...base.network.targets[0],
                path_prefixes: ["/api//ambiguous"],
              },
            ],
          },
        }),
      ),
    ).toThrow("PLATFORM_SOURCE_PATH_NON_CANONICAL");
  });

  it("fails closed on policy, snapshot or revision drift", () => {
    const policy = compilePlatformPolicy(
      validateProgramSnapshot(snapshotValue()),
    );
    const accepted = {
      upstreamPolicyHash: policy.upstreamPolicyHash,
      sourceSnapshotHash: policy.sourceSnapshotHash,
      sourceRevision: policy.sourceRevision,
      acceptedBy: "local-reviewer",
      acceptedAt: "2026-07-13T12:01:00Z",
    };
    expect(() => {
      verifySourceAcceptance(policy, accepted);
    }).not.toThrow();
    expect(() => {
      verifySourceAcceptance(policy, {
        ...accepted,
        upstreamPolicyHash: "c".repeat(64),
      });
    }).toThrow("UPSTREAM_POLICY_DRIFT");
    expect(() => {
      verifySourceAcceptance(policy, {
        ...accepted,
        sourceSnapshotHash: "d".repeat(64),
      });
    }).toThrow("PLATFORM_SNAPSHOT_DRIFT");
    expect(() => {
      verifySourceAcceptance(policy, {
        ...accepted,
        sourceRevision: "fixture-002",
      });
    }).toThrow("PLATFORM_SOURCE_REVISION_DRIFT");
    expect(() => {
      verifySourceAcceptance(policy, {
        ...accepted,
        acceptedAt: "2026-07-13T11:59:00Z",
      });
    }).toThrow("PLATFORM_ACCEPTANCE_INVALID");
  });

  it("binds immutable snapshots and compiled scope to their validated hash", () => {
    const validated = validateProgramSnapshot(snapshotValue());
    expect(Object.isFrozen(validated.snapshot.network.targets)).toBe(true);
    expect(() => {
      compilePlatformPolicy({ ...validated, snapshotHash: "f".repeat(64) });
    }).toThrow("PLATFORM_SOURCE_INTEGRITY_INVALID");
    const policy = compilePlatformPolicy(validated);
    expect(Object.isFrozen(policy.targets)).toBe(true);
  });

  it("rejects canonical duplicate hosts and query-like path prefixes", () => {
    const base = snapshotValue();
    expect(() =>
      compilePlatformPolicy(
        validateProgramSnapshot({
          ...base,
          network: {
            ...base.network,
            targets: [base.network.targets[0], base.network.targets[0]],
          },
        }),
      ),
    ).toThrow("PLATFORM_SOURCE_DUPLICATE_HOST");
    expect(() =>
      compilePlatformPolicy(
        validateProgramSnapshot({
          ...base,
          network: {
            ...base.network,
            targets: [
              { ...base.network.targets[0], path_prefixes: ["/api?unsafe"] },
            ],
          },
        }),
      ),
    ).toThrow("PLATFORM_SOURCE_PATH_NON_CANONICAL");
  });
});
