import { describe, expect, it } from "vitest";
import { detectScopeChange } from "../../../packages/platform/scope-monitor.js";
import { compilePlatformPolicy } from "../../../packages/platform-source/compiler.js";
import { validateProgramSnapshot } from "../../../packages/platform-source/fixture-source.js";
import { snapshotValue } from "../../fixtures/platform-source.factory.js";

const compile = (value = snapshotValue()) =>
  compilePlatformPolicy(validateProgramSnapshot(value));

describe("scope change monitor", () => {
  it("keeps an identical snapshot stable", () => {
    expect(detectScopeChange(compile(), compile())).toEqual({
      changed: false,
      stopCampaign: false,
      requiresHumanAcceptance: false,
      changes: [],
    });
  });

  it("stops on policy, scope, exclusion and revision changes", () => {
    const base = snapshotValue();
    const accepted = compile(base);
    const firstTarget = base.network.targets[0];
    if (firstTarget === undefined) throw new Error("MISSING_TEST_TARGET");
    const candidates = [
      {
        value: { ...base, policy: { content_sha256: "c".repeat(64) } },
        code: "POLICY_HASH_CHANGED",
      },
      {
        value: {
          ...base,
          source: { ...base.source, source_revision: "fixture-002" },
        },
        code: "SOURCE_REVISION_CHANGED",
      },
      {
        value: {
          ...base,
          network: {
            ...base.network,
            targets: [firstTarget],
          },
        },
        code: "TARGETS_CHANGED",
      },
      {
        value: {
          ...base,
          network: {
            ...base.network,
            blocked_hosts: ["new-block.example.test"],
          },
        },
        code: "BLOCKED_HOSTS_CHANGED",
      },
    ];
    for (const candidate of candidates) {
      const decision = detectScopeChange(accepted, compile(candidate.value));
      expect(decision.stopCampaign).toBe(true);
      expect(decision.requiresHumanAcceptance).toBe(true);
      expect(decision.changes).toContain(candidate.code);
    }
  });

  it("does not classify array reordering as a semantic target change", () => {
    const base = snapshotValue();
    const reordered = {
      ...base,
      network: {
        ...base.network,
        targets: [...base.network.targets].reverse(),
      },
    };
    const decision = detectScopeChange(compile(base), compile(reordered));
    expect(decision.changes).not.toContain("TARGETS_CHANGED");
    expect(decision.changes).toContain("SOURCE_SNAPSHOT_CHANGED");
    expect(decision.stopCampaign).toBe(true);
  });
});
