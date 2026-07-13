import { describe, expect, it } from "vitest";
import {
  diffPolicies,
  normalizePolicy,
  type PolicyInput,
} from "../../../packages/control-plane/policy.js";
import { sha256 } from "../../../packages/shared/canonical.js";

function policy(overrides: Partial<PolicyInput> = {}): PolicyInput {
  return {
    text: "Local fixture policy",
    allowedAssets: ["app.local", "api.local"],
    excludedAssets: ["admin.local"],
    requestLimits: {
      requestsPerMinute: 20,
      maxRequestsTotal: 100,
      maxConcurrency: 1,
    },
    allowedTestClasses: ["owned_read"],
    forbiddenTestClasses: ["destructive"],
    rules: ["Use only researcher-controlled objects"],
    unclearRules: [],
    ...overrides,
  };
}

describe("control-plane policy normalization", () => {
  it("trims, deduplicates and ASCII-sorts every set-like field", () => {
    const normalized = normalizePolicy(
      policy({
        text: "  Local fixture policy  ",
        allowedAssets: ["z.local", " a.local ", "z.local", "B.local"],
        excludedAssets: ["private.local", " admin.local "],
        allowedTestClasses: ["read", "offline", "read"],
        forbiddenTestClasses: ["write", " destructive "],
        rules: ["Rule Z", " Rule A ", "Rule Z"],
        unclearRules: ["Unknown Z", " Unknown A ", "Unknown Z"],
      }),
    );

    expect(normalized).toMatchObject({
      version: 1,
      text: "Local fixture policy",
      allowedAssets: ["B.local", "a.local", "z.local"],
      excludedAssets: ["admin.local", "private.local"],
      allowedTestClasses: ["offline", "read"],
      forbiddenTestClasses: ["destructive", "write"],
      rules: ["Rule A", "Rule Z"],
      unclearRules: ["Unknown A", "Unknown Z"],
    });
    expect(normalized.policyHash).toBe(sha256(normalized.canonical));
    expect(normalized.policyHash).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("produces deterministic, deeply immutable policies", () => {
    const first = normalizePolicy(
      policy({ allowedAssets: ["z.local", "a.local", "z.local"] }),
    );
    const second = normalizePolicy(
      policy({ allowedAssets: ["a.local", "z.local"] }),
    );

    expect(first.canonical).toBe(second.canonical);
    expect(first.policyHash).toBe(second.policyHash);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.allowedAssets)).toBe(true);
    expect(Object.isFrozen(first.excludedAssets)).toBe(true);
    expect(Object.isFrozen(first.requestLimits)).toBe(true);
    expect(Object.isFrozen(first.allowedTestClasses)).toBe(true);
    expect(Object.isFrozen(first.forbiddenTestClasses)).toBe(true);
    expect(Object.isFrozen(first.rules)).toBe(true);
    expect(Object.isFrozen(first.unclearRules)).toBe(true);
  });

  it("rejects malformed, ambiguous and overlapping policy data", () => {
    const cases: unknown[] = [
      { ...policy(), text: "   " },
      { ...policy(), unexpected: true },
      { ...policy(), allowedAssets: ["valid.local", " "] },
      { ...policy(), rules: ["bad\nrule"] },
      {
        ...policy(),
        allowedAssets: ["same.local"],
        excludedAssets: [" same.local "],
      },
      {
        ...policy(),
        allowedTestClasses: ["same"],
        forbiddenTestClasses: ["same"],
      },
      {
        ...policy(),
        requestLimits: {
          requestsPerMinute: 0,
          maxRequestsTotal: 100,
          maxConcurrency: 1,
        },
      },
      {
        ...policy(),
        requestLimits: {
          requestsPerMinute: 20,
          maxRequestsTotal: 1,
          maxConcurrency: 2,
        },
      },
      {
        ...policy(),
        requestLimits: {
          requestsPerMinute: 20,
          maxRequestsTotal: 100,
          maxConcurrency: 1,
          unknown: 1,
        },
      },
    ];

    for (const value of cases)
      expect(() => normalizePolicy(value as PolicyInput)).toThrow();
  });

  it("rejects secret-like material before policy persistence", () => {
    for (const text of [
      "accidental access".concat("_token=placeholder-value"),
      "token=".concat("abcdefghijklmnop"),
      "Cookie: sessionid=".concat("local-session-value"),
      "Authorization: Token ".concat("abcdefghijklmnop"),
      "otpauth://totp/local?secret=".concat("ABCDEFGHIJKLMNOP"),
      "eyJabcdefghij".concat(".abcdefghij.abcdefghij"),
    ])
      expect(() => normalizePolicy(policy({ text }))).toThrow(
        "POLICY_SENSITIVE_MATERIAL",
      );
    for (const patch of [
      { allowedAssets: ["token=".concat("abcdefghijklmnop")] },
      { excludedAssets: ["session=".concat("abcdefghijklmnop")] },
      { allowedTestClasses: ["api_key=".concat("abcdefghijklmnop")] },
      { forbiddenTestClasses: ["client_secret=".concat("abcdefghijklmnop")] },
    ])
      expect(() => normalizePolicy(policy(patch))).toThrow(
        "POLICY_SENSITIVE_MATERIAL",
      );
  });
});

describe("control-plane policy diff", () => {
  it("describes scope, limits, test classes, rules and uncertainty changes", () => {
    const before = normalizePolicy(
      policy({
        text: "Version one",
        allowedAssets: ["api.local", "old.local"],
        excludedAssets: ["old-block.local"],
        allowedTestClasses: ["offline", "read"],
        forbiddenTestClasses: ["destructive", "write"],
        rules: ["Keep A", "Remove B"],
        unclearRules: ["Old uncertainty"],
      }),
    );
    const after = normalizePolicy(
      policy({
        text: "Version two",
        allowedAssets: ["api.local", "new.local"],
        excludedAssets: ["new-block.local"],
        requestLimits: {
          requestsPerMinute: 10,
          maxRequestsTotal: 100,
          maxConcurrency: 1,
        },
        allowedTestClasses: ["read", "reversible_write"],
        forbiddenTestClasses: ["destructive", "credential_access"],
        rules: ["Add C", "Keep A"],
        unclearRules: ["New uncertainty"],
      }),
    );

    const diff = diffPolicies(before, after);
    expect(diff).toMatchObject({
      changed: true,
      beforeHash: before.policyHash,
      afterHash: after.policyHash,
      textChanged: true,
      addedAssets: ["new.local"],
      removedAssets: ["old.local"],
      newlyExcludedAssets: ["new-block.local"],
      noLongerExcludedAssets: ["old-block.local"],
      changedRequestLimits: [
        { field: "requestsPerMinute", before: 20, after: 10 },
      ],
      newlyAllowedTestClasses: ["reversible_write"],
      noLongerAllowedTestClasses: ["offline"],
      newlyForbiddenTestClasses: ["credential_access"],
      noLongerForbiddenTestClasses: ["write"],
      changedRules: { added: ["Add C"], removed: ["Remove B"] },
      unclearRules: {
        added: ["New uncertainty"],
        removed: ["Old uncertainty"],
        current: ["New uncertainty"],
      },
    });
    expect(Object.isFrozen(diff)).toBe(true);
    expect(Object.isFrozen(diff.changedRequestLimits)).toBe(true);
    expect(Object.isFrozen(diff.changedRequestLimits[0])).toBe(true);
    expect(Object.isFrozen(diff.changedRules)).toBe(true);
    expect(Object.isFrozen(diff.unclearRules)).toBe(true);
  });

  it("returns an empty immutable diff for the same normalized policy", () => {
    const normalized = normalizePolicy(policy());
    const diff = diffPolicies(normalized, normalized);

    expect(diff).toMatchObject({
      changed: false,
      textChanged: false,
      addedAssets: [],
      removedAssets: [],
      newlyExcludedAssets: [],
      noLongerExcludedAssets: [],
      changedRequestLimits: [],
      newlyAllowedTestClasses: [],
      noLongerAllowedTestClasses: [],
      newlyForbiddenTestClasses: [],
      noLongerForbiddenTestClasses: [],
      changedRules: { added: [], removed: [] },
      unclearRules: { added: [], removed: [], current: [] },
    });
    expect(Object.isFrozen(diff.addedAssets)).toBe(true);
    expect(Object.isFrozen(diff.changedRules.added)).toBe(true);
    expect(Object.isFrozen(diff.unclearRules.current)).toBe(true);
  });

  it("rejects a normalized policy whose canonical payload or hash was forged", () => {
    const normalized = normalizePolicy(policy());
    expect(() =>
      diffPolicies(normalized, {
        ...normalized,
        policyHash: "0".repeat(64),
      }),
    ).toThrow("POLICY_INTEGRITY_INVALID");
    expect(() =>
      diffPolicies(
        { ...normalized, canonical: `${normalized.canonical} ` },
        normalized,
      ),
    ).toThrow("POLICY_INTEGRITY_INVALID");
  });
});
