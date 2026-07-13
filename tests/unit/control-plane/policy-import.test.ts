import { describe, expect, it } from "vitest";
import {
  parsePolicyImport,
  type PolicyImportFormat,
} from "../../../packages/control-plane/policy-import.js";

function structuredPolicy() {
  return {
    text: "Local structured policy",
    allowedAssets: ["z.local", " a.local ", "z.local"],
    excludedAssets: ["admin.local"],
    requestLimits: {
      requestsPerMinute: 10,
      maxRequestsTotal: 100,
      maxConcurrency: 1,
    },
    allowedTestClasses: ["owned_read", "offline", "owned_read"],
    forbiddenTestClasses: ["destructive"],
    rules: ["Use only local fixtures"],
    unclearRules: ["One ambiguous clause"],
  };
}

describe("control-plane policy import", () => {
  it("imports text conservatively without interpreting it", () => {
    const policy = parsePolicyImport(
      "  Human review required; scope is not structured.  ",
      "text",
    );

    expect(policy).toMatchObject({
      text: "Human review required; scope is not structured.",
      allowedAssets: [],
      excludedAssets: [],
      requestLimits: {
        requestsPerMinute: 1,
        maxRequestsTotal: 1,
        maxConcurrency: 1,
      },
      allowedTestClasses: [],
      forbiddenTestClasses: [],
      rules: [],
      unclearRules: ["Human review required; scope is not structured."],
    });
    expect(Object.isFrozen(policy)).toBe(true);
    expect(Object.isFrozen(policy.unclearRules)).toBe(true);
  });

  it("imports strict JSON through the shared deterministic normalizer", () => {
    const policy = parsePolicyImport(
      JSON.stringify(structuredPolicy()),
      "json",
    );

    expect(policy.allowedAssets).toEqual(["a.local", "z.local"]);
    expect(policy.allowedTestClasses).toEqual(["offline", "owned_read"]);
    expect(policy.policyHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(Object.isFrozen(policy.requestLimits)).toBe(true);
  });

  it("imports strict YAML and normalizes all set-like lists", () => {
    const yaml = `
text: Local YAML policy
allowedAssets: [z.local, a.local, z.local]
excludedAssets: [admin.local]
requestLimits:
  requestsPerMinute: 5
  maxRequestsTotal: 25
  maxConcurrency: 1
allowedTestClasses: [owned_read]
forbiddenTestClasses: [destructive]
rules:
  - Local fixtures only
unclearRules: []
`;
    const policy = parsePolicyImport(yaml, "yaml");

    expect(policy.text).toBe("Local YAML policy");
    expect(policy.allowedAssets).toEqual(["a.local", "z.local"]);
    expect(policy.requestLimits).toEqual({
      requestsPerMinute: 5,
      maxRequestsTotal: 25,
      maxConcurrency: 1,
    });
  });

  it("preserves multiline text as a conservative escaped unclear rule", () => {
    const policy = parsePolicyImport("First line\nSecond line", "text");
    expect(policy.text).toBe("First line\nSecond line");
    expect(policy.unclearRules).toEqual(["First line\\nSecond line"]);
  });

  it("retains longer text across deterministically ordered unclear fragments", () => {
    const source = "a".repeat(10_000);
    const policy = parsePolicyImport(source, "text");
    const reconstructed = policy.unclearRules
      .map((rule) => rule.replace(/^part-\d{6}: /u, ""))
      .join("");
    expect(policy.text).toBe(source);
    expect(reconstructed).toBe(source);
    expect(policy.unclearRules.every((rule) => rule.length <= 4_096)).toBe(
      true,
    );
  });

  it("rejects oversized input and malformed UTF-8 before parsing", () => {
    expect(() => parsePolicyImport(new Uint8Array(1_048_577), "json")).toThrow(
      "POLICY_IMPORT_SIZE_INVALID",
    );
    expect(() =>
      parsePolicyImport(new Uint8Array([0xc3, 0x28]), "text"),
    ).toThrow("POLICY_IMPORT_UTF8_INVALID");
  });

  it("blocks duplicate keys, aliases, merges and explicit tags", () => {
    const duplicateJson = JSON.stringify(structuredPolicy()).replace(
      '"text":"Local structured policy"',
      '"text":"first","text":"second"',
    );
    expect(() => parsePolicyImport(duplicateJson, "json")).toThrow(
      "POLICY_IMPORT_SYNTAX_INVALID",
    );

    const base = `
text: Local policy
excludedAssets: []
requestLimits: {requestsPerMinute: 1, maxRequestsTotal: 1, maxConcurrency: 1}
allowedTestClasses: []
forbiddenTestClasses: []
rules: []
unclearRules: []
`;
    expect(() =>
      parsePolicyImport(
        `
text: Local policy
allowedAssets: &assets [a.local]
excludedAssets: *assets
requestLimits: {requestsPerMinute: 1, maxRequestsTotal: 1, maxConcurrency: 1}
allowedTestClasses: []
forbiddenTestClasses: []
rules: []
unclearRules: []
`,
        "yaml",
      ),
    ).toThrow("POLICY_IMPORT_ALIAS_FORBIDDEN");
    expect(() =>
      parsePolicyImport(
        `${base}<<: {unexpected: true}\nallowedAssets: []\n`,
        "yaml",
      ),
    ).toThrow("POLICY_IMPORT_MERGE_FORBIDDEN");
    expect(() =>
      parsePolicyImport(`${base}allowedAssets: !custom []\n`, "yaml"),
    ).toThrow();
  });

  it("blocks unknown fields, malformed structure and unsafe policy semantics", () => {
    const invalidCases: (() => unknown)[] = [
      () =>
        parsePolicyImport(
          JSON.stringify({ ...structuredPolicy(), unexpected: true }),
          "json",
        ),
      () =>
        parsePolicyImport(
          JSON.stringify({
            ...structuredPolicy(),
            requestLimits: {
              ...structuredPolicy().requestLimits,
              unknown: 1,
            },
          }),
          "json",
        ),
      () =>
        parsePolicyImport(
          JSON.stringify({ ...structuredPolicy(), allowedAssets: "a.local" }),
          "json",
        ),
      () =>
        parsePolicyImport(
          JSON.stringify({
            ...structuredPolicy(),
            allowedAssets: ["same.local"],
            excludedAssets: ["same.local"],
          }),
          "json",
        ),
      () => parsePolicyImport("", "text"),
      () =>
        parsePolicyImport(
          JSON.stringify(structuredPolicy()),
          "toml" as PolicyImportFormat,
        ),
    ];
    for (const invalid of invalidCases) expect(invalid).toThrow();
  });
});
