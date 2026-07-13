import { describe, expect, it } from "vitest";
import {
  parseProgramImport,
  type ProgramImportFormat,
} from "../../../packages/control-plane/program-import.js";

function importValue() {
  return {
    id: "program-local",
    name: "Local Program",
    platform: "local_mock",
    status: "available",
    description: "Local fixture only",
    program_url: "http://127.0.0.1:8080/programs/local",
    program_type: "simulation",
    allowed_assets: ["z.local", "a.local", "z.local"],
    excluded_assets: ["admin.local"],
    last_synchronized_at: "2026-07-13T12:30:00+02:00",
    automation_permission: "allowed",
    notes: "No external requests",
    lifecycle: "active",
  };
}

function parseJson(overrides: Record<string, unknown> = {}) {
  return parseProgramImport(
    JSON.stringify({ ...importValue(), ...overrides }),
    "json",
  );
}

describe("control-plane program import", () => {
  it("parses and deeply freezes strict JSON without dereferencing its URL", () => {
    const program = parseJson();

    expect(program).toEqual({
      id: "program-local",
      name: "Local Program",
      platform: "local_mock",
      status: "available",
      description: "Local fixture only",
      programUrl: "http://127.0.0.1:8080/programs/local",
      programType: "simulation",
      allowedAssets: ["a.local", "z.local"],
      excludedAssets: ["admin.local"],
      lastSynchronizedAt: "2026-07-13T10:30:00.000Z",
      automationPermission: "allowed",
      notes: "No external requests",
      lifecycle: "active",
    });
    expect(Object.isFrozen(program)).toBe(true);
    expect(Object.isFrozen(program.allowedAssets)).toBe(true);
    expect(Object.isFrozen(program.excludedAssets)).toBe(true);
  });

  it("parses YAML, trims values and deterministically sorts assets", () => {
    const yaml = `
id: program-manual
name: " Manual Program "
platform: manual
status: unavailable
description: " Local metadata "
program_url: https://platform.invalid/program/local
program_type: private
allowed_assets:
  - z.local
  - " a.local "
  - z.local
excluded_assets:
  - private.local
last_synchronized_at: null
automation_permission: unclear
notes: " review required "
lifecycle: paused
`;

    expect(parseProgramImport(yaml, "yaml")).toMatchObject({
      id: "program-manual",
      name: "Manual Program",
      platform: "manual",
      status: "unavailable",
      programUrl: "https://platform.invalid/program/local",
      allowedAssets: ["a.local", "z.local"],
      excludedAssets: ["private.local"],
      lastSynchronizedAt: null,
      automationPermission: "unclear",
      notes: "review required",
      lifecycle: "paused",
    });
  });

  it("rejects oversized input and malformed UTF-8 before parsing", () => {
    expect(() => parseProgramImport(new Uint8Array(1_048_577), "json")).toThrow(
      "PROGRAM_IMPORT_SIZE_INVALID",
    );
    expect(() =>
      parseProgramImport(new Uint8Array([0xc3, 0x28]), "json"),
    ).toThrow("PROGRAM_IMPORT_UTF8_INVALID");
  });

  it("blocks duplicate keys in JSON and YAML", () => {
    const json = JSON.stringify(importValue()).replace(
      '"id":"program-local"',
      '"id":"first","id":"second"',
    );
    expect(() => parseProgramImport(json, "json")).toThrow(
      "PROGRAM_IMPORT_SYNTAX_INVALID",
    );
    const yaml = `
id: first
id: second
name: Program
`;
    expect(() => parseProgramImport(yaml, "yaml")).toThrow(
      "PROGRAM_IMPORT_SYNTAX_INVALID",
    );
  });

  it("blocks YAML aliases, merge keys and explicit tags", () => {
    const base = `
id: program-local
name: Local Program
platform: local_mock
status: available
description: Local fixture
program_url: http://127.0.0.1:8080/program
program_type: simulation
last_synchronized_at: null
automation_permission: allowed
notes: local
lifecycle: active
`;
    expect(() =>
      parseProgramImport(
        `${base}allowed_assets: &assets [a.local]\nexcluded_assets: *assets\n`,
        "yaml",
      ),
    ).toThrow("PROGRAM_IMPORT_ALIAS_FORBIDDEN");
    expect(() =>
      parseProgramImport(
        `${base}<<: {unexpected: true}\nallowed_assets: []\nexcluded_assets: []\n`,
        "yaml",
      ),
    ).toThrow("PROGRAM_IMPORT_MERGE_FORBIDDEN");
    expect(() =>
      parseProgramImport(
        `${base}allowed_assets: !custom [a.local]\nexcluded_assets: []\n`,
        "yaml",
      ),
    ).toThrow();
  });

  it("rejects unknown fields, invalid metadata, overlap and invalid format", () => {
    const invalidCases: (() => unknown)[] = [
      () => parseJson({ unknown: true }),
      () => parseJson({ platform: "hackerone" }),
      () => parseJson({ program_url: "file:///tmp/program" }),
      () => parseJson({ program_url: "https://user:secret@platform.invalid" }),
      () => parseJson({ last_synchronized_at: "yesterday" }),
      () =>
        parseJson({
          allowed_assets: ["same.local"],
          excluded_assets: [" same.local "],
        }),
      () =>
        parseProgramImport(
          JSON.stringify(importValue()),
          "toml" as ProgramImportFormat,
        ),
    ];

    for (const invalid of invalidCases) expect(invalid).toThrow();
  });

  it("rejects secret-like material in free text and URL queries", () => {
    expect(() =>
      parseJson({
        description: "accidental api".concat("_key=placeholder-value"),
      }),
    ).toThrow("PROGRAM_IMPORT_SENSITIVE_MATERIAL");
    expect(() =>
      parseJson({ program_url: "http://127.0.0.1/program?ref=private" }),
    ).toThrow("PROGRAM_IMPORT_URL_INVALID");
    expect(() =>
      parseJson({
        allowed_assets: ["token=".concat("abcdefghijklmnop")],
      }),
    ).toThrow("PROGRAM_IMPORT_SENSITIVE_MATERIAL");
  });
});
