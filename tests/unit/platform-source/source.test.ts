import { mkdtemp, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import {
  FixtureProgramSource,
  validateProgramSnapshot,
} from "../../../packages/platform-source/fixture-source.js";
import { snapshotValue } from "../../fixtures/platform-source.factory.js";

describe("offline fixture source", () => {
  it("reads, validates and hashes a fixture within its root", async () => {
    const source = new FixtureProgramSource("tests/fixtures/platform-source");
    const validated = await source.read("program.snapshot.json");
    expect(validated.snapshot.source.kind).toBe("offline_fixture");
    expect(validated.snapshotHash).toMatch(/^[a-f0-9]{64}$/u);
    expect(validated.canonical).not.toContain("\n");
  });

  it("rejects path escapes, absolute paths, missing files and non-JSON refs", async () => {
    const source = new FixtureProgramSource("tests/fixtures/platform-source");
    await expect(source.read("../contract.local.json")).rejects.toThrow(
      "PLATFORM_SOURCE_REFERENCE_INVALID",
    );
    await expect(source.read("/tmp/value.json")).rejects.toThrow(
      "PLATFORM_SOURCE_REFERENCE_INVALID",
    );
    await expect(source.read("missing.json")).rejects.toThrow(
      "PLATFORM_SOURCE_NOT_FOUND",
    );
    await expect(source.read("program.snapshot.yaml")).rejects.toThrow(
      "PLATFORM_SOURCE_REFERENCE_INVALID",
    );
  });

  it("rejects symlinks and oversized files", async () => {
    const root = await mkdtemp(join(tmpdir(), "platform-source-"));
    const outside = join(tmpdir(), `outside-${process.pid}.json`);
    await writeFile(outside, JSON.stringify(snapshotValue()), "utf8");
    await symlink(outside, join(root, "linked.json"));
    const source = new FixtureProgramSource(root);
    await expect(source.read("linked.json")).rejects.toThrow(
      "PLATFORM_SOURCE_PATH_ESCAPE",
    );
    const inside = join(root, "inside.json");
    await writeFile(inside, JSON.stringify(snapshotValue()), "utf8");
    await symlink(inside, join(root, "inside-link.json"));
    await expect(source.read("inside-link.json")).rejects.toThrow(
      "PLATFORM_SOURCE_SYMLINK_BLOCKED",
    );
    await writeFile(join(root, "large.json"), "x".repeat(1_048_577), "utf8");
    await expect(source.read("large.json")).rejects.toThrow(
      "PLATFORM_SOURCE_SIZE_INVALID",
    );
  });

  it("rejects unknown and secret-shaped fields without echoing values", () => {
    expect(() =>
      validateProgramSnapshot({ ...snapshotValue(), unexpected: true }),
    ).toThrow(/PLATFORM_SOURCE_SCHEMA/u);
    expect(() =>
      validateProgramSnapshot({ ...snapshotValue(), api_token: "x" }),
    ).toThrow("PLATFORM_SOURCE_SECRET_FIELD");
    let deeplyNested: unknown = {};
    for (let depth = 0; depth < 70; depth += 1)
      deeplyNested = { node: deeplyNested };
    expect(() => validateProgramSnapshot(deeplyNested)).toThrow(
      "PLATFORM_SOURCE_STRUCTURE_LIMIT",
    );
  });

  it("rejects duplicate JSON keys and malformed UTF-8", async () => {
    const root = await mkdtemp(join(tmpdir(), "platform-source-json-"));
    await writeFile(
      join(root, "duplicate.json"),
      '{"schema_version":1,"schema_version":1}',
      "utf8",
    );
    await writeFile(join(root, "utf8.json"), Uint8Array.from([0xff, 0xfe]));
    const source = new FixtureProgramSource(root);
    await expect(source.read("duplicate.json")).rejects.toThrow(
      "PLATFORM_SOURCE_JSON_AMBIGUOUS",
    );
    await expect(source.read("utf8.json")).rejects.toThrow(
      "PLATFORM_SOURCE_JSON_INVALID",
    );
  });
});
