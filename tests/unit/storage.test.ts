import { randomBytes } from "node:crypto";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { AuditLog, verifyAuditLog } from "../../packages/audit-log/audit.js";
import { EncryptedEventStore } from "../../packages/event-store/store.js";
import { InMemorySecretStore } from "../../packages/secret-store/store.js";

describe("encrypted event store", () => {
  it("round-trips ciphertext and detects tampering", async ({ task }) => {
    const directory = join("/tmp", `bbc-${process.pid}-${task.id}`);
    const secrets = new InMemorySecretStore();
    secrets.set("keychain://test/event-v1", randomBytes(32));
    const store = new EncryptedEventStore(
      directory,
      secrets,
      (version) => `keychain://test/event-v${version}`,
    );
    const path = await store.write("event-1", { safe: "redacted" });
    await expect(
      store.write("event-1", { safe: "replacement" }),
    ).rejects.toThrow();
    expect(await readFile(path, "utf8")).not.toContain("redacted");
    expect(await store.read(path)).toEqual({ safe: "redacted" });
    const envelope = JSON.parse(await readFile(path, "utf8")) as {
      ciphertext: string;
    };
    envelope.ciphertext = `${envelope.ciphertext.slice(0, -2)}AA`;
    await writeFile(path, JSON.stringify(envelope));
    await chmod(path, 0o600);
    await expect(store.read(path)).rejects.toThrow("EVENT_INTEGRITY_FAILED");
  });
  it("has no plaintext fallback when the key is absent", async ({ task }) => {
    const store = new EncryptedEventStore(
      join("/tmp", `bbc-missing-${process.pid}-${task.id}`),
      new InMemorySecretStore(),
      () => "keychain://test/missing",
    );
    await expect(store.write("event", { safe: true })).rejects.toThrow(
      "SECRET_NOT_FOUND",
    );
  });
});

describe("audit chain", () => {
  it("verifies and detects manipulation", async ({ task }) => {
    const path = join("/tmp", `audit-${process.pid}-${task.id}.jsonl`);
    const log = new AuditLog(path);
    await log.append({
      timestamp: "2026-01-01T00:00:00Z",
      action: "capture",
      decision: "allow",
      reasonCode: "ALLOW_TARGET",
      policyHash: "a".repeat(64),
    });
    await log.append({
      timestamp: "2026-01-01T00:00:01Z",
      action: "capture",
      decision: "block",
      reasonCode: "BLOCK_HOST",
      policyHash: "a".repeat(64),
    });
    await expect(verifyAuditLog(path)).resolves.toEqual({
      valid: true,
      entries: 2,
    });
    const source = await readFile(path, "utf8");
    await writeFile(path, source.replace("BLOCK_HOST", "BLOCK_PORT"));
    await expect(verifyAuditLog(path)).rejects.toThrow("AUDIT_CHAIN_INVALID");
  });
  it("rejects body-like or unsafe audit values", async ({ task }) => {
    const log = new AuditLog(
      join("/tmp", `audit-unsafe-${process.pid}-${task.id}.jsonl`),
    );
    await expect(
      log.append({
        timestamp: "2026-01-01T00:00:00Z",
        action: "{body}",
        decision: "allow",
        reasonCode: "ALLOW",
        policyHash: "a".repeat(64),
      }),
    ).rejects.toThrow("AUDIT_VALUE_INVALID");
  });
});
