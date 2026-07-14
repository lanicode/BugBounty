import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION,
  AuditLog,
  MAX_AUDIT_LOG_BYTES,
  MAX_AUDIT_RECORD_BYTES,
  recoverStaleAuditMutation,
  verifyAuditLog,
  type AuditPayload,
} from "../../packages/audit-log/audit.js";
import { canonicalJson, sha256 } from "../../packages/shared/canonical.js";

const roots: string[] = [];
const POLICY_HASH = "a".repeat(64);

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("durable audit log", () => {
  it("rehydrates the authenticated head after restart and serializes local appenders", async () => {
    const path = await freshPath("restart");
    const first = await new AuditLog(path).append(payload("first"));
    const second = await new AuditLog(path).append(payload("second"));
    expect([first.sequence, second.sequence]).toEqual([0, 1]);
    expect(second.previousHash).toBe(first.hash);

    const concurrent = await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        new AuditLog(path).append(payload(`local-${String(index)}`)),
      ),
    );
    expect(
      concurrent.map(({ sequence }) => sequence).sort((a, b) => a - b),
    ).toEqual(Array.from({ length: 20 }, (_, index) => index + 2));
    await expect(verifyAuditLog(path)).resolves.toEqual({
      valid: true,
      entries: 22,
    });

    const source = await readFile(path, "utf8");
    expect(source.endsWith("\n")).toBe(true);
    for (const line of source.slice(0, -1).split("\n"))
      expect(line).toBe(canonicalJson(JSON.parse(line)));
  });

  it("rejects extra fields, accessors, proxies, coercible references and invalid values", async () => {
    const path = await freshPath("schema");
    await expect(
      new AuditLog(path).append({
        ...payload("extra"),
        body: "must-never-be-persisted",
      } as AuditPayload),
    ).rejects.toThrow("AUDIT_PAYLOAD_INVALID");

    let getterCalls = 0;
    const accessor = { ...payload("accessor") };
    Object.defineProperty(accessor, "action", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "unsafe";
      },
    });
    await expect(new AuditLog(path).append(accessor)).rejects.toThrow(
      "AUDIT_PAYLOAD_INVALID",
    );
    expect(getterCalls).toBe(0);

    let proxyCalls = 0;
    const proxied = new Proxy(payload("proxy"), {
      ownKeys(target) {
        proxyCalls += 1;
        return Reflect.ownKeys(target);
      },
    });
    await expect(new AuditLog(path).append(proxied)).rejects.toThrow(
      "AUDIT_PAYLOAD_INVALID",
    );
    expect(proxyCalls).toBe(0);

    await expect(
      new AuditLog(path).append({
        ...payload("reference"),
        assetRef: { toString: () => "apparently-safe" },
      } as unknown as AuditPayload),
    ).rejects.toThrow("AUDIT_PAYLOAD_INVALID");
    await expect(
      new AuditLog(path).append({ ...payload("empty"), action: "" }),
    ).rejects.toThrow("AUDIT_VALUE_INVALID");
    await expect(
      new AuditLog(path).append({
        ...payload("time"),
        timestamp: "2026-02-31T00:00:00Z",
      }),
    ).rejects.toThrow("AUDIT_TIMESTAMP_INVALID");
    await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("blocks partial, non-canonical, blank, invalid-UTF8 and schema-expanded records", async () => {
    const cases = await Promise.all(
      ["partial", "canonical", "blank", "encoding", "expanded"].map(freshPath),
    );
    const line = validLine(payload("fixture"), 0, "0".repeat(64));

    await privateWrite(cases[0]!, line.slice(0, -5));
    const before = await readFile(cases[0]!);
    await expect(verifyAuditLog(cases[0]!)).rejects.toThrow(
      "AUDIT_PARTIAL_RECORD",
    );
    await expect(
      new AuditLog(cases[0]!).append(payload("blocked")),
    ).rejects.toThrow("AUDIT_PARTIAL_RECORD");
    expect(await readFile(cases[0]!)).toEqual(before);

    await privateWrite(cases[1]!, ` ${line}\n`);
    await expect(verifyAuditLog(cases[1]!)).rejects.toThrow(
      "AUDIT_CANONICAL_JSON_REQUIRED",
    );

    await privateWrite(cases[2]!, `${line}\n\n`);
    await expect(verifyAuditLog(cases[2]!)).rejects.toThrow(
      "AUDIT_FORMAT_INVALID",
    );

    await privateWrite(cases[3]!, Uint8Array.from([0xff, 0x0a]));
    await expect(verifyAuditLog(cases[3]!)).rejects.toThrow(
      "AUDIT_ENCODING_INVALID",
    );

    const expandedBase = {
      ...baseRecord(payload("expanded"), 0, "0".repeat(64)),
      body: "forbidden",
    };
    const expanded = {
      ...expandedBase,
      hash: sha256(canonicalJson(expandedBase)),
    };
    await privateWrite(cases[4]!, `${canonicalJson(expanded)}\n`);
    await expect(verifyAuditLog(cases[4]!)).rejects.toThrow(
      "AUDIT_RECORD_INVALID",
    );
  });

  it("requires a private stable parent and a private regular single-link file", async () => {
    const root = await freshRoot("metadata");
    const privateDirectory = join(root, "private");
    await mkdir(privateDirectory, { mode: 0o700 });
    const path = join(privateDirectory, "audit.jsonl");
    await new AuditLog(path).append(payload("metadata"));
    const metadata = await lstat(path);
    expect(metadata.isFile()).toBe(true);
    expect(metadata.nlink).toBe(1);
    expect(metadata.mode & 0o777).toBe(0o600);
    expect((await lstat(privateDirectory)).mode & 0o777).toBe(0o700);
    await expect(lstat(`${path}.mutation.lock`)).rejects.toMatchObject({
      code: "ENOENT",
    });

    const publicDirectory = join(root, "public");
    await mkdir(publicDirectory, { mode: 0o755 });
    await chmod(publicDirectory, 0o755);
    await expect(
      new AuditLog(join(publicDirectory, "audit.jsonl")).append(
        payload("public"),
      ),
    ).rejects.toThrow("AUDIT_PARENT_INVALID");

    const broad = join(privateDirectory, "broad.jsonl");
    await privateWrite(broad, "", 0o644);
    await expect(verifyAuditLog(broad)).rejects.toThrow("AUDIT_FILE_INVALID");

    const target = join(privateDirectory, "target.jsonl");
    await privateWrite(target, "");
    const symbolic = join(privateDirectory, "symbolic.jsonl");
    await symlink(target, symbolic);
    await expect(verifyAuditLog(symbolic)).rejects.toThrow(
      "AUDIT_FILE_INVALID",
    );

    const hard = join(privateDirectory, "hard.jsonl");
    await link(target, hard);
    await expect(verifyAuditLog(target)).rejects.toThrow("AUDIT_FILE_INVALID");
    await expect(verifyAuditLog(hard)).rejects.toThrow("AUDIT_FILE_INVALID");

    const actualParent = join(root, "actual-parent");
    await mkdir(actualParent, { mode: 0o700 });
    const parentLink = join(root, "parent-link");
    await symlink(actualParent, parentLink);
    await expect(
      new AuditLog(join(parentLink, "audit.jsonl")).append(
        payload("parent-link"),
      ),
    ).rejects.toThrow("AUDIT_PARENT_INVALID");

    const actualAncestor = join(root, "actual-ancestor");
    const nestedParent = join(actualAncestor, "nested");
    await mkdir(actualAncestor, { mode: 0o700 });
    await mkdir(nestedParent, { mode: 0o700 });
    const ancestorLink = join(root, "ancestor-link");
    await symlink(actualAncestor, ancestorLink);
    await expect(
      new AuditLog(join(ancestorLink, "nested", "audit.jsonl")).append(
        payload("ancestor-link"),
      ),
    ).rejects.toThrow("AUDIT_PARENT_INVALID");
  });

  it("fails closed when the current file owner cannot be established", async () => {
    const path = await freshPath("owner-check");
    const original = process.getuid;
    Object.defineProperty(process, "getuid", {
      configurable: true,
      enumerable: true,
      writable: true,
      value: undefined,
    });
    try {
      await expect(new AuditLog(path).append(payload("owner"))).rejects.toThrow(
        "AUDIT_OWNER_CHECK_UNAVAILABLE",
      );
    } finally {
      Object.defineProperty(process, "getuid", {
        configurable: true,
        enumerable: true,
        writable: true,
        value: original,
      });
    }
  });

  it("recovers only an exact stale lease and never truncates a partial record", async () => {
    const path = await freshPath("recovery");
    await new AuditLog(path).append(payload("committed"));
    const lockPath = `${path}.mutation.lock`;
    const stalePid = missingPid();
    await writeMutationLock(lockPath, stalePid);

    await expect(
      recoverStaleAuditMutation(path, "not-confirmed"),
    ).rejects.toThrow("AUDIT_RECOVERY_CONFIRMATION_REQUIRED");
    expect((await lstat(lockPath)).isFile()).toBe(true);
    await expect(
      recoverStaleAuditMutation(
        path,
        AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION,
      ),
    ).resolves.toEqual({ recovered: true, valid: true, entries: 1 });
    await expect(lstat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    await new AuditLog(path).append(payload("after-recovery"));
    await expect(verifyAuditLog(path)).resolves.toEqual({
      valid: true,
      entries: 2,
    });

    const partialPath = await freshPath("partial-recovery");
    await privateWrite(
      partialPath,
      validLine(payload("partial"), 0, "0".repeat(64)).slice(0, -1),
    );
    const partialLock = `${partialPath}.mutation.lock`;
    await writeMutationLock(partialLock, stalePid);
    const partialBefore = await readFile(partialPath);
    await expect(
      recoverStaleAuditMutation(
        partialPath,
        AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION,
      ),
    ).rejects.toThrow("AUDIT_PARTIAL_RECORD");
    expect(await readFile(partialPath)).toEqual(partialBefore);
    expect((await lstat(partialLock)).isFile()).toBe(true);
  });

  it("never steals a live, malformed or oversized mutation lease", async () => {
    const activePath = await freshPath("active-lock");
    await writeMutationLock(`${activePath}.mutation.lock`, process.pid);
    await expect(
      recoverStaleAuditMutation(
        activePath,
        AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION,
      ),
    ).rejects.toThrow("AUDIT_MUTATION_LOCK_ACTIVE");
    expect((await lstat(`${activePath}.mutation.lock`)).isFile()).toBe(true);

    const malformedPath = await freshPath("malformed-lock");
    await privateWrite(
      `${malformedPath}.mutation.lock`,
      `${canonicalJson({ pid: missingPid(), token: "d".repeat(32) })}\n`,
    );
    await expect(
      recoverStaleAuditMutation(
        malformedPath,
        AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION,
      ),
    ).rejects.toThrow("AUDIT_MUTATION_LEASE_INVALID");

    const oversizedPath = await freshPath("oversized-lock");
    await privateWrite(`${oversizedPath}.mutation.lock`, "x".repeat(513));
    await expect(
      recoverStaleAuditMutation(
        oversizedPath,
        AUDIT_STALE_MUTATION_RECOVERY_CONFIRMATION,
      ),
    ).rejects.toThrow("AUDIT_MUTATION_LEASE_INVALID");
  });

  it("enforces bounded records and total file size before parsing", async () => {
    const recordPath = await freshPath("record-limit");
    await privateWrite(recordPath, `${"x".repeat(MAX_AUDIT_RECORD_BYTES)}\n`);
    await expect(verifyAuditLog(recordPath)).rejects.toThrow(
      "AUDIT_FORMAT_INVALID",
    );

    const logPath = await freshPath("log-limit");
    await privateWrite(logPath, "");
    await truncate(logPath, MAX_AUDIT_LOG_BYTES + 1);
    await expect(verifyAuditLog(logPath)).rejects.toThrow(
      "AUDIT_LOG_TOO_LARGE",
    );
  });
});

function payload(action: string): AuditPayload {
  return Object.freeze({
    timestamp: "2026-07-14T12:00:00.000Z",
    action,
    decision: "allow",
    reasonCode: "LOCAL_AUDIT_TEST",
    policyHash: POLICY_HASH,
  });
}

function baseRecord(
  value: AuditPayload,
  sequence: number,
  previousHash: string,
) {
  return {
    timestamp: value.timestamp,
    action: value.action,
    decision: value.decision,
    reasonCode: value.reasonCode,
    policyHash: value.policyHash,
    sequence,
    previousHash,
  };
}

function validLine(
  value: AuditPayload,
  sequence: number,
  previousHash: string,
): string {
  const base = baseRecord(value, sequence, previousHash);
  return canonicalJson({ ...base, hash: sha256(canonicalJson(base)) });
}

async function freshRoot(label: string): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), `audit-${label}-`)));
  roots.push(root);
  await chmod(root, 0o700);
  return root;
}

async function freshPath(label: string): Promise<string> {
  return join(await freshRoot(label), "audit.jsonl");
}

async function privateWrite(
  path: string,
  value: string | Uint8Array,
  mode = 0o600,
): Promise<void> {
  await writeFile(path, value, { mode });
  await chmod(path, mode);
}

async function writeMutationLock(path: string, pid: number): Promise<void> {
  await privateWrite(
    path,
    `${canonicalJson({
      pid,
      schemaVersion: 1,
      token: "d".repeat(32),
    })}\n`,
  );
}

function missingPid(): number {
  for (
    let candidate = 2_147_483_647;
    candidate > 2_147_483_600;
    candidate -= 1
  ) {
    try {
      process.kill(candidate, 0);
    } catch (error) {
      if (error instanceof Error && "code" in error && error.code === "ESRCH")
        return candidate;
    }
  }
  throw new Error("AUDIT_TEST_MISSING_PID_UNAVAILABLE");
}
