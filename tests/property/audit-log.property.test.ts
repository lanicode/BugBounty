import {
  chmod,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  AuditLog,
  verifyAuditLog,
  type AuditPayload,
} from "../../packages/audit-log/audit.js";
import { canonicalJson } from "../../packages/shared/canonical.js";

const POLICY_HASH = "b".repeat(64);
const action = fc.stringMatching(/^[A-Za-z][A-Za-z0-9_.-]{0,31}$/u);

describe("audit log properties", () => {
  it("preserves a canonical contiguous chain across arbitrary restart points", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(action, { minLength: 1, maxLength: 24 }),
        async (actions) => {
          await withAuditPath(async (path) => {
            for (const [index, value] of actions.entries()) {
              const record = await new AuditLog(path).append(
                payload(value, index),
              );
              expect(record.sequence).toBe(index);
            }
            await expect(verifyAuditLog(path)).resolves.toEqual({
              valid: true,
              entries: actions.length,
            });
            const source = await readFile(path, "utf8");
            expect(source.endsWith("\n")).toBe(true);
            const lines = source.slice(0, -1).split("\n");
            expect(lines).toHaveLength(actions.length);
            for (const line of lines)
              expect(line).toBe(canonicalJson(JSON.parse(line)));
          });
        },
      ),
      { numRuns: 24 },
    );
  });

  it("rejects every sampled partial final record without changing the file", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(action, { minLength: 1, maxLength: 8 }),
        fc.nat(),
        async (actions, selector) => {
          await withAuditPath(async (path) => {
            for (const [index, value] of actions.entries())
              await new AuditLog(path).append(payload(value, index));
            const complete = await readFile(path);
            const previousNewline = complete.lastIndexOf(
              0x0a,
              complete.byteLength - 2,
            );
            const finalStart = previousNewline + 1;
            const finalRecordBytes = complete.byteLength - finalStart - 1;
            const retained = 1 + (selector % (finalRecordBytes - 1));
            const partial = complete.subarray(0, finalStart + retained);
            await writeFile(path, partial);
            await expect(verifyAuditLog(path)).rejects.toThrow(
              "AUDIT_PARTIAL_RECORD",
            );
            await expect(
              new AuditLog(path).append(payload("blocked", actions.length)),
            ).rejects.toThrow("AUDIT_PARTIAL_RECORD");
            expect(await readFile(path)).toEqual(partial);
          });
        },
      ),
      { numRuns: 24 },
    );
  });

  it("detects arbitrary sampled single-byte record mutations", async () => {
    await fc.assert(
      fc.asyncProperty(action, fc.nat(), async (value, selector) => {
        await withAuditPath(async (path) => {
          await new AuditLog(path).append(payload(value, 0));
          const source = await readFile(path);
          const index = selector % (source.byteLength - 1);
          source[index] = source[index]! ^ 1;
          await writeFile(path, source);
          await expect(verifyAuditLog(path)).rejects.toThrow();
        });
      }),
      { numRuns: 32 },
    );
  });
});

function payload(value: string, index: number): AuditPayload {
  return Object.freeze({
    timestamp: `2026-07-14T12:00:${String(index % 60).padStart(2, "0")}.000Z`,
    action: value,
    decision: index % 2 === 0 ? "allow" : "block",
    reasonCode: `PROPERTY_${String(index)}`,
    policyHash: POLICY_HASH,
  });
}

async function withAuditPath(
  operation: (path: string) => Promise<void>,
): Promise<void> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "audit-property-")));
  await chmod(root, 0o700);
  try {
    await operation(join(root, "audit.jsonl"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
