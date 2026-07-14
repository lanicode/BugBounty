import { AuditLog } from "../../packages/audit-log/audit.js";

const path = process.argv[2];
const worker = process.argv[3];
const countText = process.argv[4];
if (
  path === undefined ||
  worker === undefined ||
  countText === undefined ||
  !/^[A-Za-z0-9_-]{1,32}$/u.test(worker) ||
  !/^[1-9][0-9]{0,2}$/u.test(countText)
)
  throw new Error("AUDIT_TEST_ARGUMENT_INVALID");
const count = Number(countText);
if (!Number.isSafeInteger(count) || count > 100)
  throw new Error("AUDIT_TEST_ARGUMENT_INVALID");

for (let index = 0; index < count; index += 1) {
  await new AuditLog(path).append({
    timestamp: `2026-07-14T12:00:${String(index % 60).padStart(2, "0")}.000Z`,
    action: `worker-${worker}-${String(index)}`,
    decision: "allow",
    reasonCode: "LOCAL_CHILD_PROCESS",
    policyHash: "c".repeat(64),
  });
}
process.stdout.write(`${JSON.stringify({ worker, count })}\n`);
