import { once } from "node:events";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { dirname } from "node:path";
import { canonicalJson } from "../../packages/shared/canonical.js";

const path = process.argv[2];
if (path === undefined) throw new Error("AUDIT_TEST_PATH_REQUIRED");
const lockPath = `${path}.mutation.lock`;
const lock = await open(
  lockPath,
  constants.O_CREAT |
    constants.O_EXCL |
    constants.O_RDWR |
    constants.O_NOFOLLOW,
  0o600,
);
await lock.chmod(0o600);
await lock.writeFile(
  `${canonicalJson({
    pid: process.pid,
    schemaVersion: 1,
    token: "e".repeat(32),
  })}\n`,
  "utf8",
);
await lock.sync();
const directory = await open(
  dirname(path),
  constants.O_RDONLY | constants.O_NOFOLLOW,
);
try {
  await directory.sync();
} finally {
  await directory.close();
}
process.stdout.write("LOCKED\n");
await once(process.stdin, "data");
await lock.close();
