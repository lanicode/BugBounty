import { writeSync } from "node:fs";
import { ControlPlaneDatabase } from "../../packages/control-plane/database.js";

const path = process.argv[2];
const mode = process.argv[3];
if (path === undefined) throw new Error("TEST_DATABASE_PATH_REQUIRED");
if (mode !== "hold" && mode !== "commit")
  throw new Error("TEST_DATABASE_MODE_INVALID");

const database = await ControlPlaneDatabase.file(path);
let closed = false;
try {
  if (mode === "commit") {
    database.transaction(() => {
      insertAudit("child-committed");
    });
    database.close();
    closed = true;
    writeSync(1, "COMMITTED\n");
  } else {
    database.transaction(() => {
      insertAudit("child-uncommitted");
      writeSync(1, "TRANSACTION_OPEN\n");
      const gate = new Int32Array(new SharedArrayBuffer(4));
      Atomics.wait(gate, 0, 0);
    });
  }
} finally {
  if (!closed) {
    try {
      database.close();
    } catch {
      // The commit mode already closed; the hold mode is terminated by SIGKILL.
    }
  }
}

function insertAudit(id: string): void {
  database.run(
    "INSERT INTO control_plane_audit VALUES(?,?,?,?,?,?,?)",
    id,
    "2026-07-14T12:00:00.000Z",
    "child_process_database_test",
    "deny",
    "LOCAL_TEST_ONLY",
    null,
    "a".repeat(64),
  );
}
