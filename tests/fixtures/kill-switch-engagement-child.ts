import { writeSync } from "node:fs";
import { ControlPlaneDatabase } from "../../packages/control-plane/database.js";

const path = process.argv[2];
if (path === undefined) throw new Error("TEST_DATABASE_PATH_REQUIRED");

const database = await ControlPlaneDatabase.file(path);
database.transaction(() => {
  const current = database.get(
    "SELECT revision FROM system_state WHERE key='global_kill_switch'",
  )?.["revision"];
  if (typeof current !== "number" || !Number.isSafeInteger(current))
    throw new Error("TEST_KILL_SWITCH_REVISION_INVALID");
  const updated = database.run(
    `UPDATE system_state SET value='engaged',revision=?,updated_at=?,
     audit_reference=NULL WHERE key='global_kill_switch' AND revision=?`,
    current + 1,
    "2026-07-14T16:00:00.000Z",
    current,
  );
  if (updated.changes !== 1)
    throw new Error("TEST_KILL_SWITCH_ENGAGEMENT_FAILED");
});

writeSync(1, "ENGAGEMENT_COMMITTED\n");
const gate = new Int32Array(new SharedArrayBuffer(4));
Atomics.wait(gate, 0, 0);
