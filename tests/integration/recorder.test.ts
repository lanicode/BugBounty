import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { EncryptedEventStore } from "../../packages/event-store/store.js";
import { SelectiveEventRecorder } from "../../packages/recorder/recorder.js";
import { Pseudonymizer } from "../../packages/redaction/redactor.js";
import { InMemorySecretStore } from "../../packages/secret-store/store.js";

it("never persists a secret marker in ciphertext or normal events", async ({
  task,
}) => {
  const marker = ["PHASE1", "SECRET", randomBytes(6).toString("hex")].join("-");
  const root = join("/tmp", `recorder-${process.pid}-${task.id}`);
  const secrets = new InMemorySecretStore();
  secrets.set("keychain://test/event-v1", randomBytes(32));
  const normal = new EncryptedEventStore(
    join(root, "normal"),
    secrets,
    (version) => `keychain://test/event-v${version}`,
  );
  const quarantine = new EncryptedEventStore(
    join(root, "quarantine"),
    secrets,
    (version) => `keychain://test/event-v${version}`,
  );
  const recorder = new SelectiveEventRecorder(normal, quarantine, {
    maxBytes: 1024,
    allowedContentTypes: ["application/json"],
    pseudonymizer: new Pseudonymizer(randomBytes(32)),
  });
  const result = await recorder.record({
    id: "capture-1",
    timestamp: "2026-01-01T00:00:00Z",
    assetKind: "target",
    request: {
      url: `https://api.example.test/api/?token=${marker}`,
      method: "GET",
      headers: { authorization: `Bearer ${marker}` },
    },
    response: {
      status: 200,
      headers: { "content-type": "application/json" },
      body: Buffer.from(JSON.stringify({ password: marker, ok: true })),
    },
  });
  const encrypted = await readFile(result.path, "utf8");
  expect(encrypted).not.toContain(marker);
  const event = await normal.read(result.path);
  expect(JSON.stringify(event)).not.toContain(marker);
});
