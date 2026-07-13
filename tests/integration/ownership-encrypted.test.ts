import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, it } from "vitest";
import { EncryptedEventStore } from "../../packages/event-store/store.js";
import {
  EncryptedOwnershipJournal,
  OwnershipLedger,
  SimulationReceiptAuthority,
} from "../../packages/ownership-ledger/ledger.js";
import { InMemorySecretStore } from "../../packages/secret-store/store.js";

it("journals ownership only as authenticated ciphertext", async ({ task }) => {
  const marker = ["ownership", "marker", randomBytes(4).toString("hex")].join(
    "-",
  );
  const root = join("/tmp", `ownership-${process.pid}-${task.id}`);
  const secrets = new InMemorySecretStore();
  secrets.set("keychain://phase2/ownership-v1", randomBytes(32));
  const store = new EncryptedEventStore(
    root,
    secrets,
    (version) => `keychain://phase2/ownership-v${String(version)}`,
  );
  const authority = new SimulationReceiptAuthority(randomBytes(32));
  const ledger = new OwnershipLedger(
    authority,
    new EncryptedOwnershipJournal(store),
    "a".repeat(64),
  );
  await ledger.activateAccount(
    authority.issueAccountActive({
      receiptId: "account-event",
      applicationRef: "local-app:fixture",
      accountRef: marker,
      policyHash: "a".repeat(64),
    }),
  );
  const envelope = await readFile(
    join(root, "account-event.events.enc"),
    "utf8",
  );
  expect(envelope).not.toContain(marker);
  expect(envelope).not.toContain("ACCOUNT_ACTIVATED");
});
