import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  InMemoryOwnershipJournal,
  OwnershipLedger,
  SimulationReceiptAuthority,
} from "../../packages/ownership-ledger/ledger.js";

const POLICY_HASH = "a".repeat(64);

function setup() {
  const authority = new SimulationReceiptAuthority(randomBytes(32));
  const journal = new InMemoryOwnershipJournal();
  const ledger = new OwnershipLedger(authority, journal, POLICY_HASH);
  return { authority, journal, ledger };
}

describe("ownership ledger", () => {
  it("requires signed account and object runner receipts", async () => {
    const { authority, journal, ledger } = setup();
    const account = authority.issueAccountActive({
      receiptId: "receipt-account",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      policyHash: POLICY_HASH,
    });
    await ledger.activateAccount(account);
    const rawCanary = ["local", "canary", "value"].join("-");
    const object = authority.issueObjectCreated({
      receiptId: "receipt-object",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:1",
      policyHash: POLICY_HASH,
      canary: rawCanary,
    });
    expect(JSON.stringify(object)).not.toContain(rawCanary);
    await ledger.registerObject(object);
    expect(
      ledger.assertOwned({
        applicationRef: "local-app:fixture",
        accountRef: "account-a",
        objectRef: "object:1",
        policyHash: POLICY_HASH,
      }),
    ).toMatchObject({ state: "ACTIVE", accountRef: "account-a" });
    expect(journal.events).toHaveLength(2);
  });

  it("blocks object-before-account, tampering, mismatch, drift and canary collision", async () => {
    const { authority, ledger } = setup();
    const object = authority.issueObjectCreated({
      receiptId: "receipt-object",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:1",
      policyHash: POLICY_HASH,
      canary: "canary-one",
    });
    await expect(ledger.registerObject(object)).rejects.toThrow(
      "OWNERSHIP_ACCOUNT_NOT_ACTIVE",
    );
    const account = authority.issueAccountActive({
      receiptId: "receipt-account",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      policyHash: POLICY_HASH,
    });
    await ledger.activateAccount(account);
    await expect(
      ledger.activateAccount({ ...account, accountRef: "account-b" }),
    ).rejects.toThrow("OWNERSHIP_RECEIPT_INVALID");
    await ledger.registerObject(object);
    expect(() =>
      ledger.assertOwned({
        applicationRef: "local-app:fixture",
        accountRef: "account-b",
        objectRef: "object:1",
        policyHash: POLICY_HASH,
      }),
    ).toThrow("OWNERSHIP_ACCOUNT_MISMATCH");
    expect(() =>
      ledger.assertOwned({
        applicationRef: "local-app:fixture",
        accountRef: "account-a",
        objectRef: "object:1",
        policyHash: "b".repeat(64),
      }),
    ).toThrow("OWNERSHIP_POLICY_DRIFT");
    const collision = authority.issueObjectCreated({
      receiptId: "receipt-object-two",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:2",
      policyHash: POLICY_HASH,
      canary: "canary-one",
    });
    await expect(ledger.registerObject(collision)).rejects.toThrow(
      "OWNERSHIP_CANARY_COLLISION",
    );
  });

  it("is idempotent for the same receipt and denies retired objects", async () => {
    const { authority, journal, ledger } = setup();
    const account = authority.issueAccountActive({
      receiptId: "account-receipt",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      policyHash: POLICY_HASH,
    });
    const object = authority.issueObjectCreated({
      receiptId: "object-receipt",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:1",
      policyHash: POLICY_HASH,
      canary: "canary",
    });
    await ledger.activateAccount(account);
    await ledger.activateAccount(account);
    await ledger.registerObject(object);
    await ledger.registerObject(object);
    expect(journal.events).toHaveLength(2);
    await ledger.retireObject({
      eventId: "retire-object",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:1",
      policyHash: POLICY_HASH,
    });
    expect(() =>
      ledger.assertOwned({
        applicationRef: "local-app:fixture",
        accountRef: "account-a",
        objectRef: "object:1",
        policyHash: POLICY_HASH,
      }),
    ).toThrow("OWNERSHIP_OBJECT_NOT_ACTIVE");
  });
});
