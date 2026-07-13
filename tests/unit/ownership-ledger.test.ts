import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  InMemoryOwnershipJournal,
  OwnershipLedger,
  SimulationReceiptAuthority,
  type OwnershipJournal,
} from "../../packages/ownership-ledger/ledger.js";

const POLICY_HASH = "a".repeat(64);

function setup() {
  const authority = new SimulationReceiptAuthority(randomBytes(32));
  const journal = new InMemoryOwnershipJournal();
  const ledger = new OwnershipLedger(authority, journal, POLICY_HASH);
  return { authority, journal, ledger };
}

class FailableJournal implements OwnershipJournal {
  public readonly events: Parameters<OwnershipJournal["append"]>[1][] = [];
  public failNext = false;

  public append(
    _eventId: string,
    event: Parameters<OwnershipJournal["append"]>[1],
  ): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      return Promise.reject(new Error("JOURNAL_FAILURE"));
    }
    this.events.push(event);
    return Promise.resolve();
  }
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

  it("treats only an exactly identical full receipt as idempotent", async () => {
    const { authority, journal, ledger } = setup();
    const account = authority.issueAccountActive({
      receiptId: "shared-account-receipt",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      policyHash: POLICY_HASH,
    });
    await ledger.activateAccount(account);
    await expect(ledger.activateAccount(account)).resolves.toBeUndefined();
    await expect(
      ledger.activateAccount(
        authority.issueAccountActive({
          receiptId: "shared-account-receipt",
          applicationRef: "local-app:fixture",
          accountRef: "account-b",
          policyHash: POLICY_HASH,
        }),
      ),
    ).rejects.toThrow("OWNERSHIP_RECEIPT_CONFLICT");

    const object = authority.issueObjectCreated({
      receiptId: "shared-object-receipt",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:shared",
      policyHash: POLICY_HASH,
      canary: "canary-one",
    });
    await ledger.registerObject(object);
    await expect(ledger.registerObject(object)).resolves.toBeUndefined();
    await expect(
      ledger.registerObject(
        authority.issueObjectCreated({
          receiptId: "shared-object-receipt",
          applicationRef: "local-app:fixture",
          accountRef: "account-a",
          objectRef: "object:shared",
          policyHash: POLICY_HASH,
          canary: "canary-two",
        }),
      ),
    ).rejects.toThrow("OWNERSHIP_RECEIPT_CONFLICT");
    expect(journal.events).toHaveLength(2);
  });

  it("serializes concurrent receipt, object, canary and retirement races", async () => {
    const { authority, journal, ledger } = setup();
    const account = authority.issueAccountActive({
      receiptId: "parallel-account",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      policyHash: POLICY_HASH,
    });
    await Promise.all(
      Array.from({ length: 8 }, () => ledger.activateAccount(account)),
    );
    expect(journal.events).toHaveLength(1);

    const object = authority.issueObjectCreated({
      receiptId: "parallel-object",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:parallel",
      policyHash: POLICY_HASH,
      canary: "parallel-canary",
    });
    await Promise.all(
      Array.from({ length: 8 }, () => ledger.registerObject(object)),
    );
    expect(journal.events).toHaveLength(2);

    const objectWinner = authority.issueObjectCreated({
      receiptId: "object-race-winner",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:shared-race",
      policyHash: POLICY_HASH,
      canary: "object-race-canary-one",
    });
    const objectLoser = authority.issueObjectCreated({
      receiptId: "object-race-loser",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:shared-race",
      policyHash: POLICY_HASH,
      canary: "object-race-canary-two",
    });
    const firstObject = ledger.registerObject(objectWinner);
    const secondObject = ledger.registerObject(objectLoser);
    await expect(firstObject).resolves.toBeUndefined();
    await expect(secondObject).rejects.toThrow("OWNERSHIP_OBJECT_CONFLICT");
    expect(journal.events).toHaveLength(3);

    const canaryWinner = authority.issueObjectCreated({
      receiptId: "canary-race-winner",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:canary-winner",
      policyHash: POLICY_HASH,
      canary: "shared-race-canary",
    });
    const canaryLoser = authority.issueObjectCreated({
      receiptId: "canary-race-loser",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:canary-loser",
      policyHash: POLICY_HASH,
      canary: "shared-race-canary",
    });
    const winner = ledger.registerObject(canaryWinner);
    const loser = ledger.registerObject(canaryLoser);
    await expect(winner).resolves.toBeUndefined();
    await expect(loser).rejects.toThrow("OWNERSHIP_CANARY_COLLISION");
    expect(journal.events).toHaveLength(4);

    const retirement = {
      eventId: "parallel-retirement-one",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:canary-winner",
      policyHash: POLICY_HASH,
    };
    const firstRetirement = ledger.retireObject(retirement);
    const secondRetirement = ledger.retireObject({
      ...retirement,
      eventId: "parallel-retirement-two",
    });
    await expect(firstRetirement).resolves.toBeUndefined();
    await expect(secondRetirement).rejects.toThrow(
      "OWNERSHIP_OBJECT_NOT_ACTIVE",
    );
    expect(journal.events).toHaveLength(5);
  });

  it("never commits memory state when the journal append fails", async () => {
    const authority = new SimulationReceiptAuthority(randomBytes(32));
    const journal = new FailableJournal();
    const ledger = new OwnershipLedger(authority, journal, POLICY_HASH);
    const account = authority.issueAccountActive({
      receiptId: "recoverable-account",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      policyHash: POLICY_HASH,
    });
    journal.failNext = true;
    await expect(ledger.activateAccount(account)).rejects.toThrow(
      "JOURNAL_FAILURE",
    );
    await expect(ledger.activateAccount(account)).resolves.toBeUndefined();
    expect(journal.events).toHaveLength(1);

    const object = authority.issueObjectCreated({
      receiptId: "recoverable-object",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:recoverable",
      policyHash: POLICY_HASH,
      canary: "recoverable-canary",
    });
    journal.failNext = true;
    await expect(ledger.registerObject(object)).rejects.toThrow(
      "JOURNAL_FAILURE",
    );
    expect(() =>
      ledger.assertOwned({
        applicationRef: "local-app:fixture",
        accountRef: "account-a",
        objectRef: "object:recoverable",
        policyHash: POLICY_HASH,
      }),
    ).toThrow("OWNERSHIP_OBJECT_NOT_ACTIVE");
    await expect(ledger.registerObject(object)).resolves.toBeUndefined();

    const retirement = {
      eventId: "recoverable-retirement",
      applicationRef: "local-app:fixture",
      accountRef: "account-a",
      objectRef: "object:recoverable",
      policyHash: POLICY_HASH,
    };
    journal.failNext = true;
    await expect(ledger.retireObject(retirement)).rejects.toThrow(
      "JOURNAL_FAILURE",
    );
    expect(
      ledger.assertOwned({
        applicationRef: "local-app:fixture",
        accountRef: "account-a",
        objectRef: "object:recoverable",
        policyHash: POLICY_HASH,
      }).state,
    ).toBe("ACTIVE");
    await expect(ledger.retireObject(retirement)).resolves.toBeUndefined();
    expect(() => ledger.assertOwned(retirement)).toThrow(
      "OWNERSHIP_OBJECT_NOT_ACTIVE",
    );
    expect(journal.events).toHaveLength(3);
  });
});
