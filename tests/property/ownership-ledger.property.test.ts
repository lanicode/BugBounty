import { randomBytes } from "node:crypto";
import fc from "fast-check";
import { expect, it } from "vitest";
import {
  InMemoryOwnershipJournal,
  OwnershipLedger,
  SimulationReceiptAuthority,
} from "../../packages/ownership-ledger/ledger.js";

it("never treats a generated different account as the owner", async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.stringMatching(/^[a-z]{1,20}$/u),
      fc.stringMatching(/^[a-z]{1,20}$/u),
      async (owner, actor) => {
        fc.pre(owner !== actor);
        const authority = new SimulationReceiptAuthority(randomBytes(32));
        const ledger = new OwnershipLedger(
          authority,
          new InMemoryOwnershipJournal(),
          "a".repeat(64),
        );
        await ledger.activateAccount(
          authority.issueAccountActive({
            receiptId: "account-receipt",
            applicationRef: "local-app:fixture",
            accountRef: owner,
            policyHash: "a".repeat(64),
          }),
        );
        await ledger.registerObject(
          authority.issueObjectCreated({
            receiptId: "object-receipt",
            applicationRef: "local-app:fixture",
            accountRef: owner,
            objectRef: "object:1",
            policyHash: "a".repeat(64),
            canary: "local-canary",
          }),
        );
        expect(() =>
          ledger.assertOwned({
            applicationRef: "local-app:fixture",
            accountRef: actor,
            objectRef: "object:1",
            policyHash: "a".repeat(64),
          }),
        ).toThrow("OWNERSHIP_ACCOUNT_MISMATCH");
      },
    ),
    { numRuns: 100 },
  );
});

it("never accepts different signed receipt content as an idempotent replay", async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.stringMatching(/^[a-z]{1,20}$/u),
      fc.stringMatching(/^[a-z]{1,20}$/u),
      async (firstCanary, secondCanary) => {
        fc.pre(firstCanary !== secondCanary);
        const authority = new SimulationReceiptAuthority(randomBytes(32));
        const ledger = new OwnershipLedger(
          authority,
          new InMemoryOwnershipJournal(),
          "a".repeat(64),
        );
        await ledger.activateAccount(
          authority.issueAccountActive({
            receiptId: "account-receipt",
            applicationRef: "local-app:fixture",
            accountRef: "owner",
            policyHash: "a".repeat(64),
          }),
        );
        await ledger.registerObject(
          authority.issueObjectCreated({
            receiptId: "shared-receipt",
            applicationRef: "local-app:fixture",
            accountRef: "owner",
            objectRef: "object:1",
            policyHash: "a".repeat(64),
            canary: firstCanary,
          }),
        );
        await expect(
          ledger.registerObject(
            authority.issueObjectCreated({
              receiptId: "shared-receipt",
              applicationRef: "local-app:fixture",
              accountRef: "owner",
              objectRef: "object:1",
              policyHash: "a".repeat(64),
              canary: secondCanary,
            }),
          ),
        ).rejects.toThrow("OWNERSHIP_RECEIPT_CONFLICT");
      },
    ),
    { numRuns: 100 },
  );
});
