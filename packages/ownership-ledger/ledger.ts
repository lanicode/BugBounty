import { createHmac, timingSafeEqual } from "node:crypto";
import type { EncryptedEventStore } from "../event-store/store.js";
import { canonicalJson, type JsonValue } from "../shared/canonical.js";
import { SecurityError } from "../shared/errors.js";

export interface SimulationReceipt {
  readonly version: 1;
  readonly receiptId: string;
  readonly kind: "ACCOUNT_ACTIVE" | "OBJECT_CREATED";
  readonly applicationRef: string;
  readonly accountRef: string;
  readonly objectRef: string | null;
  readonly policyHash: string;
  readonly canaryHmac: string | null;
  readonly locatorPseudonym: string;
  readonly signature: string;
}

export interface OwnershipJournal {
  append(eventId: string, event: JsonValue): Promise<void>;
}

export class InMemoryOwnershipJournal implements OwnershipJournal {
  readonly events: JsonValue[] = [];
  public append(_eventId: string, event: JsonValue): Promise<void> {
    this.events.push(event);
    return Promise.resolve();
  }
}

export class EncryptedOwnershipJournal implements OwnershipJournal {
  public constructor(private readonly store: EncryptedEventStore) {}
  public async append(eventId: string, event: JsonValue): Promise<void> {
    await this.store.write(eventId, event);
  }
}

export class SimulationReceiptAuthority {
  public constructor(private readonly key: Uint8Array) {
    if (key.byteLength < 32) throw new SecurityError("RECEIPT_KEY_INVALID");
  }

  public issueAccountActive(input: {
    readonly receiptId: string;
    readonly applicationRef: string;
    readonly accountRef: string;
    readonly policyHash: string;
  }): SimulationReceipt {
    return this.sign({
      version: 1,
      receiptId: input.receiptId,
      kind: "ACCOUNT_ACTIVE",
      applicationRef: input.applicationRef,
      accountRef: input.accountRef,
      objectRef: null,
      policyHash: input.policyHash,
      canaryHmac: null,
      locatorPseudonym: this.pseudonym(input.accountRef),
    });
  }

  public issueObjectCreated(input: {
    readonly receiptId: string;
    readonly applicationRef: string;
    readonly accountRef: string;
    readonly objectRef: string;
    readonly policyHash: string;
    readonly canary: string;
  }): SimulationReceipt {
    return this.sign({
      version: 1,
      receiptId: input.receiptId,
      kind: "OBJECT_CREATED",
      applicationRef: input.applicationRef,
      accountRef: input.accountRef,
      objectRef: input.objectRef,
      policyHash: input.policyHash,
      canaryHmac: this.digest(`canary:${input.canary}`),
      locatorPseudonym: this.pseudonym(input.objectRef),
    });
  }

  public verify(receipt: SimulationReceipt): boolean {
    if (!isReceipt(receipt)) return false;
    const { signature, ...unsigned } = receipt;
    const expected = Buffer.from(this.digest(canonicalJson(unsigned)), "hex");
    const supplied = Buffer.from(signature, "hex");
    return (
      expected.byteLength === supplied.byteLength &&
      timingSafeEqual(expected, supplied)
    );
  }

  private sign(
    unsigned: Omit<SimulationReceipt, "signature">,
  ): SimulationReceipt {
    validateUnsigned(unsigned);
    return Object.freeze({
      ...unsigned,
      signature: this.digest(canonicalJson(unsigned)),
    });
  }

  private pseudonym(value: string): string {
    return `p:${this.digest(`locator:${value}`).slice(0, 24)}`;
  }

  private digest(value: string): string {
    return createHmac("sha256", this.key).update(value).digest("hex");
  }
}

interface AccountOwnership {
  readonly receiptId: string;
  readonly applicationRef: string;
  readonly accountRef: string;
  readonly policyHash: string;
  readonly state: "ACTIVE" | "RETIRED";
}

export interface ObjectOwnership {
  readonly receiptId: string;
  readonly applicationRef: string;
  readonly accountRef: string;
  readonly objectRef: string;
  readonly policyHash: string;
  readonly canaryHmac: string;
  readonly locatorPseudonym: string;
  readonly state: "ACTIVE" | "RETIRED";
}

export class OwnershipLedger {
  readonly #accounts = new Map<string, AccountOwnership>();
  readonly #objects = new Map<string, ObjectOwnership>();
  readonly #canaries = new Set<string>();

  public constructor(
    private readonly authority: SimulationReceiptAuthority,
    private readonly journal: OwnershipJournal,
    private readonly currentPolicyHash: string,
  ) {}

  public async activateAccount(receipt: SimulationReceipt): Promise<void> {
    this.assertReceipt(receipt, "ACCOUNT_ACTIVE");
    const key = accountKey(receipt.applicationRef, receipt.accountRef);
    const existing = this.#accounts.get(key);
    if (existing !== undefined) {
      if (existing.receiptId === receipt.receiptId) return;
      throw new SecurityError("OWNERSHIP_ACCOUNT_CONFLICT");
    }
    const record: AccountOwnership = Object.freeze({
      receiptId: receipt.receiptId,
      applicationRef: receipt.applicationRef,
      accountRef: receipt.accountRef,
      policyHash: receipt.policyHash,
      state: "ACTIVE",
    });
    await this.journal.append(
      receipt.receiptId,
      eventFor("ACCOUNT_ACTIVATED", record),
    );
    this.#accounts.set(key, record);
  }

  public async registerObject(receipt: SimulationReceipt): Promise<void> {
    this.assertReceipt(receipt, "OBJECT_CREATED");
    if (receipt.objectRef === null || receipt.canaryHmac === null)
      throw new SecurityError("OWNERSHIP_RECEIPT_INVALID");
    const account = this.#accounts.get(
      accountKey(receipt.applicationRef, receipt.accountRef),
    );
    if (account?.state !== "ACTIVE")
      throw new SecurityError("OWNERSHIP_ACCOUNT_NOT_ACTIVE");
    const key = objectKey(receipt.applicationRef, receipt.objectRef);
    const existing = this.#objects.get(key);
    if (existing !== undefined) {
      if (existing.receiptId === receipt.receiptId) return;
      throw new SecurityError("OWNERSHIP_OBJECT_CONFLICT");
    }
    if (this.#canaries.has(receipt.canaryHmac))
      throw new SecurityError("OWNERSHIP_CANARY_COLLISION");
    const record: ObjectOwnership = Object.freeze({
      receiptId: receipt.receiptId,
      applicationRef: receipt.applicationRef,
      accountRef: receipt.accountRef,
      objectRef: receipt.objectRef,
      policyHash: receipt.policyHash,
      canaryHmac: receipt.canaryHmac,
      locatorPseudonym: receipt.locatorPseudonym,
      state: "ACTIVE",
    });
    await this.journal.append(
      receipt.receiptId,
      eventFor("OBJECT_REGISTERED", record),
    );
    this.#objects.set(key, record);
    this.#canaries.add(receipt.canaryHmac);
  }

  public assertOwned(input: {
    readonly applicationRef: string;
    readonly accountRef: string;
    readonly objectRef: string;
    readonly policyHash: string;
  }): ObjectOwnership {
    if (input.policyHash !== this.currentPolicyHash)
      throw new SecurityError("OWNERSHIP_POLICY_DRIFT");
    const record = this.#objects.get(
      objectKey(input.applicationRef, input.objectRef),
    );
    if (record?.state !== "ACTIVE")
      throw new SecurityError("OWNERSHIP_OBJECT_NOT_ACTIVE");
    if (record.accountRef !== input.accountRef)
      throw new SecurityError("OWNERSHIP_ACCOUNT_MISMATCH");
    return record;
  }

  public async retireObject(input: {
    readonly eventId: string;
    readonly applicationRef: string;
    readonly accountRef: string;
    readonly objectRef: string;
    readonly policyHash: string;
  }): Promise<void> {
    const record = this.assertOwned(input);
    const retired = Object.freeze({ ...record, state: "RETIRED" as const });
    await this.journal.append(
      input.eventId,
      eventFor("OBJECT_RETIRED", retired),
    );
    this.#objects.set(
      objectKey(input.applicationRef, input.objectRef),
      retired,
    );
  }

  private assertReceipt(
    receipt: SimulationReceipt,
    kind: SimulationReceipt["kind"],
  ): void {
    if (!this.authority.verify(receipt) || receipt.kind !== kind)
      throw new SecurityError("OWNERSHIP_RECEIPT_INVALID");
    if (receipt.policyHash !== this.currentPolicyHash)
      throw new SecurityError("OWNERSHIP_POLICY_DRIFT");
  }
}

function eventFor(
  type: string,
  record: AccountOwnership | ObjectOwnership,
): JsonValue {
  return {
    version: 1,
    type,
    record: {
      receiptId: record.receiptId,
      applicationRef: record.applicationRef,
      accountRef: record.accountRef,
      policyHash: record.policyHash,
      state: record.state,
      ...(isObjectOwnership(record)
        ? {
            objectRef: record.objectRef,
            canaryHmac: record.canaryHmac,
            locatorPseudonym: record.locatorPseudonym,
          }
        : {}),
    },
  };
}

function isObjectOwnership(
  record: AccountOwnership | ObjectOwnership,
): record is ObjectOwnership {
  return "objectRef" in record;
}

function validateUnsigned(receipt: Omit<SimulationReceipt, "signature">): void {
  if (
    !/^[A-Za-z0-9_-]{1,128}$/u.test(receipt.receiptId) ||
    !/^local-app:[A-Za-z0-9_-]{1,100}$/u.test(receipt.applicationRef) ||
    !/^[A-Za-z0-9_-]{1,128}$/u.test(receipt.accountRef) ||
    !/^[a-f0-9]{64}$/u.test(receipt.policyHash) ||
    (receipt.objectRef !== null &&
      !/^[A-Za-z0-9:_-]{1,160}$/u.test(receipt.objectRef))
  )
    throw new SecurityError("OWNERSHIP_RECEIPT_INVALID");
}

function isReceipt(value: unknown): value is SimulationReceipt {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  return (
    "version" in value &&
    value.version === 1 &&
    "receiptId" in value &&
    typeof value.receiptId === "string" &&
    "kind" in value &&
    (value.kind === "ACCOUNT_ACTIVE" || value.kind === "OBJECT_CREATED") &&
    "applicationRef" in value &&
    typeof value.applicationRef === "string" &&
    "accountRef" in value &&
    typeof value.accountRef === "string" &&
    "objectRef" in value &&
    (value.objectRef === null || typeof value.objectRef === "string") &&
    "policyHash" in value &&
    typeof value.policyHash === "string" &&
    "canaryHmac" in value &&
    (value.canaryHmac === null || typeof value.canaryHmac === "string") &&
    "locatorPseudonym" in value &&
    typeof value.locatorPseudonym === "string" &&
    "signature" in value &&
    /^[a-f0-9]{64}$/u.test(
      typeof value.signature === "string" ? value.signature : "",
    )
  );
}

function accountKey(applicationRef: string, accountRef: string): string {
  return `${applicationRef}\u0000${accountRef}`;
}

function objectKey(applicationRef: string, objectRef: string): string {
  return `${applicationRef}\u0000${objectRef}`;
}
