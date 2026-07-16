import { generateKeyPairSync } from "node:crypto";
import type {
  CoreKeychainHelperOperation,
  CoreKeychainHelperRunner,
  CoreKeychainStatus,
} from "../../packages/secret-store/index.js";

const RECEIPT_MAGIC = Uint8Array.from([
  0x42, 0x42, 0x43, 0x4f, 0x52, 0x45, 0x52, 0x31,
]);
const INPUT_MAGIC = Uint8Array.from([
  0x42, 0x42, 0x43, 0x4f, 0x52, 0x45, 0x50, 0x31,
]);
const GENERATION = Uint8Array.from({ length: 16 }, (_, index) => index + 1);

export class TestCoreKeychainRunner implements CoreKeychainHelperRunner {
  public readonly operations: CoreKeychainHelperOperation[] = [];
  public status: CoreKeychainStatus;
  public operatorId: string;
  public failInspection = false;
  readonly #eventKey = new Uint8Array(32).fill(0x51);
  readonly #operatorKey: Uint8Array;

  public constructor(
    status: CoreKeychainStatus = "absent",
    operatorId = "local-operator",
  ) {
    this.status = status;
    this.operatorId = operatorId;
    const { privateKey } = generateKeyPairSync("ed25519");
    const der = privateKey.export({ format: "der", type: "pkcs8" });
    this.#operatorKey = Uint8Array.from(der);
    der.fill(0);
  }

  public execute(
    operation: CoreKeychainHelperOperation,
    input?: Uint8Array,
  ): Promise<Uint8Array> {
    this.operations.push(operation);
    if (operation === "inspect") {
      if (this.failInspection) return Promise.reject(new Error("inspect"));
      return Promise.resolve(receipt(this.status, this.operatorId));
    }
    if (operation === "provision-fresh") {
      if (this.status !== "absent" || input === undefined)
        return Promise.reject(new Error("state"));
      this.operatorId = operatorIdFromFrame(input);
      this.status = "fresh_bundle";
      return Promise.resolve(receipt(this.status, this.operatorId));
    }
    if (operation === "complete-legacy") {
      if (this.status !== "legacy_ready" || input === undefined)
        return Promise.reject(new Error("state"));
      this.operatorId = operatorIdFromFrame(input);
      this.status = "legacy_complete";
      return Promise.resolve(receipt(this.status, this.operatorId));
    }
    if (input !== undefined) return Promise.reject(new Error("input"));
    if (operation === "read-event" && isReadableStatus(this.status))
      return Promise.resolve(Uint8Array.from(this.#eventKey));
    if (operation === "read-operator" && isCompleteStatus(this.status))
      return Promise.resolve(Uint8Array.from(this.#operatorKey));
    return Promise.reject(new Error("unavailable"));
  }
}

function receipt(status: CoreKeychainStatus, operatorId: string): Uint8Array {
  const statusByte = {
    absent: 0,
    fresh_bundle: 1,
    legacy_complete: 2,
    legacy_ready: 3,
    conflict: 4,
    legacy_direct_complete: 5,
  }[status];
  if (!isCompleteStatus(status)) {
    const output = new Uint8Array(RECEIPT_MAGIC.byteLength + 1);
    output.set(RECEIPT_MAGIC);
    output[RECEIPT_MAGIC.byteLength] = statusByte;
    return output;
  }
  const operatorBytes = Buffer.from(operatorId, "ascii");
  try {
    const output = new Uint8Array(
      RECEIPT_MAGIC.byteLength +
        1 +
        GENERATION.byteLength +
        1 +
        operatorBytes.byteLength,
    );
    output.set(RECEIPT_MAGIC);
    output[RECEIPT_MAGIC.byteLength] = statusByte;
    const generationOffset = RECEIPT_MAGIC.byteLength + 1;
    output.set(GENERATION, generationOffset);
    output[generationOffset + GENERATION.byteLength] = operatorBytes.byteLength;
    output.set(operatorBytes, generationOffset + GENERATION.byteLength + 1);
    return output;
  } finally {
    operatorBytes.fill(0);
  }
}

function operatorIdFromFrame(frame: Uint8Array): string {
  if (
    frame.byteLength < INPUT_MAGIC.byteLength + 3 ||
    INPUT_MAGIC.some((byte, index) => frame[index] !== byte)
  )
    throw new Error("frame");
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const length = view.getUint16(INPUT_MAGIC.byteLength, false);
  if (frame.byteLength !== INPUT_MAGIC.byteLength + 2 + length)
    throw new Error("frame");
  return Buffer.from(frame.subarray(INPUT_MAGIC.byteLength + 2)).toString(
    "ascii",
  );
}

function isCompleteStatus(status: CoreKeychainStatus): boolean {
  return status === "fresh_bundle" || status === "legacy_complete";
}

function isReadableStatus(status: CoreKeychainStatus): boolean {
  return (
    isCompleteStatus(status) ||
    status === "legacy_direct_complete" ||
    status === "legacy_ready"
  );
}
