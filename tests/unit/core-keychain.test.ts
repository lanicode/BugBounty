import { createPrivateKey } from "node:crypto";
import { chmod, mkdtemp, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  CORE_EVENT_KEY_REFERENCE,
  CORE_OPERATOR_KEY_REFERENCE,
  MacOSCoreKeychainBackend,
  SpawnCoreKeychainHelperRunner,
  type CoreKeychainHelperOperation,
  type CoreKeychainHelperProcess,
  type CoreKeychainHelperRunner,
  type CoreProvisioningStateProbe,
} from "../../packages/secret-store/core-keychain.js";

const RECEIPT_MAGIC = Uint8Array.from([
  0x42, 0x42, 0x43, 0x4f, 0x52, 0x45, 0x52, 0x31,
]);
const INPUT_MAGIC = Uint8Array.from([
  0x42, 0x42, 0x43, 0x4f, 0x52, 0x45, 0x50, 0x31,
]);
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
  0x22, 0x04, 0x20,
]);

class StatefulRunner implements CoreKeychainHelperRunner {
  public readonly calls: {
    readonly operation: CoreKeychainHelperOperation;
    readonly inputCopy: Uint8Array | null;
    readonly inputReference: Uint8Array | undefined;
  }[] = [];
  public readonly outputs: Uint8Array[] = [];
  public status: 0 | 1 | 2 | 3 | 4 | 5 = 0;
  public operatorId = "local.admin";
  public eventKey = new Uint8Array(32).fill(0x5a);
  public operatorKey = operatorDer(0x6b);

  public execute(
    operation: CoreKeychainHelperOperation,
    input?: Uint8Array,
  ): Promise<Uint8Array> {
    this.calls.push({
      operation,
      inputCopy: input === undefined ? null : Uint8Array.from(input),
      inputReference: input,
    });
    if (operation === "provision-fresh") this.status = 1;
    if (operation === "complete-legacy") this.status = 2;
    const output =
      operation === "read-event"
        ? Uint8Array.from(this.eventKey)
        : operation === "read-operator"
          ? Uint8Array.from(this.operatorKey)
          : receipt(this.status, this.operatorId);
    this.outputs.push(output);
    return Promise.resolve(output);
  }
}

class SuccessfulProcess implements CoreKeychainHelperProcess {
  public inputReference: Uint8Array | undefined;
  public inputCopy: Uint8Array | undefined;
  public listenersRemoved = false;
  private stdoutListener: ((chunk: unknown) => void) | undefined;
  private closeListener:
    ((code: number | null, signal: NodeJS.Signals | null) => void) | undefined;

  public constructor(private readonly output: Buffer) {}

  public onStdoutData(listener: (chunk: unknown) => void): void {
    this.stdoutListener = listener;
  }
  public onStderrData(listener: (chunk: unknown) => void): void {
    void listener;
  }
  public onStdinError(listener: () => void): void {
    void listener;
  }
  public onError(listener: () => void): void {
    void listener;
  }
  public onClose(
    listener: (code: number | null, signal: NodeJS.Signals | null) => void,
  ): void {
    this.closeListener = listener;
  }
  public writeInput(input: Uint8Array | undefined): void {
    this.inputReference = input;
    this.inputCopy = input === undefined ? undefined : Uint8Array.from(input);
    this.stdoutListener?.(this.output);
    this.closeListener?.(0, null);
  }
  public removeAllListeners(): void {
    this.listenersRemoved = true;
    this.stdoutListener = undefined;
    this.closeListener = undefined;
  }
  public kill(): void {
    throw new Error("successful helper must not be killed");
  }
}

describe("macOS core keychain backend", () => {
  it("performs an explicit fresh bundle commit only after closed-state checks", async () => {
    const runner = new StatefulRunner();
    const backend = new MacOSCoreKeychainBackend("darwin", runner);
    const state = await safeStateProbe();

    const result = await backend.provisionFresh("local.admin", state);

    expect(result).toEqual({
      version: 1,
      mode: "fresh_bundle",
      operatorId: "local.admin",
      initialEventKeyVersion: 1,
      operatorKeyRevision: 1,
      generation: Buffer.alloc(16, 0x31).toString("base64url"),
    });
    expect(runner.calls.map((call) => call.operation)).toEqual([
      "inspect",
      "provision-fresh",
    ]);
    const provision = runner.calls[1];
    expect(provision?.inputCopy).toEqual(provisioningFrame("local.admin"));
    expect(provision?.inputReference?.every((byte) => byte === 0)).toBe(true);
    expect(
      runner.outputs.every((value) => value.every((byte) => byte === 0)),
    ).toBe(true);
  });

  it("completes only the exact legacy-ready state without receiving event-key bytes", async () => {
    const runner = new StatefulRunner();
    runner.status = 3;
    runner.operatorId = "legacy.reviewer";
    const backend = new MacOSCoreKeychainBackend("darwin", runner);

    const result = await backend.completeLegacy(
      "legacy.reviewer",
      await safeStateProbe(),
    );

    expect(result.mode).toBe("legacy_complete");
    expect(result.operatorId).toBe("legacy.reviewer");
    expect(runner.calls.map((call) => call.operation)).toEqual([
      "inspect",
      "complete-legacy",
    ]);
    expect(runner.calls.some((call) => call.operation === "read-event")).toBe(
      false,
    );
  });

  it("blocks conflicts, existing event stores, credentials, invalid IDs and platforms", async () => {
    const runner = new StatefulRunner();
    runner.status = 4;
    const backend = new MacOSCoreKeychainBackend("darwin", runner);
    await expect(
      backend.provisionFresh("local.admin", await safeStateProbe()),
    ).rejects.toThrow("CORE_KEYCHAIN_PROVISIONING_CONFLICT");

    const existingStore = await safeStateProbe();
    await writeFile(existingStore.eventStoreDirectory, "not-an-event-store", {
      mode: 0o600,
    });
    await expect(
      new MacOSCoreKeychainBackend(
        "darwin",
        new StatefulRunner(),
      ).provisionFresh("local.admin", existingStore),
    ).rejects.toThrow("CORE_KEYCHAIN_PROVISIONING_PRECONDITION_FAILED");

    const credential = await safeStateProbe(true);
    await expect(
      new MacOSCoreKeychainBackend(
        "darwin",
        new StatefulRunner(),
      ).provisionFresh("local.admin", credential),
    ).rejects.toThrow("CORE_KEYCHAIN_PROVISIONING_PRECONDITION_FAILED");
    await expect(
      new MacOSCoreKeychainBackend(
        "darwin",
        new StatefulRunner(),
      ).provisionFresh("../invalid", await safeStateProbe()),
    ).rejects.toThrow("CORE_KEYCHAIN_OPERATOR_ID_INVALID");
    await expect(
      new MacOSCoreKeychainBackend("linux", new StatefulRunner()).inspect(),
    ).rejects.toThrow("CORE_KEYCHAIN_UNAVAILABLE");
  });

  it("recognizes the receiptless legacy-direct compatibility state without making it provisionable", async () => {
    const runner = new StatefulRunner();
    runner.status = 5;
    const backend = new MacOSCoreKeychainBackend("darwin", runner);

    await expect(backend.inspect()).resolves.toEqual({
      status: "legacy_direct_complete",
      receipt: null,
    });
    await expect(
      backend.provisionFresh("local.admin", await safeStateProbe()),
    ).rejects.toThrow("CORE_KEYCHAIN_PROVISIONING_CONFLICT");
    expect(runner.calls.map((call) => call.operation)).not.toContain(
      "provision-fresh",
    );
    expect(runner.calls.map((call) => call.operation)).not.toContain(
      "complete-legacy",
    );
  });

  it("rechecks external state after commit and never attempts rollback deletion", async () => {
    const runner = new StatefulRunner();
    const base = await safeStateProbe();
    let probes = 0;
    const changingState: CoreProvisioningStateProbe = {
      eventStoreDirectory: base.eventStoreDirectory,
      hasOperatorCredential: () => {
        probes += 1;
        return probes > 1;
      },
    };

    await expect(
      new MacOSCoreKeychainBackend("darwin", runner).provisionFresh(
        "local.admin",
        changingState,
      ),
    ).rejects.toThrow("CORE_KEYCHAIN_PROVISIONING_PRECONDITION_FAILED");
    expect(probes).toBe(2);
    expect(runner.calls.map((call) => call.operation)).toEqual([
      "inspect",
      "provision-fresh",
    ]);
  });

  it("routes only the two fixed logical references and zeroes helper output", async () => {
    const runner = new StatefulRunner();
    const backend = new MacOSCoreKeychainBackend("darwin", runner);
    await expect(backend.get(CORE_EVENT_KEY_REFERENCE)).resolves.toEqual(
      runner.eventKey,
    );
    const operator = await backend.get(CORE_OPERATOR_KEY_REFERENCE);
    expect(operator).toEqual(runner.operatorKey);
    expect(
      createPrivateKey({ key: operator, format: "der", type: "pkcs8" })
        .asymmetricKeyType,
    ).toBe("ed25519");
    operator.fill(0);
    expect(
      runner.outputs.every((value) => value.every((byte) => byte === 0)),
    ).toBe(true);
    await expect(
      backend.get("keychain://bugbounty-copilot/event-store-v2"),
    ).rejects.toThrow("CORE_KEYCHAIN_REFERENCE_INVALID");
  });

  it("rejects malformed receipts and incorrectly sized secret output", async () => {
    const malformed: CoreKeychainHelperRunner = {
      execute: () => Promise.resolve(Uint8Array.from([1, 2, 3])),
    };
    await expect(
      new MacOSCoreKeychainBackend("darwin", malformed).inspect(),
    ).rejects.toThrow("CORE_KEYCHAIN_RECEIPT_INVALID");
    await expect(
      new MacOSCoreKeychainBackend("darwin", malformed).get(
        CORE_EVENT_KEY_REFERENCE,
      ),
    ).rejects.toThrow("CORE_KEYCHAIN_READ_FAILED");
  });
});

describe("core keychain helper runner", () => {
  it("passes the bounded stdin frame by pipe and zeroes all process buffers", async () => {
    const output = Buffer.from(receipt(1, "local.admin"));
    const process = new SuccessfulProcess(output);
    const runner = new SpawnCoreKeychainHelperRunner(
      () => Promise.resolve("/private/helper"),
      (path, operation) => {
        expect(path).toBe("/private/helper");
        expect(operation).toBe("provision-fresh");
        return process;
      },
    );
    const frame = provisioningFrame("local.admin");

    const result = await runner.execute("provision-fresh", frame);

    expect(result).toEqual(receipt(1, "local.admin"));
    expect(process.inputCopy).toEqual(frame);
    expect(process.inputReference?.every((byte) => byte === 0)).toBe(true);
    expect(output.every((byte) => byte === 0)).toBe(true);
    expect(process.listenersRemoved).toBe(true);
    result.fill(0);
    frame.fill(0);
  });

  it("rejects inputs on read operations and missing inputs on provisioning", async () => {
    const runner = new SpawnCoreKeychainHelperRunner(
      () => Promise.resolve("/private/helper"),
      () => new SuccessfulProcess(Buffer.from([1])),
    );
    await expect(
      runner.execute("read-event", Uint8Array.from([1])),
    ).rejects.toThrow("CORE_KEYCHAIN_HELPER_FAILED");
    await expect(runner.execute("complete-legacy")).rejects.toThrow(
      "CORE_KEYCHAIN_HELPER_FAILED",
    );
  });
});

async function safeStateProbe(
  hasCredential = false,
): Promise<CoreProvisioningStateProbe> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "core-keychain-state-")),
  );
  await chmod(root, 0o700);
  return {
    eventStoreDirectory: join(root, "event-store"),
    hasOperatorCredential: () => hasCredential,
  };
}

function receipt(
  status: 0 | 1 | 2 | 3 | 4 | 5,
  operatorId?: string,
): Uint8Array {
  if (status !== 1 && status !== 2)
    return Uint8Array.from([...RECEIPT_MAGIC, status]);
  if (operatorId === undefined) throw new Error("operator id required");
  const id = Buffer.from(operatorId, "ascii");
  return Uint8Array.from([
    ...RECEIPT_MAGIC,
    status,
    ...Buffer.alloc(16, 0x31),
    id.byteLength,
    ...id,
  ]);
}

function provisioningFrame(operatorId: string): Uint8Array {
  const id = Buffer.from(operatorId, "ascii");
  return Uint8Array.from([
    ...INPUT_MAGIC,
    (id.byteLength >>> 8) & 0xff,
    id.byteLength & 0xff,
    ...id,
  ]);
}

function operatorDer(seedByte: number): Uint8Array {
  return Uint8Array.from([
    ...PKCS8_PREFIX,
    ...new Uint8Array(32).fill(seedByte),
  ]);
}
