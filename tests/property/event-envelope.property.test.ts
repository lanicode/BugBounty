import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { afterEach, expect, it } from "vitest";
import { EncryptedEventStore } from "../../packages/event-store/index.js";
import {
  InMemorySecretStore,
  type SecretStore,
} from "../../packages/secret-store/index.js";

const roots: string[] = [];
const KEY_REFERENCE = "secret://property/event-envelope-v1";

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture(label: string) {
  const root = await mkdtemp(join(tmpdir(), `event-envelope-${label}-`));
  roots.push(root);
  const key = randomBytes(32);
  const secrets = new InMemorySecretStore();
  secrets.set(KEY_REFERENCE, key);
  const writer = new EncryptedEventStore(root, secrets, () => KEY_REFERENCE);
  const path = await writer.write("event", { property: true });
  const envelope = JSON.parse(await readFile(path, "utf8")) as Record<
    string,
    unknown
  >;
  return { root, key, path, envelope };
}

it("rejects generated malformed envelope fields before any secret lookup", async () => {
  const { root, key, path, envelope } = await fixture("invalid");
  let secretCalls = 0;
  const countingSecrets: SecretStore = {
    get() {
      secretCalls += 1;
      return Promise.resolve(Uint8Array.from(key));
    },
  };
  const reader = new EncryptedEventStore(
    root,
    countingSecrets,
    () => KEY_REFERENCE,
    1,
    [1],
  );

  await fc.assert(
    fc.asyncProperty(
      fc.integer({ min: 0, max: 7 }),
      fc.integer({ min: 0, max: 32 }),
      async (field, magnitude) => {
        const mutation: Record<string, unknown> = { ...envelope };
        switch (field) {
          case 0:
            mutation["version"] = magnitude + 2;
            break;
          case 1:
            mutation["keyVersion"] = magnitude % 2 === 0 ? 0 : 10_001;
            break;
          case 2:
            mutation["keyVersion"] = 2;
            break;
          case 3: {
            const length = magnitude === 12 ? 11 : magnitude;
            mutation["nonce"] = Buffer.alloc(length).toString("base64");
            break;
          }
          case 4: {
            const length = magnitude === 16 ? 15 : magnitude;
            mutation["tag"] = Buffer.alloc(length).toString("base64");
            break;
          }
          case 5:
            mutation["ciphertext"] = magnitude % 2 === 0 ? "" : "A===";
            break;
          case 6:
            mutation["nonce"] = "***not-base64***";
            break;
          default:
            mutation["unexpected"] = magnitude;
        }
        await writeFile(path, JSON.stringify(mutation), "utf8");
        secretCalls = 0;
        await expect(reader.read(path)).rejects.toThrow(
          /EVENT_(?:ENVELOPE_INVALID|KEY_VERSION_(?:INVALID|NOT_READABLE))/u,
        );
        expect(secretCalls).toBe(0);
      },
    ),
    { numRuns: 64 },
  );
});

it("rejects every generated authenticated-length ciphertext mutation", async () => {
  const { root, key, path, envelope } = await fixture("integrity");
  const ciphertext = Buffer.from(String(envelope["ciphertext"]), "base64");
  const secrets: SecretStore = {
    get: () => Promise.resolve(Uint8Array.from(key)),
  };
  const reader = new EncryptedEventStore(root, secrets, () => KEY_REFERENCE);

  await fc.assert(
    fc.asyncProperty(
      fc.nat({ max: Math.max(0, ciphertext.byteLength - 1) }),
      fc.integer({ min: 1, max: 255 }),
      async (offset, xor) => {
        const tampered = Buffer.from(ciphertext);
        const index = offset % tampered.byteLength;
        const original = tampered[index];
        expect(original).toBeDefined();
        tampered[index] = (original ?? 0) ^ xor;
        await writeFile(
          path,
          JSON.stringify({
            ...envelope,
            ciphertext: tampered.toString("base64"),
          }),
          "utf8",
        );
        await expect(reader.read(path)).rejects.toThrow(
          "EVENT_INTEGRITY_FAILED",
        );
      },
    ),
    { numRuns: 32 },
  );
});
