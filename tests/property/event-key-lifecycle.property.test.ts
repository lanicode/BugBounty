import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { expect, it } from "vitest";
import { EventKeyLifecycle } from "../../packages/event-key-lifecycle/index.js";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";
import { canonicalJson } from "../../packages/shared/canonical.js";

const KEY_REFERENCE = (version: number): string =>
  `secret://property/event-key-v${String(version)}`;

it("rejects every generated mutation of every authenticated state field", async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 0, max: 7 }), async (fieldIndex) => {
      const root = await mkdtemp(join(tmpdir(), "event-key-property-field-"));
      const directory = join(root, "events");
      try {
        const secrets = secretsFor(1);
        await EventKeyLifecycle.initializeFresh({
          directory,
          secrets,
          keyReference: KEY_REFERENCE,
          minimumActiveKeyVersion: 1,
        });
        const statePath = join(
          directory,
          ".event-key-state",
          "state-0000000001.json",
        );
        const original = JSON.parse(await readFile(statePath, "utf8")) as {
          schemaVersion: number;
          storeId: string;
          revision: number;
          operation: string;
          activeKeyVersion: number;
          readableKeyVersions: number[];
          previousRecordDigest: string;
          authenticationTag: string;
        };
        const mutated = mutateState(original, fieldIndex);
        await writeFile(statePath, canonicalJson(mutated), "utf8");
        await chmod(statePath, 0o600);
        await expect(
          EventKeyLifecycle.open({
            directory,
            secrets,
            keyReference: KEY_REFERENCE,
            minimumActiveKeyVersion: 1,
          }),
        ).rejects.toThrow();
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }),
    { numRuns: 32 },
  );
});

it("preserves every prior event across generated monotone rotations and restarts", async () => {
  await fc.assert(
    fc.asyncProperty(fc.integer({ min: 0, max: 5 }), async (rotations) => {
      const root = await mkdtemp(join(tmpdir(), "event-key-property-rotate-"));
      const directory = join(root, "events");
      try {
        const secrets = secretsFor(rotations + 1);
        let lifecycle = await EventKeyLifecycle.initializeFresh({
          directory,
          secrets,
          keyReference: KEY_REFERENCE,
          minimumActiveKeyVersion: 1,
        });
        const paths: string[] = [];
        paths.push(
          await lifecycle.write("event-v1", {
            keyVersionAtWrite: 1,
          }),
        );
        for (let version = 2; version <= rotations + 1; version += 1) {
          await lifecycle.rotate({
            expectedActiveKeyVersion: version - 1,
            nextKeyVersion: version,
          });
          paths.push(
            await lifecycle.write(`event-v${String(version)}`, {
              keyVersionAtWrite: version,
            }),
          );
          lifecycle = await EventKeyLifecycle.open({
            directory,
            secrets,
            keyReference: KEY_REFERENCE,
            minimumActiveKeyVersion: version,
          });
        }
        expect(lifecycle.status()).toMatchObject({
          revision: rotations + 1,
          activeKeyVersion: rotations + 1,
        });
        for (let index = 0; index < paths.length; index += 1) {
          const path = paths[index];
          expect(path).toBeDefined();
          await expect(lifecycle.read(path ?? "")).resolves.toEqual({
            keyVersionAtWrite: index + 1,
          });
        }
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }),
    { numRuns: 16 },
  );
});

function secretsFor(count: number): InMemorySecretStore {
  const secrets = new InMemorySecretStore();
  for (let version = 1; version <= count; version += 1) {
    const key = new Uint8Array(32).fill(version);
    key[0] = version;
    secrets.set(KEY_REFERENCE(version), key);
  }
  return secrets;
}

function mutateState(
  original: {
    readonly schemaVersion: number;
    readonly storeId: string;
    readonly revision: number;
    readonly operation: string;
    readonly activeKeyVersion: number;
    readonly readableKeyVersions: readonly number[];
    readonly previousRecordDigest: string;
    readonly authenticationTag: string;
  },
  fieldIndex: number,
): Record<string, unknown> {
  const mutated: Record<string, unknown> = {
    ...original,
    readableKeyVersions: [...original.readableKeyVersions],
  };
  switch (fieldIndex) {
    case 0:
      mutated["schemaVersion"] = 2;
      break;
    case 1:
      mutated["storeId"] = "f".repeat(64);
      break;
    case 2:
      mutated["revision"] = 2;
      break;
    case 3:
      mutated["operation"] = "rotate";
      break;
    case 4:
      mutated["activeKeyVersion"] = 2;
      break;
    case 5:
      mutated["readableKeyVersions"] = [1, 2];
      break;
    case 6:
      mutated["previousRecordDigest"] = "f".repeat(64);
      break;
    case 7:
      mutated["authenticationTag"] =
        original.authenticationTag === "f".repeat(64)
          ? "e".repeat(64)
          : "f".repeat(64);
      break;
  }
  return mutated;
}
