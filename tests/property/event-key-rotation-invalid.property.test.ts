import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import fc from "fast-check";
import { expect, it } from "vitest";
import { EventKeyLifecycle } from "../../packages/event-key-lifecycle/index.js";
import { InMemorySecretStore } from "../../packages/secret-store/index.js";

const keyReference = (version: number): string =>
  `secret://property/invalid-rotation-v${String(version)}`;

it("never advances state for generated stale, skipped, backward, or invalid rotations", async () => {
  await fc.assert(
    fc.asyncProperty(
      fc.oneof(
        fc.record({
          expectedActiveKeyVersion: fc.integer({ min: 2, max: 10_000 }),
          nextKeyVersion: fc.integer({ min: 1, max: 10_000 }),
        }),
        fc.record({
          expectedActiveKeyVersion: fc.constant(1),
          nextKeyVersion: fc.oneof(
            fc.constant(1),
            fc.integer({ min: 3, max: 10_000 }),
          ),
        }),
        fc.constantFrom(
          { expectedActiveKeyVersion: 0, nextKeyVersion: 2 },
          { expectedActiveKeyVersion: 1, nextKeyVersion: 0 },
          { expectedActiveKeyVersion: 1, nextKeyVersion: 10_001 },
          { expectedActiveKeyVersion: 1.5, nextKeyVersion: 2 },
        ),
      ),
      async (rotation) => {
        const root = await mkdtemp(
          join(tmpdir(), "event-key-invalid-rotation-"),
        );
        const directory = join(root, "events");
        try {
          const secrets = new InMemorySecretStore();
          secrets.set(keyReference(1), new Uint8Array(32).fill(1));
          secrets.set(keyReference(2), new Uint8Array(32).fill(2));
          const lifecycle = await EventKeyLifecycle.initializeFresh({
            directory,
            secrets,
            keyReference,
            minimumActiveKeyVersion: 1,
          });
          await expect(lifecycle.rotate(rotation)).rejects.toThrow();
          expect(lifecycle.status()).toMatchObject({
            revision: 1,
            activeKeyVersion: 1,
            readableKeyVersions: [1],
          });
          expect(await readdir(join(directory, ".event-key-state"))).toEqual([
            "state-0000000001.json",
          ]);
        } finally {
          await rm(root, { recursive: true, force: true });
        }
      },
    ),
    { numRuns: 48 },
  );
});
