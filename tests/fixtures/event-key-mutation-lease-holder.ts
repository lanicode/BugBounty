import { once } from "node:events";
import { EventKeyLifecycle } from "../../packages/event-key-lifecycle/index.js";
import {
  InMemorySecretStore,
  type SecretStore,
} from "../../packages/secret-store/index.js";

const directory = process.argv[2];
if (directory === undefined) throw new Error("TEST_EVENT_DIRECTORY_REQUIRED");
const mode = process.argv[3] ?? "write";
if (!new Set(["write", "rotate-pre-link", "rotate-post-link"]).has(mode))
  throw new Error("TEST_EVENT_MUTATION_MODE_INVALID");

const KEY_REFERENCE = (version: number): string =>
  `secret://event-key/v${String(version)}`;
class ProcessGateSecretStore implements SecretStore {
  #armed = false;
  #v2Calls = 0;

  public constructor(private readonly backing: SecretStore) {}

  public arm(): void {
    this.#armed = true;
  }

  public async get(reference: string): Promise<Uint8Array> {
    if (reference === KEY_REFERENCE(2)) this.#v2Calls += 1;
    const shouldBlock =
      this.#armed &&
      (mode === "write" ||
        (mode === "rotate-pre-link" && this.#v2Calls === 1) ||
        (mode === "rotate-post-link" && this.#v2Calls === 2));
    if (shouldBlock) {
      this.#armed = false;
      process.stdout.write("LOCKED\n");
      await once(process.stdin, "data");
    }
    return this.backing.get(reference);
  }
}

const backing = new InMemorySecretStore();
backing.set(KEY_REFERENCE(1), new Uint8Array(32).fill(1));
backing.set(KEY_REFERENCE(2), new Uint8Array(32).fill(2));
const gated = new ProcessGateSecretStore(backing);
const lifecycle = await EventKeyLifecycle.open({
  directory,
  secrets: gated,
  keyReference: KEY_REFERENCE,
  minimumActiveKeyVersion: 1,
});

gated.arm();
if (mode === "write")
  await lifecycle.write("child-process", { source: "local-child" });
else
  await lifecycle.rotate({
    expectedActiveKeyVersion: 1,
    nextKeyVersion: 2,
  });
process.stdout.write("DONE\n");
