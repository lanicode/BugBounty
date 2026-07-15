import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import {
  hackerOneCredentialCliExitCode,
  readHiddenCredential,
  type HiddenCredentialInput,
  type HiddenCredentialOutput,
} from "../../apps/hackerone-credentials-cli/index.js";

describe("HackerOne credential TTY", () => {
  it("completes two sequential hidden prompts and pauses stdin after each", async () => {
    const { input, setRawMode } = fakeTtyInput();
    const writes: string[] = [];
    const output = fakeOutput(writes);

    const identifierPromise = readHiddenCredential(
      "HackerOne API-Identifier: ",
      input,
      output,
    );
    input.write("synthetic-identifier\r");
    const identifier = await identifierPromise;
    expect(new TextDecoder().decode(identifier)).toBe("synthetic-identifier");
    expect(input.isPaused()).toBe(true);
    expect(input.listenerCount("data")).toBe(0);

    const tokenPromise = readHiddenCredential(
      "HackerOne API-Token: ",
      input,
      output,
    );
    input.write("synthetic-token\r");
    const token = await tokenPromise;
    expect(new TextDecoder().decode(token)).toBe("synthetic-token");
    expect(input.isPaused()).toBe(true);
    expect(input.listenerCount("data")).toBe(0);
    expect(writes).toEqual([
      "HackerOne API-Identifier: ",
      "\n",
      "HackerOne API-Token: ",
      "\n",
    ]);
    expect(setRawMode.mock.calls).toEqual([[true], [false], [true], [false]]);
    identifier.fill(0);
    token.fill(0);
  });

  it("maps a local Ctrl-C abort to exit status 130 without leaving stdin live", async () => {
    const { input } = fakeTtyInput();
    let thrown: unknown;
    const pending = readHiddenCredential("Synthetic prompt: ", input, {
      write: () => true,
    });
    input.write(Buffer.from([0x03]));
    try {
      await pending;
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({ code: "HACKERONE_TTY_INPUT_ABORTED" });
    expect(hackerOneCredentialCliExitCode(thrown)).toBe(130);
    expect(input.isPaused()).toBe(true);
    expect(input.listenerCount("data")).toBe(0);
  });
});

function fakeTtyInput(): {
  readonly input: PassThrough & HiddenCredentialInput;
  readonly setRawMode: ReturnType<typeof vi.fn>;
} {
  const input = new PassThrough() as PassThrough & HiddenCredentialInput;
  Object.defineProperty(input, "isRaw", {
    configurable: true,
    value: false,
    writable: true,
  });
  const setRawMode = vi.fn((enabled: boolean) => {
    input.isRaw = enabled;
    return input;
  });
  input.setRawMode = setRawMode;
  return { input, setRawMode };
}

function fakeOutput(writes: string[]): HiddenCredentialOutput {
  return {
    write: (value: string | Uint8Array) => {
      writes.push(String(value));
      return true;
    },
  };
}
