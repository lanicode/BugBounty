import { expect, it } from "vitest";
import {
  MacOSKeychainSecretStore,
  SecurityCliKeychainReader,
  type KeychainReader,
  type SecurityCliExecutor,
} from "../../packages/secret-store/store.js";

it("reads a keychain reference through the fixed reader abstraction", async () => {
  const calls: string[] = [];
  const readerValue = Uint8Array.from([1, 2, 3]);
  const reader: KeychainReader = {
    read(service, account) {
      calls.push(service, account);
      return Promise.resolve(readerValue);
    },
  };
  const store = new MacOSKeychainSecretStore(reader, "darwin");
  await expect(store.get("keychain://bugbounty/account-a")).resolves.toEqual(
    Uint8Array.from([1, 2, 3]),
  );
  expect(calls).toEqual(["bugbounty", "account-a"]);
  expect(readerValue).toEqual(Uint8Array.from([0, 0, 0]));
});

it("fails closed for unavailable platforms, invalid refs and reader failure", async () => {
  const failing: KeychainReader = {
    read: () => Promise.reject(new Error("internal-sensitive-error")),
  };
  await expect(
    new MacOSKeychainSecretStore(failing, "linux").get(
      "keychain://bugbounty/account",
    ),
  ).rejects.toThrow("KEYCHAIN_UNAVAILABLE");
  await expect(
    new MacOSKeychainSecretStore(failing, "darwin").get("invalid"),
  ).rejects.toThrow("SECRET_REFERENCE_INVALID");
  await expect(
    new MacOSKeychainSecretStore(failing, "darwin").get(
      "keychain://bugbounty/account",
    ),
  ).rejects.toThrow("KEYCHAIN_READ_FAILED");
});

it("zeroes an invalid reader buffer before failing closed", async () => {
  const oversized = new Uint8Array(4_097).fill(0x61);
  const reader: KeychainReader = {
    read: () => Promise.resolve(oversized),
  };

  await expect(
    new MacOSKeychainSecretStore(reader, "darwin").get(
      "keychain://bugbounty/account",
    ),
  ).rejects.toThrow("KEYCHAIN_READ_FAILED");
  expect(oversized.every((byte) => byte === 0)).toBe(true);
});

it("reads the safe maximum from security CLI and zeroes both output buffers", async () => {
  const stdout = Buffer.alloc(4_097, 0x61);
  stdout[4_096] = 0x0a;
  const stderr = Buffer.alloc(0);
  const calls: unknown[][] = [];
  const executor: SecurityCliExecutor = (file, args, options) => {
    calls.push([file, args, options]);
    return Promise.resolve({ stdout, stderr });
  };

  const value = await new SecurityCliKeychainReader(executor).read(
    "bugbounty",
    "account-a",
  );

  expect(value).toHaveLength(4_096);
  expect(value.every((byte) => byte === 0x61)).toBe(true);
  expect(stdout.every((byte) => byte === 0)).toBe(true);
  expect(stderr.every((byte) => byte === 0)).toBe(true);
  expect(calls).toEqual([
    [
      "/usr/bin/security",
      ["find-generic-password", "-s", "bugbounty", "-a", "account-a", "-w"],
      {
        encoding: "buffer",
        maxBuffer: 4_097,
        timeout: 5_000,
        windowsHide: true,
      },
    ],
  ]);
  value.fill(0);
});

it("rejects over-boundary output and zeroes normal failure output", async () => {
  const oversized = Buffer.alloc(4_097, 0x61);
  const stderr = Buffer.from("synthetic-sensitive-error");
  const executor: SecurityCliExecutor = () =>
    Promise.resolve({ stdout: oversized, stderr });

  await expect(
    new SecurityCliKeychainReader(executor).read("bugbounty", "account-a"),
  ).rejects.toThrow("KEYCHAIN_READ_FAILED");
  expect(oversized.every((byte) => byte === 0)).toBe(true);
  expect(stderr.every((byte) => byte === 0)).toBe(true);
});

it("zeroes security CLI stdout and stderr attached to an execution error", async () => {
  const stdout = Buffer.from("synthetic-sensitive-stdout");
  const stderr = Buffer.from("synthetic-sensitive-stderr");
  const failure = Object.assign(new Error("synthetic-sensitive-error"), {
    stdout,
    stderr,
  });
  const executor: SecurityCliExecutor = () => Promise.reject(failure);

  await expect(
    new SecurityCliKeychainReader(executor).read("bugbounty", "account-a"),
  ).rejects.toThrow("KEYCHAIN_READ_FAILED");
  expect(stdout.every((byte) => byte === 0)).toBe(true);
  expect(stderr.every((byte) => byte === 0)).toBe(true);
});
