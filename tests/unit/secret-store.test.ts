import { expect, it } from "vitest";
import {
  MacOSKeychainSecretStore,
  type KeychainReader,
} from "../../packages/secret-store/store.js";

it("reads a keychain reference through the fixed reader abstraction", async () => {
  const calls: string[] = [];
  const reader: KeychainReader = {
    read(service, account) {
      calls.push(service, account);
      return Promise.resolve(Uint8Array.from([1, 2, 3]));
    },
  };
  const store = new MacOSKeychainSecretStore(reader, "darwin");
  await expect(store.get("keychain://bugbounty/account-a")).resolves.toEqual(
    Uint8Array.from([1, 2, 3]),
  );
  expect(calls).toEqual(["bugbounty", "account-a"]);
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
