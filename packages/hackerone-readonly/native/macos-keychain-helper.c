#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#ifndef BUGBOUNTY_KEYCHAIN_SERVICE
#define BUGBOUNTY_KEYCHAIN_SERVICE "bugbounty-copilot"
#endif

#ifndef BUGBOUNTY_HACKERONE_IDENTIFIER_ACCOUNT
#define BUGBOUNTY_HACKERONE_IDENTIFIER_ACCOUNT "hackerone-api-identifier"
#endif

#ifndef BUGBOUNTY_HACKERONE_TOKEN_ACCOUNT
#define BUGBOUNTY_HACKERONE_TOKEN_ACCOUNT "hackerone-api-token"
#endif

#ifndef BUGBOUNTY_KEYCHAIN_ACCESS_LABEL
#define BUGBOUNTY_KEYCHAIN_ACCESS_LABEL                                         \
  "bugbounty-copilot-hackerone-credentials"
#endif

#define MAX_SECRET_BYTES ((size_t)4095U)
#define LOCKED_BUFFER_BYTES (MAX_SECRET_BYTES + (size_t)1U)
#define CREDENTIAL_PREFIX "BBC-H1-CRED-V1."
#define CREDENTIAL_GENERATION_BYTES ((size_t)22U)

typedef enum {
  COMMAND_INVALID = 0,
  COMMAND_READ,
  COMMAND_STORE,
  COMMAND_DELETE
} command_kind;

typedef enum {
  ROLE_INVALID = 0,
  ROLE_IDENTIFIER,
  ROLE_TOKEN
} credential_role;

static void secure_zero(void *pointer, size_t length) {
  volatile uint8_t *bytes = (volatile uint8_t *)pointer;
  while (length > (size_t)0U) {
    *bytes = (uint8_t)0U;
    bytes += 1;
    length -= (size_t)1U;
  }
}

static bool configure_process(void) {
  struct rlimit core_limit;
  core_limit.rlim_cur = (rlim_t)0;
  core_limit.rlim_max = (rlim_t)0;
  if (setrlimit(RLIMIT_CORE, &core_limit) != 0) {
    return false;
  }
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    return false;
  }
  return SecKeychainSetUserInteractionAllowed(false) == errSecSuccess;
}

static command_kind parse_command(const char *value) {
  if (value == NULL) {
    return COMMAND_INVALID;
  }
  if (strcmp(value, "read") == 0) {
    return COMMAND_READ;
  }
  if (strcmp(value, "store") == 0) {
    return COMMAND_STORE;
  }
  if (strcmp(value, "delete") == 0) {
    return COMMAND_DELETE;
  }
  return COMMAND_INVALID;
}

static credential_role parse_role(const char *value) {
  if (value == NULL) {
    return ROLE_INVALID;
  }
  if (strcmp(value, "identifier") == 0) {
    return ROLE_IDENTIFIER;
  }
  if (strcmp(value, "token") == 0) {
    return ROLE_TOKEN;
  }
  return ROLE_INVALID;
}

static const char *account_for_role(credential_role role) {
  if (role == ROLE_IDENTIFIER) {
    return BUGBOUNTY_HACKERONE_IDENTIFIER_ACCOUNT;
  }
  if (role == ROLE_TOKEN) {
    return BUGBOUNTY_HACKERONE_TOKEN_ACCOUNT;
  }
  return NULL;
}

static bool valid_fixed_value(const char *value) {
  if (value == NULL) {
    return false;
  }
  const size_t length = strlen(value);
  if (length == (size_t)0U || length > (size_t)UINT32_MAX) {
    return false;
  }
  for (size_t index = (size_t)0U; index < length; index += (size_t)1U) {
    const uint8_t byte = (uint8_t)value[index];
    if (byte < (uint8_t)0x21U || byte > (uint8_t)0x7eU) {
      return false;
    }
  }
  return true;
}

static int base64url_value(uint8_t byte) {
  if (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') {
    return (int)(byte - (uint8_t)'A');
  }
  if (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') {
    return (int)(byte - (uint8_t)'a') + 26;
  }
  if (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') {
    return (int)(byte - (uint8_t)'0') + 52;
  }
  if (byte == (uint8_t)'-') {
    return 62;
  }
  if (byte == (uint8_t)'_') {
    return 63;
  }
  return -1;
}

static bool canonical_base64url(const uint8_t *value, size_t length) {
  if (value == NULL || length == (size_t)0U ||
      length % (size_t)4U == (size_t)1U) {
    return false;
  }
  for (size_t index = (size_t)0U; index < length; index += (size_t)1U) {
    if (base64url_value(value[index]) < 0) {
      return false;
    }
  }
  const size_t remainder = length % (size_t)4U;
  const int final_value = base64url_value(value[length - (size_t)1U]);
  if (remainder == (size_t)2U) {
    return (final_value & 0x0f) == 0;
  }
  if (remainder == (size_t)3U) {
    return (final_value & 0x03) == 0;
  }
  return true;
}

static bool valid_credential_envelope(credential_role role,
                                      const uint8_t *secret, size_t length) {
  const size_t prefix_length = sizeof(CREDENTIAL_PREFIX) - (size_t)1U;
  const size_t role_offset = prefix_length;
  const size_t generation_offset = role_offset + (size_t)2U;
  const size_t secret_separator_offset =
      generation_offset + CREDENTIAL_GENERATION_BYTES;
  const size_t encoded_secret_offset = secret_separator_offset + (size_t)1U;
  if (secret == NULL || length <= encoded_secret_offset ||
      length > MAX_SECRET_BYTES ||
      memcmp(secret, CREDENTIAL_PREFIX, prefix_length) != 0 ||
      secret[role_offset] !=
          (uint8_t)(role == ROLE_IDENTIFIER ? 'i' : 't') ||
      secret[role_offset + (size_t)1U] != (uint8_t)'.' ||
      secret[secret_separator_offset] != (uint8_t)'.') {
    return false;
  }
  const size_t encoded_secret_length = length - encoded_secret_offset;
  if (encoded_secret_length < (size_t)2U ||
      !canonical_base64url(secret + generation_offset,
                           CREDENTIAL_GENERATION_BYTES) ||
      !canonical_base64url(secret + encoded_secret_offset,
                           encoded_secret_length)) {
    return false;
  }
  return true;
}

static bool read_standard_input(uint8_t *buffer, size_t *length_out) {
  size_t used = (size_t)0U;
  while (used < LOCKED_BUFFER_BYTES) {
    const ssize_t amount =
        read(STDIN_FILENO, buffer + used, LOCKED_BUFFER_BYTES - used);
    if (amount == (ssize_t)0) {
      *length_out = used;
      return used <= MAX_SECRET_BYTES;
    }
    if (amount < (ssize_t)0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    used += (size_t)amount;
    if (used > MAX_SECRET_BYTES) {
      return false;
    }
  }
  return false;
}

static bool write_standard_output(const uint8_t *buffer, size_t length) {
  size_t written = (size_t)0U;
  while (written < length) {
    const ssize_t amount =
        write(STDOUT_FILENO, buffer + written, length - written);
    if (amount < (ssize_t)0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (amount == (ssize_t)0) {
      return false;
    }
    written += (size_t)amount;
  }
  return true;
}

static OSStatus find_item(const char *account, UInt32 *password_length,
                          void **password_data,
                          SecKeychainItemRef *item_out) {
  const char *service = BUGBOUNTY_KEYCHAIN_SERVICE;
  return SecKeychainFindGenericPassword(
      NULL, (UInt32)strlen(service), service, (UInt32)strlen(account), account,
      password_length, password_data, item_out);
}

static void release_item(SecKeychainItemRef item) {
  if (item != NULL) {
    CFRelease(item);
  }
}

static bool create_access(SecAccessRef *access_out) {
  SecTrustedApplicationRef trusted_application = NULL;
  CFArrayRef trusted_applications = NULL;
  SecAccessRef access = NULL;
  bool success = false;

  if (SecTrustedApplicationCreateFromPath(NULL, &trusted_application) !=
          errSecSuccess ||
      trusted_application == NULL) {
    goto cleanup;
  }

  const void *trusted_values[] = {trusted_application};
  trusted_applications =
      CFArrayCreate(kCFAllocatorDefault, trusted_values, (CFIndex)1,
                    &kCFTypeArrayCallBacks);
  if (trusted_applications == NULL) {
    goto cleanup;
  }

  CFStringRef label = CFStringCreateWithCString(
      kCFAllocatorDefault, BUGBOUNTY_KEYCHAIN_ACCESS_LABEL,
      kCFStringEncodingUTF8);
  if (label == NULL) {
    goto cleanup;
  }
  const OSStatus status =
      SecAccessCreate(label, trusted_applications, &access);
  CFRelease(label);
  if (status != errSecSuccess || access == NULL) {
    goto cleanup;
  }

  *access_out = access;
  access = NULL;
  success = true;

cleanup:
  if (access != NULL) {
    CFRelease(access);
  }
  if (trusted_applications != NULL) {
    CFRelease(trusted_applications);
  }
  if (trusted_application != NULL) {
    CFRelease(trusted_application);
  }
  return success;
}

static OSStatus create_item(const char *account, const uint8_t *secret,
                            UInt32 secret_length,
                            SecKeychainItemRef *item_out) {
  const char *service = BUGBOUNTY_KEYCHAIN_SERVICE;
  SecAccessRef access = NULL;
  if (!create_access(&access)) {
    return errSecInternalComponent;
  }

  SecKeychainAttribute attributes[] = {
      {kSecServiceItemAttr, (UInt32)strlen(service), (void *)service},
      {kSecAccountItemAttr, (UInt32)strlen(account), (void *)account},
      {kSecLabelItemAttr, (UInt32)strlen(service), (void *)service},
  };
  SecKeychainAttributeList attribute_list = {
      (UInt32)(sizeof(attributes) / sizeof(attributes[0])), attributes};
  const OSStatus status = SecKeychainItemCreateFromContent(
      kSecGenericPasswordItemClass, &attribute_list, secret_length, secret,
      NULL, access, item_out);
  CFRelease(access);
  return status;
}

static bool harden_item_access(SecKeychainItemRef item) {
  SecAccessRef access = NULL;
  if (item == NULL || !create_access(&access) || access == NULL) {
    return false;
  }
  const OSStatus status = SecKeychainItemSetAccess(item, access);
  CFRelease(access);
  return status == errSecSuccess;
}

static bool store_secret(const char *account, const uint8_t *secret,
                         size_t secret_length) {
  if (secret_length == (size_t)0U || secret_length > MAX_SECRET_BYTES) {
    return false;
  }

  SecKeychainItemRef item = NULL;
  OSStatus status = find_item(account, NULL, NULL, &item);
  if (status == errSecSuccess && item != NULL) {
    if (!harden_item_access(item)) {
      release_item(item);
      return false;
    }
    status = SecKeychainItemModifyContent(
        item, NULL, (UInt32)secret_length, secret);
    release_item(item);
    return status == errSecSuccess;
  }
  release_item(item);
  item = NULL;
  if (status != errSecItemNotFound) {
    return false;
  }

  status = create_item(account, secret, (UInt32)secret_length, &item);
  if (status == errSecDuplicateItem) {
    release_item(item);
    item = NULL;
    status = find_item(account, NULL, NULL, &item);
    if (status == errSecSuccess && item != NULL) {
      if (!harden_item_access(item)) {
        release_item(item);
        return false;
      }
      status = SecKeychainItemModifyContent(
          item, NULL, (UInt32)secret_length, secret);
    }
  }
  release_item(item);
  return status == errSecSuccess;
}

static bool delete_secret(const char *account) {
  SecKeychainItemRef item = NULL;
  const OSStatus find_status = find_item(account, NULL, NULL, &item);
  if (find_status == errSecItemNotFound) {
    return true;
  }
  if (find_status != errSecSuccess || item == NULL) {
    release_item(item);
    return false;
  }
  const OSStatus delete_status = SecKeychainItemDelete(item);
  release_item(item);
  return delete_status == errSecSuccess || delete_status == errSecItemNotFound;
}

static bool read_secret(const char *account, uint8_t *secret,
                        size_t *secret_length_out) {
  UInt32 raw_length = (UInt32)0U;
  void *raw_data = NULL;
  SecKeychainItemRef item = NULL;
  bool raw_locked = false;
  bool success = false;

  const OSStatus status =
      find_item(account, &raw_length, &raw_data, &item);
  if (status != errSecSuccess || item == NULL || raw_data == NULL ||
      raw_length == (UInt32)0U || raw_length > (UInt32)MAX_SECRET_BYTES) {
    goto cleanup;
  }
  if (mlock(raw_data, (size_t)raw_length) != 0) {
    goto cleanup;
  }
  raw_locked = true;
  memcpy(secret, raw_data, (size_t)raw_length);
  *secret_length_out = (size_t)raw_length;
  success = true;

cleanup:
  if (raw_data != NULL) {
    if (raw_length > (UInt32)0U) {
      secure_zero(raw_data, (size_t)raw_length);
      if (raw_locked && munlock(raw_data, (size_t)raw_length) != 0) {
        success = false;
      }
    }
    if (SecKeychainItemFreeContent(NULL, raw_data) != errSecSuccess) {
      success = false;
    }
  }
  release_item(item);
  if (!success) {
    secure_zero(secret, LOCKED_BUFFER_BYTES);
    *secret_length_out = (size_t)0U;
  }
  return success;
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    return 1;
  }
  const command_kind command = parse_command(argv[1]);
  const credential_role role = parse_role(argv[2]);
  const char *account = account_for_role(role);
  if (command == COMMAND_INVALID || role == ROLE_INVALID || account == NULL ||
      !valid_fixed_value(BUGBOUNTY_KEYCHAIN_SERVICE) ||
      !valid_fixed_value(account) ||
      !valid_fixed_value(BUGBOUNTY_KEYCHAIN_ACCESS_LABEL) ||
      !configure_process()) {
    return 1;
  }

  uint8_t secret[LOCKED_BUFFER_BYTES];
  if (mlock(secret, sizeof(secret)) != 0) {
    return 1;
  }
  secure_zero(secret, sizeof(secret));

  bool success = false;
  size_t secret_length = (size_t)0U;
  if (!read_standard_input(secret, &secret_length)) {
    goto cleanup;
  }

  if (command == COMMAND_STORE) {
    if (!valid_credential_envelope(role, secret, secret_length)) {
      goto cleanup;
    }
    success = store_secret(account, secret, secret_length);
    goto cleanup;
  }
  if (secret_length != (size_t)0U) {
    goto cleanup;
  }
  if (command == COMMAND_DELETE) {
    success = delete_secret(account);
    goto cleanup;
  }
  if (command == COMMAND_READ) {
    if (!read_secret(account, secret, &secret_length)) {
      goto cleanup;
    }
    success = write_standard_output(secret, secret_length);
  }

cleanup:
  secure_zero(secret, sizeof(secret));
  if (munlock(secret, sizeof(secret)) != 0) {
    success = false;
  }
  return success ? 0 : 1;
}
