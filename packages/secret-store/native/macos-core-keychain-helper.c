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

#ifndef BUGBOUNTY_CORE_KEYCHAIN_SERVICE
#define BUGBOUNTY_CORE_KEYCHAIN_SERVICE "bugbounty-copilot"
#endif

#ifndef BUGBOUNTY_CORE_BUNDLE_ACCOUNT
#define BUGBOUNTY_CORE_BUNDLE_ACCOUNT "core-key-bundle-v1"
#endif

#ifndef BUGBOUNTY_EVENT_KEY_ACCOUNT
#define BUGBOUNTY_EVENT_KEY_ACCOUNT "event-store-v1"
#endif

#ifndef BUGBOUNTY_OPERATOR_KEY_ACCOUNT
#define BUGBOUNTY_OPERATOR_KEY_ACCOUNT "operator-ed25519-v1"
#endif

#ifndef BUGBOUNTY_CORE_KEYCHAIN_ACCESS_LABEL
#define BUGBOUNTY_CORE_KEYCHAIN_ACCESS_LABEL                                  \
  "bugbounty-copilot-core-keys-v1"
#endif

#define EVENT_KEY_BYTES ((size_t)32U)
#define ED25519_SEED_BYTES ((size_t)32U)
#define OPERATOR_DER_BYTES ((size_t)48U)
#define GENERATION_BYTES ((size_t)16U)
#define MAGIC_BYTES ((size_t)8U)
#define MAX_OPERATOR_ID_BYTES ((size_t)128U)
#define INPUT_HEADER_BYTES ((size_t)10U)
#define MAX_INPUT_BYTES (INPUT_HEADER_BYTES + MAX_OPERATOR_ID_BYTES)
#define BUNDLE_FIXED_BYTES                                                     \
  (MAGIC_BYTES + GENERATION_BYTES + (size_t)1U + EVENT_KEY_BYTES +            \
   OPERATOR_DER_BYTES)
#define MAX_BUNDLE_BYTES (BUNDLE_FIXED_BYTES + MAX_OPERATOR_ID_BYTES)
#define OPERATOR_ENVELOPE_FIXED_BYTES                                          \
  (MAGIC_BYTES + GENERATION_BYTES + (size_t)1U + OPERATOR_DER_BYTES)
#define MAX_OPERATOR_ENVELOPE_BYTES                                            \
  (OPERATOR_ENVELOPE_FIXED_BYTES + MAX_OPERATOR_ID_BYTES)
#define RECEIPT_FIXED_BYTES                                                    \
  (MAGIC_BYTES + (size_t)1U + GENERATION_BYTES + (size_t)1U)
#define MAX_RECEIPT_BYTES (RECEIPT_FIXED_BYTES + MAX_OPERATOR_ID_BYTES)

static const uint8_t INPUT_MAGIC[MAGIC_BYTES] = {'B', 'B', 'C', 'O',
                                                  'R', 'E', 'P', '1'};
static const uint8_t BUNDLE_MAGIC[MAGIC_BYTES] = {'B', 'B', 'C', 'O',
                                                   'R', 'E', 'B', '1'};
static const uint8_t OPERATOR_MAGIC[MAGIC_BYTES] = {'B', 'B', 'C', 'O',
                                                     'R', 'E', 'O', '1'};
static const uint8_t RECEIPT_MAGIC[MAGIC_BYTES] = {'B', 'B', 'C', 'O',
                                                    'R', 'E', 'R', '1'};
static const uint8_t PKCS8_PREFIX[16] = {
    0x30U, 0x2eU, 0x02U, 0x01U, 0x00U, 0x30U, 0x05U, 0x06U,
    0x03U, 0x2bU, 0x65U, 0x70U, 0x04U, 0x22U, 0x04U, 0x20U};

typedef enum {
  COMMAND_INVALID = 0,
  COMMAND_INSPECT,
  COMMAND_PROVISION_FRESH,
  COMMAND_COMPLETE_LEGACY,
  COMMAND_READ_EVENT,
  COMMAND_READ_OPERATOR
} command_kind;

typedef enum {
  ITEM_STATE_ERROR = 0,
  ITEM_STATE_MISSING,
  ITEM_STATE_PRESENT
} item_state;

typedef enum {
  RECEIPT_ABSENT = 0,
  RECEIPT_FRESH = 1,
  RECEIPT_LEGACY_COMPLETE = 2,
  RECEIPT_LEGACY_READY = 3,
  RECEIPT_CONFLICT = 4,
  RECEIPT_LEGACY_DIRECT_COMPLETE = 5
} receipt_status;

typedef struct {
  uint8_t generation[GENERATION_BYTES];
  uint8_t operator_id[MAX_OPERATOR_ID_BYTES];
  size_t operator_id_length;
} public_metadata;

typedef struct {
  uint8_t input[MAX_INPUT_BYTES + (size_t)1U];
  uint8_t item[MAX_BUNDLE_BYTES];
  uint8_t verification[MAX_BUNDLE_BYTES];
  uint8_t event_key[EVENT_KEY_BYTES];
  uint8_t event_verification[EVENT_KEY_BYTES];
  uint8_t operator_der[OPERATOR_DER_BYTES];
  uint8_t seed[ED25519_SEED_BYTES];
  uint8_t receipt[MAX_RECEIPT_BYTES];
  public_metadata metadata;
} locked_workspace;

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
  if (setrlimit(RLIMIT_CORE, &core_limit) != 0 ||
      signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
    return false;
  }
  return SecKeychainSetUserInteractionAllowed(false) == errSecSuccess;
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

static bool valid_operator_id(const uint8_t *value, size_t length) {
  if (value == NULL || length == (size_t)0U ||
      length > MAX_OPERATOR_ID_BYTES) {
    return false;
  }
  for (size_t index = (size_t)0U; index < length; index += (size_t)1U) {
    const uint8_t byte = value[index];
    const bool valid =
        (byte >= (uint8_t)'A' && byte <= (uint8_t)'Z') ||
        (byte >= (uint8_t)'a' && byte <= (uint8_t)'z') ||
        (byte >= (uint8_t)'0' && byte <= (uint8_t)'9') || byte == (uint8_t)'.' ||
        byte == (uint8_t)'_' || byte == (uint8_t)'@' || byte == (uint8_t)'-';
    if (!valid) {
      return false;
    }
  }
  return true;
}

static command_kind parse_command(int argc, char *argv[]) {
  if (argc == 2 && strcmp(argv[1], "inspect") == 0) {
    return COMMAND_INSPECT;
  }
  if (argc != 3) {
    return COMMAND_INVALID;
  }
  if (strcmp(argv[1], "provision") == 0 && strcmp(argv[2], "fresh") == 0) {
    return COMMAND_PROVISION_FRESH;
  }
  if (strcmp(argv[1], "provision") == 0 &&
      strcmp(argv[2], "complete-legacy") == 0) {
    return COMMAND_COMPLETE_LEGACY;
  }
  if (strcmp(argv[1], "read") == 0 && strcmp(argv[2], "event") == 0) {
    return COMMAND_READ_EVENT;
  }
  if (strcmp(argv[1], "read") == 0 && strcmp(argv[2], "operator") == 0) {
    return COMMAND_READ_OPERATOR;
  }
  return COMMAND_INVALID;
}

static bool constant_time_equal(const uint8_t *left, const uint8_t *right,
                                size_t length) {
  uint8_t difference = (uint8_t)0U;
  for (size_t index = (size_t)0U; index < length; index += (size_t)1U) {
    difference |= (uint8_t)(left[index] ^ right[index]);
  }
  return difference == (uint8_t)0U;
}

static bool contains_nonzero_byte(const uint8_t *value, size_t length) {
  uint8_t combined = (uint8_t)0U;
  for (size_t index = (size_t)0U; index < length; index += (size_t)1U) {
    combined |= value[index];
  }
  return combined != (uint8_t)0U;
}

static bool read_standard_input(uint8_t *buffer, size_t capacity,
                                size_t *length_out) {
  size_t used = (size_t)0U;
  while (used < capacity) {
    const ssize_t amount = read(STDIN_FILENO, buffer + used, capacity - used);
    if (amount == (ssize_t)0) {
      *length_out = used;
      return true;
    }
    if (amount < (ssize_t)0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    used += (size_t)amount;
  }
  uint8_t extra = (uint8_t)0U;
  ssize_t amount;
  do {
    amount = read(STDIN_FILENO, &extra, (size_t)1U);
  } while (amount < (ssize_t)0 && errno == EINTR);
  secure_zero(&extra, sizeof(extra));
  return amount == (ssize_t)0;
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
  const char *service = BUGBOUNTY_CORE_KEYCHAIN_SERVICE;
  return SecKeychainFindGenericPassword(
      NULL, (UInt32)strlen(service), service, (UInt32)strlen(account), account,
      password_length, password_data, item_out);
}

static item_state probe_item(const char *account) {
  SecKeychainItemRef item = NULL;
  const OSStatus status = find_item(account, NULL, NULL, &item);
  if (item != NULL) {
    CFRelease(item);
  }
  if (status == errSecItemNotFound) {
    return ITEM_STATE_MISSING;
  }
  return status == errSecSuccess ? ITEM_STATE_PRESENT : ITEM_STATE_ERROR;
}

static bool read_item(const char *account, uint8_t *destination,
                      size_t capacity, size_t *length_out) {
  UInt32 raw_length = (UInt32)0U;
  void *raw_data = NULL;
  SecKeychainItemRef item = NULL;
  bool raw_locked = false;
  bool success = false;
  const OSStatus status =
      find_item(account, &raw_length, &raw_data, &item);
  if (status != errSecSuccess || item == NULL || raw_data == NULL ||
      raw_length == (UInt32)0U || (size_t)raw_length > capacity) {
    goto cleanup;
  }
  if (mlock(raw_data, (size_t)raw_length) != 0) {
    goto cleanup;
  }
  raw_locked = true;
  memcpy(destination, raw_data, (size_t)raw_length);
  *length_out = (size_t)raw_length;
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
  if (item != NULL) {
    CFRelease(item);
  }
  if (!success) {
    secure_zero(destination, capacity);
    *length_out = (size_t)0U;
  }
  return success;
}

static bool create_access(SecAccessRef *access_out) {
  SecTrustedApplicationRef trusted_application = NULL;
  CFArrayRef trusted_applications = NULL;
  SecAccessRef access = NULL;
  CFStringRef label = NULL;
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
  label = CFStringCreateWithCString(kCFAllocatorDefault,
                                    BUGBOUNTY_CORE_KEYCHAIN_ACCESS_LABEL,
                                    kCFStringEncodingUTF8);
  if (label == NULL ||
      SecAccessCreate(label, trusted_applications, &access) != errSecSuccess ||
      access == NULL) {
    goto cleanup;
  }
  *access_out = access;
  access = NULL;
  success = true;

cleanup:
  if (label != NULL) {
    CFRelease(label);
  }
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

static bool create_item(const char *account, const uint8_t *secret,
                        size_t secret_length) {
  if (secret == NULL || secret_length == (size_t)0U ||
      secret_length > (size_t)UINT32_MAX) {
    return false;
  }
  const char *service = BUGBOUNTY_CORE_KEYCHAIN_SERVICE;
  SecAccessRef access = NULL;
  SecKeychainItemRef item = NULL;
  if (!create_access(&access)) {
    return false;
  }
  SecKeychainAttribute attributes[] = {
      {kSecServiceItemAttr, (UInt32)strlen(service), (void *)service},
      {kSecAccountItemAttr, (UInt32)strlen(account), (void *)account},
      {kSecLabelItemAttr, (UInt32)strlen(service), (void *)service},
  };
  SecKeychainAttributeList attribute_list = {
      (UInt32)(sizeof(attributes) / sizeof(attributes[0])), attributes};
  const OSStatus status = SecKeychainItemCreateFromContent(
      kSecGenericPasswordItemClass, &attribute_list, (UInt32)secret_length,
      secret, NULL, access, &item);
  CFRelease(access);
  if (item != NULL) {
    CFRelease(item);
  }
  return status == errSecSuccess;
}

static bool parse_input_frame(const uint8_t *input, size_t length,
                              public_metadata *metadata) {
  if (input == NULL || metadata == NULL || length < INPUT_HEADER_BYTES ||
      !constant_time_equal(input, INPUT_MAGIC, MAGIC_BYTES)) {
    return false;
  }
  const size_t operator_id_length =
      ((size_t)input[MAGIC_BYTES] << 8U) |
      (size_t)input[MAGIC_BYTES + (size_t)1U];
  if (length != INPUT_HEADER_BYTES + operator_id_length ||
      !valid_operator_id(input + INPUT_HEADER_BYTES, operator_id_length)) {
    return false;
  }
  metadata->operator_id_length = operator_id_length;
  memcpy(metadata->operator_id, input + INPUT_HEADER_BYTES,
         operator_id_length);
  return true;
}

static bool valid_operator_der(const uint8_t *value, size_t length) {
  return value != NULL && length == OPERATOR_DER_BYTES &&
         constant_time_equal(value, PKCS8_PREFIX, sizeof(PKCS8_PREFIX));
}

static void create_operator_der(uint8_t *destination, const uint8_t *seed) {
  memcpy(destination, PKCS8_PREFIX, sizeof(PKCS8_PREFIX));
  memcpy(destination + sizeof(PKCS8_PREFIX), seed, ED25519_SEED_BYTES);
}

static size_t build_bundle(uint8_t *destination,
                           const public_metadata *metadata,
                           const uint8_t *event_key,
                           const uint8_t *operator_der) {
  size_t offset = (size_t)0U;
  memcpy(destination + offset, BUNDLE_MAGIC, MAGIC_BYTES);
  offset += MAGIC_BYTES;
  memcpy(destination + offset, metadata->generation, GENERATION_BYTES);
  offset += GENERATION_BYTES;
  destination[offset] = (uint8_t)metadata->operator_id_length;
  offset += (size_t)1U;
  memcpy(destination + offset, metadata->operator_id,
         metadata->operator_id_length);
  offset += metadata->operator_id_length;
  memcpy(destination + offset, event_key, EVENT_KEY_BYTES);
  offset += EVENT_KEY_BYTES;
  memcpy(destination + offset, operator_der, OPERATOR_DER_BYTES);
  return offset + OPERATOR_DER_BYTES;
}

static size_t build_operator_envelope(uint8_t *destination,
                                      const public_metadata *metadata,
                                      const uint8_t *operator_der) {
  size_t offset = (size_t)0U;
  memcpy(destination + offset, OPERATOR_MAGIC, MAGIC_BYTES);
  offset += MAGIC_BYTES;
  memcpy(destination + offset, metadata->generation, GENERATION_BYTES);
  offset += GENERATION_BYTES;
  destination[offset] = (uint8_t)metadata->operator_id_length;
  offset += (size_t)1U;
  memcpy(destination + offset, metadata->operator_id,
         metadata->operator_id_length);
  offset += metadata->operator_id_length;
  memcpy(destination + offset, operator_der, OPERATOR_DER_BYTES);
  return offset + OPERATOR_DER_BYTES;
}

static bool parse_bundle(const uint8_t *source, size_t length,
                         public_metadata *metadata, uint8_t *event_key,
                         uint8_t *operator_der) {
  if (source == NULL || metadata == NULL || event_key == NULL ||
      operator_der == NULL || length < BUNDLE_FIXED_BYTES ||
      length > MAX_BUNDLE_BYTES ||
      !constant_time_equal(source, BUNDLE_MAGIC, MAGIC_BYTES)) {
    return false;
  }
  size_t offset = MAGIC_BYTES;
  memcpy(metadata->generation, source + offset, GENERATION_BYTES);
  offset += GENERATION_BYTES;
  const size_t operator_id_length = (size_t)source[offset];
  offset += (size_t)1U;
  if (length != BUNDLE_FIXED_BYTES + operator_id_length ||
      !valid_operator_id(source + offset, operator_id_length)) {
    return false;
  }
  metadata->operator_id_length = operator_id_length;
  memcpy(metadata->operator_id, source + offset, operator_id_length);
  offset += operator_id_length;
  memcpy(event_key, source + offset, EVENT_KEY_BYTES);
  offset += EVENT_KEY_BYTES;
  memcpy(operator_der, source + offset, OPERATOR_DER_BYTES);
  return contains_nonzero_byte(metadata->generation, GENERATION_BYTES) &&
         contains_nonzero_byte(event_key, EVENT_KEY_BYTES) &&
         valid_operator_der(operator_der, OPERATOR_DER_BYTES) &&
         contains_nonzero_byte(operator_der + sizeof(PKCS8_PREFIX),
                               ED25519_SEED_BYTES) &&
         !constant_time_equal(event_key,
                              operator_der + sizeof(PKCS8_PREFIX),
                              EVENT_KEY_BYTES);
}

static bool parse_operator_envelope(const uint8_t *source, size_t length,
                                    public_metadata *metadata,
                                    uint8_t *operator_der) {
  if (source == NULL || metadata == NULL || operator_der == NULL ||
      length < OPERATOR_ENVELOPE_FIXED_BYTES ||
      length > MAX_OPERATOR_ENVELOPE_BYTES ||
      !constant_time_equal(source, OPERATOR_MAGIC, MAGIC_BYTES)) {
    return false;
  }
  size_t offset = MAGIC_BYTES;
  memcpy(metadata->generation, source + offset, GENERATION_BYTES);
  offset += GENERATION_BYTES;
  const size_t operator_id_length = (size_t)source[offset];
  offset += (size_t)1U;
  if (length != OPERATOR_ENVELOPE_FIXED_BYTES + operator_id_length ||
      !valid_operator_id(source + offset, operator_id_length)) {
    return false;
  }
  metadata->operator_id_length = operator_id_length;
  memcpy(metadata->operator_id, source + offset, operator_id_length);
  offset += operator_id_length;
  memcpy(operator_der, source + offset, OPERATOR_DER_BYTES);
  return contains_nonzero_byte(metadata->generation, GENERATION_BYTES) &&
         valid_operator_der(operator_der, OPERATOR_DER_BYTES) &&
         contains_nonzero_byte(operator_der + sizeof(PKCS8_PREFIX),
                               ED25519_SEED_BYTES);
}

static bool write_receipt(receipt_status status,
                          const public_metadata *metadata,
                          uint8_t *scratch) {
  size_t length = MAGIC_BYTES + (size_t)1U;
  memcpy(scratch, RECEIPT_MAGIC, MAGIC_BYTES);
  scratch[MAGIC_BYTES] = (uint8_t)status;
  if (metadata != NULL) {
    memcpy(scratch + length, metadata->generation, GENERATION_BYTES);
    length += GENERATION_BYTES;
    scratch[length] = (uint8_t)metadata->operator_id_length;
    length += (size_t)1U;
    memcpy(scratch + length, metadata->operator_id,
           metadata->operator_id_length);
    length += metadata->operator_id_length;
  }
  const bool success = write_standard_output(scratch, length);
  secure_zero(scratch, MAX_RECEIPT_BYTES);
  return success;
}

static receipt_status inspect_items(locked_workspace *workspace,
                                    public_metadata **metadata_out) {
  const item_state bundle = probe_item(BUGBOUNTY_CORE_BUNDLE_ACCOUNT);
  const item_state event = probe_item(BUGBOUNTY_EVENT_KEY_ACCOUNT);
  const item_state operator_key = probe_item(BUGBOUNTY_OPERATOR_KEY_ACCOUNT);
  if (bundle == ITEM_STATE_ERROR || event == ITEM_STATE_ERROR ||
      operator_key == ITEM_STATE_ERROR) {
    return RECEIPT_CONFLICT;
  }
  if (bundle == ITEM_STATE_PRESENT) {
    if (event != ITEM_STATE_MISSING || operator_key != ITEM_STATE_MISSING) {
      return RECEIPT_CONFLICT;
    }
    size_t length = (size_t)0U;
    if (!read_item(BUGBOUNTY_CORE_BUNDLE_ACCOUNT, workspace->item,
                   sizeof(workspace->item), &length) ||
        !parse_bundle(workspace->item, length, &workspace->metadata,
                      workspace->event_key, workspace->operator_der)) {
      return RECEIPT_CONFLICT;
    }
    *metadata_out = &workspace->metadata;
    return RECEIPT_FRESH;
  }
  if (event == ITEM_STATE_MISSING && operator_key == ITEM_STATE_MISSING) {
    return RECEIPT_ABSENT;
  }
  if (event != ITEM_STATE_PRESENT) {
    return RECEIPT_CONFLICT;
  }
  size_t event_length = (size_t)0U;
  if (!read_item(BUGBOUNTY_EVENT_KEY_ACCOUNT, workspace->event_key,
                 sizeof(workspace->event_key), &event_length) ||
      event_length != EVENT_KEY_BYTES) {
    return RECEIPT_CONFLICT;
  }
  if (operator_key == ITEM_STATE_MISSING) {
    return RECEIPT_LEGACY_READY;
  }
  size_t operator_length = (size_t)0U;
  if (!read_item(BUGBOUNTY_OPERATOR_KEY_ACCOUNT, workspace->item,
                 MAX_OPERATOR_ENVELOPE_BYTES, &operator_length)) {
    return RECEIPT_CONFLICT;
  }
  if (operator_length == OPERATOR_DER_BYTES &&
      valid_operator_der(workspace->item, operator_length) &&
      contains_nonzero_byte(workspace->item + sizeof(PKCS8_PREFIX),
                            ED25519_SEED_BYTES) &&
      !constant_time_equal(workspace->event_key,
                           workspace->item + sizeof(PKCS8_PREFIX),
                           EVENT_KEY_BYTES)) {
    memcpy(workspace->operator_der, workspace->item, OPERATOR_DER_BYTES);
    return RECEIPT_LEGACY_DIRECT_COMPLETE;
  }
  if (!parse_operator_envelope(workspace->item, operator_length,
                               &workspace->metadata,
                               workspace->operator_der) ||
      constant_time_equal(workspace->event_key,
                          workspace->operator_der + sizeof(PKCS8_PREFIX),
                          EVENT_KEY_BYTES)) {
    return RECEIPT_CONFLICT;
  }
  *metadata_out = &workspace->metadata;
  return RECEIPT_LEGACY_COMPLETE;
}

static bool provision_fresh(locked_workspace *workspace) {
  if (probe_item(BUGBOUNTY_CORE_BUNDLE_ACCOUNT) != ITEM_STATE_MISSING ||
      probe_item(BUGBOUNTY_EVENT_KEY_ACCOUNT) != ITEM_STATE_MISSING ||
      probe_item(BUGBOUNTY_OPERATOR_KEY_ACCOUNT) != ITEM_STATE_MISSING ||
      SecRandomCopyBytes(kSecRandomDefault, GENERATION_BYTES,
                         workspace->metadata.generation) != errSecSuccess ||
      SecRandomCopyBytes(kSecRandomDefault, EVENT_KEY_BYTES,
                         workspace->event_key) != errSecSuccess ||
      SecRandomCopyBytes(kSecRandomDefault, ED25519_SEED_BYTES,
                         workspace->seed) != errSecSuccess) {
    return false;
  }
  if (!contains_nonzero_byte(workspace->metadata.generation,
                             GENERATION_BYTES) ||
      !contains_nonzero_byte(workspace->event_key, EVENT_KEY_BYTES) ||
      !contains_nonzero_byte(workspace->seed, ED25519_SEED_BYTES) ||
      constant_time_equal(workspace->event_key, workspace->seed,
                          EVENT_KEY_BYTES)) {
    return false;
  }
  create_operator_der(workspace->operator_der, workspace->seed);
  const size_t bundle_length =
      build_bundle(workspace->item, &workspace->metadata,
                   workspace->event_key, workspace->operator_der);
  if (!create_item(BUGBOUNTY_CORE_BUNDLE_ACCOUNT, workspace->item,
                   bundle_length)) {
    return false;
  }
  size_t verification_length = (size_t)0U;
  if (!read_item(BUGBOUNTY_CORE_BUNDLE_ACCOUNT, workspace->verification,
                 sizeof(workspace->verification), &verification_length) ||
      verification_length != bundle_length ||
      !constant_time_equal(workspace->item, workspace->verification,
                           bundle_length) ||
      probe_item(BUGBOUNTY_EVENT_KEY_ACCOUNT) != ITEM_STATE_MISSING ||
      probe_item(BUGBOUNTY_OPERATOR_KEY_ACCOUNT) != ITEM_STATE_MISSING) {
    return false;
  }
  return write_receipt(RECEIPT_FRESH, &workspace->metadata,
                       workspace->receipt);
}

static bool complete_legacy(locked_workspace *workspace) {
  if (probe_item(BUGBOUNTY_CORE_BUNDLE_ACCOUNT) != ITEM_STATE_MISSING ||
      probe_item(BUGBOUNTY_EVENT_KEY_ACCOUNT) != ITEM_STATE_PRESENT ||
      probe_item(BUGBOUNTY_OPERATOR_KEY_ACCOUNT) != ITEM_STATE_MISSING) {
    return false;
  }
  size_t event_length = (size_t)0U;
  if (!read_item(BUGBOUNTY_EVENT_KEY_ACCOUNT, workspace->event_key,
                 sizeof(workspace->event_key), &event_length) ||
      event_length != EVENT_KEY_BYTES ||
      SecRandomCopyBytes(kSecRandomDefault, GENERATION_BYTES,
                         workspace->metadata.generation) != errSecSuccess ||
      SecRandomCopyBytes(kSecRandomDefault, ED25519_SEED_BYTES,
                         workspace->seed) != errSecSuccess ||
      !contains_nonzero_byte(workspace->metadata.generation,
                             GENERATION_BYTES) ||
      !contains_nonzero_byte(workspace->seed, ED25519_SEED_BYTES) ||
      constant_time_equal(workspace->event_key, workspace->seed,
                          EVENT_KEY_BYTES)) {
    return false;
  }
  create_operator_der(workspace->operator_der, workspace->seed);
  const size_t envelope_length = build_operator_envelope(
      workspace->item, &workspace->metadata, workspace->operator_der);
  if (!create_item(BUGBOUNTY_OPERATOR_KEY_ACCOUNT, workspace->item,
                   envelope_length)) {
    return false;
  }
  size_t verification_length = (size_t)0U;
  size_t event_verification_length = (size_t)0U;
  if (!read_item(BUGBOUNTY_OPERATOR_KEY_ACCOUNT, workspace->verification,
                 MAX_OPERATOR_ENVELOPE_BYTES, &verification_length) ||
      verification_length != envelope_length ||
      !constant_time_equal(workspace->item, workspace->verification,
                           envelope_length) ||
      !read_item(BUGBOUNTY_EVENT_KEY_ACCOUNT, workspace->event_verification,
                 sizeof(workspace->event_verification),
                 &event_verification_length) ||
      event_verification_length != EVENT_KEY_BYTES ||
      !constant_time_equal(workspace->event_key,
                           workspace->event_verification, EVENT_KEY_BYTES) ||
      probe_item(BUGBOUNTY_CORE_BUNDLE_ACCOUNT) != ITEM_STATE_MISSING) {
    return false;
  }
  return write_receipt(RECEIPT_LEGACY_COMPLETE, &workspace->metadata,
                       workspace->receipt);
}

static bool read_completed_role(command_kind command,
                                locked_workspace *workspace) {
  public_metadata *metadata = NULL;
  const receipt_status status = inspect_items(workspace, &metadata);
  (void)metadata;
  if (status != RECEIPT_FRESH && status != RECEIPT_LEGACY_COMPLETE &&
      status != RECEIPT_LEGACY_DIRECT_COMPLETE) {
    return false;
  }
  if (command == COMMAND_READ_EVENT) {
    const bool success =
        write_standard_output(workspace->event_key, EVENT_KEY_BYTES);
    secure_zero(workspace->event_key, sizeof(workspace->event_key));
    return success;
  }
  if (command == COMMAND_READ_OPERATOR) {
    const bool success =
        write_standard_output(workspace->operator_der, OPERATOR_DER_BYTES);
    secure_zero(workspace->operator_der, sizeof(workspace->operator_der));
    return success;
  }
  return false;
}

int main(int argc, char *argv[]) {
  const command_kind command = parse_command(argc, argv);
  if (command == COMMAND_INVALID ||
      !valid_fixed_value(BUGBOUNTY_CORE_KEYCHAIN_SERVICE) ||
      !valid_fixed_value(BUGBOUNTY_CORE_BUNDLE_ACCOUNT) ||
      !valid_fixed_value(BUGBOUNTY_EVENT_KEY_ACCOUNT) ||
      !valid_fixed_value(BUGBOUNTY_OPERATOR_KEY_ACCOUNT) ||
      !valid_fixed_value(BUGBOUNTY_CORE_KEYCHAIN_ACCESS_LABEL) ||
      !configure_process()) {
    return 1;
  }

  locked_workspace workspace = {0};
  if (mlock(&workspace, sizeof(workspace)) != 0) {
    return 1;
  }
  secure_zero(&workspace, sizeof(workspace));
  size_t input_length = (size_t)0U;
  bool success = false;
  if (!read_standard_input(workspace.input, sizeof(workspace.input),
                           &input_length)) {
    goto cleanup;
  }

  if (command == COMMAND_INSPECT) {
    if (input_length != (size_t)0U) {
      goto cleanup;
    }
    public_metadata *metadata = NULL;
    const receipt_status status = inspect_items(&workspace, &metadata);
    success = write_receipt(status, metadata, workspace.receipt);
    goto cleanup;
  }
  if (command == COMMAND_READ_EVENT || command == COMMAND_READ_OPERATOR) {
    if (input_length != (size_t)0U) {
      goto cleanup;
    }
    success = read_completed_role(command, &workspace);
    goto cleanup;
  }
  if (!parse_input_frame(workspace.input, input_length,
                         &workspace.metadata)) {
    goto cleanup;
  }
  if (command == COMMAND_PROVISION_FRESH) {
    success = provision_fresh(&workspace);
  } else if (command == COMMAND_COMPLETE_LEGACY) {
    success = complete_legacy(&workspace);
  }

cleanup:
  secure_zero(&workspace, sizeof(workspace));
  if (munlock(&workspace, sizeof(workspace)) != 0) {
    success = false;
  }
  return success ? 0 : 1;
}
