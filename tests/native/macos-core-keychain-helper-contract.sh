#!/bin/sh
set -eu

if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
  exit 0
fi

repository_root=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")/../.." && /bin/pwd -P)
source_file="$repository_root/packages/secret-store/native/macos-core-keychain-helper.c"
temporary_directory=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/bugbounty-core-keychain-contract.XXXXXX")
binary="$temporary_directory/core-keychain-helper"
stdout_file="$temporary_directory/stdout"
stderr_file="$temporary_directory/stderr"

cleanup() {
  /bin/rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR="$temporary_directory" \
  /usr/bin/xcrun clang \
  -std=c17 -Wall -Wextra -Werror -Wno-deprecated-declarations \
  "$source_file" \
  -framework Security \
  -framework CoreFoundation \
  -o "$binary"

assert_rejected_without_output() {
  set +e
  /usr/bin/env -i "$binary" "$@" </dev/null \
    >"$stdout_file" 2>"$stderr_file"
  result=$?
  set -e
  if [ "$result" -eq 0 ] || [ -s "$stdout_file" ] || [ -s "$stderr_file" ]; then
    exit 1
  fi
}

assert_rejected_without_output
assert_rejected_without_output unknown
assert_rejected_without_output provision fresh extra
assert_rejected_without_output read unknown
assert_rejected_without_output provision fresh
assert_rejected_without_output provision complete-legacy

if /usr/bin/grep -Eq \
  '(^|[^A-Za-z0-9_])(getenv|putenv|setenv|fopen|freopen|popen|system|SecKeychainItemModifyContent|SecKeychainItemDelete|SecItemUpdate)[[:space:]]*\(' \
  "$source_file"; then
  exit 1
fi

for required_boundary in \
  'setrlimit(RLIMIT_CORE' \
  'SecKeychainSetUserInteractionAllowed(false)' \
  'SecKeychainItemCreateFromContent(' \
  'SecRandomCopyBytes(' \
  'mlock(' \
  'secure_zero(' \
  'munlock(' \
  'constant_time_equal(' \
  'complete_legacy(' \
  'RECEIPT_LEGACY_DIRECT_COMPLETE' \
  'valid_operator_der(' \
  'EVENT_KEY_BYTES' \
  'OPERATOR_DER_BYTES'
do
  if ! /usr/bin/grep -Fq "$required_boundary" "$source_file"; then
    exit 1
  fi
done

# Fresh provisioning writes exactly one bundle item. Legacy completion writes
# only the missing operator envelope and never writes the existing event item.
fresh_body=$(/usr/bin/awk \
  '/^static bool provision_fresh\(/,/^}/ { print }' "$source_file")
legacy_body=$(/usr/bin/awk \
  '/^static bool complete_legacy\(/,/^}/ { print }' "$source_file")
inspection_body=$(/usr/bin/awk \
  '/^static receipt_status inspect_items\(/,/^}/ { print }' "$source_file")
printf '%s' "$fresh_body" | /usr/bin/grep -Fq \
  'create_item(BUGBOUNTY_CORE_BUNDLE_ACCOUNT'
printf '%s' "$legacy_body" | /usr/bin/grep -Fq \
  'create_item(BUGBOUNTY_OPERATOR_KEY_ACCOUNT'
if printf '%s' "$legacy_body" | /usr/bin/grep -Fq \
  'create_item(BUGBOUNTY_EVENT_KEY_ACCOUNT'; then
  exit 1
fi

# The pre-Pilot-C complete layout remains readable only when the operator item
# is the exact raw canonical Ed25519 PKCS#8 length and shape. Recognition is
# receiptless and never mutates or upgrades either item.
printf '%s' "$inspection_body" | /usr/bin/grep -Fq \
  'operator_length == OPERATOR_DER_BYTES'
printf '%s' "$inspection_body" | /usr/bin/grep -Fq \
  'valid_operator_der(workspace->item, operator_length)'
printf '%s' "$inspection_body" | /usr/bin/grep -Fq \
  'return RECEIPT_LEGACY_DIRECT_COMPLETE'
if printf '%s' "$inspection_body" | /usr/bin/grep -Fq 'create_item('; then
  exit 1
fi
