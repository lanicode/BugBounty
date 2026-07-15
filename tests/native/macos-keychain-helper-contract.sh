#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  exit 0
fi

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_file="$repository_root/packages/hackerone-readonly/native/macos-keychain-helper.c"
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/bugbounty-keychain-helper.XXXXXX")
binary="$temporary_directory/macos-keychain-helper"
stdout_file="$temporary_directory/stdout"
stderr_file="$temporary_directory/stderr"

cleanup() {
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

clang -std=c17 -Wall -Wextra -Werror -Wno-deprecated-declarations \
  "$source_file" \
  -framework Security \
  -framework CoreFoundation \
  -o "$binary"

assert_rejected_without_output() {
  set +e
  "$binary" "$@" </dev/null >"$stdout_file" 2>"$stderr_file"
  status=$?
  set -e
  if [ "$status" -eq 0 ] || [ -s "$stdout_file" ] || [ -s "$stderr_file" ]; then
    exit 1
  fi
}

assert_rejected_without_output
assert_rejected_without_output unknown identifier
assert_rejected_without_output read unknown
assert_rejected_without_output store token extra

if grep -Eq '(^|[^A-Za-z0-9_])(getenv|putenv|setenv|fopen|freopen|popen|system)[[:space:]]*\(' "$source_file"; then
  exit 1
fi

for required_boundary in \
  'setrlimit(RLIMIT_CORE' \
  'SecKeychainSetUserInteractionAllowed(false)' \
  'SecKeychainItemSetAccess(' \
  'canonical_base64url(' \
  'valid_credential_envelope(' \
  'mlock(' \
  'secure_zero(' \
  'munlock('
do
  if ! grep -Fq "$required_boundary" "$source_file"; then
    exit 1
  fi
done
