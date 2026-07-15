#!/bin/sh
set -eu

if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
  exit 0
fi

repository_root=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")/../.." && /bin/pwd -P)
source_file="$repository_root/packages/hackerone-readonly/native/macos-keychain-helper.c"
temporary_directory=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/bugbounty-keychain-integration.XXXXXX")
binary="$temporary_directory/macos-keychain-helper"
stdout_file="$temporary_directory/stdout"
stderr_file="$temporary_directory/stderr"
service="bugbounty-copilot-native-test-$$-$(/bin/date +%s)"
identifier_account="synthetic-identifier"
token_account="synthetic-token"
access_label="bugbounty-copilot-native-test-access"
legacy_item_owned=0

cleanup() {
  if [ -x "$binary" ]; then
    "$binary" delete identifier </dev/null >/dev/null 2>/dev/null || true
    "$binary" delete token </dev/null >/dev/null 2>/dev/null || true
  fi
  if [ "$legacy_item_owned" -eq 1 ]; then
    /usr/bin/security delete-generic-password -s "$service" \
      -a "$identifier_account" >/dev/null 2>&1 || true
  fi
  /bin/rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

service_define="-DBUGBOUNTY_KEYCHAIN_SERVICE=\"$service\""
identifier_define="-DBUGBOUNTY_HACKERONE_IDENTIFIER_ACCOUNT=\"$identifier_account\""
token_define="-DBUGBOUNTY_HACKERONE_TOKEN_ACCOUNT=\"$token_account\""
access_define="-DBUGBOUNTY_KEYCHAIN_ACCESS_LABEL=\"$access_label\""

/usr/bin/env -i PATH=/usr/bin:/bin TMPDIR="$temporary_directory" \
  /usr/bin/xcrun clang \
  -std=c17 -Wall -Wextra -Werror -Wno-deprecated-declarations \
  "$service_define" "$identifier_define" "$token_define" "$access_define" \
  "$source_file" \
  -framework Security \
  -framework CoreFoundation \
  -o "$binary"

generation="AAAAAAAAAAAAAAAAAAAAAA"
identifier_envelope="BBC-H1-CRED-V1.i.$generation.c3ludGhldGljLWlkZW50aWZpZXI"
token_envelope="BBC-H1-CRED-V1.t.$generation.c3ludGhldGljLXRva2Vu"

assert_no_output() {
  if [ -s "$stdout_file" ] || [ -s "$stderr_file" ]; then
    exit 1
  fi
}

store_value() {
  role="$1"
  value="$2"
  /usr/bin/printf '%s' "$value" | /usr/bin/env -i "$binary" store "$role" \
    >"$stdout_file" 2>"$stderr_file"
  assert_no_output
}

read_value() {
  role="$1"
  expected="$2"
  actual=$(/usr/bin/env -i "$binary" read "$role" </dev/null 2>"$stderr_file")
  if [ "$actual" != "$expected" ] || [ -s "$stderr_file" ]; then
    exit 1
  fi
}

delete_value() {
  role="$1"
  /usr/bin/env -i "$binary" delete "$role" </dev/null \
    >"$stdout_file" 2>"$stderr_file"
  assert_no_output
}

# A pre-existing generic-password item must either be migrated to the helper's
# explicit ACL before its content changes, or remain byte-for-byte unchanged.
/usr/bin/security add-generic-password -s "$service" \
  -a "$identifier_account" -w "legacy-synthetic-value" -U >/dev/null 2>&1
legacy_item_owned=1
minimal_environment_value=$(
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    /usr/bin/security find-generic-password -s "$service" \
      -a "$identifier_account" -w 2>/dev/null
)
[ "$minimal_environment_value" = "legacy-synthetic-value" ] || exit 1
minimal_environment_value=
set +e
/usr/bin/printf '%s' "$identifier_envelope" | \
  /usr/bin/env -i "$binary" store identifier \
    >"$stdout_file" 2>"$stderr_file"
migration_status=$?
set -e
assert_no_output
if [ "$migration_status" -eq 0 ]; then
  legacy_item_owned=0
  read_value identifier "$identifier_envelope"
  delete_value identifier
else
  legacy_value=$(/usr/bin/security find-generic-password -s "$service" \
    -a "$identifier_account" -w 2>/dev/null)
  [ "$legacy_value" = "legacy-synthetic-value" ] || exit 1
  /usr/bin/security delete-generic-password -s "$service" \
    -a "$identifier_account" >/dev/null 2>&1
  legacy_item_owned=0
fi

store_value identifier "$identifier_envelope"
store_value token "$token_envelope"
read_value identifier "$identifier_envelope"
read_value token "$token_envelope"
delete_value identifier
delete_value token

set +e
/usr/bin/env -i "$binary" read identifier </dev/null \
  >"$stdout_file" 2>"$stderr_file"
missing_status=$?
set -e
if [ "$missing_status" -eq 0 ]; then
  exit 1
fi
assert_no_output

set +e
/usr/bin/env -i "$binary" read token </dev/null \
  >"$stdout_file" 2>"$stderr_file"
missing_token_status=$?
set -e
if [ "$missing_token_status" -eq 0 ]; then
  exit 1
fi
assert_no_output

# The exact 4,095-byte helper boundary is accepted only for a structurally
# valid envelope; 4,096 bytes and arbitrary printable material are rejected.
maximum_payload=$(/usr/bin/awk 'BEGIN { for (i = 0; i < 4055; i += 1) printf "A" }')
maximum_envelope="BBC-H1-CRED-V1.i.$generation.$maximum_payload"
[ "${#maximum_envelope}" -eq 4095 ] || exit 1
store_value identifier "$maximum_envelope"
delete_value identifier

set +e
/usr/bin/printf '%sA' "$maximum_envelope" | \
  /usr/bin/env -i "$binary" store identifier \
    >"$stdout_file" 2>"$stderr_file"
oversized_status=$?
set -e
if [ "$oversized_status" -eq 0 ]; then
  exit 1
fi
assert_no_output

set +e
/usr/bin/printf '%s' "arbitrary-printable-material" | \
  /usr/bin/env -i "$binary" store token \
    >"$stdout_file" 2>"$stderr_file"
invalid_envelope_status=$?
set -e
if [ "$invalid_envelope_status" -eq 0 ]; then
  exit 1
fi
assert_no_output

for noncanonical_envelope in \
  "BBC-H1-CRED-V1.t.AAAAAAAAAAAAAAAAAAAAAB.c3ludGhldGlj" \
  "BBC-H1-CRED-V1.t.$generation.QR" \
  "BBC-H1-CRED-V1.t.$generation.QUJ"
do
  set +e
  /usr/bin/printf '%s' "$noncanonical_envelope" | \
    /usr/bin/env -i "$binary" store token \
      >"$stdout_file" 2>"$stderr_file"
  noncanonical_status=$?
  set -e
  if [ "$noncanonical_status" -eq 0 ]; then
    exit 1
  fi
  assert_no_output
done
