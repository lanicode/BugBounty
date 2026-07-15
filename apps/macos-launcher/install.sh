#!/bin/bash

set -u
umask 077

APP_NAME="Bug Bounty Copilot.app"
BUNDLE_IDENTIFIER="dev.local.bugbounty-copilot.launcher"

fail() {
  /usr/bin/printf '%s\n' "$1" >&2
  exit 1
}

valid_event_key_minimum_version() {
  local VALUE="$1"
  case "$VALUE" in
    "" | 0* | *[!0-9]*) return 1 ;;
  esac
  [ "${#VALUE}" -le 5 ] || return 1
  [ "$VALUE" -le 10000 ] 2>/dev/null || return 1
}

valid_positive_safe_integer() {
  local VALUE="$1"
  case "$VALUE" in
    "" | 0* | *[!0-9]*) return 1 ;;
  esac
  if [ "${#VALUE}" -lt 16 ]; then
    return 0
  fi
  [ "${#VALUE}" -eq 16 ] || return 1
  [[ "$VALUE" < "9007199254740991" || "$VALUE" = "9007199254740991" ]]
}

valid_operator_id() {
  local VALUE="$1"
  [ "${#VALUE}" -ge 1 ] && [ "${#VALUE}" -le 128 ] || return 1
  case "$VALUE" in
    *[!A-Za-z0-9._@-]*) return 1 ;;
  esac
}

valid_keychain_reference() {
  local VALUE="$1"
  local WITHOUT_SCHEME
  local ACCOUNT
  [ "${#VALUE}" -le 512 ] || return 1
  [[ "$VALUE" =~ ^keychain://[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+$ ]] ||
    return 1
  WITHOUT_SCHEME="${VALUE#keychain://}"
  ACCOUNT="${WITHOUT_SCHEME#*/}"
  case "$ACCOUNT" in
    *..*) return 1 ;;
  esac
}

mode_is_not_group_or_world_writable() {
  local MODE="$1"
  case "$MODE" in
    "" | *[!0-7]*) return 1 ;;
  esac
  (( (8#$MODE & 8#022) == 0 ))
}

trusted_regular_file() {
  local PATH_TO_CHECK="$1"
  local MAXIMUM_SIZE="$2"
  local REQUIRED_UID="$3"
  local METADATA
  local OWNER_UID
  local MODE
  local LINK_COUNT
  local SIZE

  [ -f "$PATH_TO_CHECK" ] && [ ! -L "$PATH_TO_CHECK" ] || return 1
  METADATA="$(/usr/bin/stat -f '%u %Lp %l %z' -- "$PATH_TO_CHECK")" ||
    return 1
  read -r OWNER_UID MODE LINK_COUNT SIZE <<< "$METADATA"
  [ "$OWNER_UID" -eq "$REQUIRED_UID" ] || return 1
  [ "$LINK_COUNT" -eq 1 ] || return 1
  [ "$SIZE" -gt 0 ] && [ "$SIZE" -le "$MAXIMUM_SIZE" ] || return 1
  mode_is_not_group_or_world_writable "$MODE"
}

trusted_user_owned_directory() {
  local PATH_TO_CHECK="$1"
  local REQUIRED_UID="$2"
  local METADATA
  local OWNER_UID
  local MODE

  [ -d "$PATH_TO_CHECK" ] && [ ! -L "$PATH_TO_CHECK" ] || return 1
  METADATA="$(/usr/bin/stat -f '%u %Lp' -- "$PATH_TO_CHECK")" || return 1
  read -r OWNER_UID MODE <<< "$METADATA"
  [ "$OWNER_UID" -eq "$REQUIRED_UID" ] || return 1
  mode_is_not_group_or_world_writable "$MODE"
}

trusted_root_owned_path_and_ancestors() {
  local PATH_TO_CHECK="$1"
  local METADATA
  local OWNER_UID
  local MODE

  while :; do
    [ -e "$PATH_TO_CHECK" ] && [ ! -L "$PATH_TO_CHECK" ] || return 1
    METADATA="$(/usr/bin/stat -f '%u %Lp' -- "$PATH_TO_CHECK")" || return 1
    read -r OWNER_UID MODE <<< "$METADATA"
    [ "$OWNER_UID" -eq 0 ] || return 1
    mode_is_not_group_or_world_writable "$MODE" || return 1
    [ "$PATH_TO_CHECK" = "/" ] && return 0
    PATH_TO_CHECK="$(/usr/bin/dirname -- "$PATH_TO_CHECK")"
  done
}

if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
  fail "MACOS_LAUNCHER_INSTALL_PLATFORM_BLOCKED"
fi

INTEGRATION_MODE="local-only"
if [ "${1:-}" = "--enable-hackerone-readonly" ]; then
  INTEGRATION_MODE="hackerone-readonly"
  shift
fi

if [ "$#" -gt 1 ]; then
  fail "Verwendung: pnpm app:install-macos -- [--enable-hackerone-readonly] [Zielverzeichnis]"
fi

EVENT_KEY_MINIMUM_VERSION="unset"
if [ "${BUGBOUNTY_EVENT_KEY_MIN_VERSION+x}" = "x" ]; then
  [ "$BUGBOUNTY_EVENT_KEY_MIN_VERSION" != "unset" ] ||
    fail "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID"
  valid_event_key_minimum_version "$BUGBOUNTY_EVENT_KEY_MIN_VERSION" ||
    fail "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID"
  EVENT_KEY_MINIMUM_VERSION="$BUGBOUNTY_EVENT_KEY_MIN_VERSION"
fi

OPERATOR_KEY_REFERENCE="unset"
OPERATOR_ID="unset"
OPERATOR_KEY_REVISION="unset"
OPERATOR_CONFIGURATION_COUNT=0
[ "${BUGBOUNTY_OPERATOR_KEY_REFERENCE+x}" = "x" ] &&
  OPERATOR_CONFIGURATION_COUNT=$((OPERATOR_CONFIGURATION_COUNT + 1))
[ "${BUGBOUNTY_OPERATOR_ID+x}" = "x" ] &&
  OPERATOR_CONFIGURATION_COUNT=$((OPERATOR_CONFIGURATION_COUNT + 1))
[ "${BUGBOUNTY_OPERATOR_KEY_REVISION+x}" = "x" ] &&
  OPERATOR_CONFIGURATION_COUNT=$((OPERATOR_CONFIGURATION_COUNT + 1))

if [ "$OPERATOR_CONFIGURATION_COUNT" -ne 0 ]; then
  [ "$OPERATOR_CONFIGURATION_COUNT" -eq 3 ] ||
    fail "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID"
  [ "$BUGBOUNTY_OPERATOR_KEY_REFERENCE" != "unset" ] ||
    fail "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID"
  [ "$BUGBOUNTY_OPERATOR_ID" != "unset" ] ||
    fail "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID"
  [ "$BUGBOUNTY_OPERATOR_KEY_REVISION" != "unset" ] ||
    fail "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID"
  valid_keychain_reference "$BUGBOUNTY_OPERATOR_KEY_REFERENCE" ||
    fail "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID"
  valid_operator_id "$BUGBOUNTY_OPERATOR_ID" ||
    fail "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID"
  valid_positive_safe_integer "$BUGBOUNTY_OPERATOR_KEY_REVISION" ||
    fail "MACOS_LAUNCHER_INSTALL_CORE_METADATA_INVALID"
  OPERATOR_KEY_REFERENCE="$BUGBOUNTY_OPERATOR_KEY_REFERENCE"
  OPERATOR_ID="$BUGBOUNTY_OPERATOR_ID"
  OPERATOR_KEY_REVISION="$BUGBOUNTY_OPERATOR_KEY_REVISION"
fi

SCRIPT_DIRECTORY="$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)" ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
REPOSITORY_ROOT="$(CDPATH= cd -- "$SCRIPT_DIRECTORY/../.." && /bin/pwd -P)" ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
CURRENT_UID="$(/usr/bin/id -u)" || fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"

if [ "$#" -eq 1 ]; then
  INSTALL_ROOT="$1"
elif [ -n "${BUGBOUNTY_COPILOT_APP_DIR:-}" ]; then
  INSTALL_ROOT="$BUGBOUNTY_COPILOT_APP_DIR"
else
  INSTALL_ROOT="$HOME/Applications"
fi

case "$INSTALL_ROOT" in
  /*) ;;
  *) fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID" ;;
esac
case "$INSTALL_ROOT" in
  *$'\n'* | *$'\r'*) fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID" ;;
esac

[ -f "$REPOSITORY_ROOT/package.json" ] ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
[ -f "$REPOSITORY_ROOT/apps/dashboard/index.ts" ] ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
[ -f "$REPOSITORY_ROOT/apps/macos-launcher/index.ts" ] ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
[ -f "$REPOSITORY_ROOT/apps/macos-launcher/native/BugBountyCopilotLauncher.m" ] ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
[ -f "$REPOSITORY_ROOT/node_modules/tsx/dist/cli.mjs" ] ||
  fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING"
trusted_regular_file \
  "$REPOSITORY_ROOT/apps/macos-launcher/native/BugBountyCopilotLauncher.m" \
  1048576 "$CURRENT_UID" ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
trusted_regular_file "$SCRIPT_DIRECTORY/bundle/Info.plist" 65536 \
  "$CURRENT_UID" || fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
SOURCE_BUNDLE_IDENTIFIER="$(/usr/bin/plutil -extract CFBundleIdentifier raw \
  -- "$SCRIPT_DIRECTORY/bundle/Info.plist" 2>/dev/null)" ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
[ "$SOURCE_BUNDLE_IDENTIFIER" = "$BUNDLE_IDENTIFIER" ] ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"

NODE_COMMAND="$(command -v node)" ||
  fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING"
case "$NODE_COMMAND" in
  /*) ;;
  *) fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING" ;;
esac
NODE_EXECUTABLE="$(/usr/bin/env -i PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
  "$NODE_COMMAND" -p 'process.execPath')" ||
  fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING"
case "$NODE_EXECUTABLE" in
  /*) ;;
  *) fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING" ;;
esac
case "$NODE_EXECUTABLE" in
  *$'\n'* | *$'\r'*) fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING" ;;
esac
NODE_DIRECTORY="$(CDPATH= cd -- "$(/usr/bin/dirname -- "$NODE_EXECUTABLE")" && /bin/pwd -P)" ||
  fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING"
CANONICAL_NODE_EXECUTABLE="$NODE_DIRECTORY/$(/usr/bin/basename -- "$NODE_EXECUTABLE")"
[ "$NODE_EXECUTABLE" = "$CANONICAL_NODE_EXECUTABLE" ] ||
  fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING"
[ -f "$NODE_EXECUTABLE" ] && [ ! -L "$NODE_EXECUTABLE" ] &&
  [ -x "$NODE_EXECUTABLE" ] ||
  fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING"
/usr/bin/env -i PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
  "$NODE_EXECUTABLE" -e 'process.exit(Number(process.versions.node.split(".", 1)[0]) >= 24 ? 0 : 1)' ||
  fail "MACOS_LAUNCHER_INSTALL_NODE_VERSION_BLOCKED"

TSX_ENTRY="$REPOSITORY_ROOT/node_modules/tsx/dist/cli.mjs"
TSX_DIRECTORY="$(CDPATH= cd -- "$(/usr/bin/dirname -- "$TSX_ENTRY")" && /bin/pwd -P)" ||
  fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING"
CANONICAL_TSX_ENTRY="$TSX_DIRECTORY/$(/usr/bin/basename -- "$TSX_ENTRY")"
[ -f "$CANONICAL_TSX_ENTRY" ] && [ ! -L "$CANONICAL_TSX_ENTRY" ] ||
  fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING"
case "$CANONICAL_TSX_ENTRY" in
  "$REPOSITORY_ROOT"/*) ;;
  *) fail "MACOS_LAUNCHER_INSTALL_DEPENDENCIES_MISSING" ;;
esac

COMPILER="$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/tmp \
  /usr/bin/xcrun --find clang)" ||
  fail "MACOS_LAUNCHER_INSTALL_COMPILER_MISSING"
[ -f "$COMPILER" ] && [ ! -L "$COMPILER" ] && [ -x "$COMPILER" ] ||
  fail "MACOS_LAUNCHER_INSTALL_COMPILER_MISSING"
SDK_PATH="$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/tmp \
  /usr/bin/xcrun --sdk macosx --show-sdk-path)" ||
  fail "MACOS_LAUNCHER_INSTALL_COMPILER_MISSING"
SDK_ROOT="$(CDPATH= cd -- "$SDK_PATH" && /bin/pwd -P)" ||
  fail "MACOS_LAUNCHER_INSTALL_COMPILER_MISSING"
[ -d "$SDK_ROOT" ] && [ ! -L "$SDK_ROOT" ] ||
  fail "MACOS_LAUNCHER_INSTALL_COMPILER_MISSING"
trusted_root_owned_path_and_ancestors "$COMPILER" ||
  fail "MACOS_LAUNCHER_INSTALL_COMPILER_MISSING"
trusted_root_owned_path_and_ancestors "$SDK_ROOT" ||
  fail "MACOS_LAUNCHER_INSTALL_COMPILER_MISSING"

/bin/mkdir -p -- "$INSTALL_ROOT" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
INSTALL_ROOT="$(CDPATH= cd -- "$INSTALL_ROOT" && /bin/pwd -P)" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"

APP_PATH="$INSTALL_ROOT/$APP_NAME"
STAGING_PATH="$INSTALL_ROOT/.bugbounty-copilot-launcher-staging-$$"
BACKUP_PATH="$INSTALL_ROOT/.bugbounty-copilot-launcher-backup-$$"

cleanup() {
  if [ -d "$STAGING_PATH" ] && [ ! -L "$STAGING_PATH" ]; then
    /bin/rm -Rf -- "$STAGING_PATH"
  fi
}
trap cleanup EXIT HUP INT TERM

if [ -e "$APP_PATH" ] || [ -L "$APP_PATH" ]; then
  trusted_user_owned_directory "$APP_PATH" "$CURRENT_UID" ||
    fail "MACOS_LAUNCHER_INSTALL_EXISTING_APP_BLOCKED"
  trusted_user_owned_directory "$APP_PATH/Contents" "$CURRENT_UID" ||
    fail "MACOS_LAUNCHER_INSTALL_EXISTING_APP_BLOCKED"
  [ -f "$APP_PATH/Contents/Info.plist" ] &&
    [ ! -L "$APP_PATH/Contents/Info.plist" ] ||
    fail "MACOS_LAUNCHER_INSTALL_EXISTING_APP_BLOCKED"
  trusted_regular_file "$APP_PATH/Contents/Info.plist" 65536 "$CURRENT_UID" ||
    fail "MACOS_LAUNCHER_INSTALL_EXISTING_APP_BLOCKED"
  EXISTING_BUNDLE_IDENTIFIER="$(/usr/bin/plutil -extract \
    CFBundleIdentifier raw -- "$APP_PATH/Contents/Info.plist" 2>/dev/null)" ||
    fail "MACOS_LAUNCHER_INSTALL_EXISTING_APP_BLOCKED"
  [ "$EXISTING_BUNDLE_IDENTIFIER" = "$BUNDLE_IDENTIFIER" ] ||
    fail "MACOS_LAUNCHER_INSTALL_EXISTING_APP_BLOCKED"
  EXISTING_BUNDLE_EXECUTABLE="$(/usr/bin/plutil -extract \
    CFBundleExecutable raw -- "$APP_PATH/Contents/Info.plist" 2>/dev/null)" ||
    fail "MACOS_LAUNCHER_INSTALL_EXISTING_APP_BLOCKED"
  [ "$EXISTING_BUNDLE_EXECUTABLE" = "BugBountyCopilotLauncher" ] ||
    fail "MACOS_LAUNCHER_INSTALL_EXISTING_APP_BLOCKED"
  [ -f "$APP_PATH/Contents/MacOS/BugBountyCopilotLauncher" ] &&
    [ ! -L "$APP_PATH/Contents/MacOS/BugBountyCopilotLauncher" ] ||
    fail "MACOS_LAUNCHER_INSTALL_EXISTING_APP_BLOCKED"
fi

[ ! -e "$STAGING_PATH" ] && [ ! -L "$STAGING_PATH" ] ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
[ ! -e "$BACKUP_PATH" ] && [ ! -L "$BACKUP_PATH" ] ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"

/bin/mkdir -p -- \
  "$STAGING_PATH/Contents/MacOS" \
  "$STAGING_PATH/Contents/Resources" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
/bin/cp -- "$SCRIPT_DIRECTORY/bundle/Info.plist" \
  "$STAGING_PATH/Contents/Info.plist" ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
/usr/bin/printf '%s\n' "$REPOSITORY_ROOT" \
  > "$STAGING_PATH/Contents/Resources/repository-path" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
/usr/bin/printf '%s\n' "$NODE_EXECUTABLE" \
  > "$STAGING_PATH/Contents/Resources/node-path" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
/usr/bin/printf '%s\n' "$CANONICAL_TSX_ENTRY" \
  > "$STAGING_PATH/Contents/Resources/tsx-path" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
/usr/bin/printf '%s\n' "$INTEGRATION_MODE" \
  > "$STAGING_PATH/Contents/Resources/integration-mode" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
/usr/bin/printf '%s\n' "$EVENT_KEY_MINIMUM_VERSION" \
  > "$STAGING_PATH/Contents/Resources/event-key-minimum-version" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
/usr/bin/printf '%s\n' "$OPERATOR_KEY_REFERENCE" \
  > "$STAGING_PATH/Contents/Resources/operator-key-reference" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
/usr/bin/printf '%s\n' "$OPERATOR_ID" \
  > "$STAGING_PATH/Contents/Resources/operator-id" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
/usr/bin/printf '%s\n' "$OPERATOR_KEY_REVISION" \
  > "$STAGING_PATH/Contents/Resources/operator-key-revision" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"

CAPTURED_NATIVE_SOURCE="$STAGING_PATH/Contents/Resources/.BugBountyCopilotLauncher.$$.m"
/bin/cp -- \
  "$SCRIPT_DIRECTORY/native/BugBountyCopilotLauncher.m" \
  "$CAPTURED_NATIVE_SOURCE" ||
  fail "MACOS_LAUNCHER_INSTALL_SOURCE_INVALID"
/bin/chmod 600 "$CAPTURED_NATIVE_SOURCE" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
/usr/bin/env -i \
  PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
  TMPDIR="$STAGING_PATH/Contents/Resources" \
  "$COMPILER" \
  -isysroot "$SDK_ROOT" \
  -fobjc-arc \
  -fstack-protector-strong \
  -D_FORTIFY_SOURCE=2 \
  -fno-common \
  -Wall -Wextra -Werror -Wno-deprecated-declarations \
  -O2 \
  -mmacosx-version-min=13.0 \
  -Wl,-dead_strip \
  "$CAPTURED_NATIVE_SOURCE" \
  -framework AppKit \
  -framework Foundation \
  -o "$STAGING_PATH/Contents/MacOS/BugBountyCopilotLauncher" ||
  fail "MACOS_LAUNCHER_INSTALL_COMPILE_FAILED"
/bin/rm -f -- "$CAPTURED_NATIVE_SOURCE" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"

COMPILED_EXECUTABLE="$STAGING_PATH/Contents/MacOS/BugBountyCopilotLauncher"
trusted_regular_file "$COMPILED_EXECUTABLE" 16777216 "$CURRENT_UID" ||
  fail "MACOS_LAUNCHER_INSTALL_COMPILE_FAILED"
MACHO_MAGIC="$(/usr/bin/od -An -tx1 -N4 "$COMPILED_EXECUTABLE" | \
  /usr/bin/tr -d ' \n')" || fail "MACOS_LAUNCHER_INSTALL_COMPILE_FAILED"
[ "$MACHO_MAGIC" = "cffaedfe" ] ||
  fail "MACOS_LAUNCHER_INSTALL_COMPILE_FAILED"

/bin/chmod 700 "$STAGING_PATH" \
  "$STAGING_PATH/Contents" \
  "$STAGING_PATH/Contents/MacOS" \
  "$STAGING_PATH/Contents/Resources" \
  "$STAGING_PATH/Contents/MacOS/BugBountyCopilotLauncher" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
/bin/chmod 600 "$STAGING_PATH/Contents/Info.plist" \
  "$STAGING_PATH/Contents/Resources/repository-path" \
  "$STAGING_PATH/Contents/Resources/node-path" \
  "$STAGING_PATH/Contents/Resources/tsx-path" \
  "$STAGING_PATH/Contents/Resources/integration-mode" \
  "$STAGING_PATH/Contents/Resources/event-key-minimum-version" \
  "$STAGING_PATH/Contents/Resources/operator-key-reference" \
  "$STAGING_PATH/Contents/Resources/operator-id" \
  "$STAGING_PATH/Contents/Resources/operator-key-revision" ||
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"

/usr/bin/codesign --force --sign - --timestamp=none "$STAGING_PATH" \
  >/dev/null 2>&1 ||
  fail "MACOS_LAUNCHER_INSTALL_CODESIGN_FAILED"
/usr/bin/codesign --verify --strict "$STAGING_PATH" >/dev/null 2>&1 ||
  fail "MACOS_LAUNCHER_INSTALL_CODESIGN_FAILED"

if [ -d "$APP_PATH" ]; then
  /bin/mv -- "$APP_PATH" "$BACKUP_PATH" ||
    fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
fi
if ! /bin/mv -- "$STAGING_PATH" "$APP_PATH"; then
  if [ -d "$BACKUP_PATH" ] && [ ! -e "$APP_PATH" ]; then
    /bin/mv -- "$BACKUP_PATH" "$APP_PATH"
  fi
  fail "MACOS_LAUNCHER_INSTALL_TARGET_INVALID"
fi
if ! /usr/bin/codesign --verify --strict "$APP_PATH" >/dev/null 2>&1; then
  /bin/mv -- "$APP_PATH" "$STAGING_PATH" ||
    fail "MACOS_LAUNCHER_INSTALL_CODESIGN_FAILED"
  if [ -d "$BACKUP_PATH" ] && [ ! -e "$APP_PATH" ]; then
    /bin/mv -- "$BACKUP_PATH" "$APP_PATH" ||
      fail "MACOS_LAUNCHER_INSTALL_CODESIGN_FAILED"
  fi
  fail "MACOS_LAUNCHER_INSTALL_CODESIGN_FAILED"
fi
if [ -d "$BACKUP_PATH" ] && [ ! -L "$BACKUP_PATH" ]; then
  /bin/rm -Rf -- "$BACKUP_PATH"
fi

trap - EXIT HUP INT TERM
/usr/bin/printf 'Installiert: %s\n' "$APP_PATH"
