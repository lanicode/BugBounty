#!/bin/sh
set -eu

if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
  exit 0
fi

repository_root=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")/../.." && /bin/pwd -P)
wrapper_source="$repository_root/apps/macos-launcher/native/BugBountyCopilotLauncher.m"
fake_node_source="$repository_root/tests/native/fixtures/macos-wrapper-fake-node.c"
temporary_directory=$(/usr/bin/mktemp -d "/private/tmp/bugbounty-wrapper-integration.XXXXXX")
fixture_repository="$temporary_directory/repository"
app="$temporary_directory/Bug Bounty Copilot.app"
resources="$app/Contents/Resources"
wrapper="$app/Contents/MacOS/BugBountyCopilotLauncher"
fake_node="$fixture_repository/fake-node"
tsx_entry="$fixture_repository/node_modules/tsx/dist/cli.mjs"
launcher_entry="$fixture_repository/apps/macos-launcher/index.ts"
wrapper_pid=""
control_pid=""
child_pid=""
grandchild_pid=""
bundle_identifier="dev.local.bugbounty-copilot.launcher.lifecycle-test.$$"

fixture_process_matches() {
  process_identifier="$1"
  process_command=$(/bin/ps -p "$process_identifier" -o command= 2>/dev/null) ||
    return 1
  case "$process_command" in
    "$fake_node" | "$fake_node "*) return 0 ;;
    *) return 1 ;;
  esac
}

cleanup() {
  if [ -n "$wrapper_pid" ] &&
    [ "$(/bin/ps -p "$wrapper_pid" -o command= 2>/dev/null || true)" = "$wrapper" ]; then
    /bin/kill -KILL "$wrapper_pid" >/dev/null 2>&1 || true
  fi
  /usr/bin/pkill -KILL -f -x "$wrapper" >/dev/null 2>&1 || true
  if [ -n "$child_pid" ] && fixture_process_matches "$child_pid"; then
    /bin/kill -KILL "-$child_pid" >/dev/null 2>&1 || true
  elif [ -n "$grandchild_pid" ] && fixture_process_matches "$grandchild_pid"; then
    /bin/kill -KILL "$grandchild_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$control_pid" ]; then
    /bin/kill -TERM "$control_pid" >/dev/null 2>&1 || true
  fi
  /bin/rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

/bin/mkdir -p -- \
  "$fixture_repository/node_modules/tsx/dist" \
  "$fixture_repository/apps/macos-launcher" \
  "$app/Contents/MacOS" \
  "$resources"
/bin/chmod 700 \
  "$temporary_directory" \
  "$fixture_repository" \
  "$fixture_repository/node_modules" \
  "$fixture_repository/node_modules/tsx" \
  "$fixture_repository/node_modules/tsx/dist" \
  "$fixture_repository/apps" \
  "$fixture_repository/apps/macos-launcher" \
  "$app" \
  "$app/Contents" \
  "$app/Contents/MacOS" \
  "$resources"

/usr/bin/printf 'synthetic tsx fixture\n' >"$tsx_entry"
/usr/bin/printf 'synthetic launcher fixture\n' >"$launcher_entry"
/bin/chmod 600 "$tsx_entry" "$launcher_entry"
/bin/cp -- "$repository_root/apps/macos-launcher/bundle/Info.plist" \
  "$app/Contents/Info.plist"
/usr/bin/plutil -replace CFBundleIdentifier -string "$bundle_identifier" \
  "$app/Contents/Info.plist"
/usr/bin/plutil -replace CFBundleDisplayName -string \
  "Bug Bounty Copilot Lifecycle Test" "$app/Contents/Info.plist"
/bin/chmod 600 "$app/Contents/Info.plist"

compiler=$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/tmp \
  /usr/bin/xcrun --find clang)
sdk_path=$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/tmp \
  /usr/bin/xcrun --sdk macosx --show-sdk-path)
sdk_root=$(CDPATH= cd -- "$sdk_path" && /bin/pwd -P)

/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR="$temporary_directory" \
  "$compiler" -std=c17 -Wall -Wextra -Werror -O2 \
  -isysroot "$sdk_root" "$fake_node_source" -o "$fake_node"
/bin/chmod 700 "$fake_node"

/usr/bin/printf '%s\n' "$fixture_repository" >"$resources/repository-path"
/usr/bin/printf '%s\n' "$fake_node" >"$resources/node-path"
/usr/bin/printf '%s\n' "$tsx_entry" >"$resources/tsx-path"
/bin/chmod 600 \
  "$resources/repository-path" \
  "$resources/node-path" \
  "$resources/tsx-path"

/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR="$temporary_directory" \
  "$compiler" \
  -isysroot "$sdk_root" \
  -fobjc-arc \
  -fstack-protector-strong \
  -D_FORTIFY_SOURCE=2 \
  -fno-common \
  -Wall -Wextra -Werror -Wno-deprecated-declarations \
  -O2 \
  -mmacosx-version-min=13.0 \
  -Wl,-dead_strip \
  "$wrapper_source" \
  -framework AppKit \
  -framework Foundation \
  -o "$wrapper"
/bin/chmod 700 "$wrapper"
/usr/bin/codesign --force --sign - --timestamp=none "$app" >/dev/null 2>&1
/usr/bin/codesign --verify --strict "$app" >/dev/null 2>&1

/bin/sleep 30 &
control_pid=$!
"$wrapper" &
wrapper_pid=$!

ready=0
attempt=0
while [ "$attempt" -lt 100 ]; do
  if [ -f "$fixture_repository/ready" ]; then
    ready=1
    break
  fi
  /bin/kill -0 "$wrapper_pid" >/dev/null 2>&1 || break
  /bin/sleep 0.05
  attempt=$((attempt + 1))
done
[ "$ready" -eq 1 ] || exit 1

expected_arguments="$temporary_directory/expected-arguments"
/usr/bin/printf '%s\n%s\n%s\n' \
  "$tsx_entry" "$launcher_entry" "$resources" >"$expected_arguments"
/usr/bin/cmp -s "$expected_arguments" "$fixture_repository/observed-arguments"

child_pid=$(/bin/cat "$fixture_repository/child-pid")
grandchild_pid=$(/bin/cat "$fixture_repository/grandchild-pid")
started_at=$(/bin/date +%s)
/bin/kill -TERM "$wrapper_pid"

attempt=0
while /bin/kill -0 "$wrapper_pid" >/dev/null 2>&1; do
  [ "$attempt" -lt 100 ] || exit 1
  /bin/sleep 0.1
  attempt=$((attempt + 1))
done
set +e
wait "$wrapper_pid"
wrapper_status=$?
set -e
wrapper_pid=""
finished_at=$(/bin/date +%s)
elapsed=$((finished_at - started_at))
[ "$wrapper_status" -eq 0 ] || exit 1
[ "$elapsed" -ge 4 ] && [ "$elapsed" -le 9 ] || exit 1

attempt=0
while /bin/kill -0 "$child_pid" >/dev/null 2>&1 || \
  /bin/kill -0 "$grandchild_pid" >/dev/null 2>&1; do
  [ "$attempt" -lt 20 ] || exit 1
  /bin/sleep 0.05
  attempt=$((attempt + 1))
done
child_pid=""
grandchild_pid=""

/bin/kill -0 "$control_pid" >/dev/null 2>&1 || exit 1
/bin/kill -TERM "$control_pid"
wait "$control_pid" || true
control_pid=""

# The LaunchServices path exercises a modal reopen alert followed by an
# AppKit quit while the synthetic child and grandchild ignore SIGTERM.
/bin/rm -f -- \
  "$fixture_repository/observed-arguments" \
  "$fixture_repository/child-pid" \
  "$fixture_repository/grandchild-pid" \
  "$fixture_repository/ready"
/bin/sleep 30 &
control_pid=$!
/usr/bin/open "$app"

ready=0
attempt=0
while [ "$attempt" -lt 100 ]; do
  if [ -f "$fixture_repository/ready" ]; then
    ready=1
    break
  fi
  /bin/sleep 0.05
  attempt=$((attempt + 1))
done
[ "$ready" -eq 1 ] || exit 1
child_pid=$(/bin/cat "$fixture_repository/child-pid")
grandchild_pid=$(/bin/cat "$fixture_repository/grandchild-pid")

/bin/sleep 1.2
/usr/bin/open "$app"
/bin/sleep 0.2
started_at=$(/bin/date +%s)
/usr/bin/osascript \
  -e 'with timeout of 12 seconds' \
  -e "tell application id \"$bundle_identifier\" to quit" \
  -e 'end timeout'
finished_at=$(/bin/date +%s)
elapsed=$((finished_at - started_at))
[ "$elapsed" -ge 4 ] && [ "$elapsed" -le 9 ] || exit 1

attempt=0
while fixture_process_matches "$child_pid" || \
  fixture_process_matches "$grandchild_pid"; do
  [ "$attempt" -lt 20 ] || exit 1
  /bin/sleep 0.05
  attempt=$((attempt + 1))
done
child_pid=""
grandchild_pid=""

attempt=0
while /usr/bin/pgrep -f -x "$wrapper" >/dev/null 2>&1; do
  [ "$attempt" -lt 20 ] || exit 1
  /bin/sleep 0.05
  attempt=$((attempt + 1))
done
/bin/kill -0 "$control_pid" >/dev/null 2>&1 || exit 1
/bin/kill -TERM "$control_pid"
wait "$control_pid" || true
control_pid=""
