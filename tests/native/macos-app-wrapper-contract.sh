#!/bin/sh
set -eu

if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
  exit 0
fi

repository_root=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")/../.." && /bin/pwd -P)
source_file="$repository_root/apps/macos-launcher/native/BugBountyCopilotLauncher.m"
temporary_directory=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/bugbounty-app-wrapper.XXXXXX")
binary="$temporary_directory/BugBountyCopilotLauncher"

cleanup() {
  /bin/rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

compiler=$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/tmp \
  /usr/bin/xcrun --find clang)
sdk_path=$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/tmp \
  /usr/bin/xcrun --sdk macosx --show-sdk-path)
sdk_root=$(CDPATH= cd -- "$sdk_path" && /bin/pwd -P)
/usr/bin/env -i \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  TMPDIR="$temporary_directory" \
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
  "$source_file" \
  -framework AppKit \
  -framework Foundation \
  -o "$binary"

[ -x "$binary" ] || exit 1
/usr/bin/file "$binary" | /usr/bin/grep -Fq 'Mach-O 64-bit executable'
/usr/bin/codesign --force --sign - --timestamp=none "$binary" >/dev/null 2>&1
/usr/bin/codesign --verify --strict "$binary" >/dev/null 2>&1

if /usr/bin/grep -Eq \
  '(^|[^A-Za-z0-9_])(getenv|putenv|setenv|popen|system|NSLog)[[:space:]]*\(' \
  "$source_file"; then
  exit 1
fi

if /usr/bin/grep -Eiq \
  '(https?://|hackerone\.com|api\.hackerone\.com|curl|npm|npx|pnpm|NSURLSession)' \
  "$source_file"; then
  exit 1
fi

for required_boundary in \
  '<NSApplicationDelegate>' \
  '[application run]' \
  'NSApplicationActivationPolicyAccessory' \
  'applicationShouldHandleReopen:' \
  'applicationShouldTerminate:' \
  'waitid(P_PID' \
  'WEXITED | WNOWAIT' \
  'pthread_mutex_lock(&gChildMutex)' \
  'pthread_cond_timedwait(' \
  'sigwait(&gTerminationSignals' \
  'POSIX_SPAWN_SETPGROUP' \
  'POSIX_SPAWN_SETSIGDEF' \
  'POSIX_SPAWN_SETSIGMASK' \
  'posix_spawn_file_actions_addchdir_np' \
  'waitpid(child' \
  'kill(-child, SIGTERM)' \
  'kill(-child, SIGKILL)' \
  'setrlimit(RLIMIT_CORE' \
  'O_NOFOLLOW' \
  'kAlreadyRunningExitCode = 73' \
  'kStartupTimeoutExitCode = 74' \
  'PATH=/usr/bin:/bin:/usr/sbin:/sbin'
do
  if ! /usr/bin/grep -Fq "$required_boundary" "$source_file"; then
    exit 1
  fi
done
