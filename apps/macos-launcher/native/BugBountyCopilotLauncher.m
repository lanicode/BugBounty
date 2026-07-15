#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const int kAlreadyRunningExitCode = 73;
static const int kStartupTimeoutExitCode = 74;
static const time_t kTerminationGraceSeconds = 5;
static const time_t kTerminationReapSeconds = 2;
static const off_t kMaximumConfigBytes = 4096;
static const off_t kMaximumCodeBytes = 16 * 1024 * 1024;
static const off_t kMaximumExecutableBytes = 512 * 1024 * 1024;
static sigset_t gTerminationSignals;
static pthread_mutex_t gChildMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gChildCondition = PTHREAD_COND_INITIALIZER;
static pid_t gTrackedChild = 0;
static BOOL gTrackedChildReaped = YES;
static BOOL gTerminationRequestedBySignal = NO;

static BOOL BlockTerminationSignals(void) {
  if (sigemptyset(&gTerminationSignals) != 0 ||
      sigaddset(&gTerminationSignals, SIGTERM) != 0 ||
      sigaddset(&gTerminationSignals, SIGINT) != 0 ||
      sigaddset(&gTerminationSignals, SIGHUP) != 0)
    return NO;
  return pthread_sigmask(SIG_BLOCK, &gTerminationSignals, NULL) == 0;
}

static BOOL RegisterTrackedChild(pid_t child) {
  if (pthread_mutex_lock(&gChildMutex) != 0) return NO;
  BOOL registered = NO;
  if (child > 0 && gTrackedChild == 0 && gTrackedChildReaped) {
    gTrackedChild = child;
    gTrackedChildReaped = NO;
    registered = YES;
  }
  (void)pthread_mutex_unlock(&gChildMutex);
  return registered;
}

static void SignalExpectedTrackedChild(pid_t expectedChild, int signalNumber) {
  if (pthread_mutex_lock(&gChildMutex) != 0) return;
  if (gTrackedChild == expectedChild && expectedChild > 0)
    (void)kill(-expectedChild, signalNumber);
  (void)pthread_mutex_unlock(&gChildMutex);
}

static void DeadlineAfterSeconds(time_t seconds, struct timespec *deadline) {
  if (clock_gettime(CLOCK_REALTIME, deadline) != 0) {
    deadline->tv_sec = 0;
    deadline->tv_nsec = 0;
    return;
  }
  deadline->tv_sec += seconds;
}

static NSString *CanonicalPathForExistingPath(NSString *path) {
  if (path == nil || ![path isAbsolutePath]) return nil;
  const char *fileSystemPath = [path fileSystemRepresentation];
  if (fileSystemPath == NULL) return nil;
  char resolved[PATH_MAX];
  if (realpath(fileSystemPath, resolved) == NULL) return nil;
  return [[NSString alloc] initWithUTF8String:resolved];
}

static BOOL IsCanonicalPath(NSString *path) {
  NSString *canonical = CanonicalPathForExistingPath(path);
  return canonical != nil && [path isEqualToString:canonical];
}

static BOOL IsOwnedPrivateDirectory(NSString *path) {
  if (!IsCanonicalPath(path)) return NO;
  struct stat status;
  if (lstat([path fileSystemRepresentation], &status) != 0) return NO;
  return S_ISDIR(status.st_mode) && status.st_uid == getuid() &&
         (status.st_mode & 0077) == 0;
}

static BOOL IsTrustedRegularFile(NSString *path, BOOL executable,
                                 off_t maximumBytes) {
  if (!IsCanonicalPath(path)) return NO;
  struct stat status;
  if (lstat([path fileSystemRepresentation], &status) != 0) return NO;
  if (!S_ISREG(status.st_mode) || status.st_nlink != 1 || status.st_size < 1 ||
      status.st_size > maximumBytes ||
      (status.st_uid != 0 && status.st_uid != getuid()) ||
      (status.st_mode & 0022) != 0)
    return NO;
  if (executable && access([path fileSystemRepresentation], X_OK) != 0)
    return NO;
  return YES;
}

static NSString *ReadPrivateAbsolutePath(NSString *path) {
  const char *fileSystemPath = [path fileSystemRepresentation];
  if (fileSystemPath == NULL) return nil;
  int descriptor = open(fileSystemPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return nil;

  NSString *result = nil;
  struct stat status;
  char *bytes = NULL;
  do {
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_nlink != 1 || status.st_uid != getuid() ||
        (status.st_mode & 0777) != 0600 || status.st_size < 2 ||
        status.st_size > kMaximumConfigBytes)
      break;

    size_t size = (size_t)status.st_size;
    bytes = calloc(size + 1, 1);
    if (bytes == NULL) break;
    size_t offset = 0;
    while (offset < size) {
      ssize_t count = read(descriptor, bytes + offset, size - offset);
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) break;
      offset += (size_t)count;
    }
    if (offset != size || bytes[size - 1] != '\n') break;
    bool invalid = false;
    for (size_t index = 0; index + 1 < size; index += 1) {
      if (bytes[index] == '\0' || bytes[index] == '\n' || bytes[index] == '\r') {
        invalid = true;
        break;
      }
    }
    if (invalid) break;

    char trailing = 0;
    ssize_t extra;
    do {
      extra = read(descriptor, &trailing, 1);
    } while (extra < 0 && errno == EINTR);
    if (extra != 0) break;

    result = [[NSString alloc] initWithBytes:bytes
                                      length:size - 1
                                    encoding:NSUTF8StringEncoding];
    if (result == nil || ![result isAbsolutePath]) result = nil;
  } while (false);

  if (bytes != NULL) {
    memset(bytes, 0, (size_t)status.st_size + 1);
    free(bytes);
  }
  close(descriptor);
  return result;
}

static BOOL IsPathInsideRoot(NSString *path, NSString *root) {
  NSString *prefix = [root stringByAppendingString:@"/"];
  return [path hasPrefix:prefix];
}

@interface BugBountyCopilotAppDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic) pid_t childProcessIdentifier;
@property(nonatomic) BOOL terminationPending;
@property(nonatomic) BOOL reopenReady;
@property(nonatomic) BOOL alertVisible;
@end

@implementation BugBountyCopilotAppDelegate

- (instancetype)init {
  self = [super init];
  if (self != nil) {
    _childProcessIdentifier = 0;
    _terminationPending = NO;
    _reopenReady = NO;
    _alertVisible = NO;
  }
  return self;
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
  (void)notification;
  [[NSProcessInfo processInfo] disableSuddenTermination];
  [[NSProcessInfo processInfo]
      disableAutomaticTermination:@"Local dashboard supervisor is active"];
  [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

  if (![self startLocalSupervisor]) {
    [self startTerminationSignalWaiter];
    [self showGenericBlockedMessage];
    [NSApp terminate:nil];
    return;
  }
  [self startTerminationSignalWaiter];

  [self performSelector:@selector(enableReopenHandling)
             withObject:nil
             afterDelay:1.0];
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender
                     hasVisibleWindows:(BOOL)flag {
  (void)sender;
  (void)flag;
  if (self.reopenReady && self.childProcessIdentifier > 0)
    [self showAlreadyRunningMessage];
  return NO;
}

- (NSApplicationTerminateReply)applicationShouldTerminate:
    (NSApplication *)sender {
  (void)sender;
  pid_t child = self.childProcessIdentifier;
  if (child <= 0) return NSTerminateNow;
  if (!self.terminationPending) {
    self.terminationPending = YES;
    SignalExpectedTrackedChild(child, SIGTERM);
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW,
                      (int64_t)kTerminationGraceSeconds * NSEC_PER_SEC),
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
          SignalExpectedTrackedChild(child, SIGKILL);
        });
  }
  return NSTerminateLater;
}

- (void)enableReopenHandling { self.reopenReady = YES; }

- (void)startTerminationSignalWaiter {
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
    if (pthread_sigmask(SIG_BLOCK, &gTerminationSignals, NULL) != 0) _exit(1);
    int receivedSignal = 0;
    if (sigwait(&gTerminationSignals, &receivedSignal) != 0) _exit(1);

    if (pthread_mutex_lock(&gChildMutex) != 0) _exit(1);
    gTerminationRequestedBySignal = YES;
    pid_t child = gTrackedChild;
    if (child > 0) (void)kill(-child, SIGTERM);

    struct timespec deadline;
    DeadlineAfterSeconds(kTerminationGraceSeconds, &deadline);
    int waitStatus = 0;
    while (!gTrackedChildReaped && waitStatus == 0) {
      waitStatus = pthread_cond_timedwait(&gChildCondition, &gChildMutex,
                                         &deadline);
    }
    if (!gTrackedChildReaped && gTrackedChild == child && child > 0)
      (void)kill(-child, SIGKILL);

    DeadlineAfterSeconds(kTerminationReapSeconds, &deadline);
    waitStatus = 0;
    while (!gTrackedChildReaped && waitStatus == 0) {
      waitStatus = pthread_cond_timedwait(&gChildCondition, &gChildMutex,
                                         &deadline);
    }
    BOOL reaped = gTrackedChildReaped;
    (void)pthread_mutex_unlock(&gChildMutex);
    _exit(reaped ? 0 : 1);
  });
}

- (BOOL)startLocalSupervisor {
  NSString *resources = [[NSBundle mainBundle] resourcePath];
  if (!IsOwnedPrivateDirectory(resources)) return NO;

  NSString *repository = ReadPrivateAbsolutePath(
      [resources stringByAppendingPathComponent:@"repository-path"]);
  NSString *node = ReadPrivateAbsolutePath(
      [resources stringByAppendingPathComponent:@"node-path"]);
  NSString *tsx = ReadPrivateAbsolutePath(
      [resources stringByAppendingPathComponent:@"tsx-path"]);
  if (repository == nil || node == nil || tsx == nil ||
      !IsCanonicalPath(repository) || !IsCanonicalPath(node) ||
      !IsCanonicalPath(tsx))
    return NO;

  struct stat repositoryStatus;
  if (lstat([repository fileSystemRepresentation], &repositoryStatus) != 0 ||
      !S_ISDIR(repositoryStatus.st_mode) ||
      repositoryStatus.st_uid != getuid() ||
      (repositoryStatus.st_mode & 0022) != 0)
    return NO;

  NSString *launcher =
      [repository stringByAppendingPathComponent:@"apps/macos-launcher/index.ts"];
  NSString *expectedTsx = CanonicalPathForExistingPath(
      [repository stringByAppendingPathComponent:
                      @"node_modules/tsx/dist/cli.mjs"]);
  if (!IsTrustedRegularFile(node, YES, kMaximumExecutableBytes) ||
      !IsTrustedRegularFile(tsx, NO, kMaximumCodeBytes) ||
      !IsTrustedRegularFile(launcher, NO, kMaximumCodeBytes) ||
      expectedTsx == nil || ![tsx isEqualToString:expectedTsx] ||
      !IsPathInsideRoot(tsx, repository) ||
      !IsPathInsideRoot(launcher, repository))
    return NO;

  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attributes;
  if (posix_spawn_file_actions_init(&actions) != 0) return NO;
  if (posix_spawnattr_init(&attributes) != 0) {
    posix_spawn_file_actions_destroy(&actions);
    return NO;
  }

  BOOL configured = YES;
  configured = configured &&
               posix_spawn_file_actions_addopen(
                   &actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0;
  configured = configured &&
               posix_spawn_file_actions_addopen(
                   &actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0;
  configured = configured &&
               posix_spawn_file_actions_addopen(
                   &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0;
  configured =
      configured &&
      posix_spawn_file_actions_addchdir_np(
          &actions, [repository fileSystemRepresentation]) == 0;

  short flags = POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF |
                POSIX_SPAWN_SETSIGMASK;
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
  flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
#endif
  sigset_t defaults;
  sigemptyset(&defaults);
  sigaddset(&defaults, SIGHUP);
  sigaddset(&defaults, SIGINT);
  sigaddset(&defaults, SIGTERM);
  sigaddset(&defaults, SIGPIPE);
  sigset_t mask;
  sigemptyset(&mask);
  configured = configured && posix_spawnattr_setflags(&attributes, flags) == 0;
  configured = configured &&
               posix_spawnattr_setpgroup(&attributes, 0) == 0;
  configured = configured &&
               posix_spawnattr_setsigdefault(&attributes, &defaults) == 0;
  configured = configured &&
               posix_spawnattr_setsigmask(&attributes, &mask) == 0;

  pid_t child = 0;
  int spawnStatus = EINVAL;
  if (configured) {
    char *arguments[] = {
        (char *)[node fileSystemRepresentation],
        (char *)[tsx fileSystemRepresentation],
        (char *)[launcher fileSystemRepresentation],
        (char *)[resources fileSystemRepresentation],
        NULL,
    };
    char *environment[] = {
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        NULL,
    };
    spawnStatus = posix_spawn(&child, [node fileSystemRepresentation], &actions,
                              &attributes, arguments, environment);
  }
  posix_spawnattr_destroy(&attributes);
  posix_spawn_file_actions_destroy(&actions);
  if (!configured || spawnStatus != 0 || child <= 0) return NO;
  if (!RegisterTrackedChild(child)) {
    (void)kill(-child, SIGKILL);
    int ignoredStatus = 0;
    while (waitpid(child, &ignoredStatus, 0) < 0 && errno == EINTR) {
    }
    return NO;
  }

  self.childProcessIdentifier = child;
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
    siginfo_t childInformation;
    memset(&childInformation, 0, sizeof(childInformation));
    int observationStatus;
    do {
      observationStatus =
          waitid(P_PID, (id_t)child, &childInformation, WEXITED | WNOWAIT);
    } while (observationStatus != 0 && errno == EINTR);

    BOOL childWasOwned = NO;
    if (pthread_mutex_lock(&gChildMutex) == 0) {
      if (gTrackedChild == child) {
        gTrackedChild = 0;
        childWasOwned = YES;
        // The direct child is deliberately still waitable here. Its PID and
        // process-group identity therefore cannot be reused before cleanup.
        (void)kill(-child, SIGKILL);
      }
      (void)pthread_mutex_unlock(&gChildMutex);
    }

    int status = 0;
    pid_t result;
    do {
      result = waitpid(child, &status, 0);
    } while (result < 0 && errno == EINTR);
    BOOL terminateAfterSignal = NO;
    if (pthread_mutex_lock(&gChildMutex) == 0) {
      if (childWasOwned) {
        gTrackedChildReaped = YES;
        terminateAfterSignal = gTerminationRequestedBySignal;
        (void)pthread_cond_broadcast(&gChildCondition);
      }
      (void)pthread_mutex_unlock(&gChildMutex);
    }
    if (terminateAfterSignal)
      _exit(observationStatus == 0 && result == child ? 0 : 1);
    dispatch_async(dispatch_get_main_queue(), ^{
      [self childDidExit:child
                   status:status
               waitResult:result
        observationSucceeded:observationStatus == 0
                    wasOwned:childWasOwned];
    });
  });
  return YES;
}

- (void)childDidExit:(pid_t)child
                 status:(int)status
             waitResult:(pid_t)waitResult
  observationSucceeded:(BOOL)observationSucceeded
               wasOwned:(BOOL)wasOwned {
  if (!wasOwned) return;
  self.childProcessIdentifier = 0;

  if (self.terminationPending) {
    [NSApp replyToApplicationShouldTerminate:YES];
    return;
  }

  if (observationSucceeded && waitResult == child && WIFEXITED(status)) {
    int exitCode = WEXITSTATUS(status);
    if (exitCode == kAlreadyRunningExitCode)
      [self showAlreadyRunningMessage];
    else if (exitCode == kStartupTimeoutExitCode)
      [self showStartupTimeoutMessage];
    else if (exitCode != 0)
      [self showGenericBlockedMessage];
  } else {
    [self showGenericBlockedMessage];
  }
  [NSApp terminate:nil];
}

- (void)showAlreadyRunningMessage {
  [self showMessage:@"Bug Bounty Copilot läuft bereits. Verwende das vorhandene "
                    @"Browserfenster. Falls du es geschlossen hast, beende die "
                    @"App in der Aktivitätsanzeige und öffne sie erneut."
              style:NSAlertStyleInformational];
}

- (void)showStartupTimeoutMessage {
  [self showMessage:@"Der erste lokale Start hat zu lange gedauert und wurde "
                    @"sicher beendet. Öffne die App bitte erneut; es wurde keine "
                    @"externe Verbindung hergestellt."
              style:NSAlertStyleInformational];
}

- (void)showGenericBlockedMessage {
  [self showMessage:@"Der lokale Start wurde sicher blockiert. Prüfe das "
                    @"Repository und führe danach den lokalen macOS-Installer "
                    @"erneut aus."
              style:NSAlertStyleCritical];
}

- (void)showMessage:(NSString *)message style:(NSAlertStyle)style {
  if (self.alertVisible) return;
  self.alertVisible = YES;
  [NSApp activateIgnoringOtherApps:YES];
  NSAlert *alert = [[NSAlert alloc] init];
  [alert setMessageText:@"Bug Bounty Copilot"];
  [alert setInformativeText:message];
  [alert setAlertStyle:style];
  [alert addButtonWithTitle:@"OK"];
  [alert runModal];
  self.alertVisible = NO;
}

@end

int main(int argc, const char *argv[]) {
  (void)argc;
  (void)argv;
  umask(0077);
  struct rlimit limit = {0, 0};
  if (setrlimit(RLIMIT_CORE, &limit) != 0 || !BlockTerminationSignals() ||
      signal(SIGPIPE, SIG_IGN) == SIG_ERR)
    return 1;
  @autoreleasepool {
    NSApplication *application = [NSApplication sharedApplication];
    BugBountyCopilotAppDelegate *delegate =
        [[BugBountyCopilotAppDelegate alloc] init];
    [application setDelegate:delegate];
    [application run];
  }
  return 0;
}
