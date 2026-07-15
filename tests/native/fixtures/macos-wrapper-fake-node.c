#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern char **environ;

static void fail(void) { _exit(90); }

static void sibling_path(char output[PATH_MAX], const char *executable,
                         const char *name) {
  char resolved[PATH_MAX];
  if (realpath(executable, resolved) == NULL) fail();
  char *separator = strrchr(resolved, '/');
  if (separator == NULL) fail();
  separator[1] = '\0';
  int count = snprintf(output, PATH_MAX, "%s%s", resolved, name);
  if (count < 1 || count >= PATH_MAX) fail();
}

static void write_all(int descriptor, const char *bytes, size_t size) {
  size_t offset = 0;
  while (offset < size) {
    ssize_t count = write(descriptor, bytes + offset, size - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) fail();
    offset += (size_t)count;
  }
}

static void write_text(const char *executable, const char *name,
                       const char *value) {
  char path[PATH_MAX];
  sibling_path(path, executable, name);
  int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (descriptor < 0) fail();
  write_all(descriptor, value, strlen(value));
  if (close(descriptor) != 0) fail();
}

static void write_pid(const char *executable, const char *name, pid_t value) {
  char text[64];
  int count = snprintf(text, sizeof(text), "%ld\n", (long)value);
  if (count < 1 || (size_t)count >= sizeof(text)) fail();
  write_text(executable, name, text);
}

int main(int argc, char *argv[]) {
  umask(0077);
  if (argc != 4 || environ == NULL || environ[0] == NULL ||
      strcmp(environ[0], "PATH=/usr/bin:/bin:/usr/sbin:/sbin") != 0 ||
      environ[1] != NULL)
    return 91;

  char arguments[PATH_MAX * 3 + 4];
  int argumentCount = snprintf(arguments, sizeof(arguments), "%s\n%s\n%s\n",
                               argv[1], argv[2], argv[3]);
  if (argumentCount < 1 || (size_t)argumentCount >= sizeof(arguments)) fail();
  write_text(argv[0], "observed-arguments", arguments);

  if (signal(SIGTERM, SIG_IGN) == SIG_ERR ||
      signal(SIGINT, SIG_IGN) == SIG_ERR ||
      signal(SIGHUP, SIG_IGN) == SIG_ERR)
    fail();

  pid_t grandchild = fork();
  if (grandchild < 0) fail();
  if (grandchild == 0) {
    for (;;) pause();
  }

  write_pid(argv[0], "child-pid", getpid());
  write_pid(argv[0], "grandchild-pid", grandchild);
  write_text(argv[0], "ready", "ready\n");
  for (;;) pause();
}
