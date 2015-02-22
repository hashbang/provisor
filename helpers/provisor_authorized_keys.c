#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <syslog.h>
#include <pwd.h>
#include <errno.h>

#include <sys/prctl.h>

#define SSS_KEYS "/usr/bin/sss_ssh_authorizedkeys"
#define SSS_KEYS_NAME "sss_ssh_authorizedkeys"
#define PROGNAME "provisor_authorized_keys"
#define AUTHKEYS "/.ssh/authorized_keys"

void initialize(
    void)
{
  openlog(PROGNAME, 0, LOG_AUTH);
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0) {
    syslog(LOG_ERR, "Cannot turn off binary dumpability");
    exit(EXIT_FAILURE);
  }
}

int main(
    const int argc,
    const char **argv)
{
  initialize();

  struct passwd *pwd = NULL;
  char path[4096];
  char buf[4096];
  FILE *keys = NULL;

  memset(path, 0, 4096);

  if (argc != 2) {
    syslog(LOG_ERR, PROGNAME " called with incorrect argument");
    exit(1);
  }

  errno = 0;
  if ((pwd = getpwnam(argv[1])) == NULL) {
    if (errno) {
      syslog(LOG_ERR, "Username %s not found due to error: %s", argv[1], strerror(errno));
      exit(EXIT_FAILURE);
    }
    else {
      syslog(LOG_ERR, "Username %s was not found", argv[1]);
      exit(EXIT_FAILURE);
    }
  }

  snprintf(path, sizeof(path), "%s%s", pwd->pw_dir, AUTHKEYS);
  if ((keys = fopen(path, "r")) == NULL) {
    if (errno == ENOENT) {
      syslog(LOG_INFO, "Cannot find authorized keys for %s, moving on", argv[1]);
    }
    else {
      syslog(LOG_ERR, "Cannot open authorized keys for %s: %s", argv[1], strerror(errno));
      exit(EXIT_FAILURE);
    }
  }
  else {
    while (fgets(buf, sizeof(buf), keys) != NULL) {
      printf("%s", buf);
      memset(buf, 0, sizeof(buf));
    }
    fclose(keys);
  }

  closelog();
  if (execl(SSS_KEYS, SSS_KEYS_NAME, argv[1], NULL) < 0) {
    syslog(LOG_ERR, "Cannot execute %s: %s", SSS_KEYS_NAME, strerror(errno));
    exit(EXIT_FAILURE);
  }
  exit(0);
}
