
#include <config.h>
#include <log.h>
#include <server.h>
#include <sigs.h>
#include <ssl_init.h>

#include <event2/util.h>
#include <event2/event.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <pwd.h>

int main(int argc, char ** argv) {
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();

  log_init(stderr);

  if(argc >= 2) {
    cfg_init(argv[1]);
  } else {
    cfg_init(CFG_MAIN_CONFIG_FILE);
  }

  SSL_CTX * ssl_context = ssl_ctx_new();

  if(!ssl_context) {
    log_error("Failed to create SSL context\n");
    return 1;
  }

  const char * user = cfg_user();
  struct passwd * p = getpwnam(user);
  if(p) {
    if(setuid(p->pw_uid)) {
      log_warning("setuid() failed: %s", strerror(errno));
    }
  } else {
    log_warning("User %s not found", user);
  }

  if(getuid() == 0) {
    log_error("Refusing to run as root (UID = 0)");
    exit(1);
  }

  const char * group = cfg_group();
  p = getpwnam(group);
  if(p) {
    if(setgid(p->pw_gid)) {
      log_warning("setgid() failed: %s", strerror(errno));
    }
  } else {
    log_warning("Group %s not found", group);
  }

  if(getgid() == 0) {
    log_error("Refusing to run as root (GID = 0)");
    exit(1);
  }

  chdir(cfg_root_directory());

  struct event_base * base = event_base_new();
  if(!base) {
    log_error("event_base_new() failed\n");
    return 1;
  }

  server_init(base, ssl_context);
  sigs_init(base);

  log_info("Server running (user: %s)", getlogin());

  event_base_dispatch(base);

  sigs_deinit();
  server_deinit();

  event_base_free(base);
  base = NULL;

  SSL_CTX_free(ssl_context);
  ssl_context = NULL;

  cfg_deinit();

  return 0;
}

