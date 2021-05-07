
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

  SSL_CTX * ssl_context = ssl_ctx_new();

  // Initialize libevent by creating a libevent base
  struct event_base * base = event_base_new();
  if(!base) {
    log_error("event_base_new() failed!\n");
    return 1;
  }

  /*
  char hostname[HOST_NAME_MAX+1];
  gethostname(hostname, sizeof(hostname));
  log_info("Hostname: %s", hostname);
  */

  /*
  struct passwd * p = getpwnam("http");
  if(p) {
    log_info("setuid(%d);", p->pw_uid);
    setuid(p->pw_uid);
    log_info("%s", strerror(errno));
  }
  */

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

  return 0;
}

