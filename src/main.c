
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

// TODO: Read from config file
const char default_data_user[] = "gemini-data";

int main(int argc, char ** argv) {
  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();

  log_init(stderr);

  SSL_CTX * ssl_context = ssl_ctx_new();

  if(!ssl_context) {
    log_error("Failed to create SSL context\n");
    return 1;
  }

  struct passwd * p = getpwnam(default_data_user);
  if(p) {
    if(setuid(p->pw_uid)) {
      log_warning("setuid() failed: %s", strerror(errno));
    }
  } else {
    log_warning("User %s not found", default_data_user);
  }

  if(getuid() == 0) {
    log_error("Refusing to run as root");
    exit(1);
  }

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

  return 0;
}

