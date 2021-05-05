
#include <log.h>
#include <server.h>
#include <sigs.h>
#include <uri_parser.h>

#include <event2/util.h>
#include <event2/event.h>

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>

int main(int argc, char ** argv) {
  log_init(stderr);

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

  server_init(base);
  sigs_init(base);

  log_info("Server running");

  event_base_dispatch(base);

  sigs_deinit();
  server_deinit();

  event_base_free(base);
  base = NULL;

  return 0;
}

