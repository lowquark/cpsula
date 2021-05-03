
#include <log.h>
#include <server.h>
#include <sigs.h>

#include <event2/util.h>
#include <event2/event.h>

#include <string.h>
#include <stdio.h>

int main(int argc, char ** argv) {
  log_init(stderr);

  log_error("test error");
  log_warning("test warning");
  log_info("test info");

  // Initialize libevent by creating a libevent base
  struct event_base * base = event_base_new();
  if(!base) {
    log_error("event_base_new() failed!\n");
    return 1;
  }

  server_init(base);
  sigs_init(base);

  event_base_dispatch(base);

  sigs_deinit();
  server_deinit();

  event_base_free(base);
  base = NULL;

  return 0;
}

