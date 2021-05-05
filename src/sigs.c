
#include <sigs.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static struct event * sigint_event;

static struct event * add_new_signal(struct event_base * base, int signal, event_callback_fn cb, void * ud) {
  // Listen for sigint with a signal event
  struct event * signal_event = evsignal_new(base, signal, cb, ud);

  if(signal_event) {
    if(event_add(signal_event, NULL) == 0) {
      return signal_event;
    } else {
      fprintf(stderr, "event_add() failed!\n");
    }

    event_free(signal_event);
    signal_event = NULL;
  } else {
    fprintf(stderr, "evsignal_new() failed!\n");
  }

  return NULL;
}

static void sigint_handler(evutil_socket_t sig, short events, void * user_data) {
  struct event_base * base = user_data;
  struct timeval delay = { 0, 0 };

  printf("\nCaught SIGINT, terminating\n");

  event_base_loopexit(base, &delay);
}

void sigs_init(struct event_base * base) {
  sigint_event = add_new_signal(base, SIGINT, sigint_handler, (void *)base);
  if(!sigint_event) { exit(1); }
}

void sigs_deinit() {
  event_free(sigint_event);
  sigint_event = NULL;
}

