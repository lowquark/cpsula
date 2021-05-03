#ifndef SIGS_H
#define SIGS_H

#include <event2/event.h>

void sigs_init(struct event_base * base);
void sigs_deinit();

#endif
