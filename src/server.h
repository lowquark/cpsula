#ifndef RBVDIN_H
#define RBVDIN_H

#include <event2/event.h>

void server_init(struct event_base * base);
void server_deinit();

#endif
