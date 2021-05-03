#ifndef SCRIPT_H
#define SCRIPT_H

#include <event2/buffer.h>
#include <event2/event.h>

typedef struct script_session script_session;

void new_session(const char * uri);

#endif
