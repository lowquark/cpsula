#ifndef SCRIPT_H
#define SCRIPT_H

#include <event2/buffer.h>
#include <event2/event.h>

typedef struct scr_env scr_env;
typedef struct scr_reqhandler scr_reqhandler;

#define SCR_REQHANDLER_DEAD      0
#define SCR_REQHANDLER_SUSPENDED 1

scr_env * scr_env_new();
void scr_env_free(scr_env * base);

scr_reqhandler * scr_reqhandler_new(scr_env * base);
void scr_reqhandler_free(scr_reqhandler * handler);

int scr_reqhandler_status(scr_reqhandler * handler);

const char * scr_reqhandler_result(scr_reqhandler * handler, size_t * length);

void scr_reqhandler_execute(scr_reqhandler * handler,
                            const char * authority,
                            const char * resource,
                            const char * fingerprint,
                            time_t expiry);

void scr_reqhandler_continue(scr_reqhandler * handler);

#endif
