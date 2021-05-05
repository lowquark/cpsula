#ifndef LUAENV_H
#define LUAENV_H

#include <stddef.h>
#include <time.h>

// luaenv - Lua Environment

typedef struct luaenv_context luaenv_context;
typedef struct luaenv_request luaenv_request;

#define LUAENV_REQUEST_DEAD      0
#define LUAENV_REQUEST_SUSPENDED 1

luaenv_context * luaenv_context_new  ();
void             luaenv_context_free (luaenv_context * base);

luaenv_request * luaenv_request_new  (luaenv_context * base);
void             luaenv_request_free (luaenv_request * handler);

void luaenv_request_execute  (luaenv_request * handler,
                              const char * authority,
                              const char * resource,
                              const char * fingerprint,
                              time_t expiry);

void luaenv_request_continue (luaenv_request * handler);

int          luaenv_request_status (luaenv_request * handler);
const char * luaenv_request_result (luaenv_request * handler, size_t * length);

#endif
