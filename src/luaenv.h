#ifndef LUAENV_H
#define LUAENV_H

#include <stddef.h>
#include <time.h>

// luaenv - Lua Environment

typedef struct luaenv_context luaenv_context;
typedef struct luaenv_request luaenv_request;

// TODO: Add LUAENV_REQUEST_FRESH status for better conditioning of
// luaenv_request_execute/luaenv_request_continue
#define LUAENV_REQUEST_DEAD      0
#define LUAENV_REQUEST_SUSPENDED 1

luaenv_context * luaenv_context_new();
void luaenv_context_free(luaenv_context * env);

// Loads and runs the given Lua file, expecting it to return a request handler function. Returns 0
// on success, and nonzero in the event of failure.
int luaenv_context_init(luaenv_context * env, const char * main_filepath);

luaenv_request * luaenv_request_new(luaenv_context * env);
void luaenv_request_free(luaenv_request * handler);

// Calls the Lua environment's request handler with the given arguments. Depending on how Lua
// handles the request, it may wish to be continued later with luaenv_request_continue.
void luaenv_request_execute(luaenv_request * handler,
                            const char * authority,
                            const char * resource,
                            const char * fingerprint,
                            time_t expiry);

// Attempts to resume the request for more response data.
void luaenv_request_continue(luaenv_request * handler);

// Returns LUAENV_REQUEST_DEAD to indicate that the request has finished (with or without errors).
// Returns LUAENV_REQUEST_SUSPENDED to indicate luaenv_request_continue should be called to produce
// another chunk of data.
int luaenv_request_status(luaenv_request * handler);

// Returns a pointer to an internal buffer containing the response data last produced during
// luaenv_request_execute or luaenv_request_continue. Sets *length to the length of the response.
const char * luaenv_request_result(luaenv_request * handler, size_t * length);

#endif
