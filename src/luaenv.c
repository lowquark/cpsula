
#include <config.h>
#include <log.h>
#include <luaenv.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct luaenv_context {
  // Lua environment
  lua_State * L;

  // Linked list of request objects
  luaenv_request * handlers;

  // Either LUA_REFNIL or a reference to the request handler function
  int handler_fn_ref;
};

struct luaenv_request {
  // Pointer to parent context
  struct luaenv_context * env;

  // Pointer to next request object
  struct luaenv_request * next;

  // Lua coroutine
  int thread_ref;

  // Either LUA_REFNIL or a reference to a string containing the most recent chunk of response data
  int result_ref;
};

static const char * err_header_42_lua_error = "42 Lua error\r\n";

// Wrapper around lua_pcall for debug.traceback
static int pcall_debug_traceback(lua_State * L, int narg, int nret) {
  int rval;
  assert(L);
  assert(narg >= 0);
  assert(nret >= 0);
  // Push debug.traceback
  lua_getglobal(L, "debug");
  lua_getfield(L, -1, "traceback");
  lua_remove(L, -2);
  // Place debug.traceback below existing function + args
  lua_insert(L, -2-narg);
  // Call function + args using debug.traceback as error handler
  rval = lua_pcall(L, narg, nret, -2-narg);
  // Remove debug.traceback
  lua_remove(L, -1-nret);
  return rval;
}

// Calls debug.traceback and replaces the error object on the top of the stack
static void filter_debug_traceback(lua_State * L) {
  assert(L);
  assert(lua_gettop(L) > 0);
  // Push debug.traceback
  lua_getglobal(L, "debug");
  lua_getfield(L, -1, "traceback");
  lua_remove(L, -2);
  // Place debug.traceback below existing error object
  lua_insert(L, -2);
  // Call debug.traceback on error object
  lua_call(L, 1, 1);
  // Error object left on top of stack
}

static void set_ref(int * ref_dst, lua_State * L) {
  assert(lua_gettop(L) > 0);
  luaL_unref(L, LUA_REGISTRYINDEX, *ref_dst);
  *ref_dst = luaL_ref(L, LUA_REGISTRYINDEX);
}
static void unset_ref(int * ref_dst, lua_State * L) {
  luaL_unref(L, LUA_REGISTRYINDEX, *ref_dst);
  *ref_dst = LUA_REFNIL;
}
static void push_ref(int ref_dst, lua_State * L) {
  lua_rawgeti(L, LUA_REGISTRYINDEX, ref_dst);
}

// Placeholder request handler for error reporting
static int error_request_handler(lua_State * L) {
  if(cfg_lua_error_responses()) {
    lua_pushfstring(
        L,
        "20 text/gemini\r\n"
        "# !! Lua error !!\n\n"
        "Server failed to initialize\n\n"
        "%s",
        lua_tostring(L, lua_upvalueindex(1)), 5);
  } else {
    lua_pushstring(L, err_header_42_lua_error);
  }
  return 1;
}

static void resume_request_thread(struct luaenv_request * req,
                                  lua_State * thread,
                                  int nargs,
                                  _Bool initial) {
  int return_type;
  int rval, nresults;

  rval = lua_resume(thread, NULL, nargs, &nresults);

  /*
  log_info("nresults (execute, post-resume): %d", nresults);
  log_info("gettop (execute, post-resume): %d", lua_gettop(thread));

  for(int i = 1 ; i <= lua_gettop(thread) ; ++i) {
    int type = lua_type(thread, i);
    log_info("[%d] : %s", i, lua_typename(thread, type));
    if(type == LUA_TSTRING) {
      log_info("  -> '%s'", lua_tostring(thread, i));
    }
  }
  */

  if(rval == LUA_OK || rval == LUA_YIELD) {
    // Only one return value considered
    lua_settop(thread, 1);

    // Switch on return value type
    return_type = lua_type(thread, 1);

    if(return_type == LUA_TSTRING || return_type == LUA_TNIL) {
      // Set result to return value, pop
      set_ref(&req->result_ref, thread);

      if(rval == LUA_OK) {
        // Thread over, clear registry reference
        unset_ref(&req->thread_ref, thread);
        thread = NULL;
      }
    } else {
      if(initial) {
        if(cfg_lua_error_responses()) {
          lua_pushfstring(
              thread,
              "20 text/gemini\r\n"
              "# !! Lua error !!\n\n"
              "Bad return value from request handler (expected string, function, or nil, got %s)",
              lua_typename(thread, return_type));
        } else {
          lua_pushstring(thread, err_header_42_lua_error);
        }

        // Error result
        set_ref(&req->result_ref, thread);
      } else {
        unset_ref(&req->result_ref, thread);
      }

      log_warning("Bad return value from request handler (expected string or nil, got %s)",
                  lua_typename(thread, return_type));

      // Thread over, clear registry reference
      unset_ref(&req->thread_ref, thread);
      thread = NULL;
    }
  } else {
    filter_debug_traceback(thread);

    if(initial) {
      if(cfg_lua_error_responses()) {
        lua_pushfstring(
            thread,
            "20 text/gemini\r\n"
            "# !! Lua error !!\n\n"
            "Error during request handler\n\n"
            "%s",
            lua_tostring(thread, -1));
      } else {
        lua_pushstring(thread, err_header_42_lua_error);
      }

      // Error result
      set_ref(&req->result_ref, thread);
    } else {
      unset_ref(&req->result_ref, thread);
    }

    log_warning("Error during request handler");
    log_info("%s", lua_tostring(thread, -1));

    // Thread over, clear registry reference
    unset_ref(&req->thread_ref, thread);
    thread = NULL;
  }
}

luaenv_context * luaenv_context_new() {
  struct luaenv_context * env;
  env = calloc(sizeof(struct luaenv_context), 1);
  env->handler_fn_ref = LUA_REFNIL;
  return env;
}

void luaenv_context_free(luaenv_context * env) {
  if(env) {
    // Free all pending requests
    struct luaenv_request * req = env->handlers;
    while(req) {
      struct luaenv_request * next = req->next;
      luaenv_request_free(req);
      req = next;
    }
    // Free all Lua data
    if(env->L) {
      lua_close(env->L);
    }
    memset(env, 0, sizeof(*env));
    free(env);
  }
}

int luaenv_context_init(luaenv_context * env, const char * main_filepath) {
  assert(env);
  assert(main_filepath);

  if(env->L) {
    lua_close(env->L);
  }
  env->L = luaL_newstate();

  luaL_openlibs(env->L);

  if(luaL_loadfile(env->L, main_filepath) == LUA_OK) {
    if(pcall_debug_traceback(env->L, 0, 1) == LUA_OK) {
      // Set handler to return value
      set_ref(&env->handler_fn_ref, env->L);
      assert(lua_gettop(env->L) == 0);
      return 0;
    } else {
      // Notify error
      log_warning("Error in %s", main_filepath);
      log_info("%s", lua_tostring(env->L, -1));
      // Set handler to error handler, consuming error string as an upvalue
      lua_pushcclosure(env->L, error_request_handler, 1);
      set_ref(&env->handler_fn_ref, env->L);
    }
  } else {
    // Notify error
    log_warning("Failed to load %s", main_filepath);
    log_info("%s", lua_tostring(env->L, -1));
    // Set handler to error handler, consuming error string as an upvalue
    lua_pushcclosure(env->L, error_request_handler, 1);
    set_ref(&env->handler_fn_ref, env->L);
  }

  assert(lua_gettop(env->L) == 0);
  return 1;
}

luaenv_request * luaenv_request_new(luaenv_context * env) {
  struct luaenv_request * req;

  assert(env);

  req = calloc(sizeof(struct luaenv_request), 1);
  req->env = env;
  req->next = env->handlers;
  env->handlers = req;
  req->result_ref = LUA_REFNIL;
  req->thread_ref = LUA_REFNIL;

  return req;
}

void luaenv_request_free(luaenv_request * req) {
  struct luaenv_context * env;

  if(req) {
    env = req->env;

    assert(env);

    // Unref Lua references
    if(env->L) {
      unset_ref(&req->result_ref, env->L);
      unset_ref(&req->thread_ref, env->L);
    }

    // Remove from linked list
    luaenv_request ** slot = &env->handlers;
    while(*slot && *slot != req) {
      slot = &(*slot)->next;
    }
    assert(*slot);
    *slot = req->next;

    // Clear and free
    memset(req, 0, sizeof(*req));
    free(req);
  }
}

void luaenv_request_execute(luaenv_request * req,
                            const char * authority,
                            const char * resource,
                            const char * fingerprint,
                            time_t expiry) {
  struct luaenv_context * env;

  assert(req);
  assert(authority);

  env = req->env;
  assert(env);

  if(!env->L) {
    // luaenv_context_init was never called
    return;
  }
  if(req->thread_ref != LUA_REFNIL) {
    // Chunk callback set, i.e. suspended; luaenv_request_execute must called instead
    return;
  }

  // Stack sanity check
  assert(lua_gettop(env->L) == 0);

  // Push new thread and keep in registry
  lua_State * thread = lua_newthread(env->L);
  set_ref(&req->thread_ref, env->L);

  // Call handler function on new thread
  push_ref(env->handler_fn_ref, thread);

  lua_pushstring(thread, authority);
  if(resource) {
    lua_pushstring(thread, resource);
  } else {
    lua_pushnil(thread);
  }
  if(fingerprint) {
    lua_pushstring(thread, fingerprint);
    lua_pushinteger(thread, expiry);
  } else {
    lua_pushnil(thread);
    lua_pushnil(thread);
  }

  resume_request_thread(req, thread, 4, 1);

  // Stack sanity check
  assert(lua_gettop(env->L) == 0);
}

void luaenv_request_continue(luaenv_request * req) {
  struct luaenv_context * env;

  assert(req);

  env = req->env;
  assert(env);

  if(!env->L) {
    // luaenv_context_init was never called
    return;
  }
  if(req->thread_ref == LUA_REFNIL) {
    // No chunk callback, i.e. not suspended; luaenv_request_execute must called instead
    return;
  }

  // Stack sanity check
  assert(lua_gettop(env->L) == 0);

  // Retrieve thread from registry
  push_ref(req->thread_ref, env->L);
  lua_State * thread = lua_tothread(env->L, 1);
  lua_pop(env->L, 1);

  resume_request_thread(req, thread, 0, 0);

  // Stack sanity check
  assert(lua_gettop(env->L) == 0);
}

int luaenv_request_status(luaenv_request * req) {
  if(req->thread_ref == LUA_REFNIL) {
    return LUAENV_REQUEST_DEAD;
  } else {
    return LUAENV_REQUEST_SUSPENDED;
  }
}

const char * luaenv_request_result(const luaenv_request * req, size_t * length) {
  struct luaenv_context * env;
  const char * result_str;

  assert(req);
  assert(length);

  env = req->env;
  assert(env);

  *length = 0;

  if(!env->L) {
    // luaenv_context_init was never called
    return NULL;
  }

  // Stack sanity check
  assert(lua_gettop(env->L) == 0);

  if(req->result_ref != LUA_REFNIL) {
    // Push result string
    push_ref(req->result_ref, req->env->L);
    // Because the string is referenced by the registry, we should be able to count on it not being
    // garbage collected when it's removed from the stack
    result_str = lua_tolstring(env->L, 1, length);
    // Pop result string
    lua_pop(env->L, 1);

    // Stack sanity check
    assert(lua_gettop(env->L) == 0);

    return result_str;
  }

  return NULL;
}

#ifdef TEST

#include <btest.h>

int cfg_lua_error_responses() {
  return 0;
}

static const char * dummy_response = "dummy response";

void test_request(const char * main_file) {
  const char * data;
  size_t data_size;
  int rval;

  fprintf(stderr, "> test_request(\"%s\")\n", main_file);

  luaenv_context * env = luaenv_context_new();

  rval = luaenv_context_init(env, main_file);
  assert(rval == 0);

  // Create a request and execute
  luaenv_request * req = luaenv_request_new(env);

  luaenv_request_execute(req, "localhost", "/", NULL, 0);

  // Should not yield
  assert(luaenv_request_status(req) == LUAENV_REQUEST_DEAD);

  // Should return the dummy response
  data = luaenv_request_result(req, &data_size);
  assert(data);
  assert(data_size == strlen(dummy_response));
  assert(strcmp(data, dummy_response) == 0);

  // A continue should not cause problems
  luaenv_request_continue(req);

  luaenv_request_free(req);
  req = NULL;
  luaenv_context_free(env);
  env = NULL;
}

void test_request_resume(const char * main_file) {
  const char * data;
  size_t data_size;
  int rval;

  fprintf(stderr, "> test_request(\"%s\")\n", main_file);

  luaenv_context * env = luaenv_context_new();

  rval = luaenv_context_init(env, main_file);
  BTEST_INT_EQ(rval, 0);

  // Create a request and execute
  luaenv_request * req = luaenv_request_new(env);

  luaenv_request_execute(req, "localhost", "/", NULL, 0);

  // Should yield
  BTEST_INT_EQ(luaenv_request_status(req), LUAENV_REQUEST_SUSPENDED);

  // Should return the dummy response
  data = luaenv_request_result(req, &data_size);
  BTEST_STR_EQ(data, dummy_response);
  BTEST_UINT_EQ(data_size, strlen(dummy_response));

  // A continue should succeed
  luaenv_request_continue(req);

  // Should not yield
  BTEST_INT_EQ(luaenv_request_status(req), LUAENV_REQUEST_DEAD);

  // Should return the dummy response
  data = luaenv_request_result(req, &data_size);
  BTEST_STR_EQ(data, dummy_response);
  BTEST_UINT_EQ(data_size, strlen(dummy_response));

  // A continue should not cause problems
  luaenv_request_continue(req);

  luaenv_request_free(req);
  req = NULL;
  luaenv_context_free(env);
  env = NULL;
}

void test_request_error(const char * main_file, int init_rval_expected) {
  int rval;

  fprintf(stderr, "> test_request_error(\"%s\", %d)\n", main_file, init_rval_expected);

  luaenv_context * env = luaenv_context_new();

  rval = luaenv_context_init(env, main_file);
  BTEST_INT_EQ(rval, init_rval_expected);

  // Create a request regardless of initialization error
  luaenv_request * req = luaenv_request_new(env);

  luaenv_request_execute(req, "localhost", "/", NULL, 0);

  // Should not yield
  BTEST_INT_EQ(luaenv_request_status(req), LUAENV_REQUEST_DEAD);

  // Should return an error response that depends on cfg_lua_error_responses()
  const char * data;
  size_t data_size;
  data = luaenv_request_result(req, &data_size);

  BTEST_STR_EQ(data, err_header_42_lua_error);
  BTEST_UINT_EQ(data_size, strlen(err_header_42_lua_error));

  luaenv_request_free(req);
  req = NULL;
  luaenv_context_free(env);
  env = NULL;
}

void test_request_resume_error(const char * main_file) {
  const char * data;
  size_t data_size;
  int rval;

  fprintf(stderr, "> test_request_resume_error(\"%s\")\n", main_file);

  luaenv_context * env = luaenv_context_new();

  rval = luaenv_context_init(env, main_file);
  BTEST_INT_EQ(rval, 0);

  // Create a request and execute
  luaenv_request * req = luaenv_request_new(env);

  luaenv_request_execute(req, "localhost", "/", NULL, 0);

  // Should yield
  BTEST_INT_EQ(luaenv_request_status(req), LUAENV_REQUEST_SUSPENDED);

  // Should return the dummy response
  data = luaenv_request_result(req, &data_size);
  BTEST_STR_EQ(data, dummy_response);
  BTEST_UINT_EQ(data_size, strlen(dummy_response));

  // Continue our (re)quest
  luaenv_request_continue(req);

  // Should not yield
  BTEST_INT_EQ(luaenv_request_status(req), LUAENV_REQUEST_DEAD);

  // Should not provide an error response
  data = luaenv_request_result(req, &data_size);
  BTEST_STR_EQ(data, NULL);
  BTEST_UINT_EQ(data_size, 0);

  luaenv_request_free(req);
  req = NULL;
  luaenv_context_free(env);
  env = NULL;
}

int main(int argc, char ** argv) {
  log_init(stderr);

  test_request("request.lua");
  test_request_resume("request-resume.lua");

  test_request_error("no-file.lua", 1);
  test_request_error("syntax-error.lua", 1);
  test_request_error("error-in-main.lua", 1);
  test_request_error("handler-not-callable.lua", 0);
  test_request_error("error-in-handler.lua", 0);
  test_request_error("bad-return-value.lua", 0);

  test_request_resume_error("error-in-resumed-handler.lua");
  test_request_resume_error("bad-yield-value.lua");

  //test_multiple_requests();

  // TODO: Watch ref values for memory leaks?

  return 0;
}

#endif

