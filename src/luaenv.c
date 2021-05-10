
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

  // Either LUA_REFNIL or a reference to a string containing the most recent chunk of response data
  int result_ref;

  // Either LUA_REFNIL or a reference to this request's chunk callback function
  int chunk_cb_ref;
};

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

// Pops value (bad return value) from the stack, sets request result value
static void handle_rh_bad_rval(struct luaenv_request * req, int return_type) {
  log_warning(
      "Bad return value from request handler (expected string, function, or nil, got %s)",
      lua_typename(req->env->L, return_type));

  if(cfg_lua_error_responses()) {
    lua_pushfstring(
        req->env->L,
        "20 text/gemini\r\n"
        "# !! Lua error !!\n\n"
        "Bad return value from request handler (expected string, function, or nil, got %s)",
        lua_typename(req->env->L, return_type));
  } else {
    lua_pushliteral(req->env->L, "42 Lua error\r\n");
  }

  set_ref(&req->result_ref, req->env->L);

  lua_pop(req->env->L, 1);
}

// Pops value (traceback / error object) from the stack, sets request result value
static void handle_rh_err(struct luaenv_request * req) {
  log_warning("Error during request handler");
  log_info("%s", lua_tostring(req->env->L, -1));

  if(cfg_lua_error_responses()) {
    lua_pushfstring(
        req->env->L,
        "20 text/gemini\r\n"
        "# !! Lua error !!\n\n"
        "Error during request handler\n\n"
        "%s",
        lua_tostring(req->env->L, -1));
  } else {
    lua_pushliteral(req->env->L, "42 Internal server error\r\n");
  }

  set_ref(&req->result_ref, req->env->L);

  lua_pop(req->env->L, 1);
}

// Pops value (bad return value) from the stack, unsets request result value, chunk callback
static void handle_ccb_bad_rval(struct luaenv_request * req, int return_type) {
  log_warning(
      "Bad return value from chunk callback (expected string or nil, got %s)",
      lua_typename(req->env->L, return_type));

  unset_ref(&req->chunk_cb_ref, req->env->L);
  unset_ref(&req->result_ref, req->env->L);

  lua_pop(req->env->L, 1);
}

// Pops value (traceback / error object) from the stack, unsets request result value, chunk callback
static void handle_ccb_err(struct luaenv_request * req) {
  log_warning("Error during chunk callback");
  log_info("%s", lua_tostring(req->env->L, -1));

  unset_ref(&req->chunk_cb_ref, req->env->L);
  unset_ref(&req->result_ref, req->env->L);

  lua_pop(req->env->L, 1);
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
    lua_pushliteral(L, "42 Internal server error\r\n");
  }
  return 1;
}

luaenv_context * luaenv_context_new() {
  struct luaenv_context * env;

  env = calloc(sizeof(struct luaenv_context), 1);
  env->handler_fn_ref = LUA_REFNIL;
  return env;
}

void luaenv_context_free(luaenv_context * env) {
  if(env) {
    if(env->L) {
      lua_close(env->L);
    }

    struct luaenv_request * req = env->handlers;

    while(req) {
      struct luaenv_request * next = req->next;
      luaenv_request_free(req);
      req = next;
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

  assert(env->L);

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
  req->chunk_cb_ref = LUA_REFNIL;

  return req;
}

void luaenv_request_free(luaenv_request * req) {
  if(req) {
    assert(req->env);

    // Unref Lua references
    if(req->env->L) {
      unset_ref(&req->result_ref, req->env->L);
      unset_ref(&req->chunk_cb_ref, req->env->L);
    }

    // Remove from linked list
    luaenv_request ** slot = &req->env->handlers;
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
  int return_type;

  assert(req);
  assert(authority);

  env = req->env;
  assert(env);

  if(!env->L) {
    // luaenv_context_init was never called
    return;
  }
  if(req->chunk_cb_ref != LUA_REFNIL) {
    // Chunk callback set, i.e. suspended; luaenv_request_execute must called instead
    return;
  }

  // Handler function should be set upon init
  assert(env->handler_fn_ref != LUA_REFNIL);

  // Stack sanity check
  assert(lua_gettop(env->L) == 0);

  // Push/call handler
  push_ref(env->handler_fn_ref, env->L);

  lua_pushstring(env->L, authority);
  if(resource) {
    lua_pushstring(env->L, resource);
  } else {
    lua_pushnil(env->L);
  }
  if(fingerprint) {
    lua_pushstring(env->L, fingerprint);
    lua_pushinteger(env->L, expiry);
  } else {
    lua_pushnil(env->L);
    lua_pushnil(env->L);
  }

  if(pcall_debug_traceback(env->L, 4, 1) == LUA_OK) {
    // Switch on return value type
    return_type = lua_type(env->L, -1);
    if(return_type == LUA_TSTRING) {
      // Set result to return value
      set_ref(&req->result_ref, env->L);
    } else if(return_type == LUA_TFUNCTION) {
      // Set chunk callback to return value
      set_ref(&req->chunk_cb_ref, env->L);
      // Call the chunk callback to produce first value
      luaenv_request_continue(req);
    } else if(return_type == LUA_TNIL) {
      // Ignore return value
      lua_pop(env->L, 1);
    } else {
      handle_rh_bad_rval(req, return_type);
    }
  } else {
    handle_rh_err(req);
  }

  // Stack sanity check
  assert(lua_gettop(env->L) == 0);
}

void luaenv_request_continue(luaenv_request * req) {
  struct luaenv_context * env;
  int return_type;

  assert(req);

  env = req->env;
  assert(env);

  if(!env->L) {
    // luaenv_context_init was never called
    return;
  }
  if(req->chunk_cb_ref == LUA_REFNIL) {
    // No chunk callback, i.e. not suspended; luaenv_request_execute must called instead
    return;
  }

  // Stack sanity check
  assert(lua_gettop(env->L) == 0);

  // Push/call chunk callback
  push_ref(req->chunk_cb_ref, env->L);
  if(pcall_debug_traceback(env->L, 0, 1) == LUA_OK) {
    // Switch on return value type
    return_type = lua_type(env->L, -1);
    if(return_type == LUA_TSTRING) {
      // Set result to return value
      set_ref(&req->result_ref, env->L);
    } else if(return_type == LUA_TNIL) {
      // Ignore return value
      lua_pop(env->L, 1);
      unset_ref(&req->result_ref, req->env->L);
    } else {
      handle_ccb_bad_rval(req, return_type);
    }
  } else {
    handle_ccb_err(req);
  }

  // Stack sanity check
  assert(lua_gettop(env->L) == 0);
}

int luaenv_request_status(luaenv_request * req) {
  if(req->chunk_cb_ref == LUA_REFNIL) {
    return LUAENV_REQUEST_DEAD;
  } else {
    return LUAENV_REQUEST_SUSPENDED;
  }
}

const char * luaenv_request_result(luaenv_request * req, size_t * length) {
  struct luaenv_context * env;
  const char * result_str;

  assert(req);
  assert(length);

  env = req->env;
  assert(env);

  if(!env->L) {
    // luaenv_context_init was never called
    *length = 0;
    return NULL;
  }

  // Stack sanity check
  assert(lua_gettop(env->L) == 0);

  if(req->result_ref != LUA_REFNIL) {
    // Push result string
    push_ref(req->result_ref, req->env->L);
    // Because the string is referenced by the registry, we should be able to count on it not being
    // garbage collected when it's removed from the stack
    result_str = lua_tolstring(env->L, -1, length);
    // Pop result string
    lua_pop(env->L, 1);

    // Stack sanity check
    assert(lua_gettop(env->L) == 0);

    return result_str;
  }

  *length = 0;
  return NULL;
}

