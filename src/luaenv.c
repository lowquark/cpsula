
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

    struct luaenv_request * handler = env->handlers;

    while(handler) {
      struct luaenv_request * next = handler->next;
      luaenv_request_free(handler);
      handler = next;
    }

    memset(env, 0, sizeof(*env));
    free(env);
  }
}

int luaenv_context_init(luaenv_context * env, const char * main_filepath) {
  assert(env);
  assert(main_filepath);

  env->L = luaL_newstate();
  if(env->L) {
    // TODO: Consider some kind of file io sandboxing?
    luaL_openlibs(env->L);

    if(luaL_loadfile(env->L, main_filepath) == LUA_OK) {
      if(pcall_debug_traceback(env->L, 0, 1) == LUA_OK) {
        // Set handler to return value
        env->handler_fn_ref = luaL_ref(env->L, LUA_REGISTRYINDEX);

        assert(lua_gettop(env->L) == 0);
        return 0;
      } else {
        // Notify error
        log_error("Error in %s", main_filepath);
        log_info("%s", lua_tostring(env->L, -1));
        lua_pop(env->L, 1);
      }
    } else {
      // Notify error
      log_error("Failed to load %s", main_filepath);
      log_info("%s", lua_tostring(env->L, -1));
      lua_pop(env->L, 1);
    }
  } else {
    log_error("luaL_newstate() failed");
  }

  lua_close(env->L);
  env->L = NULL;

  assert(lua_gettop(env->L) == 0);
  return 1;
}

luaenv_request * luaenv_request_new(luaenv_context * env) {
  struct luaenv_request * handler;

  assert(env);

  handler = calloc(sizeof(struct luaenv_request), 1);
  handler->env = env;
  handler->next = env->handlers;
  env->handlers = handler;
  handler->result_ref = LUA_REFNIL;
  handler->chunk_cb_ref = LUA_REFNIL;

  return handler;
}

void luaenv_request_free(luaenv_request * handler) {
  if(handler) {
    assert(handler->env);
    if(handler->env->L) {
      // Unref Lua references
      luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->result_ref);
      handler->result_ref = LUA_REFNIL;

      luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->chunk_cb_ref);
      handler->chunk_cb_ref = LUA_REFNIL;
    }

    // Remove from linked list
    luaenv_request ** slot = &handler->env->handlers;
    while(*slot && *slot != handler) {
      slot = &(*slot)->next;
    }
    assert(*slot);
    *slot = handler->next;

    // Clear and free
    memset(handler, 0, sizeof(*handler));
    free(handler);
  }
}

void luaenv_request_execute(luaenv_request * handler,
                            const char * authority,
                            const char * resource,
                            const char * fingerprint,
                            time_t expiry) {
  struct luaenv_context * env;
  int return_type;

  assert(handler);
  assert(handler->result_ref == LUA_REFNIL);
  assert(handler->chunk_cb_ref == LUA_REFNIL);
  assert(authority);
  assert(resource);

  env = handler->env;

  assert(env);

  if(!env->L) {
    log_warning("No Lua state; can't execute request");
    return;
  }

  if(env->handler_fn_ref != LUA_REFNIL) {
    // Push/call handler
    lua_rawgeti(env->L, LUA_REGISTRYINDEX, env->handler_fn_ref);

    lua_pushstring(env->L, authority);
    lua_pushstring(env->L, resource);
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
        handler->result_ref = luaL_ref(env->L, LUA_REGISTRYINDEX);
      } else if(return_type == LUA_TFUNCTION) {
        // Set chunk callback to return value
        handler->chunk_cb_ref = luaL_ref(env->L, LUA_REGISTRYINDEX);
        // Call the chunk callback to produce first value
        luaenv_request_continue(handler);
      } else {
        if(return_type != LUA_TNIL) {
          log_warning(
              "Request handler returned value of type %s, expected string, function, or nil",
              lua_typename(env->L, return_type));
        }
        // Ignore return value
        lua_pop(env->L, 1);
      }
    } else {
      // Notify error
      log_error("Error during request handler");
      log_info("%s", lua_tostring(env->L, -1));
      lua_pop(env->L, 1);
    }
  }

  assert(lua_gettop(env->L) == 0);
}

void luaenv_request_continue(luaenv_request * handler) {
  struct luaenv_context * env;
  int return_type;

  assert(handler);

  env = handler->env;

  assert(env);

  if(!env->L) {
    log_warning("No Lua state; can't continue request");
    return;
  }

  if(handler->chunk_cb_ref != LUA_REFNIL) {
    // Push/call chunk callback
    lua_rawgeti(env->L, LUA_REGISTRYINDEX, handler->chunk_cb_ref);
    if(pcall_debug_traceback(env->L, 0, 1) == LUA_OK) {
      // Switch on return value type
      return_type = lua_type(env->L, -1);
      if(return_type == LUA_TSTRING) {
        // Set result to return value
        handler->result_ref = luaL_ref(env->L, LUA_REGISTRYINDEX);
      } else {
        if(return_type != LUA_TNIL) {
          log_warning(
              "Chunk callback returned value of type %s, expected string or nil",
              lua_typename(env->L, return_type));
        }
        // Ignore return value
        lua_pop(env->L, 1);
        // Unset chunk callback
        luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->chunk_cb_ref);
        handler->chunk_cb_ref = LUA_REFNIL;
        // Unset result
        luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->result_ref);
        handler->result_ref = LUA_REFNIL;
      }
    } else {
      // Notify error
      log_error("Error during chunk callback");
      log_info("%s", lua_tostring(env->L, -1));
      lua_pop(env->L, 1);
      // Unset chunk callback
      luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->chunk_cb_ref);
      handler->chunk_cb_ref = LUA_REFNIL;
      // Unset result
      luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->result_ref);
      handler->result_ref = LUA_REFNIL;
    }
  }

  assert(lua_gettop(env->L) == 0);
}

int luaenv_request_status(luaenv_request * handler) {
  if(handler->chunk_cb_ref == LUA_REFNIL) {
    return LUAENV_REQUEST_DEAD;
  } else {
    return LUAENV_REQUEST_SUSPENDED;
  }
}

const char * luaenv_request_result(luaenv_request * handler, size_t * length) {
  struct luaenv_context * env;
  const char * result_str;

  assert(handler);
  assert(length);

  env = handler->env;

  if(env->L && handler->result_ref != LUA_REFNIL) {
    // Push result string
    lua_rawgeti(env->L, LUA_REGISTRYINDEX, handler->result_ref);
    // Because the string is referenced by the registry, we should be able to count on it not being
    // garbage collected when it's removed from the stack here
    result_str = lua_tolstring(env->L, -1, length);
    // Pop result string
    lua_pop(env->L, 1);

    assert(lua_gettop(env->L) == 0);

    return result_str;
  }

  *length = 0;
  return NULL;
}

