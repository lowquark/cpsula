
#include <log.h>
#include <script.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

const char * main_file = "main.lua";

struct scr_env {
  lua_State * L;
  scr_reqhandler * handlers;
  int handler_fn_ref;
};

struct scr_reqhandler {
  struct scr_env * env;
  struct scr_reqhandler * next;
  int result_ref;
  int chunkcb_ref;
};

int pcall_debug_traceback(lua_State * L, int narg, int nret) {
  int rval;

  assert(L);
  assert(narg >= 0);
  assert(nret >= 0);

  lua_getglobal(L, "debug");
  lua_getfield(L, -1, "traceback");
  lua_remove(L, -2);

  lua_insert(L, -2-narg);

  rval = lua_pcall(L, narg, nret, -2-narg);

  lua_remove(L, -1-nret);

  return rval;
}

scr_env * scr_env_new() {
  struct scr_env * env;

  env = calloc(sizeof(struct scr_env), 1);
  env->L = luaL_newstate();
  env->handler_fn_ref = LUA_NOREF;

  luaL_openlibs(env->L);

  if(luaL_loadfile(env->L, main_file) == LUA_OK) {
    if(pcall_debug_traceback(env->L, 0, 1) == LUA_OK) {
      // Set handler to return value
      env->handler_fn_ref = luaL_ref(env->L, LUA_REGISTRYINDEX);
    } else {
      // Notify error
      log_error("Error in %s", main_file);
      log_info("%s", lua_tostring(env->L, -1));
      lua_pop(env->L, 1);
    }
  } else {
    // Notify error
    log_error("Failed to load %s", main_file);
    log_info("%s", lua_tostring(env->L, -1));
    lua_pop(env->L, 1);
  }

  assert(lua_gettop(env->L) == 0);

  return env;
}

void scr_env_free(scr_env * env) {
  if(env) {
    lua_close(env->L);

    struct scr_reqhandler * handler = env->handlers;

    while(handler) {
      struct scr_reqhandler * next = handler->next;
      scr_reqhandler_free(handler);
      handler = next;
    }

    memset(env, 0, sizeof(*env));
    free(env);
  }
}

scr_reqhandler * scr_reqhandler_new(scr_env * env) {
  struct scr_reqhandler * handler;

  assert(env);

  handler = calloc(sizeof(struct scr_reqhandler), 1);
  handler->env = env;
  handler->next = env->handlers;
  env->handlers = handler;
  handler->result_ref = LUA_REFNIL;
  handler->chunkcb_ref = LUA_REFNIL;

  return handler;
}

void scr_reqhandler_free(scr_reqhandler * handler) {
  if(handler) {
    assert(handler->env);
    assert(handler->env->L);

    // Unref lua reference
    luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->result_ref);
    luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->chunkcb_ref);

    // Remove from environment
    scr_reqhandler ** slot = &handler->env->handlers;
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

int scr_reqhandler_status(scr_reqhandler * handler) {
  if(handler->chunkcb_ref == LUA_REFNIL) {
    return SCR_REQHANDLER_DEAD;
  } else {
    return SCR_REQHANDLER_SUSPENDED;
  }
}

const char * scr_reqhandler_result(scr_reqhandler * handler, size_t * length) {
  struct scr_env * env;
  const char * result_str;

  assert(handler);
  assert(length);

  env = handler->env;

  if(handler->result_ref != LUA_REFNIL) {
    lua_rawgeti(env->L, LUA_REGISTRYINDEX, handler->result_ref);
    result_str = lua_tolstring(env->L, -1, length);
    lua_pop(env->L, 1); // result string

    assert(lua_gettop(env->L) == 0);

    return result_str;
  }

  *length = 0;
  return NULL;
}

void scr_reqhandler_execute(scr_reqhandler * handler,
                            const char * authority,
                            const char * resource,
                            const char * fingerprint,
                            time_t expiry) {
  struct scr_env * env;
  int return_type;

  assert(handler);
  assert(handler->result_ref == LUA_REFNIL);
  assert(handler->chunkcb_ref == LUA_REFNIL);
  assert(authority);
  assert(resource);

  env = handler->env;

  assert(env);

  if(env->handler_fn_ref != LUA_NOREF) {
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
      if(return_type == LUA_TSTRING || return_type == LUA_TNUMBER) {
        // Set result to return value
        handler->result_ref = luaL_ref(env->L, LUA_REGISTRYINDEX);
      } else if(return_type == LUA_TFUNCTION) {
        // Set chunk callback to return value
        handler->chunkcb_ref = luaL_ref(env->L, LUA_REGISTRYINDEX);
        // Call the chunk callback to produce first value
        scr_reqhandler_continue(handler);
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
      log_error("Error during request handler");
      log_info("%s", lua_tostring(env->L, -1));
      lua_pop(env->L, 1); // error object
    }
  }

  assert(lua_gettop(env->L) == 0);
}

void scr_reqhandler_continue(scr_reqhandler * handler) {
  struct scr_env * env;
  int return_type;

  assert(handler);

  env = handler->env;

  assert(env);

  if(handler->chunkcb_ref != LUA_REFNIL) {
    // Push/call chunk callback
    lua_rawgeti(env->L, LUA_REGISTRYINDEX, handler->chunkcb_ref);
    if(pcall_debug_traceback(env->L, 0, 1) == LUA_OK) {
      // Switch on return value type
      return_type = lua_type(env->L, -1);
      if(return_type == LUA_TSTRING || return_type == LUA_TNUMBER) {
        // Set result to return value
        handler->result_ref = luaL_ref(env->L, LUA_REGISTRYINDEX);
      } else {
        if(return_type != LUA_TNIL) {
          log_warning(
              "Chunk callback returned value of type %s, expected string, function, or nil",
              lua_typename(env->L, return_type));
        }
        // Ignore return value
        lua_pop(env->L, 1);
        // Unset chunk callback
        luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->chunkcb_ref);
        handler->chunkcb_ref = LUA_REFNIL;
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
      luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->chunkcb_ref);
      handler->chunkcb_ref = LUA_REFNIL;
      // Unset result
      luaL_unref(handler->env->L, LUA_REGISTRYINDEX, handler->result_ref);
      handler->result_ref = LUA_REFNIL;
    }
  }

  assert(lua_gettop(env->L) == 0);
}

