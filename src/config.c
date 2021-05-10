
#include <config.h>
#include <log.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

// Configuration values
char * private_key_file;
char * certificate_file;
char * certificate_hostname;

char * user;
char * group;

char * bind_address;
uint16_t bind_port;

char * root_directory;
char * lua_main;

int lua_error_responses;

// Configuration defaults
const char default_user[] = "gemini-data";
const char default_group[] = "gemini-data";

const uint16_t default_bind_port = 1965;

const char default_lua_main[] = "main.lua";

const int default_lua_error_responses = 0;

static int is_whitespace(uint_fast32_t c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static char * parse_key_value(const char * line, const char * key) {
  char * colon_loc;
  char * read_ptr;

  if(strncmp(line, key, strlen(key)) == 0) {
    colon_loc = strchr(line, ':');
    if(colon_loc) {
      for(read_ptr = colon_loc + 1 ; *read_ptr ; ++read_ptr) {
        if(!is_whitespace(*read_ptr)) {
          return read_ptr;
        }
      }
      return read_ptr;
    }
  }

  return NULL;
}

static void set_config_str(char ** var, const char * value) {
  size_t size = strlen(value);
  if(*var) { free(*var); }
  if(size) {
    *var = (char *)malloc(size + 1);
    memcpy(*var, value, size);
    (*var)[size] = '\x00';
  } else {
    *var = NULL;
  }
}

void cfg_init(const char * file) {
  ssize_t line_size = 0;
  char * linebuf = NULL;
  size_t linebuf_size = 0;

  // Configure defaults
  private_key_file = NULL;
  certificate_file = NULL;
  certificate_hostname = NULL;

  set_config_str(&user, default_user);
  set_config_str(&group, default_group);

  bind_address = NULL;
  bind_port = default_bind_port;

  set_config_str(&lua_main, default_lua_main);

  lua_error_responses = default_lua_error_responses;

  // Overwrite based on config file
  log_info("Reading configuration from %s", file);

  FILE * fp = fopen(file, "r");
  if(!fp) {
    log_error("Failed to open %s for reading", file);
    exit(1);
  }

  while((line_size = getline(&linebuf, &linebuf_size, fp)) != -1) {
    // XXX: Remove newline
    assert(line_size > 0);
    linebuf[line_size - 1] = '\x00';

    const char * value;
    if((value = parse_key_value(linebuf, "private_key_file"))) {
      if(strlen(value) == 0) {
        log_error("<private_key_file> may not be null");
        exit(1);
      }
      set_config_str(&private_key_file, value);
    }

    if((value = parse_key_value(linebuf, "certificate_file"))) {
      if(strlen(value) == 0) {
        log_error("<certificate_file> may not be null");
        exit(1);
      }
      set_config_str(&certificate_file, value);
    }

    if((value = parse_key_value(linebuf, "certificate_hostname"))) {
      if(strlen(value) == 0) {
        log_error("<certificate_hostname> may not be null");
        exit(1);
      }
      set_config_str(&certificate_hostname, value);
    }

    if((value = parse_key_value(linebuf, "user"))) {
      if(strlen(value) == 0) {
        log_error("<user> may not be null");
        exit(1);
      }
      set_config_str(&user, value);
    }

    if((value = parse_key_value(linebuf, "group"))) {
      if(strlen(value) == 0) {
        log_error("<group> may not be null");
        exit(1);
      }
      set_config_str(&group, value);
    }

    if((value = parse_key_value(linebuf, "bind_address"))) {
      set_config_str(&bind_address, value);
    }

    if((value = parse_key_value(linebuf, "bind_port"))) {
      if(strlen(value) == 0) {
        log_error("<bind_port> may not be null");
        exit(1);
      }
      long int value_int = strtol(value, NULL, 10);
      if(value_int <= 0 || value_int > UINT16_MAX) {
        log_error("Invalid value '%s' for <bind_port>", value);
        exit(1);
      }
      bind_port = value_int;
    }

    if((value = parse_key_value(linebuf, "root_directory"))) {
      if(strlen(value) == 0) {
        log_error("<root_directory> may not be null");
        exit(1);
      }
      set_config_str(&root_directory, value);
    }

    if((value = parse_key_value(linebuf, "lua_main"))) {
      if(strlen(value) == 0) {
        log_error("<lua_main> may not be null");
        exit(1);
      }
      set_config_str(&lua_main, value);
    }

    if((value = parse_key_value(linebuf, "lua_error_responses"))) {
      if(strlen(value) == 0) {
        log_error("<lua_error_responses> may not be null");
        exit(1);
      }
      if(strcmp(value, "true") == 0) {
        lua_error_responses = 1;
      } else if(strcmp(value, "false") == 0) {
        lua_error_responses = 0;
      } else {
        log_error("Invalid value '%s' for <lua_error_responses>", value);
        exit(1);
      }
    }
  }

  free(linebuf);
  linebuf = NULL;
  linebuf_size = 0;

  fclose(fp);
  fp = NULL;
}

void cfg_deinit(void) {
  free(private_key_file);
  private_key_file = NULL;

  free(certificate_file);
  certificate_file = NULL;

  free(certificate_hostname);
  certificate_hostname = NULL;

  free(user);
  user = NULL;

  free(group);
  group = NULL;

  free(bind_address);
  bind_address = NULL;

  bind_port = 0;

  free(root_directory);
  root_directory = NULL;

  free(lua_main);
  lua_main = NULL;

  lua_error_responses = 0;
}

const char * cfg_private_key_file(void) {
  return private_key_file;
}

const char * cfg_certificate_file(void) {
  return certificate_file;
}

const char * cfg_certificate_hostname(void) {
  return certificate_hostname;
}

const char * cfg_user(void) {
  return user;
}

const char * cfg_group(void) {
  return group;
}

const char * cfg_bind_address(void) {
  return bind_address;
}

uint16_t cfg_bind_port(void) {
  return bind_port;
}

const char * cfg_root_directory(void) {
  return root_directory;
}

const char * cfg_lua_main(void) {
  return lua_main;
}

const int cfg_lua_error_responses(void) {
  return lua_error_responses;
}

