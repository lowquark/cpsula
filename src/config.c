
#include <config.h>
#include <log.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

char * parse_key_value(const char * line, const char * key) {
  if(strncmp(line, key, strlen(key)) == 0) {
    char * equals_loc = strchr(line, '=');
    if(equals_loc) {
      return equals_loc + 1;
    }
  }
  return NULL;
}

void set_config_str(char ** var, const char * value) {
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


const char default_certificate_file[] = "/etc/cpsula/private/cert";
const char default_certificate_key_file[] = "/etc/cpsula/private/pkey";

const char default_user[] = "gemini-data";
const char default_group[] = "gemini-data";

const uint16_t default_socket_port = 1965;

const char default_root_directory[] = "/var/gemini";
const char default_lua_main[] = "/var/gemini/main.lua";


char * certificate_file;
char * certificate_key_file;

char * user;
char * group;

char * socket_address;
uint16_t socket_port;

char * root_directory;
char * lua_main;


void cfg_init(const char * file) {
  ssize_t line_size = 0;
  char * linebuf = NULL;
  size_t linebuf_size = 0;

  // Configure defaults
  set_config_str(&certificate_file, default_certificate_file);
  set_config_str(&certificate_key_file, default_certificate_key_file);

  set_config_str(&user, default_user);
  set_config_str(&group, default_group);

  socket_address = NULL;
  socket_port = default_socket_port;

  set_config_str(&root_directory, default_root_directory);
  set_config_str(&lua_main, default_lua_main);

  // Overwrite based on config file
  log_info("Reading configuration from %s", file);

  FILE * fp = fopen(file, "r");
  if(!fp) {
    log_error("Failed to open %s for reading", file);
    exit(1);
  }

  while((line_size = getline(&linebuf, &linebuf_size, fp)) != -1) {
    assert(line_size > 0);

    // XXX: Remove newline
    linebuf[line_size - 1] = '\x00';

    const char * value;
    if((value = parse_key_value(linebuf, "certificate-file"))) {
      if(strlen(value) == 0) {
        log_error("Invalid certificate file '%s'", value);
        exit(1);
      }
      set_config_str(&certificate_file, value);
    }
    if((value = parse_key_value(linebuf, "certificate-key-file"))) {
      if(strlen(value) == 0) {
        log_error("Invalid certificate key file '%s'", value);
        exit(1);
      }
      set_config_str(&certificate_key_file, value);
    }
    if((value = parse_key_value(linebuf, "user"))) {
      if(strlen(value) == 0) {
        log_error("Invalid user '%s'", value);
        exit(1);
      }
      set_config_str(&user, value);
    }
    if((value = parse_key_value(linebuf, "group"))) {
      if(strlen(value) == 0) {
        log_error("Invalid group '%s'", value);
        exit(1);
      }
      set_config_str(&group, value);
    }
    if((value = parse_key_value(linebuf, "socket-address"))) {
      set_config_str(&socket_address, value);
    }
    if((value = parse_key_value(linebuf, "socket-port"))) {
      long int value_int = strtol(value, NULL, 10);
      if(value_int < 0 || value_int > UINT16_MAX) {
        log_error("Invalid port '%s'", value);
        exit(1);
      }
      socket_port = value_int;
    }
    if((value = parse_key_value(linebuf, "root-directory"))) {
      if(strlen(value) == 0) {
        log_error("Invalid root directory '%s'", value);
        exit(1);
      }
      set_config_str(&root_directory, value);
    }
    if((value = parse_key_value(linebuf, "lua-main"))) {
      if(strlen(value) == 0) {
        log_error("Invalid lua main file '%s'", value);
        exit(1);
      }
      set_config_str(&lua_main, value);
    }
  }

  free(linebuf);
  linebuf = NULL;
  linebuf_size = 0;

  fclose(fp);
  fp = NULL;
}

void cfg_deinit(void) {
  free(certificate_file);
  certificate_file = NULL;

  free(certificate_key_file);
  certificate_key_file = NULL;

  free(user);
  user = NULL;

  free(group);
  group = NULL;

  free(socket_address);
  socket_address = NULL;

  socket_port = 0;

  free(root_directory);
  root_directory = NULL;

  free(lua_main);
  lua_main = NULL;
}

const char * cfg_certificate_file(void) {
  return certificate_file;
}

const char * cfg_certificate_key_file(void) {
  return certificate_key_file;
}

const char * cfg_user(void) {
  return user;
}

const char * cfg_group(void) {
  return group;
}

const char * cfg_socket_address(void) {
  return socket_address;
}

uint16_t cfg_socket_port(void) {
  return socket_port;
}

const char * cfg_root_directory(void) {
  return root_directory;
}

const char * cfg_lua_main(void) {
  return lua_main;
}

