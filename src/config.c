
#include <config.h>

void cfg_init() {
}

const char * cfg_certificate_file() {
  return "./cert";
}

const char * cfg_certificate_key_file() {
  return "./pkey";
}

const char * cfg_user() {
  return "gemini-data";
}

const char * cfg_group() {
  return "gemini-data";
}

const char * cfg_socket_address() {
  return "localhost";
}

uint16_t cfg_socket_port() {
  return 1965;
}

const char * cfg_root_directory() {
  return ".";
}

const char * cfg_lua_main() {
  return "./main.lua";
}

