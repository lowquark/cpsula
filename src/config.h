#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

void cfg_init();

// Never NULL
const char * cfg_certificate_file();
// Never NULL
const char * cfg_certificate_key_file();

// Never NULL
const char * cfg_user();
// Never NULL
const char * cfg_group();

// Possibly NULL
const char * cfg_socket_address();
// Never zero
uint16_t cfg_socket_port();

// Never NULL
const char * cfg_root_directory();
// Never NULL
const char * cfg_lua_main();

#endif
