#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

void cfg_init(const char * file);
void cfg_deinit(void);

// Never NULL
const char * cfg_certificate_file(void);
// Never NULL
const char * cfg_certificate_key_file(void);

// Never NULL
const char * cfg_user(void);
// Never NULL
const char * cfg_group(void);

// Possibly NULL
const char * cfg_socket_address(void);
// Never zero
uint16_t cfg_socket_port(void);

// Never NULL
const char * cfg_root_directory(void);
// Never NULL
const char * cfg_lua_main(void);

#endif
