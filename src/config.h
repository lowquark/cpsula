#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

// Compiled configuration

/*
#ifndef CFG_ETC_DIRECTORY
#define CFG_ETC_DIRECTORY "/etc/cpsula"
#endif

#ifndef CFG_SHARE_DIRECTORY
#define CFG_SHARE_DIRECTORY "/usr/share/cpsula"
#endif
*/

#define CFG_MAIN_CONFIG_FILE (CFG_ETC_DIRECTORY "/cpsula.conf")
#define CFG_SSL_DIRECTORY (CFG_SHARE_DIRECTORY "/ssl")
#define CFG_CERT_FILE_EXT "cert"
#define CFG_PKEY_FILE_EXT "pkey"

// Runtime configuration

void cfg_init(const char * file);
void cfg_deinit(void);

// Possibly NULL
const char * cfg_certificate_file(void);
// Possibly NULL
const char * cfg_private_key_file(void);
// Possibly NULL
const char * cfg_certificate_hostname(void);

// Never NULL
const char * cfg_user(void);
// Never NULL
const char * cfg_group(void);

// Possibly NULL
const char * cfg_bind_address(void);
// Never zero
uint16_t cfg_bind_port(void);

// Never NULL
const char * cfg_root_directory(void);
// Never NULL
const char * cfg_lua_main(void);

#endif
