#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>

SSL_CTX * tls_init(void);
void tls_deinit(void);

#endif
