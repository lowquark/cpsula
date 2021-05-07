#ifndef SSL_INIT_H
#define SSL_INIT_H

#include <openssl/ssl.h>

// Allocates and returns an appropriately configured SSL context object. Free with SSL_CTX_free().
SSL_CTX * ssl_ctx_new(void);

#endif
