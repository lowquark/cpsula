#ifndef SERVER_H
#define SERVER_H

#include <event2/event.h>
#include <openssl/ssl.h>

void server_init(struct event_base * base, SSL_CTX * ssl_context);
void server_deinit();

#endif
