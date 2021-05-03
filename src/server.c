
#include <server.h>
#include <script.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#endif

static const char message_str[] = "Hello, World!\n";

static const unsigned short port = 1965;

struct server_context {
  SSL_CTX * ssl_context;
  struct event_base * event_base;
  struct evconnlistener * listener;
};

static void conn_readcb(struct bufferevent * bev, void * user_data) {
  printf("conn_readcb()\n");

  struct evbuffer * input = bufferevent_get_input(bev);
  if(evbuffer_get_length(input) > 0) {
    printf("length(input) > 0?\n");
  }
}

static void conn_writecb(struct bufferevent * bev, void * user_data) {
  printf("conn_writecb()\n");

  struct evbuffer * output = bufferevent_get_output(bev);
  if(evbuffer_get_length(output) == 0) {
    printf("flushed answer\n");

    // Now is the time to resume the lua coroutine which called this garbage fucking function
    // Garbage is all in your mind
    // The man convinces you his product is a product. Certainly not garbage.
    // You envy him. But his underpinnings, and his software assets, are garbage. His enslaved
    // developers work 9-5 to write his code. It works. But this isn't any different.

    bufferevent_free(bev);
  }
}

static void conn_eventcb(struct bufferevent * bev, short events, void * user_data) {
  printf("conn_eventcb()\n");

  if(events & BEV_EVENT_EOF) {
    printf("Connection closed.\n");
  } else if(events & BEV_EVENT_ERROR) {
    printf("Got an error on the connection: %s\n", strerror(errno));
  }

  /* None of the other events can happen here, since we haven't enabled
   * timeouts */
  bufferevent_free(bev);
}

static void server_accept_cb(struct evconnlistener * listener,
                             evutil_socket_t fd,
                             struct sockaddr * sa,
                             int socklen,
                             void * user_data) {
  struct server_context * server_context = (struct server_context *)user_data;

  printf("accept_cb()\n");

  struct bufferevent * bev = bufferevent_socket_new(server_context->event_base, fd, BEV_OPT_CLOSE_ON_FREE);
  if(!bev) {
    fprintf(stderr, "bufferevent_socket_new() failed");
    return;
  }

  bufferevent_setcb(bev, conn_readcb, conn_writecb, conn_eventcb, NULL);
  bufferevent_enable(bev, EV_WRITE);
  bufferevent_enable(bev, EV_READ);

  bufferevent_write(bev, message_str, strlen(message_str));
}

static SSL_CTX * evssl_init(void)
{
    SSL_CTX  *server_ctx;

    /* Initialize the OpenSSL library */
    SSL_load_error_strings();
    SSL_library_init();
    /* We MUST have entropy, or else there's no point to crypto. */
    if (!RAND_poll())
        return NULL;

    server_ctx = SSL_CTX_new(SSLv23_server_method());

    if (! SSL_CTX_use_certificate_chain_file(server_ctx, "cert") ||
        ! SSL_CTX_use_PrivateKey_file(server_ctx, "pkey", SSL_FILETYPE_PEM)) {
        puts("Couldn't read 'pkey' or 'cert' file. To generate a key and a self-signed certificate, run:\n"
           "  openssl genrsa -out pkey 2048\n"
           "  openssl req -new -key pkey -out cert.req\n"
           "  openssl x509 -req -days 365 -in cert.req -signkey pkey -out cert");
        return NULL;
    }
    SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);

    return server_ctx;
}

static struct server_context * global_server_context;

void server_init(struct event_base * event_base) {
  global_server_context = (struct server_context *)malloc(sizeof(*global_server_context));

  global_server_context->ssl_context = evssl_init();

  global_server_context->event_base = event_base;

  struct sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);

  global_server_context->listener = evconnlistener_new_bind(event_base,
                                                     server_accept_cb,
                                                     global_server_context,
                                                     LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
                                                     -1,
                                                     (struct sockaddr*)&sin,
                                                     sizeof(sin));

  if(!global_server_context->listener) {
    fprintf(stderr, "evconnlistener_new_bind() failed\n");
    exit(1);
  }
}

void server_deinit() {
  SSL_CTX_free(global_server_context->ssl_context);
  global_server_context->ssl_context = NULL;

  global_server_context->event_base = NULL;

  evconnlistener_free(global_server_context->listener);
  global_server_context->listener = NULL;

  free(global_server_context);
  global_server_context = NULL;
}

