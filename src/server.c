
#include <log.h>
#include <server.h>
#include <script.h>
#include <uri_parser.h>

#include <event2/bufferevent_ssl.h>
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

static const unsigned short gemini_port = 1965;

static const char allowed_ciphers[] = 
  "ECDHE-ECDSA-AES128-GCM-SHA256:"
  "ECDHE-RSA-AES128-GCM-SHA256:"
  "ECDHE-ECDSA-AES256-GCM-SHA384:"
  "ECDHE-RSA-AES256-GCM-SHA384:"
  "ECDHE-ECDSA-CHACHA20-POLY1305:"
  "ECDHE-RSA-CHACHA20-POLY1305:"
  "DHE-RSA-AES128-GCM-SHA256:"
  "DHE-RSA-AES256-GCM-SHA384:"
  "TLS_AES_128_GCM_SHA256:"
  "TLS_AES_256_GCM_SHA384:"
  "TLS_CHACHA20_POLY1305_SHA256";

static const char certificate_file_path[] = "./cert";
static const char private_key_file_path[] = "./pkey";

static const int min_protocol_version = TLS1_2_VERSION;

#define MAX_REQUEST_SIZE (1026)
static const size_t max_request_size = MAX_REQUEST_SIZE;

static const char maximum_request_size_response_str[] = "59 Request size limit exceeded.\r\n";

struct server_context {
  SSL_CTX * ssl_context;
  struct event_base * event_base;
  struct evconnlistener * listener;
  struct scr_env * script_env;
};

struct client_context {
  struct server_context * server_context;
  SSL * ssl_connection;
  struct bufferevent * buffer_event;
  char request_buffer[MAX_REQUEST_SIZE];
  size_t request_size;
  struct scr_reqhandler * script_request_handler;
};

static const char nyble_ascii(unsigned int nyble) {
  if(nyble <= 0x9) {
    return '0'+nyble;
  }
  if(nyble <= 0xF) {
    return 'A'+(nyble-0xA);
  }
  return '\0';
}

static int compute_X509_digest(char (*sha1_hex_out)[41], X509 * x509) {
  const EVP_MD * sha1 = EVP_get_digestbyname("sha1");
  if(!sha1) {
    log_warning("EVP_get_digestbyname() failed");
    return 1;
  }

  unsigned char sha1_digest[EVP_MAX_MD_SIZE] = { };
  unsigned int sha1_digest_len = 0;
  if(!X509_digest(x509, sha1, sha1_digest, &sha1_digest_len)) {
    log_warning("X509_digest() failed");
    return 1;
  }

  if(sha1_digest_len != 20) {
    log_warning("SHA1 digest does not appear to be the size of a SHA1 digest");
    return 1;
  }

  char * out = *sha1_hex_out;

  for(unsigned int i = 0 ; i < 20 ; ++i) {
    out[2*i]   = nyble_ascii((sha1_digest[i] & 0xF0) >> 4);
    out[2*i+1] = nyble_ascii(sha1_digest[i] & 0xF);
  }
  out[40] = '\0';

  return 0;
}

static time_t compute_X509_expiry(X509 * x509) {
  struct tm time_tm;
  ASN1_TIME_to_tm(X509_get0_notAfter(x509), &time_tm);
  return mktime(&time_tm);
}

static struct client_context * create_client() {
  return (struct client_context *)calloc(sizeof(struct client_context), 1);
}

static void destroy_client(struct client_context * client_context) {
  // The SSL connection is owned by this buffer event
  bufferevent_free(client_context->buffer_event);
  scr_reqhandler_free(client_context->script_request_handler);
  memset(client_context, 0, sizeof(*client_context));
  free(client_context);
}

static void client_readcb(struct bufferevent * buffer_event, void * user_data) {
  struct client_context * client_context;
  struct evbuffer * input;

  client_context = (struct client_context *)user_data;
  input = bufferevent_get_input(buffer_event);

  size_t size_in = evbuffer_get_length(input);

  if(client_context->request_size + size_in > max_request_size) {
    // No room in the inn
    bufferevent_write(buffer_event,
                      maximum_request_size_response_str,
                      strlen(maximum_request_size_response_str));
    destroy_client(client_context);
    client_context = NULL;
    return;
  }

  evbuffer_remove(input, client_context->request_buffer + client_context->request_size, size_in);

  size_t uri_size = 0;

  for(size_t i = 0 ; i < client_context->request_size - 1 ; ++i) {
    if(client_context->request_buffer[i] == '\r' && 
       client_context->request_buffer[i+1] == '\n') {
      uri_size = i;
      break;
    }
  }

  if(uri_size) {
    struct uri_parser parser;
    uri_parser_init(&parser);

    if(uri_parser_parse(&parser, client_context->request_buffer, uri_size)) {
      static const char error_response[] = "59 Malformed URI\n";
      bufferevent_write(buffer_event, error_response, strlen(error_response));
    } else {
      client_context->script_request_handler = scr_reqhandler_new(client_context->server_context->script_env);

      X509 * x509 = SSL_get_peer_certificate(client_context->ssl_connection);
      if(x509) {
        char sha1_hex_str[41];
        time_t expiry_time;

        compute_X509_digest(&sha1_hex_str, x509);
        expiry_time = compute_X509_expiry(x509);

        log_info("Client certificate sha1 digest: %s", sha1_hex_str);
        log_info("Expiry: %ld", expiry_time);

        scr_reqhandler_execute(client_context->script_request_handler, parser.address, parser.path, sha1_hex_str, expiry_time);
      } else {
        scr_reqhandler_execute(client_context->script_request_handler, parser.address, parser.path, NULL, 0);
      }

      size_t len;
      const char * str = scr_reqhandler_result(client_context->script_request_handler, &len);
      if(str) {
        log_info("result:\n%.*s", (int)len, str);
        bufferevent_write(buffer_event, str, len);
      }
    }

    uri_parser_clear(&parser);
  }
}

static void client_writecb(struct bufferevent * buffer_event, void * user_data) {
  struct client_context * client_context;

  client_context = (struct client_context *)user_data;

  struct evbuffer * output = bufferevent_get_output(buffer_event);
  if(evbuffer_get_length(output) == 0) {
    destroy_client(client_context);
    client_context = NULL;
  }
}

static void client_eventcb(struct bufferevent * buffer_event, short events, void * user_data) {
  struct client_context * client_context;

  client_context = (struct client_context *)user_data;

  if(events & BEV_EVENT_CONNECTED) {
    // This seems to correspond to when the handshake completes successfully
    X509 * x509 = SSL_get_peer_certificate(client_context->ssl_connection);
    if(x509) {
      time_t time_now = time(NULL);
      if(X509_cmp_time(X509_get0_notBefore(x509), &time_now) != -1) {
        log_warning("Invalid certificate, not yet valid");
        bufferevent_write(buffer_event, "62 Not yet valid\r\n", strlen("62 Not yet valid\r\n"));
      }
      if(X509_cmp_time(X509_get0_notAfter(x509), &time_now) != 1) {
        log_warning("Invalid certificate, expired");
        bufferevent_write(buffer_event, "62 Expired\r\n", strlen("62 Expired\r\n"));
      }
    }
  } else {
    if(events & BEV_EVENT_EOF) {
      log_info("Connection closed");
    } else if(events & BEV_EVENT_ERROR) {
      unsigned long openssl_error;
      while((openssl_error = bufferevent_get_openssl_error(buffer_event))) {
        const char * whilestr = "";
        if(events & BEV_EVENT_WRITING) {
          whilestr = " while writing";
        } else if(events & BEV_EVENT_READING) {
          whilestr = " while reading";
        }
        log_warning("Client SSL error 0x%08lX%s: %s",
            openssl_error, whilestr, ERR_reason_error_string(openssl_error));
      }
    } else if(events & BEV_EVENT_TIMEOUT) {
      log_warning("Connection timed out");
    }
    destroy_client(client_context);
    client_context = NULL;
  }
}

static int client_init(struct client_context * client_context,
                       struct server_context * server_context,
                       evutil_socket_t socket_fd) {
  client_context->server_context = server_context;

  client_context->ssl_connection = SSL_new(server_context->ssl_context);

  if(client_context->ssl_connection) {
    client_context->buffer_event = bufferevent_openssl_socket_new(
        server_context->event_base,
        socket_fd,
        client_context->ssl_connection,
        BUFFEREVENT_SSL_ACCEPTING,
        BEV_OPT_CLOSE_ON_FREE);

    if(client_context->buffer_event) {
      bufferevent_setcb(client_context->buffer_event,
                        client_readcb,
                        client_writecb,
                        client_eventcb,
                        client_context);

      bufferevent_enable(client_context->buffer_event, EV_WRITE);
      bufferevent_enable(client_context->buffer_event, EV_READ);

      return 0;
    } else {
      log_warning("bufferevent_openssl_socket_new() failed");
    }

    SSL_free(client_context->ssl_connection);
    client_context->ssl_connection = NULL;
  } else {
    log_warning("SSL_new() failed");
  }

  return -1;
}

static void server_accept_cb(struct evconnlistener * listener,
                             evutil_socket_t socket_fd,
                             struct sockaddr * sa,
                             int socklen,
                             void * user_data) {
  struct server_context * server_context;
  struct client_context * client_context;

  server_context = (struct server_context *)user_data;

  client_context = create_client(server_context, socket_fd);

  client_init(client_context, server_context, socket_fd);
}

static int ssl_verify_cb(X509_STORE_CTX * x509_ctx, void * user_data) {
  return 1;
}

static SSL_CTX * evssl_init(void) {
  SSL_CTX  *server_ctx;
  int rval;

  ERR_load_crypto_strings();
  SSL_load_error_strings();
  SSL_library_init();

  if(!RAND_poll()) {
    log_error("Failed to seed RNG (RAND_poll)");
    exit(1);
  }

  server_ctx = SSL_CTX_new(TLS_server_method());
  if(!server_ctx) {
    log_error("SSL_CTX_new() failed");
    exit(1);
  }

  rval = SSL_CTX_set_min_proto_version(server_ctx, min_protocol_version);
  if(!rval) {
    log_error("SSL_CTX_set_min_proto_version() failed");
    exit(1);
  }

  rval = SSL_CTX_set_cipher_list(server_ctx, allowed_ciphers);
  if(!rval) {
    log_error("SSL_CTX_set_cipher_list() failed");
    exit(1);
  }

  rval = SSL_CTX_set_tlsext_servername_callback(server_ctx, NULL);
  if(!rval) {
    log_error("SSL_CTX_set_tlsext_servername_callback() failed");
    exit(1);
  }

  SSL_CTX_set_verify(server_ctx, SSL_VERIFY_PEER, NULL);

  SSL_CTX_set_cert_verify_callback(server_ctx, ssl_verify_cb, NULL);

  rval = SSL_CTX_set_options(server_ctx, SSL_OP_NO_RENEGOTIATION);
  if(!rval) {
    log_error("Yikes. Disabling renegotiation failed");
    exit(1);
  }

  if(!SSL_CTX_use_certificate_chain_file(server_ctx, certificate_file_path) ||
     !SSL_CTX_use_PrivateKey_file(server_ctx, private_key_file_path, SSL_FILETYPE_PEM)) {
    log_error("Failed to locate certificate / private key");
    puts("Couldn't read 'pkey' or 'cert' file. To generate a key and a self-signed certificate, run:\n"
         "  openssl genrsa -out pkey 2048\n"
         "  openssl req -new -key pkey -out cert.req\n"
         "  openssl x509 -req -days 365 -in cert.req -signkey pkey -out cert");
    exit(1);
  }

  SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);

  return server_ctx;
}

static struct server_context * global_server_context;

void server_init(struct event_base * event_base) {
  global_server_context = (struct server_context *)malloc(sizeof(*global_server_context));

  global_server_context->ssl_context = evssl_init();

  global_server_context->event_base = event_base;

  global_server_context->script_env = scr_env_new();

  struct sockaddr_in sin = {0};
  sin.sin_family = AF_INET;
  sin.sin_port = htons(gemini_port);

  global_server_context->listener =
    evconnlistener_new_bind(event_base,
                            server_accept_cb,
                            global_server_context,
                            LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE,
                            -1,
                            (struct sockaddr*)&sin,
                            sizeof(sin));

  if(!global_server_context->listener) {
    log_error("evconnlistener_new_bind() failed");
    exit(1);
  }
}

void server_deinit() {
  scr_env_free(global_server_context->script_env);
  global_server_context->script_env = NULL;

  SSL_CTX_free(global_server_context->ssl_context);
  global_server_context->ssl_context = NULL;

  global_server_context->event_base = NULL;

  evconnlistener_free(global_server_context->listener);
  global_server_context->listener = NULL;

  free(global_server_context);
  global_server_context = NULL;
}

