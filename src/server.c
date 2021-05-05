
#include <log.h>
#include <server.h>
#include <luaenv.h>
#include <uri_parser.h>

#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <assert.h>
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

static const char gemini_allowed_ciphers[] = 
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

static const int gemini_min_protocol_version = TLS1_2_VERSION;

// TODO: Create a config module
static const char certificate_file_path[] = "./cert";
static const char private_key_file_path[] = "./pkey";

#define CLIENT_MAX_REQUEST_SIZE (1026)

static const char err_header_59_size_exceeded[] = "59 Request size limit exceeded.\r\n";
static const char err_header_59_malformed_uri[] = "59 Malformed URI.\r\n";
static const char err_header_62_not_yet_valid[] = "62 Not yet valid.\r\n";
static const char err_header_62_expired[]       = "62 Expired.\r\n";

#define LITERAL_AND_LENGTH(x) x, strlen(x)

struct server_context {
  // SSL context object
  SSL_CTX * ssl_context;

  // Top level libevent loop object
  struct event_base * event_base;

  // libevent listener object governing accept callback
  struct evconnlistener * listener;

  // Lua environment object
  struct luaenv_context * script_env;
};

struct client_context {
  // Pointer to parent server
  struct server_context * server_context;

  // SSL peer connection object
  SSL * ssl_connection;

  // libevent buffer object governing read/write/event callbacks
  struct bufferevent * buffer_event;

  // Simple buffer for the entire client request
  char rx_buffer[CLIENT_MAX_REQUEST_SIZE];
  size_t rx_buffer_size;

  // Lua request handler
  struct luaenv_request * script_request_handler;
};

static char nyble_ascii(unsigned int nyble) {
  if(nyble <= 0x9) {
    return '0'+nyble;
  }
  if(nyble <= 0xF) {
    return 'A'+(nyble-0xA);
  }
  return '\0';
}

// Computes SHA-1 digest from the X509 certificate, and writes its ASCII/hex representation to
// sha1_hex_out. This can be verified via the following command:
//
// $ openssl x509 -noout -in cert -fingerprint -serial
//
// Returns 1 on success, and 0 if the SSL library fails somehow.
static int compute_X509_digest(char (*sha1_hex_out)[41], const X509 * x509) {
  const EVP_MD * sha1 = EVP_get_digestbyname("sha1");
  if(!sha1) {
    log_warning("EVP_get_digestbyname() failed");
    return 0;
  }

  unsigned char sha1_digest[EVP_MAX_MD_SIZE] = { };
  unsigned int sha1_digest_len = 0;
  if(!X509_digest(x509, sha1, sha1_digest, &sha1_digest_len)) {
    log_warning("X509_digest() failed");
    return 0;
  }

  if(sha1_digest_len != 20) {
    log_warning("SHA1 digest does not appear to be the size of a SHA1 digest");
    return 0;
  }

  char * out = *sha1_hex_out;

  for(unsigned int i = 0 ; i < 20 ; ++i) {
    out[2*i]   = nyble_ascii((sha1_digest[i] & 0xF0) >> 4);
    out[2*i+1] = nyble_ascii(sha1_digest[i] & 0xF);
  }
  out[40] = '\0';

  return 1;
}

// Computes a GMT, POSIX timestamp from the unwieldy formats in the X509 certificate.
static int compute_X509_expiry(time_t * expiry, const X509 * x509) {
  struct tm time_tm;

  assert(expiry);
  assert(x509);

  if(ASN1_TIME_to_tm(X509_get0_notAfter(x509), &time_tm)) {
    *expiry = mktime(&time_tm);
    return 1;
  } else {
    log_warning("ASN1_TIME_to_tm failed");
    return 0;
  }
}

static struct client_context * create_client() {
  return (struct client_context *)calloc(sizeof(struct client_context), 1);
}

static void destroy_client(struct client_context * client_context) {
  // Note: This also frees the SSL connection object
  bufferevent_free(client_context->buffer_event);

  luaenv_request_free(client_context->script_request_handler);

  memset(client_context, 0, sizeof(*client_context));
  free(client_context);

  log_info("Connection closed");
}

// Reads as many bytes from the input buffer as possible, and stores them in the client's request
// buffer.
static void client_read_bytes(struct client_context * client, struct evbuffer * input_buf) {
  assert(client);
  assert(input_buf);

  size_t read_size = evbuffer_get_length(input_buf);
  size_t rx_free = CLIENT_MAX_REQUEST_SIZE - client->rx_buffer_size;

  if(read_size > rx_free) {
    read_size = rx_free;
  }

  evbuffer_remove(input_buf, client->rx_buffer + client->rx_buffer_size, read_size);
  client->rx_buffer_size += read_size;
}

// If <CR><LF> is found in the buffer, sets *req_size_out to the number of preceeding bytes and
// returns 1.
// Otherwise, returns 0.
static int request_ready(const char * buf, size_t buf_size, size_t * req_size_out) {
  if(!buf || buf_size == 0) {
    return 0;
  }
  for(size_t i = 0 ; i < buf_size - 1 ; ++i) {
    if(buf[i] == '\r' && buf[i + 1] == '\n') {
      *req_size_out = i;
      return 1;
    }
  }
  return 0;
}

// Writes the given C string to the given libevent bufferevent object.
static void xbufferevent_write_str(struct bufferevent * bufev, const char * str) {
  bufferevent_write(bufev, str, strlen(str));
}

// Commences the server response by executing the luaenv request handler with the given URI and
// optional certificate information. If no data is returned, closes the connection. Otherwise,
// writes the resultant data chunk to the client's bufferevent object.
static void client_execute_response(struct client_context * client,
                                    const struct uri_parser * uri_parser) {
  assert(client);
  assert(uri_parser);

  char sha1_hex_str[41];

  const char * uri_address = uri_parser_address(uri_parser);
  const char * uri_path = uri_parser_path(uri_parser);
  const char * cert_digest = NULL;
  time_t cert_expiry = 0;

  const X509 * x509 = SSL_get_peer_certificate(client->ssl_connection);
  if(x509) {
    if(compute_X509_digest(&sha1_hex_str, x509)) {
      if(compute_X509_expiry(&cert_expiry, x509)) {
        cert_digest = sha1_hex_str;
        log_info("Client certificate: %s expires: %ld", cert_digest, cert_expiry);
      }
    }
  }

  assert(!client->script_request_handler);
  client->script_request_handler = luaenv_request_new(client->server_context->script_env);

  luaenv_request_execute(client->script_request_handler,
                         uri_address,
                         uri_path,
                         cert_digest,
                         cert_expiry);

  size_t len;
  const char * str = luaenv_request_result(client->script_request_handler, &len);
  if(str) {
    bufferevent_write(client->buffer_event, str, len);
  } else {
    destroy_client(client);
    client = NULL;
  }
}

// Queries the luaenv request handler for more response data. Writes the result to the client's
// bufferevent object. If no data is returned, closes the connection. Otherwise, writes the
// resultant data chunk to the client's bufferevent object.
static void client_continue_response(struct client_context * client) {
  assert(client);
  assert(client->script_request_handler);

  luaenv_request_continue(client->script_request_handler);

  size_t len;
  const char * str = luaenv_request_result(client->script_request_handler, &len);
  if(str) {
    bufferevent_write(client->buffer_event, str, len);
  } else {
    destroy_client(client);
    client = NULL;
  }
}

static void parse_and_respond(struct client_context * client,
                              const char * request,
                              size_t request_size) {
  struct uri_parser * uri_parser;

  assert(client);
  assert(request);

  uri_parser = uri_parser_new();

  if(uri_parser_parse(uri_parser, request, request_size)) {
    log_warning("Rejecting malformed URL");
    xbufferevent_write_str(client->buffer_event, err_header_59_malformed_uri);
  } else {
    log_info("Handling request for %.*s", (int)request_size, request);
    client_execute_response(client, uri_parser);
  }

  uri_parser_free(uri_parser);
}

static void client_readcb(struct bufferevent * buffer_event, void * user_data) {
  struct client_context * client;
  struct evbuffer * input_buf;

  client = (struct client_context *)user_data;

  input_buf = bufferevent_get_input(buffer_event);

  client_read_bytes(client, input_buf);

  size_t request_size;
  if(request_ready(client->rx_buffer, client->rx_buffer_size, &request_size)) {
    parse_and_respond(client, client->rx_buffer, request_size);

    bufferevent_disable(client->buffer_event, EV_READ);
  } else if(client->rx_buffer_size == CLIENT_MAX_REQUEST_SIZE) {
    log_warning("Maximum request size exceeded");
    xbufferevent_write_str(buffer_event, err_header_59_size_exceeded);

    bufferevent_disable(client->buffer_event, EV_READ);
  }
}

static void client_writecb(struct bufferevent * buffer_event, void * user_data) {
  struct client_context * client;

  client = (struct client_context *)user_data;

  if(client->script_request_handler) {
    int status = luaenv_request_status(client->script_request_handler);

    if(status == LUAENV_REQUEST_SUSPENDED) {
      client_continue_response(client);
    } else if(status == LUAENV_REQUEST_DEAD) {
      destroy_client(client);
      client = NULL;
    }
  } else {
    destroy_client(client);
    client = NULL;
  }
}

static void client_eventcb(struct bufferevent * buffer_event, short events, void * user_data) {
  struct client_context * client;

  client = (struct client_context *)user_data;

  if(events & BEV_EVENT_CONNECTED) {
    // This event seems to correspond to when the handshake completes successfully
    const X509 * x509 = SSL_get_peer_certificate(client->ssl_connection);
    if(x509) {
      time_t time_now = time(NULL);
      if(X509_cmp_time(X509_get0_notBefore(x509), &time_now) != -1) {
        log_warning("Invalid certificate, not yet valid");
        xbufferevent_write_str(buffer_event, err_header_62_not_yet_valid);
      }
      if(X509_cmp_time(X509_get0_notAfter(x509), &time_now) != 1) {
        log_warning("Invalid certificate, expired");
        xbufferevent_write_str(buffer_event, err_header_62_expired);
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
    destroy_client(client);
    client = NULL;
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

static int ssl_verify_cb(X509_STORE_CTX * x509_store, void * user_data) {
  return 1;
}

static SSL_CTX * new_ssl_context(void) {
  SSL_CTX * server_ctx;
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

  rval = SSL_CTX_set_min_proto_version(server_ctx, gemini_min_protocol_version);
  if(!rval) {
    log_error("SSL_CTX_set_min_proto_version() failed");
    exit(1);
  }

  rval = SSL_CTX_set_cipher_list(server_ctx, gemini_allowed_ciphers);
  if(!rval) {
    log_error("SSL_CTX_set_cipher_list() failed");
    exit(1);
  }

  rval = SSL_CTX_set_tlsext_servername_callback(server_ctx, NULL);
  if(!rval) {
    log_error("SSL_CTX_set_tlsext_servername_callback() failed");
    exit(1);
  }

  SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);

  SSL_CTX_set_verify(server_ctx, SSL_VERIFY_PEER, NULL);

  SSL_CTX_set_cert_verify_callback(server_ctx, ssl_verify_cb, NULL);

  rval = SSL_CTX_set_options(server_ctx, SSL_OP_NO_RENEGOTIATION);
  if(!rval) {
    log_error("Yikes. Disabling renegotiation failed");
    exit(1);
  }

  if(!SSL_CTX_use_certificate_chain_file(server_ctx, certificate_file_path)) {
    log_error("Failed to read certificate file '%s'", certificate_file_path);
    exit(1);
  }

  if(!SSL_CTX_use_PrivateKey_file(server_ctx, private_key_file_path, SSL_FILETYPE_PEM)) {
    log_error("Failed to read private key file '%s'", private_key_file_path);
    exit(1);
  }

  return server_ctx;
}

static struct server_context * global_server_context;

void server_init(struct event_base * event_base) {
  global_server_context = (struct server_context *)malloc(sizeof(*global_server_context));

  global_server_context->ssl_context = new_ssl_context();

  global_server_context->event_base = event_base;

  global_server_context->script_env = luaenv_context_new();

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
  luaenv_context_free(global_server_context->script_env);
  global_server_context->script_env = NULL;

  SSL_CTX_free(global_server_context->ssl_context);
  global_server_context->ssl_context = NULL;

  global_server_context->event_base = NULL;

  evconnlistener_free(global_server_context->listener);
  global_server_context->listener = NULL;

  free(global_server_context);
  global_server_context = NULL;
}

