
#include <config.h>
#include <log.h>
#include <ssl_init.h>

#include <openssl/rand.h>

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

static const int min_protocol_version = TLS1_2_VERSION;

static int ssl_verify_cb(X509_STORE_CTX * x509_store, void * user_data) {
  return 1;
}

SSL_CTX * ssl_ctx_new(void) {
  SSL_CTX * server_ctx;
  int rval;
  const char * cert_file;
  const char * cert_key_file;

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

  SSL_CTX_set_options(server_ctx, SSL_OP_NO_SSLv2);

  SSL_CTX_set_verify(server_ctx, SSL_VERIFY_PEER, NULL);

  SSL_CTX_set_cert_verify_callback(server_ctx, ssl_verify_cb, NULL);

  rval = SSL_CTX_set_options(server_ctx, SSL_OP_NO_RENEGOTIATION);
  if(!rval) {
    log_error("Yikes. Disabling renegotiation failed");
    exit(1);
  }

  cert_file = cfg_certificate_file();
  if(!SSL_CTX_use_certificate_chain_file(server_ctx, cert_file)) {
    log_error("Failed to read certificate file '%s'", cert_file);
    exit(1);
  }

  cert_key_file = cfg_certificate_key_file();
  if(!SSL_CTX_use_PrivateKey_file(server_ctx, cert_key_file, SSL_FILETYPE_PEM)) {
    log_error("Failed to read private key file '%s'", cert_key_file);
    exit(1);
  }

  return server_ctx;
}

