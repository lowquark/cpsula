
#include <config.h>
#include <log.h>
#include <tls.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/fcntl.h>
#include <unistd.h>

// TODO: These should really all be configurable
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

static const long auto_x509_serial_number = 9001;
static const long auto_x509_expiration_s = 630720000L;
static const char * auto_x509_C = NULL;     // e.g. US
static const char * auto_x509_O = "cpsula"; // 

static EVP_PKEY * read_pkey(const char * filepath) {
  FILE * file;
  EVP_PKEY * pkey = NULL;

  assert(filepath);

  file = fopen(filepath, "r");
  pkey = NULL;

  if(file) {
    pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);

    if(pkey) {
      log_info("Read private key from %s", filepath);
    } else {
      log_warning("Error reading private key from %s: %s",
          filepath, ERR_reason_error_string(ERR_get_error()));
    }

    fclose(file);
    file = NULL;
  } else {
    log_warning("Error reading private key from %s: %s", filepath, strerror(errno));
  }

  return pkey;
}

static void write_pkey(const char * filepath, EVP_PKEY * pkey) {
  FILE * file;
  int fd;

  assert(filepath);
  assert(pkey);

  fd = open(filepath, O_CREAT | O_WRONLY, 0600);
  if(fd < 0) {
    log_warning("Failed to open %s for writing: %s", filepath, strerror(errno));
    return;
  }

  file = fdopen(fd, "w");
  assert(file);

  PEM_write_PrivateKey(file, pkey, NULL, NULL, 0, NULL, NULL);
  log_info("Private key written to %s", filepath);

  fclose(file);
  file = NULL;
}

static X509 * read_cert(const char * filepath, EVP_PKEY * pkey) {
  FILE * file;
  X509 * cert;

  // TODO: Validate against pkey?
  (void)pkey;

  assert(filepath);

  file = fopen(filepath, "r");
  cert = NULL;

  if(file) {
    cert = PEM_read_X509(file, NULL, NULL, NULL);

    if(cert) {
      log_info("Read certificate from %s", filepath);
    } else {
      log_warning("Error reading certificate from %s: %s",
          filepath, ERR_reason_error_string(ERR_get_error()));
    }

    fclose(file);
    file = NULL;
  } else {
    log_warning("Error reading certificate from %s: %s", filepath, strerror(errno));
  }

  return cert;
}

static void write_cert(const char * filepath, X509 * cert) {
  FILE * file;
  int fd;

  assert(filepath);
  assert(cert);

  fd = open(filepath, O_CREAT | O_WRONLY, 0644);
  if(fd < 0) {
    log_warning("Failed to open %s for writing: %s", filepath, strerror(errno));
    return;
  }

  file = fdopen(fd, "w");
  assert(file);

  PEM_write_X509(file, cert);
  log_info("Certificate written to %s", filepath);

  fclose(file);
  file = NULL;
}

// Returns a malloc'd buffer to e.g. /usr/share/cpsula/ssl/<hostname>.<file_ext>
char * get_host_ssl_filepath(const char * hostname, const char * file_ext) {
  size_t bufsize;
  char * buf;
  int rval;

  assert(hostname);
  assert(file_ext);

  bufsize = strlen(CFG_SSL_DIRECTORY) + 1 + 
            strlen(hostname) + 1 + 
            strlen(file_ext) + 1;

  buf = malloc(bufsize);

  rval = snprintf(buf, bufsize, "%s/%s.%s", CFG_SSL_DIRECTORY, hostname, file_ext);

  assert(rval >= 0 && rval < bufsize);

  return buf;
}

static EVP_PKEY * generate_pkey(void) {
  EC_KEY * ec_key;
  int rval;

  // Choosing the 'manly' curve from
  // https://security.stackexchange.com/questions/78621/which-elliptic-curve-should-i-use
  ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
  if(ec_key) {
    if(EC_KEY_generate_key(ec_key)) {
      EVP_PKEY * pkey = EVP_PKEY_new();
      if(pkey) {
        rval = EVP_PKEY_assign_EC_KEY(pkey, ec_key);
        assert(rval);
        return pkey;
      } else {
        log_error("EVP_PKEY_new() failed");
      }
    } else {
      log_error("EC_KEY_generate_key() failed");
    }
    EC_KEY_free(ec_key);
    ec_key = NULL;
  } else {
    log_error("EC_KEY_new_by_curve_name() failed");
  }
  return NULL;
}

static X509 * generate_cert(const char * hostname, EVP_PKEY * pkey) {
  X509 * cert;

  assert(hostname);
  assert(pkey);

  // https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl
  cert = X509_new();

  if(cert) {
    X509_set_version(cert, 2);

    ASN1_INTEGER_set(X509_get_serialNumber(cert), auto_x509_serial_number);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), auto_x509_expiration_s);

    X509_NAME * x509_name = X509_get_subject_name(cert);

    if(auto_x509_C) {
      X509_NAME_add_entry_by_txt(x509_name,
                                 "C",
                                 MBSTRING_ASC,
                                 (unsigned char *)auto_x509_C,
                                 -1, -1, 0);
    }

    if(auto_x509_O) {
      X509_NAME_add_entry_by_txt(x509_name,
                                 "O",
                                 MBSTRING_ASC,
                                 (unsigned char *)auto_x509_O,
                                 -1, -1, 0);
    }

    X509_NAME_add_entry_by_txt(x509_name,
                               "CN",
                               MBSTRING_ASC,
                               (unsigned char *)hostname,
                               -1, -1, 0);

    X509_set_issuer_name(cert, x509_name);

    X509_set_pubkey(cert, pkey);

    if(X509_sign(cert, pkey, EVP_sha1())) {
      return cert;
    } else {
      log_warning("X509_sign() failed");
    }

    X509_free(cert);
    cert = NULL;
  }

  return NULL;
}

static EVP_PKEY * read_or_generate_pkey(const char * filepath) {
  EVP_PKEY * pkey;

  assert(filepath);

  if(access(filepath, F_OK) == 0) {
    pkey = read_pkey(filepath);
  } else {
    pkey = generate_pkey();
    if(pkey) {
      write_pkey(filepath, pkey);
    }
  }

  return pkey;
}

static X509 * read_or_generate_cert(const char * filepath, const char * hostname, EVP_PKEY * pkey) {
  X509 * cert;

  assert(filepath);
  assert(hostname);
  assert(pkey);

  if(access(filepath, F_OK) == 0) {
    cert = read_cert(filepath, pkey);
  } else {
    cert = generate_cert(hostname, pkey);
    if(cert) {
      write_cert(filepath, cert);
    }
  }

  return cert;
}

static int attain_credentials(EVP_PKEY ** pkey_out, X509 ** cert_out) {
  EVP_PKEY * pkey;
  X509 * cert;
  char * filepath;

  if(cfg_private_key_file()) {
    pkey = read_pkey(cfg_private_key_file());
  } else if(cfg_certificate_hostname()) {
    filepath = get_host_ssl_filepath(cfg_certificate_hostname(), CFG_PKEY_FILE_EXT);
    pkey = read_or_generate_pkey(filepath);
    free(filepath);
    filepath = NULL;
  } else {
    log_error("Neither <private_key_file> nor <certificate_hostname> specified in config");
  }

  if(pkey) {
    if(cfg_certificate_file()) {
      cert = read_cert(cfg_certificate_file(), pkey);
    } else if(cfg_certificate_hostname()) {
      filepath = get_host_ssl_filepath(cfg_certificate_hostname(), CFG_CERT_FILE_EXT);
      cert = read_or_generate_cert(filepath, cfg_certificate_hostname(), pkey);
      free(filepath);
      filepath = NULL;
    } else {
      log_warning("Neither <certificate_file> nor <certificate_hostname> specified in config");
    }

    if(cert) {
      *pkey_out = pkey;
      *cert_out = cert;
      return 1;
    }

    EVP_PKEY_free(pkey);
    pkey = NULL;
  }

  *pkey_out = NULL;
  *cert_out = NULL;
  return 0;
}

static int ssl_verify_cb(X509_STORE_CTX * x509_store, void * user_data) {
  return 1;
}

static EVP_PKEY * server_pkey;
static X509 * server_cert;
static SSL_CTX * server_ssl_context;

SSL_CTX * tls_init(void) {
  int rval;

  server_ssl_context = SSL_CTX_new(TLS_server_method());
  if(!server_ssl_context) {
    log_error("SSL_CTX_new() failed");
    exit(1);
  }

  rval = SSL_CTX_set_min_proto_version(server_ssl_context, min_protocol_version);
  if(!rval) {
    log_error("SSL_CTX_set_min_proto_version() failed");
    exit(1);
  }

  rval = SSL_CTX_set_cipher_list(server_ssl_context, allowed_ciphers);
  if(!rval) {
    log_error("SSL_CTX_set_cipher_list() failed");
    exit(1);
  }

  rval = SSL_CTX_set_tlsext_servername_callback(server_ssl_context, NULL);
  if(!rval) {
    log_error("SSL_CTX_set_tlsext_servername_callback() failed");
    exit(1);
  }

  SSL_CTX_set_options(server_ssl_context, SSL_OP_NO_SSLv2);

  SSL_CTX_set_verify(server_ssl_context, SSL_VERIFY_PEER, NULL);

  SSL_CTX_set_cert_verify_callback(server_ssl_context, ssl_verify_cb, NULL);

  rval = SSL_CTX_set_options(server_ssl_context, SSL_OP_NO_RENEGOTIATION);
  if(!rval) {
    log_error("Yikes. Disabling renegotiation failed");
    exit(1);
  }

  if(!attain_credentials(&server_pkey, &server_cert)) {
    log_error("Failed to read private key / certificate, cannot start server");
    exit(1);
  }

  if(!SSL_CTX_use_PrivateKey(server_ssl_context, server_pkey)) {
    log_error("SSL_CTX_use_PrivateKey() failed: %s", ERR_reason_error_string(ERR_get_error()));
    exit(1);
  }

  if(!SSL_CTX_use_certificate(server_ssl_context, server_cert)) {
    log_error("Failed to certificate file: %s", ERR_reason_error_string(ERR_get_error()));
    exit(1);
  }

  return server_ssl_context;
}

void tls_deinit(void) {
  EVP_PKEY_free(server_pkey);
  server_pkey = NULL;

  X509_free(server_cert);
  server_cert = NULL;

  SSL_CTX_free(server_ssl_context);
  server_ssl_context = NULL;
}

