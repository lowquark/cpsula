
#include <config.h>
#include <log.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

// Configuration values - Empty strings are NULL
char * certificate_hostname;
char * private_key_file;
char * certificate_file;

char * user;
char * group;

char * bind_address;
long bind_port;

char * root_directory;
char * lua_main;
int lua_error_responses;

static void copy_str_realloc_noterm(char ** dst, const char * src_begin, const char * src_end) {
  assert(dst);
  assert(src_begin);
  assert(src_end);
  assert(src_end >= src_begin);
  size_t size = src_end - src_begin;
  *dst = (char *)realloc(*dst, size + 1);
  memcpy(*dst, src_begin, size);
  (*dst)[size] = '\x00';
}

static void copy_str_realloc(char ** dst, const char * src) {
  assert(dst);
  assert(src);
  size_t size = strlen(src);
  *dst = (char *)realloc(*dst, size + 1);
  memcpy(*dst, src, size);
  (*dst)[size] = '\x00';
}

static int set_boolean(int * value, const char * str) {
  assert(value);
  assert(str);

  if(strcmp(str, "true") == 0) {
    *value = 1;
    return 1;
  } else if(strcmp(str, "false") == 0) {
    *value = 0;
    return 1;
  } else {
    return 0;
  }
}

static int set_integer_minmax(long * value, const char * str, long min, long max) {
  assert(value);
  assert(str);

  if(strlen(str) == 0) {
    return 0;
  }
  if(str[0] != '-' && str[0] != '+' && !(str[0] >= '0' && str[0] <= '9')) {
    return 0;
  }
  long int str_value = strtol(str, NULL, 10);
  if(str_value < min || str_value > max) {
    return 0;
  }
  *value = str_value;
  return 1;
}

int set_string_nonnull(char ** str_inout, const char * src) {
  assert(str_inout);
  assert(src);

  if(strlen(src) == 0) {
    return 0;
  }
  copy_str_realloc(str_inout, src);
  return 1;
}

int set_string(char ** str_inout, const char * src) {
  assert(str_inout);
  assert(src);

  if(strlen(src) == 0) {
    free(*str_inout);
    *str_inout = NULL;
  } else {
    copy_str_realloc(str_inout, src);
  }
  return 1;
}

int set_certificate_hostname(const char * value) {
  assert(value);
  return set_string(&certificate_hostname, value);
}

int set_private_key_file(const char * value) {
  assert(value);
  return set_string(&private_key_file, value);
}

int set_certificate_file(const char * value) {
  assert(value);
  return set_string(&certificate_file, value);
}

int set_user(const char * value) {
  assert(value);
  return set_string_nonnull(&user, value);
}

int set_group(const char * value) {
  assert(value);
  return set_string_nonnull(&group, value);
}

int set_bind_address(const char * value) {
  assert(value);
  return set_string(&bind_address, value);
}

int set_bind_port(const char * value) {
  assert(value);
  return set_integer_minmax(&bind_port, value, 1, 65535);
}

int set_root_directory(const char * value) {
  assert(value);
  return set_string_nonnull(&root_directory, value);
}

int set_lua_main(const char * value) {
  assert(value);
  return set_string_nonnull(&lua_main, value);
}

int set_lua_error_responses(const char * value) {
  assert(value);
  return set_boolean(&lua_error_responses, value);
}

static void set_defaults() {
  set_certificate_hostname("");
  set_private_key_file("");
  set_certificate_file("");

  set_user("gemini-data");
  set_group("gemini-data");

  set_bind_address("");
  set_bind_port("1965");

  set_root_directory("/var/gemini");
  set_lua_main("main.lua");
  set_lua_error_responses("false");
}

static void set_key_value_or_die(const char * key, const char * value) {
  int rval;

  assert(key);
  assert(value);

  if(strcmp(key, "certificate_hostname") == 0) {
    rval = set_certificate_hostname(value);
  } else if(strcmp(key, "private_key_file") == 0) {
    rval = set_private_key_file(value);
  } else if(strcmp(key, "certificate_file") == 0) {
    rval = set_certificate_file(value);
  } else if(strcmp(key, "user") == 0) {
    rval = set_user(value);
  } else if(strcmp(key, "group") == 0) {
    rval = set_group(value);
  } else if(strcmp(key, "bind_address") == 0) {
    rval = set_bind_address(value);
  } else if(strcmp(key, "bind_port") == 0) {
    rval = set_bind_port(value);
  } else if(strcmp(key, "root_directory") == 0) {
    rval = set_root_directory(value);
  } else if(strcmp(key, "lua_main") == 0) {
    rval = set_lua_main(value);
  } else if(strcmp(key, "lua_error_responses") == 0) {
    rval = set_lua_error_responses(value);
  } else {
    log_error("Unrecognized config value <%s>", key);
    exit(1);
  }

  if(!rval) {
    log_error("Invalid value '%s' for <%s>", value, key);
    exit(1);
  }
}

static int is_space(uint_fast32_t c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static int is_key_char(uint_fast32_t c) {
  return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

#define PARSE_COMMENT     0
#define PARSE_KEY         1
#define PARSE_KEY_VALUE   2
#define PARSE_ERR_SYNTAX -1

static int parse_line(const char * line, char ** key_inout, char ** value_inout) {
  assert(line);
  assert(key_inout);
  assert(value_inout);

  const char * read_ptr = line;
  const char * key_begin = NULL;
  const char * key_end = NULL;
  const char * value_begin = NULL;
  const char * value_end = NULL;

  while(is_space(*read_ptr)) {
    ++read_ptr;
  }

  if(is_key_char(*read_ptr)) {
    key_begin = read_ptr;
    while(is_key_char(*read_ptr)) {
      ++read_ptr;
    }
    key_end = read_ptr;

    while(is_space(*read_ptr)) {
      ++read_ptr;
    }

    if(*read_ptr == ':') {
      ++read_ptr;

      while(is_space(*read_ptr)) {
        ++read_ptr;
      }

      if(*read_ptr) {
        // Key read, value here too
        value_begin = read_ptr;
        while(*read_ptr && !is_space(*read_ptr)) {
          ++read_ptr;
        }
        value_end = read_ptr;

        while(is_space(*read_ptr)) {
          ++read_ptr;
        }

        if(!*read_ptr) {
          // End of line
          copy_str_realloc_noterm(key_inout, key_begin, key_end);
          copy_str_realloc_noterm(value_inout, value_begin, value_end);
          return PARSE_KEY_VALUE;
        } else {
          // Garbage at end of line
          return PARSE_ERR_SYNTAX;
        }
      } else {
        // Key read, but no value
        copy_str_realloc_noterm(key_inout, key_begin, key_end);
        copy_str_realloc(value_inout, "");
        return PARSE_KEY;
      }
    } else {
      // Expected ':'
      return PARSE_ERR_SYNTAX;
    }
  } else if(*read_ptr == '#') {
    // Comment line
    return PARSE_COMMENT;
  } else if(!*read_ptr) {
    // Whitespace or empty line
    return PARSE_COMMENT;
  } else {
    // Something invalid
    return PARSE_ERR_SYNTAX;
  }
}

static void set_from_file_or_die(const char * filename) {
  ssize_t line_size = 0;
  char * linebuf = NULL;
  size_t linebuf_size = 0; // TODO: Try to remove this
  char * key = NULL;
  char * value = NULL;
  int line = 1;

  // Overwrite based on config file
  log_info("Reading configuration from %s", filename);

  FILE * fp = fopen(filename, "r");
  if(!fp) {
    log_error("Failed to open %s for reading", filename);
    exit(1);
  }

  while((line_size = getline(&linebuf, &linebuf_size, fp)) != -1) {
    assert(line_size > 0);
    linebuf[line_size - 1] = '\x00';

    int rval = parse_line(linebuf, &key, &value);

    if(rval == PARSE_KEY || rval == PARSE_KEY_VALUE) {
      //log_info("%s -> %s", key, value);
      set_key_value_or_die(key, value);
    } else if(rval == PARSE_ERR_SYNTAX) {
      log_error("Error parsing %s: syntax error on line %d", filename, line);
      exit(1);
    }

    ++line;
  }

  free(linebuf);
  linebuf = NULL;
  linebuf_size = 0;
  free(key);
  key = NULL;
  free(value);
  value = NULL;

  fclose(fp);
  fp = NULL;
}

void cfg_init(const char * filename) {
  set_defaults();

  set_from_file_or_die(filename);
}

void cfg_deinit(void) {
  free(private_key_file);
  private_key_file = NULL;

  free(certificate_file);
  certificate_file = NULL;

  free(certificate_hostname);
  certificate_hostname = NULL;

  free(user);
  user = NULL;

  free(group);
  group = NULL;

  free(bind_address);
  bind_address = NULL;

  bind_port = 0;

  free(root_directory);
  root_directory = NULL;

  free(lua_main);
  lua_main = NULL;

  lua_error_responses = 0;
}

const char * cfg_certificate_hostname(void) {
  return certificate_hostname;
}

const char * cfg_private_key_file(void) {
  return private_key_file;
}

const char * cfg_certificate_file(void) {
  return certificate_file;
}

const char * cfg_user(void) {
  return user;
}

const char * cfg_group(void) {
  return group;
}

const char * cfg_bind_address(void) {
  return bind_address;
}

uint16_t cfg_bind_port(void) {
  return bind_port;
}

const char * cfg_root_directory(void) {
  return root_directory;
}

const char * cfg_lua_main(void) {
  return lua_main;
}

const int cfg_lua_error_responses(void) {
  return lua_error_responses;
}

#ifdef TEST

#include <btest.h>

struct cfg_test_case {
  const char * line;
  const char * key;
  const char * value;
  int return_value;
};

static const struct cfg_test_case cfg_test_cases[] = {
  { "",                     NULL,          NULL,     PARSE_COMMENT    },
  { "     ",                NULL,          NULL,     PARSE_COMMENT    },
  { "\t",                   NULL,          NULL,     PARSE_COMMENT    },
  { "#",                    NULL,          NULL,     PARSE_COMMENT    },
  { " \r\t# bla :",         NULL,          NULL,     PARSE_COMMENT    },
  { "test:",                "test",        "",       PARSE_KEY        },
  { "test: ",               "test",        "",       PARSE_KEY        },
  { " test: \t",            "test",        "",       PARSE_KEY        },
  { "test: abcd",           "test",        "abcd",   PARSE_KEY_VALUE  },
  { "test : abcd",          "test",        "abcd",   PARSE_KEY_VALUE  },
  { " test\t : abcd",       "test",        "abcd",   PARSE_KEY_VALUE  },
  { " test : abcd ",        "test",        "abcd",   PARSE_KEY_VALUE  },
  { " asdf_asdf : $$$$ ",   "asdf_asdf",   "$$$$",   PARSE_KEY_VALUE  },
  { "a:*",                  "a",           "*",      PARSE_KEY_VALUE  },
  { "test",                 NULL,          NULL,     PARSE_ERR_SYNTAX },
  { "test ",                NULL,          NULL,     PARSE_ERR_SYNTAX },
  { " test ",               NULL,          NULL,     PARSE_ERR_SYNTAX },
  { "test : abcd xyz",      NULL,          NULL,     PARSE_ERR_SYNTAX },
  { " : : $$$$ ",           NULL,          NULL,     PARSE_ERR_SYNTAX },
};

void test_cfg_case(const struct cfg_test_case * test_case) {
  fprintf(stderr, "> test_cfg_case(\"%s\")\n", test_case->line);

  char * key = NULL;
  char * value = NULL;
  int rval = parse_line(test_case->line, &key, &value);

  BTEST_INT_EQ(rval, test_case->return_value);
  BTEST_STR_EQ(key, test_case->key);
  BTEST_STR_EQ(value, test_case->value);

  free(key);
  key = NULL;
  free(value);
  value = NULL;
}

int main(int argc, char ** argv) {
  log_init(stderr);

  for(unsigned int i = 0 ; i < sizeof(cfg_test_cases)/sizeof(*cfg_test_cases) ; ++i) {
    test_cfg_case(cfg_test_cases + i);
  }

  // TODO: Test values of a dummy config file

  return 0;
}

#endif

