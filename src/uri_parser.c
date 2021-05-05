
#include <log.h>
#include <uri_parser.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>

struct uri_parser {
  char * address;
  char * path;
};

static void clear(struct uri_parser * up) {
  free(up->address);
  free(up->path);
  memset(up, 0, sizeof(*up));
}

struct uri_parser * uri_parser_new(void) {
  return calloc(sizeof(struct uri_parser), 1);
}

void uri_parser_free(struct uri_parser * up) {
  clear(up);
  free(up);
}

const char * uri_parser_address(const struct uri_parser * up) {
  return up->address;
}

const char * uri_parser_path(const struct uri_parser * up) {
  return up->path;
}

static int is_alpha(int c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_numeric(int c) {
  return (c >= '0' && c <= '9');
}

static int is_host_char(int c) {
  return is_alpha(c) || is_numeric(c) || c == '.' || c == '-';
}

static char * new_str(const char * begin, const char * end) {
  size_t size = end - begin;
  char * str = (char *)malloc(size + 1);
  memcpy(str, begin, size);
  str[size] = '\0';
  return str;
}

int uri_parser_parse(struct uri_parser * up, const char * uri, size_t uri_size) {
  const char * host_begin = NULL;
  const char * host_end = NULL;
  const char * port_begin = NULL;
  const char * port_end = NULL;
  const char * path_begin = NULL;
  const char * path_end = NULL;
  const char * read_ptr = uri;
  const char * read_end = uri + uri_size;

  char c;

  if(uri_size < strlen("gemini://")) {
    return 1;
  }

  if(strncmp(uri, "gemini://", strlen("gemini://"))) {
    return 1;
  }

  read_ptr = uri + strlen("gemini://");

  // At least one <host-char> until '/'
  host_begin = read_ptr;
  if(read_ptr == read_end) { return 1; }
  c = *read_ptr++;

  if(!is_host_char(c)) { return 1; }

  for(;;) {
    host_end = read_ptr;
    if(read_ptr == read_end) { goto parse_complete; }
    c = *read_ptr++;

    if(c == '@') {
      // Userinfo not allowed
      return 1;
    }
    if(c == '/') {
      goto parse_path;
    }
    if(c == ':') {
      goto parse_port;
    }
    if(!is_host_char(c)) { return 1; }
  }

parse_port:
  // At least one number until '/'
  port_begin = read_ptr;
  port_end = read_ptr;
  if(read_ptr == read_end) { return 1; }
  c = *read_ptr++;

  if(!is_numeric(c)) { return 1; }

  for(;;) {
    port_end = read_ptr;
    if(read_ptr == read_end) { goto parse_complete; }
    c = *read_ptr++;

    if(c == '/') {
      goto parse_path;
    }
    if(!is_numeric(c)) { return 1; }
  }

parse_path:
  path_begin = read_ptr-1;
  path_end = read_end;

parse_complete:
  clear(up);

  if(host_end != host_begin) {
    if(port_end != port_begin) {
      assert(port_end > host_begin);
      up->address = new_str(host_begin, port_end);
    } else {
      up->address = new_str(host_begin, host_end);
    }
  }

  if(path_end != path_begin) {
    up->path = new_str(path_begin, path_end);
  }

  return 0;
}

#ifdef TEST

struct uri_test_case {
  const char * uri;
  const char * address;
  const char * path;
  int return_value;
};

static const struct uri_test_case uri_test_cases[] = {
  { "",                                NULL,                       NULL,     1 },
  { "g",                               NULL,                       NULL,     1 },
  { "ge",                              NULL,                       NULL,     1 },
  { "gem",                             NULL,                       NULL,     1 },
  { "gemi",                            NULL,                       NULL,     1 },
  { "gemin",                           NULL,                       NULL,     1 },
  { "gemini",                          NULL,                       NULL,     1 },
  { "gemini:",                         NULL,                       NULL,     1 },
  { "gemini:/",                        NULL,                       NULL,     1 },
  { "gemini://",                       NULL,                       NULL,     1 },
  { "gemini://a",                      "a",                        NULL,     0 },
  { "gemini://aa",                     "aa",                       NULL,     0 },
  { "gemini://aa.bb",                  "aa.bb",                    NULL,     0 },
  { "gemini://aa.bb:0",                "aa.bb:0",                  NULL,     0 },
  { "gemini://aa.bb:01",               "aa.bb:01",                 NULL,     0 },
  { "gemini://aa.bb:9001",             "aa.bb:9001",               NULL,     0 },
  { "gemini://aa.bb:1239001",          "aa.bb:1239001",            NULL,     0 },
  { "gemini://127.0.0.1:1239001",      "127.0.0.1:1239001",        NULL,     0 },
  { "gemini://aa.bb:9001/",            "aa.bb:9001",               "/",      0 },
  { "gemini://aa.bb:9001/x",           "aa.bb:9001",               "/x",     0 },
  { "gemini://aa.bb:9001/x/",          "aa.bb:9001",               "/x/",    0 },
  { "gemini://aa.bb:9001/x/y",         "aa.bb:9001",               "/x/y",   0 },
  { "gemini://aa:",                    NULL,                       NULL,     1 },
  { "gemini://test /asdf",             NULL,                       NULL,     1 },
  { "gemini://aa:88:88/asdf",          NULL,                       NULL,     1 },
  { "gemini://",                       NULL,                       NULL,     1 },
  { "gemini:///asdf",                  NULL,                       NULL,     1 },
  { "gemini:///aa/bb/cc",              NULL,                       NULL,     1 },
  { "gemini:///aa/bb:88/cc",           NULL,                       NULL,     1 },
  { "gemini://:8888",                  NULL,                       NULL,     1 },
  { "gemini://:8888/asdf",             NULL,                       NULL,     1 },
  { "test:8888/asdf",                  NULL,                       NULL,     1 },
  { "gemini:/test:8888/asdf",          NULL,                       NULL,     1 },
  { "gamini://test:8888/asdf",         NULL,                       NULL,     1 },
  { "gemini://test:a888/asdf",         NULL,                       NULL,     1 },
  { "gemini://test:/asdf",             NULL,                       NULL,     1 },
};

void test_uri_parser_case(const struct uri_test_case * test_case) {
  struct uri_parser * parser;
  int rval;

  parser = uri_parser_new();

  log_info("%s", test_case->uri);

  rval = uri_parser_parse(parser, test_case->uri, strlen(test_case->uri));

  assert(rval == test_case->return_value);

  if(test_case->address) {
    assert(parser->address && !strcmp(test_case->address, parser->address));
  } else {
    assert(!parser->address);
  }

  if(test_case->path) {
    assert(parser->path && !strcmp(test_case->path, parser->path));
  } else {
    assert(!parser->path);
  }

  uri_parser_free(parser);
  parser = NULL;
}

int main(int argc, char ** argv) {
  log_init(stderr);

  for(unsigned int i = 0 ; i < sizeof(uri_test_cases)/sizeof(*uri_test_cases) ; ++i) {
    test_uri_parser_case(uri_test_cases + i);
  }

  return 0;
}

#endif

