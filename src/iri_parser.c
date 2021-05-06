
#include <log.h>
#include <iri_parser.h>

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static char * new_str(const char * begin, const char * end) {
  size_t size = end - begin;
  char * str = (char *)malloc(size + 1);
  memcpy(str, begin, size);
  str[size] = '\0';
  return str;
}

static int is_alpha(uint_fast32_t c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_digit(uint_fast32_t c) {
  return (c >= '0' && c <= '9');
}

static int is_hex_digit(uint_fast32_t c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
}

// https://tools.ietf.org/html/rfc3987#section-2.2
static int is_ucs(uint_fast32_t c) {
  // TODO: This is itching to be optimized
  return (c >= 0x000A0 && c <= 0x0D7FF) || (c >= 0x0F900 && c <= 0x0FDCF) ||
         (c >= 0x0FDF0 && c <= 0x0FFEF) || (c >= 0x10000 && c <= 0x1FFFD) ||
         (c >= 0x20000 && c <= 0x2FFFD) || (c >= 0x30000 && c <= 0x3FFFD) ||
         (c >= 0x40000 && c <= 0x4FFFD) || (c >= 0x50000 && c <= 0x5FFFD) ||
         (c >= 0x60000 && c <= 0x6FFFD) || (c >= 0x70000 && c <= 0x7FFFD) ||
         (c >= 0x80000 && c <= 0x8FFFD) || (c >= 0x90000 && c <= 0x9FFFD) ||
         (c >= 0xA0000 && c <= 0xAFFFD) || (c >= 0xB0000 && c <= 0xBFFFD) ||
         (c >= 0xC0000 && c <= 0xCFFFD) || (c >= 0xD0000 && c <= 0xDFFFD) ||
         (c >= 0xE1000 && c <= 0xEFFFD);
}

static int is_private(uint_fast32_t c) {
  // TODO: This is itching to be optimized
  return (c >= 0xE000 && c <= 0xF8FF) || (c >= 0xF0000 && c <= 0xFFFFD) ||
         (c >= 0x100000 && c <= 0x10FFFD);
}

static int is_unreserved(uint_fast32_t c) {
  return is_alpha(c) || is_digit(c) || is_ucs(c) ||
         c == '-' || c == '.' || c == '_' || c == '~';
}

static int is_sub_delim(uint_fast32_t c) {
  return c == '!' || c == '$' || c == '&' || c == '\'' ||
         c == '(' || c == ')' || c == '*' || c == '+' ||
         c == ',' || c == ';' || c == '=';
}

static int is_host_char(uint_fast32_t c) {
  return is_unreserved(c) || is_sub_delim(c) ||
         c == '%';
}

static int is_path_char(uint_fast32_t c) {
  return is_unreserved(c) || is_sub_delim(c) ||
         c == '%' || c == ':' || c == '@' || c == '/';
}

static int is_query_char(uint_fast32_t c) {
  return is_unreserved(c) || is_sub_delim(c) || is_private(c) ||
         c == '%' || c == ':' || c == '@' || c == '/' || c == '?';
}

static int is_fragment_char(uint_fast32_t c) {
  return is_unreserved(c) || is_sub_delim(c) ||
         c == '%' || c == ':' || c == '@' || c == '/' || c == '?';
}

static size_t read_char_utf8(uint_fast32_t * codepoint_out,
                             const char * read_ptr,
                             const char * read_end) {
  uint_fast32_t codepoint;
  size_t valid_size;
  uint_fast32_t c;
  uint_fast32_t bit;

  assert(codepoint_out);
  assert(read_ptr);
  assert(read_end);
  assert(read_ptr <= read_end);

  valid_size = read_end - read_ptr;
  if(valid_size == 0) { return 0; }

  c = *read_ptr++;
  bit = 0x80;

  if(!(c & bit)) {
    // This is a regular ASCII byte
    *codepoint_out = c;
    return 1;
  }

  bit >>= 1;

  if(!(c & bit)) {
    // This is a continuation byte
    return 0;
  }

  bit >>= 1;

  if(!(c & bit)) {
    // This is a 2-byte code
    if(valid_size < 2) { return 0; }

    codepoint = (c & 0x1F) << 6;

    c = *read_ptr++;
    if((c & 0xC0) != 0x80) { return 0; }
    codepoint |= (c & 0x3F);

    *codepoint_out = codepoint;
    return 2;
  }

  bit >>= 1;

  if(!(c & bit)) {
    // This is a 3-byte code
    if(valid_size < 3) { return 0; }

    codepoint = (c & 0x0F) << 12;

    c = *read_ptr++;
    codepoint |= (c & 0x3F) << 6;
    if((c & 0xC0) != 0x80) { return 0; }

    c = *read_ptr++;
    codepoint |= (c & 0x3F);
    if((c & 0xC0) != 0x80) { return 0; }

    *codepoint_out = codepoint;
    return 3;
  }

  bit >>= 1;

  if(!(c & bit)) {
    // This is a 4-byte code
    if(valid_size < 4) { return 0; }

    codepoint = (c & 0x07) << 18;

    c = *read_ptr++;
    codepoint |= (c & 0x3F) << 12;
    if((c & 0xC0) != 0x80) { return 0; }

    c = *read_ptr++;
    codepoint |= (c & 0x3F) << 6;
    if((c & 0xC0) != 0x80) { return 0; }

    c = *read_ptr++;
    codepoint |= (c & 0x3F);
    if((c & 0xC0) != 0x80) { return 0; }

    *codepoint_out = codepoint;
    return 4;
  }

  // Too many 1s
  return 0;
}

struct iri_parser {
  char * address;
  char * resource;
};

static void clear(struct iri_parser * up) {
  free(up->address);
  free(up->resource);
  memset(up, 0, sizeof(*up));
}

struct iri_parser * iri_parser_new(void) {
  return calloc(sizeof(struct iri_parser), 1);
}

void iri_parser_free(struct iri_parser * up) {
  clear(up);
  free(up);
}

/*

URI grammar: https://tools.ietf.org/html/rfc3986#section-3
IRI grammar: https://tools.ietf.org/html/rfc3987#section-2.2

Because Gemini mandates that a URI's host is required, we may consider only the IRI ABNF rule for
'ipath-abempty', greatly reducing the complexity of a parse. This parser implements the following:

 Gemini IRI:
 -----------

     +-----------+  +------+     +------+     +------+     +-------+     +----------+
 ||--| gemini:// |--| Host |--+--| Port |--+--| Path |--+--| Query |--+--| Fragment |--+--||
     +-----------+  +------+  |  +------+  |  +------+  |  +-------+  |  +----------+  |
                              +----->------+----->------+------>------+------->--------+

 Host:
 -----

     +--------<--------+
     |  +-----------+  |
 ||--+--| host char |--+--||
        +-----------+

Note: IP literals (IPv6 and IPvFuture) are not currently parsed. IPv4 addresses, while not
validated by this parser, are parsed by this rule.

 Port:
 -----

              +------<------+
     +-----+  |  +-------+  |
 ||--| ':' |--+--| digit |--+--||
     +-----+     +-------+

 Path:
 -----

              +------<----------+
     +-----+  |  +-----------+  |
 ||--| '/' |--+--| path char |--+--||
     +-----+     +-----------+

Note: Here, path char includes '/', and segments are not handled individually. (Compare to IRI ABNF
rules 'ipath-abempty', 'isegment'.)

 Query:
 ------

              +------<-----------+
     +-----+  |  +------------+  |
 ||--| '?' |--+--| query char |--+--||
     +-----+     +------------+

 Fragment:
 ---------

              +------<--------------+
     +-----+  |  +---------------+  |
 ||--| '#' |--+--| fragment char |--+--||
     +-----+     +---------------+

*/

int iri_parser_parse(struct iri_parser * up, const char * iri, size_t iri_size) {
  // Host, port string slice markers
  const char * address_begin = NULL;
  const char * address_end = NULL;
  // Path, query, fragment string slice markers
  const char * pqf_begin = NULL;
  const char * pqf_end = NULL;
  // Read location & upper bound
  const char * read_ptr = iri;
  const char * read_end = iri + iri_size;

  // Most recent UTF-8 character read
  uint_fast32_t c;
  size_t c_size;

  assert(up);
  assert(iri);

  // Select
  if(iri_size < strlen("gemini://")) {
    return 1;
  }
  if(strncmp(iri, "gemini://", strlen("gemini://"))) {
    return 1;
  }

  // Consume
  read_ptr = iri + strlen("gemini://");

  // Select
  if(read_ptr == read_end) { return 1; }
  c_size = read_char_utf8(&c, read_ptr, read_end);
  if(!c_size) { return 1; }
  if(!is_host_char(c)) { return 1; }

// parse_host:
  // Consume
  address_begin = read_ptr;

  for(;;) {
    // Consume
    assert(is_host_char(c));
    read_ptr += c_size;
    address_end = read_ptr;

    // Select
    if(read_ptr == read_end) { goto parse_complete; }
    c_size = read_char_utf8(&c, read_ptr, read_end);
    if(!c_size) { return 1; }
    if(c == ':') { goto parse_port; }
    else if(c == '/') { goto parse_path; }
    else if(c == '?') { goto parse_query; }
    else if(c == '#') { goto parse_fragment; }
    else if(!is_host_char(c)) { return 1; }
  }

parse_port:
  // Consume
  assert(c == ':');
  read_ptr += c_size;
  address_end = read_ptr;

  // Select
  if(read_ptr == read_end) { return 1; }
  c_size = read_char_utf8(&c, read_ptr, read_end);
  if(!c_size) { return 1; }
  if(!is_digit(c)) { return 1; }

  for(;;) {
    // Consume
    assert(is_digit(c));
    read_ptr += c_size;
    address_end = read_ptr;

    // Select
    if(read_ptr == read_end) { goto parse_complete; }
    c_size = read_char_utf8(&c, read_ptr, read_end);
    if(!c_size) { return 1; }
    if(c == '/') { goto parse_path; }
    else if(c == '?') { goto parse_query; }
    else if(c == '#') { goto parse_fragment; }
    else if(!is_digit(c)) { return 1; }
  }

parse_path:
  // Consume
  assert(c == '/');
  pqf_begin = read_ptr;

  for(;;) {
    // Consume
    read_ptr += c_size;
    pqf_end = read_ptr;

    // Select
    if(read_ptr == read_end) { goto parse_complete; }
    c_size = read_char_utf8(&c, read_ptr, read_end);
    if(!c_size) { return 1; }
    if(c == '?') { goto parse_query; }
    else if(c == '#') { goto parse_fragment; }
    else if(!is_path_char(c)) { return 1; }
  }

parse_query:
  // Consume
  assert(c == '?');
  if(!pqf_begin) {
    pqf_begin = read_ptr;
  }

  for(;;) {
    // Consume
    read_ptr += c_size;
    pqf_end = read_ptr;

    // Select
    if(read_ptr == read_end) { goto parse_complete; }
    c_size = read_char_utf8(&c, read_ptr, read_end);
    if(!c_size) { return 1; }
    if(c == '#') { goto parse_fragment; }
    else if(!is_query_char(c)) { return 1; }
  }

parse_fragment:
  // Consume
  assert(c == '#');
  if(!pqf_begin) {
    pqf_begin = read_ptr;
  }

  for(;;) {
    // Consume
    read_ptr += c_size;
    pqf_end = read_ptr;

    // Select
    if(read_ptr == read_end) { goto parse_complete; }
    c_size = read_char_utf8(&c, read_ptr, read_end);
    if(!c_size) { return 1; }
    if(!is_fragment_char(c)) { return 1; }
  }

parse_complete:
  // Validate percent-encoded sequences
  for(read_ptr = iri ; read_ptr != read_end ; ++read_ptr) {
    if(*read_ptr == '%') {
      ++read_ptr;
      if(read_ptr == read_end) { return 1; }
      if(!is_hex_digit(*read_ptr)) { return 1; }

      ++read_ptr;
      if(read_ptr == read_end) { return 1; }
      if(!is_hex_digit(*read_ptr)) { return 1; }
    }
  }

  // Parse successful, replace existing field values
  clear(up);

  if(address_end != address_begin) {
    up->address = new_str(address_begin, address_end);
  }

  if(pqf_end != pqf_begin) {
    up->resource = new_str(pqf_begin, pqf_end);
  }

  return 0;
}

const char * iri_parser_address(const struct iri_parser * up) {
  return up->address;
}

const char * iri_parser_resource(const struct iri_parser * up) {
  return up->resource;
}

#ifdef TEST

struct iri_test_case {
  const char * iri;
  const char * address;
  const char * resource;
  int return_value;
};

static const struct iri_test_case iri_test_cases[] = {
  { "",                                       NULL,                         NULL,               1 },
  { "g",                                      NULL,                         NULL,               1 },
  { "ge",                                     NULL,                         NULL,               1 },
  { "gem",                                    NULL,                         NULL,               1 },
  { "gemi",                                   NULL,                         NULL,               1 },
  { "gemin",                                  NULL,                         NULL,               1 },
  { "gemini",                                 NULL,                         NULL,               1 },
  { "gemini:",                                NULL,                         NULL,               1 },
  { "gemini:/",                               NULL,                         NULL,               1 },
  { "gemini://",                              NULL,                         NULL,               1 },
  { "gemini://a",                             "a",                          NULL,               0 },
  { "gemini://ä",                             "ä",                          NULL,               0 },
  { "gemini://aa",                            "aa",                         NULL,               0 },
  { "gemini://aa.bb",                         "aa.bb",                      NULL,               0 },
  { "gemini://aa.bb:0",                       "aa.bb:0",                    NULL,               0 },
  { "gemini://aa.bb:01",                      "aa.bb:01",                   NULL,               0 },
  { "gemini://aa.bb:9001",                    "aa.bb:9001",                 NULL,               0 },
  { "gemini://aa.bb:1239001",                 "aa.bb:1239001",              NULL,               0 },
  { "gemini://127.0.0.1:1239001",             "127.0.0.1:1239001",          NULL,               0 },
  { "gemini://aa.bb:9001/",                   "aa.bb:9001",                 "/",                0 },
  { "gemini://aa.bb:9001/x",                  "aa.bb:9001",                 "/x",               0 },
  { "gemini://aa.bb:9001/x/",                 "aa.bb:9001",                 "/x/",              0 },
  { "gemini://aa.bb:9001/x/y",                "aa.bb:9001",                 "/x/y",             0 },
  { "gemini://aa.bb:9001/x/y?",               "aa.bb:9001",                 "/x/y?",            0 },
  { "gemini://aa.bb:9001/x/y??",              "aa.bb:9001",                 "/x/y??",           0 },
  { "gemini://aa.bb:9001/x/y?q",              "aa.bb:9001",                 "/x/y?q",           0 },
  { "gemini://aa.bb:9001/x/y?q=5",            "aa.bb:9001",                 "/x/y?q=5",         0 },
  { "gemini://aa.bb:9001/x/y?q=5#",           "aa.bb:9001",                 "/x/y?q=5#",        0 },
  { "gemini://aa.bb:9001/x/y?q=5#g",          "aa.bb:9001",                 "/x/y?q=5#g",       0 },
  { "gemini://aa.bb#",                        "aa.bb",                      "#",                0 },
  { "gemini://aa.bb?#",                       "aa.bb",                      "?#",               0 },
  { "gemini://aa.bb/?#",                      "aa.bb",                      "/?#",              0 },
  { "gemini://aa.bb??",                       "aa.bb",                      "??",               0 },
  { "gemini://aa.bb??#",                      "aa.bb",                      "??#",              0 },
  { "gemini://aa.bb?/?/#/",                   "aa.bb",                      "?/?/#/",           0 },
  { "gemini://ää%20%20",                      "ää%20%20",                   NULL,               0 },
  { "gemini://ää%FF%FF",                      "ää%FF%FF",                   NULL,               0 },
  { "gemini://ää%F%FF",                       NULL,                         NULL,               1 },
  { "gemini://ää%FF%F",                       NULL,                         NULL,               1 },
  { "gemini://aa.bb##",                       NULL,                         NULL,               1 },
  { "gemini://aa.bb?##",                      NULL,                         NULL,               1 },
  { "gemini://aa.bb/?##",                     NULL,                         NULL,               1 },
  { "gemini://aa:",                           NULL,                         NULL,               1 },
  { "gemini://test /asdf",                    NULL,                         NULL,               1 },
  { "gemini://test/asdf^",                    NULL,                         NULL,               1 },
  { "gemini://test/asdf/^",                   NULL,                         NULL,               1 },
  { "gemini://test/asdf/?^",                  NULL,                         NULL,               1 },
  { "gemini://test/asdf/?#^",                 NULL,                         NULL,               1 },
  { "gemini://test/^asdf/?#",                 NULL,                         NULL,               1 },
  { "gemini://aa:88:88/asdf",                 NULL,                         NULL,               1 },
  { "gemini:///asdf",                         NULL,                         NULL,               1 },
  { "gemini:///aa/bb/cc",                     NULL,                         NULL,               1 },
  { "gemini:///aa/bb:88/cc",                  NULL,                         NULL,               1 },
  { "gemini://:8888",                         NULL,                         NULL,               1 },
  { "gemini://:8888/asdf",                    NULL,                         NULL,               1 },
  { "test:8888/asdf",                         NULL,                         NULL,               1 },
  { "gemini:/test:8888/asdf",                 NULL,                         NULL,               1 },
  { "gamini://test:8888/asdf",                NULL,                         NULL,               1 },
  { "gemini://test:a888/asdf",                NULL,                         NULL,               1 },
  { "gemini://test:/asdf",                    NULL,                         NULL,               1 },
};

struct utf8_test_case {
  uint8_t data[5];
  size_t length;
  uint_fast32_t codepoint;
  size_t return_value;
};

static const struct utf8_test_case utf8_test_cases[] = {
  // Encodings of zero
  { { 0x00                         }, 1, 0x000000, 1 },
  { { 0xC0, 0x80                   }, 2, 0x000000, 2 },
  { { 0xE0, 0x80, 0x80             }, 3, 0x000000, 3 },
  { { 0xF0, 0x80, 0x80, 0x80       }, 4, 0x000000, 4 },
  // Encodings from Wikipedia
  { { 0x24                         }, 1, 0x000024, 1 },
  { { 0xC2, 0xA2                   }, 2, 0x0000A2, 2 },
  { { 0xE0, 0xA4, 0xB9             }, 3, 0x000939, 3 },
  { { 0xE2, 0x82, 0xAC             }, 3, 0x0020AC, 3 },
  { { 0xED, 0x95, 0x9C             }, 3, 0x00D55C, 3 },
  { { 0xF0, 0x90, 0x8D, 0x88       }, 4, 0x010348, 4 },
  // Encodings of U+070F
  { { 0xDC, 0x8F                   }, 2, 0x00070F, 2 },
  { { 0xE0, 0x9C, 0x8F             }, 3, 0x00070F, 3 },
  { { 0xF0, 0x80, 0x9C, 0x8F       }, 4, 0x00070F, 4 },
  // Encodings of zero + extra byte
  { { 0x00, 0xFF                   }, 2, 0x000000, 1 },
  { { 0xC0, 0x80, 0xFF             }, 3, 0x000000, 2 },
  { { 0xE0, 0x80, 0x80, 0xFF       }, 4, 0x000000, 3 },
  { { 0xF0, 0x80, 0x80, 0x80, 0xFF }, 5, 0x000000, 4 },
  // End of buffer
  { {                              }, 0, 0x000000, 0 },
  // Continuation bytes only
  { { 0x80                         }, 1, 0x000000, 0 },
  { { 0x80, 0x00                   }, 2, 0x000000, 0 },
  // Invalid bytes
  { { 0xF8                         }, 1, 0x000000, 0 },
  { { 0xFC                         }, 1, 0x000000, 0 },
  { { 0xFE                         }, 1, 0x000000, 0 },
  { { 0xFF                         }, 1, 0x000000, 0 },
  // Truncated encodings
  { { 0xC2                         }, 1, 0x000000, 0 },
  { { 0xE0, 0xA4                   }, 2, 0x000000, 0 },
  { { 0xF0, 0x90, 0x8D             }, 3, 0x000000, 0 },
  // Bad continuation bytes
  { { 0xC2, 0x22                   }, 2, 0x000000, 0 },
  { { 0xE0, 0x24, 0x39             }, 3, 0x000000, 0 },
  { { 0xF0, 0x10, 0x0D, 0x08       }, 4, 0x000000, 0 },
};

void test_iri_parser_case(const struct iri_test_case * test_case) {
  struct iri_parser * parser;
  int rval;

  parser = iri_parser_new();

  log_info("%s", test_case->iri);

  rval = iri_parser_parse(parser, test_case->iri, strlen(test_case->iri));

  assert(rval == test_case->return_value);

  if(test_case->address) {
    assert(parser->address && !strcmp(test_case->address, parser->address));
  } else {
    assert(!parser->address);
  }

  if(test_case->resource) {
    assert(parser->resource && !strcmp(test_case->resource, parser->resource));
  } else {
    assert(!parser->resource);
  }

  iri_parser_free(parser);
  parser = NULL;
}

void test_read_utf8_case(const struct utf8_test_case * test_case) {
  uint_fast32_t codepoint;
  int rval = read_char_utf8(&codepoint,
                            (const char *)test_case->data,
                            (const char *)test_case->data + test_case->length);

  fprintf(stderr, "[ ");
  for(size_t i = 0 ; i < test_case->length ; ++i) {
    fprintf(stderr, "%02X ", test_case->data[i]);
  }
  fprintf(stderr, "]\n");

  assert(rval == test_case->return_value);

  if(rval) {
    assert(codepoint == test_case->codepoint);
  }
}

int main(int argc, char ** argv) {
  log_init(stderr);

  for(unsigned int i = 0 ; i < sizeof(utf8_test_cases)/sizeof(*utf8_test_cases) ; ++i) {
    test_read_utf8_case(utf8_test_cases + i);
  }

  for(unsigned int i = 0 ; i < sizeof(iri_test_cases)/sizeof(*iri_test_cases) ; ++i) {
    test_iri_parser_case(iri_test_cases + i);
  }

  return 0;
}

#endif

