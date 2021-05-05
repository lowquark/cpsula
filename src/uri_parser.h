#ifndef URI_PARSER_H
#define URI_PARSER_H

#include <stddef.h>

struct uri_parser {
  char * address;
  char * path;
};

void uri_parser_init(struct uri_parser * up);
void uri_parser_clear(struct uri_parser * up);

int uri_parser_parse(struct uri_parser * up, const char * uri, size_t uri_size);

const char * uri_parser_address(const struct uri_parser * up);
const char * uri_parser_path(const struct uri_parser * up);

#endif
