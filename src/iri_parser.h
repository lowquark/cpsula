#ifndef URI_PARSER_H
#define URI_PARSER_H

#include <stddef.h>

struct iri_parser;

struct iri_parser * iri_parser_new(void);
void iri_parser_free(struct iri_parser * up);

// Attempts to parse the given IRI.
// If the input string represents a valid IRI, copies relevant fields from the input string into the
// parser object and returns 0.
// If the input string does not represent a valid IRI, returns nonzero and leaves the parser object
// unchanged.
int iri_parser_parse(struct iri_parser * up, const char * iri, size_t iri_size);

// Returns a C-string containing the address field of the most recent parse (e.g.
// "my.example.host:9001").
// The returned value be valid until the next successful call to iri_parser_parse(), or the parser
// object is freed.
const char * iri_parser_address(const struct iri_parser * up);

// Returns a C-string containing the path, query, and fragment of the most recent parse (e.g.
// "/example/directory/index.gmi?query=no#frag").
// The returned value be valid until the next successful call to iri_parser_parse(), or the parser
// object is freed.
const char * iri_parser_resource(const struct iri_parser * up);

#endif
