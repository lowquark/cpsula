
SERVER_TARGET=cpsula

SERVER_OBJECTS=    \
	src/main.o       \
	src/server.o     \
	src/sigs.o       \
	src/log.o        \
	src/luaenv.o     \
	src/iri_parser.o \
	src/ssl_init.o   \
	src/config.o     \

SERVER_CFLAGS=-Wall -g -Isrc/

SERVER_LFLAGS=-levent -lssl -lcrypto -levent_openssl -llua

$(SERVER_TARGET): $(SERVER_OBJECTS)
	gcc $(SERVER_CFLAGS) -o $@ $^ $(SERVER_LFLAGS)

%.o: %.c
	gcc $(SERVER_CFLAGS) -c -o $@ $^

tests: test/test_iri_parser

test/test_iri_parser: src/iri_parser.c src/log.c
	@mkdir -p $(@D)
	gcc $(SERVER_CFLAGS) -DTEST -o $@ $^

