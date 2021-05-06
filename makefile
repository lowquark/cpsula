
TARGET=cpsula

all: $(TARGET) test/test_iri_parser

$(TARGET): src/main.o src/server.o src/sigs.o src/log.o src/luaenv.o src/iri_parser.o
	gcc -Wall -g -o $@ $^ -levent -lssl -lcrypto -levent_openssl -llua

test/test_iri_parser: src/iri_parser.c src/log.c
	@mkdir -p $(@D)
	gcc -Wall -g -Isrc/ -DTEST -o $@ $^

%.o: %.c
	gcc -Wall -g -Isrc/ -c -o $@ $^

