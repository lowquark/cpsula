
TARGET=lançar

all: $(TARGET) test_uri_parser

$(TARGET): src/main.c src/server.c src/sigs.c src/log.c src/script.c src/uri_parser.c
	gcc -g -Isrc/ -o $@ $^ -levent -lssl -lcrypto -levent_openssl -Wall -llua

test_uri_parser: src/uri_parser.c src/log.c
	gcc -DTEST -g -Isrc/ -o $@ $^

