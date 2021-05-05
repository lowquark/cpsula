
TARGET=lançar

all: $(TARGET) test_uri_parser

$(TARGET): src/main.o src/server.o src/sigs.o src/log.o src/script.o src/uri_parser.o
	gcc -Wall -g -o $@ $^ -levent -lssl -lcrypto -levent_openssl -llua

test_uri_parser: src/uri_parser.c src/log.c
	gcc -Wall -g -Isrc/ -DTEST -o $@ $^

%.o: %.c
	gcc -Wall -g -Isrc/ -c -o $@ $^

