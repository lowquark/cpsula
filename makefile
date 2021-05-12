
# Linux with systemd

CFG_ETC_DIRECTORY=/etc/cpsula
CFG_SHARE_DIRECTORY=/usr/share/cpsula

SERVER_TARGET=cpsula

SERVER_OBJECTS=    \
	src/main.o       \
	src/server.o     \
	src/sigs.o       \
	src/log.o        \
	src/luaenv.o     \
	src/iri_parser.o \
	src/tls.o        \
	src/config.o     \

SERVER_CFLAGS='-DCFG_ETC_DIRECTORY="$(CFG_ETC_DIRECTORY)"' \
              '-DCFG_SHARE_DIRECTORY="$(CFG_SHARE_DIRECTORY)"' \
							-DOPENSSL_API_COMPAT=0x10100000L -DOPENSSL_NO_DEPRECATED \
							-Wall -g -Isrc/

SERVER_LFLAGS=-levent -lssl -lcrypto -levent_openssl -llua

$(SERVER_TARGET): $(SERVER_OBJECTS)
	gcc $(SERVER_CFLAGS) -o $@ $^ $(SERVER_LFLAGS)

%.o: %.c
	gcc $(SERVER_CFLAGS) -c -o $@ $^

tests: test/test_iri_parser test/test_config

test/test_iri_parser: src/iri_parser.c src/log.c
	@mkdir -p $(@D)
	gcc $(SERVER_CFLAGS) -DTEST -o $@ $^

test/test_config: src/config.c src/log.c
	@mkdir -p $(@D)
	gcc $(SERVER_CFLAGS) -DTEST -o $@ $^

test/test_luaenv: src/luaenv.c src/log.c
	@mkdir -p $(@D)
	gcc $(SERVER_CFLAGS) -DTEST -o $@ $^ -llua

INSTALL_ROOT=./pkg
.PHONY: install
install:
	install -Dm755 "cpsula"                         "$(INSTALL_ROOT)/usr/bin/cpsula"
	install -Dm644 "contrib/systemd/cpsula.service" "$(INSTALL_ROOT)/usr/lib/systemd/system/cpsula.service"
	install -Dm644 "contrib/cpsula.conf"            "$(INSTALL_ROOT)$(CFG_ETC_DIRECTORY)/cpsula.conf"
	install -dm755 "$(INSTALL_ROOT)$(CFG_SHARE_DIRECTORY)/ssl"
	install -dm755 "$(INSTALL_ROOT)$(CFG_ETC_DIRECTORY)/ssl"

