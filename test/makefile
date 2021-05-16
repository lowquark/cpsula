
all: test_iri_parser test_config test_luaenv

SERVER_CFLAGS='-DCFG_ETC_DIRECTORY="$(CFG_ETC_DIRECTORY)"' \
              '-DCFG_SHARE_DIRECTORY="$(CFG_SHARE_DIRECTORY)"' \
							-DOPENSSL_API_COMPAT=0x10100000L -DOPENSSL_NO_DEPRECATED \
							-Wall -g -I../src/ -I.

test_iri_parser: ../src/iri_parser.c ../src/log.c
	@mkdir -p $(@D)
	gcc $(SERVER_CFLAGS) -DTEST -o $@ $^

test_config: ../src/config.c ../src/log.c
	@mkdir -p $(@D)
	gcc $(SERVER_CFLAGS) -DTEST -o $@ $^

test_luaenv: ../src/luaenv.c ../src/log.c
	@mkdir -p $(@D)
	gcc $(SERVER_CFLAGS) -DTEST -o $@ $^ -llua

.PHONY: test
test:
	./test_iri_parser
	./test_config
	./test_luaenv

