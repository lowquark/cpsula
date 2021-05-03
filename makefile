
lançar: src/main.c src/server.c src/sigs.c src/log.c
	gcc -g -Isrc/ -o $@ $^ -levent -lssl -lcrypto

