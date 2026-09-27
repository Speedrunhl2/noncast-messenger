CC = gcc

CFLAGS = -Wall -Wextra -Iinclude
LDLIBS = -lssl -lcrypto

CLIENT_BIN = client
SERVER_BIN = server
LAUNCHER_BIN = launcher

CLIENT_SRC = src/client/client.c src/client/tls.c
SERVER_SRC = src/server/server.c src/server/tor.c src/server/tls.c
LAUNCHER_SRC = src/launcher/launcher.c \
               src/server/tor.c \
               src/server/tls.c \
               src/server/server.c \
               src/client/client.c \
               src/client/tls.c \
	       src/crypto/hash_create.c

.PHONY: all clean

all: $(CLIENT_BIN) $(SERVER_BIN) $(LAUNCHER_BIN)

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(SERVER_BIN): $(SERVER_SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(LAUNCHER_BIN): $(LAUNCHER_SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) -lsodium

clean:
	rm -f $(CLIENT_BIN) $(SERVER_BIN) $(LAUNCHER_BIN)
