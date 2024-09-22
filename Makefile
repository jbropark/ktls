CC = gcc
COMMON_FLAGS = -g
OPENSSL_INCLUDES = -I/home/jhpark/.local/ssl/include
LIBS = /home/jhpark/.local/ssl/lib64/libssl.a /home/jhpark/.local/ssl/lib64/libcrypto.a -lpthread

CLIENT_BIN = client
SERVER_BIN = server
WRITE_BIN = write

CLIENT_SRC = ktls_client.c
SERVER_SRC = ktls_server.c
WRITE_SRC = writefile.c

all: $(CLIENT_BIN) $(SERVER_BIN) $(WRITE_BIN)

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CC) -o $@ $^ $(COMMON_FLAGS) $(OPENSSL_INCLUDES) $(LIBS)

$(SERVER_BIN): $(SERVER_SRC)
	$(CC) -o $@ $^ $(COMMON_FLAGS) $(OPENSSL_INCLUDES) $(LIBS)

$(WRITE_BIN): $(WRITE_SRC)
	$(CC) -o $@ $^ $(COMMON_FLAGS)

clean:
	rm -f $(CLIENT_BIN) $(SERVER_BIN) $(WRITE_BIN)

.PHONY: all clean

