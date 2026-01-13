CC = gcc
CFLAGS = -O2 -Wall
LIBS = -lsodium

all: bin zettel_server zettel_client keygen

bin:
    mkdir -p bin

zettel_server: src/zettel_server.c
    $(CC) $(CFLAGS) src/zettel_server.c -o bin/zettel_server $(LIBS)

zettel_client: src/zettel_client.c
    $(CC) $(CFLAGS) src/zettel_client.c -o bin/zettel_client $(LIBS)

keygen: src/keygen.c
    $(CC) $(CFLAGS) src/keygen.c -o bin/keygen $(LIBS)

clean:
    rm -rf bin
