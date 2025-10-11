# Nome do compilador
CC = gcc

# Flags de compilação
CFLAGS = -Wall -g -pthread

# Arquivos-fonte
SRC = main.c resolver.c dns_utils.c cache_client.c cache_daemon.c

# Executáveis
TARGET_RESOLVER = dns_resolver
TARGET_CACHE = dns_cache

# Regra padrão
all: $(TARGET_RESOLVER) $(TARGET_CACHE)

$(TARGET_RESOLVER): main.c resolver.c dns_utils.c cache_client.c
	$(CC) $(CFLAGS) -o $(TARGET_RESOLVER) main.c resolver.c dns_utils.c cache_client.c -lssl -lcrypto

$(TARGET_CACHE): cache_daemon.c cache_client.c
	$(CC) $(CFLAGS) -o $(TARGET_CACHE) cache_daemon.c cache_client.c

clean:
	rm -f $(TARGET_RESOLVER) $(TARGET_CACHE) *.o
