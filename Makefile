# Makefile para compilação com diretórios src/ e build/

# Compilador
CC = gcc

# Diretórios
SRCDIR = src
BUILDDIR = build

# Flags do compilador
CFLAGS = -Wall -g -pthread -I$(SRCDIR)

# Flags do linker para o resolver
LDFLAGS_RESOLVER = -lssl -lcrypto

TARGET_RESOLVER = dns_resolver
TARGET_CACHE = cache_daemon 

# Nomes base dos arquivos-fonte para cada alvo
BASE_SRCS_RESOLVER = main.c resolver.c dns_utils.c cache_client.c
BASE_SRCS_CACHE = cache_daemon.c cache_client.c

# Adiciona o prefixo do diretório de fontes (src/)
SRCS_RESOLVER = $(addprefix $(SRCDIR)/, $(BASE_SRCS_RESOLVER))
SRCS_CACHE = $(addprefix $(SRCDIR)/, $(BASE_SRCS_CACHE))

# Gera os nomes dos arquivos-objeto, colocando-os no diretório de build (build/)
OBJS_RESOLVER = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS_RESOLVER))
OBJS_CACHE = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS_CACHE))

# Regra padrão: compila ambos os executáveis
.PHONY: all
all: $(TARGET_RESOLVER) $(TARGET_CACHE)

# Regra para vincular o executável dns_resolver
$(TARGET_RESOLVER): $(OBJS_RESOLVER)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_RESOLVER)

# Regra para vincular o executável cache_daemon
$(TARGET_CACHE): $(OBJS_CACHE)
	$(CC) $(CFLAGS) -o $@ $^

# Regra para criar o diretório de build antes de qualquer compilação
$(BUILDDIR):
	@echo "CRIANDO DIRETÓRIO"
	@mkdir -p $(BUILDDIR)

# Regra de padrão para compilar arquivos .c de 'src/' para .o em 'build/'
$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	@echo "COMPILANDO"
	$(CC) $(CFLAGS) -c -o $@ $<

# Remove os executáveis e o diretório de build
.PHONY: clean
clean:
	@echo "LIMPANDO"
	rm -f $(TARGET_RESOLVER) $(TARGET_CACHE)
	rm -rf $(BUILDDIR)