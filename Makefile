# Makefile para compilação com diretórios src/ e build/

# --- Variáveis de Configuração ---

# Compilador
CC = gcc

# Diretórios
SRCDIR = src
BUILDDIR = build

# Flags do compilador
# -I$(SRCDIR): Adiciona o diretório 'src' à busca por arquivos de cabeçalho (.h)
CFLAGS = -Wall -g -pthread -I$(SRCDIR)

# Flags do linker para o resolver
LDFLAGS_RESOLVER = -lssl -lcrypto

# --- Definição dos Alvos (Executáveis) ---

TARGET_RESOLVER = dns_resolver
TARGET_CACHE = dns_cache

# --- Definição dos Arquivos-Fonte e Objeto ---

# Nomes base dos arquivos-fonte para cada alvo
BASE_SRCS_RESOLVER = main.c resolver.c dns_utils.c cache_client.c
BASE_SRCS_CACHE = cache_daemon.c cache_client.c

# Adiciona o prefixo do diretório de fontes (src/)
SRCS_RESOLVER = $(addprefix $(SRCDIR)/, $(BASE_SRCS_RESOLVER))
SRCS_CACHE = $(addprefix $(SRCDIR)/, $(BASE_SRCS_CACHE))

# Gera os nomes dos arquivos-objeto, colocando-os no diretório de build (build/)
OBJS_RESOLVER = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS_RESOLVER))
OBJS_CACHE = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS_CACHE))

# --- Regras de Compilação ---

# Regra padrão: compila ambos os executáveis
.PHONY: all
all: $(TARGET_RESOLVER) $(TARGET_CACHE)

# Regra para vincular (link) o executável dns_resolver
# Depende dos seus arquivos-objeto. O pipe | significa que $(BUILDDIR) é uma
# dependência de ordem, ou seja, deve existir antes, mas mudanças nele não
# disparam uma recompilação.
$(TARGET_RESOLVER): $(OBJS_RESOLVER)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS_RESOLVER)

# Regra para vincular (link) o executável dns_cache
$(TARGET_CACHE): $(OBJS_CACHE)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) -o $@ $^

# Regra para criar o diretório de build antes de qualquer compilação
# É uma pré-condição para a compilação dos arquivos .o
$(BUILDDIR):
	@echo "Creating build directory..."
	@mkdir -p $(BUILDDIR)

# Regra de padrão para compilar arquivos .c de 'src/' para .o em 'build/'
# A criação de $(BUILDDIR) é uma dependência de ordem aqui também.
$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c -o $@ $<

# --- Regra de Limpeza ---

# Remove os executáveis e o diretório de build
.PHONY: clean
clean:
	@echo "Cleaning up..."
	rm -f $(TARGET_RESOLVER) $(TARGET_CACHE)
	rm -rf $(BUILDDIR)