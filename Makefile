# Nome do compilador
CC=gcc

# Flags de compilação: -Wall (mostra todos os avisos), -g (informações para debug)
CFLAGS=-Wall -g

# Nome do executável final
TARGET=dns_resolver

# Pasta onde os fontes estão
SRCDIR=src

# Lista de todos os arquivos fonte .c
SOURCES=$(wildcard $(SRCDIR)/*.c)

# Substitui a extensão .c por .o para criar a lista de arquivos objeto
OBJECTS=$(SOURCES:.c=.o)

# Regra principal: criar o executável
all: $(TARGET)

# Regra para linkar os arquivos objeto e criar o executável final
$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS)

# Regra para compilar cada arquivo .c em um arquivo .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Regra para limpar os arquivos compilados
clean:
	rm -f $(OBJECTS) $(TARGET)