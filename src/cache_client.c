#include "cache_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define CACHE_SOCKET_PATH "/tmp/dnscache.sock"   // hmm, talvez tornar isso configurável depois

// Helper para conectar no socket do cache local.
// TODO: talvez adicionar tentativas de reconexão se o socket não estiver pronto.
static int connect_to_cache_socket() {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CACHE_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

// Recupera algo do cache.
// Retorna uma string duplicada (precisa dar free depois) ou NULL se não achou.
char *cache_get(const char *host, int query_type, int *is_negative, int *rcode) {
    if (!host) return NULL; // apenas por segurança

    *is_negative = 0;
    *rcode = 0;

    int sock = connect_to_cache_socket();
    if (sock < 0) {
        fprintf(stderr, "[cache_get] Falha ao conectar no socket do cache.\n");
        return NULL;
    }

    char send_buf[1024];
    snprintf(send_buf, sizeof(send_buf), "GET %s %d\n", host, query_type);

    // Não checando retorno do send — provavelmente ok pra sockets locais.
    send(sock, send_buf, strlen(send_buf), 0);

    char recv_buf[1024];
    int received = recv(sock, recv_buf, sizeof(recv_buf) - 1, 0);
    close(sock);

    if (received <= 0) {
        // Sem dados ou erro
        return NULL;
    }

    recv_buf[received] = '\0';  // garantir terminação nula

    if (strncmp(recv_buf, "POS ", 4) == 0) {
        char *value = strdup(recv_buf + 4);
        if (!value) return NULL; // raro, mas pode falhar

        // Remover o newline (deve ter um)
        char *nl = strchr(value, '\n');
        if (nl) *nl = '\0';
        return value;
    } 
    else if (strncmp(recv_buf, "NEG ", 4) == 0) {
        *is_negative = 1;
        // Parsing meio preguiçoso, mas funciona
        sscanf(recv_buf, "NEG %d", rcode);
        return NULL;
    }

    else if (strncmp(recv_buf, "MISS", 4) == 0) {
        // É um cache miss. Apenas retorne NULL sem imprimir nada.
        return NULL;
    }

    // Resposta inesperada — talvez o protocolo mudou?
    fprintf(stderr, "Resposta inesperada do cache: %s\n", recv_buf);
    return NULL;
}

// Coloca uma resposta positiva no cache (hostname resolvido com sucesso).
void cache_put_positive(const char *host, int qtype, int ttl, const char *val) {
    if (!host || !val) return;

    int fd = connect_to_cache_socket();
    if (fd < 0) {
        fprintf(stderr, "[cache_put_positive] Não foi possível abrir o socket do cache.\n");
        return;
    }

    char buf[1024];
    // Poderia quebrar se 'val' for muito grande, mas vamos assumir que não é o caso.
    snprintf(buf, sizeof(buf), "PUT POS %s %d %s %d\n", host, qtype, val, ttl);
    send(fd, buf, strlen(buf), 0);
    close(fd);
}

// Coloca uma resposta negativa no cache (ex: NXDOMAIN ou timeout)
void cache_put_negative(const char *hostname, int qtype, int ttl, int rcode) {
    int fd = connect_to_cache_socket();
    if (fd < 0) {
        // Poderia logar, mas por enquanto só ignoramos
        return;
    }

    char out[512];  // menor buffer, resposta curta
    snprintf(out, sizeof(out), "PUT NEG %s %d %d %d\n", hostname, qtype, ttl, rcode);

    // Não checando retorno — ok pra socket local
    send(fd, out, strlen(out), 0);
    close(fd);

    // NOTE: talvez adicionar uma flag de debug pra logar respostas negativas
}
