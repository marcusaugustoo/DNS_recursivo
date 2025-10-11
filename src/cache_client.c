#include "cache_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define CACHE_SOCKET_PATH "/tmp/dnscache.sock"

static int connect_cache() {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CACHE_SOCKET_PATH, sizeof(addr.sun_path)-1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

char *cache_get(const char *hostname, int qtype, int *is_neg, int *rcode) {
    *is_neg = 0;
    *rcode = 0;
    int sock = connect_cache();
    if (sock < 0) return NULL;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "GET %s %d\n", hostname, qtype);
    send(sock, cmd, strlen(cmd), 0);

    char resp[1024];
    int n = recv(sock, resp, sizeof(resp)-1, 0);
    close(sock);
    if (n <= 0) return NULL;
    resp[n] = '\0';

    if (strncmp(resp, "POS ", 4) == 0) {
        char* value = strdup(resp + 4);
        char* newline = strchr(value, '\n');
        if (newline) *newline = '\0';
        return value;
    } else if (strncmp(resp, "NEG ", 4) == 0) {
        *is_neg = 1;
        sscanf(resp, "NEG %d", rcode);
        return NULL;
    }
    return NULL;
}

void cache_put_positive(const char *hostname, int qtype, int ttl, const char *value) {
    int sock = connect_cache();
    if (sock < 0) return;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "PUT POS %s %d %s %d\n", hostname, qtype, value, ttl);
    send(sock, cmd, strlen(cmd), 0);
    close(sock);
}

void cache_put_negative(const char *hostname, int qtype, int ttl, int rcode) {
    int sock = connect_cache();
    if (sock < 0) return;
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "PUT NEG %s %d %d %d\n", hostname, qtype, ttl, rcode);
    send(sock, cmd, strlen(cmd), 0);
    close(sock);
}