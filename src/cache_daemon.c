#include "cache_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <signal.h>
#include <ctype.h>
#include <strings.h>

#define CACHE_SOCKET_PATH "/tmp/dnscache.sock"
#define PID_FILE_PATH "/tmp/dnscache.pid"
#define MAX_KEY_LEN 512
#define MAX_VALUE_LEN 256
#define INITIAL_CACHE_CAPACITY 250

typedef struct {
    char key[MAX_KEY_LEN];
    char value[MAX_VALUE_LEN];
    time_t expiry;
    int rcode;
} CacheEntry;

static CacheEntry *positive_cache = NULL;
static CacheEntry *negative_cache = NULL;
static int positive_cache_count = 0;
static int negative_cache_count = 0;
static int positive_cache_max_size = 50;
static int negative_cache_max_size = 50;
static pthread_mutex_t pos_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t neg_cache_lock = PTHREAD_MUTEX_INITIALIZER;

void purge_cache(int *count, pthread_mutex_t *lock) {
    pthread_mutex_lock(lock);
    *count = 0;
    pthread_mutex_unlock(lock);
}

void list_cache_entries(int client_sock, CacheEntry *cache, int count, pthread_mutex_t *lock, const char* cache_name) {
    char header[128];
    int max_size = (strcmp(cache_name, "Positiva") == 0) ? positive_cache_max_size : negative_cache_max_size;
    snprintf(header, sizeof(header), "--- Cache %s (%d/%d) ---\n", cache_name, count, max_size);
    send(client_sock, header, strlen(header), 0);
    pthread_mutex_lock(lock);
    time_t now = time(NULL);
    for (int i = 0; i < count; i++) {
        char entry_str[1024];
        long ttl_left = (long)cache[i].expiry - now;
        if (ttl_left < 0) ttl_left = 0;
        if (cache[i].rcode >= 0) {
             snprintf(entry_str, sizeof(entry_str), "  [%lds] %s (RCODE: %d)\n", ttl_left, cache[i].key, cache[i].rcode);
        } else {
             snprintf(entry_str, sizeof(entry_str), "  [%lds] %s -> %s\n", ttl_left, cache[i].key, cache[i].value);
        }
        send(client_sock, entry_str, strlen(entry_str), 0);
    }
    pthread_mutex_unlock(lock);
}

static void remove_expired_entries() {
    time_t now = time(NULL);
    pthread_mutex_lock(&pos_cache_lock);
    for (int i = 0; i < positive_cache_count; ) {
        if (positive_cache[i].expiry <= now) positive_cache[i] = positive_cache[--positive_cache_count];
        else i++;
    }
    pthread_mutex_unlock(&pos_cache_lock);
    pthread_mutex_lock(&neg_cache_lock);
    for (int i = 0; i < negative_cache_count; ) {
        if (negative_cache[i].expiry <= now) negative_cache[i] = negative_cache[--negative_cache_count];
        else i++;
    }
    pthread_mutex_unlock(&neg_cache_lock);
}

static CacheEntry* find_entry_in_cache(const char* key, CacheEntry* cache, int count, pthread_mutex_t* lock) {
    pthread_mutex_lock(lock);
    time_t now = time(NULL);
    CacheEntry* found = NULL;
    for (int i = 0; i < count; i++) {
        if (strcmp(cache[i].key, key) == 0 && cache[i].expiry > now) {
            found = &cache[i];
            break;
        }
    }
    pthread_mutex_unlock(lock);
    return found;
}

static void put_entry(const char *key, const char *value, int ttl, int rcode) {
    time_t expiry = time(NULL) + ttl;
    CacheEntry *cache;
    int *count, max_size;
    pthread_mutex_t *lock;
    if (rcode >= 0) {
        cache = negative_cache; count = &negative_cache_count; max_size = negative_cache_max_size; lock = &neg_cache_lock;
    } else {
        cache = positive_cache; count = &positive_cache_count; max_size = positive_cache_max_size; lock = &pos_cache_lock;
    }
    pthread_mutex_lock(lock);
    if (*count < max_size) {
        strncpy(cache[*count].key, key, MAX_KEY_LEN-1);
        cache[*count].key[MAX_KEY_LEN-1] = '\0';
        strncpy(cache[*count].value, value, MAX_VALUE_LEN-1);
        cache[*count].value[MAX_VALUE_LEN-1] = '\0';
        cache[*count].expiry = expiry;
        cache[*count].rcode = rcode;
        (*count)++;
    }
    pthread_mutex_unlock(lock);
}

static void *client_thread(void *arg) {
    int client_sock = *(int *)arg;
    free(arg);
    char buf[1024];
    ssize_t n = recv(client_sock, buf, sizeof(buf)-1, 0);
    if (n <= 0) { close(client_sock); return NULL; }
    buf[n] = '\0';
    char *p = strchr(buf, '\n'); if (p) *p = '\0';
    char key[MAX_KEY_LEN], val[MAX_VALUE_LEN], type_str[32];
    int ttl, qtype, rcode, new_size;
    if (sscanf(buf, "GET %490s %d", key, &qtype) == 2) {
        remove_expired_entries();
        char composite_key[MAX_KEY_LEN];
        snprintf(composite_key, sizeof(composite_key), "%.500s:%d", key, qtype);
        composite_key[sizeof(composite_key) - 1] = '\0';
        CacheEntry* e = find_entry_in_cache(composite_key, positive_cache, positive_cache_count, &pos_cache_lock);
        if(e) {
            char resp[1024];
            snprintf(resp, sizeof(resp), "POS %s\n", e->value);
            send(client_sock, resp, strlen(resp), 0);
        } else {
            e = find_entry_in_cache(composite_key, negative_cache, negative_cache_count, &neg_cache_lock);
            if(e) {
                char resp[128];
                snprintf(resp, sizeof(resp), "NEG %d\n", e->rcode);
                send(client_sock, resp, strlen(resp), 0);
            } else {
                send(client_sock, "MISS\n", 5, 0);
            }
        }
    }
    else if (sscanf(buf, "PUT POS %490s %d %255s %d", key, &qtype, val, &ttl) == 4) {
        char composite_key[MAX_KEY_LEN];
        snprintf(composite_key, sizeof(composite_key), "%.500s:%d", key, qtype);
        composite_key[sizeof(composite_key) - 1] = '\0';
        put_entry(composite_key, val, ttl, -1);
        send(client_sock, "OK\n", 3, 0);
    }
    else if (sscanf(buf, "PUT NEG %490s %d %d %d", key, &qtype, &ttl, &rcode) == 4) {
        char composite_key[MAX_KEY_LEN];
        snprintf(composite_key, sizeof(composite_key), "%.500s:%d", key, qtype);
        composite_key[sizeof(composite_key) - 1] = '\0';
        put_entry(composite_key, "", ttl, rcode);
        send(client_sock, "OK\n", 3, 0);
    }
    else if (strcmp(buf, "STATUS") == 0) {
        char resp[256];
        snprintf(resp, sizeof(resp), "Cache Positiva: %d/%d entradas\nCache Negativa: %d/%d entradas\n",
                 positive_cache_count, positive_cache_max_size,
                 negative_cache_count, negative_cache_max_size);
        send(client_sock, resp, strlen(resp), 0);
    }
    else if (strcmp(buf, "PURGE POSITIVE") == 0) {
        purge_cache(&positive_cache_count, &pos_cache_lock);
        send(client_sock, "Cache positiva expurgada.\n", 27, 0);
    }
    else if (strcmp(buf, "PURGE NEGATIVE") == 0) {
        purge_cache(&negative_cache_count, &neg_cache_lock);
        send(client_sock, "Cache negativa expurgada.\n", 27, 0);
    }
    else if (strcmp(buf, "PURGE ALL") == 0) {
        purge_cache(&positive_cache_count, &pos_cache_lock);
        purge_cache(&negative_cache_count, &neg_cache_lock);
        send(client_sock, "Todas as caches foram expurgadas.\n", 34, 0);
    }
    else if (sscanf(buf, "SET %s %d", type_str, &new_size) == 2) {
        if (strcasecmp(type_str, "positive") == 0) positive_cache_max_size = new_size;
        else if (strcasecmp(type_str, "negative") == 0) negative_cache_max_size = new_size;
        send(client_sock, "OK\n", 3, 0);
    }
    else if (strcmp(buf, "LIST POSITIVE") == 0) {
        list_cache_entries(client_sock, positive_cache, positive_cache_count, &pos_cache_lock, "Positiva");
    }
    else if (strcmp(buf, "LIST NEGATIVE") == 0) {
        list_cache_entries(client_sock, negative_cache, negative_cache_count, &neg_cache_lock, "Negativa");
    }
    else if (strcmp(buf, "LIST ALL") == 0) {
        list_cache_entries(client_sock, positive_cache, positive_cache_count, &pos_cache_lock, "Positiva");
        list_cache_entries(client_sock, negative_cache, negative_cache_count, &neg_cache_lock, "Negativa");
    }
    close(client_sock);
    return NULL;
}

void run_daemon() {
    positive_cache = malloc(sizeof(CacheEntry) * INITIAL_CACHE_CAPACITY);
    negative_cache = malloc(sizeof(CacheEntry) * INITIAL_CACHE_CAPACITY);
    if (!positive_cache || !negative_cache) { perror("malloc"); exit(1); }
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) { printf("Daemon ativado com PID: %d\n", pid); exit(0); }
    FILE *pid_file = fopen(PID_FILE_PATH, "w");
    if (pid_file) { fprintf(pid_file, "%d", getpid()); fclose(pid_file); }
    unlink(CACHE_SOCKET_PATH);
    int server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sock < 0) { perror("socket"); exit(1); }
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CACHE_SOCKET_PATH, sizeof(addr.sun_path)-1);
    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); exit(1); }
    if (listen(server_sock, 20) < 0) { perror("listen"); exit(1); }
    while (1) {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock < 0) continue;
        int *sock_ptr = malloc(sizeof(int));
        *sock_ptr = client_sock;
        pthread_t tid;
        pthread_create(&tid, NULL, client_thread, sock_ptr);
        pthread_detach(tid);
    }
}

void send_command_and_print_response(const char *command) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return; }
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CACHE_SOCKET_PATH, sizeof(addr.sun_path)-1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("Não foi possível conectar ao daemon. Ele está ativo?\n");
        close(sock); return;
    }
    send(sock, command, strlen(command), 0);
    send(sock, "\n", 1, 0);
    char resp_buf[4096];
    ssize_t n;
    while ((n = recv(sock, resp_buf, sizeof(resp_buf)-1, 0)) > 0) {
        resp_buf[n] = '\0';
        printf("%s", resp_buf);
    }
    close(sock);
}

void print_usage(const char* prog_name) {
    fprintf(stderr, "Uso: %s <comando>\n", prog_name);
    fprintf(stderr, "Comandos:\n");
    fprintf(stderr, "  --activate\n  --deactivate\n  --status\n");
    fprintf(stderr, "  --set positive|negative <num>\n  --purge positive|negative|all\n");
    fprintf(stderr, "  --list positive|negative|all\n");
}

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);
    if (argc < 2) { print_usage(argv[0]); return 1; }
    const char *command = argv[1];
    if (strcmp(command, "--activate") == 0) {
        run_daemon();
    } else if (strcmp(command, "--deactivate") == 0) {
        FILE *pid_file = fopen(PID_FILE_PATH, "r");
        if (!pid_file) { printf("Daemon não parece estar ativo.\n"); unlink(CACHE_SOCKET_PATH); return 1; }
        pid_t pid;
        if(fscanf(pid_file, "%d", &pid) != 1) { 
            fclose(pid_file); 
            fprintf(stderr, "Erro ao ler PID do arquivo.\n");
            return 1;
        }
        fclose(pid_file);
        if (kill(pid, SIGTERM) == 0) {
            unlink(PID_FILE_PATH);
            unlink(CACHE_SOCKET_PATH);
            printf("Daemon (PID: %d) desativado.\n", pid);
        } else {
            perror("kill");
        }
    } else if (strcmp(command, "--status") == 0) {
        send_command_and_print_response("STATUS");
    } else if (strcmp(command, "--purge") == 0 && argc == 3) {
        char full_cmd[64];
        snprintf(full_cmd, sizeof(full_cmd), "PURGE %s", argv[2]);
        for(char *c = full_cmd; *c; ++c) *c = toupper(*c);
        send_command_and_print_response(full_cmd);
    } else if (strcmp(command, "--set") == 0 && argc == 4) {
        char full_cmd[64];
        snprintf(full_cmd, sizeof(full_cmd), "SET %s %s", argv[2], argv[3]);
        send_command_and_print_response(full_cmd);
    } else if (strcmp(command, "--list") == 0 && argc == 3) {
        char full_cmd[64];
        snprintf(full_cmd, sizeof(full_cmd), "LIST %s", argv[2]);
        for(char *c = full_cmd; *c; ++c) *c = toupper(*c);
        send_command_and_print_response(full_cmd);
    } else {
        print_usage(argv[0]);
        return 1;
    }
    return 0;
}