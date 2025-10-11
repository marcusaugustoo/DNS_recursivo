#include "resolver.h"
#include "dns_utils.h"
#include "cache_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <sys/time.h>

#define RCODE_MASK 0x000F
#define TC_MASK 0x0200
#define AA_MASK 0x0400
#define TYPE_OPT 41

#define MAX_SERVERS 50
#define MAX_NS 20
#define MAX_DEPTH 10
#define MAX_LOOP_QUERIES 200

#define COLOR_INFO  "\033[1;34m"
#define COLOR_WARN  "\033[1;33m"
#define COLOR_ERR   "\033[1;31m"
#define COLOR_OK    "\033[1;32m"
#define COLOR_RESET "\033[0m"

static int dot_enabled = 0;
static char dot_sni[256] = {0};

/* --- Suporte a --mode e --trust-anchor --- */
static char resolver_mode[32] = "recursive";
static char trust_anchor_path[512] = {0};
static char trust_anchor_data[8192] = {0};

void resolver_set_mode(const char *mode) {
    if (!mode) return;
    strncpy(resolver_mode, mode, sizeof(resolver_mode) - 1);
    resolver_mode[sizeof(resolver_mode) - 1] = '\0';
    fprintf(stderr, "[INFO] Resolver mode set to: %s\n", resolver_mode);
}

int resolver_load_trust_anchor(const char *path) {
    if (!path) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "[WARN] Não foi possível abrir trust-anchor '%s'.\n", path);
        return -1;
    }
    size_t n = fread(trust_anchor_data, 1, sizeof(trust_anchor_data) - 1, f);
    fclose(f);
    trust_anchor_data[n] = '\0';
    strncpy(trust_anchor_path, path, sizeof(trust_anchor_path) - 1);
    trust_anchor_path[sizeof(trust_anchor_path) - 1] = '\0';
    fprintf(stderr, "[INFO] Trust-anchor carregado de '%s' (%zu bytes)\n",
            trust_anchor_path, n);
    return 0;
}

void resolver_set_dot(int enabled, const char *sni) {
    dot_enabled = enabled ? 1 : 0;
    if (sni && sni[0]) {
        strncpy(dot_sni, sni, sizeof(dot_sni)-1);
        dot_sni[sizeof(dot_sni)-1] = '\0';
    } else {
        dot_sni[0] = '\0';
    }
}

static int add_edns_opt_record(unsigned char *buffer, int current_size) {
    unsigned char *p = buffer + current_size;
    *p++ = 0x00;
    *((uint16_t*)p) = htons(TYPE_OPT); p += 2;
    *((uint16_t*)p) = htons(4096);     p += 2;
    *((uint32_t*)p) = htonl(0);        p += 4;
    *((uint16_t*)p) = htons(0);        p += 2;
    return (p - buffer);
}

/* ---- Implementações de envio ---- */

static int send_and_receive_tcp(const char *server_ip,
                                unsigned char *query_buffer,
                                int query_size,
                                unsigned char *response_buffer,
                                int response_buffer_size) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sockfd);
        return -1;
    }
    uint16_t len_net = htons(query_size);
    if (send(sockfd, &len_net, 2, 0) != 2) { close(sockfd); return -1; }
    if (send(sockfd, query_buffer, query_size, 0) != query_size) { close(sockfd); return -1; }
    uint16_t resp_len_net;
    if (recv(sockfd, &resp_len_net, 2, 0) < 2) { close(sockfd); return -1; }
    int resp_len = ntohs(resp_len_net);
    if (resp_len > response_buffer_size) { close(sockfd); return -1; }
    int total_read = 0;
    while (total_read < resp_len) {
        int n = recv(sockfd, response_buffer + total_read, resp_len - total_read, 0);
        if (n <= 0) { close(sockfd); return -1; }
        total_read += n;
    }
    close(sockfd);
    return total_read;
}

static int send_and_receive_udp(const char *server_ip,
                                unsigned char *query_buffer,
                                int query_size,
                                unsigned char *response_buffer,
                                int response_buffer_size,
                                int timeout_sec) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, server_ip, &addr.sin_addr);
    struct timeval timeout = {timeout_sec, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    if (sendto(sockfd, query_buffer, query_size, 0, (struct sockaddr*)&addr, sizeof(addr)) != query_size) {
        close(sockfd);
        return -1;
    }
    int n = recvfrom(sockfd, response_buffer, response_buffer_size, 0, NULL, NULL);
    close(sockfd);
    return n;
}

static int send_and_receive_dot(const char *server_ip,
                                const char *sni_hostname,
                                unsigned char *query_buffer,
                                int query_size,
                                unsigned char *response_buffer,
                                int response_buffer_size) {
    int ret = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    const SSL_METHOD *method = TLS_client_method();
    if (!method) return -1;
    ctx = SSL_CTX_new(method);
    if (!ctx) return -1;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { SSL_CTX_free(ctx); return -1; }
    struct sockaddr_in servaddr = {0};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(853);
    if (inet_pton(AF_INET, server_ip, &servaddr.sin_addr) != 1) { close(sockfd); SSL_CTX_free(ctx); return -1; }
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) { close(sockfd); SSL_CTX_free(ctx); return -1; }
    ssl = SSL_new(ctx);
    if (!ssl) { close(sockfd); SSL_CTX_free(ctx); return -1; }
    if (sni_hostname) SSL_set_tlsext_host_name(ssl, sni_hostname);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) goto cleanup;
    if (SSL_get_verify_result(ssl) != X509_V_OK) goto cleanup;
    uint16_t len_net = htons((uint16_t)query_size);
    if (SSL_write(ssl, &len_net, 2) != 2) goto cleanup;
    if (SSL_write(ssl, query_buffer, query_size) != query_size) goto cleanup;
    unsigned char lenbuf[2];
    if (SSL_read(ssl, lenbuf, 2) != 2) goto cleanup;
    uint16_t resp_len = ntohs(*(uint16_t*)lenbuf);
    if (resp_len > response_buffer_size) goto cleanup;
    int total_read = 0;
    while (total_read < resp_len) {
        int n = SSL_read(ssl, response_buffer + total_read, resp_len - total_read);
        if (n <= 0) goto cleanup;
        total_read += n;
    }
    ret = total_read;
cleanup:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    close(sockfd);
    SSL_CTX_free(ctx);
    return ret;
}

/* --- Fan-out (threads para resolver múltiplos NS) --- */

struct ThreadArg {
    char ns_name[256];
    const char *start_server_ip;
    uint16_t qtype;
    int depth;
    int trace_mode;
    int timeout_sec;
    char *result;
};

static void *resolve_thread(void *arg) {
    struct ThreadArg *a = (struct ThreadArg*)arg;
    a->result = resolve_iterative(a->ns_name, a->start_server_ip,
                                  TYPE_A, a->depth + 1,
                                  a->trace_mode, a->timeout_sec);
    return NULL;
}

/* --- Função principal de resolução --- */

char* resolve_iterative(const char *hostname_to_resolve,
                        const char *start_server_ip,
                        uint16_t qtype,
                        int depth,
                        int trace_mode,
                        int timeout_sec) {
    if (depth > MAX_DEPTH) return NULL;

    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    char server_list[MAX_SERVERS][INET_ADDRSTRLEN];
    int server_count = 1;
    snprintf(server_list[0], INET_ADDRSTRLEN, "%s", start_server_ip);

    char current_hostname[256];
    strncpy(current_hostname, hostname_to_resolve, sizeof(current_hostname) - 1);
    current_hostname[sizeof(current_hostname) - 1] = '\0';

    int query_count = 0;
    while (server_count > 0 && query_count++ < MAX_LOOP_QUERIES) {
        char current_server_ip[INET_ADDRSTRLEN];
        strcpy(current_server_ip, server_list[--server_count]);

        if (trace_mode)
            printf(COLOR_INFO "\n[depth %d]" COLOR_RESET " Consultando %s por '%s' (tipo=%d)\n",
                   depth, current_server_ip, current_hostname, qtype);

        int is_neg = 0;
        int cached_rcode = 0;
        char *cached = cache_get(current_hostname, qtype, &is_neg, &cached_rcode);

        if (cached) {
            if (trace_mode) printf(COLOR_OK "[CACHE HIT]" COLOR_RESET " %s -> %s\n", current_hostname, cached);
            gettimeofday(&end_time, NULL);
            double elapsed = (end_time.tv_sec - start_time.tv_sec) * 1000.0;
            elapsed += (end_time.tv_usec - start_time.tv_usec) / 1000.0;
            if (trace_mode) printf(COLOR_INFO "[TEMPO]" COLOR_RESET " %.2f ms\n", elapsed);
            return cached;
        } else if (is_neg) {
            if (trace_mode) printf(COLOR_WARN "[CACHE NEG]" COLOR_RESET " %s (rcode=%d)\n", current_hostname, cached_rcode);
            gettimeofday(&end_time, NULL);
            double elapsed = (end_time.tv_sec - start_time.tv_sec) * 1000.0;
            elapsed += (end_time.tv_usec - start_time.tv_usec) / 1000.0;
            if (trace_mode) printf(COLOR_INFO "[TEMPO]" COLOR_RESET " %.2f ms\n", elapsed);
            return NULL;
        }

        unsigned char query[4096], response[65536];
        memset(query, 0, sizeof(query));

        struct DnsHeader *hdr = (struct DnsHeader*)query;
        hdr->id = htons(getpid() + query_count);
        hdr->flags = htons(0x0000);
        hdr->qdcount = htons(1);
        hdr->arcount = htons(1);

        unsigned char *qname = query + sizeof(struct DnsHeader);
        format_dns_name(qname, current_hostname);
        struct DnsQuestion *qinfo = (struct DnsQuestion*)(qname + strlen((char*)qname) + 1);
        qinfo->qtype = htons(qtype);
        qinfo->qclass = htons(1);

        int packet_size = sizeof(struct DnsHeader) + strlen((char*)qname) + 1 + sizeof(struct DnsQuestion);
        packet_size = add_edns_opt_record(query, packet_size);

        int recv_size = -1;
        if (dot_enabled) {
            recv_size = send_and_receive_dot(current_server_ip, dot_sni, query, packet_size, response, sizeof(response));
        } else {
            recv_size = send_and_receive_udp(current_server_ip, query, packet_size, response, sizeof(response), timeout_sec);
        }

        if (recv_size < 0) {
            if (trace_mode) printf(COLOR_WARN "[WARN]" COLOR_RESET " Sem resposta de %s\n", current_server_ip);
            continue;
        }

        struct DnsHeader *resp_hdr = (struct DnsHeader*)response;
        uint16_t flags = ntohs(resp_hdr->flags);

        if (!dot_enabled && (flags & TC_MASK)) {
            if (trace_mode) printf(COLOR_WARN "[INFO]" COLOR_RESET " Resposta truncada (TC=1). Tentando TCP...\n");
            recv_size = send_and_receive_tcp(current_server_ip, query, packet_size, response, sizeof(response));
            if (recv_size < 0) continue;
            resp_hdr = (struct DnsHeader*)response;
            flags = ntohs(resp_hdr->flags);
        }

        uint16_t rcode = flags & RCODE_MASK;
        if (rcode != 0) {
            if (rcode == 3) {
                if (trace_mode) printf(COLOR_WARN "[INFO]" COLOR_RESET " NXDOMAIN: %s não existe.\n", current_hostname);
                cache_put_negative(current_hostname, qtype, 60, 3);
            }
            gettimeofday(&end_time, NULL);
            double elapsed = (end_time.tv_sec - start_time.tv_sec) * 1000.0;
            elapsed += (end_time.tv_usec - start_time.tv_usec) / 1000.0;
            if (trace_mode) printf(COLOR_INFO "[TEMPO]" COLOR_RESET " %.2f ms\n", elapsed);
            return NULL;
        }

        unsigned char *reader = response + sizeof(struct DnsHeader);
        char name_buf[256];
        reader += decode_dns_name(reader, response, name_buf);
        reader += sizeof(struct DnsQuestion);

        int ancount = ntohs(resp_hdr->ancount);
        int nscount = ntohs(resp_hdr->nscount);

        if ((flags & AA_MASK) && rcode == 0 && ancount == 0 && nscount > 0) {
            if (trace_mode) printf(COLOR_WARN "[INFO]" COLOR_RESET " NODATA: O nome '%s' existe, mas não para o tipo solicitado.\n", current_hostname);
            cache_put_negative(current_hostname, qtype, 60, 0);
            gettimeofday(&end_time, NULL);
            double elapsed = (end_time.tv_sec - start_time.tv_sec) * 1000.0;
            elapsed += (end_time.tv_usec - start_time.tv_usec) / 1000.0;
            if (trace_mode) printf(COLOR_INFO "[TEMPO]" COLOR_RESET " %.2f ms\n", elapsed);
            return NULL;
        }

        for (int i = 0; i < ancount; i++) {
            char rr_name[256], rdata_str[256];
            reader += decode_dns_name(reader, response, rr_name);
            struct RrData *rr = (struct RrData*)reader;
            reader += sizeof(struct RrData);

            uint16_t type = ntohs(rr->type);
            uint16_t rdlen = ntohs(rr->rdlength);
            uint32_t rr_ttl = ntohl(rr->ttl);

            if (type == qtype && strcmp(rr_name, current_hostname) == 0) {
                if (type == TYPE_A) {
                    inet_ntop(AF_INET, reader, rdata_str, INET_ADDRSTRLEN);
                    char *res = strdup(rdata_str);
                    if (trace_mode) printf(COLOR_OK "[RESPOSTA]" COLOR_RESET " %s -> %s (ttl=%u)\n", rr_name, rdata_str, rr_ttl);
                    cache_put_positive(rr_name, type, rr_ttl, rdata_str);
                    gettimeofday(&end_time, NULL);
                    double elapsed = (end_time.tv_sec - start_time.tv_sec) * 1000.0;
                    elapsed += (end_time.tv_usec - start_time.tv_usec) / 1000.0;
                    if (trace_mode) printf(COLOR_INFO "[TEMPO]" COLOR_RESET " %.2f ms\n", elapsed);
                    return res;
                }
            } else if (type == TYPE_CNAME) {
                decode_dns_name(reader, response, rdata_str);
                if (trace_mode) printf(COLOR_INFO "[INFO]" COLOR_RESET " CNAME: %s → %s\n", rr_name, rdata_str);
                gettimeofday(&end_time, NULL);
                double elapsed = (end_time.tv_sec - start_time.tv_sec) * 1000.0;
                elapsed += (end_time.tv_usec - start_time.tv_usec) / 1000.0;
                if (trace_mode) printf(COLOR_INFO "[TEMPO]" COLOR_RESET " %.2f ms\n", elapsed);
                return resolve_iterative(rdata_str, start_server_ip, qtype, depth + 1, trace_mode, timeout_sec);
            }
            reader += rdlen;
        }

        int arcount = ntohs(resp_hdr->arcount);
        char ns_names[MAX_NS][256];
        int ns_count = 0;

        for (int i = 0; i < nscount; i++) {
            char rr_name[256];
            reader += decode_dns_name(reader, response, rr_name);
            struct RrData *rr = (struct RrData*)reader;
            reader += sizeof(struct RrData);
            if (ntohs(rr->type) == TYPE_NS) {
                decode_dns_name(reader, response, ns_names[ns_count++]);
            }
            reader += ntohs(rr->rdlength);
        }

        int glue_found = 0;
        for (int i = 0; i < arcount; i++) {
            char rr_name[256], ipstr[INET_ADDRSTRLEN];
            reader += decode_dns_name(reader, response, rr_name);
            struct RrData *rr = (struct RrData*)reader;
            reader += sizeof(struct RrData);
            if (ntohs(rr->type) == TYPE_A) {
                inet_ntop(AF_INET, reader, ipstr, sizeof(ipstr));
                snprintf(server_list[server_count++], INET_ADDRSTRLEN, "%s", ipstr);
                glue_found++;
            }
            reader += ntohs(rr->rdlength);
        }

        if (glue_found > 0) continue;

        /* --- FAN-OUT MULTITHREAD --- */
        pthread_t tids[MAX_NS];
        struct ThreadArg args[MAX_NS];
        int active_threads = 0;

        for (int i = 0; i < ns_count && i < MAX_NS; i++) {
            memset(&args[i], 0, sizeof(args[i]));
            strncpy(args[i].ns_name, ns_names[i], sizeof(args[i].ns_name) - 1);
            args[i].start_server_ip = start_server_ip;
            args[i].qtype = TYPE_A;
            args[i].depth = depth;
            args[i].trace_mode = trace_mode;
            args[i].timeout_sec = timeout_sec;
            pthread_create(&tids[i], NULL, resolve_thread, &args[i]);
            active_threads++;
        }

        for (int i = 0; i < active_threads; i++) {
            pthread_join(tids[i], NULL);
            if (args[i].result) {
                if (server_count < MAX_SERVERS)
                    snprintf(server_list[server_count++], INET_ADDRSTRLEN, "%s", args[i].result);
                free(args[i].result);
            }
        }
        /* --- FIM FAN-OUT --- */
    }

    gettimeofday(&end_time, NULL);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) * 1000.0;
    elapsed += (end_time.tv_usec - start_time.tv_usec) / 1000.0;
    if (trace_mode) printf(COLOR_INFO "[TEMPO]" COLOR_RESET " %.2f ms\n", elapsed);

    return NULL;
}
