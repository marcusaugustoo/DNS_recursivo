// resolver.c

#include "resolver.h"
#include "dns_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void resolve_iterative(const char *hostname_to_resolve, const char *root_server_ip) {
    
    char server_list[20][INET_ADDRSTRLEN];
    int server_count = 0;

    strcpy(server_list[0], root_server_ip);
    server_count = 1;

    char current_hostname[256];
    strcpy(current_hostname, hostname_to_resolve);

    int max_queries = 30;
    int query_count = 0;

    while (server_count > 0 && query_count++ < max_queries) {
        
        char current_server_ip[INET_ADDRSTRLEN];
        strcpy(current_server_ip, server_list[--server_count]);

        printf("\n[Passo %d] Consultando %s por '%s'...\n", query_count, current_server_ip, current_hostname);

        unsigned char buffer[65536];
        int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(53);
        inet_pton(AF_INET, current_server_ip, &server_addr.sin_addr);

        memset(buffer, 0, sizeof(buffer));
        struct DnsHeader *dns_header = (struct DnsHeader *)buffer;
        dns_header->id = htons(getpid() + query_count);
        dns_header->rd = 0;
        dns_header->qdcount = htons(1);

        unsigned char *query_name = buffer + sizeof(struct DnsHeader);
        format_dns_name(query_name, current_hostname);

        struct DnsQuestion *question_info = (struct DnsQuestion *)(query_name + strlen((const char*)query_name) + 1);
        question_info->qtype = htons(TYPE_A);
        question_info->qclass = htons(1);

        int packet_size = sizeof(struct DnsHeader) + strlen((const char*)query_name) + 1 + sizeof(struct DnsQuestion);
        
        sendto(sockfd, buffer, packet_size, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

        int recv_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
        close(sockfd);

        if (recv_size < 0) {
            printf("Erro na consulta. Tentando próximo servidor...\n");
            continue;
        }

        struct DnsHeader *response_header = (struct DnsHeader *)buffer;
        unsigned char *reader = buffer + packet_size;

        if (ntohs(response_header->ancount) > 0) {
            int found_a = 0;
            for (int i = 0; i < ntohs(response_header->ancount); i++) {
                char name[256], rdata_str[256];
                int name_bytes = decode_dns_name(reader, buffer, name);
                reader += name_bytes;
                struct RrData *rr = (struct RrData *)reader;
                reader += sizeof(struct RrData);
                
                if (ntohs(rr->type) == TYPE_A && strcmp(name, current_hostname) == 0) {
                    inet_ntop(AF_INET, reader, rdata_str, INET_ADDRSTRLEN);
                    printf("\n>>> Resposta Final Encontrada: %s -> %s\n", name, rdata_str);
                    found_a = 1;
                    break; 
                } else if (ntohs(rr->type) == TYPE_CNAME) {
                    decode_dns_name(reader, buffer, rdata_str);
                    printf(">>> Encontrado CNAME: %s -> %s. Reiniciando a busca.\n", name, rdata_str);
                    strcpy(current_hostname, rdata_str);
                    strcpy(server_list[0], root_server_ip);
                    server_count = 1;
                    break;
                }
                reader += ntohs(rr->rdlength);
            }
            if (found_a) break;
            else continue;
        }
        else if (ntohs(response_header->nscount) > 0) {
            printf("Delegação recebida. Buscando próximos servidores...\n");
            server_count = 0;

            unsigned char *ns_reader = reader;
            for (int i = 0; i < ntohs(response_header->nscount); i++) {
                char name[256];
                int name_bytes = decode_dns_name(ns_reader, buffer, name);
                ns_reader += name_bytes;
                struct RrData *rr = (struct RrData *)ns_reader;
                ns_reader += sizeof(struct RrData) + ntohs(rr->rdlength);
            }
            
            for (int i = 0; i < ntohs(response_header->arcount); i++) {
                char name[256], rdata_str[256];
                int name_bytes = decode_dns_name(ns_reader, buffer, name);
                ns_reader += name_bytes;
                struct RrData *rr = (struct RrData *)ns_reader;
                
                if (ntohs(rr->type) == TYPE_A) {
                    inet_ntop(AF_INET, ns_reader + sizeof(struct RrData), rdata_str, INET_ADDRSTRLEN);
                    printf("    Adicionando servidor à fila: %s (%s)\n", name, rdata_str);
                    strcpy(server_list[server_count++], rdata_str);
                }
                ns_reader += sizeof(struct RrData) + ntohs(rr->rdlength);
            }

            if (server_count == 0) {
                 printf("Delegação sem glue records. (Resolução de NS não implementada).\n");
                 break;
            }
        } else {
            printf("Resposta sem ANCOUNT ou NSCOUNT. Não foi possível continuar.\n");
            break;
        }
    }

    if (query_count >= max_queries) {
        printf("\nLimite máximo de consultas atingido. Falha na resolução.\n");
    }
}