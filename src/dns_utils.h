#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdint.h>

// Definindo constantes para tipos de registro DNS
#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5

#pragma pack(push, 1)
struct DnsHeader {
    uint16_t id;
    uint8_t rd : 1;
    uint8_t tc : 1;
    uint8_t aa : 1;
    uint8_t opcode : 4;
    uint8_t qr : 1;
    uint8_t rcode : 4;
    uint8_t z : 3;
    uint8_t ra : 1;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
struct DnsQuestion {
    uint16_t qtype;
    uint16_t qclass;
};
struct RrData {
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
};
#pragma pack(pop)

// Protótipos das funções que serão implementadas em dns_utils.c
void format_dns_name(unsigned char *dns_name, const char *hostname);
int decode_dns_name(unsigned char *reader, unsigned char *buffer, char *decoded_name);

#endif // DNS_UTILS_H