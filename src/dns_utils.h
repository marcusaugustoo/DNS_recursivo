#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdint.h>
#define TYPE_A 1
#define TYPE_NS 2
#define TYPE_CNAME 5
#define TYPE_MX 15
#define TYPE_AAAA 28

#pragma pack(push, 1)
struct DnsHeader {
    uint16_t id;
    uint16_t flags;
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

void format_dns_name(unsigned char *dns_name, const char *hostname);
int decode_dns_name(unsigned char *reader, unsigned char *buffer, char *decoded_name);

#endif