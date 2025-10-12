#ifndef DNS_UTILS_H
#define DNS_UTILS_H

#include <stdint.h>

// tipos d registro DNS + comuns
#define TYPE_A     1   // IPv4
#define TYPE_NS    2   // servidor de nomes
#define TYPE_CNAME 5   // nome canonico
#define TYPE_MX    15  // reg de email
#define TYPE_AAAA  28  // IPv6

// garante q ñ tenha padding na estrutura (importante p pacotes DNS)
#pragma pack(push, 1)

// cabeçalho DNS — aparece no inicio de todo pacote
struct DnsHeader {
    uint16_t id;       // id da consulta
    uint16_t flags;    // flags e codigos de operacao e resposta
    uint16_t qdcount;  // n° d questoes
    uint16_t ancount;  // n° drespostas
    uint16_t nscount;  // n° d regs d autoridade
    uint16_t arcount;  // n° d regs adicionais
};

// estrutura d uma questao DNS(query)
struct DnsQuestion {
    uint16_t qtype;    // tipo da consulta ex: A, AAAA, MX
    uint16_t qclass;   // classe da consulta (normalmente 1 = IN)
};

// estrutura dos dados d resposta (resource record)
struct RrData {
    uint16_t type;      // tipo do reg
    uint16_t class;     // classe (geralmente IN)
    uint32_t ttl;       // tempo de vida do registro
    uint16_t rdlength;  // tam dos dados RDATA
};

#pragma pack(pop)

// converte um nome de host ("www.exemplo.com") p o formato DNS bin
void format_dns_name(unsigned char *dns_name, const char *hostname);

// decodifica um nome DNS a partir do buffer bin
// retorna o n° d bytes consumidos na decodificacao
int decode_dns_name(unsigned char *reader, unsigned char *buffer, char *decoded_name);

#endif  // DNS_UTILS_H
