#include "dns_utils.h"
#include <string.h>
#include <stdio.h>

// converte um hostname p um formato legivel (ex: "www.google.com")
// p o formato DNS (com os comprimentos dos rotulos antes d cada parte)
void format_dns_name(unsigned char *dns_name, const char *hostname) {
    char hostname_copy[256];
    strcpy(hostname_copy, hostname);
    strcat(hostname_copy, ".");  // add ponto final p facilitar o loop

    size_t lock = 0; // marcador p inicio d cada rotulo

    for (size_t i = 0; i < strlen(hostname_copy); i++) {
        if (hostname_copy[i] == '.') {
            *dns_name++ = i - lock; // escreve o comprimento do rotulo
            for (; lock < i; lock++) {
                *dns_name++ = hostname_copy[lock]; // copia os caracteres do rotulo
            }
            lock++; // pula o ponto
        }
    }
    *dns_name++ = '\0'; // finaliza a string DNS
}

// decodifica um nome DNS do formato binrio p texto legivel
// retorna o n° de bytes consumidos no processo
int decode_dns_name(unsigned char *reader, unsigned char *buffer, char *decoded_name) {
    int bytes_consumed = 0;
    int name_pos = 0;
    int jumped = 0;       // indica s houve "salto" por compressao
    int jump_count = 0;   // evita loop infinito s o pacote estiver corrompido
    unsigned char *p = reader;

    while (*p != 0) {
        if (jump_count++ > 10) return -1; // segurança contra loops

        // s os dois bits mais altos sao 11, significa que é um ponteiro (compressao DNS)
        if ((*p & 0xC0) == 0xC0) {
            if (!jumped) {
                bytes_consumed = (p - reader) + 2;
                jumped = 1;
            }
            int offset = ((*p & 0x3F) << 8) | *(p + 1); // calcula o offset do ponteiro
            p = buffer + offset; // move o ponteiro de leitura p o destino
        } else {
            int label_len = *p;
            p++;

            if (name_pos > 0) {
                decoded_name[name_pos++] = '.';
            }

            memcpy(decoded_name + name_pos, p, label_len);
            name_pos += label_len;
            p += label_len;
        }
    }

    decoded_name[name_pos] = '\0'; // finaliza o nome decodificado

    // s ñ houve salto, calcula bytes consumidos normal
    if (!jumped) {
        bytes_consumed = (p - reader) + 1;
    }

    return bytes_consumed;
}
