#include "dns_utils.h"
#include <string.h>
#include <stdio.h>

void format_dns_name(unsigned char *dns_name, const char *hostname) {
    char hostname_copy[256];
    strcpy(hostname_copy, hostname);
    strcat(hostname_copy, ".");
    size_t lock = 0;
    for (size_t i = 0; i < strlen(hostname_copy); i++) {
        if (hostname_copy[i] == '.') {
            *dns_name++ = i - lock;
            for (; lock < i; lock++) {
                *dns_name++ = hostname_copy[lock];
            }
            lock++;
        }
    }
    *dns_name++ = '\0';
}

int decode_dns_name(unsigned char *reader, unsigned char *buffer, char *decoded_name) {
    int bytes_consumed = 0;
    int name_pos = 0;
    int jumped = 0;
    int jump_count = 0;
    unsigned char *p = reader;

    while (*p != 0) {
        if (jump_count++ > 10) return -1;

        if ((*p & 0xC0) == 0xC0) {
            if (!jumped) {
                bytes_consumed = (p - reader) + 2;
                jumped = 1;
            }
            int offset = ((*p & 0x3F) << 8) | *(p + 1);
            p = buffer + offset;
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

    decoded_name[name_pos] = '\0';

    if (!jumped) {
        bytes_consumed = (p - reader) + 1;
    }

    return bytes_consumed;
}