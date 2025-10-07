// dns_utils.c

#include "dns_utils.h"
#include <string.h>
#include <stdio.h>

void format_dns_name(unsigned char *dns_name, const char *hostname) {
    char hostname_copy[256];
    strcpy(hostname_copy, hostname);
    strcat(hostname_copy, ".");
    int lock = 0;
    for (int i = 0; i < strlen(hostname_copy); i++) {
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
    int name_len = 0;
    int jumped = 0;
    int jumps_performed = 0;
    int total_bytes_read = 0;
    unsigned char *name_ptr = reader;
    while (*name_ptr != 0) {
        if ((*name_ptr & 0xC0) == 0xC0) {
            if (jumps_performed > 5) return -1;
            int offset = ((*name_ptr & 0x3F) << 8) + *(name_ptr + 1);
            name_ptr = buffer + offset;
            if (!jumped) {
                total_bytes_read += 2;
                jumped = 1;
            }
            jumps_performed++;
            continue;
        } else {
            int label_len = *name_ptr;
            name_ptr++;
            memcpy(decoded_name + name_len, name_ptr, label_len);
            name_len += label_len;
            name_ptr += label_len;
            if (*name_ptr != 0) {
                decoded_name[name_len] = '.';
                name_len++;
            }
            if (!jumped) {
                total_bytes_read += (label_len + 1);
            }
        }
    }
    decoded_name[name_len] = '\0';
    if (!jumped) {
        total_bytes_read++;
    }
    return total_bytes_read;
}