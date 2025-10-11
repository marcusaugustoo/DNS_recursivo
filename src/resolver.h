#ifndef RESOLVER_H
#define RESOLVER_H

#include <stdint.h>

char* resolve_iterative(const char *hostname_to_resolve,
                        const char *start_server_ip,
                        uint16_t qtype,
                        int depth,
                        int trace_mode,
                        int timeout_sec);

void resolver_set_dot(int enabled, const char *sni);

/* --- Adições para CLI e Trust Anchor --- */

/* Define o modo de operação do resolver (recursive, validating, etc.) */
void resolver_set_mode(const char *mode);

/* Carrega o arquivo de âncora de confiança (root.keys) */
int resolver_load_trust_anchor(const char *path);

#endif
