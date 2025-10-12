#include "resolver.h"
#include "dns_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <strings.h>

// converte o tp d consulta em string (ex: "A", "AAAA") p o cod numerico DNS
static uint16_t qtype_from_string(const char *str) {
    if (strcasecmp(str, "A") == 0) return TYPE_A;
    if (strcasecmp(str, "AAAA") == 0) return TYPE_AAAA;
    if (strcasecmp(str, "MX") == 0) return TYPE_MX;
    if (strcasecmp(str, "NS") == 0) return TYPE_NS;
    return TYPE_A; // padrao se não reconhecido
}

int main(int argc, char *argv[]) {
    char *hostname = NULL;
    char *qtype_str = "A";
    char *start_server = "198.41.0.4"; // servidor raiz padrao
    int trace_mode = 0;
    int timeout_sec = 5;
    int use_dot = 0; // DNS-over-TLS -> DoT
    char sni_value[256] = {0};
    char *mode_str = NULL;
    char *trust_anchor_file = NULL;

    // processamento d args d linha de comando
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
            hostname = argv[++i];
        else if (strcmp(argv[i], "--qtype") == 0 && i + 1 < argc)
            qtype_str = argv[++i];
        else if (strcmp(argv[i], "--ns") == 0 && i + 1 < argc)
            start_server = argv[++i];
        else if (strcmp(argv[i], "--trace") == 0)
            trace_mode = 1;
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc)
            timeout_sec = atoi(argv[++i]);
        else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc)
            mode_str = argv[++i];
        else if (strcmp(argv[i], "--sni") == 0 && i + 1 < argc)
            strncpy(sni_value, argv[++i], sizeof(sni_value) - 1);
        else if (strcmp(argv[i], "--trust-anchor") == 0 && i + 1 < argc)
            trust_anchor_file = argv[++i];
    }

    // verific basica d uso
    if (!hostname) {
        fprintf(stderr,
                "Uso: %s --name <hostname> [--qtype <A|AAAA|MX|NS>] "
                "[--ns <ip>] [--timeout <seg>] [--mode <modo>] "
                "[--sni <hostname>] [--trust-anchor <arquivo>] [--trace]\n",
                argv[0]);
        return 1;
    }

    // define o modo do resolvedor (recursivo, iterativo, dot, etc)
    if (mode_str)
        resolver_set_mode(mode_str);
    else
        resolver_set_mode("recursive"); // padrao

    // carrega trust anchor s fornecido (p validacao DNSSEC)
    if (trust_anchor_file) {
        if (resolver_load_trust_anchor(trust_anchor_file) != 0)
            fprintf(stderr, "Continuando sem trust-anchor (não encontrado).\n");
    } else {
        fprintf(stderr, "[INFO] Nenhum trust-anchor especificado.\n");
    }

    uint16_t qtype = qtype_from_string(qtype_str);

    // ativa DNS-over-TLS s modo "dot" estiver selecionado
    if (strcasecmp(mode_str ? mode_str : "", "dot") == 0)
        use_dot = 1;
    if (use_dot)
        resolver_set_dot(1, sni_value[0] ? sni_value : NULL);

    printf("--- Resolvendo %s (tipo: %s, servidor inicial: %s, timeout: %ds) ---\n",
           hostname, qtype_str, start_server, timeout_sec);

    // faz a resolucao iterativa d fato
    char *final_ip = resolve_iterative(hostname, start_server, qtype, 0,
                                       trace_mode, timeout_sec);

    printf("\n----------------------------------------\n");
    if (final_ip) {
        printf(">>> Resposta final: %s\n", final_ip);
        free(final_ip);
    } else {
        printf(">>> Não foi possível obter uma resposta final.\n");
    }
    printf("----------------------------------------\n");

    return 0;
}
