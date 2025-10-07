#include "resolver.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s <hostname_a_resolver>\n", argv[0]);
        fprintf(stderr, "Exemplo: %s www.google.com\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *hostname = argv[1];
    // Um dos 13 servidores raiz da Internet
    const char *root_server = "198.41.0.4"; // a.root-servers.net

    // Chama a função que faz todo o trabalho
    resolve_iterative(hostname, root_server);

    return 0;
}