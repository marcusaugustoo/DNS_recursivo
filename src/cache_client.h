#ifndef CACHE_CLIENT_H
#define CACHE_CLIENT_H

// Header do cliente de cache DNS
// (simples mas funcional — talvez expandir depois com cache_clear, etc.)

// Recupera uma entrada do cache.
// Retorna string alocada (precisa dar free) ou NULL se não existir.
// is_neg indica se é uma resposta negativa (0 ou 1).
// rcode é o código de erro (por ex: NXDOMAIN).
char *cache_get(const char *hostname, int qtype, int *is_neg, int *rcode);

// Armazena uma resposta positiva no cache (hostname resolvido).
// ttl define o tempo de vida (em segundos).
void cache_put_positive(const char *hostname, int qtype, int ttl, const char *value);

// Armazena uma resposta negativa (falha de resolução).
// ttl define quanto tempo a falha deve ser lembrada.
void cache_put_negative(const char *hostname, int qtype, int ttl, int rcode);

#endif  // CACHE_CLIENT_H
