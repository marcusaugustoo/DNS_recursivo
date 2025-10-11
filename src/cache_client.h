#ifndef CACHE_CLIENT_H
#define CACHE_CLIENT_H

char *cache_get(const char *hostname, int qtype, int *is_neg, int *rcode);
void cache_put_positive(const char *hostname, int qtype, int ttl, const char *value);
void cache_put_negative(const char *hostname, int qtype, int ttl, int rcode);

#endif