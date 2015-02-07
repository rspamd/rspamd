#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>

#if defined(__cplusplus)
extern "C"
{
#endif

typedef struct poly1305_state
{
	unsigned char opaque[320];
} poly1305_state;

typedef struct poly1305_key
{
	unsigned char b[32];
} poly1305_key;

void poly1305_init(poly1305_state *S, const poly1305_key *key);
void poly1305_init_ext(poly1305_state *S, const poly1305_key *key,
		size_t bytes_hint);
void poly1305_update(poly1305_state *S, const unsigned char *in, size_t inlen);
void poly1305_finish(poly1305_state *S, unsigned char *mac);

void poly1305_auth(unsigned char *mac, const unsigned char *in, size_t inlen,
		const poly1305_key *key);
int poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]);

void poly1305_load(void);

#if defined(__cplusplus)
}
#endif

#endif /* POLY1305_H */

