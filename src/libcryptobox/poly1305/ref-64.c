/*
	poly1305 implementation using 64 bit * 64 bit = 128 bit multiplication and 128 bit addition

	assumes the existence of uint64_t and uint128_t
*/

#include "config.h"
#include "poly1305.h"
enum {
	POLY1305_BLOCK_SIZE = 16
};

#if defined(_MSC_VER)
	#include <intrin.h>

	typedef struct uint128_t {
		unsigned long long lo;
		unsigned long long hi;
	} uint128_t;

	#define POLY1305_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
	#if defined(__SIZEOF_INT128__)
		typedef unsigned __int128 uint128_t;
	#else
		typedef unsigned uint128_t __attribute__((mode(TI)));
	#endif

	#define POLY1305_NOINLINE __attribute__((noinline))
#endif

typedef struct poly1305_state_ref_t {
	uint64_t r[3];
	uint64_t h[3];
	uint64_t pad[2];
	unsigned char final;
} poly1305_state_ref_t;

/* interpret eight 8 bit unsigned integers as a 64 bit unsigned integer in little endian */
static uint64_t
U8TO64(const unsigned char *p) {
	return
		((uint64_t)p[0]      ) |
		((uint64_t)p[1] <<  8) |
		((uint64_t)p[2] << 16) |
		((uint64_t)p[3] << 24) |
		((uint64_t)p[4] << 32) |
		((uint64_t)p[5] << 40) |
		((uint64_t)p[6] << 48) |
		((uint64_t)p[7] << 56);
}

/* store a 64 bit unsigned integer as eight 8 bit unsigned integers in little endian */
static void
U64TO8(unsigned char *p, uint64_t v) {
	p[0] = (unsigned char)(v      ) & 0xff;
	p[1] = (unsigned char)(v >>  8) & 0xff;
	p[2] = (unsigned char)(v >> 16) & 0xff;
	p[3] = (unsigned char)(v >> 24) & 0xff;
	p[4] = (unsigned char)(v >> 32) & 0xff;
	p[5] = (unsigned char)(v >> 40) & 0xff;
	p[6] = (unsigned char)(v >> 48) & 0xff;
	p[7] = (unsigned char)(v >> 56) & 0xff;
}

size_t
poly1305_block_size_ref(void) {
	return POLY1305_BLOCK_SIZE;
}

void
poly1305_init_ext_ref(void *state, const poly1305_key *key, size_t bytes_hint) {
	poly1305_state_ref_t *st = (poly1305_state_ref_t *)state;
	uint64_t t0, t1;

	/* bytes_hint not used */
	(void)bytes_hint;

	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	t0 = U8TO64(&key->b[0]);
	t1 = U8TO64(&key->b[8]);
	st->r[0] = ( t0                    ) & 0xffc0fffffff;
	st->r[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
	st->r[2] = ((t1 >> 24)             ) & 0x00ffffffc0f;

	/* h = 0 */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;

	/* save pad for later */
	st->pad[0] = U8TO64(&key->b[16]);
	st->pad[1] = U8TO64(&key->b[24]);

	st->final = 0;
}

void
poly1305_blocks_ref(void *state, const unsigned char *in, size_t inlen) {
	poly1305_state_ref_t *st = (poly1305_state_ref_t *)state;
	const uint64_t hibit = (st->final) ? 0 : ((uint64_t)1 << 40); /* 1 << 128 */
	uint64_t r0,r1,r2;
	uint64_t s1,s2;
	uint64_t h0,h1,h2;
	uint64_t c;
	uint128_t d0,d1,d2;

	r0 = st->r[0];
	r1 = st->r[1];
	r2 = st->r[2];

	s1 = r1 * (5 << 2);
	s2 = r2 * (5 << 2);

	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];

	while (inlen >= POLY1305_BLOCK_SIZE) {
		uint64_t t0, t1;

		/* h += in[i] */
		t0 = U8TO64(in + 0);
		t1 = U8TO64(in + 8);
		h0 += (( t0                    ) & 0xfffffffffff);
		h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff);
		h2 += (((t1 >> 24)             ) & 0x3ffffffffff) | hibit;

		/* h *= r */
		d0 = ((uint128_t)h0 * r0) + ((uint128_t)h1 * s2) + ((uint128_t)h2 * s1);
		d1 = ((uint128_t)h0 * r1) + ((uint128_t)h1 * r0) + ((uint128_t)h2 * s2);
		d2 = ((uint128_t)h0 * r2) + ((uint128_t)h1 * r1) + ((uint128_t)h2 * r0);

		/* (partial) h %= p */
		              c = (uint64_t)(d0 >> 44); h0 = (uint64_t)d0 & 0xfffffffffff;
		d1 += c;      c = (uint64_t)(d1 >> 44); h1 = (uint64_t)d1 & 0xfffffffffff;
		d2 += c;      c = (uint64_t)(d2 >> 42); h2 = (uint64_t)d2 & 0x3ffffffffff;
		h0 += c * 5;  c =           (h0 >> 44); h0 =           h0 & 0xfffffffffff;
		h1 += c;

		in += POLY1305_BLOCK_SIZE;
		inlen -= POLY1305_BLOCK_SIZE;
	}

	st->h[0] = h0;
	st->h[1] = h1;
	st->h[2] = h2;
}

void
poly1305_finish_ext_ref(void *state, const unsigned char *in, size_t remaining, unsigned char mac[16]) {
	poly1305_state_ref_t *st = (poly1305_state_ref_t *)state;
	uint64_t h0, h1, h2, c;
	uint64_t g0, g1, g2;
	uint64_t t0, t1;

	/* process the remaining block */
	if (remaining) {
		unsigned char final[POLY1305_BLOCK_SIZE] = {0};
		size_t i;
		for (i = 0; i < remaining; i++)
			final[i] = in[i];
		final[remaining] = 1;
		st->final = 1;
		poly1305_blocks_ref(st, final, POLY1305_BLOCK_SIZE);
	}

	/* fully carry h */
	h0 = st->h[0];
	h1 = st->h[1];
	h2 = st->h[2];

	             c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
	h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += c;     c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += c;     c = (h2 >> 42); h2 &= 0x3ffffffffff;
	h0 += c * 5; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += c;

	/* compute h + -p */
	g0 = h0 + 5; c = (g0 >> 44); g0 &= 0xfffffffffff;
	g1 = h1 + c; c = (g1 >> 44); g1 &= 0xfffffffffff;
	g2 = h2 + c - ((uint64_t)1 << 42);

	/* select h if h < p, or h + -p if h >= p */
	c = (g2 >> 63) - 1;
	h0 = (h0 & ~c) | (g0 & c);
	h1 = (h1 & ~c) | (g1 & c);
	h2 = (h2 & ~c) | (g2 & c);

	/* h = (h + pad) */
	t0 = st->pad[0];
	t1 = st->pad[1];

	h0 += (( t0                    ) & 0xfffffffffff)    ; c = (h0 >> 44); h0 &= 0xfffffffffff;
	h1 += (((t0 >> 44) | (t1 << 20)) & 0xfffffffffff) + c; c = (h1 >> 44); h1 &= 0xfffffffffff;
	h2 += (((t1 >> 24)             ) & 0x3ffffffffff) + c;                 h2 &= 0x3ffffffffff;

	/* mac = h % (2^128) */
	h0 = ((h0      ) | (h1 << 44));
	h1 = ((h1 >> 20) | (h2 << 24));

	U64TO8(&mac[0], h0);
	U64TO8(&mac[8], h1);

	/* zero out the state */
	st->h[0] = 0;
	st->h[1] = 0;
	st->h[2] = 0;
	st->r[0] = 0;
	st->r[1] = 0;
	st->r[2] = 0;
	st->pad[0] = 0;
	st->pad[1] = 0;
}


void
poly1305_auth_ref(unsigned char mac[16], const unsigned char *in, size_t inlen, const poly1305_key *key) {
	poly1305_state_ref_t st;
	size_t blocks;
	poly1305_init_ext_ref(&st, key, inlen);
	blocks = (inlen & ~(POLY1305_BLOCK_SIZE - 1));
	if (blocks) {
		poly1305_blocks_ref(&st, in, blocks);
		in += blocks;
		inlen -= blocks;
	}
	poly1305_finish_ext_ref(&st, in, inlen, mac);
}

