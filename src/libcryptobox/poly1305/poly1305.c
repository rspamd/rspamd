/*
 * Copyright (c) 2015, Vsevolod Stakhov
 * Copyright (c) 2015, Andrew Moon
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "cryptobox.h"
#include "poly1305.h"
#include "platform_config.h"

extern unsigned long cpu_config;

typedef struct poly1305_state_internal_t
{
	unsigned char opaque[192]; /* largest state required (AVX2) */
	size_t leftover, block_size;
	unsigned char buffer[64]; /* largest blocksize (AVX2) */
} poly1305_state_internal;

typedef struct poly1305_impl_t
{
	unsigned long cpu_flags;
	const char *desc;

	size_t (*block_size)(void);
	void (*init_ext)(void *state, const poly1305_key *key, size_t bytes_hint);
	void (*blocks)(void *state, const unsigned char *in, size_t inlen);
	void (*finish_ext)(void *state, const unsigned char *in, size_t remaining,
			unsigned char *mac);
	void (*auth)(unsigned char *mac, const unsigned char *in, size_t inlen,
			const poly1305_key *key);
} poly1305_impl_t;

#define POLY1305_DECLARE(ext) \
	size_t poly1305_block_size_##ext(void); \
	void poly1305_init_ext_##ext(void *state, const poly1305_key *key, size_t bytes_hint); \
	void poly1305_blocks_##ext(void *state, const unsigned char *in, size_t inlen); \
	void poly1305_finish_ext_##ext(void *state, const unsigned char *in, size_t remaining, unsigned char *mac); \
	void poly1305_auth_##ext(unsigned char *mac, const unsigned char *m, size_t inlen, const poly1305_key *key);

#define POLY1305_IMPL(cpuflags, desc, ext) \
	{(cpuflags), desc, poly1305_block_size_##ext, poly1305_init_ext_##ext, poly1305_blocks_##ext, poly1305_finish_ext_##ext, poly1305_auth_##ext}

#if defined(HAVE_AVX2)
POLY1305_DECLARE(avx2)
#define POLY1305_AVX2 POLY1305_IMPL(CPUID_AVX2, "avx2", avx2)
#endif
#if defined(HAVE_AVX)
POLY1305_DECLARE(avx)
#define POLY1305_AVX POLY1305_IMPL(CPUID_AVX, "avx", avx)
#endif
#if defined(HAVE_SSE2)
POLY1305_DECLARE(sse2)
#define POLY1305_SSE2 POLY1305_IMPL(CPUID_SSE2, "sse2", sse2)
#endif

POLY1305_DECLARE(ref)
#define POLY1305_GENERIC POLY1305_IMPL(0, "generic", ref)

/* list implemenations from most optimized to least, with generic as the last entry */
static const poly1305_impl_t poly1305_list[] =
{
POLY1305_GENERIC,

#if defined(POLY1305_AVX2)
		POLY1305_AVX2,
#endif
#if defined(POLY1305_AVX)
		POLY1305_AVX,
#endif
#if defined(POLY1305_SSE2)
		POLY1305_SSE2,
#endif
};

static const poly1305_impl_t *poly1305_opt = &poly1305_list[0];

/* is the pointer aligned on a word boundary? */
static int poly1305_is_aligned(const void *p)
{
	return ((size_t) p & (sizeof(size_t) - 1)) == 0;
}

void poly1305_load(void)
{
	guint i;

	if (cpu_config != 0) {
		for (i = 0; i < G_N_ELEMENTS(poly1305_list); i++) {
			if (poly1305_list[i].cpu_flags & cpu_config) {
				poly1305_opt = &poly1305_list[i];
				break;
			}
		}
	}
}

/* processes inlen bytes (full blocks only), handling input alignment */
static void poly1305_consume(poly1305_state_internal *state,
		const unsigned char *in, size_t inlen)
{
	int in_aligned;

	/* it's ok to call with 0 bytes */
	if (!inlen)
		return;

	/* if everything is aligned, handle directly */
	in_aligned = poly1305_is_aligned (in);
	if (in_aligned) {
		poly1305_opt->blocks (state->opaque, in, inlen);
		return;
	}

	/* copy the unaligned data to an aligned buffer and process in chunks */
	while (inlen) {
		unsigned char buffer[1024];
		const size_t bytes = (inlen > sizeof(buffer)) ? sizeof(buffer) : inlen;
		memcpy (buffer, in, bytes);
		poly1305_opt->blocks (state->opaque, buffer, bytes);
		in += bytes;
		inlen -= bytes;
	}
}

void poly1305_init(poly1305_state *S, const poly1305_key *key)
{
	poly1305_state_internal *state = (poly1305_state_internal *) S;
	poly1305_opt->init_ext (state->opaque, key, 0);
	state->leftover = 0;
	state->block_size = poly1305_opt->block_size ();
}

void poly1305_init_ext(poly1305_state *S, const poly1305_key *key,
		size_t bytes_hint)
{
	poly1305_state_internal *state = (poly1305_state_internal *) S;
	poly1305_opt->init_ext (state->opaque, key, bytes_hint);
	state->leftover = 0;
	state->block_size = poly1305_opt->block_size ();
}

void poly1305_update(poly1305_state *S, const unsigned char *in, size_t inlen)
{
	poly1305_state_internal *state = (poly1305_state_internal *) S;

	/* handle leftover */
	if (state->leftover) {
		size_t want = (state->block_size - state->leftover);
		if (want > inlen)
			want = inlen;
		memcpy (state->buffer + state->leftover, in, want);
		inlen -= want;
		in += want;
		state->leftover += want;
		if (state->leftover < state->block_size)
			return;
		poly1305_opt->blocks (state->opaque, state->buffer, state->block_size);
		state->leftover = 0;
	}

	/* process full blocks */
	if (inlen >= state->block_size) {
		size_t want = (inlen & ~(state->block_size - 1));
		poly1305_consume (state, in, want);
		in += want;
		inlen -= want;
	}

	/* store leftover */
	if (inlen) {
		memcpy (state->buffer + state->leftover, in, inlen);
		state->leftover += inlen;
	}
}

void poly1305_finish(poly1305_state *S, unsigned char *mac)
{
	poly1305_state_internal *state = (poly1305_state_internal *) S;
	poly1305_opt->finish_ext (state->opaque, state->buffer, state->leftover,
			mac);
}

void poly1305_auth(unsigned char *mac, const unsigned char *in, size_t inlen,
		const poly1305_key *key)
{
	poly1305_opt->auth (mac, in, inlen, key);
}

int poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16])
{
	size_t i;
	unsigned int dif = 0;

	for (i = 0; i < 16; i++) {
		dif |= (mac1[i] ^ mac2[i]);
	}

	dif = (dif - 1) >> ((sizeof(unsigned int) * 8) - 1);
	return (dif & 1);
}
