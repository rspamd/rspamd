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
#include "platform_config.h"
#include "blake2.h"
#include "blake2-internal.h"

extern unsigned long cpu_config;

typedef struct blake2b_impl_t {
	unsigned long cpu_flags;
	const char *desc;

	void (*blake2b_blocks) (blake2b_state_internal *state,
			const unsigned char *in,
			size_t bytes,
			size_t stride);
} blake2b_impl_t;

#define BLAKE2B_STRIDE BLAKE2B_BLOCKBYTES
#define BLAKE2B_STRIDE_NONE 0

#define BLAKE2B_DECLARE(ext) \
    void blake2b_blocks_##ext(blake2b_state_internal *state, const unsigned char *in, size_t bytes, size_t stride);

#define BLAKE2B_IMPL(cpuflags, desc, ext) \
    {(cpuflags), desc, blake2b_blocks_##ext}

#if defined(HAVE_AVX)
BLAKE2B_DECLARE(avx)
#define BLAKE2B_AVX BLAKE2B_IMPL(CPUID_AVX, "avx", avx)
#endif

#if defined(CMAKE_ARCH_x86_64) || defined(CMAKE_ARCH_i386)
BLAKE2B_DECLARE(x86)
#define BLAKE2B_X86 BLAKE2B_IMPL(CPUID_SSE2, "x86", x86)
#endif

/* the "always runs" version */
BLAKE2B_DECLARE(ref)
#define BLAKE2B_GENERIC BLAKE2B_IMPL(0, "generic", ref)

/* list implementations from most optimized to least, with generic as the last entry */
static const blake2b_impl_t blake2b_list[] = {
		BLAKE2B_GENERIC,
#if defined(BLAKE2B_AVX)
		BLAKE2B_AVX,
#endif
#if defined(BLAKE2B_X86)
		BLAKE2B_X86,
#endif
};

static const blake2b_impl_t *blake2b_opt = &blake2b_list[0];


/* is the pointer not aligned on a word boundary? */
static int
blake2b_not_aligned (const void *p)
{
#if !defined(CPU_8BITS)
	return ((size_t) p & (sizeof (size_t) - 1)) != 0;
#else
	return 0;
#endif
}

static const union endian_test_t {
	unsigned char b[2];
	unsigned short s;
} blake2b_endian_test = {{1, 0}};

/* copy the hash from the internal state */
static void
blake2b_store_hash (blake2b_state_internal *state, unsigned char *hash)
{
	if (blake2b_endian_test.s == 0x0001) {
		memcpy (hash, state->h, 64);
	}
	else {
		size_t i, j;
		for (i = 0; i < 8; i++, hash += 8) {
			for (j = 0; j < 8; j++)
				hash[7 - j] = state->h[(i * 8) + j];
		}
	}
}

static const unsigned char blake2b_init_le[64] = {
		0x08 ^ 0x40, 0xc9 ^ 0x00, 0xbc ^ 0x01, 0xf3 ^ 0x01, 0x67 ^ 0x00,
		0xe6 ^ 0x00, 0x09 ^ 0x00, 0x6a ^ 0x00,
		0x3b, 0xa7, 0xca, 0x84, 0x85, 0xae, 0x67, 0xbb,
		0x2b, 0xf8, 0x94, 0xfe, 0x72, 0xf3, 0x6e, 0x3c,
		0xf1, 0x36, 0x1d, 0x5f, 0x3a, 0xf5, 0x4f, 0xa5,
		0xd1, 0x82, 0xe6, 0xad, 0x7f, 0x52, 0x0e, 0x51,
		0x1f, 0x6c, 0x3e, 0x2b, 0x8c, 0x68, 0x05, 0x9b,
		0x6b, 0xbd, 0x41, 0xfb, 0xab, 0xd9, 0x83, 0x1f,
		0x79, 0x21, 0x7e, 0x13, 0x19, 0xcd, 0xe0, 0x5b,
};

/* initialize the state in serial mode */
void
blake2b_init (blake2b_state *S)
{
	blake2b_state_internal *state = (blake2b_state_internal *) S;
	/* assume state is fully little endian for now */
	memcpy (state, blake2b_init_le, 64);
	/*memcpy(state, (blake2b_endian_test.s == 1) ? blake2b_init_le : blake2b_init_be, 64);*/
	memset (state->t,
			0,
			sizeof (state->t) + sizeof (state->f) + sizeof (state->leftover));
}

/* initialized the state in serial-key'd mode */
void
blake2b_keyed_init (blake2b_state *S, const unsigned char *key, size_t keylen)
{
	unsigned char k[BLAKE2B_BLOCKBYTES];
	blake2b_state _ks;
	blake2b_state_internal *state = (blake2b_state_internal *)S;

	memset (k, 0, sizeof (k));

	if (keylen <= BLAKE2B_KEYBYTES) {
		memcpy (k, key, keylen);
		blake2b_init (S);
		state->h[1] ^= keylen;
		blake2b_update (S, k, sizeof (k));
	}
	else {
		blake2b_init (S);
		/*
		 * We use additional blake2 iteration to store large key
		 * XXX: it is not compatible with the original implementation but safe
		 */
		blake2b_init (&_ks);
		blake2b_update (&_ks, key, keylen);
		blake2b_final (&_ks, k);
		blake2b_keyed_init (S, k, BLAKE2B_KEYBYTES);
	}

	rspamd_explicit_memzero (k, sizeof (k));
}

/* hash inlen bytes from in, which may or may not be word aligned, returns the number of bytes used */
static size_t
blake2b_consume_blocks (blake2b_state_internal *state,
		const unsigned char *in,
		size_t inlen)
{
	/* always need to leave at least BLAKE2B_BLOCKBYTES in case this is the final block */
	if (inlen <= BLAKE2B_BLOCKBYTES)
		return 0;

	inlen = ((inlen - 1) & ~(BLAKE2B_BLOCKBYTES - 1));
	if (blake2b_not_aligned (in)) {
		/* copy the unaligned data to an aligned buffer and process in chunks */
		unsigned char buffer[16 * BLAKE2B_BLOCKBYTES];
		size_t left = inlen;
		while (left) {
			const size_t bytes = (left > sizeof (buffer)) ? sizeof (buffer)
														  : left;
			memcpy (buffer, in, bytes);
			blake2b_opt->blake2b_blocks (state, buffer, bytes, BLAKE2B_STRIDE);
			in += bytes;
			left -= bytes;
		}
	}
	else {
		/* word aligned, handle directly */
		blake2b_opt->blake2b_blocks (state, in, inlen, BLAKE2B_STRIDE);
	}

	return inlen;
}

/* update the hash state with inlen bytes from in */
void
blake2b_update (blake2b_state *S, const unsigned char *in, size_t inlen)
{
	blake2b_state_internal *state = (blake2b_state_internal *) S;
	size_t bytes;

	/* blake2b processes the final <=BLOCKBYTES bytes raw, so we can only update if there are at least BLOCKBYTES+1 bytes available */
	if ((state->leftover + inlen) > BLAKE2B_BLOCKBYTES) {
		/* handle the previous data, we know there is enough for at least one block */
		if (state->leftover) {
			bytes = (BLAKE2B_BLOCKBYTES - state->leftover);
			memcpy (state->buffer + state->leftover, in, bytes);
			in += bytes;
			inlen -= bytes;
			state->leftover = 0;
			blake2b_opt->blake2b_blocks (state,
					state->buffer,
					BLAKE2B_BLOCKBYTES,
					BLAKE2B_STRIDE_NONE);
		}

		/* handle the direct data (if any) */
		bytes = blake2b_consume_blocks (state, in, inlen);
		inlen -= bytes;
		in += bytes;
	}

	/* handle leftover data */
	memcpy (state->buffer + state->leftover, in, inlen);
	state->leftover += inlen;
}

/* finalize the hash */
void
blake2b_final (blake2b_state *S, unsigned char *hash)
{
	blake2b_state_internal *state = (blake2b_state_internal *) S;
	memset (&state->f[0], 0xff, 8);
	blake2b_opt->blake2b_blocks (state,
			state->buffer,
			state->leftover,
			BLAKE2B_STRIDE_NONE);
	blake2b_store_hash (state, hash);
	rspamd_explicit_memzero (state, sizeof (*state));
}

/* one-shot hash inlen bytes from in */
void
blake2b (unsigned char *hash, const unsigned char *in, size_t inlen)
{
	blake2b_state S;
	blake2b_state_internal *state = (blake2b_state_internal *) &S;
	size_t bytes;

	blake2b_init (&S);

	/* hash until <= 128 bytes left */
	bytes = blake2b_consume_blocks (state, in, inlen);
	in += bytes;
	inlen -= bytes;

	/* final block */
	memset (&state->f[0], 0xff, 8);
	blake2b_opt->blake2b_blocks (state, in, inlen, BLAKE2B_STRIDE_NONE);
	blake2b_store_hash (state, hash);
}

void
blake2b_keyed (unsigned char *hash,
		const unsigned char *in,
		size_t inlen,
		const unsigned char *key,
		size_t keylen)
{
	blake2b_state S;
	blake2b_keyed_init (&S, key, keylen);
	blake2b_update (&S, in, inlen);
	blake2b_final (&S, hash);
}

const char*
blake2b_load (void)
{
	guint i;

	if (cpu_config != 0) {
		for (i = 0; i < G_N_ELEMENTS (blake2b_list); i++) {
			if (blake2b_list[i].cpu_flags & cpu_config) {
				blake2b_opt = &blake2b_list[i];
				break;
			}
		}
	}

	return blake2b_opt->desc;
}
