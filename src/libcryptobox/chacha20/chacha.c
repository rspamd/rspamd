/* Copyright (c) 2015, Vsevolod Stakhov
 * Copyright (c) 2015, Andrew Moon
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#include "chacha.h"
#include "platform_config.h"

extern unsigned cpu_config;

typedef struct chacha_impl_t {
	unsigned long cpu_flags;
	const char *desc;
	void (*chacha) (const chacha_key *key, const chacha_iv *iv,
			const unsigned char *in, unsigned char *out, size_t inlen,
			size_t rounds);
	void (*xchacha) (const chacha_key *key, const chacha_iv24 *iv,
			const unsigned char *in, unsigned char *out, size_t inlen,
			size_t rounds);
	void (*chacha_blocks) (chacha_state_internal *state,
			const unsigned char *in, unsigned char *out, size_t bytes);
	void (*hchacha) (const unsigned char key[32], const unsigned char iv[16],
			unsigned char out[32], size_t rounds);
} chacha_impl_t;

#define CHACHA_DECLARE(ext) \
		void chacha_##ext(const chacha_key *key, const chacha_iv *iv, const unsigned char *in, unsigned char *out, size_t inlen, size_t rounds); \
		void xchacha_##ext(const chacha_key *key, const chacha_iv24 *iv, const unsigned char *in, unsigned char *out, size_t inlen, size_t rounds); \
		void chacha_blocks_##ext(chacha_state_internal *state, const unsigned char *in, unsigned char *out, size_t bytes); \
		void hchacha_##ext(const unsigned char key[32], const unsigned char iv[16], unsigned char out[32], size_t rounds);
#define CHACHA_IMPL(cpuflags, desc, ext) \
		{(cpuflags), desc, chacha_##ext, xchacha_##ext, chacha_blocks_##ext, hchacha_##ext}

#if defined(HAVE_AVX2) && defined(__x86_64__)
	CHACHA_DECLARE(avx2)
	#define CHACHA_AVX2 CHACHA_IMPL(CPUID_AVX2, "avx2", avx2)
#endif
#if defined(HAVE_AVX) && defined(__x86_64__)
	CHACHA_DECLARE(avx)
	#define CHACHA_AVX CHACHA_IMPL(CPUID_AVX, "avx", avx)
#endif
#if defined(HAVE_SSE2) && defined(__x86_64__)
	CHACHA_DECLARE(sse2)
	#define CHACHA_SSE2 CHACHA_IMPL(CPUID_SSE2, "sse2", sse2)
#endif

CHACHA_DECLARE(ref)
#define CHACHA_GENERIC CHACHA_IMPL(0, "generic", ref)

static const chacha_impl_t chacha_list[] = {
	CHACHA_GENERIC,
#if defined(CHACHA_AVX2) && defined(__x86_64__)
	CHACHA_AVX2,
#endif
#if defined(CHACHA_AVX) && defined(__x86_64__)
	CHACHA_AVX,
#endif
#if defined(CHACHA_SSE2) && defined(__x86_64__)
	CHACHA_SSE2
#endif
};

static const chacha_impl_t *chacha_impl = &chacha_list[0];

static int
chacha_is_aligned (const void *p)
{
	return ((size_t) p & (sizeof(size_t) - 1)) == 0;
}

const char *
chacha_load (void)
{
	guint i;

	if (cpu_config != 0) {
		for (i = 0; i < G_N_ELEMENTS (chacha_list); i ++) {
			if (chacha_list[i].cpu_flags & cpu_config) {
				chacha_impl = &chacha_list[i];
				break;
			}
		}
	}

	return chacha_impl->desc;
}

void chacha_init (chacha_state *S, const chacha_key *key,
		const chacha_iv *iv, size_t rounds)
{
	chacha_state_internal *state = (chacha_state_internal *) S;
	memcpy (state->s + 0, key, 32);
	memset (state->s + 32, 0, 8);
	memcpy (state->s + 40, iv, 8);
	state->rounds = rounds;
	state->leftover = 0;
}

/* processes inlen bytes (can do partial blocks), handling input/output alignment */
static void
chacha_consume (chacha_state_internal *state,
		const unsigned char *in, unsigned char *out, size_t inlen)
{
	unsigned char buffer[16 * CHACHA_BLOCKBYTES];
	int in_aligned, out_aligned;

	/* it's ok to call with 0 bytes */
	if (!inlen)
		return;

	/* if everything is aligned, handle directly */
	in_aligned = chacha_is_aligned (in);
	out_aligned = chacha_is_aligned (out);
	if (in_aligned && out_aligned) {
		chacha_impl->chacha_blocks (state, in, out, inlen);
		return;
	}

	/* copy the unaligned data to an aligned buffer and process in chunks */
	while (inlen) {
		const size_t bytes = (inlen > sizeof(buffer)) ? sizeof(buffer) : inlen;
		const unsigned char *src = in;
		unsigned char *dst = (out_aligned) ? out : buffer;
		if (!in_aligned) {
			memcpy (buffer, in, bytes);
			src = buffer;
		}
		chacha_impl->chacha_blocks (state, src, dst, bytes);
		if (!out_aligned)
			memcpy (out, buffer, bytes);
		if (in)
			in += bytes;
		out += bytes;
		inlen -= bytes;
	}
}

/* hchacha */
void hchacha (const unsigned char key[32],
		const unsigned char iv[16], unsigned char out[32], size_t rounds)
{
	chacha_impl->hchacha (key, iv, out, rounds);
}

/* update, returns number of bytes written to out */
size_t
chacha_update (chacha_state *S, const unsigned char *in, unsigned char *out,
		size_t inlen)
{
	chacha_state_internal *state = (chacha_state_internal *) S;
	unsigned char *out_start = out;
	size_t bytes;

	/* enough for at least one block? */
	while ((state->leftover + inlen) >= CHACHA_BLOCKBYTES) {
		/* handle the previous data */
		if (state->leftover) {
			bytes = (CHACHA_BLOCKBYTES - state->leftover);
			if (in) {
				memcpy (state->buffer + state->leftover, in, bytes);
				in += bytes;
			}
			chacha_consume (state, (in) ? state->buffer : NULL, out,
					CHACHA_BLOCKBYTES);
			inlen -= bytes;
			out += CHACHA_BLOCKBYTES;
			state->leftover = 0;
		}

		/* handle the direct data */
		bytes = (inlen & ~(CHACHA_BLOCKBYTES - 1));
		if (bytes) {
			chacha_consume (state, in, out, bytes);
			inlen -= bytes;
			if (in)
				in += bytes;
			out += bytes;
		}
	}

	/* handle leftover data */
	if (inlen) {
		if (in)
			memcpy (state->buffer + state->leftover, in, inlen);
		else
			memset (state->buffer + state->leftover, 0, inlen);
		state->leftover += inlen;
	}

	return out - out_start;
}

/* finalize, write out any leftover data */
size_t
chacha_final (chacha_state *S, unsigned char *out)
{
	chacha_state_internal *state = (chacha_state_internal *) S;
	size_t leftover = state->leftover;
	if (leftover) {
		if (chacha_is_aligned (out)) {
			chacha_impl->chacha_blocks (state, state->buffer, out, leftover);
		}
		else {
			chacha_impl->chacha_blocks (state, state->buffer, state->buffer,
					leftover);
			memcpy (out, state->buffer, leftover);
		}
	}
	rspamd_explicit_memzero (S, sizeof(chacha_state));
	return leftover;
}

/* one-shot, input/output assumed to be word aligned */
void
chacha (const chacha_key *key, const chacha_iv *iv,
		const unsigned char *in, unsigned char *out, size_t inlen,
		size_t rounds)
{
	chacha_impl->chacha (key, iv, in, out, inlen, rounds);
}

/*
 xchacha, chacha with a 192 bit nonce
 */

void
xchacha_init (chacha_state *S, const chacha_key *key,
		const chacha_iv24 *iv, size_t rounds)
{
	chacha_key subkey;
	hchacha (key->b, iv->b, subkey.b, rounds);
	chacha_init (S, &subkey, (chacha_iv *) (iv->b + 16), rounds);
}

/* one-shot, input/output assumed to be word aligned */
void
xchacha (const chacha_key *key, const chacha_iv24 *iv,
		const unsigned char *in, unsigned char *out, size_t inlen,
		size_t rounds)
{
	chacha_impl->xchacha (key, iv, in, out, inlen, rounds);
}
