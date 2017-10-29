/*
 * Copyright (c) 2017, Vsevolod Stakhov
 * Copyright (c) 2017, Frank Denis
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
#include "ottery-internal.h"
#include "cryptobox.h"

#if defined(__x86_64__) && defined(RSPAMD_HAS_TARGET_ATTR)
#pragma GCC push_options
#pragma GCC target("aes")
#ifndef __SSE2__
#define __SSE2__
#endif
#ifndef __SSE__
#define __SSE__
#endif
#ifndef __AES__
#define __AES__
#endif
#include <immintrin.h>
#define ROUNDS 10

typedef struct RSPAMD_ALIGNED(16) aes_rng_state {
	__m128i round_keys[ROUNDS + 1];
	__m128i counter;
} aes_stream_state;


#define STATE_LEN   sizeof(aes_stream_state)
#define STATE_BYTES 16

#define OUTPUT_LEN  1024

static void
aes_key_expand (__m128i round_keys[ROUNDS + 1], __m128i t) __attribute__((target("aes")));

static void
aes_key_expand (__m128i round_keys[ROUNDS + 1], __m128i t)
{
	__m128i t1;

#define DO_ROUND_KEY(ROUND, RC)                           \
    do {                                                   \
        t1 = _mm_aeskeygenassist_si128(t, (RC));           \
        round_keys[ROUND] = t;                             \
        t = _mm_xor_si128(t, _mm_slli_si128(t, 4));        \
        t = _mm_xor_si128(t, _mm_slli_si128(t, 8));        \
        t = _mm_xor_si128(t, _mm_shuffle_epi32(t1, 0xff)); \
    } while (0)

	DO_ROUND_KEY(0, 1);
	DO_ROUND_KEY(1, 2);
	DO_ROUND_KEY(2, 4);
	DO_ROUND_KEY(3, 8);
	DO_ROUND_KEY(4, 16);
	DO_ROUND_KEY(5, 32);
	DO_ROUND_KEY(6, 64);
	DO_ROUND_KEY(7, 128);
	DO_ROUND_KEY(8, 27);
	DO_ROUND_KEY(9, 54);
	round_keys[10] = t;
}

/*
 * Computes one 128 bytes block and refresh keys
 */
static void
aes_round(unsigned char *buf, struct aes_rng_state *st) __attribute__((target("aes")));
static void
aes_round(unsigned char *buf, struct aes_rng_state *st)
{
	const __m128i  one = _mm_set_epi64x(0, 1);
	__m128i *round_keys = st->round_keys;
	__m128i c0, c1, c2, c3, c4, c5, c6, c7;
	__m128i r0, r1, r2, r3, r4, r5, r6, r7;
	__m128i s0, s1, s2, s3, s4, s5, s6, s7;
	size_t i;

#define COMPUTE_ROUNDS(N)                                                              \
    do {                                                                               \
        r##N = _mm_aesenc_si128(   _mm_xor_si128(c##N, round_keys[0]), round_keys[1]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[2]), round_keys[3]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[4]), round_keys[5]); \
        s##N = r##N;                                                                   \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[6]), round_keys[7]); \
        r##N = _mm_aesenc_si128(_mm_aesenc_si128(r##N, round_keys[8]), round_keys[9]); \
        r##N = _mm_xor_si128(s##N, _mm_aesenclast_si128(r##N, round_keys[10]));        \
    } while (0)

	c0 = st->counter;

	for (i = 0; i < OUTPUT_LEN / 128; i ++) {
		c1 = _mm_add_epi64 (c0, one);
		c2 = _mm_add_epi64 (c1, one);
		c3 = _mm_add_epi64 (c2, one);
		c4 = _mm_add_epi64 (c3, one);
		c5 = _mm_add_epi64 (c4, one);
		c6 = _mm_add_epi64 (c5, one);
		c7 = _mm_add_epi64 (c6, one);
		COMPUTE_ROUNDS(0);
		COMPUTE_ROUNDS(1);
		COMPUTE_ROUNDS(2);
		COMPUTE_ROUNDS(3);
		COMPUTE_ROUNDS(4);
		COMPUTE_ROUNDS(5);
		COMPUTE_ROUNDS(6);
		COMPUTE_ROUNDS(7);
		c0 = _mm_add_epi64 (c7, one);
		_mm_storeu_si128 ((__m128i *) (void *) (buf + 0), r0);
		_mm_storeu_si128 ((__m128i *) (void *) (buf + 16), r1);
		_mm_storeu_si128 ((__m128i *) (void *) (buf + 32), r2);
		_mm_storeu_si128 ((__m128i *) (void *) (buf + 48), r3);
		_mm_storeu_si128 ((__m128i *) (void *) (buf + 64), r4);
		_mm_storeu_si128 ((__m128i *) (void *) (buf + 80), r5);
		_mm_storeu_si128 ((__m128i *) (void *) (buf + 96), r6);
		_mm_storeu_si128 ((__m128i *) (void *) (buf + 112), r7);
		buf += 128;
	}

	st->counter = c0;
	c0 = _mm_setzero_si128();
	COMPUTE_ROUNDS(0);
	aes_key_expand(round_keys, r0);
}


static void
aes_cryptobox_state_setup (void *state_, const uint8_t *bytes)
{
	struct aes_rng_state *x = state_;

	aes_key_expand (x->round_keys,
			_mm_loadu_si128((const __m128i *) (const void *)bytes));
}

static void
aes_cryptobox_generate (void *state_, uint8_t *output, uint32_t idx)
{
	struct aes_rng_state *x = state_;

	aes_round(output, x);
}

#define PRF_AES(r) {                         \
  "AES-" #r,                                  \
  "AES-" #r "-NOSIMD",                        \
  "AES-" #r "-NOSIMD-DEFAULT",                \
  STATE_LEN,                                    \
  STATE_BYTES,                                  \
  OUTPUT_LEN,                                   \
  OTTERY_CPUCAP_AES,                                            \
  aes_cryptobox_state_setup,                    \
  aes_cryptobox_generate               \
}

const struct ottery_prf ottery_prf_aes_cryptobox_ = PRF_AES(128);
#endif /* x86_64 */
