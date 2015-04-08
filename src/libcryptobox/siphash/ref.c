/* Copyright (c) 2015, Vsevolod Stakhov
 * Copyright (c) 2012-2014 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
 * Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
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

/* default: SipHash-2-4 */
#define cROUNDS 2
#define dROUNDS 4

#define ROTL(x,b) (uint64_t)( ((x) << (b)) | ( (x) >> (64 - (b))) )

#define U32TO8_LE(p, v)                                         \
  (p)[0] = (uint8_t)((v)      ); (p)[1] = (uint8_t)((v) >>  8); \
  (p)[2] = (uint8_t)((v) >> 16); (p)[3] = (uint8_t)((v) >> 24);

#define U64TO8_LE(p, v)                        \
  U32TO8_LE((p),     (uint32_t)((v)      ));   \
  U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#if BYTE_ORDER != LITTLE_ENDIAN
#define U8TO64_LE(p) \
	(((uint64_t)((p)[0]) <<  0) | \
	 ((uint64_t)((p)[1]) <<  8) | \
	 ((uint64_t)((p)[2]) << 16) | \
	 ((uint64_t)((p)[3]) << 24) | \
	 ((uint64_t)((p)[4]) << 32) | \
	 ((uint64_t)((p)[5]) << 40) | \
	 ((uint64_t)((p)[6]) << 48) | \
	 ((uint64_t)((p)[7]) << 56))
#else
#define U8TO64_LE(p) (*(uint64_t*)(p))
#endif

#define SIPROUND                                        \
  do {                                                  \
    v0 += v1; v1=ROTL(v1,13); v1 ^= v0; v0=ROTL(v0,32); \
    v2 += v3; v3=ROTL(v3,16); v3 ^= v2;                 \
    v0 += v3; v3=ROTL(v3,21); v3 ^= v0;                 \
    v2 += v1; v1=ROTL(v1,17); v1 ^= v2; v2=ROTL(v2,32); \
  } while(0)


void
siphash_ref (uint8_t *out, const uint8_t *in, uint64_t inlen, const uint8_t *k)
{
	/* "somepseudorandomlygeneratedbytes" */
	uint64_t v0 = 0x736f6d6570736575ULL;
	uint64_t v1 = 0x646f72616e646f6dULL;
	uint64_t v2 = 0x6c7967656e657261ULL;
	uint64_t v3 = 0x7465646279746573ULL;
	uint64_t b;
	uint64_t k0 = U8TO64_LE(k);
	uint64_t k1 = U8TO64_LE(k + 8);
	uint64_t m;
	int i;
	const uint8_t *end = in + inlen - (inlen % sizeof(uint64_t));
	const int left = inlen & 7;
	b = ((uint64_t) inlen) << 56;
	v3 ^= k1;
	v2 ^= k0;
	v1 ^= k1;
	v0 ^= k0;

#ifdef DOUBLE
	v1 ^= 0xee;
#endif

	for (; in != end; in += 8) {
		m = U8TO64_LE(in);
		v3 ^= m;

		for (i = 0; i < cROUNDS; ++i)
			SIPROUND
			;

		v0 ^= m;
	}

	switch (left) {
	case 7:
		b |= ((uint64_t) in[6]) << 48;
	case 6:
		b |= ((uint64_t) in[5]) << 40;
	case 5:
		b |= ((uint64_t) in[4]) << 32;
	case 4:
		b |= ((uint64_t) in[3]) << 24;
	case 3:
		b |= ((uint64_t) in[2]) << 16;
	case 2:
		b |= ((uint64_t) in[1]) << 8;
	case 1:
		b |= ((uint64_t) in[0]);
		break;
	case 0:
		break;
	}

	v3 ^= b;

	for (i = 0; i < cROUNDS; ++i)
		SIPROUND
		;

	v0 ^= b;

#ifndef DOUBLE
	v2 ^= 0xff;
#else
	v2 ^= 0xee;
#endif

	for (i = 0; i < dROUNDS; ++i)
		SIPROUND
		;

	b = v0 ^ v1 ^ v2 ^ v3;
	U64TO8_LE(out, b);

#ifdef DOUBLE
	v1 ^= 0xdd;

	TRACE;
	for( i=0; i<dROUNDS; ++i ) SIPROUND;

	b = v0 ^ v1 ^ v2 ^ v3;
	U64TO8_LE( out+8, b );
#endif
}
