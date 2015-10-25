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
#include "blake2.h"
#include "blake2-internal.h"

typedef uint64_t blake2b_uint64;

static const unsigned char blake2b_sigma[12][16] = {
		{0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15},
		{14, 10, 4,  8,  9,  15, 13, 6,  1,  12, 0,  2,  11, 7,  5,  3},
		{11, 8,  12, 0,  5,  2,  15, 13, 10, 14, 3,  6,  7,  1,  9,  4},
		{7,  9,  3,  1,  13, 12, 11, 14, 2,  6,  5,  10, 4,  0,  15, 8},
		{9,  0,  5,  7,  2,  4,  10, 15, 14, 1,  11, 12, 6,  8,  3,  13},
		{2,  12, 6,  10, 0,  11, 8,  3,  4,  13, 7,  5,  15, 14, 1,  9},
		{12, 5,  1,  15, 14, 13, 4,  10, 0,  7,  6,  3,  9,  2,  8,  11},
		{13, 11, 7,  14, 12, 1,  3,  9,  5,  0,  15, 4,  8,  6,  2,  10},
		{6,  15, 14, 9,  11, 3,  0,  8,  12, 2,  13, 7,  1,  4,  10, 5},
		{10, 2,  8,  4,  7,  6,  1,  5,  15, 11, 9,  14, 3,  12, 13, 0},
		{0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15},
		{14, 10, 4,  8,  9,  15, 13, 6,  1,  12, 0,  2,  11, 7,  5,  3}
};

static blake2b_uint64
ROTR64 (blake2b_uint64 x, int k)
{
	return ((x >> k) | (x << (64 - k)));
}

static blake2b_uint64
U8TO64 (const unsigned char *p)
{
	return
			((blake2b_uint64) p[0]) |
					((blake2b_uint64) p[1] << 8) |
					((blake2b_uint64) p[2] << 16) |
					((blake2b_uint64) p[3] << 24) |
					((blake2b_uint64) p[4] << 32) |
					((blake2b_uint64) p[5] << 40) |
					((blake2b_uint64) p[6] << 48) |
					((blake2b_uint64) p[7] << 56);
}

static void
U64TO8 (unsigned char *p, blake2b_uint64 v)
{
	p[0] = (v) & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
	p[4] = (v >> 32) & 0xff;
	p[5] = (v >> 40) & 0xff;
	p[6] = (v >> 48) & 0xff;
	p[7] = (v >> 56) & 0xff;
}

void
blake2b_blocks_ref (blake2b_state_internal *S,
		const unsigned char *in,
		size_t bytes,
		size_t stride)
{
	const blake2b_uint64 f0 = U8TO64 (&S->f[0]);
	const blake2b_uint64 f1 = U8TO64 (&S->f[8]);

	const blake2b_uint64 w8 = 0x6a09e667f3bcc908ull;
	const blake2b_uint64 w9 = 0xbb67ae8584caa73bull;
	const blake2b_uint64 w10 = 0x3c6ef372fe94f82bull;
	const blake2b_uint64 w11 = 0xa54ff53a5f1d36f1ull;
	const blake2b_uint64 w12 = 0x510e527fade682d1ull;
	const blake2b_uint64 w13 = 0x9b05688c2b3e6c1full;
	const blake2b_uint64 w14 = 0x1f83d9abfb41bd6bull ^f0;
	const blake2b_uint64 w15 = 0x5be0cd19137e2179ull ^f1;

	const size_t inc = (bytes >= 128) ? 128 : bytes;

	blake2b_uint64 t0 = U8TO64 (&S->t[0]);
	blake2b_uint64 t1 = U8TO64 (&S->t[8]);

	blake2b_uint64 h[8];
	blake2b_uint64 v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15;
	unsigned char buffer[128];

	size_t i;

	if (f0) {
		memset (buffer, 0, sizeof (buffer));
		memcpy (buffer, in, bytes);
		in = buffer;
	}

	for (i = 0; i < 8; i++)
		h[i] = U8TO64 (&S->h[i * 8]);

	while (1) {
		blake2b_uint64 m[16];

		t0 += inc;
		if (t0 < inc)
			t1 += 1;

		for (i = 0; i < 16; i++)
			m[i] = U8TO64 (in + (i * 8));

		v0 = h[0];
		v1 = h[1];
		v2 = h[2];
		v3 = h[3];
		v4 = h[4];
		v5 = h[5];
		v6 = h[6];
		v7 = h[7];
		v8 = w8;
		v9 = w9;
		v10 = w10;
		v11 = w11;
		v12 = w12 ^ t0;
		v13 = w13 ^ t1;
		v14 = w14;
		v15 = w15;

#define G(r, x, a, b, c, d)                       \
            a += b + m[blake2b_sigma[r][2*x+0]]; \
            d = ROTR64(d ^ a, 32);               \
            c += d;                              \
            b = ROTR64(b ^ c, 24);               \
            a += b + m[blake2b_sigma[r][2*x+1]]; \
            d = ROTR64(d ^ a, 16);               \
            c += d;                              \
            b = ROTR64(b ^ c, 63);

		for (i = 0; i < 12; i++) {
			G(i, 0, v0, v4, v8, v12);
			G(i, 1, v1, v5, v9, v13);
			G(i, 2, v2, v6, v10, v14);
			G(i, 3, v3, v7, v11, v15);
			G(i, 4, v0, v5, v10, v15);
			G(i, 5, v1, v6, v11, v12);
			G(i, 6, v2, v7, v8, v13);
			G(i, 7, v3, v4, v9, v14);
		}

		h[0] ^= (v0 ^ v8);
		h[1] ^= (v1 ^ v9);
		h[2] ^= (v2 ^ v10);
		h[3] ^= (v3 ^ v11);
		h[4] ^= (v4 ^ v12);
		h[5] ^= (v5 ^ v13);
		h[6] ^= (v6 ^ v14);
		h[7] ^= (v7 ^ v15);

		if (bytes <= 128)
			break;
		in += stride;
		bytes -= 128;
	}

	for (i = 0; i < 8; i++)
		U64TO8 (&S->h[i * 8], h[i]);
	U64TO8 (&S->t[0], t0);
	U64TO8 (&S->t[8], t1);
}
