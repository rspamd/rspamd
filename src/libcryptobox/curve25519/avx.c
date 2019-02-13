/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "cryptobox.h"
#include "curve25519.h"
#include "platform_config.h"

typedef struct {
	guint64 v[5];
} fe51;
typedef guint64 fe[10];

extern void ladder_avx (fe *var, const guchar *p);
extern void ladder_base_avx (fe *var, const guchar *p);
extern void fe51_mul_avx (fe51 *a, const fe51 *b, const fe51 *c);
extern void fe51_pack_avx (guchar *out, const fe51 *var);
extern void fe51_nsquare_avx (fe51 *a, const fe51 *b, gint n);


static guint64 load_3 (const unsigned char *in)
{
	guint64 result;
	result = (guint64) in[0];
	result |= ((guint64) in[1]) << 8;
	result |= ((guint64) in[2]) << 16;
	return result;
}

static guint64 load_4 (const unsigned char *in)
{
	guint64 result;
	result = (guint64) in[0];
	result |= ((guint64) in[1]) << 8;
	result |= ((guint64) in[2]) << 16;
	result |= ((guint64) in[3]) << 24;
	return result;
}

static void
fe_frombytes (fe h, const unsigned char *s)
{
	guint64 h0 = load_4 (s);
	guint64 h1 = load_3 (s + 4) << 6;
	guint64 h2 = load_3 (s + 7) << 5;
	guint64 h3 = load_3 (s + 10) << 3;
	guint64 h4 = load_3 (s + 13) << 2;
	guint64 h5 = load_4 (s + 16);
	guint64 h6 = load_3 (s + 20) << 7;
	guint64 h7 = load_3 (s + 23) << 5;
	guint64 h8 = load_3 (s + 26) << 4;
	guint64 h9 = (load_3(s + 29) & 8388607) << 2;
	guint64 carry0;
	guint64 carry1;
	guint64 carry2;
	guint64 carry3;
	guint64 carry4;
	guint64 carry5;
	guint64 carry6;
	guint64 carry7;
	guint64 carry8;
	guint64 carry9;

	carry9 = h9 >> 25;
	h0 += carry9 * 19;
	h9 &= 0x1FFFFFF;
	carry1 = h1 >> 25;
	h2 += carry1;
	h1 &= 0x1FFFFFF;
	carry3 = h3 >> 25;
	h4 += carry3;
	h3 &= 0x1FFFFFF;
	carry5 = h5 >> 25;
	h6 += carry5;
	h5 &= 0x1FFFFFF;
	carry7 = h7 >> 25;
	h8 += carry7;
	h7 &= 0x1FFFFFF;

	carry0 = h0 >> 26;
	h1 += carry0;
	h0 &= 0x3FFFFFF;
	carry2 = h2 >> 26;
	h3 += carry2;
	h2 &= 0x3FFFFFF;
	carry4 = h4 >> 26;
	h5 += carry4;
	h4 &= 0x3FFFFFF;
	carry6 = h6 >> 26;
	h7 += carry6;
	h6 &= 0x3FFFFFF;
	carry8 = h8 >> 26;
	h9 += carry8;
	h8 &= 0x3FFFFFF;

	h[0] = h0;
	h[1] = h1;
	h[2] = h2;
	h[3] = h3;
	h[4] = h4;
	h[5] = h5;
	h[6] = h6;
	h[7] = h7;
	h[8] = h8;
	h[9] = h9;
}

#define fe51_square(x, y) fe51_nsquare_avx(x, y, 1)

void fe51_invert (fe51 *r, const fe51 *x)
{
	fe51 z2;
	fe51 z9;
	fe51 z11;
	fe51 z2_5_0;
	fe51 z2_10_0;
	fe51 z2_20_0;
	fe51 z2_50_0;
	fe51 z2_100_0;
	fe51 t;

	/* 2 */ fe51_square (&z2, x);
	/* 4 */ fe51_square (&t, &z2);
	/* 8 */ fe51_square (&t, &t);
	/* 9 */ fe51_mul_avx (&z9, &t, x);
	/* 11 */ fe51_mul_avx (&z11, &z9, &z2);
	/* 22 */ fe51_square (&t, &z11);
	/* 2^5 - 2^0 = 31 */ fe51_mul_avx (&z2_5_0, &t, &z9);

	/* 2^10 - 2^5 */ fe51_nsquare_avx (&t, &z2_5_0, 5);
	/* 2^10 - 2^0 */ fe51_mul_avx (&z2_10_0, &t, &z2_5_0);

	/* 2^20 - 2^10 */ fe51_nsquare_avx (&t, &z2_10_0, 10);
	/* 2^20 - 2^0 */ fe51_mul_avx (&z2_20_0, &t, &z2_10_0);

	/* 2^40 - 2^20 */ fe51_nsquare_avx (&t, &z2_20_0, 20);
	/* 2^40 - 2^0 */ fe51_mul_avx (&t, &t, &z2_20_0);

	/* 2^50 - 2^10 */ fe51_nsquare_avx (&t, &t, 10);
	/* 2^50 - 2^0 */ fe51_mul_avx (&z2_50_0, &t, &z2_10_0);

	/* 2^100 - 2^50 */ fe51_nsquare_avx (&t, &z2_50_0, 50);
	/* 2^100 - 2^0 */ fe51_mul_avx (&z2_100_0, &t, &z2_50_0);

	/* 2^200 - 2^100 */ fe51_nsquare_avx (&t, &z2_100_0, 100);
	/* 2^200 - 2^0 */ fe51_mul_avx (&t, &t, &z2_100_0);

	/* 2^250 - 2^50 */ fe51_nsquare_avx (&t, &t, 50);
	/* 2^250 - 2^0 */ fe51_mul_avx (&t, &t, &z2_50_0);

	/* 2^255 - 2^5 */ fe51_nsquare_avx (&t, &t, 5);
	/* 2^255 - 21 */ fe51_mul_avx (r, &t, &z11);
}

#define x1 var[0]
#define x2 var[1]
#define z2 var[2]

void
scalarmult_avx (unsigned char *q,
		const unsigned char *n,
		const unsigned char *p)
{
	fe var[3];
	fe51 x_51;
	fe51 z_51;
	unsigned char e[32];

	memcpy (e, n, 32);
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;

	fe_frombytes (x1, p);

	ladder_avx (var, e);

	z_51.v[0] = (z2[1] << 26) + z2[0];
	z_51.v[1] = (z2[3] << 26) + z2[2];
	z_51.v[2] = (z2[5] << 26) + z2[4];
	z_51.v[3] = (z2[7] << 26) + z2[6];
	z_51.v[4] = (z2[9] << 26) + z2[8];

	x_51.v[0] = (x2[1] << 26) + x2[0];
	x_51.v[1] = (x2[3] << 26) + x2[2];
	x_51.v[2] = (x2[5] << 26) + x2[4];
	x_51.v[3] = (x2[7] << 26) + x2[6];
	x_51.v[4] = (x2[9] << 26) + x2[8];

	fe51_invert (&z_51, &z_51);
	fe51_mul_avx (&x_51, &x_51, &z_51);
	fe51_pack_avx (q, &x_51);
}

#undef x2
#undef z2
#define x2 var[0]
#define z2 var[1]

int
scalarmult_base_avx (unsigned char *q, const unsigned char *n)
{
	unsigned char e[32];

	fe var[3];

	fe51 x_51;
	fe51 z_51;

	memcpy (e, n, 32);
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;

	ladder_base_avx (var, e);

	z_51.v[0] = (z2[1] << 26) + z2[0];
	z_51.v[1] = (z2[3] << 26) + z2[2];
	z_51.v[2] = (z2[5] << 26) + z2[4];
	z_51.v[3] = (z2[7] << 26) + z2[6];
	z_51.v[4] = (z2[9] << 26) + z2[8];

	x_51.v[0] = (x2[1] << 26) + x2[0];
	x_51.v[1] = (x2[3] << 26) + x2[2];
	x_51.v[2] = (x2[5] << 26) + x2[4];
	x_51.v[3] = (x2[7] << 26) + x2[6];
	x_51.v[4] = (x2[9] << 26) + x2[8];

	fe51_invert (&z_51, &z_51);
	fe51_mul_avx (&x_51, &x_51, &z_51);
	fe51_pack_avx (q, &x_51);

	return 0;
}
