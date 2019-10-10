/*-
 * Copyright 2016 Vsevolod Stakhov
 * Copyright (c) 2014 cforler
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "config.h"
#include "catena.h"

#include <sodium.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define TO_LITTLE_ENDIAN_64(n) (n)
#define TO_LITTLE_ENDIAN_32(n) (n)
#else
#define TO_LITTLE_ENDIAN_64 GUINT64_SWAP_LE_BE
#define TO_LITTLE_ENDIAN_32 GUINT32_SWAP_LE_BE
#endif

/* Recommended default values */
#define H_LEN      CATENA_HLEN
#define KEY_LEN    16

const uint8_t VERSION_ID[] = "Butterfly-Full";
const uint8_t LAMBDA = 4;
const uint8_t GARLIC = 16;
const uint8_t MIN_GARLIC = 16;

/*
 * Hash part
 */

static inline void
__Hash1(const uint8_t *input, const uint32_t inputlen,
		uint8_t hash[H_LEN])
{
	crypto_generichash_blake2b_state ctx;
	crypto_generichash_blake2b_init (&ctx, NULL, 0, H_LEN);
	crypto_generichash_blake2b_update (&ctx, input, inputlen);
	crypto_generichash_blake2b_final (&ctx, hash, H_LEN);
}

/***************************************************/

static inline
void __Hash2(const uint8_t *i1, const uint8_t i1len, const uint8_t *i2,
		const uint8_t i2len, uint8_t hash[H_LEN])
{
	crypto_generichash_blake2b_state ctx;

	crypto_generichash_blake2b_init (&ctx, NULL, 0, H_LEN);
	crypto_generichash_blake2b_update (&ctx, i1, i1len);
	crypto_generichash_blake2b_update (&ctx, i2, i2len);
	crypto_generichash_blake2b_final (&ctx, hash, H_LEN);
}

/***************************************************/

static inline
void __Hash3(const uint8_t *i1, const uint8_t i1len, const uint8_t *i2,
		const uint8_t i2len, const uint8_t *i3, const uint8_t i3len,
		uint8_t hash[H_LEN])
{
	crypto_generichash_blake2b_state ctx;

	crypto_generichash_blake2b_init (&ctx, NULL, 0, H_LEN);
	crypto_generichash_blake2b_update (&ctx, i1, i1len);
	crypto_generichash_blake2b_update (&ctx, i2, i2len);
	crypto_generichash_blake2b_update (&ctx, i3, i3len);
	crypto_generichash_blake2b_final (&ctx, hash, H_LEN);
}

/***************************************************/

static inline
void __Hash4(const uint8_t *i1, const uint8_t i1len, const uint8_t *i2,
		const uint8_t i2len, const uint8_t *i3, const uint8_t i3len,
		const uint8_t *i4, const uint8_t i4len, uint8_t hash[H_LEN])
{
	crypto_generichash_blake2b_state ctx;

	crypto_generichash_blake2b_init (&ctx, NULL, 0, H_LEN);
	crypto_generichash_blake2b_update (&ctx, i1, i1len);
	crypto_generichash_blake2b_update (&ctx, i2, i2len);
	crypto_generichash_blake2b_update (&ctx, i3, i3len);
	crypto_generichash_blake2b_update (&ctx, i4, i4len);
	crypto_generichash_blake2b_final (&ctx, hash, H_LEN);
}

/***************************************************/

static inline
void __Hash5(const uint8_t *i1, const uint8_t i1len, const uint8_t *i2,
		const uint8_t i2len, const uint8_t *i3, const uint8_t i3len,
		const uint8_t *i4, const uint8_t i4len, const uint8_t *i5,
		const uint8_t i5len, uint8_t hash[H_LEN])
{
	crypto_generichash_blake2b_state ctx;

	crypto_generichash_blake2b_init (&ctx, NULL, 0, H_LEN);
	crypto_generichash_blake2b_update (&ctx, i1, i1len);
	crypto_generichash_blake2b_update (&ctx, i2, i2len);
	crypto_generichash_blake2b_update (&ctx, i3, i3len);
	crypto_generichash_blake2b_update (&ctx, i4, i4len);
	crypto_generichash_blake2b_update (&ctx, i5, i5len);
	crypto_generichash_blake2b_final (&ctx, hash, H_LEN);
}

static inline void
__HashFast(int vindex, const uint8_t* i1, const uint8_t* i2,
		uint8_t hash[H_LEN])
{
	__Hash2 (i1, H_LEN, i2, H_LEN, hash);
}

static void __ResetState(void)
{
}

/*
 * Misc utils
 */
const uint8_t ZERO8[H_LEN] = {0};

/* see: http://en.wikipedia.org/wiki/Xorshift#Variations */
static int p;
static uint64_t s[16];

static void
initXSState (const uint8_t* a, const uint8_t* b)
{
	p = 0;

	for (int i = 0; i < 8; i++) {
		s[i] = UINT64_C(0);
		s[i + 8] = UINT64_C(0);

		for (int j = 0; j < 8; j++) {
			s[i] |= ((uint64_t) a[i * 8 + j]) << j * 8;
			s[i + 8] |= ((uint64_t) b[i * 8 + j]) << j * 8;
		}
	}
}

static uint64_t
xorshift1024star (void)
{
	uint64_t s0 = s[p];
	uint64_t s1 = s[p = (p + 1) & 15];
	s1 ^= s1 << 31;
	s1 ^= s1 >> 11;
	s0 ^= s0 >> 30;
	return (s[p] = s0 ^ s1) * UINT64_C(1181783497276652981);
}

static void
H_INIT (const uint8_t* x, const uint16_t xlen, uint8_t *vm1, uint8_t *vm2)
{
	const uint8_t l = 2;
	uint8_t *tmp = (uint8_t*) g_malloc (l * H_LEN);

	for (uint8_t i = 0; i != l; ++i) {
		__Hash2 (&i, 1, x, xlen, tmp + i * H_LEN);
	}

	memcpy (vm1, tmp, H_LEN);
	memcpy (vm2, tmp+(l/2*H_LEN), H_LEN);
	g_free (tmp);
}

static void
H_First (const uint8_t* i1, const uint8_t* i2, uint8_t* hash)
{
	uint8_t i = 0;
	uint8_t *x = (uint8_t*) g_malloc (H_LEN);

	__ResetState ();
	__Hash2 (i1, H_LEN, i2, H_LEN, x);
	__Hash2 (&i, 1, x, H_LEN, hash);
	g_free (x);
}

static inline void
initmem (const uint8_t x[H_LEN], const uint64_t c, uint8_t *r)
{
	uint8_t *vm2 = (uint8_t*) g_malloc (H_LEN);
	uint8_t *vm1 = (uint8_t*) g_malloc (H_LEN);

	H_INIT (x, H_LEN, vm1, vm2);
	__ResetState ();
	__HashFast (0, vm1, vm2, r);
	__HashFast (1, r, vm1, r + H_LEN);

	/* Top row */
	for (uint64_t i = 2; i < c; i++) {
		__HashFast (i, r + (i - 1) * H_LEN, r + (i - 2) * H_LEN, r + i * H_LEN);
	}

	g_free (vm2);
	g_free (vm1);
}

static inline void
catena_gamma (const uint8_t garlic, const uint8_t *salt,
			  const uint8_t saltlen, uint8_t *r)
{
	const uint64_t q = UINT64_C(1) << ((3 * garlic + 3) / 4);

	uint64_t i, j, j2;
	uint8_t *tmp = g_malloc (H_LEN);
	uint8_t *tmp2 = g_malloc (H_LEN);

	__Hash1 (salt, saltlen, tmp);
	__Hash1 (tmp, H_LEN, tmp2);
	initXSState (tmp, tmp2);

	__ResetState ();
	for (i = 0; i < q; i++) {
		j = xorshift1024star () >> (64 - garlic);
		j2 = xorshift1024star () >> (64 - garlic);
		__HashFast (i, r + j * H_LEN, r + j2 * H_LEN, r + j * H_LEN);
	}

	g_free (tmp);
	g_free (tmp2);
}

static void
XOR (const uint8_t *input1, const uint8_t *input2, uint8_t *output)
{
	uint32_t i;

	for(i = 0; i < H_LEN; i++) {
		output[i] = input1[i] ^ input2[i];
	}
}

/*
 * Butterfly part
 */
/*
 * Sigma function that defines the diagonal connections of a DBG
 * diagonal front: flip the (g-i)th bit (Inverse Buttferly Graph)
 * diagonal back: flip the i-(g-1)th bit (Regular Butterfly Graph)
 */
static uint64_t
sigma(const uint8_t g, const uint64_t i, const uint64_t j)
{
	if (i < g) {
		return (j ^ (UINT64_C(1) << (g - 1 - i))); /* diagonal front */
	}
	else {
		return (j ^ (UINT64_C(1) << (i - (g - 1)))); /* diagonal back */
	}
}

/*calculate actual index from level and element index*/
static uint64_t
idx(uint64_t i, uint64_t j, uint8_t co, uint64_t c, uint64_t m)
{
	i += co;
	if (i % 3 == 0) {
		return j;
	}
	else if (i % 3 == 1) {
		if (j < m) {
			/* still fits in the array */
			return j + c;
		}
		else {
			/* start overwriting elements at the beginning */
			return j - m;
		}
	}
	/* i % 3 == 2 */
	return j + m;
}

/*
 * Computes the hash of x using a Double Butterfly Graph,
 * that forms as (2^g,\lamba)-Superconcentrator
 */
static void
Flap (const uint8_t x[H_LEN], const uint8_t lambda, const uint8_t garlic,
		const uint8_t *salt, const uint8_t saltlen, uint8_t h[H_LEN])
{
	const uint64_t c = UINT64_C(1) << garlic;
	const uint64_t m = UINT64_C(1) << (garlic - 1);    /* 0.5 * 2^g */
	const uint32_t l = 2 * garlic;

	uint8_t *r = g_malloc ((c + m) * H_LEN);
	uint8_t *tmp = g_malloc (H_LEN);
	uint64_t i, j;
	uint8_t k;
	uint8_t co = 0;    /* carry over from last iteration */

	/* Top row */
	initmem (x, c, r);

	/*Gamma Function*/
	catena_gamma (garlic, salt, saltlen, r);

	/* DBH */
	for (k = 0; k < lambda; k++) {
		for (i = 1; i < l; i++) {
			XOR (r + idx (i - 1, c - 1, co, c, m) * H_LEN,
					r + idx (i - 1, 0, co, c, m) * H_LEN, tmp);

			/*
			 * r0 := H(tmp || vsigma(g,i-1,0) )
			 * __Hash2(tmp, H_LEN, r+idx(i-1,sigma(garlic,i-1,0),co,c,m) * H_LEN, H_LEN,
			 * r+idx(i,0,co,c,m) *H_LEN);
			 */
			H_First (tmp,
					r + idx (i - 1, sigma (garlic, i - 1, 0), co, c, m) * H_LEN,
					r + idx (i, 0, co, c, m) * H_LEN);
			__ResetState ();

			/* vertices */
			for (j = 1; j < c; j++) {
				/* tmp:= rj-1 XOR vj */
				XOR (r + idx (i, j - 1, co, c, m) * H_LEN,
						r + idx (i - 1, j, co, c, m) * H_LEN, tmp);
				/* rj := H(tmp || vsigma(g,i-1,j)) */
				__HashFast (j, tmp,
						r + idx (i - 1, sigma (garlic, i - 1, j), co, c, m) * H_LEN,
						r + idx (i, j, co, c, m) * H_LEN);
			}
		}
		co = (co + (i - 1)) % 3;
	}

	memcpy(h, r + idx(0,c-1,co,c,m) * H_LEN, H_LEN);
	g_free (r);
	g_free (tmp);
}

static int
__Catena (const uint8_t *pwd, const uint32_t pwdlen,
		const uint8_t *salt, const uint8_t saltlen, const uint8_t *data,
		const uint32_t datalen, const uint8_t lambda, const uint8_t min_garlic,
		const uint8_t garlic, const uint8_t hashlen, const uint8_t client,
		const uint8_t tweak_id, uint8_t *hash)
{
	uint8_t x[H_LEN];
	uint8_t hv[H_LEN];
	uint8_t t[4];
	uint8_t c;

	if ((hashlen > H_LEN) || (garlic > 63) || (min_garlic > garlic)
			|| (lambda == 0) || (min_garlic == 0)) {
		return -1;
	}

	/*Compute H(V)*/
	__Hash1 (VERSION_ID, strlen ((char*) VERSION_ID), hv);

	/* Compute Tweak */
	t[0] = tweak_id;
	t[1] = lambda;
	t[2] = hashlen;
	t[3] = saltlen;

	/* Compute H(AD) */
	__Hash1 ((uint8_t *) data, datalen, x);

	/* Compute the initial value to hash  */
	__Hash5 (hv, H_LEN, t, 4, x, H_LEN, pwd, pwdlen, salt, saltlen, x);

	/*Overwrite Password if enabled*/
#ifdef OVERWRITE
	erasepwd(pwd,pwdlen);
#endif

	Flap (x, lambda, (min_garlic + 1) / 2, salt, saltlen, x);

	for (c = min_garlic; c <= garlic; c++) {
		Flap (x, lambda, c, salt, saltlen, x);
		if ((c == garlic) && (client == CLIENT)) {
			memcpy (hash, x, H_LEN);
			return 0;
		}
		__Hash2 (&c, 1, x, H_LEN, x);
		memset (x + hashlen, 0, H_LEN - hashlen);
	}

	memcpy (hash, x, hashlen);

	return 0;
}

/***************************************************/

int
catena (const uint8_t *pwd, const uint32_t pwdlen, const uint8_t *salt,
		const uint8_t saltlen, const uint8_t *data, const uint32_t datalen,
		const uint8_t lambda, const uint8_t min_garlic, const uint8_t garlic,
		const uint8_t hashlen, uint8_t *hash)
{
	return __Catena (pwd, pwdlen, salt, saltlen, data, datalen, lambda,
			min_garlic, garlic, hashlen, REGULAR, PASSWORD_HASHING_MODE, hash);

}

int
simple_catena (const uint8_t *pwd,   const uint32_t pwdlen,
		  const uint8_t *salt,  const uint8_t  saltlen,
		  const uint8_t *data,  const uint32_t datalen,
		  uint8_t hash[H_LEN])
{
  return __Catena (pwd, pwdlen, salt, saltlen, data, datalen,
		  LAMBDA, MIN_GARLIC, GARLIC, H_LEN,
		  REGULAR, PASSWORD_HASHING_MODE, hash);
}

int
catena_test (void)
{
	/* From catena-v3.1 spec */
	guint8 pw[] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64};
	guint8 salt[] = {0x73, 0x61, 0x6c, 0x74};
	guint8 ad[] = {0x64, 0x61,0x74, 0x61};
	guint8 expected[] = {
		0x20, 0xc5, 0x91, 0x93, 0x8f, 0xc3, 0xaf, 0xcc, 0x3b, 0xba, 0x91, 0xd2, 0xfb,
		0x84, 0xbf, 0x7b, 0x44, 0x04, 0xf9, 0x4c, 0x45, 0xed, 0x4d, 0x11, 0xa7, 0xe2,
		0xb4, 0x12, 0x3e, 0xab, 0x0b, 0x77, 0x4a, 0x12, 0xb4, 0x22, 0xd0, 0xda, 0xb5,
		0x25, 0x29, 0x02, 0xfc, 0x54, 0x47, 0xea, 0x82, 0x63, 0x8c, 0x1a, 0xfb, 0xa7,
		0xa9, 0x94, 0x24, 0x13, 0x0e, 0x44, 0x36, 0x3b, 0x9d, 0x9f, 0xc9, 0x60
	};
	guint8 real[H_LEN];

	if (catena (pw, sizeof (pw), salt, sizeof (salt), ad, sizeof (ad),
			4, 10, 10, H_LEN, real) != 0) {
		return -1;
	}

	return memcmp (real, expected, H_LEN);
}
