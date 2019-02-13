/*
 * Copyright (c) 2013-2016
 * Frank Denis <j at pureftpd dot org>
 * Vsevolod Stakhov
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "config.h"
#include "ed25519.h"
#include "cryptobox.h"
#include "../curve25519/fe.h"
#include "ottery.h"
#include <openssl/evp.h> /* SHA512 */

int
ed_seed_keypair_ref (unsigned char *pk, unsigned char *sk,
		const unsigned char *seed)
{
	ge_p3 A;
	EVP_MD_CTX *sha_ctx;

	sha_ctx = EVP_MD_CTX_create ();
	g_assert (sha_ctx && EVP_DigestInit (sha_ctx, EVP_sha512()) == 1);
	EVP_DigestUpdate (sha_ctx, seed, 32);
	EVP_DigestFinal (sha_ctx, sk, NULL);

	sk[0] &= 248;
	sk[31] &= 63;
	sk[31] |= 64;

	ge_scalarmult_base (&A, sk);
	ge_p3_tobytes (pk, &A);

	memmove (sk, seed, 32);
	memmove (sk + 32, pk, 32);

	EVP_MD_CTX_destroy (sha_ctx);

	return 0;
}

int
ed_keypair_ref (unsigned char *pk, unsigned char *sk)
{
	unsigned char seed[32];
	int ret;

	ottery_rand_bytes (seed, sizeof (seed));
	ret = ed_seed_keypair_ref (pk, sk, seed);
	rspamd_explicit_memzero (seed, sizeof (seed));

	return ret;
}

int
ed_verify_ref(const unsigned char *sig, const unsigned char *m,
		size_t mlen, const unsigned char *pk)
{
	EVP_MD_CTX *sha_ctx;
	unsigned char h[64];
	unsigned char rcheck[32];
	unsigned int i;
	unsigned char d = 0;
	ge_p3 A;
	ge_p2 R;

	if (sig[63] & 224) {
		return -1;
	}
	if (ge_frombytes_negate_vartime (&A, pk) != 0) {
		return -1;
	}
	for (i = 0; i < 32; ++i) {
		d |= pk[i];
	}
	if (d == 0) {
		return -1;
	}

	sha_ctx = EVP_MD_CTX_create ();
	g_assert (sha_ctx && EVP_DigestInit (sha_ctx, EVP_sha512()) == 1);
	EVP_DigestUpdate (sha_ctx, sig, 32);
	EVP_DigestUpdate (sha_ctx, pk, 32);
	EVP_DigestUpdate (sha_ctx, m, mlen);
	EVP_DigestFinal (sha_ctx, h, NULL);

	sc_reduce (h);

	EVP_MD_CTX_destroy (sha_ctx);

	ge_double_scalarmult_vartime (&R, h, &A, sig + 32);
	ge_tobytes (rcheck, &R);

	return verify_32 (rcheck, sig) | (-(rcheck == sig));
}

void
ed_sign_ref(unsigned char *sig, size_t *siglen_p,
		const unsigned char *m, size_t mlen,
		const unsigned char *sk)
{
	EVP_MD_CTX *sha_ctx;
	unsigned char az[64];
	unsigned char nonce[64];
	unsigned char hram[64];
	ge_p3 R;

	sha_ctx = EVP_MD_CTX_create ();
	g_assert (sha_ctx && EVP_DigestInit (sha_ctx, EVP_sha512()) == 1);
	EVP_DigestUpdate (sha_ctx, sk, 32);
	EVP_DigestFinal (sha_ctx, az, NULL);
	az[0] &= 248;
	az[31] &= 63;
	az[31] |= 64;

	g_assert (EVP_DigestInit (sha_ctx, EVP_sha512()) == 1);
	EVP_DigestUpdate (sha_ctx, az + 32, 32);
	EVP_DigestUpdate (sha_ctx, m, mlen);
	EVP_DigestFinal (sha_ctx, nonce, NULL);

	memmove (sig + 32, sk + 32, 32);

	sc_reduce (nonce);
	ge_scalarmult_base (&R, nonce);
	ge_p3_tobytes (sig, &R);

	g_assert (EVP_DigestInit (sha_ctx, EVP_sha512()) == 1);
	EVP_DigestUpdate (sha_ctx, sig, 64);
	EVP_DigestUpdate (sha_ctx, m, mlen);
	EVP_DigestFinal (sha_ctx, hram, NULL);

	sc_reduce (hram);
	sc_muladd (sig + 32, hram, az, nonce);

	rspamd_explicit_memzero (az, sizeof (az));
	EVP_MD_CTX_destroy (sha_ctx);

	if (siglen_p != NULL) {
		*siglen_p = 64U;
	}
}
