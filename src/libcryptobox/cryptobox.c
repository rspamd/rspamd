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
/* Workaround for memset_s */
#ifdef __APPLE__
#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>
#endif

#include "config.h"
#include "cryptobox.h"
#include "platform_config.h"
#include "chacha20/chacha.h"
#include "poly1305/poly1305.h"
#include "curve25519/curve25519.h"
#include "ed25519/ed25519.h"
#include "blake2/blake2.h"
#include "siphash/siphash.h"
#include "catena/catena.h"
#include "ottery.h"
#include "printf.h"
#include "xxhash.h"
#define MUM_TARGET_INDEPENDENT_HASH 1 /* For 32/64 bit equal hashes */
#include "../../contrib/mumhash/mum.h"
#include "../../contrib/metrohash/metro.h"
#ifdef HAVE_CPUID_H
#include <cpuid.h>
#endif
#ifdef HAVE_OPENSSL
#include <openssl/opensslv.h>
/* Openssl >= 1.0.1d is required for GCM verification */
#if OPENSSL_VERSION_NUMBER >= 0x1000104fL
#define HAVE_USABLE_OPENSSL 1
#endif
#endif

#ifdef HAVE_USABLE_OPENSSL
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#define CRYPTOBOX_CURVE_NID NID_X9_62_prime256v1
#endif

#include <signal.h>
#include <setjmp.h>

unsigned long cpu_config = 0;

static gboolean cryptobox_loaded = FALSE;

static const guchar n0[16] = {0};

#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
_dummy_symbol_to_prevent_lto(void * const pnt, const size_t len)
{
	(void) pnt;
	(void) len;
}
#endif

#define CRYPTOBOX_ALIGNMENT   32    /* Better for AVX */
#define cryptobox_align_ptr(p, a)                                             \
    (void *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

void
rspamd_explicit_memzero(void * const pnt, const gsize len)
{
#if defined(HAVE_MEMSET_S)
	if (memset_s (pnt, (rsize_t) len, 0, (rsize_t) len) != 0) {
		g_assert (0);
	}
#elif defined(HAVE_EXPLICIT_BZERO)
	explicit_bzero (pnt, len);
#elif defined(HAVE_WEAK_SYMBOLS)
	memset (pnt, 0, len);
	_dummy_symbol_to_prevent_lto (pnt, len);
#else
	volatile unsigned char *pnt_ = (volatile unsigned char *) pnt;
	gsize i = (gsize) 0U;
	while (i < len) {
		pnt_[i++] = 0U;
	}
#endif
}

static void
rspamd_cryptobox_cpuid (gint cpu[4], gint info)
{
	guint32 eax, ecx = 0, ebx = 0, edx = 0;

	eax = info;
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
# if defined( __i386__ ) && defined ( __PIC__ )

	/* in case of PIC under 32-bit EBX cannot be clobbered */

	__asm__ volatile ("movl %%ebx, %%edi \n\t cpuid \n\t xchgl %%ebx, %%edi" : "=D" (ebx),
			"+a" (eax), "+c" (ecx), "=d" (edx));
# else
	__asm__ volatile ("cpuid" : "+b" (ebx), "+a" (eax), "+c" (ecx), "=d" (edx));
# endif

	cpu[0] = eax; cpu[1] = ebx; cpu[2] = ecx; cpu[3] = edx;
#else
	memset (cpu, 0, sizeof (gint) * 4);
#endif
}

static sig_atomic_t ok = 0;
static jmp_buf j;

static void
rspamd_cryptobox_ill_handler (int signo)
{
	ok = 0;
	longjmp (j, -1);
}

static gboolean
rspamd_cryptobox_test_instr (gint instr)
{
	void (*old_handler) (int);
	guint32 rd;

#if defined(__GNUC__)
	ok = 1;
	old_handler = signal (SIGILL, rspamd_cryptobox_ill_handler);

	if (setjmp (j) != 0) {
		signal (SIGILL, old_handler);

		return FALSE;
	}

	switch (instr) {
#ifdef HAVE_SSE2
	case CPUID_SSE2:
		__asm__ volatile ("pmuludq %xmm0, %xmm0");
		break;
	case CPUID_RDRAND:
		/* Use byte code here for compatibility */
		__asm__ volatile (".byte 0x0f,0xc7,0xf0; setc %1"
			: "=a" (rd), "=qm" (ok)
			:
			: "edx"
		);
		break;
#endif
#ifdef HAVE_SSE3
	case CPUID_SSE3:
		__asm__ volatile ("movshdup %xmm0, %xmm0");
		break;
#endif
#ifdef HAVE_SSSE3
	case CPUID_SSSE3:
		__asm__ volatile ("pshufb %xmm0, %xmm0");
		break;
#endif
#ifdef HAVE_SSE41
	case CPUID_SSE41:
		__asm__ volatile ("pcmpeqq %xmm0, %xmm0");
		break;
#endif
#ifdef HAVE_AVX
	case CPUID_AVX:
		__asm__ volatile ("vpaddq %xmm0, %xmm0, %xmm0");
		break;
#endif
#ifdef HAVE_AVX2
	case CPUID_AVX2:
		__asm__ volatile ("vpaddq %ymm0, %ymm0, %ymm0");\
		break;
#endif
	default:
		return FALSE;
		break;
	}

	signal (SIGILL, old_handler);
#endif

	/* We actually never return here if SIGILL has been caught */
	return ok == 1;
}

struct rspamd_cryptobox_library_ctx*
rspamd_cryptobox_init (void)
{
	gint cpu[4], nid;
	const guint32 osxsave_mask = (1 << 27);
	const guint32 fma_movbe_osxsave_mask = ((1 << 12) | (1 << 22) | (1 << 27));
	const guint32 avx2_bmi12_mask = (1 << 5) | (1 << 3) | (1 << 8);
	gulong bit;
	static struct rspamd_cryptobox_library_ctx *ctx;
	GString *buf;

	if (cryptobox_loaded) {
		/* Ignore reload attempts */
		return ctx;
	}

	cryptobox_loaded = TRUE;
	ctx = g_malloc0 (sizeof (*ctx));

	rspamd_cryptobox_cpuid (cpu, 0);
	nid = cpu[0];
	rspamd_cryptobox_cpuid (cpu, 1);

	if (nid > 1) {
		if ((cpu[3] & ((guint32)1 << 26))) {
			if (rspamd_cryptobox_test_instr (CPUID_SSE2)) {
				cpu_config |= CPUID_SSE2;
			}
		}
		if ((cpu[2] & ((guint32)1 << 0))) {
			if (rspamd_cryptobox_test_instr (CPUID_SSE3)) {
				cpu_config |= CPUID_SSE3;
			}
		}
		if ((cpu[2] & ((guint32)1 << 9))) {
			if (rspamd_cryptobox_test_instr (CPUID_SSSE3)) {
				cpu_config |= CPUID_SSSE3;
			}
		}
		if ((cpu[2] & ((guint32)1 << 19))) {
			if (rspamd_cryptobox_test_instr (CPUID_SSE41)) {
				cpu_config |= CPUID_SSE41;
			}
		}
		if ((cpu[2] & ((guint32)1 << 30))) {
			if (rspamd_cryptobox_test_instr (CPUID_RDRAND)) {
				cpu_config |= CPUID_RDRAND;
			}
		}

		/* OSXSAVE */
		if ((cpu[2] & osxsave_mask) == osxsave_mask) {
			if ((cpu[2] & ((guint32)1 << 28))) {
				if (rspamd_cryptobox_test_instr (CPUID_AVX)) {
					cpu_config |= CPUID_AVX;
				}
			}

			if (nid >= 7 &&
					(cpu[2] & fma_movbe_osxsave_mask) == fma_movbe_osxsave_mask) {
				rspamd_cryptobox_cpuid (cpu, 7);

				if ((cpu[1] & avx2_bmi12_mask) == avx2_bmi12_mask) {
					if (rspamd_cryptobox_test_instr (CPUID_AVX2)) {
						cpu_config |= CPUID_AVX2;
					}
				}
			}
		}
	}

	buf = g_string_new ("");

	for (bit = 0x1; bit != 0; bit <<= 1) {
		if (cpu_config & bit) {
			switch (bit) {
			case CPUID_SSE2:
				rspamd_printf_gstring (buf, "sse2, ");
				break;
			case CPUID_SSE3:
				rspamd_printf_gstring (buf, "sse3, ");
				break;
			case CPUID_SSSE3:
				rspamd_printf_gstring (buf, "ssse3, ");
				break;
			case CPUID_SSE41:
				rspamd_printf_gstring (buf, "sse4.1, ");
				break;
			case CPUID_AVX:
				rspamd_printf_gstring (buf, "avx, ");
				break;
			case CPUID_AVX2:
				rspamd_printf_gstring (buf, "avx2, ");
				break;
			case CPUID_RDRAND:
				rspamd_printf_gstring (buf, "rdrand, ");
				break;
			}
		}
	}

	if (buf->len > 2) {
		/* Trim last chars */
		g_string_erase (buf, buf->len - 2, 2);
	}

	ctx->cpu_extensions = buf->str;
	g_string_free (buf, FALSE);
	ctx->cpu_config = cpu_config;

	ctx->chacha20_impl = chacha_load ();
	ctx->poly1305_impl = poly1305_load ();
	ctx->siphash_impl = siphash_load ();
	ctx->curve25519_impl = curve25519_load ();
	ctx->blake2_impl = blake2b_load ();
	ctx->ed25519_impl = ed25519_load ();
#ifdef HAVE_USABLE_OPENSSL
	ERR_load_ECDSA_strings ();
	ERR_load_EC_strings ();
	ERR_load_RAND_strings ();
	ERR_load_EVP_strings ();
	ERR_load_ECDH_strings ();
#endif

	return ctx;
}

void
rspamd_cryptobox_keypair (rspamd_pk_t pk, rspamd_sk_t sk,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		ottery_rand_bytes (sk, rspamd_cryptobox_MAX_SKBYTES);
		sk[0] &= 248;
		sk[31] &= 127;
		sk[31] |= 64;

		curve25519_base (pk, sk);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EC_KEY *ec_sec;
		const BIGNUM *bn_sec;
		BIGNUM *bn_pub;
		const EC_POINT *ec_pub;
		gint len;

		ec_sec = EC_KEY_new_by_curve_name (CRYPTOBOX_CURVE_NID);
		g_assert (ec_sec != NULL);
		g_assert (EC_KEY_generate_key (ec_sec) != 0);

		bn_sec = EC_KEY_get0_private_key (ec_sec);
		g_assert (bn_sec != NULL);
		ec_pub = EC_KEY_get0_public_key (ec_sec);
		g_assert (ec_pub != NULL);
		bn_pub = EC_POINT_point2bn (EC_KEY_get0_group (ec_sec),
				ec_pub, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);

		len = BN_num_bytes (bn_sec);
		g_assert (len <= (gint)sizeof (rspamd_sk_t));
		BN_bn2bin (bn_sec, sk);
		len = BN_num_bytes (bn_pub);
		g_assert (len <= (gint)rspamd_cryptobox_pk_bytes (mode));
		BN_bn2bin (bn_pub, pk);
		BN_free (bn_pub);
		EC_KEY_free (ec_sec);
#endif
	}
}

void
rspamd_cryptobox_keypair_sig (rspamd_sig_pk_t pk, rspamd_sig_sk_t sk,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		ed25519_keypair (pk, sk);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EC_KEY *ec_sec;
		const BIGNUM *bn_sec;
		BIGNUM *bn_pub;
		const EC_POINT *ec_pub;
		gint len;

		ec_sec = EC_KEY_new_by_curve_name (CRYPTOBOX_CURVE_NID);
		g_assert (ec_sec != NULL);
		g_assert (EC_KEY_generate_key (ec_sec) != 0);

		bn_sec = EC_KEY_get0_private_key (ec_sec);
		g_assert (bn_sec != NULL);
		ec_pub = EC_KEY_get0_public_key (ec_sec);
		g_assert (ec_pub != NULL);
		bn_pub = EC_POINT_point2bn (EC_KEY_get0_group (ec_sec),
				ec_pub, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);

		len = BN_num_bytes (bn_sec);
		g_assert (len <= (gint)sizeof (rspamd_sk_t));
		BN_bn2bin (bn_sec, sk);
		len = BN_num_bytes (bn_pub);
		g_assert (len <= (gint)rspamd_cryptobox_pk_bytes (mode));
		BN_bn2bin (bn_pub, pk);
		BN_free (bn_pub);
		EC_KEY_free (ec_sec);
#endif
	}
}

void
rspamd_cryptobox_nm (rspamd_nm_t nm,
		const rspamd_pk_t pk, const rspamd_sk_t sk,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		guchar s[32];
		guchar e[32];

		memcpy (e, sk, 32);
		e[0] &= 248;
		e[31] &= 127;
		e[31] |= 64;

		curve25519 (s, e, pk);
		hchacha (s, n0, nm, 20);

		rspamd_explicit_memzero (e, 32);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EC_KEY *lk;
		EC_POINT *ec_pub;
		BIGNUM *bn_pub, *bn_sec;
		gint len;
		guchar s[32];

		lk = EC_KEY_new_by_curve_name (CRYPTOBOX_CURVE_NID);
		g_assert (lk != NULL);

		bn_pub = BN_bin2bn (pk, rspamd_cryptobox_pk_bytes (mode), NULL);
		g_assert (bn_pub != NULL);
		bn_sec = BN_bin2bn (sk, sizeof (rspamd_sk_t), NULL);
		g_assert (bn_sec != NULL);

		g_assert (EC_KEY_set_private_key (lk, bn_sec) == 1);
		ec_pub = EC_POINT_bn2point (EC_KEY_get0_group (lk), bn_pub, NULL, NULL);
		g_assert (ec_pub != NULL);
		len = ECDH_compute_key (s, sizeof (s), ec_pub, lk, NULL);
		g_assert (len == sizeof (s));

		/* Still do hchacha iteration since we are not using SHA1 KDF */
		hchacha (s, n0, nm, 20);

		EC_KEY_free (lk);
		EC_POINT_free (ec_pub);
		BN_free (bn_sec);
		BN_free (bn_pub);
#endif
	}
}

void
rspamd_cryptobox_sign (guchar *sig, gsize *siglen_p,
		const guchar *m, gsize mlen,
		const rspamd_sk_t sk,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		ed25519_sign (sig, siglen_p, m, mlen, sk);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EC_KEY *lk;
		BIGNUM *bn_sec, *kinv = NULL, *rp = NULL;
		EVP_MD_CTX sha_ctx;
		unsigned char h[64];
		guint diglen = rspamd_cryptobox_signature_bytes (mode);

		/* Prehash */
		g_assert (EVP_DigestInit (&sha_ctx, EVP_sha512()) == 1);
		EVP_DigestUpdate (&sha_ctx, m, mlen);
		EVP_DigestFinal (&sha_ctx, h, NULL);

		/* Key setup */
		lk = EC_KEY_new_by_curve_name (CRYPTOBOX_CURVE_NID);
		g_assert (lk != NULL);
		bn_sec = BN_bin2bn (sk, sizeof (rspamd_sk_t), NULL);
		g_assert (bn_sec != NULL);
		g_assert (EC_KEY_set_private_key (lk, bn_sec) == 1);

		/* ECDSA */
		g_assert (ECDSA_sign_setup (lk, NULL, &kinv, &rp) == 1);
		g_assert (ECDSA_sign_ex (0, h, sizeof (h), sig,
				&diglen, kinv, rp, lk) == 1);
		g_assert (diglen <= sizeof (rspamd_signature_t));

		EC_KEY_free (lk);
		BN_free (bn_sec);
		BN_free (kinv);
		BN_free (rp);

#endif
	}
}

bool
rspamd_cryptobox_verify (const guchar *sig,
		const guchar *m,
		gsize mlen,
		const rspamd_pk_t pk,
		enum rspamd_cryptobox_mode mode)
{
	bool ret = false;

	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		ret = ed25519_verify (sig, m, mlen, pk);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EC_KEY *lk;
		EC_POINT *ec_pub;
		BIGNUM *bn_pub;
		EVP_MD_CTX sha_ctx;
		unsigned char h[64];

		/* Prehash */
		g_assert (EVP_DigestInit (&sha_ctx, EVP_sha512()) == 1);
		EVP_DigestUpdate (&sha_ctx, m, mlen);
		EVP_DigestFinal (&sha_ctx, h, NULL);

		/* Key setup */
		lk = EC_KEY_new_by_curve_name (CRYPTOBOX_CURVE_NID);
		g_assert (lk != NULL);
		bn_pub = BN_bin2bn (pk, rspamd_cryptobox_pk_bytes (mode), NULL);
		g_assert (bn_pub != NULL);
		ec_pub = EC_POINT_bn2point (EC_KEY_get0_group (lk), bn_pub, NULL, NULL);
		g_assert (ec_pub != NULL);
		g_assert (EC_KEY_set_public_key (lk, ec_pub) == 1);

		/* ECDSA */
		ret = ECDSA_verify (0, h, sizeof (h), sig,
				rspamd_cryptobox_signature_bytes (mode), lk) == 1;

		EC_KEY_free (lk);
		BN_free (bn_pub);
		EC_POINT_free (ec_pub);
#endif
	}

	return ret;
}

static gsize
rspamd_cryptobox_encrypt_ctx_len (enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return sizeof (chacha_state) + CRYPTOBOX_ALIGNMENT;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		return sizeof (EVP_CIPHER_CTX) + CRYPTOBOX_ALIGNMENT;
#endif
	}

	return 0;
}

static gsize
rspamd_cryptobox_auth_ctx_len (enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return sizeof (poly1305_state) + CRYPTOBOX_ALIGNMENT;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		return sizeof (void *);
#endif
	}

	return 0;
}

static void *
rspamd_cryptobox_encrypt_init (void *enc_ctx, const rspamd_nonce_t nonce,
		const rspamd_nm_t nm,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		chacha_state *s;

		s = cryptobox_align_ptr (enc_ctx, CRYPTOBOX_ALIGNMENT);
		xchacha_init (s,
				(const chacha_key *) nm,
				(const chacha_iv24 *) nonce,
				20);

		return s;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EVP_CIPHER_CTX *s;

		s = cryptobox_align_ptr (enc_ctx, CRYPTOBOX_ALIGNMENT);
		memset (s, 0, sizeof (*s));
		g_assert (EVP_EncryptInit_ex (s, EVP_aes_256_gcm (), NULL, NULL, NULL) == 1);
		g_assert (EVP_CIPHER_CTX_ctrl (s, EVP_CTRL_GCM_SET_IVLEN,
				rspamd_cryptobox_nonce_bytes (mode), NULL) == 1);
		g_assert (EVP_EncryptInit_ex (s, NULL, NULL, nm, nonce) == 1);

		return s;
#endif
	}

	return NULL;
}

static void *
rspamd_cryptobox_auth_init (void *auth_ctx, void *enc_ctx,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		poly1305_state *mac_ctx;
		guchar RSPAMD_ALIGNED(32) subkey[CHACHA_BLOCKBYTES];

		mac_ctx = cryptobox_align_ptr (auth_ctx, CRYPTOBOX_ALIGNMENT);
		memset (subkey, 0, sizeof (subkey));
		chacha_update (enc_ctx, subkey, subkey, sizeof (subkey));
		poly1305_init (mac_ctx, (const poly1305_key *) subkey);
		rspamd_explicit_memzero (subkey, sizeof (subkey));

		return mac_ctx;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		auth_ctx = enc_ctx;

		return auth_ctx;
#endif
	}

	return NULL;
}

static gboolean
rspamd_cryptobox_encrypt_update (void *enc_ctx, const guchar *in, gsize inlen,
		guchar *out, gsize *outlen,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		gsize r;

		r = chacha_update (enc_ctx, in, out, inlen);

		if (outlen != NULL) {
			*outlen = r;
		}

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EVP_CIPHER_CTX *s = enc_ctx;
		gint r;

		r = inlen;
		g_assert (EVP_EncryptUpdate (s, out, &r, in, inlen) == 1);

		if (outlen) {
			*outlen = r;
		}

		return TRUE;
#endif
	}

	return FALSE;
}

static gboolean
rspamd_cryptobox_auth_update (void *auth_ctx, const guchar *in, gsize inlen,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		poly1305_update (auth_ctx, in, inlen);

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		return TRUE;
#endif
	}

	return FALSE;
}

static gsize
rspamd_cryptobox_encrypt_final (void *enc_ctx, guchar *out, gsize remain,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return chacha_final (enc_ctx, out);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EVP_CIPHER_CTX *s = enc_ctx;
		gint r = remain;

		g_assert (EVP_EncryptFinal_ex (s, out, &r) == 1);

		return r;
#endif
	}

	return 0;
}

static gboolean
rspamd_cryptobox_auth_final (void *auth_ctx, rspamd_mac_t sig,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		poly1305_finish (auth_ctx, sig);

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EVP_CIPHER_CTX *s = auth_ctx;

		g_assert (EVP_CIPHER_CTX_ctrl (s, EVP_CTRL_GCM_GET_TAG,
				sizeof (rspamd_mac_t), sig) == 1);

		return TRUE;
#endif
	}

	return FALSE;
}

static void *
rspamd_cryptobox_decrypt_init (void *enc_ctx, const rspamd_nonce_t nonce,
		const rspamd_nm_t nm,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {

		chacha_state *s;

		s = cryptobox_align_ptr (enc_ctx, CRYPTOBOX_ALIGNMENT);
		xchacha_init (s,
				(const chacha_key *) nm,
				(const chacha_iv24 *) nonce,
				20);

		return s;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EVP_CIPHER_CTX *s;

		s = cryptobox_align_ptr (enc_ctx, CRYPTOBOX_ALIGNMENT);
		memset (s, 0, sizeof (*s));
		g_assert (EVP_DecryptInit_ex(s, EVP_aes_256_gcm (), NULL, NULL, NULL) == 1);
		g_assert (EVP_CIPHER_CTX_ctrl (s, EVP_CTRL_GCM_SET_IVLEN,
				rspamd_cryptobox_nonce_bytes (mode), NULL) == 1);
		g_assert (EVP_DecryptInit_ex (s, NULL, NULL, nm, nonce) == 1);

		return s;
#endif
	}

	return NULL;
}

static void *
rspamd_cryptobox_auth_verify_init (void *auth_ctx, void *enc_ctx,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		poly1305_state *mac_ctx;
		guchar RSPAMD_ALIGNED(32) subkey[CHACHA_BLOCKBYTES];

		mac_ctx = cryptobox_align_ptr (auth_ctx, CRYPTOBOX_ALIGNMENT);
		memset (subkey, 0, sizeof (subkey));
		chacha_update (enc_ctx, subkey, subkey, sizeof (subkey));
		poly1305_init (mac_ctx, (const poly1305_key *) subkey);
		rspamd_explicit_memzero (subkey, sizeof (subkey));

		return mac_ctx;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		auth_ctx = enc_ctx;

		return auth_ctx;
#endif
	}

	return NULL;
}

static gboolean
rspamd_cryptobox_decrypt_update (void *enc_ctx, const guchar *in, gsize inlen,
		guchar *out, gsize *outlen,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		gsize r;

		r = chacha_update (enc_ctx, in, out, inlen);

		if (outlen != NULL) {
			*outlen = r;
		}

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EVP_CIPHER_CTX *s = enc_ctx;
		gint r;

		r = outlen ? *outlen : inlen;
		g_assert (EVP_DecryptUpdate (s, out, &r, in, inlen) == 1);

		if (outlen) {
			*outlen = r;
		}

		return TRUE;
#endif
	}
}

static gboolean
rspamd_cryptobox_auth_verify_update (void *auth_ctx,
		const guchar *in, gsize inlen,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		poly1305_update (auth_ctx, in, inlen);

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		/* We do not need to authenticate as a separate process */
		return TRUE;
#else
#endif
	}

	return FALSE;
}

static gboolean
rspamd_cryptobox_decrypt_final (void *enc_ctx, guchar *out, gsize remain,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		chacha_final (enc_ctx, out);

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EVP_CIPHER_CTX *s = enc_ctx;
		gint r = remain;

		if (EVP_DecryptFinal_ex (s, out, &r) < 0) {
			return FALSE;
		}

		return TRUE;
#endif
	}

	return FALSE;
}

static gboolean
rspamd_cryptobox_auth_verify_final (void *auth_ctx, const rspamd_mac_t sig,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		rspamd_mac_t mac;

		poly1305_finish (auth_ctx, mac);

		if (!poly1305_verify (mac, sig)) {
			return FALSE;
		}

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EVP_CIPHER_CTX *s = auth_ctx;

		if (EVP_CIPHER_CTX_ctrl (s, EVP_CTRL_GCM_SET_TAG, 16, (guchar *)sig) != 1) {
			return FALSE;
		}

		return TRUE;
#endif
	}

	return FALSE;
}


static void
rspamd_cryptobox_cleanup (void *enc_ctx, void *auth_ctx,
		enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		rspamd_explicit_memzero (auth_ctx, sizeof (poly1305_state));
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		EVP_CIPHER_CTX *s = enc_ctx;

		EVP_CIPHER_CTX_cleanup (s);
#endif
	}
}

void rspamd_cryptobox_encrypt_nm_inplace (guchar *data, gsize len,
		const rspamd_nonce_t nonce,
		const rspamd_nm_t nm,
		rspamd_mac_t sig,
		enum rspamd_cryptobox_mode mode)
{
	gsize r;
	void *enc_ctx, *auth_ctx;

	enc_ctx = g_alloca (rspamd_cryptobox_encrypt_ctx_len (mode));
	auth_ctx = g_alloca (rspamd_cryptobox_auth_ctx_len (mode));

	enc_ctx = rspamd_cryptobox_encrypt_init (enc_ctx, nonce, nm, mode);
	auth_ctx = rspamd_cryptobox_auth_init (auth_ctx, enc_ctx, mode);

	rspamd_cryptobox_encrypt_update (enc_ctx, data, len, data, &r, mode);
	rspamd_cryptobox_encrypt_final (enc_ctx, data + r, len - r, mode);

	rspamd_cryptobox_auth_update (auth_ctx, data, len, mode);
	rspamd_cryptobox_auth_final (auth_ctx, sig, mode);

	rspamd_cryptobox_cleanup (enc_ctx, auth_ctx, mode);
}

static void
rspamd_cryptobox_flush_outbuf (struct rspamd_cryptobox_segment *st,
		const guchar *buf, gsize len, gsize offset)
{
	gsize cpy_len;

	while (len > 0) {
		cpy_len = MIN (len, st->len - offset);
		memcpy (st->data + offset, buf, cpy_len);
		st ++;
		buf += cpy_len;
		len -= cpy_len;
		offset = 0;
	}
}

void
rspamd_cryptobox_encryptv_nm_inplace (struct rspamd_cryptobox_segment *segments,
		gsize cnt,
		const rspamd_nonce_t nonce,
		const rspamd_nm_t nm, rspamd_mac_t sig,
		enum rspamd_cryptobox_mode mode)
{
	struct rspamd_cryptobox_segment *cur = segments, *start_seg = segments;
	guchar outbuf[CHACHA_BLOCKBYTES * 16];
	void *enc_ctx, *auth_ctx;
	guchar *out, *in;
	gsize r, remain, inremain, seg_offset;

	enc_ctx = g_alloca (rspamd_cryptobox_encrypt_ctx_len (mode));
	auth_ctx = g_alloca (rspamd_cryptobox_auth_ctx_len (mode));

	enc_ctx = rspamd_cryptobox_encrypt_init (enc_ctx, nonce, nm, mode);
	auth_ctx = rspamd_cryptobox_auth_init (auth_ctx, enc_ctx, mode);

	remain = sizeof (outbuf);
	out = outbuf;
	inremain = cur->len;
	seg_offset = 0;

	for (;;) {
		if (cur - segments == (gint)cnt) {
			break;
		}

		if (cur->len <= remain) {
			memcpy (out, cur->data, cur->len);
			remain -= cur->len;
			out += cur->len;
			cur ++;

			if (remain == 0) {
				rspamd_cryptobox_encrypt_update (enc_ctx, outbuf, sizeof (outbuf),
						outbuf, NULL, mode);
				rspamd_cryptobox_auth_update (auth_ctx, outbuf, sizeof (outbuf),
						mode);
				rspamd_cryptobox_flush_outbuf (start_seg, outbuf,
						sizeof (outbuf), seg_offset);
				start_seg = cur;
				seg_offset = 0;
				remain = sizeof (outbuf);
				out = outbuf;
			}
		}
		else {
			memcpy (out, cur->data, remain);
			rspamd_cryptobox_encrypt_update (enc_ctx, outbuf, sizeof (outbuf),
					outbuf, NULL, mode);
			rspamd_cryptobox_auth_update (auth_ctx, outbuf, sizeof (outbuf),
					mode);
			rspamd_cryptobox_flush_outbuf (start_seg, outbuf, sizeof (outbuf),
					seg_offset);
			seg_offset = 0;

			inremain = cur->len - remain;
			in = cur->data + remain;
			out = outbuf;
			remain = 0;
			start_seg = cur;

			while (inremain > 0) {
				if (sizeof (outbuf) <= inremain) {
					memcpy (outbuf, in, sizeof (outbuf));
					rspamd_cryptobox_encrypt_update (enc_ctx,
							outbuf,
							sizeof (outbuf),
							outbuf,
							NULL,
							mode);
					rspamd_cryptobox_auth_update (auth_ctx,
							outbuf,
							sizeof (outbuf),
							mode);
					memcpy (in, outbuf, sizeof (outbuf));
					in += sizeof (outbuf);
					inremain -= sizeof (outbuf);
					remain = sizeof (outbuf);
				}
				else {
					memcpy (outbuf, in, inremain);
					remain = sizeof (outbuf) - inremain;
					out = outbuf + inremain;
					inremain = 0;
				}
			}

			seg_offset = cur->len - (sizeof (outbuf) - remain);
			cur ++;
		}
	}

	rspamd_cryptobox_encrypt_update (enc_ctx, outbuf, sizeof (outbuf) - remain,
			outbuf, &r, mode);
	out = outbuf + r;
	rspamd_cryptobox_encrypt_final (enc_ctx, out, sizeof (outbuf) - remain - r,
			mode);

	rspamd_cryptobox_auth_update (auth_ctx, outbuf, sizeof (outbuf) - remain,
			mode);
	rspamd_cryptobox_auth_final (auth_ctx, sig, mode);

	rspamd_cryptobox_flush_outbuf (start_seg, outbuf, sizeof (outbuf) - remain,
			seg_offset);
	rspamd_cryptobox_cleanup (enc_ctx, auth_ctx, mode);
}

gboolean
rspamd_cryptobox_decrypt_nm_inplace (guchar *data, gsize len,
		const rspamd_nonce_t nonce, const rspamd_nm_t nm,
		const rspamd_mac_t sig, enum rspamd_cryptobox_mode mode)
{
	gsize r = 0;
	gboolean ret = TRUE;
	void *enc_ctx, *auth_ctx;

	enc_ctx = g_alloca (rspamd_cryptobox_encrypt_ctx_len (mode));
	auth_ctx = g_alloca (rspamd_cryptobox_auth_ctx_len (mode));

	enc_ctx = rspamd_cryptobox_decrypt_init (enc_ctx, nonce, nm, mode);
	auth_ctx = rspamd_cryptobox_auth_verify_init (auth_ctx, enc_ctx, mode);

	rspamd_cryptobox_auth_verify_update (auth_ctx, data, len, mode);

	if (!rspamd_cryptobox_auth_verify_final (auth_ctx, sig, mode)) {
		ret = FALSE;
	}
	else {
		rspamd_cryptobox_decrypt_update (enc_ctx, data, len, data, &r, mode);
		ret = rspamd_cryptobox_decrypt_final (enc_ctx, data + r, len - r, mode);
	}

	rspamd_cryptobox_cleanup (enc_ctx, auth_ctx, mode);

	return ret;
}

gboolean
rspamd_cryptobox_decrypt_inplace (guchar *data, gsize len,
		const rspamd_nonce_t nonce,
		const rspamd_pk_t pk, const rspamd_sk_t sk,
		const rspamd_mac_t sig,
		enum rspamd_cryptobox_mode mode)
{
	guchar nm[rspamd_cryptobox_MAX_NMBYTES];
	gboolean ret;

	rspamd_cryptobox_nm (nm, pk, sk, mode);
	ret = rspamd_cryptobox_decrypt_nm_inplace (data, len, nonce, nm, sig, mode);

	rspamd_explicit_memzero (nm, sizeof (nm));

	return ret;
}

void
rspamd_cryptobox_encrypt_inplace (guchar *data, gsize len,
		const rspamd_nonce_t nonce,
		const rspamd_pk_t pk, const rspamd_sk_t sk,
		rspamd_mac_t sig,
		enum rspamd_cryptobox_mode mode)
{
	guchar nm[rspamd_cryptobox_MAX_NMBYTES];

	rspamd_cryptobox_nm (nm, pk, sk, mode);
	rspamd_cryptobox_encrypt_nm_inplace (data, len, nonce, nm, sig, mode);
	rspamd_explicit_memzero (nm, sizeof (nm));
}

void
rspamd_cryptobox_encryptv_inplace (struct rspamd_cryptobox_segment *segments,
		gsize cnt,
		const rspamd_nonce_t nonce,
		const rspamd_pk_t pk, const rspamd_sk_t sk,
		rspamd_mac_t sig,
		enum rspamd_cryptobox_mode mode)
{
	guchar nm[rspamd_cryptobox_MAX_NMBYTES];

	rspamd_cryptobox_nm (nm, pk, sk, mode);
	rspamd_cryptobox_encryptv_nm_inplace (segments, cnt, nonce, nm, sig, mode);
	rspamd_explicit_memzero (nm, sizeof (nm));
}


void
rspamd_cryptobox_siphash (unsigned char *out, const unsigned char *in,
		unsigned long long inlen,
		const rspamd_sipkey_t k)
{
	siphash24 (out, in, inlen, k);
}

/*
 * Password-Based Key Derivation Function 2 (PKCS #5 v2.0).
 * Code based on IEEE Std 802.11-2007, Annex H.4.2.
 */
static gboolean
rspamd_cryptobox_pbkdf2 (const char *pass, gsize pass_len,
		const guint8 *salt, gsize salt_len, guint8 *key, gsize key_len,
		unsigned int rounds)
{
	guint8 *asalt, obuf[BLAKE2B_OUTBYTES];
	guint8 d1[BLAKE2B_OUTBYTES], d2[BLAKE2B_OUTBYTES];
	unsigned int i, j;
	unsigned int count;
	gsize r;

	if (rounds < 1 || key_len == 0) {
		return FALSE;
	}
	if (salt_len == 0 || salt_len > G_MAXSIZE - 4) {
		return FALSE;
	}

	asalt = g_malloc (salt_len + 4);
	memcpy (asalt, salt, salt_len);

	for (count = 1; key_len > 0; count++) {
		asalt[salt_len + 0] = (count >> 24) & 0xff;
		asalt[salt_len + 1] = (count >> 16) & 0xff;
		asalt[salt_len + 2] = (count >> 8) & 0xff;
		asalt[salt_len + 3] = count & 0xff;
		blake2b_keyed (d1, asalt, salt_len + 4, pass, pass_len);
		memcpy (obuf, d1, sizeof(obuf));

		for (i = 1; i < rounds; i++) {
			blake2b_keyed (d2, d1, BLAKE2B_OUTBYTES, pass, pass_len);
			memcpy (d1, d2, sizeof(d1));

			for (j = 0; j < sizeof(obuf); j++) {
				obuf[j] ^= d1[j];
			}
		}

		r = MIN(key_len, BLAKE2B_OUTBYTES);
		memcpy (key, obuf, r);
		key += r;
		key_len -= r;
	}

	rspamd_explicit_memzero (asalt, salt_len + 4);
	g_free (asalt);
	rspamd_explicit_memzero (d1, sizeof (d1));
	rspamd_explicit_memzero (d2, sizeof (d2));
	rspamd_explicit_memzero (obuf, sizeof (obuf));

	return TRUE;
}

gboolean
rspamd_cryptobox_pbkdf (const char *pass, gsize pass_len,
		const guint8 *salt, gsize salt_len, guint8 *key, gsize key_len,
		unsigned int complexity, enum rspamd_cryptobox_pbkdf_type type)
{
	gboolean ret = FALSE;

	switch (type) {
	case RSPAMD_CRYPTOBOX_CATENA:
		if (catena (pass, pass_len, salt, salt_len, "rspamd", 6,
				4, complexity, complexity, key_len, key) == 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_CRYPTOBOX_PBKDF2:
	default:
		ret = rspamd_cryptobox_pbkdf2 (pass, pass_len, salt, salt_len, key,
				key_len, complexity);
		break;
	}

	return ret;
}

guint
rspamd_cryptobox_pk_bytes (enum rspamd_cryptobox_mode mode)
{
	if (G_UNLIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return 32;
	}
	else {
		return 65;
	}
}

guint
rspamd_cryptobox_pk_sig_bytes (enum rspamd_cryptobox_mode mode)
{
	if (G_UNLIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return 32;
	}
	else {
		return 65;
	}
}

guint
rspamd_cryptobox_nonce_bytes (enum rspamd_cryptobox_mode mode)
{
	if (G_UNLIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return 24;
	}
	else {
		return 16;
	}
}


guint
rspamd_cryptobox_sk_bytes (enum rspamd_cryptobox_mode mode)
{
	return 32;
}

guint
rspamd_cryptobox_sk_sig_bytes (enum rspamd_cryptobox_mode mode)
{
	if (G_UNLIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return 64;
	}
	else {
		return 32;
	}
}

guint
rspamd_cryptobox_signature_bytes (enum rspamd_cryptobox_mode mode)
{
	static guint ssl_keylen;

	if (G_UNLIKELY (mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return 64;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert (0);
#else
		if (ssl_keylen == 0) {
			EC_KEY *lk;
			lk = EC_KEY_new_by_curve_name (CRYPTOBOX_CURVE_NID);
			ssl_keylen = ECDSA_size (lk);
			EC_KEY_free (lk);
		}
#endif
		return ssl_keylen;
	}
}

guint
rspamd_cryptobox_nm_bytes (enum rspamd_cryptobox_mode mode)
{
	return 32;
}

guint
rspamd_cryptobox_mac_bytes (enum rspamd_cryptobox_mode mode)
{
	return 16;
}

void
rspamd_cryptobox_hash_init (void *st, const guchar *key, gsize keylen)
{
	if (key != NULL && keylen > 0) {
		blake2b_keyed_init (st, key, keylen);
	}
	else {
		blake2b_init (st);
	}
}

/**
 * Update hash with data portion
 */
void
rspamd_cryptobox_hash_update (void *st, const guchar *data, gsize len)
{
	blake2b_update (st, data, len);
}

/**
 * Output hash to the buffer of rspamd_cryptobox_HASHBYTES length
 */
void
rspamd_cryptobox_hash_final (void *st, guchar *out)
{
	blake2b_final (st, out);
	rspamd_explicit_memzero (st, rspamd_cryptobox_HASHSTATEBYTES);
}

/**
 * One in all function
 */
void rspamd_cryptobox_hash (guchar *out,
		const guchar *data,
		gsize len,
		const guchar *key,
		gsize keylen)
{
	blake2b_state RSPAMD_ALIGNED(32) st;

	rspamd_cryptobox_hash_init (&st, key, keylen);
	rspamd_cryptobox_hash_update (&st, data, len);
	rspamd_cryptobox_hash_final (&st, out);
}

/* MUST be 64 bytes at maximum */
struct rspamd_cryptobox_fast_hash_state_real {
	guint64 h;  /* current hash value */
	guint64 pos; /* pos in bytes in the buf */
	guint64 buf;
};

void
rspamd_cryptobox_fast_hash_init (rspamd_cryptobox_fast_hash_state_t *st,
		guint64 seed)
{
	struct rspamd_cryptobox_fast_hash_state_real *rst =
			(struct rspamd_cryptobox_fast_hash_state_real *)st;

	memset (rst, 0, sizeof (*rst));
	rst->h = seed;
}

void
rspamd_cryptobox_fast_hash_update (rspamd_cryptobox_fast_hash_state_t *st,
		const void *data, gsize len)
{
	struct rspamd_cryptobox_fast_hash_state_real *rst =
			(struct rspamd_cryptobox_fast_hash_state_real *)st;
	const guchar *d = data;
	guint leftover;
	guint64 n;

	leftover = rst->pos;

	if (leftover > 0 && len + leftover >= 8) {
		n = sizeof (rst->buf) - leftover;
		memcpy (((guchar *)&rst->buf) + leftover, d, n);
		d += n;
		len -= n;
		rst->h = mum_hash_step (rst->h, rst->buf);
		rst->buf = 0;
		rst->pos = 0;
	}

	while (len > 8) {
#ifdef _MUM_UNALIGNED_ACCESS
		rst->h = mum_hash_step (rst->h, *(guint64 *)d);
#else
		memcpy (&n, d, sizeof (n));
		rst->h = mum_hash_step (rst->h, n);
#endif
		len -= 8;
		d += 8;
	}

	if (len > 0 && rst->pos + len <= 8) {
		memcpy (((guchar *)&rst->buf) + rst->pos, d, len);
		rst->pos += len;
	}
}

guint64
rspamd_cryptobox_fast_hash_final (rspamd_cryptobox_fast_hash_state_t *st)
{
	struct rspamd_cryptobox_fast_hash_state_real *rst =
			(struct rspamd_cryptobox_fast_hash_state_real *)st;
	guint leftover;

	leftover = rst->pos;

	if (leftover > 0) {
		memset (((guchar *)&rst->buf) + leftover, 0, sizeof (rst->buf) - leftover);
		rst->h = mum_hash_step (rst->h, rst->buf);
	}

	return mum_hash_finish (rst->h);
}

/**
 * One in all function
 */
static inline guint64
rspamd_cryptobox_fast_hash_machdep (const void *data,
		gsize len, guint64 seed)
{
	if (len >= 8 && len % 8 == 0) {
		return mum_hash (data, len, seed);
	}
	else {
#if defined(__LP64__) || defined(_LP64)
		return metrohash64_1 (data, len, seed);
#endif
	}

	return XXH32 (data, len, seed);
}

static inline guint64
rspamd_cryptobox_fast_hash_indep (const void *data,
		gsize len, guint64 seed)
{
	if (len >= 8 && len % 8 == 0) {
		return mum_hash (data, len, seed);
	}

	return metrohash64_1 (data, len, seed);
}

guint64
rspamd_cryptobox_fast_hash (const void *data,
		gsize len, guint64 seed)
{
	return rspamd_cryptobox_fast_hash_machdep (data, len, seed);
}

guint64
rspamd_cryptobox_fast_hash_specific (
		enum rspamd_cryptobox_fast_hash_type type,
		const void *data,
		gsize len, guint64 seed)
{
	switch (type) {
	case RSPAMD_CRYPTOBOX_XXHASH32:
		return XXH32 (data, len, seed);
	case RSPAMD_CRYPTOBOX_XXHASH64:
		return XXH64 (data, len, seed);
	case RSPAMD_CRYPTOBOX_MUMHASH:
		return mum_hash (data, len, seed);
	case RSPAMD_CRYPTOBOX_HASHFAST_INDEPENDENT:
		return rspamd_cryptobox_fast_hash_indep (data, len, seed);
	case RSPAMD_CRYPTOBOX_HASHFAST:
	default:
		return rspamd_cryptobox_fast_hash_machdep (data, len, seed);
	}
}
