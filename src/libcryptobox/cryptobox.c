/*
 * Copyright 2024 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
#include "catena/catena.h"
#include "base64/base64.h"
#include "ottery.h"
#include "printf.h"
#define XXH_INLINE_ALL
#define XXH_PRIVATE_API
#include "xxhash.h"
#define MUM_TARGET_INDEPENDENT_HASH 1 /* For 32/64 bit equal hashes */
#include "../../contrib/mumhash/mum.h"
#include "../../contrib/t1ha/t1ha.h"
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
#include <openssl/engine.h>
#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/param_build.h>
#include <openssl/core.h>
#endif
#define CRYPTOBOX_CURVE_NID NID_X9_62_prime256v1
#endif

#include <signal.h>
#include <setjmp.h>
#include <stdalign.h>

#include <sodium.h>

unsigned cpu_config = 0;

static gboolean cryptobox_loaded = FALSE;

static const unsigned char n0[16] = {0};

#define CRYPTOBOX_ALIGNMENT 16
#define cryptobox_align_ptr(p, a) \
	(void *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

static void
rspamd_cryptobox_cpuid(int cpu[4], int info)
{
	uint32_t __attribute__((unused)) eax, __attribute__((unused)) ecx = 0, __attribute__((unused)) ebx = 0, __attribute__((unused)) edx = 0;

	eax = info;
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#if defined(__i386__) && defined(__PIC__)

	/* in case of PIC under 32-bit EBX cannot be clobbered */

	__asm__ volatile("movl %%ebx, %%edi \n\t cpuid \n\t xchgl %%ebx, %%edi"
					 : "=D"(ebx),
					   "+a"(eax), "+c"(ecx), "=d"(edx));
#else
	__asm__ volatile("cpuid"
					 : "+b"(ebx), "+a"(eax), "+c"(ecx), "=d"(edx));
#endif

	cpu[0] = eax;
	cpu[1] = ebx;
	cpu[2] = ecx;
	cpu[3] = edx;
#else
	memset(cpu, 0, sizeof(int) * 4);
#endif
}

static sig_atomic_t ok = 0;
static jmp_buf j;

__attribute__((noreturn)) static void
rspamd_cryptobox_ill_handler(int signo)
{
	ok = 0;
	longjmp(j, -1);
}

static gboolean
rspamd_cryptobox_test_instr(int instr)
{
	void (*old_handler)(int);
	uint32_t rd;

#if defined(__GNUC__)
	ok = 1;
	old_handler = signal(SIGILL, rspamd_cryptobox_ill_handler);

	if (setjmp(j) != 0) {
		signal(SIGILL, old_handler);

		return FALSE;
	}

	switch (instr) {
#if defined HAVE_SSE2 && defined(__x86_64__)
	case CPUID_SSE2:
		__asm__ volatile("psubb %xmm0, %xmm0");
		break;
	case CPUID_RDRAND:
		/* Use byte code here for compatibility */
		__asm__ volatile(".byte 0x0f,0xc7,0xf0; setc %1"
						 : "=a"(rd), "=qm"(ok)
						 :
						 : "edx");
		break;
#endif
#ifdef HAVE_SSE3
	case CPUID_SSE3:
		__asm__ volatile("movshdup %xmm0, %xmm0");
		break;
#endif
#ifdef HAVE_SSSE3
	case CPUID_SSSE3:
		__asm__ volatile("pshufb %xmm0, %xmm0");
		break;
#endif
#ifdef HAVE_SSE41
	case CPUID_SSE41:
		__asm__ volatile("pcmpeqq %xmm0, %xmm0");
		break;
#endif
#if defined HAVE_SSE42 && defined(__x86_64__)
	case CPUID_SSE42:
		__asm__ volatile("pushq %rax\n"
						 "xorq %rax, %rax\n"
						 "crc32 %rax, %rax\n"
						 "popq %rax");
		break;
#endif
#ifdef HAVE_AVX
	case CPUID_AVX:
		__asm__ volatile("vpaddq %xmm0, %xmm0, %xmm0");
		break;
#endif
#ifdef HAVE_AVX2
	case CPUID_AVX2:
		__asm__ volatile("vpaddq %ymm0, %ymm0, %ymm0");
		break;
#endif
	default:
		return FALSE;
		break;
	}

	signal(SIGILL, old_handler);
#endif

	(void) rd; /* Silence warning */

	/* We actually never return here if SIGILL has been caught */
	return ok == 1;
}

struct rspamd_cryptobox_library_ctx *
rspamd_cryptobox_init(void)
{
	int cpu[4], nid;
	const uint32_t osxsave_mask = (1 << 27);
	const uint32_t fma_movbe_osxsave_mask = ((1 << 12) | (1 << 22) | (1 << 27));
	const uint32_t avx2_bmi12_mask = (1 << 5) | (1 << 3) | (1 << 8);
	gulong bit;
	static struct rspamd_cryptobox_library_ctx *ctx;
	GString *buf;

	if (cryptobox_loaded) {
		/* Ignore reload attempts */
		return ctx;
	}

	cryptobox_loaded = TRUE;
	ctx = g_malloc0(sizeof(*ctx));

	rspamd_cryptobox_cpuid(cpu, 0);
	nid = cpu[0];
	rspamd_cryptobox_cpuid(cpu, 1);

	if (nid > 1) {
		if ((cpu[3] & ((uint32_t) 1 << 26))) {
			if (rspamd_cryptobox_test_instr(CPUID_SSE2)) {
				cpu_config |= CPUID_SSE2;
			}
		}
		if ((cpu[2] & ((uint32_t) 1 << 0))) {
			if (rspamd_cryptobox_test_instr(CPUID_SSE3)) {
				cpu_config |= CPUID_SSE3;
			}
		}
		if ((cpu[2] & ((uint32_t) 1 << 9))) {
			if (rspamd_cryptobox_test_instr(CPUID_SSSE3)) {
				cpu_config |= CPUID_SSSE3;
			}
		}
		if ((cpu[2] & ((uint32_t) 1 << 19))) {
			if (rspamd_cryptobox_test_instr(CPUID_SSE41)) {
				cpu_config |= CPUID_SSE41;
			}
		}
		if ((cpu[2] & ((uint32_t) 1 << 20))) {
			if (rspamd_cryptobox_test_instr(CPUID_SSE42)) {
				cpu_config |= CPUID_SSE42;
			}
		}
		if ((cpu[2] & ((uint32_t) 1 << 30))) {
			if (rspamd_cryptobox_test_instr(CPUID_RDRAND)) {
				cpu_config |= CPUID_RDRAND;
			}
		}

		/* OSXSAVE */
		if ((cpu[2] & osxsave_mask) == osxsave_mask) {
			if ((cpu[2] & ((uint32_t) 1 << 28))) {
				if (rspamd_cryptobox_test_instr(CPUID_AVX)) {
					cpu_config |= CPUID_AVX;
				}
			}

			if (nid >= 7 &&
				(cpu[2] & fma_movbe_osxsave_mask) == fma_movbe_osxsave_mask) {
				rspamd_cryptobox_cpuid(cpu, 7);

				if ((cpu[1] & avx2_bmi12_mask) == avx2_bmi12_mask) {
					if (rspamd_cryptobox_test_instr(CPUID_AVX2)) {
						cpu_config |= CPUID_AVX2;
					}
				}
			}
		}
	}

	buf = g_string_new("");

	for (bit = 0x1; bit != 0; bit <<= 1) {
		if (cpu_config & bit) {
			switch (bit) {
			case CPUID_SSE2:
				rspamd_printf_gstring(buf, "sse2, ");
				break;
			case CPUID_SSE3:
				rspamd_printf_gstring(buf, "sse3, ");
				break;
			case CPUID_SSSE3:
				rspamd_printf_gstring(buf, "ssse3, ");
				break;
			case CPUID_SSE41:
				rspamd_printf_gstring(buf, "sse4.1, ");
				break;
			case CPUID_SSE42:
				rspamd_printf_gstring(buf, "sse4.2, ");
				break;
			case CPUID_AVX:
				rspamd_printf_gstring(buf, "avx, ");
				break;
			case CPUID_AVX2:
				rspamd_printf_gstring(buf, "avx2, ");
				break;
			case CPUID_RDRAND:
				rspamd_printf_gstring(buf, "rdrand, ");
				break;
			default:
				break; /* Silence warning */
			}
		}
	}

	if (buf->len > 2) {
		/* Trim last chars */
		g_string_erase(buf, buf->len - 2, 2);
	}

	ctx->cpu_extensions = buf->str;
	g_string_free(buf, FALSE);
	ctx->cpu_config = cpu_config;
	g_assert(sodium_init() != -1);

	ctx->chacha20_impl = chacha_load();
	ctx->base64_impl = base64_load();
#if defined(HAVE_USABLE_OPENSSL) && (OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER))
	/* Needed for old openssl api, not sure about LibreSSL */
	ERR_load_EC_strings();
	ERR_load_RAND_strings();
	ERR_load_EVP_strings();
#endif

	return ctx;
}

void rspamd_cryptobox_deinit(struct rspamd_cryptobox_library_ctx *ctx)
{
	if (ctx) {
		g_free(ctx->cpu_extensions);
		g_free(ctx);
	}
}

void rspamd_cryptobox_keypair(rspamd_pk_t pk, rspamd_sk_t sk,
							  enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		ottery_rand_bytes(sk, rspamd_cryptobox_MAX_SKBYTES);
		sk[0] &= 248;
		sk[31] &= 127;
		sk[31] |= 64;

		crypto_scalarmult_base(pk, sk);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else

		gsize len;
#if OPENSSL_VERSION_MAJOR >= 3
		OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
		EVP_PKEY *pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", EC_curve_nid2nist(CRYPTOBOX_CURVE_NID));
		g_assert(pkey != NULL);

		BIGNUM *bn_sec = NULL;
		g_assert(EVP_PKEY_get_bn_param(pkey, "priv", &bn_sec) == 1);

		len = BN_num_bytes(bn_sec);
		g_assert(len <= (int) rspamd_cryptobox_sk_bytes(RSPAMD_CRYPTOBOX_MODE_NIST));
		BN_bn2bin(bn_sec, sk);

		g_assert(EVP_PKEY_get_octet_string_param(pkey, "pub", pk,
												 rspamd_cryptobox_pk_bytes(RSPAMD_CRYPTOBOX_MODE_NIST),
												 &len) == 1);

		g_assert(len <= (int) rspamd_cryptobox_pk_bytes(RSPAMD_CRYPTOBOX_MODE_NIST));

		BN_free(bn_sec);
		EVP_PKEY_free(pkey);
		OSSL_LIB_CTX_free(libctx);
#else
		const EC_POINT *ec_pub;
		const EC_GROUP *group;
		const BIGNUM *bn_sec;

		EC_KEY *ec_sec;

		ec_sec = EC_KEY_new_by_curve_name(CRYPTOBOX_CURVE_NID);
		g_assert(ec_sec != NULL);
		g_assert(EC_KEY_generate_key(ec_sec) != 0);

		bn_sec = EC_KEY_get0_private_key(ec_sec);
		g_assert(bn_sec != NULL);
		ec_pub = EC_KEY_get0_public_key(ec_sec);
		g_assert(ec_pub != NULL);

		group = EC_KEY_get0_group(ec_sec);
		BIGNUM *bn_pub;
		bn_pub = EC_POINT_point2bn(group,
								   ec_pub, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
		len = BN_num_bytes(bn_pub);
		g_assert(len <= (int) rspamd_cryptobox_pk_bytes(mode));
		BN_bn2bin(bn_pub, pk);
		BN_free(bn_pub);
		EC_KEY_free(ec_sec);

		len = BN_num_bytes(bn_sec);
		g_assert(len <= (int) rspamd_cryptobox_sk_bytes(RSPAMD_CRYPTOBOX_MODE_NIST));
		BN_bn2bin(bn_sec, sk);
#endif
#endif
	}
}

void rspamd_cryptobox_keypair_sig(rspamd_sig_pk_t pk, rspamd_sig_sk_t sk,
								  enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		crypto_sign_keypair(pk, sk);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else

		size_t len;
#if OPENSSL_VERSION_MAJOR >= 3
		OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
		EVP_PKEY *pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", EC_curve_nid2nist(CRYPTOBOX_CURVE_NID));
		g_assert(pkey != NULL);

		BIGNUM *bn_sec = NULL;
		g_assert(EVP_PKEY_get_bn_param(pkey, "priv", &bn_sec) == 1);

		len = BN_num_bytes(bn_sec);
		g_assert(len <= (int) sizeof(rspamd_sig_sk_t));
		BN_bn2bin(bn_sec, sk);

		EVP_PKEY_get_octet_string_param(pkey, "pub", pk,
										sizeof(rspamd_sig_pk_t), &len);

		g_assert(len <= (int) sizeof(rspamd_sig_pk_t));

		BN_free(bn_sec);
		EVP_PKEY_free(pkey);
		OSSL_LIB_CTX_free(libctx);
#else
		EC_KEY *ec_sec;
		const BIGNUM *bn_sec;
		const EC_POINT *ec_pub;
		const EC_GROUP *group;

		ec_sec = EC_KEY_new_by_curve_name(CRYPTOBOX_CURVE_NID);
		g_assert(ec_sec != NULL);
		g_assert(EC_KEY_generate_key(ec_sec) != 0);

		bn_sec = EC_KEY_get0_private_key(ec_sec);
		g_assert(bn_sec != NULL);
		ec_pub = EC_KEY_get0_public_key(ec_sec);
		g_assert(ec_pub != NULL);

		group = EC_KEY_get0_group(ec_sec);

		BIGNUM *bn_pub;
		bn_pub = EC_POINT_point2bn(group, ec_pub, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
		len = BN_num_bytes(bn_pub);
		g_assert(len <= (int) rspamd_cryptobox_pk_sig_bytes(mode));
		BN_bn2bin(bn_pub, pk);
		BN_free(bn_pub);

		len = BN_num_bytes(bn_sec);
		g_assert(len <= (int) sizeof(rspamd_sig_sk_t));
		BN_bn2bin(bn_sec, sk);

		EC_KEY_free(ec_sec);
#endif

#endif
	}
}

#if OPENSSL_VERSION_MAJOR >= 3
/* Compatibility function for OpenSSL 3.0 - thanks for breaking all API one more time */
EC_POINT *ec_point_bn2point_compat(const EC_GROUP *group,
								   const BIGNUM *bn, EC_POINT *point, BN_CTX *ctx)
{
	size_t buf_len = 0;
	unsigned char *buf;
	EC_POINT *ret;

	if ((buf_len = BN_num_bytes(bn)) == 0)
		buf_len = 1;
	if ((buf = OPENSSL_malloc(buf_len)) == NULL) {
		return NULL;
	}

	if (!BN_bn2binpad(bn, buf, buf_len)) {
		OPENSSL_free(buf);
		return NULL;
	}

	if (point == NULL) {
		if ((ret = EC_POINT_new(group)) == NULL) {
			OPENSSL_free(buf);
			return NULL;
		}
	}
	else
		ret = point;

	if (!EC_POINT_oct2point(group, ret, buf, buf_len, ctx)) {
		if (ret != point)
			EC_POINT_clear_free(ret);
		OPENSSL_free(buf);
		return NULL;
	}

	OPENSSL_free(buf);
	return ret;
}
#else
#define ec_point_bn2point_compat EC_POINT_bn2point
#endif

void rspamd_cryptobox_nm(rspamd_nm_t nm,
						 const rspamd_pk_t pk, const rspamd_sk_t sk,
						 enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		unsigned char s[32];
		unsigned char e[32];

		memcpy(e, sk, 32);
		e[0] &= 248;
		e[31] &= 127;
		e[31] |= 64;

		if (crypto_scalarmult(s, e, pk) != -1) {
			hchacha(s, n0, nm, 20);
		}

		rspamd_explicit_memzero(e, 32);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		unsigned char s[32];

#if OPENSSL_VERSION_MAJOR >= 3
		EVP_PKEY *sec_pkey = NULL;
		EVP_PKEY *pub_pkey = NULL;
		OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
		EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
		OSSL_PARAM param[3];

		param[0] = OSSL_PARAM_construct_utf8_string("group", "P-256", 0);
		param[1] = OSSL_PARAM_construct_BN("priv", (void *) sk, rspamd_cryptobox_sk_bytes(mode));
		param[2] = OSSL_PARAM_construct_end();

		g_assert(EVP_PKEY_fromdata_init(pctx) == 1);
		g_assert(EVP_PKEY_fromdata(pctx, &sec_pkey, EVP_PKEY_PRIVATE_KEY, param) == 1);
		EVP_PKEY_CTX_free(pctx);
		pctx = EVP_PKEY_CTX_new_from_pkey(libctx, sec_pkey, NULL);

		param[0] = OSSL_PARAM_construct_utf8_string("group", "P-256", 0);
		param[1] = OSSL_PARAM_construct_octet_string("pub", (void *) pk, rspamd_cryptobox_pk_bytes(mode));
		param[2] = OSSL_PARAM_construct_end();

		g_assert(EVP_PKEY_fromdata_init(dctx) == 1);
		EVP_PKEY_fromdata(dctx, &pub_pkey, EVP_PKEY_PUBLIC_KEY, param);

		g_assert(EVP_PKEY_derive_init(pctx) == 1);

		g_assert(EVP_PKEY_derive_set_peer(pctx, pub_pkey) == 1);

		size_t s_len = sizeof(s);
		g_assert(EVP_PKEY_derive(pctx, s, &s_len) == 1);

		EVP_PKEY_CTX_free(pctx);
		EVP_PKEY_free(pub_pkey);
		EVP_PKEY_free(sec_pkey);
		OSSL_LIB_CTX_free(libctx);
#else
		//g_error(ERR_error_string(ERR_get_error(), NULL));
		int len;
		EC_KEY *lk;
		EC_POINT *ec_pub;
		BIGNUM *bn_pub, *bn_sec;

		lk = EC_KEY_new_by_curve_name(CRYPTOBOX_CURVE_NID);
		g_assert(lk != NULL);

		bn_pub = BN_bin2bn(pk, rspamd_cryptobox_pk_bytes(mode), NULL);
		g_assert(bn_pub != NULL);
		bn_sec = BN_bin2bn(sk, sizeof(rspamd_sk_t), NULL);
		g_assert(bn_sec != NULL);

		g_assert(EC_KEY_set_private_key(lk, bn_sec) == 1);
		ec_pub = ec_point_bn2point_compat(EC_KEY_get0_group(lk), bn_pub, NULL, NULL);
		g_assert(ec_pub != NULL);

		len = ECDH_compute_key(s, sizeof(s), ec_pub, lk, NULL);
		g_assert(len == sizeof(s));

		EC_KEY_free(lk);

		EC_POINT_free(ec_pub);
		BN_free(bn_sec);
		BN_free(bn_pub);
#endif
		/* Still do hchacha iteration since we are not using SHA1 KDF */
		hchacha(s, n0, nm, 20);

#endif
	}
}

void rspamd_cryptobox_sign(unsigned char *sig, unsigned long long *siglen_p,
						   const unsigned char *m, gsize mlen,
						   const rspamd_sig_sk_t sk,
						   enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		crypto_sign_detached(sig, siglen_p, m, mlen, sk);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_MD_CTX *sha_ctx;
		unsigned char h[64];
		unsigned int diglen = rspamd_cryptobox_signature_bytes(mode);

		/* Prehash */
		sha_ctx = EVP_MD_CTX_create();
		g_assert(EVP_DigestInit(sha_ctx, EVP_sha512()) == 1);
		EVP_DigestUpdate(sha_ctx, m, mlen);
		EVP_DigestFinal(sha_ctx, h, NULL);

		/* ECDSA */
#if OPENSSL_VERSION_MAJOR >= 3
		EVP_PKEY *pkey = NULL;
		OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
		OSSL_PARAM_BLD *param_bld;
		OSSL_PARAM *params = NULL;
		BIGNUM *bn_sec;

		param_bld = OSSL_PARAM_BLD_new();
		g_assert(OSSL_PARAM_BLD_push_utf8_string(param_bld, "group",
												 EC_curve_nid2nist(CRYPTOBOX_CURVE_NID), 0) == 1);

		bn_sec = BN_bin2bn(sk, rspamd_cryptobox_sk_sig_bytes(RSPAMD_CRYPTOBOX_MODE_NIST), NULL);
		g_assert(bn_sec != NULL);

		g_assert(OSSL_PARAM_BLD_push_BN(param_bld, "priv", bn_sec) == 1);

		params = OSSL_PARAM_BLD_to_param(param_bld);
		g_assert(EVP_PKEY_fromdata_init(pctx) == 1);
		g_assert(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) == 1);

		g_assert(pkey != NULL);

		g_assert(EVP_DigestSignInit(sha_ctx, NULL, EVP_sha512(), NULL, pkey) == 1);

		size_t diglen_size_t = diglen;
		EVP_DigestSign(sha_ctx, sig, &diglen_size_t, m, mlen);
		diglen = diglen_size_t;

		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_BLD_free(param_bld);
		OSSL_PARAM_free(params);
		BN_free(bn_sec);
		EVP_PKEY_free(pkey);
		OSSL_LIB_CTX_free(libctx);
#else
		EC_KEY *lk;
		BIGNUM *bn_sec;

		/* Key setup */
		lk = EC_KEY_new_by_curve_name(CRYPTOBOX_CURVE_NID);
		g_assert(lk != NULL);
		bn_sec = BN_bin2bn(sk, rspamd_cryptobox_sk_sig_bytes(RSPAMD_CRYPTOBOX_MODE_NIST), NULL);
		g_assert(bn_sec != NULL);
		g_assert(EC_KEY_set_private_key(lk, bn_sec) == 1);

		g_assert(ECDSA_sign(0, h, sizeof(h), sig, &diglen, lk) == 1);
		EC_KEY_free(lk);
		BN_free(bn_sec);
#endif
		g_assert(diglen <= sizeof(rspamd_signature_t));

		if (siglen_p) {
			*siglen_p = diglen;
		}

		EVP_MD_CTX_destroy(sha_ctx);
#endif
	}
}

#ifdef HAVE_OPENSSL
bool rspamd_cryptobox_verify_evp_ed25519(int nid,
										 const unsigned char *sig,
										 gsize siglen,
										 const unsigned char *digest,
										 gsize dlen,
										 struct evp_pkey_st *pub_key)
{
	bool ret = false;

	if (siglen == rspamd_cryptobox_signature_bytes(RSPAMD_CRYPTOBOX_MODE_25519)) {
		rspamd_pk_t pk;
		size_t len_pk = sizeof(rspamd_pk_t);
		EVP_PKEY_get_raw_public_key(pub_key, pk, &len_pk);
		ret = (crypto_sign_verify_detached(sig, digest, dlen, pk) == 0);
	}

	return ret;
}

bool rspamd_cryptobox_verify_evp_ecdsa(int nid,
									   const unsigned char *sig,
									   gsize siglen,
									   const unsigned char *digest,
									   gsize dlen,
									   EVP_PKEY *pub_key)
{
	bool ret = false;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pub_key, NULL);
	g_assert(pctx != NULL);
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_get_digestbynid(nid);

	g_assert(EVP_PKEY_verify_init(pctx) == 1);
	g_assert(EVP_PKEY_CTX_set_signature_md(pctx, md) == 1);

	ret = (EVP_PKEY_verify(pctx, sig, siglen, digest, dlen) == 1);

	EVP_PKEY_CTX_free(pctx);
	EVP_MD_CTX_free(mdctx);

	return ret;
}
bool rspamd_cryptobox_verify_evp_rsa(int nid,
									 const unsigned char *sig,
									 gsize siglen,
									 const unsigned char *digest,
									 gsize dlen,
									 EVP_PKEY *pub_key)
{
	bool ret = false;

	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pub_key, NULL);
	g_assert(pctx != NULL);
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_get_digestbynid(nid);

	g_assert(EVP_PKEY_verify_init(pctx) == 1);
	g_assert(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1);
	g_assert(EVP_PKEY_CTX_set_signature_md(pctx, md) == 1);

	ret = (EVP_PKEY_verify(pctx, sig, siglen, digest, dlen) == 1);

	EVP_PKEY_CTX_free(pctx);
	EVP_MD_CTX_free(mdctx);

	return ret;
}
#endif

bool rspamd_cryptobox_verify(const unsigned char *sig,
							 gsize siglen,
							 const unsigned char *m,
							 gsize mlen,
							 const rspamd_sig_pk_t pk,
							 enum rspamd_cryptobox_mode mode)
{
	bool ret = false;

	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		if (siglen == rspamd_cryptobox_signature_bytes(RSPAMD_CRYPTOBOX_MODE_25519)) {
			ret = (crypto_sign_verify_detached(sig, m, mlen, pk) == 0);
		}
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_MD_CTX *sha_ctx;
		unsigned char h[64];

		/* Prehash */
		sha_ctx = EVP_MD_CTX_create();
		g_assert(EVP_DigestInit(sha_ctx, EVP_sha512()) == 1);
		EVP_DigestUpdate(sha_ctx, m, mlen);
		EVP_DigestFinal(sha_ctx, h, NULL);


#if OPENSSL_VERSION_MAJOR >= 3
		EVP_PKEY *pkey = NULL;
		OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
		EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
		OSSL_PARAM_BLD *param_bld;
		OSSL_PARAM *params = NULL;

		param_bld = OSSL_PARAM_BLD_new();
		g_assert(OSSL_PARAM_BLD_push_utf8_string(param_bld, "group",
												 EC_curve_nid2nist(CRYPTOBOX_CURVE_NID), 0) == 1);

		g_assert(OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", pk,
												  rspamd_cryptobox_pk_sig_bytes(RSPAMD_CRYPTOBOX_MODE_NIST)) == 1);

		params = OSSL_PARAM_BLD_to_param(param_bld);
		g_assert(EVP_PKEY_fromdata_init(pctx) == 1);
		g_assert(EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1);

		g_assert(pkey != NULL);

		g_assert(EVP_DigestVerifyInit(sha_ctx, NULL, EVP_sha512(), NULL, pkey) == 1);

		if (EVP_DigestVerify(sha_ctx, sig, siglen, m, mlen) == 1)
			ret = true;

		EVP_PKEY_free(pkey);
		EVP_PKEY_CTX_free(pctx);
		OSSL_PARAM_free(params);
		OSSL_PARAM_BLD_free(param_bld);
		OSSL_LIB_CTX_free(libctx);
#else
		EC_KEY *lk;
		EC_POINT *ec_pub;
		BIGNUM *bn_pub;

		/* Key setup */
		lk = EC_KEY_new_by_curve_name(CRYPTOBOX_CURVE_NID);
		g_assert(lk != NULL);
		bn_pub = BN_bin2bn(pk, rspamd_cryptobox_pk_sig_bytes(RSPAMD_CRYPTOBOX_MODE_NIST), NULL);
		g_assert(bn_pub != NULL);
		ec_pub = ec_point_bn2point_compat(EC_KEY_get0_group(lk), bn_pub, NULL, NULL);
		g_assert(ec_pub != NULL);
		g_assert(EC_KEY_set_public_key(lk, ec_pub) == 1);

		/* ECDSA */
		ret = ECDSA_verify(0, h, sizeof(h), sig, siglen, lk) == 1;

		EC_KEY_free(lk);

		BN_free(bn_pub);
		EC_POINT_free(ec_pub);
#endif

		EVP_MD_CTX_destroy(sha_ctx);
#endif
	}

	return ret;
}

static gsize
rspamd_cryptobox_encrypt_ctx_len(enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return sizeof(chacha_state) + CRYPTOBOX_ALIGNMENT;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		return sizeof(EVP_CIPHER_CTX *) + CRYPTOBOX_ALIGNMENT;
#endif
	}

	return 0;
}

static gsize
rspamd_cryptobox_auth_ctx_len(enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return sizeof(crypto_onetimeauth_state) + RSPAMD_ALIGNOF(crypto_onetimeauth_state);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		return sizeof(void *);
#endif
	}

	return 0;
}

static void *
rspamd_cryptobox_encrypt_init(void *enc_ctx, const rspamd_nonce_t nonce,
							  const rspamd_nm_t nm,
							  enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		chacha_state *s;

		s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
		xchacha_init(s,
					 (const chacha_key *) nm,
					 (const chacha_iv24 *) nonce,
					 20);

		return s;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_CIPHER_CTX **s;

		s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
		memset(s, 0, sizeof(*s));
		*s = EVP_CIPHER_CTX_new();
		g_assert(EVP_EncryptInit_ex(*s, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1);
		g_assert(EVP_CIPHER_CTX_ctrl(*s, EVP_CTRL_GCM_SET_IVLEN,
									 rspamd_cryptobox_nonce_bytes(mode), NULL) == 1);
		g_assert(EVP_EncryptInit_ex(*s, NULL, NULL, nm, nonce) == 1);

		return s;
#endif
	}

	return NULL;
}

static void *
rspamd_cryptobox_auth_init(void *auth_ctx, void *enc_ctx,
						   enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		crypto_onetimeauth_state *mac_ctx;
		unsigned char RSPAMD_ALIGNED(32) subkey[CHACHA_BLOCKBYTES];

		mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
		memset(subkey, 0, sizeof(subkey));
		chacha_update(enc_ctx, subkey, subkey, sizeof(subkey));
		crypto_onetimeauth_init(mac_ctx, subkey);
		rspamd_explicit_memzero(subkey, sizeof(subkey));

		return mac_ctx;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		auth_ctx = enc_ctx;

		return auth_ctx;
#endif
	}

	return NULL;
}

static gboolean
rspamd_cryptobox_encrypt_update(void *enc_ctx, const unsigned char *in, gsize inlen,
								unsigned char *out, gsize *outlen,
								enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		gsize r;
		chacha_state *s;

		s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);

		r = chacha_update(s, in, out, inlen);

		if (outlen != NULL) {
			*outlen = r;
		}

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_CIPHER_CTX **s = enc_ctx;
		int r;

		r = inlen;
		g_assert(EVP_EncryptUpdate(*s, out, &r, in, inlen) == 1);

		if (outlen) {
			*outlen = r;
		}

		return TRUE;
#endif
	}

	return FALSE;
}

static gboolean
rspamd_cryptobox_auth_update(void *auth_ctx, const unsigned char *in, gsize inlen,
							 enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		crypto_onetimeauth_state *mac_ctx;

		mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
		crypto_onetimeauth_update(mac_ctx, in, inlen);

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		return TRUE;
#endif
	}

	return FALSE;
}

static gsize
rspamd_cryptobox_encrypt_final(void *enc_ctx, unsigned char *out, gsize remain,
							   enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		chacha_state *s;

		s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
		return chacha_final(s, out);
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_CIPHER_CTX **s = enc_ctx;
		int r = remain;

		g_assert(EVP_EncryptFinal_ex(*s, out, &r) == 1);

		return r;
#endif
	}

	return 0;
}

static gboolean
rspamd_cryptobox_auth_final(void *auth_ctx, rspamd_mac_t sig,
							enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		crypto_onetimeauth_state *mac_ctx;

		mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
		crypto_onetimeauth_final(mac_ctx, sig);

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_CIPHER_CTX **s = auth_ctx;

		g_assert(EVP_CIPHER_CTX_ctrl(*s, EVP_CTRL_GCM_GET_TAG,
									 sizeof(rspamd_mac_t), sig) == 1);

		return TRUE;
#endif
	}

	return FALSE;
}

static void *
rspamd_cryptobox_decrypt_init(void *enc_ctx, const rspamd_nonce_t nonce,
							  const rspamd_nm_t nm,
							  enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {

		chacha_state *s;

		s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
		xchacha_init(s,
					 (const chacha_key *) nm,
					 (const chacha_iv24 *) nonce,
					 20);

		return s;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_CIPHER_CTX **s;

		s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
		memset(s, 0, sizeof(*s));
		*s = EVP_CIPHER_CTX_new();
		g_assert(EVP_DecryptInit_ex(*s, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1);
		g_assert(EVP_CIPHER_CTX_ctrl(*s, EVP_CTRL_GCM_SET_IVLEN,
									 rspamd_cryptobox_nonce_bytes(mode), NULL) == 1);
		g_assert(EVP_DecryptInit_ex(*s, NULL, NULL, nm, nonce) == 1);

		return s;
#endif
	}

	return NULL;
}

static void *
rspamd_cryptobox_auth_verify_init(void *auth_ctx, void *enc_ctx,
								  enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		crypto_onetimeauth_state *mac_ctx;
		unsigned char RSPAMD_ALIGNED(32) subkey[CHACHA_BLOCKBYTES];

		mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
		memset(subkey, 0, sizeof(subkey));
		chacha_update(enc_ctx, subkey, subkey, sizeof(subkey));
		crypto_onetimeauth_init(mac_ctx, subkey);
		rspamd_explicit_memzero(subkey, sizeof(subkey));

		return mac_ctx;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		auth_ctx = enc_ctx;

		return auth_ctx;
#endif
	}

	return NULL;
}

static gboolean
rspamd_cryptobox_decrypt_update(void *enc_ctx, const unsigned char *in, gsize inlen,
								unsigned char *out, gsize *outlen,
								enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		gsize r;
		chacha_state *s;

		s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
		r = chacha_update(s, in, out, inlen);

		if (outlen != NULL) {
			*outlen = r;
		}

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_CIPHER_CTX **s = enc_ctx;
		int r;

		r = outlen ? *outlen : inlen;
		g_assert(EVP_DecryptUpdate(*s, out, &r, in, inlen) == 1);

		if (outlen) {
			*outlen = r;
		}

		return TRUE;
#endif
	}
}

static gboolean
rspamd_cryptobox_auth_verify_update(void *auth_ctx,
									const unsigned char *in, gsize inlen,
									enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		crypto_onetimeauth_state *mac_ctx;

		mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
		crypto_onetimeauth_update(mac_ctx, in, inlen);

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
rspamd_cryptobox_decrypt_final(void *enc_ctx, unsigned char *out, gsize remain,
							   enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		chacha_state *s;

		s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
		chacha_final(s, out);

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_CIPHER_CTX **s = enc_ctx;
		int r = remain;

		if (EVP_DecryptFinal_ex(*s, out, &r) < 0) {
			return FALSE;
		}

		return TRUE;
#endif
	}

	return FALSE;
}

static gboolean
rspamd_cryptobox_auth_verify_final(void *auth_ctx, const rspamd_mac_t sig,
								   enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		rspamd_mac_t mac;
		crypto_onetimeauth_state *mac_ctx;

		mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
		crypto_onetimeauth_final(mac_ctx, mac);

		if (crypto_verify_16(mac, sig) != 0) {
			return FALSE;
		}

		return TRUE;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_CIPHER_CTX **s = auth_ctx;

		if (EVP_CIPHER_CTX_ctrl(*s, EVP_CTRL_GCM_SET_TAG, 16, (unsigned char *) sig) != 1) {
			return FALSE;
		}

		return TRUE;
#endif
	}

	return FALSE;
}


static void
rspamd_cryptobox_cleanup(void *enc_ctx, void *auth_ctx,
						 enum rspamd_cryptobox_mode mode)
{
	if (G_LIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		crypto_onetimeauth_state *mac_ctx;

		mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
		rspamd_explicit_memzero(mac_ctx, sizeof(*mac_ctx));
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
		EVP_CIPHER_CTX **s = enc_ctx;

		EVP_CIPHER_CTX_cleanup(*s);
		EVP_CIPHER_CTX_free(*s);
#endif
	}
}

void rspamd_cryptobox_encrypt_nm_inplace(unsigned char *data, gsize len,
										 const rspamd_nonce_t nonce,
										 const rspamd_nm_t nm,
										 rspamd_mac_t sig,
										 enum rspamd_cryptobox_mode mode)
{
	gsize r;
	void *enc_ctx, *auth_ctx;

	enc_ctx = g_alloca(rspamd_cryptobox_encrypt_ctx_len(mode));
	auth_ctx = g_alloca(rspamd_cryptobox_auth_ctx_len(mode));

	enc_ctx = rspamd_cryptobox_encrypt_init(enc_ctx, nonce, nm, mode);
	auth_ctx = rspamd_cryptobox_auth_init(auth_ctx, enc_ctx, mode);

	rspamd_cryptobox_encrypt_update(enc_ctx, data, len, data, &r, mode);
	rspamd_cryptobox_encrypt_final(enc_ctx, data + r, len - r, mode);

	rspamd_cryptobox_auth_update(auth_ctx, data, len, mode);
	rspamd_cryptobox_auth_final(auth_ctx, sig, mode);

	rspamd_cryptobox_cleanup(enc_ctx, auth_ctx, mode);
}

static void
rspamd_cryptobox_flush_outbuf(struct rspamd_cryptobox_segment *st,
							  const unsigned char *buf, gsize len, gsize offset)
{
	gsize cpy_len;

	while (len > 0) {
		cpy_len = MIN(len, st->len - offset);
		memcpy(st->data + offset, buf, cpy_len);
		st++;
		buf += cpy_len;
		len -= cpy_len;
		offset = 0;
	}
}

void rspamd_cryptobox_encryptv_nm_inplace(struct rspamd_cryptobox_segment *segments,
										  gsize cnt,
										  const rspamd_nonce_t nonce,
										  const rspamd_nm_t nm, rspamd_mac_t sig,
										  enum rspamd_cryptobox_mode mode)
{
	struct rspamd_cryptobox_segment *cur = segments, *start_seg = segments;
	unsigned char outbuf[CHACHA_BLOCKBYTES * 16];
	void *enc_ctx, *auth_ctx;
	unsigned char *out, *in;
	gsize r, remain, inremain, seg_offset;

	enc_ctx = g_alloca(rspamd_cryptobox_encrypt_ctx_len(mode));
	auth_ctx = g_alloca(rspamd_cryptobox_auth_ctx_len(mode));

	enc_ctx = rspamd_cryptobox_encrypt_init(enc_ctx, nonce, nm, mode);
	auth_ctx = rspamd_cryptobox_auth_init(auth_ctx, enc_ctx, mode);

	remain = sizeof(outbuf);
	out = outbuf;
	inremain = cur->len;
	seg_offset = 0;

	for (;;) {
		if (cur - segments == (int) cnt) {
			break;
		}

		if (cur->len <= remain) {
			memcpy(out, cur->data, cur->len);
			remain -= cur->len;
			out += cur->len;
			cur++;

			if (remain == 0) {
				rspamd_cryptobox_encrypt_update(enc_ctx, outbuf, sizeof(outbuf),
												outbuf, NULL, mode);
				rspamd_cryptobox_auth_update(auth_ctx, outbuf, sizeof(outbuf),
											 mode);
				rspamd_cryptobox_flush_outbuf(start_seg, outbuf,
											  sizeof(outbuf), seg_offset);
				start_seg = cur;
				seg_offset = 0;
				remain = sizeof(outbuf);
				out = outbuf;
			}
		}
		else {
			memcpy(out, cur->data, remain);
			rspamd_cryptobox_encrypt_update(enc_ctx, outbuf, sizeof(outbuf),
											outbuf, NULL, mode);
			rspamd_cryptobox_auth_update(auth_ctx, outbuf, sizeof(outbuf),
										 mode);
			rspamd_cryptobox_flush_outbuf(start_seg, outbuf, sizeof(outbuf),
										  seg_offset);
			seg_offset = 0;

			inremain = cur->len - remain;
			in = cur->data + remain;
			out = outbuf;
			remain = 0;
			start_seg = cur;

			while (inremain > 0) {
				if (sizeof(outbuf) <= inremain) {
					memcpy(outbuf, in, sizeof(outbuf));
					rspamd_cryptobox_encrypt_update(enc_ctx,
													outbuf,
													sizeof(outbuf),
													outbuf,
													NULL,
													mode);
					rspamd_cryptobox_auth_update(auth_ctx,
												 outbuf,
												 sizeof(outbuf),
												 mode);
					memcpy(in, outbuf, sizeof(outbuf));
					in += sizeof(outbuf);
					inremain -= sizeof(outbuf);
					remain = sizeof(outbuf);
				}
				else {
					memcpy(outbuf, in, inremain);
					remain = sizeof(outbuf) - inremain;
					out = outbuf + inremain;
					inremain = 0;
				}
			}

			seg_offset = cur->len - (sizeof(outbuf) - remain);
			cur++;
		}
	}

	rspamd_cryptobox_encrypt_update(enc_ctx, outbuf, sizeof(outbuf) - remain,
									outbuf, &r, mode);
	out = outbuf + r;
	rspamd_cryptobox_encrypt_final(enc_ctx, out, sizeof(outbuf) - remain - r,
								   mode);

	rspamd_cryptobox_auth_update(auth_ctx, outbuf, sizeof(outbuf) - remain,
								 mode);
	rspamd_cryptobox_auth_final(auth_ctx, sig, mode);

	rspamd_cryptobox_flush_outbuf(start_seg, outbuf, sizeof(outbuf) - remain,
								  seg_offset);
	rspamd_cryptobox_cleanup(enc_ctx, auth_ctx, mode);
}

gboolean
rspamd_cryptobox_decrypt_nm_inplace(unsigned char *data, gsize len,
									const rspamd_nonce_t nonce, const rspamd_nm_t nm,
									const rspamd_mac_t sig, enum rspamd_cryptobox_mode mode)
{
	gsize r = 0;
	gboolean ret = TRUE;
	void *enc_ctx, *auth_ctx;

	enc_ctx = g_alloca(rspamd_cryptobox_encrypt_ctx_len(mode));
	auth_ctx = g_alloca(rspamd_cryptobox_auth_ctx_len(mode));

	enc_ctx = rspamd_cryptobox_decrypt_init(enc_ctx, nonce, nm, mode);
	auth_ctx = rspamd_cryptobox_auth_verify_init(auth_ctx, enc_ctx, mode);

	rspamd_cryptobox_auth_verify_update(auth_ctx, data, len, mode);

	if (!rspamd_cryptobox_auth_verify_final(auth_ctx, sig, mode)) {
		ret = FALSE;
	}
	else {
		rspamd_cryptobox_decrypt_update(enc_ctx, data, len, data, &r, mode);
		ret = rspamd_cryptobox_decrypt_final(enc_ctx, data + r, len - r, mode);
	}

	rspamd_cryptobox_cleanup(enc_ctx, auth_ctx, mode);

	return ret;
}

gboolean
rspamd_cryptobox_decrypt_inplace(unsigned char *data, gsize len,
								 const rspamd_nonce_t nonce,
								 const rspamd_pk_t pk, const rspamd_sk_t sk,
								 const rspamd_mac_t sig,
								 enum rspamd_cryptobox_mode mode)
{
	unsigned char nm[rspamd_cryptobox_MAX_NMBYTES];
	gboolean ret;

	rspamd_cryptobox_nm(nm, pk, sk, mode);
	ret = rspamd_cryptobox_decrypt_nm_inplace(data, len, nonce, nm, sig, mode);

	rspamd_explicit_memzero(nm, sizeof(nm));

	return ret;
}

void rspamd_cryptobox_encrypt_inplace(unsigned char *data, gsize len,
									  const rspamd_nonce_t nonce,
									  const rspamd_pk_t pk, const rspamd_sk_t sk,
									  rspamd_mac_t sig,
									  enum rspamd_cryptobox_mode mode)
{
	unsigned char nm[rspamd_cryptobox_MAX_NMBYTES];

	rspamd_cryptobox_nm(nm, pk, sk, mode);
	rspamd_cryptobox_encrypt_nm_inplace(data, len, nonce, nm, sig, mode);
	rspamd_explicit_memzero(nm, sizeof(nm));
}

void rspamd_cryptobox_encryptv_inplace(struct rspamd_cryptobox_segment *segments,
									   gsize cnt,
									   const rspamd_nonce_t nonce,
									   const rspamd_pk_t pk, const rspamd_sk_t sk,
									   rspamd_mac_t sig,
									   enum rspamd_cryptobox_mode mode)
{
	unsigned char nm[rspamd_cryptobox_MAX_NMBYTES];

	rspamd_cryptobox_nm(nm, pk, sk, mode);
	rspamd_cryptobox_encryptv_nm_inplace(segments, cnt, nonce, nm, sig, mode);
	rspamd_explicit_memzero(nm, sizeof(nm));
}


void rspamd_cryptobox_siphash(unsigned char *out, const unsigned char *in,
							  unsigned long long inlen,
							  const rspamd_sipkey_t k)
{
	crypto_shorthash_siphash24(out, in, inlen, k);
}

/*
* Password-Based Key Derivation Function 2 (PKCS #5 v2.0).
* Code based on IEEE Std 802.11-2007, Annex H.4.2.
*/
static gboolean
rspamd_cryptobox_pbkdf2(const char *pass, gsize pass_len,
						const uint8_t *salt, gsize salt_len, uint8_t *key, gsize key_len,
						unsigned int rounds)
{
	uint8_t *asalt, obuf[crypto_generichash_blake2b_BYTES_MAX];
	uint8_t d1[crypto_generichash_blake2b_BYTES_MAX],
		d2[crypto_generichash_blake2b_BYTES_MAX];
	unsigned int i, j;
	unsigned int count;
	gsize r;

	if (rounds < 1 || key_len == 0) {
		return FALSE;
	}
	if (salt_len == 0 || salt_len > G_MAXSIZE - 4) {
		return FALSE;
	}

	asalt = g_malloc(salt_len + 4);
	memcpy(asalt, salt, salt_len);

	for (count = 1; key_len > 0; count++) {
		asalt[salt_len + 0] = (count >> 24) & 0xff;
		asalt[salt_len + 1] = (count >> 16) & 0xff;
		asalt[salt_len + 2] = (count >> 8) & 0xff;
		asalt[salt_len + 3] = count & 0xff;

		if (pass_len <= crypto_generichash_blake2b_KEYBYTES_MAX) {
			crypto_generichash_blake2b(d1, sizeof(d1), asalt, salt_len + 4,
									   pass, pass_len);
		}
		else {
			uint8_t k[crypto_generichash_blake2b_BYTES_MAX];

			/*
			* We use additional blake2 iteration to store large key
			* XXX: it is not compatible with the original implementation but safe
			*/
			crypto_generichash_blake2b(k, sizeof(k), pass, pass_len,
									   NULL, 0);
			crypto_generichash_blake2b(d1, sizeof(d1), asalt, salt_len + 4,
									   k, sizeof(k));
		}

		memcpy(obuf, d1, sizeof(obuf));

		for (i = 1; i < rounds; i++) {
			if (pass_len <= crypto_generichash_blake2b_KEYBYTES_MAX) {
				crypto_generichash_blake2b(d2, sizeof(d2), d1, sizeof(d1),
										   pass, pass_len);
			}
			else {
				uint8_t k[crypto_generichash_blake2b_BYTES_MAX];

				/*
				* We use additional blake2 iteration to store large key
				* XXX: it is not compatible with the original implementation but safe
				*/
				crypto_generichash_blake2b(k, sizeof(k), pass, pass_len,
										   NULL, 0);
				crypto_generichash_blake2b(d2, sizeof(d2), d1, sizeof(d1),
										   k, sizeof(k));
			}

			memcpy(d1, d2, sizeof(d1));

			for (j = 0; j < sizeof(obuf); j++) {
				obuf[j] ^= d1[j];
			}
		}

		r = MIN(key_len, crypto_generichash_blake2b_BYTES_MAX);
		memcpy(key, obuf, r);
		key += r;
		key_len -= r;
	}

	rspamd_explicit_memzero(asalt, salt_len + 4);
	g_free(asalt);
	rspamd_explicit_memzero(d1, sizeof(d1));
	rspamd_explicit_memzero(d2, sizeof(d2));
	rspamd_explicit_memzero(obuf, sizeof(obuf));

	return TRUE;
}

gboolean
rspamd_cryptobox_pbkdf(const char *pass, gsize pass_len,
					   const uint8_t *salt, gsize salt_len, uint8_t *key, gsize key_len,
					   unsigned int complexity, enum rspamd_cryptobox_pbkdf_type type)
{
	gboolean ret = FALSE;

	switch (type) {
	case RSPAMD_CRYPTOBOX_CATENA:
		if (catena(pass, pass_len, salt, salt_len, "rspamd", 6,
				   4, complexity, complexity, key_len, key) == 0) {
			ret = TRUE;
		}
		break;
	case RSPAMD_CRYPTOBOX_PBKDF2:
	default:
		ret = rspamd_cryptobox_pbkdf2(pass, pass_len, salt, salt_len, key,
									  key_len, complexity);
		break;
	}

	return ret;
}

unsigned int rspamd_cryptobox_pk_bytes(enum rspamd_cryptobox_mode mode)
{
	if (G_UNLIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return 32;
	}
	else {
		return 65;
	}
}

unsigned int rspamd_cryptobox_pk_sig_bytes(enum rspamd_cryptobox_mode mode)
{
	if (G_UNLIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return 32;
	}
	else {
		return 65;
	}
}

unsigned int rspamd_cryptobox_nonce_bytes(enum rspamd_cryptobox_mode mode)
{
	if (G_UNLIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return 24;
	}
	else {
		return 16;
	}
}


unsigned int rspamd_cryptobox_sk_bytes(enum rspamd_cryptobox_mode mode)
{
	return 32;
}

unsigned int rspamd_cryptobox_sk_sig_bytes(enum rspamd_cryptobox_mode mode)
{
	if (G_UNLIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return 64;
	}
	else {
		return 32;
	}
}

unsigned int rspamd_cryptobox_signature_bytes(enum rspamd_cryptobox_mode mode)
{
	static unsigned int ssl_keylen;

	if (G_UNLIKELY(mode == RSPAMD_CRYPTOBOX_MODE_25519)) {
		return 64;
	}
	else {
#ifndef HAVE_USABLE_OPENSSL
		g_assert(0);
#else
#if OPENSSL_VERSION_MAJOR >= 3
		if (ssl_keylen == 0) {
			OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
			EVP_MD_CTX *sha_ctx = EVP_MD_CTX_new();
			EVP_PKEY *pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", "prime256v1");
			g_assert(pkey != NULL);

			g_assert(EVP_DigestSignInit(sha_ctx, NULL, EVP_sha512(), NULL, pkey) == 1);

			size_t keylen = 0;
			const unsigned char data[] = "data to be signed";
			size_t datalen = sizeof(data) - 1;
			g_assert(EVP_DigestSign(sha_ctx, NULL, &keylen, data, datalen) == 1);
			ssl_keylen = keylen;

			OSSL_LIB_CTX_free(libctx);
			EVP_PKEY_free(pkey);
			EVP_MD_CTX_free(sha_ctx);
		}
#else
		if (ssl_keylen == 0) {
			EC_KEY *lk;
			lk = EC_KEY_new_by_curve_name(CRYPTOBOX_CURVE_NID);
			ssl_keylen = ECDSA_size(lk);
			EC_KEY_free(lk);
		}
#endif
#endif
		return ssl_keylen;
	}
}

unsigned int rspamd_cryptobox_nm_bytes(enum rspamd_cryptobox_mode mode)
{
	return 32;
}

unsigned int rspamd_cryptobox_mac_bytes(enum rspamd_cryptobox_mode mode)
{
	return 16;
}

void rspamd_cryptobox_hash_init(rspamd_cryptobox_hash_state_t *p, const unsigned char *key, gsize keylen)
{
	crypto_generichash_blake2b_state *st = cryptobox_align_ptr(p,
															   RSPAMD_ALIGNOF(crypto_generichash_blake2b_state));
	crypto_generichash_blake2b_init(st, key, keylen,
									crypto_generichash_blake2b_BYTES_MAX);
}

/**
* Update hash with data portion
*/
void rspamd_cryptobox_hash_update(rspamd_cryptobox_hash_state_t *p, const unsigned char *data, gsize len)
{
	crypto_generichash_blake2b_state *st = cryptobox_align_ptr(p,
															   RSPAMD_ALIGNOF(crypto_generichash_blake2b_state));
	crypto_generichash_blake2b_update(st, data, len);
}

/**
* Output hash to the buffer of rspamd_cryptobox_HASHBYTES length
*/
void rspamd_cryptobox_hash_final(rspamd_cryptobox_hash_state_t *p, unsigned char *out)
{
	crypto_generichash_blake2b_state *st = cryptobox_align_ptr(p,
															   RSPAMD_ALIGNOF(crypto_generichash_blake2b_state));
	crypto_generichash_blake2b_final(st, out, crypto_generichash_blake2b_BYTES_MAX);
}

/**
* One in all function
*/
void rspamd_cryptobox_hash(unsigned char *out,
						   const unsigned char *data,
						   gsize len,
						   const unsigned char *key,
						   gsize keylen)
{
	crypto_generichash_blake2b(out, crypto_generichash_blake2b_BYTES_MAX,
							   data, len, key, keylen);
}

G_STATIC_ASSERT(sizeof(t1ha_context_t) <=
				sizeof(((rspamd_cryptobox_fast_hash_state_t *) NULL)->opaque));
G_STATIC_ASSERT(sizeof(struct XXH3_state_s) <=
				sizeof(((rspamd_cryptobox_fast_hash_state_t *) NULL)->opaque));


struct RSPAMD_ALIGNED(16) _mum_iuf {
	union {
		int64_t ll;
		unsigned char b[sizeof(uint64_t)];
	} buf;
	int64_t h;
	unsigned rem;
};

rspamd_cryptobox_fast_hash_state_t *
rspamd_cryptobox_fast_hash_new(void)
{
	rspamd_cryptobox_fast_hash_state_t *nst;
	int ret = posix_memalign((void **) &nst, RSPAMD_ALIGNOF(rspamd_cryptobox_fast_hash_state_t),
							 sizeof(rspamd_cryptobox_fast_hash_state_t));

	if (ret != 0) {
		abort();
	}

	return nst;
}

void rspamd_cryptobox_fast_hash_free(rspamd_cryptobox_fast_hash_state_t *st)
{
	free(st);
}

void rspamd_cryptobox_fast_hash_init(rspamd_cryptobox_fast_hash_state_t *st,
									 uint64_t seed)
{
	XXH3_state_t *xst = (XXH3_state_t *) st->opaque;
	st->type = RSPAMD_CRYPTOBOX_XXHASH3;
	XXH3_INITSTATE(xst);
	XXH3_64bits_reset_withSeed(xst, seed);
}

void rspamd_cryptobox_fast_hash_init_specific(rspamd_cryptobox_fast_hash_state_t *st,
											  enum rspamd_cryptobox_fast_hash_type type,
											  uint64_t seed)
{
	switch (type) {
	case RSPAMD_CRYPTOBOX_T1HA:
	case RSPAMD_CRYPTOBOX_HASHFAST:
	case RSPAMD_CRYPTOBOX_HASHFAST_INDEPENDENT: {
		t1ha_context_t *rst = (t1ha_context_t *) st->opaque;
		st->type = RSPAMD_CRYPTOBOX_T1HA;
		t1ha2_init(rst, seed, 0);
		break;
	}
	case RSPAMD_CRYPTOBOX_XXHASH64: {
		XXH64_state_t *xst = (XXH64_state_t *) st->opaque;
		memset(xst, 0, sizeof(*xst));
		st->type = RSPAMD_CRYPTOBOX_XXHASH64;
		XXH64_reset(xst, seed);
		break;
	}
	case RSPAMD_CRYPTOBOX_XXHASH32: {
		XXH32_state_t *xst = (XXH32_state_t *) st->opaque;
		memset(xst, 0, sizeof(*xst));
		st->type = RSPAMD_CRYPTOBOX_XXHASH32;
		XXH32_reset(xst, seed);
		break;
	}
	case RSPAMD_CRYPTOBOX_XXHASH3: {
		XXH3_state_t *xst = (XXH3_state_t *) st->opaque;
		XXH3_INITSTATE(xst);
		st->type = RSPAMD_CRYPTOBOX_XXHASH3;
		XXH3_64bits_reset_withSeed(xst, seed);
		break;
	}
	case RSPAMD_CRYPTOBOX_MUMHASH: {
		struct _mum_iuf *iuf = (struct _mum_iuf *) st->opaque;
		st->type = RSPAMD_CRYPTOBOX_MUMHASH;
		iuf->h = seed;
		iuf->buf.ll = 0;
		iuf->rem = 0;
		break;
	}
	}
}

void rspamd_cryptobox_fast_hash_update(rspamd_cryptobox_fast_hash_state_t *st,
									   const void *data, gsize len)
{
	if (st->type == RSPAMD_CRYPTOBOX_T1HA) {
		t1ha_context_t *rst = (t1ha_context_t *) st->opaque;
		t1ha2_update(rst, data, len);
	}
	else {
		switch (st->type) {
		case RSPAMD_CRYPTOBOX_XXHASH64: {
			XXH64_state_t *xst = (XXH64_state_t *) st->opaque;
			XXH64_update(xst, data, len);
			break;
		}
		case RSPAMD_CRYPTOBOX_XXHASH32: {
			XXH32_state_t *xst = (XXH32_state_t *) st->opaque;
			XXH32_update(xst, data, len);
			break;
		}
		case RSPAMD_CRYPTOBOX_XXHASH3: {
			XXH3_state_t *xst = (XXH3_state_t *) st->opaque;
			XXH3_64bits_update(xst, data, len);
			break;
		}
		case RSPAMD_CRYPTOBOX_MUMHASH: {
			struct _mum_iuf *iuf = (struct _mum_iuf *) st->opaque;
			gsize drem = len;
			const unsigned char *p = data;

			if (iuf->rem > 0) {
				/* Process remainder */
				if (drem >= iuf->rem) {
					memcpy(iuf->buf.b + sizeof(iuf->buf.ll) - iuf->rem,
						   p, iuf->rem);
					drem -= iuf->rem;
					p += iuf->rem;
					iuf->h = mum_hash_step(iuf->h, iuf->buf.ll);
					iuf->rem = 0;
				}
				else {
					memcpy(iuf->buf.b + sizeof(iuf->buf.ll) - iuf->rem, p, drem);
					iuf->rem -= drem;
					drem = 0;
				}
			}

			while (drem >= sizeof(iuf->buf.ll)) {
				memcpy(iuf->buf.b, p, sizeof(iuf->buf.ll));
				iuf->h = mum_hash_step(iuf->h, iuf->buf.ll);
				drem -= sizeof(iuf->buf.ll);
				p += sizeof(iuf->buf.ll);
			}

			/* Leftover */
			if (drem > 0) {
				iuf->rem = sizeof(uint64_t) - drem;
				iuf->buf.ll = 0;
				memcpy(iuf->buf.b, p, drem);
			}
			break;
		}
		case RSPAMD_CRYPTOBOX_T1HA:
		case RSPAMD_CRYPTOBOX_HASHFAST:
		case RSPAMD_CRYPTOBOX_HASHFAST_INDEPENDENT: {
			t1ha_context_t *rst = (t1ha_context_t *) st->opaque;
			t1ha2_update(rst, data, len);
			break;
		}
		}
	}
}

uint64_t
rspamd_cryptobox_fast_hash_final(rspamd_cryptobox_fast_hash_state_t *st)
{
	uint64_t ret;

	if (st->type == RSPAMD_CRYPTOBOX_T1HA) {
		t1ha_context_t *rst = (t1ha_context_t *) st->opaque;

		return t1ha2_final(rst, NULL);
	}
	else {
		switch (st->type) {
		case RSPAMD_CRYPTOBOX_XXHASH64: {
			XXH64_state_t *xst = (XXH64_state_t *) st->opaque;
			ret = XXH64_digest(xst);
			break;
		}
		case RSPAMD_CRYPTOBOX_XXHASH32: {
			XXH32_state_t *xst = (XXH32_state_t *) st->opaque;
			ret = XXH32_digest(xst);
			break;
		}
		case RSPAMD_CRYPTOBOX_XXHASH3: {
			XXH3_state_t *xst = (XXH3_state_t *) st->opaque;
			ret = XXH3_64bits_digest(xst);
			break;
		}
		case RSPAMD_CRYPTOBOX_MUMHASH: {
			struct _mum_iuf *iuf = (struct _mum_iuf *) st->opaque;
			iuf->h = mum_hash_step(iuf->h, iuf->buf.ll);
			ret = mum_hash_finish(iuf->h);
			break;
		}
		case RSPAMD_CRYPTOBOX_T1HA:
		case RSPAMD_CRYPTOBOX_HASHFAST:
		case RSPAMD_CRYPTOBOX_HASHFAST_INDEPENDENT: {
			t1ha_context_t *rst = (t1ha_context_t *) st->opaque;

			ret = t1ha2_final(rst, NULL);
			break;
		}
		}
	}

	return ret;
}

/**
* One in all function
*/
static inline uint64_t
rspamd_cryptobox_fast_hash_machdep(const void *data,
								   gsize len, uint64_t seed)
{
	return XXH3_64bits_withSeed(data, len, seed);
}

static inline uint64_t
rspamd_cryptobox_fast_hash_indep(const void *data,
								 gsize len, uint64_t seed)
{
	return XXH3_64bits_withSeed(data, len, seed);
}

uint64_t
rspamd_cryptobox_fast_hash(const void *data,
						   gsize len, uint64_t seed)
{
	return rspamd_cryptobox_fast_hash_machdep(data, len, seed);
}

uint64_t
rspamd_cryptobox_fast_hash_specific(
	enum rspamd_cryptobox_fast_hash_type type,
	const void *data,
	gsize len, uint64_t seed)
{
	switch (type) {
	case RSPAMD_CRYPTOBOX_XXHASH32:
		return XXH32(data, len, seed);
	case RSPAMD_CRYPTOBOX_XXHASH3:
		return XXH3_64bits_withSeed(data, len, seed);
	case RSPAMD_CRYPTOBOX_XXHASH64:
		return XXH64(data, len, seed);
	case RSPAMD_CRYPTOBOX_MUMHASH:
		return mum_hash(data, len, seed);
	case RSPAMD_CRYPTOBOX_T1HA:
		return t1ha2_atonce(data, len, seed);
	case RSPAMD_CRYPTOBOX_HASHFAST_INDEPENDENT:
		return rspamd_cryptobox_fast_hash_indep(data, len, seed);
	case RSPAMD_CRYPTOBOX_HASHFAST:
	default:
		return rspamd_cryptobox_fast_hash_machdep(data, len, seed);
	}
}
