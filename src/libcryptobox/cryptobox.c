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
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
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

#ifdef HAVE_BUILTIN_CPU_SUPPORTS
RSPAMD_CONSTRUCTOR(cryptobox_cpu_init)
{
	__builtin_cpu_init();
}
static gboolean
rspamd_cryptobox_test_instr(int instr)
{
	gboolean ret = FALSE;
	switch (instr) {
#if defined HAVE_SSE2 && defined(__x86_64__)
	case CPUID_SSE2:
		ret = __builtin_cpu_supports("sse2");
		break;
	case CPUID_RDRAND:
		/* XXX: no check to test for rdrand, but all avx2 cpus are def. capable of rdrand */
		ret = __builtin_cpu_supports("avx2");
		break;
#endif
#ifdef HAVE_SSE3
	case CPUID_SSE3:
		ret = __builtin_cpu_supports("sse3");
		break;
#endif
#ifdef HAVE_SSSE3
	case CPUID_SSSE3:
		ret = __builtin_cpu_supports("ssse3");
		break;
#endif
#ifdef HAVE_SSE41
	case CPUID_SSE41:
		ret = __builtin_cpu_supports("sse4.1");
		break;
#endif
#if defined HAVE_SSE42 && defined(__x86_64__)
	case CPUID_SSE42:
		ret = __builtin_cpu_supports("sse4.2");
		break;
#endif
#ifdef HAVE_AVX
	case CPUID_AVX:
		ret = __builtin_cpu_supports("avx");
		break;
#endif
#ifdef HAVE_AVX2
	case CPUID_AVX2:
		ret = __builtin_cpu_supports("avx2");
		break;
#endif
	}

	return ret;
}
#else
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
#endif /* HAVE_BUILTIN_CPU_SUPPORTS */

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

void rspamd_cryptobox_keypair(rspamd_pk_t pk, rspamd_sk_t sk)
{
	ottery_rand_bytes(sk, rspamd_cryptobox_MAX_SKBYTES);
	sk[0] &= 248;
	sk[31] &= 127;
	sk[31] |= 64;

	crypto_scalarmult_base(pk, sk);
}

void rspamd_cryptobox_keypair_sig(rspamd_sig_pk_t pk, rspamd_sig_sk_t sk)
{
	crypto_sign_keypair(pk, sk);
}

void rspamd_cryptobox_nm(rspamd_nm_t nm,
						 const rspamd_pk_t pk, const rspamd_sk_t sk)
{
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

void rspamd_cryptobox_sign(unsigned char *sig, unsigned long long *siglen_p,
						   const unsigned char *m, gsize mlen,
						   const rspamd_sig_sk_t sk)
{
	crypto_sign_detached(sig, siglen_p, m, mlen, sk);
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

	if (siglen == crypto_sign_bytes()) {
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
									 EVP_PKEY *pub_key,
									 GError **err)
{
	bool ret = false, r;

	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pub_key, NULL);
	g_assert(pctx != NULL);
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_get_digestbynid(nid);

	g_assert(EVP_PKEY_verify_init(pctx) == 1);
	g_assert(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1);

	if ((r = EVP_PKEY_CTX_set_signature_md(pctx, md)) <= 0) {
		g_set_error(err, g_quark_from_static_string("OpenSSL"),
					r,
					"cannot set digest %s for RSA verification (%s returned from OpenSSL), try use `update-crypto-policies --set LEGACY` on RH",
					EVP_MD_get0_name(md),
					ERR_lib_error_string(ERR_get_error()));
		EVP_PKEY_CTX_free(pctx);
		EVP_MD_CTX_free(mdctx);

		return false;
	}

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
							 const rspamd_sig_pk_t pk)
{
	bool ret = false;

	if (siglen == crypto_sign_bytes()) {
		ret = (crypto_sign_verify_detached(sig, m, mlen, pk) == 0);
	}

	return ret;
}

static void *
rspamd_cryptobox_encrypt_init(void *enc_ctx, const rspamd_nonce_t nonce,
							  const rspamd_nm_t nm)
{
	chacha_state *s;

	s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
	xchacha_init(s,
				 (const chacha_key *) nm,
				 (const chacha_iv24 *) nonce,
				 20);

	return s;
}

static void *
rspamd_cryptobox_auth_init(void *auth_ctx, void *enc_ctx)
{
	crypto_onetimeauth_state *mac_ctx;
	unsigned char RSPAMD_ALIGNED(32) subkey[CHACHA_BLOCKBYTES];

	mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
	memset(subkey, 0, sizeof(subkey));
	chacha_update(enc_ctx, subkey, subkey, sizeof(subkey));
	crypto_onetimeauth_init(mac_ctx, subkey);
	rspamd_explicit_memzero(subkey, sizeof(subkey));

	return mac_ctx;
}

static gboolean
rspamd_cryptobox_encrypt_update(void *enc_ctx, const unsigned char *in, gsize inlen,
								unsigned char *out, gsize *outlen)
{
	gsize r;
	chacha_state *s;

	s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);

	r = chacha_update(s, in, out, inlen);

	if (outlen != NULL) {
		*outlen = r;
	}

	return TRUE;
}

static gboolean
rspamd_cryptobox_auth_update(void *auth_ctx, const unsigned char *in, gsize inlen)
{
	crypto_onetimeauth_state *mac_ctx;

	mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
	crypto_onetimeauth_update(mac_ctx, in, inlen);

	return TRUE;
}

static gsize
rspamd_cryptobox_encrypt_final(void *enc_ctx, unsigned char *out, gsize remain)
{
	chacha_state *s;

	s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
	return chacha_final(s, out);
}

static gboolean
rspamd_cryptobox_auth_final(void *auth_ctx, rspamd_mac_t sig)
{
	crypto_onetimeauth_state *mac_ctx;

	mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
	crypto_onetimeauth_final(mac_ctx, sig);

	return TRUE;
}

static void *
rspamd_cryptobox_decrypt_init(void *enc_ctx, const rspamd_nonce_t nonce,
							  const rspamd_nm_t nm)
{
	chacha_state *s;

	s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
	xchacha_init(s,
				 (const chacha_key *) nm,
				 (const chacha_iv24 *) nonce,
				 20);

	return s;
}

static void *
rspamd_cryptobox_auth_verify_init(void *auth_ctx, void *enc_ctx)
{
	crypto_onetimeauth_state *mac_ctx;
	unsigned char RSPAMD_ALIGNED(32) subkey[CHACHA_BLOCKBYTES];

	mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
	memset(subkey, 0, sizeof(subkey));
	chacha_update(enc_ctx, subkey, subkey, sizeof(subkey));
	crypto_onetimeauth_init(mac_ctx, subkey);
	rspamd_explicit_memzero(subkey, sizeof(subkey));

	return mac_ctx;
}

static gboolean
rspamd_cryptobox_decrypt_update(void *enc_ctx, const unsigned char *in, gsize inlen,
								unsigned char *out, gsize *outlen)
{
	gsize r;
	chacha_state *s;

	s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
	r = chacha_update(s, in, out, inlen);

	if (outlen != NULL) {
		*outlen = r;
	}

	return TRUE;
}

static gboolean
rspamd_cryptobox_auth_verify_update(void *auth_ctx,
									const unsigned char *in, gsize inlen)
{
	crypto_onetimeauth_state *mac_ctx;

	mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
	crypto_onetimeauth_update(mac_ctx, in, inlen);

	return TRUE;
}

static gboolean
rspamd_cryptobox_decrypt_final(void *enc_ctx, unsigned char *out, gsize remain)
{
	chacha_state *s;

	s = cryptobox_align_ptr(enc_ctx, CRYPTOBOX_ALIGNMENT);
	chacha_final(s, out);

	return TRUE;
}

static gboolean
rspamd_cryptobox_auth_verify_final(void *auth_ctx, const rspamd_mac_t sig)
{
	rspamd_mac_t mac;
	crypto_onetimeauth_state *mac_ctx;

	mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
	crypto_onetimeauth_final(mac_ctx, mac);

	if (crypto_verify_16(mac, sig) != 0) {
		return FALSE;
	}

	return TRUE;
}


static void
rspamd_cryptobox_cleanup(void *enc_ctx, void *auth_ctx)
{
	crypto_onetimeauth_state *mac_ctx;

	mac_ctx = cryptobox_align_ptr(auth_ctx, CRYPTOBOX_ALIGNMENT);
	rspamd_explicit_memzero(mac_ctx, sizeof(*mac_ctx));
}

void rspamd_cryptobox_encrypt_nm_inplace(unsigned char *data, gsize len,
										 const rspamd_nonce_t nonce,
										 const rspamd_nm_t nm,
										 rspamd_mac_t sig)
{
	gsize r;
	void *enc_ctx, *auth_ctx;

	enc_ctx = g_alloca(sizeof(chacha_state) + CRYPTOBOX_ALIGNMENT);
	auth_ctx = g_alloca(sizeof(crypto_onetimeauth_state) + RSPAMD_ALIGNOF(crypto_onetimeauth_state));

	enc_ctx = rspamd_cryptobox_encrypt_init(enc_ctx, nonce, nm);
	auth_ctx = rspamd_cryptobox_auth_init(auth_ctx, enc_ctx);

	rspamd_cryptobox_encrypt_update(enc_ctx, data, len, data, &r);
	rspamd_cryptobox_encrypt_final(enc_ctx, data + r, len - r);

	rspamd_cryptobox_auth_update(auth_ctx, data, len);
	rspamd_cryptobox_auth_final(auth_ctx, sig);

	rspamd_cryptobox_cleanup(enc_ctx, auth_ctx);
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
										  const rspamd_nm_t nm, rspamd_mac_t sig)
{
	struct rspamd_cryptobox_segment *cur = segments, *start_seg = segments;
	unsigned char outbuf[CHACHA_BLOCKBYTES * 16];
	void *enc_ctx, *auth_ctx;
	unsigned char *out, *in;
	gsize r, remain, inremain, seg_offset;

	enc_ctx = g_alloca(sizeof(chacha_state) + CRYPTOBOX_ALIGNMENT);
	auth_ctx = g_alloca(sizeof(crypto_onetimeauth_state) + RSPAMD_ALIGNOF(crypto_onetimeauth_state));

	enc_ctx = rspamd_cryptobox_encrypt_init(enc_ctx, nonce, nm);
	auth_ctx = rspamd_cryptobox_auth_init(auth_ctx, enc_ctx);

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
												outbuf, NULL);
				rspamd_cryptobox_auth_update(auth_ctx, outbuf, sizeof(outbuf));
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
											outbuf, NULL);
			rspamd_cryptobox_auth_update(auth_ctx, outbuf, sizeof(outbuf));
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
													NULL);
					rspamd_cryptobox_auth_update(auth_ctx,
												 outbuf,
												 sizeof(outbuf));
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
									outbuf, &r);
	out = outbuf + r;
	rspamd_cryptobox_encrypt_final(enc_ctx, out, sizeof(outbuf) - remain - r);

	rspamd_cryptobox_auth_update(auth_ctx, outbuf, sizeof(outbuf) - remain);
	rspamd_cryptobox_auth_final(auth_ctx, sig);

	rspamd_cryptobox_flush_outbuf(start_seg, outbuf, sizeof(outbuf) - remain,
								  seg_offset);
	rspamd_cryptobox_cleanup(enc_ctx, auth_ctx);
}

gboolean
rspamd_cryptobox_decrypt_nm_inplace(unsigned char *data, gsize len,
									const rspamd_nonce_t nonce, const rspamd_nm_t nm,
									const rspamd_mac_t sig)
{
	gsize r = 0;
	gboolean ret = TRUE;
	void *enc_ctx, *auth_ctx;

	enc_ctx = g_alloca(sizeof(chacha_state) + CRYPTOBOX_ALIGNMENT);
	auth_ctx = g_alloca(sizeof(crypto_onetimeauth_state) + RSPAMD_ALIGNOF(crypto_onetimeauth_state));

	enc_ctx = rspamd_cryptobox_decrypt_init(enc_ctx, nonce, nm);
	auth_ctx = rspamd_cryptobox_auth_verify_init(auth_ctx, enc_ctx);

	rspamd_cryptobox_auth_verify_update(auth_ctx, data, len);

	if (!rspamd_cryptobox_auth_verify_final(auth_ctx, sig)) {
		ret = FALSE;
	}
	else {
		rspamd_cryptobox_decrypt_update(enc_ctx, data, len, data, &r);
		ret = rspamd_cryptobox_decrypt_final(enc_ctx, data + r, len - r);
	}

	rspamd_cryptobox_cleanup(enc_ctx, auth_ctx);

	return ret;
}

gboolean
rspamd_cryptobox_decrypt_inplace(unsigned char *data, gsize len,
								 const rspamd_nonce_t nonce,
								 const rspamd_pk_t pk, const rspamd_sk_t sk,
								 const rspamd_mac_t sig)
{
	unsigned char nm[rspamd_cryptobox_MAX_NMBYTES];
	gboolean ret;

	rspamd_cryptobox_nm(nm, pk, sk);
	ret = rspamd_cryptobox_decrypt_nm_inplace(data, len, nonce, nm, sig);

	rspamd_explicit_memzero(nm, sizeof(nm));

	return ret;
}

void rspamd_cryptobox_encrypt_inplace(unsigned char *data, gsize len,
									  const rspamd_nonce_t nonce,
									  const rspamd_pk_t pk, const rspamd_sk_t sk,
									  rspamd_mac_t sig)
{
	unsigned char nm[rspamd_cryptobox_MAX_NMBYTES];

	rspamd_cryptobox_nm(nm, pk, sk);
	rspamd_cryptobox_encrypt_nm_inplace(data, len, nonce, nm, sig);
	rspamd_explicit_memzero(nm, sizeof(nm));
}

void rspamd_cryptobox_encryptv_inplace(struct rspamd_cryptobox_segment *segments,
									   gsize cnt,
									   const rspamd_nonce_t nonce,
									   const rspamd_pk_t pk, const rspamd_sk_t sk,
									   rspamd_mac_t sig)
{
	unsigned char nm[rspamd_cryptobox_MAX_NMBYTES];

	rspamd_cryptobox_nm(nm, pk, sk);
	rspamd_cryptobox_encryptv_nm_inplace(segments, cnt, nonce, nm, sig);
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
