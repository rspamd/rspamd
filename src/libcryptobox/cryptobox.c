/* Copyright (c) 2015, Vsevolod Stakhov
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
#include "siphash/siphash.h"
#include "ottery.h"
#include "blake2.h"
#ifdef HAVE_CPUID_H
#include <cpuid.h>
#endif
#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#include <signal.h>
#include <setjmp.h>

unsigned long cpu_config = 0;

static gboolean use_openssl = FALSE;

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
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
# if defined(HAVE_GET_CPUID)
	__get_cpuid (info, &cpu[0], &cpu[1], &cpu[2], &cpu[3]);
# else
	__asm ("cpuid" : "=a"(cpu[0]), "=b" (cpu[1]), "=c"(cpu[2]), "=d"(cpu[3])
			: "0"(info));
# endif
#else
	memset (cpu, 0, sizeof (cpu));
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
		break;
	}

	signal (SIGILL, old_handler);
#endif

	/* We actually never return here if SIGILL has been caught */
	return ok == 1;
}

void
rspamd_cryptobox_init (void)
{
	gint cpu[4], nid;

	rspamd_cryptobox_cpuid (cpu, 0);
	nid = cpu[0];
	rspamd_cryptobox_cpuid (cpu, 1);

	if (nid > 1) {
		/* Check OSXSAVE bit first of all */
		if ((cpu[2] & ((gint)1 << 9))) {
			if ((cpu[3] & ((gint)1 << 26))) {
				if (rspamd_cryptobox_test_instr (CPUID_SSE2)) {
					cpu_config |= CPUID_SSE2;
				}
			}
			if ((cpu[2] & ((gint)1 << 28))) {
				if (rspamd_cryptobox_test_instr (CPUID_AVX)) {
					cpu_config |= CPUID_AVX;
				}
			}
			if ((cpu[2] & ((gint)1 << 0))) {
				if (rspamd_cryptobox_test_instr (CPUID_SSE3)) {
					cpu_config |= CPUID_SSE3;
				}
			}
			if ((cpu[2] & ((gint)1 << 9))) {
				if (rspamd_cryptobox_test_instr (CPUID_SSSE3)) {
					cpu_config |= CPUID_SSSE3;
				}
			}
			if ((cpu[2] & ((gint)1 << 19))) {
				if (rspamd_cryptobox_test_instr (CPUID_SSE41)) {
					cpu_config |= CPUID_SSE41;
				}
			}

			if (nid > 7) {
				rspamd_cryptobox_cpuid (cpu, 7);

				if ((cpu[1] & ((gint) 1 << 5))) {
					if (rspamd_cryptobox_test_instr (CPUID_AVX2)) {
						cpu_config |= CPUID_AVX2;
					}
				}
			}
		}
	}


	chacha_load ();
	poly1305_load ();
	siphash_load ();
	curve25519_load ();
}

void
rspamd_cryptobox_keypair (rspamd_pk_t pk, rspamd_sk_t sk)
{
	ottery_rand_bytes (sk, rspamd_cryptobox_SKBYTES);
	sk[0] &= 248;
	sk[31] &= 127;
	sk[31] |= 64;

	curve25519 (pk, sk, curve25519_basepoint);
}

void
rspamd_cryptobox_nm (rspamd_nm_t nm, const rspamd_pk_t pk, const rspamd_sk_t sk)
{
	guchar s[rspamd_cryptobox_PKBYTES];
	guchar e[rspamd_cryptobox_SKBYTES];

	memcpy (e, sk, rspamd_cryptobox_SKBYTES);
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;

	curve25519 (s, e, pk);
	hchacha (s, n0, nm, 20);

	rspamd_explicit_memzero (e, rspamd_cryptobox_SKBYTES);
}

static gsize
rspamd_cryptobox_encrypt_ctx_len (void)
{
	return sizeof (chacha_state) + CRYPTOBOX_ALIGNMENT;
}

static gsize
rspamd_cryptobox_auth_ctx_len (void)
{
	return sizeof (poly1305_state) + CRYPTOBOX_ALIGNMENT;
}

static void *
rspamd_cryptobox_encrypt_init (void *enc_ctx, const rspamd_nonce_t nonce,
		const rspamd_nm_t nm)
{
	chacha_state *s;

	s = cryptobox_align_ptr (enc_ctx, CRYPTOBOX_ALIGNMENT);
	xchacha_init (s, (const chacha_key *) nm, (const chacha_iv24 *) nonce, 20);

	return s;
}

static void *
rspamd_cryptobox_auth_init (void *auth_ctx, void *enc_ctx)
{
	poly1305_state *mac_ctx;
	guchar RSPAMD_ALIGNED(32) subkey[CHACHA_BLOCKBYTES];

	mac_ctx = cryptobox_align_ptr (auth_ctx, CRYPTOBOX_ALIGNMENT);
	memset (subkey, 0, sizeof (subkey));
	chacha_update (enc_ctx, subkey, subkey, sizeof (subkey));
	poly1305_init (mac_ctx, (const poly1305_key *) subkey);
	rspamd_explicit_memzero (subkey, sizeof (subkey));

	return mac_ctx;
}

static gboolean
rspamd_cryptobox_encrypt_update (void *enc_ctx, const guchar *in, gsize inlen,
		guchar *out, gsize *outlen)
{
	gsize r;

	r = chacha_update (enc_ctx, in, out, inlen);

	if (outlen != NULL) {
		*outlen = r;
	}

	return TRUE;
}

static gboolean
rspamd_cryptobox_auth_update (void *auth_ctx, const guchar *in, gsize inlen)
{
	poly1305_update (auth_ctx, in, inlen);

	return TRUE;
}

static gsize
rspamd_cryptobox_encrypt_final (void *enc_ctx, guchar *out)
{
	return chacha_final (enc_ctx, out);
}

static gboolean
rspamd_cryptobox_auth_final (void *auth_ctx, rspamd_sig_t sig)
{
	poly1305_finish (auth_ctx, sig);

	return TRUE;
}

static void *
rspamd_cryptobox_decrypt_init (void *enc_ctx, const rspamd_nonce_t nonce,
		const rspamd_nm_t nm)
{
	chacha_state *s;

	s = cryptobox_align_ptr (enc_ctx, CRYPTOBOX_ALIGNMENT);
	xchacha_init (s, (const chacha_key *) nm, (const chacha_iv24 *) nonce, 20);

	return s;
}

static void *
rspamd_cryptobox_auth_verify_init (void *auth_ctx, void *enc_ctx)
{
	poly1305_state *mac_ctx;
	guchar RSPAMD_ALIGNED(32) subkey[CHACHA_BLOCKBYTES];

	mac_ctx = cryptobox_align_ptr (auth_ctx, CRYPTOBOX_ALIGNMENT);
	memset (subkey, 0, sizeof (subkey));
	chacha_update (enc_ctx, subkey, subkey, sizeof (subkey));
	poly1305_init (mac_ctx, (const poly1305_key *) subkey);
	rspamd_explicit_memzero (subkey, sizeof (subkey));

	return mac_ctx;
}

static gboolean
rspamd_cryptobox_decrypt_update (void *enc_ctx, const guchar *in, gsize inlen,
		guchar *out, gsize *outlen)
{
	gsize r;

	r = chacha_update (enc_ctx, in, out, inlen);

	if (outlen != NULL) {
		*outlen = r;
	}

	return TRUE;
}

static gboolean
rspamd_cryptobox_auth_verify_update (void *auth_ctx, const guchar *in, gsize inlen)
{
	poly1305_update (auth_ctx, in, inlen);

	return TRUE;
}

static gsize
rspamd_cryptobox_decrypt_final (void *enc_ctx, guchar *out)
{
	return chacha_final (enc_ctx, out);
}

static gboolean
rspamd_cryptobox_auth_verify_final (void *auth_ctx, const rspamd_sig_t sig)
{
	rspamd_sig_t mac;

	poly1305_finish (auth_ctx, mac);

	if (!poly1305_verify (mac, sig)) {
		return FALSE;
	}

	return TRUE;
}


static void
rspamd_cryptobox_cleanup (void *enc_ctx, void *auth_ctx)
{
	rspamd_explicit_memzero (auth_ctx, sizeof (poly1305_state));
}

void rspamd_cryptobox_encrypt_nm_inplace (guchar *data, gsize len,
		const rspamd_nonce_t nonce,
		const rspamd_nm_t nm,
		rspamd_sig_t sig)
{
	gsize r;
	void *enc_ctx, *auth_ctx;

	enc_ctx = g_alloca (rspamd_cryptobox_encrypt_ctx_len ());
	auth_ctx = g_alloca (rspamd_cryptobox_auth_ctx_len ());

	enc_ctx = rspamd_cryptobox_encrypt_init (enc_ctx, nonce, nm);
	auth_ctx = rspamd_cryptobox_auth_init (auth_ctx, enc_ctx);

	rspamd_cryptobox_encrypt_update (enc_ctx, data, len, data, &r);
	rspamd_cryptobox_encrypt_final (enc_ctx, data + r);

	rspamd_cryptobox_auth_update (auth_ctx, data, len);
	rspamd_cryptobox_auth_final (auth_ctx, sig);

	rspamd_cryptobox_cleanup (enc_ctx, auth_ctx);
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
		const rspamd_nm_t nm, rspamd_sig_t sig)
{
	struct rspamd_cryptobox_segment *cur = segments, *start_seg = segments;
	guchar outbuf[CHACHA_BLOCKBYTES * 16];
	void *enc_ctx, *auth_ctx;
	guchar *out, *in;
	gsize r, remain, inremain, seg_offset;

	enc_ctx = g_alloca (rspamd_cryptobox_encrypt_ctx_len ());
	auth_ctx = g_alloca (rspamd_cryptobox_auth_ctx_len ());

	enc_ctx = rspamd_cryptobox_encrypt_init (enc_ctx, nonce, nm);
	auth_ctx = rspamd_cryptobox_auth_init (auth_ctx, enc_ctx);

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
						outbuf, NULL);
				rspamd_cryptobox_auth_update (auth_ctx, outbuf, sizeof (outbuf));
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
					outbuf, NULL);
			rspamd_cryptobox_auth_update (auth_ctx, outbuf, sizeof (outbuf));
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
							NULL);
					rspamd_cryptobox_auth_update (auth_ctx,
							outbuf,
							sizeof (outbuf));
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
			outbuf, &r);
	out = outbuf + r;
	rspamd_cryptobox_encrypt_final (enc_ctx, out);

	rspamd_cryptobox_auth_update (auth_ctx, outbuf, sizeof (outbuf) - remain);
	rspamd_cryptobox_auth_final (auth_ctx, sig);

	rspamd_cryptobox_flush_outbuf (start_seg, outbuf, sizeof (outbuf) - remain,
			seg_offset);
	rspamd_cryptobox_cleanup (auth_ctx, enc_ctx);
}

gboolean
rspamd_cryptobox_decrypt_nm_inplace (guchar *data, gsize len,
		const rspamd_nonce_t nonce, const rspamd_nm_t nm, const rspamd_sig_t sig)
{
	gsize r;
	gboolean ret = TRUE;
	void *enc_ctx, *auth_ctx;

	enc_ctx = g_alloca (rspamd_cryptobox_encrypt_ctx_len ());
	auth_ctx = g_alloca (rspamd_cryptobox_auth_ctx_len ());

	enc_ctx = rspamd_cryptobox_decrypt_init (enc_ctx, nonce, nm);
	auth_ctx = rspamd_cryptobox_auth_verify_init (auth_ctx, enc_ctx);

	rspamd_cryptobox_auth_verify_update (auth_ctx, data, len);

	if (!rspamd_cryptobox_auth_verify_final (auth_ctx, sig)) {
		ret = FALSE;
	}
	else {
		rspamd_cryptobox_decrypt_update (enc_ctx, data, len, data, &r);
		rspamd_cryptobox_decrypt_final (enc_ctx, data + r);
	}

	rspamd_cryptobox_cleanup (enc_ctx, auth_ctx);

	return ret;
}

gboolean
rspamd_cryptobox_decrypt_inplace (guchar *data, gsize len,
		const rspamd_nonce_t nonce,
		const rspamd_pk_t pk, const rspamd_sk_t sk, const rspamd_sig_t sig)
{
	guchar nm[rspamd_cryptobox_NMBYTES];
	gboolean ret;

	rspamd_cryptobox_nm (nm, pk, sk);
	ret = rspamd_cryptobox_decrypt_nm_inplace (data, len, nonce, nm, sig);

	rspamd_explicit_memzero (nm, sizeof (nm));

	return ret;
}

void
rspamd_cryptobox_encrypt_inplace (guchar *data, gsize len,
		const rspamd_nonce_t nonce,
		const rspamd_pk_t pk, const rspamd_sk_t sk, rspamd_sig_t sig)
{
	guchar nm[rspamd_cryptobox_NMBYTES];

	rspamd_cryptobox_nm (nm, pk, sk);
	rspamd_cryptobox_encrypt_nm_inplace (data, len, nonce, nm, sig);
	rspamd_explicit_memzero (nm, sizeof (nm));
}

void
rspamd_cryptobox_encryptv_inplace (struct rspamd_cryptobox_segment *segments,
		gsize cnt,
		const rspamd_nonce_t nonce,
		const rspamd_pk_t pk, const rspamd_sk_t sk, rspamd_sig_t sig)
{
	guchar nm[rspamd_cryptobox_NMBYTES];

	rspamd_cryptobox_nm (nm, pk, sk);
	rspamd_cryptobox_encryptv_nm_inplace (segments, cnt, nonce, nm, sig);
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
gboolean
rspamd_cryptobox_pbkdf (const char *pass, gsize pass_len,
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
		blake2b (d1, asalt, pass, BLAKE2B_OUTBYTES, salt_len + 4, pass_len);
		memcpy (obuf, d1, sizeof(obuf));

		for (i = 1; i < rounds; i++) {
			blake2b (d2, d1, pass, BLAKE2B_OUTBYTES, BLAKE2B_OUTBYTES,
					pass_len);
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

void
rspamd_cryptobox_openssl_mode (gboolean enable)
{
	use_openssl = enable;
}
