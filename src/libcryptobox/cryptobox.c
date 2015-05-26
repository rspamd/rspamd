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


#ifndef ALIGNED
#if defined(_MSC_VER)
# define ALIGNED(x) __declspec(align(x))
#else
# define ALIGNED(x) __attribute__((aligned(x)))
#endif
#endif

unsigned long cpu_config = 0;

static const guchar n0[16] = {0};

#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
_dummy_symbol_to_prevent_lto(void * const pnt, const size_t len)
{
	(void) pnt;
	(void) len;
}
#endif

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
				cpu_config |= CPUID_SSE2;
			}
			if ((cpu[2] & ((gint)1 << 28))) {
				cpu_config |= CPUID_AVX;
			}
			if ((cpu[2] & ((gint)1 << 0))) {
				cpu_config |= CPUID_SSE3;
			}
			if ((cpu[2] & ((gint)1 << 9))) {
				cpu_config |= CPUID_SSSE3;
			}
			if ((cpu[2] & ((gint)1 << 19))) {
				cpu_config |= CPUID_SSE41;
			}

			if (nid > 7) {
				rspamd_cryptobox_cpuid (cpu, 7);
				if ((cpu[1] & ((gint)1 <<  5))) {
					cpu_config |= CPUID_AVX2;
				}
			}
		}
	}


	chacha_load ();
	poly1305_load ();
	siphash_load ();
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

void rspamd_cryptobox_encrypt_nm_inplace (guchar *data, gsize len,
		const rspamd_nonce_t nonce,
		const rspamd_nm_t nm, rspamd_sig_t sig)
{
	poly1305_state mac_ctx;
	guchar ALIGNED(32) subkey[CHACHA_BLOCKBYTES];
	chacha_state s;
	gsize r;

	xchacha_init (&s, (const chacha_key *)nm, (const chacha_iv24 *)nonce, 20);
	memset (subkey, 0, sizeof (subkey));
	chacha_update (&s, subkey, subkey, sizeof (subkey));

	r = chacha_update (&s, data, data, len);
	chacha_final (&s, data + r);

	poly1305_init (&mac_ctx, (const poly1305_key *)subkey);
	poly1305_update (&mac_ctx, data, len);
	poly1305_finish (&mac_ctx, sig);

	rspamd_explicit_memzero (&mac_ctx, sizeof (mac_ctx));
	rspamd_explicit_memzero (subkey, sizeof (subkey));
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

void rspamd_cryptobox_encryptv_nm_inplace (struct rspamd_cryptobox_segment *segments,
		gsize cnt,
		const rspamd_nonce_t nonce,
		const rspamd_nm_t nm, rspamd_sig_t sig)
{
	struct rspamd_cryptobox_segment *cur = segments, *start_seg = segments;
	guchar ALIGNED(32) subkey[CHACHA_BLOCKBYTES],
		outbuf[CHACHA_BLOCKBYTES * 16];
	poly1305_state mac_ctx;
	guchar *out, *in;
	chacha_state s;
	gsize r, remain, inremain, seg_offset;

	xchacha_init (&s, (const chacha_key *)nm, (const chacha_iv24 *)nonce, 20);
	memset (subkey, 0, sizeof (subkey));
	chacha_update (&s, subkey, subkey, sizeof (subkey));
	poly1305_init (&mac_ctx, (const poly1305_key *)subkey);

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
				chacha_update (&s, outbuf, outbuf, sizeof (outbuf));
				poly1305_update (&mac_ctx, outbuf, sizeof (outbuf));
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
			chacha_update (&s, outbuf, outbuf, sizeof (outbuf));
			poly1305_update (&mac_ctx, outbuf, sizeof (outbuf));
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
					chacha_update (&s, outbuf, outbuf, sizeof (outbuf));
					poly1305_update (&mac_ctx, outbuf, sizeof (outbuf));
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

	r = chacha_update (&s, outbuf, outbuf, sizeof (outbuf) - remain);
	out = outbuf + r;
	chacha_final (&s, out);
	poly1305_update (&mac_ctx, outbuf, sizeof (outbuf) - remain);
	poly1305_finish (&mac_ctx, sig);

	rspamd_cryptobox_flush_outbuf (start_seg, outbuf, sizeof (outbuf) - remain,
			seg_offset);
	rspamd_explicit_memzero (&mac_ctx, sizeof (mac_ctx));
	rspamd_explicit_memzero (subkey, sizeof (subkey));
}

gboolean
rspamd_cryptobox_decrypt_nm_inplace (guchar *data, gsize len,
		const rspamd_nonce_t nonce, const rspamd_nm_t nm, const rspamd_sig_t sig)
{
	poly1305_state mac_ctx;
	guchar ALIGNED(32) subkey[CHACHA_BLOCKBYTES];
	rspamd_sig_t mac;
	chacha_state s;
	gsize r;
	gboolean ret = TRUE;

	/* Generate MAC key */
	xchacha_init (&s, (const chacha_key *)nm, (const chacha_iv24 *)nonce, 20);
	memset (subkey, 0, sizeof (subkey));
	chacha_update (&s, subkey, subkey, sizeof (subkey));

	poly1305_init (&mac_ctx, (const poly1305_key *)subkey);
	poly1305_update (&mac_ctx, data, len);
	poly1305_finish (&mac_ctx, mac);

	if (!poly1305_verify (mac, sig)) {
		ret = FALSE;
	}
	else {
		r = chacha_update (&s, data, data, len);
		chacha_final (&s, data + r);
	}

	rspamd_explicit_memzero (&mac_ctx, sizeof (mac_ctx));
	rspamd_explicit_memzero (subkey, sizeof (subkey));

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
rspamd_cryptobox_pbkdf(const char *pass, gsize pass_len,
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
