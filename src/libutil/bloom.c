/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
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
#include "bloom.h"
#include "xxhash.h"

/* 4 bits are used for counting (implementing delete operation) */
#define SIZE_BIT 4

/* These macroes are for 4 bits for counting element */
#define INCBIT(a, n, acc) do {                                                              \
		acc = \
			a[n * SIZE_BIT / CHAR_BIT] & (0xF << \
			(n % (CHAR_BIT / SIZE_BIT) * SIZE_BIT));     \
		acc ++;                                                                                 \
		acc &= 0xF;                                                                             \
                                                                                            \
		a[n * SIZE_BIT / \
		CHAR_BIT] &= (0xF << (4 - (n % (CHAR_BIT / SIZE_BIT) * SIZE_BIT)));      \
		a[n * SIZE_BIT / \
		CHAR_BIT] |= (acc << (n % (CHAR_BIT / SIZE_BIT) * SIZE_BIT));            \
} while (0);

#define DECBIT(a, n, acc) do {                                                              \
		acc = \
			a[n * SIZE_BIT / CHAR_BIT] & (0xF << \
			(n % (CHAR_BIT / SIZE_BIT) * SIZE_BIT));     \
		acc --;                                                                                 \
		acc &= 0xF;                                                                             \
                                                                                            \
		a[n * SIZE_BIT / \
		CHAR_BIT] &= (0xF << (4 - (n % (CHAR_BIT / SIZE_BIT) * SIZE_BIT)));      \
		a[n * SIZE_BIT / \
		CHAR_BIT] |= (acc << (n % (CHAR_BIT / SIZE_BIT) * SIZE_BIT));            \
} while (0);

#define GETBIT(a, \
		n) (a[n * SIZE_BIT / CHAR_BIT] & (0xF << \
	(n % (CHAR_BIT / SIZE_BIT) * SIZE_BIT)))

/* Common hash functions */


rspamd_bloom_filter_t *
rspamd_bloom_create (size_t size, size_t nfuncs, ...)
{
	rspamd_bloom_filter_t *bloom;
	va_list l;
	gsize n;

	if (!(bloom = g_malloc (sizeof (rspamd_bloom_filter_t)))) {
		return NULL;
	}
	if (!(bloom->a =
		g_new0 (gchar, (size + CHAR_BIT - 1) / CHAR_BIT * SIZE_BIT))) {
		g_free (bloom);
		return NULL;
	}
	if (!(bloom->seeds = g_new0 (guint32, nfuncs))) {
		g_free (bloom->a);
		g_free (bloom);
		return NULL;
	}

	va_start (l, nfuncs);
	for (n = 0; n < nfuncs; ++n) {
		bloom->seeds[n] = va_arg (l, guint32);
	}
	va_end (l);

	bloom->nfuncs = nfuncs;
	bloom->asize = size;

	return bloom;
}

void
rspamd_bloom_destroy (rspamd_bloom_filter_t * bloom)
{
	g_free (bloom->a);
	g_free (bloom->seeds);
	g_free (bloom);
}

gboolean
rspamd_bloom_add (rspamd_bloom_filter_t * bloom, const gchar *s)
{
	size_t n, len;
	u_char t;
	guint v;

	if (s == NULL) {
		return FALSE;
	}
	len = strlen (s);
	for (n = 0; n < bloom->nfuncs; ++n) {
		v = XXH64 (s, len, bloom->seeds[n]) % bloom->asize;
		INCBIT (bloom->a, v, t);
	}

	return TRUE;
}

gboolean
rspamd_bloom_del (rspamd_bloom_filter_t * bloom, const gchar *s)
{
	size_t n, len;
	u_char t;
	guint v;

	if (s == NULL) {
		return FALSE;
	}
	len = strlen (s);
	for (n = 0; n < bloom->nfuncs; ++n) {
		v = XXH32 (s, len, bloom->seeds[n]) % bloom->asize;
		DECBIT (bloom->a, v, t);
	}

	return TRUE;

}

gboolean
rspamd_bloom_check (rspamd_bloom_filter_t * bloom, const gchar *s)
{
	size_t n, len;
	guint v;

	if (s == NULL) {
		return FALSE;
	}
	len = strlen (s);
	for (n = 0; n < bloom->nfuncs; ++n) {
		v = XXH32 (s, len, bloom->seeds[n]) % bloom->asize;
		if (!(GETBIT (bloom->a, v))) {
			return FALSE;
		}
	}

	return TRUE;
}
