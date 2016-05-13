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
#include "bloom.h"
#include "cryptobox.h"

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
		v = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
				s, len, bloom->seeds[n]) % bloom->asize;
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
		v = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
				s, len, bloom->seeds[n]) % bloom->asize;
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
		v = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
				s, len, bloom->seeds[n]) % bloom->asize;
		if (!(GETBIT (bloom->a, v))) {
			return FALSE;
		}
	}

	return TRUE;
}
