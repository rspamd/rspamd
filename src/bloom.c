/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "bloom.h"

/* 4 bits are used for counting (implementing delete operation) */
#define SIZE_BIT 4

/* These macroes are for 4 bits for counting element */
#define INCBIT(a, n, acc) do {																\
	acc = a[n * SIZE_BIT / CHAR_BIT] & (0xF << (n % (CHAR_BIT / SIZE_BIT) * SIZE_BIT));		\
	acc ++;																					\
	acc &= 0xF;																				\
																							\
	a[n * SIZE_BIT / CHAR_BIT] &= (0xF << (4 - (n % (CHAR_BIT/SIZE_BIT) * SIZE_BIT)));		\
	a[n * SIZE_BIT / CHAR_BIT] |= (acc << (n % (CHAR_BIT/SIZE_BIT) * SIZE_BIT));			\
} while (0);

#define DECBIT(a, n, acc) do {																\
	acc = a[n * SIZE_BIT / CHAR_BIT] & (0xF << (n % (CHAR_BIT / SIZE_BIT) * SIZE_BIT));		\
	acc --;																					\
	acc &= 0xF;																				\
																							\
	a[n * SIZE_BIT / CHAR_BIT] &= (0xF << (4 - (n % (CHAR_BIT/SIZE_BIT) * SIZE_BIT)));		\
	a[n * SIZE_BIT / CHAR_BIT] |= (acc << (n % (CHAR_BIT/SIZE_BIT) * SIZE_BIT));			\
} while (0);

#define GETBIT(a, n) (a[n * SIZE_BIT / CHAR_BIT] & (0xF << (n % (CHAR_BIT/SIZE_BIT) * SIZE_BIT)))

/* Common hash functions */
guint
bloom_sax_hash (const gchar *key)
{
	guint                           h = 0;

	while (*key)
		h ^= (h << 5) + (h >> 2) + (gchar)*key++;

	return h;
}

guint
bloom_sdbm_hash (const gchar *key)
{
	guint                           h = 0;

	while (*key)
		h = (gchar)*key++ + (h << 6) + (h << 16) - h;

	return h;
}

guint
bloom_fnv_hash (const gchar *key)
{
	guint                           h = 0;

	while (*key) {
		h ^= (gchar)*key++;
		h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
	}

	return h;
}

guint
bloom_rs_hash (const gchar *key)
{
	guint                           b = 378551;
	guint                           a = 63689;
	guint                           hash = 0;

	while (*key) {
		hash = hash * a + (gchar)*key++;
		a = a * b;
	}

	return hash;
}

guint
bloom_js_hash (const gchar *key)
{
	guint                           hash = 1315423911;

	while (*key) {
		hash ^= ((hash << 5) + (gchar)*key++ + (hash >> 2));
	}

	return hash;
}


guint
bloom_elf_hash (const gchar *key)
{
	guint                           hash = 0;
	guint                           x = 0;

	while (*key) {
		hash = (hash << 4) + (gchar)*key++;
		if ((x = hash & 0xF0000000L) != 0) {
			hash ^= (x >> 24);
		}
		hash &= ~x;
	}

	return hash;
}


guint
bloom_bkdr_hash (const gchar *key)
{
	guint                           seed = 131;	/* 31 131 1313 13131 131313 etc.. */
	guint                           hash = 0;

	while (*key) {
		hash = (hash * seed) + (gchar)*key++;
	}

	return hash;
}


guint
bloom_ap_hash (const gchar *key)
{
	guint                           hash = 0xAAAAAAAA;
	guint                           i = 0;

	while (*key) {
		hash ^= ((i & 1) == 0) ? ((hash << 7) ^ ((gchar)*key) * (hash >> 3)) : (~((hash << 11) + (((gchar)*key) ^ (hash >> 5))));
		key++;
	}

	return hash;
}

bloom_filter_t                 *
bloom_create (size_t size, size_t nfuncs, ...)
{
	bloom_filter_t                 *bloom;
	va_list                         l;
	gsize                           n;

	if (!(bloom = g_malloc (sizeof (bloom_filter_t)))) {
		return NULL;
	}
	if (!(bloom->a = g_new0 (gchar,  (size + CHAR_BIT - 1) / CHAR_BIT * SIZE_BIT))) {
		g_free (bloom);
		return NULL;
	}
	if (!(bloom->funcs = (hashfunc_t *) g_malloc (nfuncs * sizeof (hashfunc_t)))) {
		g_free (bloom->a);
		g_free (bloom);
		return NULL;
	}

	va_start (l, nfuncs);
	for (n = 0; n < nfuncs; ++n) {
		bloom->funcs[n] = va_arg (l, hashfunc_t);
	}
	va_end (l);

	bloom->nfuncs = nfuncs;
	bloom->asize = size;

	return bloom;
}

void
bloom_destroy (bloom_filter_t * bloom)
{
	g_free (bloom->a);
	g_free (bloom->funcs);
	g_free (bloom);
}

gboolean
bloom_add (bloom_filter_t * bloom, const gchar *s)
{
	size_t                          n;
	u_char                          t;

	for (n = 0; n < bloom->nfuncs; ++n) {
		INCBIT (bloom->a, bloom->funcs[n] (s) % bloom->asize, t);
	}

	return TRUE;
}

gboolean
bloom_del (bloom_filter_t * bloom, const gchar *s)
{
	size_t                          n;
	u_char                          t;

	for (n = 0; n < bloom->nfuncs; ++n) {
		DECBIT (bloom->a, bloom->funcs[n] (s) % bloom->asize, t);
	}

	return TRUE;

}

gboolean
bloom_check (bloom_filter_t * bloom, const gchar *s)
{
	size_t                          n;

	for (n = 0; n < bloom->nfuncs; ++n) {
		if (!(GETBIT (bloom->a, bloom->funcs[n] (s) % bloom->asize)))
			return FALSE;
	}

	return TRUE;
}
