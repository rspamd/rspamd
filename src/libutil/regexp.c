/*
 * Copyright (c) 2015, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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
#include "regexp.h"
#include "blake2.h"
#include "ref.h"
#include <pcre.h>

typedef guchar regexp_id_t[BLAKE2B_OUTBYTES];

struct rspamd_regexp_s {
	gdouble exec_time;
	pcre *re;
	pcre_extra *extra;
	pcre *raw_re;
	pcre_extra *raw_extra;
	regexp_id_t id;
	ref_entry_t ref;
};

struct rspamd_regexp_cache {
	GHashTable *tbl;
};

static struct rspamd_regexp_cache *global_re_cache = NULL;

static void
rspamd_regexp_generate_id (const gchar *pattern, const gchar *flags,
		regexp_id_t out)
{
	blake2b_state st;

	blake2b_init (&st, sizeof (regexp_id_t));
	blake2b_update (&st, flags, strlen (flags));
	blake2b_update (&st, pattern, strlen (pattern));
	blake2b_final (&st, out, sizeof (regexp_id_t));
}

rspamd_regexp_t*
rspamd_regexp_new (const gchar *pattern, const gchar *flags,
		GError **err)
{
	return NULL;
}

gboolean
rspamd_regexp_search (rspamd_regexp_t *re, const gchar *text, gsize len)
{
	return FALSE;
}

gboolean
rspamd_regexp_match (rspamd_regexp_t *re, const gchar *text, gsize len)
{
	return FALSE;
}

void
rspamd_regexp_unref (rspamd_regexp_t *re)
{
	REF_RELEASE (re);
}

static gboolean
rspamd_regexp_equal (gconstpointer a, gconstpointer b)
{
	const guchar *ia = a, *ib = b;

	return (memcmp (ia, ib, sizeof (regexp_id_t)) == 0);
}

static guint32
rspamd_regexp_hash (gconstpointer a)
{
	const guchar *ia = a;
	guint32 res;

	memcpy (&res, ia, sizeof (res));

	return res;
}

struct rspamd_regexp_cache*
rspamd_regexp_cache_new (void)
{
	struct rspamd_regexp_cache *ncache;

	ncache = g_slice_alloc (sizeof (*ncache));
	ncache->tbl = g_hash_table_new_full (rspamd_regexp_hash, rspamd_regexp_equal,
			NULL, (GDestroyNotify)rspamd_regexp_unref);

	return ncache;
}


rspamd_regexp_t*
rspamd_regexp_cache_query (struct rspamd_regexp_cache* cache,
		const gchar *pattern,
		const gchar *flags)
{
	rspamd_regexp_t *res = NULL;
	regexp_id_t id;

	if (cache == NULL) {
		cache = global_re_cache;
	}

	g_assert (cache != NULL);
	rspamd_regexp_generate_id (pattern, flags, id);

	res = g_hash_table_lookup (cache->tbl, id);

	return res;
}


rspamd_regexp_t*
rspamd_regexp_cache_create (struct rspamd_regexp_cache *cache,
		const gchar *pattern,
		const gchar *flags, GError **err)
{
	rspamd_regexp_t *res;

	if (cache == NULL) {
		cache = global_re_cache;
	}

	g_assert (cache != NULL);
	res = rspamd_regexp_cache_query (cache, pattern, flags);

	if (res != NULL) {
		return res;
	}

	res = rspamd_regexp_new (pattern, flags, err);

	if (res) {
		g_hash_table_insert (cache->tbl, res->id, res);
	}

	return res;
}

void
rspamd_regexp_cache_destroy (struct rspamd_regexp_cache *cache)
{
	if (cache != NULL) {
		g_hash_table_destroy (cache->tbl);
	}
}

void
rspamd_regexp_library_init (void)
{
	if (global_re_cache == NULL) {
		global_re_cache = rspamd_regexp_cache_new ();
	}
}

void
rspamd_regexp_library_finalize (void)
{
	if (global_re_cache != NULL) {
		rspamd_regexp_cache_destroy (global_re_cache);
	}
}
