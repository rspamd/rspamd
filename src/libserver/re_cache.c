/*
 * Copyright (c) 2015, Vsevolod Stakhov
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

#include "re_cache.h"
#include "xxhash.h"
#include "cryptobox.h"
#include "ref.h"

struct rspamd_re_class {
	guint64 id;
	enum rspamd_re_type type;
	gpointer type_data;
	gsize type_len;
	GHashTable *re_ids;
	GPtrArray *all_re;
	gchar hash[rspamd_cryptobox_HASHBYTES * 2 + 1];
};

struct rspamd_re_cache {
	GHashTable *re_classes;
	ref_entry_t ref;
	guint nre;
};

struct rspamd_re_runtime {
	guchar *checked;
	guchar *results;
	struct rspamd_re_cache *cache;
};

static guint64
rspamd_re_cache_class_id (enum rspamd_re_type type,
		gpointer type_data,
		gsize datalen)
{
	XXH64_state_t st;

	XXH64_reset (&st, rspamd_hash_seed ());
	XXH64_update (&st, &type, sizeof (type));

	if (datalen > 0) {
		XXH64_update (&st, type_data, datalen);
	}

	return XXH64_digest (&st);
}

struct rspamd_re_cache *
rspamd_re_cache_new (void)
{
	struct rspamd_re_cache *cache;

	cache = g_slice_alloc (sizeof (*cache));
	cache->re_classes = g_hash_table_new (g_int64_hash, g_int64_equal);
	cache->nre = 0;
	REF_INIT_RETAIN (cache, rspamd_re_cache_destroy);

	return cache;
}

void
rspamd_re_cache_add (struct rspamd_re_cache *cache, rspamd_regexp_t *re,
		enum rspamd_re_type type, gpointer type_data, gsize datalen)
{
	guint64 class_id;
	struct rspamd_re_class *re_class;

	g_assert (cache != NULL);
	g_assert (re != NULL);

	class_id = rspamd_re_cache_class_id (type, type_data, datalen);
	re_class = g_hash_table_lookup (cache->re_classes, &class_id);

	if (re_class == NULL) {
		re_class = g_slice_alloc0 (sizeof (*re_class));
		re_class->id = class_id;
		re_class->type_len = datalen;
		re_class->type = type;
		re_class->re_ids = g_hash_table_new (rspamd_regexp_hash,
				rspamd_regexp_equal);

		if (datalen > 0) {
			re_class->type_data = g_slice_alloc (datalen);
			memcpy (re_class->type_data, type_data, datalen);
		}

		re_class->all_re = g_ptr_array_new ();
		g_hash_table_insert (cache->re_classes, &re_class->id, re_class);
	}

	g_ptr_array_add (re_class->all_re, rspamd_regexp_ref (re));
	/*
	 * We set re id based on the global position in the cache
	 */
	rspamd_regexp_set_cache_id (re, cache->nre ++);
}

void
rspamd_re_cache_init (struct rspamd_re_cache *cache)
{
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	rspamd_cryptobox_hash_state_t st;
	rspamd_regexp_t *re;
	guint i;
	guchar hash_out[rspamd_cryptobox_HASHBYTES];

	g_assert (cache != NULL);

	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;
		rspamd_cryptobox_hash_init (&st, NULL, 0);
		rspamd_cryptobox_hash_update (&st, (gpointer)&re_class->id,
				sizeof (re_class->id));

		for (i = 0; i < re_class->all_re->len; i ++) {
			re = g_ptr_array_index (re_class->all_re, i);
			rspamd_cryptobox_hash_update (&st, rspamd_regexp_get_id (re),
					rspamd_cryptobox_HASHBYTES);
		}

		rspamd_cryptobox_hash_final (&st, hash_out);
		rspamd_snprintf (re_class->hash, sizeof (re_class->hash), "%*xs",
				(gint)rspamd_cryptobox_HASHBYTES, hash_out);
	}
}

struct rspamd_re_runtime *
rspamd_re_cache_runtime_new (struct rspamd_re_cache *cache)
{
	struct rspamd_re_runtime *rt;
	g_assert (cache != NULL);

	rt = g_slice_alloc (sizeof (*rt));
	rt->cache = cache;
	REF_RETAIN (cache);
	rt->checked = g_slice_alloc0 (NBYTES (cache->nre));
	rt->results = g_slice_alloc0 (NBYTES (cache->nre));

	return rt;
}

gboolean
rspamd_re_cache_process (struct rspamd_task *task,
		struct rspamd_re_runtime *rt,
		rspamd_regexp_t *re,
		enum rspamd_re_type type,
		gpointer type_data,
		gsize datalen)
{
	guint64 class_id, re_id;
	struct rspamd_re_class *re_class;
	struct rspamd_re_cache *cache;

	g_assert (rt != NULL);
	g_assert (task != NULL);
	g_assert (re != NULL);

	re_id = rspamd_regexp_get_cache_id (re);

	if (re_id == RSPAMD_INVALID_ID) {
		msg_err_task ("re '%s' has no valid id for the cache",
				rspamd_regexp_get_pattern (re));
		return FALSE;
	}

	if (isset (rt->checked, re_id)) {
		/* Fast path */
		return isset (rt->results, re_id);
	}
	else {
		/* Slow path */
		cache = rt->cache;
		class_id = rspamd_re_cache_class_id (type, type_data, datalen);
		re_class = g_hash_table_lookup (cache->re_classes, &class_id);

		if (re_class == NULL) {
			msg_err_task ("cannot find re class for regexp '%s'",
					rspamd_regexp_get_pattern (re));
			return FALSE;
		}
	}

	return FALSE;
}

void
rspamd_re_cache_runtime_destroy (struct rspamd_re_runtime *rt)
{
	g_assert (rt != NULL);

	g_slice_free1 (NBYTES (rt->cache->nre), rt->checked);
	g_slice_free1 (NBYTES (rt->cache->nre), rt->results);
	REF_RELEASE (rt->cache);
	g_slice_free1 (sizeof (*rt), rt);
}

void
rspamd_re_cache_destroy (struct rspamd_re_cache *cache)
{
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	rspamd_regexp_t *re;
	guint i;

	g_assert (cache != NULL);
	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;
		g_hash_table_iter_steal (&it);

		for (i = 0; i < re_class->all_re->len; i++) {
			re = g_ptr_array_index (re_class->all_re, i);

			rspamd_regexp_set_cache_id (re, RSPAMD_INVALID_ID);
			rspamd_regexp_unref (re);
		}

		g_slice_free1 (sizeof (*re_class), re_class);
	}

	g_hash_table_unref (cache->re_classes);
	g_slice_free1 (sizeof (*cache), cache);
}
