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

#include "libmime/message.h"
#include "re_cache.h"
#include "xxhash.h"
#include "cryptobox.h"
#include "ref.h"
#include "libserver/url.h"
#include "libserver/task.h"
#include "libutil/util.h"

struct rspamd_re_class {
	guint64 id;
	enum rspamd_re_type type;
	gpointer type_data;
	gsize type_len;
	GHashTable *re;
	gchar hash[rspamd_cryptobox_HASHBYTES * 2 + 1];
};

struct rspamd_re_cache {
	GHashTable *re_classes;
	ref_entry_t ref;
	guint nre;
	guint max_re_data;
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

static void
rspamd_re_cache_destroy (struct rspamd_re_cache *cache)
{
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;

	g_assert (cache != NULL);
	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;
		g_hash_table_iter_steal (&it);
		g_hash_table_unref (re_class->re);
		g_slice_free1 (sizeof (*re_class), re_class);
	}

	g_hash_table_unref (cache->re_classes);
	g_slice_free1 (sizeof (*cache), cache);
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
	rspamd_regexp_t *nre;

	g_assert (cache != NULL);
	g_assert (re != NULL);

	class_id = rspamd_re_cache_class_id (type, type_data, datalen);
	re_class = g_hash_table_lookup (cache->re_classes, &class_id);

	if (re_class == NULL) {
		re_class = g_slice_alloc0 (sizeof (*re_class));
		re_class->id = class_id;
		re_class->type_len = datalen;
		re_class->type = type;
		re_class->re = g_hash_table_new_full (rspamd_regexp_hash,
				rspamd_regexp_equal, NULL, (GDestroyNotify)rspamd_regexp_unref);

		if (datalen > 0) {
			re_class->type_data = g_slice_alloc (datalen);
			memcpy (re_class->type_data, type_data, datalen);
		}

		g_hash_table_insert (cache->re_classes, &re_class->id, re_class);
	}

	/*
	 * We set re id based on the global position in the cache
	 */
	rspamd_regexp_set_cache_id (re, cache->nre ++);
	rspamd_regexp_set_class (re, re_class);
	nre = rspamd_regexp_ref (re);
	g_hash_table_insert (re_class->re, nre, nre);
}

void
rspamd_re_cache_replace (struct rspamd_re_cache *cache,
		rspamd_regexp_t *what,
		rspamd_regexp_t *with)
{
	guint64 re_id;
	struct rspamd_re_class *re_class;
	rspamd_regexp_t *src;

	g_assert (cache != NULL);
	g_assert (what != NULL);
	g_assert (with != NULL);

	re_class = rspamd_regexp_get_class (what);

	if (re_class != NULL) {
		re_id = rspamd_regexp_get_cache_id (what);

		g_assert (re_id != RSPAMD_INVALID_ID);
		src = g_hash_table_lookup (re_class->re, what);

		if (src) {
			rspamd_regexp_set_cache_id (what, RSPAMD_INVALID_ID);
			rspamd_regexp_set_class (what, NULL);
			rspamd_regexp_set_cache_id (with, re_id);
			rspamd_regexp_set_class (with, re_class);
			/*
			 * On calling of this function, we actually unref old re (what)
			 */
			g_hash_table_insert (re_class->re, what, rspamd_regexp_ref (with));
		}
	}
}

void
rspamd_re_cache_init (struct rspamd_re_cache *cache)
{
	GHashTableIter it, cit;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	rspamd_cryptobox_hash_state_t st;
	rspamd_regexp_t *re;
	guchar hash_out[rspamd_cryptobox_HASHBYTES];

	g_assert (cache != NULL);

	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;
		rspamd_cryptobox_hash_init (&st, NULL, 0);
		rspamd_cryptobox_hash_update (&st, (gpointer)&re_class->id,
				sizeof (re_class->id));
		g_hash_table_iter_init (&cit, re_class->re);

		while (g_hash_table_iter_next (&cit, &k, &v)) {
			re = v;
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
	rt->results = g_slice_alloc0 (cache->nre);

	return rt;
}

static guint
rspamd_re_cache_process_pcre (struct rspamd_re_cache *cache,
		rspamd_regexp_t *re, const guchar *in, gsize len,
		gboolean is_raw, gboolean is_multiple)
{
	guint r = 0;
	const gchar *start = NULL, *end = NULL;

	if (len == 0) {
		len = strlen (in);
	}

	if (cache->max_re_data > 0 && len > cache->max_re_data) {
		len = cache->max_re_data;
	}

	while (rspamd_regexp_search (re,
			in,
			len,
			&start,
			&end,
			is_raw,
			NULL)) {
		r++;

		if (!is_multiple || r >= 0xFF) {
			break;
		}
	}

	return r;
}

/*
 * Calculates the specified regexp for the specified class if it's not calculated
 */
static guint
rspamd_re_cache_exec_re (struct rspamd_task *task,
		struct rspamd_re_runtime *rt,
		rspamd_regexp_t *re,
		struct rspamd_re_class *re_class,
		guint64 re_id,
		gboolean is_strong,
		gboolean is_multiple)
{
	guint ret = 0, i;
	GList *cur, *headerlist;
	GHashTableIter it;
	struct raw_header *rh;
	const gchar *in;
	gboolean raw = FALSE;
	struct mime_text_part *part;
	struct rspamd_url *url;
	gpointer k, v;
	gsize len;

	switch (re_class->type) {
	case RSPAMD_RE_HEADER:
	case RSPAMD_RE_RAWHEADER:
		/* Get list of specified headers */
		headerlist = rspamd_message_get_header (task,
				re_class->type_data,
				is_strong);

		if (headerlist) {
			cur = headerlist;

			while (cur) {
				rh = cur->data;
				if (re_class->type == RSPAMD_RE_RAWHEADER) {
					in = rh->value;
					raw = TRUE;
				}
				else {
					in = rh->decoded;
					/* Validate input */
					if (!in || !g_utf8_validate (in, -1, NULL)) {
						cur = g_list_next (cur);
						continue;
					}
				}

				/* Match re */
				if (in) {
					ret += rspamd_re_cache_process_pcre (rt->cache, re, in,
							strlen (in), raw, is_multiple);
					debug_task ("checking header %s regexp: %s -> %d",
							re_class->type_data,
							rspamd_regexp_get_pattern (re), ret);

					if (!is_multiple && ret) {
						break;
					}
				}

				cur = g_list_next (cur);
			}
		}
		break;
	case RSPAMD_RE_ALLHEADER:
		raw = TRUE;
		in = task->raw_headers_content.begin;
		len = task->raw_headers_content.len;
		ret = rspamd_re_cache_process_pcre (rt->cache, re, in,
				len, raw, is_multiple);
		debug_task ("checking allheader regexp: %s -> %d",
				rspamd_regexp_get_pattern (re), ret);
		break;
	case RSPAMD_RE_MIME:
		/* Iterate throught text parts */
		for (i = 0; i < task->text_parts->len; i++) {
			part = g_ptr_array_index (task->text_parts, i);

			/* Skip empty parts */
			if (IS_PART_EMPTY (part)) {
				continue;
			}

			/* Check raw flags */
			if (!IS_PART_UTF (part)) {
				raw = TRUE;
			}
			/* Select data for regexp */
			if (raw) {
				in = part->orig->data;
				len = part->orig->len;
			}
			else {
				in = part->content->data;
				len = part->content->len;
			}

			if (len > 0) {
				ret += rspamd_re_cache_process_pcre (rt->cache, re, in,
						len, raw, is_multiple);
				debug_task ("checking mime regexp: %s -> %d",
						rspamd_regexp_get_pattern (re), ret);

				if (!is_multiple && ret) {
					break;
				}
			}
		}
		break;
	case RSPAMD_RE_URL:
		g_hash_table_iter_init (&it, task->urls);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			if (ret && !is_multiple) {
				break;
			}

			url = v;
			in = url->string;
			len = url->urllen;
			raw = FALSE;

			ret += rspamd_re_cache_process_pcre (rt->cache, re, in,
					len, raw, is_multiple);
		}

		g_hash_table_iter_init (&it, task->emails);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			if (ret && !is_multiple) {
				break;
			}

			url = v;
			in = url->string;
			len = url->urllen;
			raw = FALSE;

			ret += rspamd_re_cache_process_pcre (rt->cache, re, in,
					len, raw, is_multiple);
		}

		debug_task ("checking url regexp: %s -> %d",
				rspamd_regexp_get_pattern (re), ret);
		break;
	case RSPAMD_RE_BODY:
		raw = TRUE;
		in = task->msg.begin;
		len = task->msg.len;

		ret = rspamd_re_cache_process_pcre (rt->cache, re, in,
				len, raw, is_multiple);
		debug_task ("checking rawbody regexp: %s -> %d",
				rspamd_regexp_get_pattern (re), ret);
		break;
	case RSPAMD_RE_MAX:
		msg_err_task ("regexp of class invalid has been called: %s",
				rspamd_regexp_get_pattern (re));
		break;
	}

	setbit (rt->checked, re_id);
	rt->results[re_id] = ret > 0xFF ? 0xFF : ret;

	return ret;
}

gint
rspamd_re_cache_process (struct rspamd_task *task,
		struct rspamd_re_runtime *rt,
		rspamd_regexp_t *re,
		enum rspamd_re_type type,
		gpointer type_data,
		gsize datalen,
		gboolean is_strong,
		gboolean is_multiple)
{
	guint64 re_id;
	struct rspamd_re_class *re_class;
	struct rspamd_re_cache *cache;

	g_assert (rt != NULL);
	g_assert (task != NULL);
	g_assert (re != NULL);

	cache = rt->cache;
	re_id = rspamd_regexp_get_cache_id (re);

	if (re_id == RSPAMD_INVALID_ID || re_id > cache->nre) {
		msg_err_task ("re '%s' has no valid id for the cache",
				rspamd_regexp_get_pattern (re));
		return 0;
	}

	if (isset (rt->checked, re_id)) {
		/* Fast path */
		return rt->results[re_id];
	}
	else {
		/* Slow path */
		re_class = rspamd_regexp_get_class (re);

		if (re_class == NULL) {
			msg_err_task ("cannot find re class for regexp '%s'",
					rspamd_regexp_get_pattern (re));
			return 0;
		}

		return rspamd_re_cache_exec_re (task, rt, re, re_class, re_id,
				is_strong, is_multiple);
	}

	return 0;
}

void
rspamd_re_cache_runtime_destroy (struct rspamd_re_runtime *rt)
{
	g_assert (rt != NULL);

	g_slice_free1 (NBYTES (rt->cache->nre), rt->checked);
	g_slice_free1 (rt->cache->nre, rt->results);
	REF_RELEASE (rt->cache);
	g_slice_free1 (sizeof (*rt), rt);
}

void
rspamd_re_cache_unref (struct rspamd_re_cache *cache)
{
	if (cache) {
		REF_RELEASE (cache);
	}
}

struct rspamd_re_cache *
rspamd_re_cache_ref (struct rspamd_re_cache *cache)
{
	if (cache) {
		REF_RETAIN (cache);
	}

	return cache;
}

guint
rspamd_re_cache_set_limit (struct rspamd_re_cache *cache, guint limit)
{
	guint old;

	g_assert (cache != NULL);

	old = cache->max_re_data;
	cache->max_re_data = limit;

	return old;
}

const gchar *
rspamd_re_cache_type_to_string (enum rspamd_re_type type)
{
	const gchar *ret = "unknown";

	switch (type) {
	case RSPAMD_RE_HEADER:
		ret = "header";
		break;
	case RSPAMD_RE_RAWHEADER:
		ret = "raw header";
		break;
	case RSPAMD_RE_ALLHEADER:
		ret = "all headers";
		break;
	case RSPAMD_RE_MIME:
		ret = "part";
		break;
	case RSPAMD_RE_BODY:
		ret = "rawbody";
		break;
	case RSPAMD_RE_URL:
		ret = "url";
		break;
	case RSPAMD_RE_MAX:
		ret = "invalid class";
		break;
	}

	return ret;
}

enum rspamd_re_type
rspamd_re_cache_type_from_string (const char *str)
{
	enum rspamd_re_type ret = RSPAMD_RE_MAX;

	if (str != NULL) {
		if (strcmp (str, "header") == 0) {
			ret = RSPAMD_RE_HEADER;
		}
		else if (strcmp (str, "rawheader") == 0) {
			ret = RSPAMD_RE_RAWHEADER;
		}
		else if (strcmp (str, "mime") == 0) {
			ret = RSPAMD_RE_MIME;
		}
		else if (strcmp (str, "body") == 0) {
			ret = RSPAMD_RE_BODY;
		}
		else if (strcmp (str, "url") == 0) {
			ret = RSPAMD_RE_URL;
		}
		else if (strcmp (str, "allheader") == 0) {
			ret = RSPAMD_RE_ALLHEADER;
		}
	}

	return ret;
}
