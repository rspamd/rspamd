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
#ifdef WITH_HYPERSCAN
#include "hs.h"
#include "unix-std.h"
#include <signal.h>
#include <pcre.h>

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#endif

#define msg_err_re_cache(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "re_cache", cache->hash, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_re_cache(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "re_cache", cache->hash, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_re_cache(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "re_cache", cache->hash, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_re_cache(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "re_cache", cache->hash, \
        G_STRFUNC, \
        __VA_ARGS__)

#ifdef WITH_HYPERSCAN
#define RSPAMD_HS_MAGIC_LEN (sizeof (rspamd_hs_magic))
static const guchar rspamd_hs_magic[] = {'r', 's', 'h', 's', 'r', 'e', '1', '1'};
#endif

struct rspamd_re_class {
	guint64 id;
	enum rspamd_re_type type;
	gpointer type_data;
	gsize type_len;
	GHashTable *re;
	gchar hash[rspamd_cryptobox_HASHBYTES + 1];
	rspamd_cryptobox_hash_state_t *st;
#ifdef WITH_HYPERSCAN
	hs_database_t *hs_db;
	hs_scratch_t *hs_scratch;
	gint *hs_ids;
	guint nhs;
#endif
};

enum rspamd_re_cache_elt_match_type {
	RSPAMD_RE_CACHE_PCRE = 0,
	RSPAMD_RE_CACHE_HYPERSCAN,
	RSPAMD_RE_CACHE_HYPERSCAN_PRE
};

struct rspamd_re_cache_elt {
	rspamd_regexp_t *re;
	enum rspamd_re_cache_elt_match_type match_type;
};

struct rspamd_re_cache {
	GHashTable *re_classes;
	GPtrArray *re;
	ref_entry_t ref;
	guint nre;
	guint max_re_data;
	gchar hash[rspamd_cryptobox_HASHBYTES + 1];
#ifdef WITH_HYPERSCAN
	hs_platform_info_t plt;
#endif
};

struct rspamd_re_runtime {
	guchar *checked;
	guchar *results;
	struct rspamd_re_cache *cache;
	struct rspamd_re_cache_stat stat;
};

static GQuark
rspamd_re_cache_quark (void)
{
	return g_quark_from_static_string ("re_cache");
}

static guint64
rspamd_re_cache_class_id (enum rspamd_re_type type,
		gpointer type_data,
		gsize datalen)
{
	XXH64_state_t st;

	XXH64_reset (&st, 0xdeadbabe);
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
#ifdef WITH_HYPERSCAN
		if (re_class->hs_db) {
			hs_free_database (re_class->hs_db);
		}
		if (re_class->hs_scratch) {
			hs_free_scratch (re_class->hs_scratch);
		}
		if (re_class->hs_ids) {
			g_free (re_class->hs_ids);
		}
#endif
		g_slice_free1 (sizeof (*re_class), re_class);
	}

	g_hash_table_unref (cache->re_classes);
	g_ptr_array_free (cache->re, TRUE);
	g_slice_free1 (sizeof (*cache), cache);
}

static void
rspamd_re_cache_elt_dtor (gpointer e)
{
	struct rspamd_re_cache_elt *elt = e;

	rspamd_regexp_unref (elt->re);
	g_slice_free1 (sizeof (*elt), elt);
}

struct rspamd_re_cache *
rspamd_re_cache_new (void)
{
	struct rspamd_re_cache *cache;

	cache = g_slice_alloc (sizeof (*cache));
	cache->re_classes = g_hash_table_new (g_int64_hash, g_int64_equal);
	cache->nre = 0;
	cache->re = g_ptr_array_new_full (256, rspamd_re_cache_elt_dtor);
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
	struct rspamd_re_cache_elt *elt;

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
	elt = g_slice_alloc0 (sizeof (*elt));
	/* One ref for re_class */
	nre = rspamd_regexp_ref (re);
	rspamd_regexp_set_cache_id (re, cache->nre ++);
	/* One ref for cache */
	elt->re = rspamd_regexp_ref (re);
	g_ptr_array_add (cache->re, elt);
	rspamd_regexp_set_class (re, re_class);
	g_hash_table_insert (re_class->re, rspamd_regexp_get_id (nre), nre);
}

void
rspamd_re_cache_replace (struct rspamd_re_cache *cache,
		rspamd_regexp_t *what,
		rspamd_regexp_t *with)
{
	guint64 re_id;
	struct rspamd_re_class *re_class;
	rspamd_regexp_t *src;
	struct rspamd_re_cache_elt *elt;

	g_assert (cache != NULL);
	g_assert (what != NULL);
	g_assert (with != NULL);

	re_class = rspamd_regexp_get_class (what);

	if (re_class != NULL) {
		re_id = rspamd_regexp_get_cache_id (what);

		g_assert (re_id != RSPAMD_INVALID_ID);
		src = g_hash_table_lookup (re_class->re, rspamd_regexp_get_id (what));
		elt = g_ptr_array_index (cache->re, re_id);
		g_assert (elt != NULL);
		g_assert (src != NULL);

		rspamd_regexp_set_cache_id (what, RSPAMD_INVALID_ID);
		rspamd_regexp_set_class (what, NULL);
		rspamd_regexp_set_cache_id (with, re_id);
		rspamd_regexp_set_class (with, re_class);
		/*
		 * On calling of this function, we actually unref old re (what)
		 */
		g_hash_table_insert (re_class->re,
				rspamd_regexp_get_id (what),
				rspamd_regexp_ref (with));

		rspamd_regexp_unref (elt->re);
		elt->re = rspamd_regexp_ref (with);
		/* XXX: do not touch match type here */
	}
}

static gint
rspamd_re_cache_sort_func (gconstpointer a, gconstpointer b)
{
	struct rspamd_re_cache_elt * const *re1 = a, * const *re2 = b;

	return rspamd_regexp_cmp (rspamd_regexp_get_id ((*re1)->re),
			rspamd_regexp_get_id ((*re2)->re));
}

void
rspamd_re_cache_init (struct rspamd_re_cache *cache)
{
	guint i, fl;
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	rspamd_cryptobox_hash_state_t st_global;
	rspamd_regexp_t *re;
	struct rspamd_re_cache_elt *elt;
	guchar hash_out[rspamd_cryptobox_HASHBYTES];

	g_assert (cache != NULL);

	rspamd_cryptobox_hash_init (&st_global, NULL, 0);
	/* Resort all regexps */
	g_ptr_array_sort (cache->re, rspamd_re_cache_sort_func);

	for (i = 0; i < cache->re->len; i ++) {
		elt = g_ptr_array_index (cache->re, i);
		re = elt->re;
		re_class = rspamd_regexp_get_class (re);
		g_assert (re_class != NULL);
		rspamd_regexp_set_cache_id (re, i);

		if (re_class->st == NULL) {
			re_class->st = g_slice_alloc (sizeof (*re_class->st));
			rspamd_cryptobox_hash_init (re_class->st, NULL, 0);
		}

		/* Update hashes */
		rspamd_cryptobox_hash_update (re_class->st, (gpointer) &re_class->id,
				sizeof (re_class->id));
		rspamd_cryptobox_hash_update (&st_global, (gpointer) &re_class->id,
				sizeof (re_class->id));
		rspamd_cryptobox_hash_update (re_class->st, rspamd_regexp_get_id (re),
				rspamd_cryptobox_HASHBYTES);
		rspamd_cryptobox_hash_update (&st_global, rspamd_regexp_get_id (re),
				rspamd_cryptobox_HASHBYTES);
		fl = rspamd_regexp_get_pcre_flags (re);
		rspamd_cryptobox_hash_update (re_class->st, (const guchar *)&fl,
				sizeof (fl));
		rspamd_cryptobox_hash_update (&st_global, (const guchar *) &fl,
				sizeof (fl));
		fl = rspamd_regexp_get_flags (re);
		rspamd_cryptobox_hash_update (re_class->st, (const guchar *) &fl,
				sizeof (fl));
		rspamd_cryptobox_hash_update (&st_global, (const guchar *) &fl,
				sizeof (fl));
		fl = rspamd_regexp_get_maxhits (re);
		rspamd_cryptobox_hash_update (re_class->st, (const guchar *) &fl,
				sizeof (fl));
		rspamd_cryptobox_hash_update (&st_global, (const guchar *) &fl,
				sizeof (fl));
	}

	/* Now finalize all classes */
	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;

		if (re_class->st) {
			rspamd_cryptobox_hash_final (re_class->st, hash_out);
			rspamd_snprintf (re_class->hash, sizeof (re_class->hash), "%*xs",
					(gint) rspamd_cryptobox_HASHBYTES, hash_out);
			g_slice_free1 (sizeof (*re_class->st), re_class->st);
			re_class->st = NULL;
		}
	}

	rspamd_cryptobox_hash_final (&st_global, hash_out);
	rspamd_snprintf (cache->hash, sizeof (cache->hash), "%*xs",
			(gint) rspamd_cryptobox_HASHBYTES, hash_out);

#ifdef WITH_HYPERSCAN
	const gchar *platform = "generic";
	rspamd_fstring_t *features = rspamd_fstring_new ();

	g_assert (hs_populate_platform (&cache->plt) == HS_SUCCESS);

	/* Now decode what we do have */
	switch (cache->plt.tune) {
	case HS_TUNE_FAMILY_HSW:
		platform = "haswell";
		break;
	case HS_TUNE_FAMILY_SNB:
		platform = "sandy";
		break;
	case HS_TUNE_FAMILY_BDW:
		platform = "broadwell";
		break;
	case HS_TUNE_FAMILY_IVB:
		platform = "ivy";
		break;
	default:
		break;
	}

	if (cache->plt.cpu_features & HS_CPU_FEATURES_AVX2) {
		features = rspamd_fstring_append (features, "AVX2", 4);
	}

	hs_set_allocator (g_malloc, g_free);

	msg_info_re_cache ("loaded hyperscan engine witch cpu tune '%s' and features '%V'",
			platform, features);

	rspamd_fstring_free (features);
#endif
}

struct rspamd_re_runtime *
rspamd_re_cache_runtime_new (struct rspamd_re_cache *cache)
{
	struct rspamd_re_runtime *rt;
	g_assert (cache != NULL);

	rt = g_slice_alloc0 (sizeof (*rt));
	rt->cache = cache;
	REF_RETAIN (cache);
	rt->checked = g_slice_alloc0 (NBYTES (cache->nre));
	rt->results = g_slice_alloc0 (cache->nre);

	return rt;
}

const struct rspamd_re_cache_stat *
rspamd_re_cache_get_stat (struct rspamd_re_runtime *rt)
{
	g_assert (rt != NULL);

	return &rt->stat;
}

static guint
rspamd_re_cache_process_pcre (struct rspamd_re_runtime *rt,
		rspamd_regexp_t *re, const guchar *in, gsize len,
		gboolean is_raw)
{
	guint r = 0;
	const gchar *start = NULL, *end = NULL;
	guint max_hits = rspamd_regexp_get_maxhits (re);

	if (len == 0) {
		len = strlen (in);
	}

	if (rt->cache->max_re_data > 0 && len > rt->cache->max_re_data) {
		len = rt->cache->max_re_data;
	}

	while (rspamd_regexp_search (re,
			in,
			len,
			&start,
			&end,
			is_raw,
			NULL)) {
		r++;

		if (max_hits > 0 && r > max_hits) {
			break;
		}
	}

	rt->stat.regexp_checked ++;
	rt->stat.bytes_scanned_pcre += len;
	rt->stat.bytes_scanned += len;

	if (r > 0) {
		rt->stat.regexp_matched += r;
	}

	return r;
}

#ifdef WITH_HYPERSCAN
struct rspamd_re_hyperscan_cbdata {
	struct rspamd_re_runtime *rt;
	const guchar *in;
	gsize len;
	rspamd_regexp_t *re;
};

static gint
rspamd_re_cache_hyperscan_cb (unsigned int id,
		unsigned long long from,
		unsigned long long to,
		unsigned int flags,
		void *ud)
{
	struct rspamd_re_hyperscan_cbdata *cbdata = ud;
	struct rspamd_re_runtime *rt;
	struct rspamd_re_cache_elt *pcre_elt;
	guint ret, maxhits;

	rt = cbdata->rt;
	pcre_elt = g_ptr_array_index (rt->cache->re, id);
	maxhits = rspamd_regexp_get_maxhits (pcre_elt->re);

	if (pcre_elt->match_type == RSPAMD_RE_CACHE_HYPERSCAN) {
		ret = 1;
		setbit (rt->checked, id);

		if (maxhits == 0 || rt->results[id] < maxhits) {
			rt->results[id] += ret;
			rt->stat.regexp_matched++;
		}
	}
	else {
		if (!isset (rt->checked, id)) {
			ret = rspamd_re_cache_process_pcre (rt,
					pcre_elt->re,
					cbdata->in,
					cbdata->len,
					FALSE);
			rt->results[id] = ret;
			setbit (rt->checked, id);
		}
	}

	return 0;
}
#endif

static guint
rspamd_re_cache_process_regexp_data (struct rspamd_re_runtime *rt,
		rspamd_regexp_t *re,
		const guchar *in, gsize len,
		gboolean is_raw)
{
	struct rspamd_re_cache_elt *elt;
	struct rspamd_re_class *re_class;
	guint64 re_id;
	guint ret;

	re_id = rspamd_regexp_get_cache_id (re);
	elt = g_ptr_array_index (rt->cache->re, re_id);
	re_class = rspamd_regexp_get_class (re);

#ifndef WITH_HYPERSCAN
	ret = rspamd_re_cache_process_pcre (rt, re, in, len, is_raw);
	setbit (rt->checked, re_id);
	rt->results[re_id] = ret;
#else
	struct rspamd_re_hyperscan_cbdata cbdata;

	if (elt->match_type == RSPAMD_RE_CACHE_PCRE) {
		ret = rspamd_re_cache_process_pcre (rt, re, in, len, is_raw);
		setbit (rt->checked, re_id);
		rt->results[re_id] = ret;
	}
	else {
		if (len == 0) {
			len = strlen (in);
		}

		if (rt->cache->max_re_data > 0 && len > rt->cache->max_re_data) {
			len = rt->cache->max_re_data;
		}

		g_assert (re_class->hs_scratch != NULL);
		g_assert (re_class->hs_db != NULL);

		/* Go through hyperscan API */
		cbdata.in = in;
		cbdata.re = re;
		cbdata.rt = rt;
		cbdata.len = len;
		rt->stat.bytes_scanned += len;

		if ((hs_scan (re_class->hs_db, in, len, 0, re_class->hs_scratch,
				rspamd_re_cache_hyperscan_cb, &cbdata)) != HS_SUCCESS) {
			ret = 0;
		}
		else {
			ret = rt->results[re_id];
		}
	}
#endif

	return ret;
}

static void
rspamd_re_cache_finish_class (struct rspamd_re_runtime *rt,
		struct rspamd_re_class *re_class)
{
#ifdef WITH_HYPERSCAN
	guint i;
	guint64 re_id;

	/* Set all bits unchecked */
	for (i = 0; i < re_class->nhs; i++) {
		re_id = re_class->hs_ids[i];

		if (!isset (rt->checked, re_id)) {
			g_assert (rt->results[re_id] == 0);
			rt->results[re_id] = 0;
			setbit (rt->checked, re_id);
		}
	}
#endif
}

/*
 * Calculates the specified regexp for the specified class if it's not calculated
 */
static guint
rspamd_re_cache_exec_re (struct rspamd_task *task,
		struct rspamd_re_runtime *rt,
		rspamd_regexp_t *re,
		struct rspamd_re_class *re_class,
		gboolean is_strong)
{
	guint ret = 0, i;
	GList *cur, *headerlist;
	GHashTableIter it;
	struct raw_header *rh;
	const gchar *in;
	gboolean raw = FALSE;
	struct mime_text_part *part;
	struct rspamd_url *url;
	struct rspamd_re_cache *cache = rt->cache;
	gpointer k, v;
	gsize len;

	msg_debug_re_cache ("get to the slow path for re type: %s: %s",
			rspamd_re_cache_type_to_string (re_class->type),
			rspamd_regexp_get_pattern (re));

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
					ret += rspamd_re_cache_process_regexp_data (rt, re, in,
							strlen (in), raw);
					debug_task ("checking header %s regexp: %s -> %d",
							re_class->type_data,
							rspamd_regexp_get_pattern (re), ret);
				}

				cur = g_list_next (cur);
			}
		}
		break;
	case RSPAMD_RE_ALLHEADER:
		raw = TRUE;
		in = task->raw_headers_content.begin;
		len = task->raw_headers_content.len;
		ret = rspamd_re_cache_process_regexp_data (rt, re, in,
				len, raw);
		debug_task ("checking allheader regexp: %s -> %d",
				rspamd_regexp_get_pattern (re), ret);
		break;
	case RSPAMD_RE_MIME:
	case RSPAMD_RE_RAWMIME:
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
			if (re_class->type == RSPAMD_RE_RAWMIME) {
				in = part->orig->data;
				len = part->orig->len;
				raw = TRUE;
			}
			else {
				in = part->content->data;
				len = part->content->len;
			}

			if (len > 0) {
				ret += rspamd_re_cache_process_regexp_data (rt, re, in,
						len, raw);
				debug_task ("checking mime regexp: %s -> %d",
						rspamd_regexp_get_pattern (re), ret);
			}
		}
		break;
	case RSPAMD_RE_URL:
		g_hash_table_iter_init (&it, task->urls);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			url = v;
			in = url->string;
			len = url->urllen;
			raw = FALSE;

			ret += rspamd_re_cache_process_regexp_data (rt, re, in,
					len, raw);
		}

		g_hash_table_iter_init (&it, task->emails);

		while (g_hash_table_iter_next (&it, &k, &v)) {
			url = v;
			in = url->string;
			len = url->urllen;
			raw = FALSE;

			ret += rspamd_re_cache_process_regexp_data (rt, re, in,
					len, raw);
		}

		debug_task ("checking url regexp: %s -> %d",
				rspamd_regexp_get_pattern (re), ret);
		break;
	case RSPAMD_RE_BODY:
		raw = TRUE;
		in = task->msg.begin;
		len = task->msg.len;

		ret = rspamd_re_cache_process_regexp_data (rt, re, in,
				len, raw);
		debug_task ("checking rawbody regexp: %s -> %d",
				rspamd_regexp_get_pattern (re), ret);
		break;
	case RSPAMD_RE_MAX:
		msg_err_task ("regexp of class invalid has been called: %s",
				rspamd_regexp_get_pattern (re));
		break;
	}

	rspamd_re_cache_finish_class (rt, re_class);

	return ret;
}

gint
rspamd_re_cache_process (struct rspamd_task *task,
		struct rspamd_re_runtime *rt,
		rspamd_regexp_t *re,
		enum rspamd_re_type type,
		gpointer type_data,
		gsize datalen,
		gboolean is_strong)
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

		return rspamd_re_cache_exec_re (task, rt, re, re_class,
				is_strong);
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
	case RSPAMD_RE_RAWMIME:
		ret = "raw part";
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
		else if (strcmp (str, "rawmime") == 0) {
			ret = RSPAMD_RE_RAWMIME;
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

#ifdef WITH_HYPERSCAN
static gboolean
rspamd_re_cache_is_finite (struct rspamd_re_cache *cache,
		rspamd_regexp_t *re, gint flags, gdouble max_time)
{
	pid_t cld;
	gint status;
	struct timespec ts;
	hs_compile_error_t *hs_errors;
	hs_database_t *test_db;
	gdouble wait_time;
	const gint max_tries = 10;
	gint tries = 0, rc;

	wait_time = max_time / max_tries;
	/* We need to restore SIGCHLD processing */
	signal (SIGCHLD, SIG_DFL);
	cld = fork ();
	g_assert (cld != -1);

	if (cld == 0) {
		/* Try to compile pattern */
		if (hs_compile (rspamd_regexp_get_pattern (re),
				flags | HS_FLAG_PREFILTER,
				HS_MODE_BLOCK,
				&cache->plt,
				&test_db,
				&hs_errors) != HS_SUCCESS) {
			exit (EXIT_FAILURE);
		}

		exit (EXIT_SUCCESS);
	}
	else {
		double_to_ts (wait_time, &ts);

		while ((rc = waitpid (cld, &status, WNOHANG)) == 0 && tries ++ < max_tries) {
			(void)nanosleep (&ts, NULL);
		}

		/* Child has been terminated */
		if (rc > 0) {
			/* Forget about SIGCHLD after this point */
			signal (SIGCHLD, SIG_IGN);

			if (WIFEXITED (status) && WEXITSTATUS (status) == EXIT_SUCCESS) {
				return TRUE;
			}
			else {
				msg_info_re_cache (
						"cannot approximate %s to hyperscan",
						rspamd_regexp_get_pattern (re));

				return FALSE;
			}
		}
		else {
			/* We consider that as timeout */
			kill (cld, SIGKILL);
			g_assert (waitpid (cld, &status, 0) != -1);
			msg_info_re_cache (
					"cannot approximate %s to hyperscan: timeout waiting",
					rspamd_regexp_get_pattern (re));
			signal (SIGCHLD, SIG_IGN);
		}
	}

	return FALSE;
}
#endif

gint
rspamd_re_cache_compile_hyperscan (struct rspamd_re_cache *cache,
		const char *cache_dir, gdouble max_time,
		GError **err)
{
	g_assert (cache != NULL);
	g_assert (cache_dir != NULL);

#ifndef WITH_HYPERSCAN
	g_set_error (err, rspamd_re_cache_quark (), EINVAL, "hyperscan is disabled");
	return -1;
#else
	GHashTableIter it, cit;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	gchar path[PATH_MAX];
	hs_database_t *test_db;
	gint fd, i, n, *hs_ids = NULL, pcre_flags;
	guint64 crc;
	rspamd_regexp_t *re;
	hs_compile_error_t *hs_errors;
	guint *hs_flags = NULL;
	const gchar **hs_pats = NULL;
	gchar *hs_serialized;
	gsize serialized_len, total = 0;
	struct iovec iov[7];

	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;
		rspamd_snprintf (path, sizeof (path), "%s%c%s.hs", cache_dir,
				G_DIR_SEPARATOR, re_class->hash);

		if (rspamd_re_cache_is_valid_hyperscan_file (cache, path, TRUE)) {
			msg_info_re_cache ("skip already valid file for re class '%s'",
					re_class->hash);

			fd = open (path, O_RDONLY, 00600);

			/* Read number of regexps */
			g_assert (fd != -1);
			lseek (fd, RSPAMD_HS_MAGIC_LEN + sizeof (cache->plt), SEEK_SET);
			read (fd, &n, sizeof (n));
			total += n;
			close (fd);

			continue;
		}

		fd = open (path, O_CREAT|O_TRUNC|O_EXCL|O_WRONLY, 00600);

		if (fd == -1) {
			g_set_error (err, rspamd_re_cache_quark (), errno, "cannot open file "
					"%s: %s", path, strerror (errno));
			return -1;
		}

		g_hash_table_iter_init (&cit, re_class->re);
		n = g_hash_table_size (re_class->re);
		hs_flags = g_malloc0 (sizeof (*hs_flags) * n);
		hs_ids = g_malloc (sizeof (*hs_ids) * n);
		hs_pats = g_malloc (sizeof (*hs_pats) * n);
		i = 0;

		while (g_hash_table_iter_next (&cit, &k, &v)) {
			re = v;

			hs_flags[i] = 0;
			pcre_flags = rspamd_regexp_get_pcre_flags (re);

			if (pcre_flags & PCRE_UTF8) {
				hs_flags[i] |= HS_FLAG_UTF8;
			}
			if (pcre_flags & PCRE_CASELESS) {
				hs_flags[i] |= HS_FLAG_CASELESS;
			}
			if (pcre_flags & PCRE_MULTILINE) {
				hs_flags[i] |= HS_FLAG_MULTILINE;
			}
			if (rspamd_regexp_get_maxhits (re) == 1) {
				hs_flags[i] |= HS_FLAG_SINGLEMATCH;
			}

			if (hs_compile (rspamd_regexp_get_pattern (re),
					hs_flags[i],
					HS_MODE_BLOCK,
					&cache->plt,
					&test_db,
					&hs_errors) != HS_SUCCESS) {
				msg_debug_re_cache ("cannot compile %s to hyperscan, try prefilter match",
						rspamd_regexp_get_pattern (re));
				hs_free_compile_error (hs_errors);

				/* The approximation operation might take a significant
				 * amount of time, so we need to check if it's finite
				 */
				if (rspamd_re_cache_is_finite (cache, re, hs_flags[i], max_time)) {
					hs_flags[i] |= HS_FLAG_PREFILTER;
					hs_ids[i] = rspamd_regexp_get_cache_id (re);
					hs_pats[i] = rspamd_regexp_get_pattern (re);
					i++;
				}
			}
			else {
				hs_ids[i] = rspamd_regexp_get_cache_id (re);
				hs_pats[i] = rspamd_regexp_get_pattern (re);
				i ++;
				hs_free_database (test_db);
			}
		}
		/* Adjust real re number */
		n = i;

		if (n > 0) {
			/* Create the hs tree */
			if (hs_compile_multi (hs_pats,
					hs_flags,
					hs_ids,
					n,
					HS_MODE_BLOCK,
					&cache->plt,
					&test_db,
					&hs_errors) != HS_SUCCESS) {

				g_set_error (err, rspamd_re_cache_quark (), EINVAL,
						"cannot create tree of regexp when processing '%s': %s",
						hs_pats[hs_errors->expression], hs_errors->message);
				g_free (hs_flags);
				g_free (hs_ids);
				g_free (hs_pats);
				close (fd);
				hs_free_compile_error (hs_errors);

				return -1;
			}

			g_free (hs_pats);

			if (hs_serialize_database (test_db, &hs_serialized,
					&serialized_len) != HS_SUCCESS) {
				g_set_error (err,
						rspamd_re_cache_quark (),
						errno,
						"cannot serialize tree of regexp for %s",
						re_class->hash);

				close (fd);
				g_free (hs_ids);
				g_free (hs_flags);
				hs_free_database (test_db);

				return -1;
			}

			hs_free_database (test_db);

			/*
			 * Magic - 8 bytes
			 * Platform - sizeof (platform)
			 * n - number of regexps
			 * n * <regexp ids>
			 * n * <regexp flags>
			 * crc - 8 bytes checksum
			 * <hyperscan blob>
			 */
			crc = XXH64 (hs_serialized, serialized_len, 0xdeadbabe);
			iov[0].iov_base = (void *)rspamd_hs_magic;
			iov[0].iov_len = RSPAMD_HS_MAGIC_LEN;
			iov[1].iov_base = &cache->plt;
			iov[1].iov_len = sizeof (cache->plt);
			iov[2].iov_base = &n;
			iov[2].iov_len = sizeof (n);
			iov[3].iov_base = hs_ids;
			iov[3].iov_len = sizeof (*hs_ids) * n;
			iov[4].iov_base = hs_flags;
			iov[4].iov_len = sizeof (*hs_flags) * n;
			iov[5].iov_base = &crc;
			iov[5].iov_len = sizeof (crc);
			iov[6].iov_base = hs_serialized;
			iov[6].iov_len = serialized_len;

			if (writev (fd, iov, G_N_ELEMENTS (iov)) == -1) {
				g_set_error (err,
						rspamd_re_cache_quark (),
						errno,
						"cannot serialize tree of regexp to %s: %s",
						path, strerror (errno));
				close (fd);
				g_free (hs_ids);
				g_free (hs_flags);
				g_free (hs_serialized);

				return -1;
			}

			msg_info_re_cache ("compiled class %s(%*s) to cache %s, %d regexps",
					rspamd_re_cache_type_to_string (re_class->type),
					re_class->type_len,
					re_class->type_data,
					re_class->hash, n);

			total += n;

			g_free (hs_serialized);
			g_free (hs_ids);
			g_free (hs_flags);
		}

		close (fd);
	}

	return total;
#endif
}

gboolean
rspamd_re_cache_is_valid_hyperscan_file (struct rspamd_re_cache *cache,
		const char *path, gboolean silent)
{
	g_assert (cache != NULL);
	g_assert (path != NULL);

#ifndef WITH_HYPERSCAN
	return FALSE;
#else
	gint fd;
	guchar magicbuf[RSPAMD_HS_MAGIC_LEN];
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	gsize len;
	const gchar *hash_pos;
	hs_platform_info_t test_plt;

	len = strlen (path);

	if (len < sizeof (rspamd_cryptobox_HASHBYTES + 3)) {
		return FALSE;
	}

	if (memcmp (path + len - 3, ".hs", 3) != 0) {
		return FALSE;
	}

	hash_pos = path + len - 3 - (sizeof (re_class->hash) - 1);
	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;

		if (memcmp (hash_pos, re_class->hash, sizeof (re_class->hash) - 1) == 0) {
			/* Open file and check magic */
			fd = open (path, O_RDONLY);

			if (fd == -1) {
				if (!silent) {
					msg_err_re_cache ("cannot open hyperscan cache file %s: %s",
							path, strerror (errno));
				}
				return FALSE;
			}

			if (read (fd, magicbuf, sizeof (magicbuf)) != sizeof (magicbuf)) {
				msg_err_re_cache ("cannot read hyperscan cache file %s: %s",
						path, strerror (errno));
				close (fd);
				return FALSE;
			}

			if (memcmp (magicbuf, rspamd_hs_magic, sizeof (magicbuf)) != 0) {
				msg_err_re_cache ("cannot open hyperscan cache file %s: "
						"bad magic ('%*xs', '%*xs' expected)",
						path, (int) RSPAMD_HS_MAGIC_LEN, magicbuf,
						(int) RSPAMD_HS_MAGIC_LEN, rspamd_hs_magic);

				close (fd);
				return FALSE;
			}

			if (read (fd, &test_plt, sizeof (test_plt)) != sizeof (test_plt)) {
				msg_err_re_cache ("cannot read hyperscan cache file %s: %s",
						path, strerror (errno));
				close (fd);
				return FALSE;
			}

			if (memcmp (&test_plt, &cache->plt, sizeof (test_plt)) != 0) {
				msg_err_re_cache ("cannot open hyperscan cache file %s: "
						"compiled for a different platform",
						path);

				close (fd);
				return FALSE;
			}

			/* XXX: add crc check */
			close (fd);

			return TRUE;
		}
	}

	if (!silent) {
		msg_warn_re_cache ("unknown hyperscan cache file %s", path);
	}

	return FALSE;
#endif
}


gboolean
rspamd_re_cache_load_hyperscan (struct rspamd_re_cache *cache,
		const char *cache_dir)
{
	g_assert (cache != NULL);
	g_assert (cache_dir != NULL);

#ifndef WITH_HYPERSCAN
	return FALSE;
#else
	gchar path[PATH_MAX];
	gint fd, i, n, *hs_ids = NULL, *hs_flags = NULL, total = 0;
	GHashTableIter it;
	gpointer k, v;
	guint8 *map, *p, *end;
	struct rspamd_re_class *re_class;
	struct rspamd_re_cache_elt *elt;
	struct stat st;

	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;
		rspamd_snprintf (path, sizeof (path), "%s%c%s.hs", cache_dir,
				G_DIR_SEPARATOR, re_class->hash);

		if (rspamd_re_cache_is_valid_hyperscan_file (cache, path, FALSE)) {
			msg_debug_re_cache ("load hyperscan database from '%s'",
					re_class->hash);

			fd = open (path, O_RDONLY);

			/* Read number of regexps */
			g_assert (fd != -1);
			fstat (fd, &st);

			map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

			if (map == MAP_FAILED) {
				msg_err_re_cache ("cannot mmap %s: %s", path, strerror (errno));
				close (fd);
				return FALSE;
			}

			close (fd);
			end = map + st.st_size;
			p = map + RSPAMD_HS_MAGIC_LEN + sizeof (cache->plt);
			n = *(gint *)p;

			if (n <= 0 || 2 * n * sizeof (gint) + /* IDs + flags */
							sizeof (guint64) + /* crc */
							RSPAMD_HS_MAGIC_LEN + /* header */
							sizeof (cache->plt) > (gsize)st.st_size) {
				/* Some wrong amount of regexps */
				msg_err_re_cache ("bad number of expressions in %s: %d",
						path, n);
				munmap (map, st.st_size);
				return FALSE;
			}

			total += n;
			p += sizeof (n);
			hs_ids = g_malloc (n * sizeof (*hs_ids));
			memcpy (hs_ids, p, n * sizeof (*hs_ids));
			p += n * sizeof (*hs_ids);
			hs_flags = g_malloc (n * sizeof (*hs_flags));
			memcpy (hs_flags, p, n * sizeof (*hs_flags));

			/* Skip crc */
			p += n * sizeof (*hs_ids) + sizeof (guint64);

			if (hs_deserialize_database (p, end - p, &re_class->hs_db)
					!= HS_SUCCESS) {
				msg_err_re_cache ("bad hs database in %s", path);
				munmap (map, st.st_size);
				g_free (hs_ids);
				g_free (hs_flags);

				return FALSE;
			}

			munmap (map, st.st_size);
			re_class->hs_scratch = NULL;
			g_assert (hs_alloc_scratch (re_class->hs_db,
					&re_class->hs_scratch) == HS_SUCCESS);

			/*
			 * Now find hyperscan elts that are successfully compiled and
			 * specify that they should be matched using hyperscan
			 */
			for (i = 0; i < n; i ++) {
				g_assert ((gint)cache->re->len > hs_ids[i] && hs_ids[i] >= 0);
				elt = g_ptr_array_index (cache->re, hs_ids[i]);

				if (hs_flags[i] & HS_FLAG_PREFILTER) {
					elt->match_type = RSPAMD_RE_CACHE_HYPERSCAN_PRE;
				}
				else {
					elt->match_type = RSPAMD_RE_CACHE_HYPERSCAN;
				}
			}

			re_class->hs_ids = hs_ids;
			g_free (hs_flags);
			re_class->nhs = n;
		}
		else {
			msg_err_re_cache ("invalid hyperscan hash file '%s'",
					path);
			return FALSE;
		}
	}

	msg_info_re_cache ("hyperscan database of %d regexps has been loaded", total);

	return TRUE;
#endif
}
