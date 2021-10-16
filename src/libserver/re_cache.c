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
#include "libmime/message.h"
#include "re_cache.h"
#include "cryptobox.h"
#include "ref.h"
#include "libserver/url.h"
#include "libserver/task.h"
#include "libserver/cfg_file.h"
#include "libutil/util.h"
#include "libutil/regexp.h"
#include "lua/lua_common.h"
#include "libstat/stat_api.h"
#include "contrib/uthash/utlist.h"

#include "khash.h"

#ifdef WITH_HYPERSCAN
#include "hs.h"
#endif

#include "unix-std.h"
#include <signal.h>
#include <stdalign.h>
#include <math.h>
#include "contrib/libev/ev.h"

#ifndef WITH_PCRE2
#include <pcre.h>
#else
#include <pcre2.h>
#endif

#include "contrib/fastutf8/fastutf8.h"

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
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

#define msg_debug_re_task(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_re_cache_log_id, "re_cache", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_re_cache(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_re_cache_log_id, "re_cache", cache->hash, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(re_cache)

#ifdef WITH_HYPERSCAN
#define RSPAMD_HS_MAGIC_LEN (sizeof (rspamd_hs_magic))
static const guchar rspamd_hs_magic[] = {'r', 's', 'h', 's', 'r', 'e', '1', '1'},
		rspamd_hs_magic_vector[] = {'r', 's', 'h', 's', 'r', 'v', '1', '1'};
#endif


struct rspamd_re_class {
	guint64 id;
	enum rspamd_re_type type;
	gboolean has_utf8; /* if there are any utf8 regexps */
	gpointer type_data;
	gsize type_len;
	GHashTable *re;
	rspamd_cryptobox_hash_state_t *st;

	gchar hash[rspamd_cryptobox_HASHBYTES + 1];

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
	gint lua_cbref;
	enum rspamd_re_cache_elt_match_type match_type;
};

KHASH_INIT (lua_selectors_hash, gchar *, int, 1, kh_str_hash_func, kh_str_hash_equal);

struct rspamd_re_cache {
	GHashTable *re_classes;

	GPtrArray *re;
	khash_t (lua_selectors_hash) *selectors;
	ref_entry_t ref;
	guint nre;
	guint max_re_data;
	gchar hash[rspamd_cryptobox_HASHBYTES + 1];
	lua_State *L;
#ifdef WITH_HYPERSCAN
	enum rspamd_hyperscan_status hyperscan_loaded;
	gboolean disable_hyperscan;
	gboolean vectorized_hyperscan;
	hs_platform_info_t plt;
#endif
};

struct rspamd_re_selector_result {
	guchar **scvec;
	guint *lenvec;
	guint cnt;
};

KHASH_INIT (selectors_results_hash, int, struct rspamd_re_selector_result, 1,
		kh_int_hash_func, kh_int_hash_equal);

struct rspamd_re_runtime {
	guchar *checked;
	guchar *results;
	khash_t (selectors_results_hash) *sel_cache;
	struct rspamd_re_cache *cache;
	struct rspamd_re_cache_stat stat;
	gboolean has_hs;
};

static GQuark
rspamd_re_cache_quark (void)
{
	return g_quark_from_static_string ("re_cache");
}

static guint64
rspamd_re_cache_class_id (enum rspamd_re_type type,
		gconstpointer type_data,
		gsize datalen)
{
	rspamd_cryptobox_fast_hash_state_t st;

	rspamd_cryptobox_fast_hash_init (&st, 0xdeadbabe);
	rspamd_cryptobox_fast_hash_update (&st, &type, sizeof (type));

	if (datalen > 0) {
		rspamd_cryptobox_fast_hash_update (&st, type_data, datalen);
	}

	return rspamd_cryptobox_fast_hash_final (&st);
}

static void
rspamd_re_cache_destroy (struct rspamd_re_cache *cache)
{
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	gchar *skey;
	gint sref;

	g_assert (cache != NULL);
	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;
		g_hash_table_iter_steal (&it);
		g_hash_table_unref (re_class->re);

		if (re_class->type_data) {
			g_free (re_class->type_data);
		}

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
		g_free (re_class);
	}

	if (cache->L) {
		kh_foreach (cache->selectors, skey, sref, {
			luaL_unref (cache->L, LUA_REGISTRYINDEX, sref);
			g_free (skey);
		});

		struct rspamd_re_cache_elt *elt;
		guint i;

		PTR_ARRAY_FOREACH (cache->re, i, elt) {
			if (elt->lua_cbref != -1) {
				luaL_unref (cache->L, LUA_REGISTRYINDEX, elt->lua_cbref);
			}
		}
	}

	kh_destroy (lua_selectors_hash, cache->selectors);

	g_hash_table_unref (cache->re_classes);
	g_ptr_array_free (cache->re, TRUE);
	g_free (cache);
}

static void
rspamd_re_cache_elt_dtor (gpointer e)
{
	struct rspamd_re_cache_elt *elt = e;

	rspamd_regexp_unref (elt->re);
	g_free (elt);
}

struct rspamd_re_cache *
rspamd_re_cache_new (void)
{
	struct rspamd_re_cache *cache;

	cache = g_malloc0 (sizeof (*cache));
	cache->re_classes = g_hash_table_new (g_int64_hash, g_int64_equal);
	cache->nre = 0;
	cache->re = g_ptr_array_new_full (256, rspamd_re_cache_elt_dtor);
	cache->selectors = kh_init (lua_selectors_hash);
#ifdef WITH_HYPERSCAN
	cache->hyperscan_loaded = RSPAMD_HYPERSCAN_UNKNOWN;
#endif
	REF_INIT_RETAIN (cache, rspamd_re_cache_destroy);

	return cache;
}

enum rspamd_hyperscan_status
rspamd_re_cache_is_hs_loaded (struct rspamd_re_cache *cache)
{
	g_assert (cache != NULL);

#ifdef WITH_HYPERSCAN
	return cache->hyperscan_loaded;
#else
	return RSPAMD_HYPERSCAN_UNSUPPORTED;
#endif
}

rspamd_regexp_t *
rspamd_re_cache_add (struct rspamd_re_cache *cache,
					 rspamd_regexp_t *re,
					 enum rspamd_re_type type,
					 gconstpointer type_data, gsize datalen,
					 gint lua_cbref)
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
		re_class = g_malloc0 (sizeof (*re_class));
		re_class->id = class_id;
		re_class->type_len = datalen;
		re_class->type = type;
		re_class->re = g_hash_table_new_full (rspamd_regexp_hash,
				rspamd_regexp_equal, NULL, (GDestroyNotify)rspamd_regexp_unref);

		if (datalen > 0) {
			re_class->type_data = g_malloc0 (datalen);
			memcpy (re_class->type_data, type_data, datalen);
		}

		g_hash_table_insert (cache->re_classes, &re_class->id, re_class);
	}

	if ((nre = g_hash_table_lookup (re_class->re, rspamd_regexp_get_id (re)))
			== NULL) {
		/*
		 * We set re id based on the global position in the cache
		 */
		elt = g_malloc0 (sizeof (*elt));
		/* One ref for re_class */
		nre = rspamd_regexp_ref (re);
		rspamd_regexp_set_cache_id (re, cache->nre++);
		/* One ref for cache */
		elt->re = rspamd_regexp_ref (re);
		g_ptr_array_add (cache->re, elt);
		rspamd_regexp_set_class (re, re_class);
		elt->lua_cbref = lua_cbref;

		g_hash_table_insert (re_class->re, rspamd_regexp_get_id (nre), nre);
	}

	if (rspamd_regexp_get_flags (re) & RSPAMD_REGEXP_FLAG_UTF) {
		re_class->has_utf8 = TRUE;
	}

	return nre;
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
rspamd_re_cache_init (struct rspamd_re_cache *cache, struct rspamd_config *cfg)
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
			(void) !posix_memalign ((void **)&re_class->st, _Alignof (rspamd_cryptobox_hash_state_t),
			 		sizeof (*re_class->st));
			g_assert (re_class->st != NULL);
			rspamd_cryptobox_hash_init (re_class->st, NULL, 0);
		}

		/* Update hashes */
		/* Id of re class */
		rspamd_cryptobox_hash_update (re_class->st, (gpointer) &re_class->id,
				sizeof (re_class->id));
		rspamd_cryptobox_hash_update (&st_global, (gpointer) &re_class->id,
				sizeof (re_class->id));
		/* Id of re expression */
		rspamd_cryptobox_hash_update (re_class->st, rspamd_regexp_get_id (re),
				rspamd_cryptobox_HASHBYTES);
		rspamd_cryptobox_hash_update (&st_global, rspamd_regexp_get_id (re),
				rspamd_cryptobox_HASHBYTES);
		/* PCRE flags */
		fl = rspamd_regexp_get_pcre_flags (re);
		rspamd_cryptobox_hash_update (re_class->st, (const guchar *)&fl,
				sizeof (fl));
		rspamd_cryptobox_hash_update (&st_global, (const guchar *) &fl,
				sizeof (fl));
		/* Rspamd flags */
		fl = rspamd_regexp_get_flags (re);
		rspamd_cryptobox_hash_update (re_class->st, (const guchar *) &fl,
				sizeof (fl));
		rspamd_cryptobox_hash_update (&st_global, (const guchar *) &fl,
				sizeof (fl));
		/* Limit of hits */
		fl = rspamd_regexp_get_maxhits (re);
		rspamd_cryptobox_hash_update (re_class->st, (const guchar *) &fl,
				sizeof (fl));
		rspamd_cryptobox_hash_update (&st_global, (const guchar *) &fl,
				sizeof (fl));
		/* Numberic order */
		rspamd_cryptobox_hash_update (re_class->st, (const guchar *)&i,
				sizeof (i));
		rspamd_cryptobox_hash_update (&st_global, (const guchar *)&i,
				sizeof (i));
	}

	rspamd_cryptobox_hash_final (&st_global, hash_out);
	rspamd_snprintf (cache->hash, sizeof (cache->hash), "%*xs",
			(gint) rspamd_cryptobox_HASHBYTES, hash_out);

	/* Now finalize all classes */
	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;

		if (re_class->st) {
			/*
			 * We finally update all classes with the number of expressions
			 * in the cache to ensure that if even a single re has been changed
			 * we won't be broken due to id mismatch
			 */
			rspamd_cryptobox_hash_update (re_class->st,
					(gpointer)&cache->re->len,
					sizeof (cache->re->len));
			rspamd_cryptobox_hash_final (re_class->st, hash_out);
			rspamd_snprintf (re_class->hash, sizeof (re_class->hash), "%*xs",
					(gint) rspamd_cryptobox_HASHBYTES, hash_out);
			free (re_class->st); /* Due to posix_memalign */
			re_class->st = NULL;
		}
	}

	cache->L = cfg->lua_state;

#ifdef WITH_HYPERSCAN
	const gchar *platform = "generic";
	rspamd_fstring_t *features = rspamd_fstring_new ();

	cache->disable_hyperscan = cfg->disable_hyperscan;
	cache->vectorized_hyperscan = cfg->vectorized_hyperscan;

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

	msg_info_re_cache ("loaded hyperscan engine with cpu tune '%s' and features '%V'",
			platform, features);

	rspamd_fstring_free (features);
#endif
}

struct rspamd_re_runtime *
rspamd_re_cache_runtime_new (struct rspamd_re_cache *cache)
{
	struct rspamd_re_runtime *rt;
	g_assert (cache != NULL);

	rt = g_malloc0 (sizeof (*rt) + NBYTES (cache->nre) + cache->nre);
	rt->cache = cache;
	REF_RETAIN (cache);
	rt->checked = ((guchar *)rt) + sizeof (*rt);
	rt->results = rt->checked + NBYTES (cache->nre);
	rt->stat.regexp_total = cache->nre;
#ifdef WITH_HYPERSCAN
	rt->has_hs = cache->hyperscan_loaded;
#endif

	return rt;
}

const struct rspamd_re_cache_stat *
rspamd_re_cache_get_stat (struct rspamd_re_runtime *rt)
{
	g_assert (rt != NULL);

	return &rt->stat;
}

static gboolean
rspamd_re_cache_check_lua_condition (struct rspamd_task *task,
									 rspamd_regexp_t *re,
									 const guchar *in, gsize len,
									 goffset start, goffset end,
									 gint lua_cbref)
{
	lua_State *L = (lua_State *)task->cfg->lua_state;
	GError *err = NULL;
	struct rspamd_lua_text __attribute__ ((unused)) *t;
	gint text_pos;

	if (G_LIKELY (lua_cbref == -1)) {
		return TRUE;
	}

	t = lua_new_text (L, in, len, FALSE);
	text_pos = lua_gettop (L);

	if (!rspamd_lua_universal_pcall (L, lua_cbref,
			G_STRLOC, 1, "utii", &err,
			"rspamd{task}", task,
			text_pos, start, end)) {
		msg_warn_task ("cannot call for re_cache_check_lua_condition for re %s: %e",
				rspamd_regexp_get_pattern (re), err);
		g_error_free (err);

		return TRUE;
	}

	gboolean res = lua_toboolean (L, -1);

	lua_settop (L, text_pos - 1);

	return res;
}

static guint
rspamd_re_cache_process_pcre (struct rspamd_re_runtime *rt,
		rspamd_regexp_t *re, struct rspamd_task *task,
		const guchar *in, gsize len,
		gboolean is_raw,
		gint lua_cbref)
{
	guint r = 0;
	const gchar *start = NULL, *end = NULL;
	guint max_hits = rspamd_regexp_get_maxhits (re);
	guint64 id = rspamd_regexp_get_cache_id (re);
	gdouble t1 = NAN, t2, pr;
	const gdouble slow_time = 1e8;

	if (in == NULL) {
		return rt->results[id];
	}

	if (len == 0) {
		return rt->results[id];
	}

	if (rt->cache->max_re_data > 0 && len > rt->cache->max_re_data) {
		len = rt->cache->max_re_data;
	}

	r = rt->results[id];

	if (max_hits == 0 || r < max_hits) {
		pr = rspamd_random_double_fast ();

		if (pr > 0.9) {
			t1 = rspamd_get_ticks (TRUE);
		}

		while (rspamd_regexp_search (re,
				in,
				len,
				&start,
				&end,
				is_raw,
				NULL)) {
			if (rspamd_re_cache_check_lua_condition (task, re, in, len,
					start - (const gchar *)in, end - (const gchar *)in, lua_cbref)) {
				r++;
				msg_debug_re_task ("found regexp /%s/, total hits: %d",
						rspamd_regexp_get_pattern (re), r);
			}

			if (max_hits > 0 && r >= max_hits) {
				break;
			}
		}

		rt->results[id] += r;
		rt->stat.regexp_checked++;
		rt->stat.bytes_scanned_pcre += len;
		rt->stat.bytes_scanned += len;

		if (r > 0) {
			rt->stat.regexp_matched += r;
		}

		if (!isnan (t1)) {
			t2 = rspamd_get_ticks (TRUE);

			if (t2 - t1 > slow_time) {
				rspamd_symcache_enable_profile (task);
				msg_info_task ("regexp '%16s' took %.0f ticks to execute",
						rspamd_regexp_get_pattern (re), t2 - t1);
			}
		}
	}

	return r;
}

#ifdef WITH_HYPERSCAN
struct rspamd_re_hyperscan_cbdata {
	struct rspamd_re_runtime *rt;
	const guchar **ins;
	const guint *lens;
	guint count;
	rspamd_regexp_t *re;
	struct rspamd_task *task;
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
	struct rspamd_re_cache_elt *cache_elt;
	guint ret, maxhits, i, processed;
	struct rspamd_task *task;

	rt = cbdata->rt;
	task = cbdata->task;
	cache_elt = g_ptr_array_index (rt->cache->re, id);
	maxhits = rspamd_regexp_get_maxhits (cache_elt->re);

	if (cache_elt->match_type == RSPAMD_RE_CACHE_HYPERSCAN) {
		if (rspamd_re_cache_check_lua_condition (task, cache_elt->re,
				cbdata->ins[0], cbdata->lens[0], from, to, cache_elt->lua_cbref)) {
			ret = 1;
			setbit (rt->checked, id);

			if (maxhits == 0 || rt->results[id] < maxhits) {
				rt->results[id] += ret;
				rt->stat.regexp_matched++;
			}
			msg_debug_re_task ("found regexp /%s/ using hyperscan only, total hits: %d",
					rspamd_regexp_get_pattern (cache_elt->re), rt->results[id]);
		}
	}
	else {
		if (!isset (rt->checked, id)) {

			processed = 0;

			for (i = 0; i < cbdata->count; i ++) {
				rspamd_re_cache_process_pcre (rt,
						cache_elt->re,
						cbdata->task,
						cbdata->ins[i],
						cbdata->lens[i],
						FALSE,
						cache_elt->lua_cbref);
				setbit (rt->checked, id);

				processed += cbdata->lens[i];

				if (processed >= to) {
					break;
				}
			}
		}
	}

	return 0;
}
#endif

static guint
rspamd_re_cache_process_regexp_data (struct rspamd_re_runtime *rt,
		rspamd_regexp_t *re, struct rspamd_task *task,
		const guchar **in, guint *lens,
		guint count,
		gboolean is_raw,
		gboolean *processed_hyperscan)
{

	guint64 re_id;
	guint ret = 0;
	guint i;
	struct rspamd_re_cache_elt *cache_elt;

	re_id = rspamd_regexp_get_cache_id (re);

	if (count == 0 || in == NULL) {
		/* We assume this as absence of the specified data */
		setbit (rt->checked, re_id);
		rt->results[re_id] = ret;
		return ret;
	}

	cache_elt = (struct rspamd_re_cache_elt *)g_ptr_array_index (rt->cache->re, re_id);

#ifndef WITH_HYPERSCAN
	for (i = 0; i < count; i++) {
		ret = rspamd_re_cache_process_pcre (rt,
				re,
				task,
				in[i],
				lens[i],
				is_raw,
				cache_elt->lua_cbref);
		rt->results[re_id] = ret;
	}

	setbit (rt->checked, re_id);
#else
	struct rspamd_re_class *re_class;
	struct rspamd_re_hyperscan_cbdata cbdata;

	cache_elt = g_ptr_array_index (rt->cache->re, re_id);
	re_class = rspamd_regexp_get_class (re);

	if (rt->cache->disable_hyperscan || cache_elt->match_type == RSPAMD_RE_CACHE_PCRE ||
			!rt->has_hs || (is_raw && re_class->has_utf8)) {
		for (i = 0; i < count; i++) {
			ret = rspamd_re_cache_process_pcre (rt,
					re,
					task,
					in[i],
					lens[i],
					is_raw,
					cache_elt->lua_cbref);
		}

		setbit (rt->checked, re_id);
	}
	else {
		for (i = 0; i < count; i ++) {
			/* For Hyperscan we can probably safely disable all those limits */
#if 0
			if (rt->cache->max_re_data > 0 && lens[i] > rt->cache->max_re_data) {
				lens[i] = rt->cache->max_re_data;
			}
#endif
			rt->stat.bytes_scanned += lens[i];
		}

		g_assert (re_class->hs_scratch != NULL);
		g_assert (re_class->hs_db != NULL);

		/* Go through hyperscan API */
		if (!rt->cache->vectorized_hyperscan) {
			for (i = 0; i < count; i++) {
				cbdata.ins = &in[i];
				cbdata.re = re;
				cbdata.rt = rt;
				cbdata.lens = &lens[i];
				cbdata.count = 1;
				cbdata.task = task;

				if ((hs_scan (re_class->hs_db, in[i], lens[i], 0,
						re_class->hs_scratch,
						rspamd_re_cache_hyperscan_cb, &cbdata)) != HS_SUCCESS) {
					ret = 0;
				}
				else {
					ret = rt->results[re_id];
					*processed_hyperscan = TRUE;
				}
			}
		}
		else {
			cbdata.ins = in;
			cbdata.re = re;
			cbdata.rt = rt;
			cbdata.lens = lens;
			cbdata.count = 1;
			cbdata.task = task;

			if ((hs_scan_vector (re_class->hs_db, (const char **)in, lens, count, 0,
					re_class->hs_scratch,
					rspamd_re_cache_hyperscan_cb, &cbdata)) != HS_SUCCESS) {
				ret = 0;
			}
			else {
				ret = rt->results[re_id];
				*processed_hyperscan = TRUE;
			}
		}
	}
#endif

	return ret;
}

static void
rspamd_re_cache_finish_class (struct rspamd_task *task,
							  struct rspamd_re_runtime *rt,
							  struct rspamd_re_class *re_class,
							  const gchar *class_name)
{
#ifdef WITH_HYPERSCAN
	guint i;
	guint64 re_id;
	guint found = 0;

	/* Set all bits that are not checked and included in hyperscan to 1 */
	for (i = 0; i < re_class->nhs; i++) {
		re_id = re_class->hs_ids[i];

		if (!isset (rt->checked, re_id)) {
			g_assert (rt->results[re_id] == 0);
			rt->results[re_id] = 0;
			setbit (rt->checked, re_id);
		}
		else {
			found ++;
		}
	}

	msg_debug_re_task ("finished hyperscan for class %s; %d "
					   "matches found; %d hyperscan supported regexps; %d total regexps",
			class_name, found, re_class->nhs, (gint)g_hash_table_size (re_class->re));
#endif
}

static gboolean
rspamd_re_cache_process_selector (struct rspamd_task *task,
								  struct rspamd_re_runtime *rt,
								  const gchar *name,
								  guchar ***svec,
								  guint **lenvec,
								  guint *n)
{
	gint ref;
	khiter_t k;
	lua_State *L;
	gint err_idx, ret;
	struct rspamd_task **ptask;
	gboolean result = FALSE;
	struct rspamd_re_cache *cache = rt->cache;
	struct rspamd_re_selector_result *sr;

	L = cache->L;
	k = kh_get (lua_selectors_hash, cache->selectors, (gchar *)name);

	if (k == kh_end (cache->selectors)) {
		msg_err_task ("cannot find selector %s, not registered", name);

		return FALSE;
	}

	ref = kh_value (cache->selectors, k);

	/* First, search for the cached result */
	if (rt->sel_cache) {
		k = kh_get (selectors_results_hash, rt->sel_cache, ref);

		if (k != kh_end (rt->sel_cache)) {
			sr = &kh_value (rt->sel_cache, k);

			*svec = sr->scvec;
			*lenvec = sr->lenvec;
			*n = sr->cnt;

			return TRUE;
		}
	}
	else {
		rt->sel_cache = kh_init (selectors_results_hash);
	}

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	lua_rawgeti (L, LUA_REGISTRYINDEX, ref);
	ptask = lua_newuserdata (L, sizeof (*ptask));
	*ptask = task;
	rspamd_lua_setclass (L, "rspamd{task}", -1);

	if ((ret = lua_pcall (L, 1, 1, err_idx)) != 0) {
		msg_err_task ("call to selector %s "
						"failed (%d): %s", name, ret,
						lua_tostring (L, -1));
	}
	else {
		struct rspamd_lua_text *txt;
		gsize slen;
		const gchar *sel_data;

		if (lua_type (L, -1) != LUA_TTABLE) {
			txt = lua_check_text_or_string (L, -1);

			if (txt) {
				sel_data = txt->start;
				slen = txt->len;
				*n = 1;
				*svec = g_malloc (sizeof (guchar *));
				*lenvec = g_malloc (sizeof (guint));
				(*svec)[0] = g_malloc (slen);
				memcpy ((*svec)[0], sel_data, slen);
				(*lenvec)[0] = slen;
				result = TRUE;
			}
		}
		else {
			*n = rspamd_lua_table_size (L, -1);

			if (*n > 0) {
				*svec = g_malloc (sizeof (guchar *) * (*n));
				*lenvec = g_malloc (sizeof (guint) * (*n));

				for (guint i = 0; i < *n; i ++) {
					lua_rawgeti (L, -1, i + 1);

					txt = lua_check_text_or_string (L, -1);
					if (txt) {
						sel_data = txt->start;
						slen = txt->len;
					}
					else {
						sel_data = "";
						slen = 0;
					}

					(*svec)[i] = g_malloc (slen);
					memcpy ((*svec)[i], sel_data, slen);
					(*lenvec)[i] = slen;
					lua_pop (L, 1);
				}

				result = TRUE;
			}
		}
	}

	lua_settop (L, err_idx - 1);

	if (result) {
		k = kh_put (selectors_results_hash, rt->sel_cache, ref, &ret);
		sr = &kh_value (rt->sel_cache, k);

		sr->cnt = *n;
		sr->scvec = *svec;
		sr->lenvec = *lenvec;
	}

	return result;
}

static inline guint
rspamd_process_words_vector (GArray *words,
							 const guchar **scvec,
							 guint *lenvec,
							 struct rspamd_re_class *re_class,
							 guint cnt,
							 gboolean *raw)
{
	guint j;
	rspamd_stat_token_t *tok;

	if (words) {
		for (j = 0; j < words->len; j ++) {
			tok = &g_array_index (words, rspamd_stat_token_t, j);

			if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_TEXT) {
				if (!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_UTF)) {
					if (!re_class->has_utf8) {
						*raw = TRUE;
					}
					else {
						continue; /* Skip */
					}
				}
			}
			else {
				continue; /* Skip non text */
			}

			if (re_class->type == RSPAMD_RE_RAWWORDS) {
				if (tok->original.len > 0) {
					scvec[cnt] = tok->original.begin;
					lenvec[cnt++] = tok->original.len;
				}
			}
			else if (re_class->type == RSPAMD_RE_WORDS) {
				if (tok->normalized.len > 0) {
					scvec[cnt] = tok->normalized.begin;
					lenvec[cnt++] = tok->normalized.len;
				}
			}
			else {
				/* Stemmed words */
				if (tok->stemmed.len > 0) {
					scvec[cnt] = tok->stemmed.begin;
					lenvec[cnt++] = tok->stemmed.len;
				}
			}
		}
	}

	return cnt;
}

static guint
rspamd_re_cache_process_headers_list (struct rspamd_task *task,
									  struct rspamd_re_runtime *rt,
									  rspamd_regexp_t *re,
									  struct rspamd_re_class *re_class,
									  struct rspamd_mime_header *rh,
									  gboolean is_strong,
									  gboolean *processed_hyperscan)
{
	const guchar **scvec, *in;
	gboolean raw = FALSE;
	guint *lenvec;
	struct rspamd_mime_header *cur;
	guint cnt = 0, i = 0, ret = 0;

	DL_COUNT (rh, cur, cnt);

	scvec = g_malloc (sizeof (*scvec) * cnt);
	lenvec = g_malloc (sizeof (*lenvec) * cnt);

	DL_FOREACH (rh, cur) {

		if (is_strong && strcmp (cur->name, re_class->type_data) != 0) {
			/* Skip a different case */
			continue;
		}

		if (re_class->type == RSPAMD_RE_RAWHEADER) {
			in = (const guchar *)cur->value;
			lenvec[i] = strlen (cur->value);

			if (rspamd_fast_utf8_validate (in, lenvec[i]) != 0) {
				raw = TRUE;
			}
		}
		else {
			in = (const guchar *)cur->decoded;
			/* Validate input^W^WNo need to validate as it is already valid */
			if (!in) {
				lenvec[i] = 0;
				scvec[i] = (guchar *)"";
				continue;
			}

			lenvec[i] = strlen (in);
		}

		scvec[i] = in;

		i ++;
	}

	if (i > 0) {
		ret = rspamd_re_cache_process_regexp_data (rt, re,
				task, scvec, lenvec, i, raw, processed_hyperscan);
		msg_debug_re_task ("checking header %s regexp: %s=%*s -> %d",
				re_class->type_data,
				rspamd_regexp_get_pattern (re),
				(int) lenvec[0], scvec[0], ret);
	}

	g_free (scvec);
	g_free (lenvec);

	return ret;
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
	guint ret = 0, i, re_id;
	struct rspamd_mime_header *rh;
	const gchar *in;
	const guchar **scvec;
	guint *lenvec;
	gboolean raw = FALSE, processed_hyperscan = FALSE;
	struct rspamd_mime_text_part *text_part;
	struct rspamd_mime_part *mime_part;
	struct rspamd_url *url;
	guint len, cnt;
	const gchar *class_name;

	class_name = rspamd_re_cache_type_to_string (re_class->type);
	msg_debug_re_task ("start check re type: %s: /%s/",
			class_name,
			rspamd_regexp_get_pattern (re));
	re_id = rspamd_regexp_get_cache_id (re);

	switch (re_class->type) {
	case RSPAMD_RE_HEADER:
	case RSPAMD_RE_RAWHEADER:
		/* Get list of specified headers */
		rh = rspamd_message_get_header_array(task,
				re_class->type_data, FALSE);

		if (rh) {
			ret = rspamd_re_cache_process_headers_list (task, rt, re,
					re_class, rh, is_strong, &processed_hyperscan);
			msg_debug_re_task ("checked header(%s) regexp: %s -> %d",
					(const char *)re_class->type_data,
					rspamd_regexp_get_pattern (re),
					ret);
		}
		break;
	case RSPAMD_RE_ALLHEADER:
		raw = TRUE;
		in = MESSAGE_FIELD (task, raw_headers_content).begin;
		len = MESSAGE_FIELD (task, raw_headers_content).len;
		ret = rspamd_re_cache_process_regexp_data (rt, re,
				task, (const guchar **)&in, &len, 1, raw, &processed_hyperscan);
		msg_debug_re_task ("checked allheader regexp: %s -> %d",
				rspamd_regexp_get_pattern (re), ret);
		break;
	case RSPAMD_RE_MIMEHEADER:
		PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, mime_part) {
			rh = rspamd_message_get_header_from_hash(mime_part->raw_headers,
					re_class->type_data, FALSE);

			if (rh) {
				ret += rspamd_re_cache_process_headers_list (task, rt, re,
						re_class, rh, is_strong, &processed_hyperscan);
			}
			msg_debug_re_task ("checked mime header(%s) regexp: %s -> %d",
					(const char *)re_class->type_data,
					rspamd_regexp_get_pattern (re),
					ret);
		}
		break;
	case RSPAMD_RE_MIME:
	case RSPAMD_RE_RAWMIME:
		/* Iterate through text parts */
		if (MESSAGE_FIELD (task, text_parts)->len > 0) {
			cnt = MESSAGE_FIELD (task, text_parts)->len;
			scvec = g_malloc (sizeof (*scvec) * cnt);
			lenvec = g_malloc (sizeof (*lenvec) * cnt);

			PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, text_part) {
				/* Select data for regexp */
				if (re_class->type == RSPAMD_RE_RAWMIME) {
					if (text_part->raw.len == 0) {
						len = 0;
						in = "";
					}
					else {
						in = text_part->raw.begin;
						len = text_part->raw.len;
					}

					raw = TRUE;
				}
				else {
					/* Skip empty parts */
					if (IS_TEXT_PART_EMPTY (text_part)) {
						len = 0;
						in = "";
					}
					else {
						/* Check raw flags */
						if (!IS_TEXT_PART_UTF (text_part)) {
							raw = TRUE;
						}

						in = text_part->utf_content.begin;
						len = text_part->utf_content.len;
					}
				}

				scvec[i] = (guchar *) in;
				lenvec[i] = len;
			}

			ret = rspamd_re_cache_process_regexp_data (rt, re,
					task, scvec, lenvec, cnt, raw, &processed_hyperscan);
			msg_debug_re_task ("checked mime regexp: %s -> %d",
					rspamd_regexp_get_pattern (re), ret);
			g_free (scvec);
			g_free (lenvec);
		}
		break;
	case RSPAMD_RE_URL:
		cnt = kh_size (MESSAGE_FIELD (task, urls));

		if (cnt > 0) {
			scvec = g_malloc (sizeof (*scvec) * cnt);
			lenvec = g_malloc (sizeof (*lenvec) * cnt);
			i = 0;
			raw = FALSE;

			kh_foreach_key (MESSAGE_FIELD (task, urls), url, {
				if ((url->protocol & PROTOCOL_MAILTO)) {
					continue;
				}
				in = url->string;
				len = url->urllen;

				if (len > 0 && !(url->flags & RSPAMD_URL_FLAG_IMAGE)) {
					scvec[i] = (guchar *) in;
					lenvec[i++] = len;
				}
			});

#if 0
			g_hash_table_iter_init (&it, MESSAGE_FIELD (task, emails));

			while (g_hash_table_iter_next (&it, &k, &v)) {
				url = v;
				in = url->string;
				len = url->urllen;

				if (len > 0 && !(url->flags & RSPAMD_URL_FLAG_IMAGE)) {
					scvec[i] = (guchar *) in;
					lenvec[i++] = len;
				}
			}
#endif
			ret = rspamd_re_cache_process_regexp_data (rt, re,
					task, scvec, lenvec, i, raw, &processed_hyperscan);
			msg_debug_re_task ("checked url regexp: %s -> %d",
					rspamd_regexp_get_pattern (re), ret);
			g_free (scvec);
			g_free (lenvec);
		}
		break;
	case RSPAMD_RE_EMAIL:
		cnt = kh_size (MESSAGE_FIELD (task, urls));

		if (cnt > 0) {
			scvec = g_malloc (sizeof (*scvec) * cnt);
			lenvec = g_malloc (sizeof (*lenvec) * cnt);
			i = 0;
			raw = FALSE;

			kh_foreach_key (MESSAGE_FIELD (task, urls), url, {

				if (!(url->protocol & PROTOCOL_MAILTO)) {
					continue;
				}
				if (url->userlen == 0 || url->hostlen == 0) {
					continue;
				}

				in = rspamd_url_user_unsafe (url);
				len = url->userlen + 1 + url->hostlen;
				scvec[i] = (guchar *) in;
				lenvec[i++] = len;
			});

			ret = rspamd_re_cache_process_regexp_data (rt, re,
					task, scvec, lenvec, i, raw, &processed_hyperscan);
			msg_debug_re_task ("checked email regexp: %s -> %d",
					rspamd_regexp_get_pattern (re), ret);
			g_free (scvec);
			g_free (lenvec);
		}
		break;
	case RSPAMD_RE_BODY:
		raw = TRUE;
		in = task->msg.begin;
		len = task->msg.len;

		ret = rspamd_re_cache_process_regexp_data (rt, re, task,
				(const guchar **)&in, &len, 1, raw, &processed_hyperscan);
		msg_debug_re_task ("checked rawbody regexp: %s -> %d",
				rspamd_regexp_get_pattern (re), ret);
		break;
	case RSPAMD_RE_SABODY:
		/* According to SA docs:
		 * The 'body' in this case is the textual parts of the message body;
		 * any non-text MIME parts are stripped, and the message decoded from
		 * Quoted-Printable or Base-64-encoded format if necessary. The message
		 * Subject header is considered part of the body and becomes the first
		 * paragraph when running the rules. All HTML tags and line breaks will
		 * be removed before matching.
		 */
		cnt = MESSAGE_FIELD (task, text_parts)->len + 1;
		scvec = g_malloc (sizeof (*scvec) * cnt);
		lenvec = g_malloc (sizeof (*lenvec) * cnt);

		/*
		 * Body rules also include the Subject as the first line
		 * of the body content.
		 */

		rh = rspamd_message_get_header_array(task, "Subject", FALSE);

		if (rh) {
			scvec[0] = (guchar *)rh->decoded;
			lenvec[0] = strlen (rh->decoded);
		}
		else {
			scvec[0] = (guchar *)"";
			lenvec[0] = 0;
		}

		PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, text_part) {
			if (text_part->utf_stripped_content) {
				scvec[i + 1] = (guchar *)text_part->utf_stripped_content->data;
				lenvec[i + 1] = text_part->utf_stripped_content->len;

				if (!IS_TEXT_PART_UTF (text_part)) {
					raw = TRUE;
				}
			}
			else {
				scvec[i + 1] = (guchar *)"";
				lenvec[i + 1] = 0;
			}
		}

		ret = rspamd_re_cache_process_regexp_data (rt, re,
				task, scvec, lenvec, cnt, raw, &processed_hyperscan);
		msg_debug_re_task ("checked sa body regexp: %s -> %d",
				rspamd_regexp_get_pattern (re), ret);
		g_free (scvec);
		g_free (lenvec);
		break;
	case RSPAMD_RE_SARAWBODY:
		/* According to SA docs:
		 * The 'raw body' of a message is the raw data inside all textual
		 * parts. The text will be decoded from base64 or quoted-printable
		 * encoding, but HTML tags and line breaks will still be present.
		 * Multiline expressions will need to be used to match strings that are
		 * broken by line breaks.
		 */
		if (MESSAGE_FIELD (task, text_parts)->len > 0) {
			cnt = MESSAGE_FIELD (task, text_parts)->len;
			scvec = g_malloc (sizeof (*scvec) * cnt);
			lenvec = g_malloc (sizeof (*lenvec) * cnt);

			for (i = 0; i < cnt; i++) {
				text_part = g_ptr_array_index (MESSAGE_FIELD (task, text_parts), i);

				if (text_part->parsed.len > 0) {
					scvec[i] = (guchar *)text_part->parsed.begin;
					lenvec[i] = text_part->parsed.len;

					if (!IS_TEXT_PART_UTF (text_part)) {
						raw = TRUE;
					}
				}
				else {
					scvec[i] = (guchar *)"";
					lenvec[i] = 0;
				}
			}

			ret = rspamd_re_cache_process_regexp_data (rt, re,
					task, scvec, lenvec, cnt, raw, &processed_hyperscan);
			msg_debug_re_task ("checked sa rawbody regexp: %s -> %d",
					rspamd_regexp_get_pattern (re), ret);
			g_free (scvec);
			g_free (lenvec);
		}
		break;
	case RSPAMD_RE_WORDS:
	case RSPAMD_RE_STEMWORDS:
	case RSPAMD_RE_RAWWORDS:
		if (MESSAGE_FIELD (task, text_parts)->len > 0) {
			cnt = 0;
			raw = FALSE;

			PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, text_part) {
				if (text_part->utf_words) {
					cnt += text_part->utf_words->len;
				}
			}

			if (task->meta_words && task->meta_words->len > 0) {
				cnt += task->meta_words->len;
			}

			if (cnt > 0) {
				scvec = g_malloc (sizeof (*scvec) * cnt);
				lenvec = g_malloc (sizeof (*lenvec) * cnt);

				cnt = 0;

				PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, text_part) {
					if (text_part->utf_words) {
						cnt = rspamd_process_words_vector (text_part->utf_words,
								scvec, lenvec, re_class, cnt, &raw);
					}
				}

				if (task->meta_words) {
					cnt = rspamd_process_words_vector (task->meta_words,
							scvec, lenvec, re_class, cnt, &raw);
				}

				ret = rspamd_re_cache_process_regexp_data (rt, re,
						task, scvec, lenvec, cnt, raw, &processed_hyperscan);

				msg_debug_re_task ("checked sa words regexp: %s -> %d",
						rspamd_regexp_get_pattern (re), ret);
				g_free (scvec);
				g_free (lenvec);
			}
		}
		break;
	case RSPAMD_RE_SELECTOR:
		if (rspamd_re_cache_process_selector (task, rt,
				re_class->type_data,
				(guchar ***)&scvec,
				&lenvec, &cnt)) {

			ret = rspamd_re_cache_process_regexp_data (rt, re,
					task, scvec, lenvec, cnt, raw, &processed_hyperscan);
			msg_debug_re_task ("checked selector(%s) regexp: %s -> %d",
					re_class->type_data,
					rspamd_regexp_get_pattern (re), ret);

			/* Do not free vectors as they are managed by rt->sel_cache */
		}
		break;
	case RSPAMD_RE_MAX:
		msg_err_task ("regexp of class invalid has been called: %s",
				rspamd_regexp_get_pattern (re));
		break;
	}

#if WITH_HYPERSCAN
	if (processed_hyperscan) {
		rspamd_re_cache_finish_class (task, rt, re_class, class_name);
	}
#endif

	setbit (rt->checked, re_id);

	return rt->results[re_id];
}

gint
rspamd_re_cache_process (struct rspamd_task *task,
		rspamd_regexp_t *re,
		enum rspamd_re_type type,
		gconstpointer type_data,
		gsize datalen,
		gboolean is_strong)
{
	guint64 re_id;
	struct rspamd_re_class *re_class;
	struct rspamd_re_cache *cache;
	struct rspamd_re_runtime *rt;

	g_assert (task != NULL);
	rt = task->re_rt;
	g_assert (rt != NULL);
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
		rt->stat.regexp_fast_cached ++;
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

int
rspamd_re_cache_process_ffi (void *ptask,
		void *pre,
		int type,
		void *type_data,
		int is_strong)
{
	struct rspamd_lua_regexp **lua_re = pre;
	struct rspamd_task **real_task = ptask;
	gsize typelen = 0;

	if (type_data) {
		typelen = strlen (type_data);
	}

	return rspamd_re_cache_process (*real_task, (*lua_re)->re,
			type, type_data, typelen, is_strong);
}

void
rspamd_re_cache_runtime_destroy (struct rspamd_re_runtime *rt)
{
	g_assert (rt != NULL);

	if (rt->sel_cache) {
		struct rspamd_re_selector_result sr;

		kh_foreach_value (rt->sel_cache, sr, {
			for (guint i = 0; i < sr.cnt; i ++) {
				g_free ((gpointer)sr.scvec[i]);
			}

			g_free (sr.scvec);
			g_free (sr.lenvec);
		});
		kh_destroy (selectors_results_hash, rt->sel_cache);
	}

	REF_RELEASE (rt->cache);
	g_free (rt);
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
	case RSPAMD_RE_MIMEHEADER:
		ret = "mime header";
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
	case RSPAMD_RE_EMAIL:
		ret = "email";
		break;
	case RSPAMD_RE_SABODY:
		ret = "sa body";
		break;
	case RSPAMD_RE_SARAWBODY:
		ret = "sa raw body";
		break;
	case RSPAMD_RE_SELECTOR:
		ret = "selector";
		break;
	case RSPAMD_RE_WORDS:
		ret = "words";
		break;
	case RSPAMD_RE_RAWWORDS:
		ret = "raw_words";
		break;
	case RSPAMD_RE_STEMWORDS:
		ret = "stem_words";
		break;
	case RSPAMD_RE_MAX:
	default:
		ret = "invalid class";
		break;
	}

	return ret;
}

enum rspamd_re_type
rspamd_re_cache_type_from_string (const char *str)
{
	enum rspamd_re_type ret;
	guint64 h;

	/*
	 * To optimize this function, we apply hash to input string and
	 * pre-select it from the values
	 */

	if (str != NULL) {
		h = rspamd_cryptobox_fast_hash_specific (RSPAMD_CRYPTOBOX_XXHASH64,
				str, strlen (str), 0xdeadbabe);

		switch (h) {
		case G_GUINT64_CONSTANT(0x298b9c8a58887d44): /* header */
			ret = RSPAMD_RE_HEADER;
			break;
		case G_GUINT64_CONSTANT(0x467bfb5cd7ddf890): /* rawheader */
			ret = RSPAMD_RE_RAWHEADER;
			break;
		case G_GUINT64_CONSTANT(0xda081341fb600389): /* mime */
			ret = RSPAMD_RE_MIME;
			break;
		case G_GUINT64_CONSTANT(0xc35831e067a8221d): /* rawmime */
			ret = RSPAMD_RE_RAWMIME;
			break;
		case G_GUINT64_CONSTANT(0xc625e13dbe636de2): /* body */
		case G_GUINT64_CONSTANT(0xCCDEBA43518F721C): /* message */
			ret = RSPAMD_RE_BODY;
			break;
		case G_GUINT64_CONSTANT(0x286edbe164c791d2): /* url */
		case G_GUINT64_CONSTANT(0x7D9ACDF6685661A1): /* uri */
			ret = RSPAMD_RE_URL;
			break;
		case G_GUINT64_CONSTANT (0x7e232b0f60b571be): /* email */
			ret = RSPAMD_RE_EMAIL;
			break;
		case G_GUINT64_CONSTANT(0x796d62205a8778c7): /* allheader */
			ret = RSPAMD_RE_ALLHEADER;
			break;
		case G_GUINT64_CONSTANT(0xa3c6c153b3b00a5e): /* mimeheader */
			ret = RSPAMD_RE_MIMEHEADER;
			break;
		case G_GUINT64_CONSTANT(0x7794501506e604e9): /* sabody */
			ret = RSPAMD_RE_SABODY;
			break;
		case G_GUINT64_CONSTANT(0x28828962E7D2A05F): /* sarawbody */
			ret = RSPAMD_RE_SARAWBODY;
			break;
		default:
			ret = RSPAMD_RE_MAX;
			break;
		}
	}
	else {
		ret = RSPAMD_RE_MAX;
	}

	return ret;
}

#ifdef WITH_HYPERSCAN
static gchar *
rspamd_re_cache_hs_pattern_from_pcre (rspamd_regexp_t *re)
{
	/*
	 * Workaroung for bug in ragel 7.0.0.11
	 * https://github.com/intel/hyperscan/issues/133
	 */
	const gchar *pat = rspamd_regexp_get_pattern (re);
	guint flags = rspamd_regexp_get_flags (re), esc_flags = RSPAMD_REGEXP_ESCAPE_RE;
	gchar *escaped;
	gsize esc_len;

	if (flags & RSPAMD_REGEXP_FLAG_UTF) {
		esc_flags |= RSPAMD_REGEXP_ESCAPE_UTF;
	}

	escaped = rspamd_str_regexp_escape (pat, strlen (pat), &esc_len,esc_flags);

	return escaped;
}

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
	void (*old_hdl)(int);

	wait_time = max_time / max_tries;
	/* We need to restore SIGCHLD processing */
	old_hdl = signal (SIGCHLD, SIG_DFL);
	cld = fork ();

	if (cld == 0) {
		/* Try to compile pattern */

		gchar *pat = rspamd_re_cache_hs_pattern_from_pcre (re);

		if (hs_compile (pat,
				flags | HS_FLAG_PREFILTER,
				cache->vectorized_hyperscan ? HS_MODE_VECTORED : HS_MODE_BLOCK,
				&cache->plt,
				&test_db,
				&hs_errors) != HS_SUCCESS) {

			msg_info_re_cache ("cannot compile (prefilter mode) '%s' to hyperscan: '%s'",
					pat,
					hs_errors != NULL ? hs_errors->message : "unknown error");

			hs_free_compile_error (hs_errors);
			g_free (pat);

			exit (EXIT_FAILURE);
		}

		g_free (pat);
		exit (EXIT_SUCCESS);
	}
	else if (cld > 0) {
		double_to_ts (wait_time, &ts);

		while ((rc = waitpid (cld, &status, WNOHANG)) == 0 && tries ++ < max_tries) {
			(void)nanosleep (&ts, NULL);
		}

		/* Child has been terminated */
		if (rc > 0) {
			/* Forget about SIGCHLD after this point */
			signal (SIGCHLD, old_hdl);

			if (WIFEXITED (status) && WEXITSTATUS (status) == EXIT_SUCCESS) {
				return TRUE;
			}
			else {
				msg_err_re_cache (
						"cannot approximate %s to hyperscan",
						rspamd_regexp_get_pattern (re));

				return FALSE;
			}
		}
		else {
			/* We consider that as timeout */
			kill (cld, SIGKILL);
			g_assert (waitpid (cld, &status, 0) != -1);
			msg_err_re_cache (
					"cannot approximate %s to hyperscan: timeout waiting",
					rspamd_regexp_get_pattern (re));
			signal (SIGCHLD, old_hdl);
		}
	}
	else {
		msg_err_re_cache (
				"cannot approximate %s to hyperscan: fork failed: %s",
				rspamd_regexp_get_pattern (re), strerror (errno));
		signal (SIGCHLD, old_hdl);
	}

	return FALSE;
}
#endif

#ifdef WITH_HYPERSCAN
struct rspamd_re_cache_hs_compile_cbdata {
	GHashTableIter it;
	struct rspamd_re_cache *cache;
	const char *cache_dir;
	gdouble max_time;
	gboolean silent;
	guint total;
	void (*cb)(guint ncompiled, GError *err, void *cbd);
	void *cbd;
};

static void
rspamd_re_cache_compile_err (EV_P_ ev_timer *w, GError *err,
		struct rspamd_re_cache_hs_compile_cbdata *cbdata, bool is_fatal)
{
	cbdata->cb (cbdata->total, err, cbdata->cbd);

	if (is_fatal) {
		ev_timer_stop(EV_A_ w);
		g_free(w);
		g_free(cbdata);
	}
	else {
		/* Continue compilation */
		ev_timer_again(EV_A_ w);
	}
	g_error_free (err);
}

static void
rspamd_re_cache_compile_timer_cb (EV_P_ ev_timer *w, int revents )
{
	struct rspamd_re_cache_hs_compile_cbdata *cbdata =
			(struct rspamd_re_cache_hs_compile_cbdata *)w->data;
	GHashTableIter cit;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	gchar path[PATH_MAX], npath[PATH_MAX];
	hs_database_t *test_db;
	gint fd, i, n, *hs_ids = NULL, pcre_flags, re_flags;
	rspamd_cryptobox_fast_hash_state_t crc_st;
	guint64 crc;
	rspamd_regexp_t *re;
	hs_compile_error_t *hs_errors = NULL;
	guint *hs_flags = NULL;
	const hs_expr_ext_t **hs_exts = NULL;
	gchar **hs_pats = NULL;
	gchar *hs_serialized = NULL;
	gsize serialized_len;
	struct iovec iov[7];
	struct rspamd_re_cache *cache;
	GError *err;
	pid_t our_pid = getpid ();

	cache = cbdata->cache;

	if (!g_hash_table_iter_next (&cbdata->it, &k, &v)) {
		/* All done */
		ev_timer_stop (EV_A_ w);
		cbdata->cb (cbdata->total, NULL, cbdata->cbd);
		g_free (w);
		g_free (cbdata);

		return;
	}

	re_class = v;
	rspamd_snprintf (path, sizeof (path), "%s%c%s.hs", cbdata->cache_dir,
			G_DIR_SEPARATOR, re_class->hash);

	if (rspamd_re_cache_is_valid_hyperscan_file (cache, path, TRUE, TRUE)) {

		fd = open (path, O_RDONLY, 00600);

		/* Read number of regexps */
		g_assert (fd != -1);
		g_assert (lseek (fd, RSPAMD_HS_MAGIC_LEN + sizeof (cache->plt), SEEK_SET) != -1);
		g_assert (read (fd, &n, sizeof (n)) == sizeof (n));
		close (fd);

		if (re_class->type_len > 0) {
			if (!cbdata->silent) {
				msg_info_re_cache (
						"skip already valid class %s(%*s) to cache %6s, %d regexps",
						rspamd_re_cache_type_to_string (re_class->type),
						(gint) re_class->type_len - 1,
						re_class->type_data,
						re_class->hash,
						n);
			}
		}
		else {
			if (!cbdata->silent) {
				msg_info_re_cache (
						"skip already valid class %s to cache %6s, %d regexps",
						rspamd_re_cache_type_to_string (re_class->type),
						re_class->hash,
						n);
			}
		}

		ev_timer_again (EV_A_ w);
		return;
	}

	rspamd_snprintf (path, sizeof (path), "%s%c%s.%P.hs.new", cbdata->cache_dir,
			G_DIR_SEPARATOR, re_class->hash, our_pid);
	fd = open (path, O_CREAT|O_TRUNC|O_EXCL|O_WRONLY, 00600);

	if (fd == -1) {
		err = g_error_new (rspamd_re_cache_quark (), errno,
				"cannot open file %s: %s", path, strerror (errno));
		rspamd_re_cache_compile_err (EV_A_ w, err, cbdata, false);
		return;
	}

	g_hash_table_iter_init (&cit, re_class->re);
	n = g_hash_table_size (re_class->re);
	hs_flags = g_malloc0 (sizeof (*hs_flags) * n);
	hs_ids = g_malloc (sizeof (*hs_ids) * n);
	hs_pats = g_malloc (sizeof (*hs_pats) * n);
	hs_exts = g_malloc0 (sizeof (*hs_exts) * n);
	i = 0;

	while (g_hash_table_iter_next (&cit, &k, &v)) {
		re = v;

		pcre_flags = rspamd_regexp_get_pcre_flags (re);
		re_flags = rspamd_regexp_get_flags (re);

		if (re_flags & RSPAMD_REGEXP_FLAG_PCRE_ONLY) {
			/* Do not try to compile bad regexp */
			msg_info_re_cache (
					"do not try compile %s to hyperscan as it is PCRE only",
					rspamd_regexp_get_pattern (re));
			continue;
		}

		hs_flags[i] = 0;
		hs_exts[i] = NULL;
#ifndef WITH_PCRE2
		if (pcre_flags & PCRE_FLAG(UTF8)) {
			hs_flags[i] |= HS_FLAG_UTF8;
		}
#else
		if (pcre_flags & PCRE_FLAG(UTF)) {
				hs_flags[i] |= HS_FLAG_UTF8;
			}
#endif
		if (pcre_flags & PCRE_FLAG(CASELESS)) {
			hs_flags[i] |= HS_FLAG_CASELESS;
		}
		if (pcre_flags & PCRE_FLAG(MULTILINE)) {
			hs_flags[i] |= HS_FLAG_MULTILINE;
		}
		if (pcre_flags & PCRE_FLAG(DOTALL)) {
			hs_flags[i] |= HS_FLAG_DOTALL;
		}


		if (re_flags & RSPAMD_REGEXP_FLAG_LEFTMOST) {
			hs_flags[i] |= HS_FLAG_SOM_LEFTMOST;
		}
		else if (rspamd_regexp_get_maxhits (re) == 1) {
			hs_flags[i] |= HS_FLAG_SINGLEMATCH;
		}

		gchar *pat = rspamd_re_cache_hs_pattern_from_pcre (re);

		if (hs_compile (pat,
				hs_flags[i],
				cache->vectorized_hyperscan ? HS_MODE_VECTORED : HS_MODE_BLOCK,
				&cache->plt,
				&test_db,
				&hs_errors) != HS_SUCCESS) {
			msg_info_re_cache ("cannot compile '%s' to hyperscan: '%s', try prefilter match",
					pat,
					hs_errors != NULL ? hs_errors->message : "unknown error");
			hs_free_compile_error (hs_errors);

			/* The approximation operation might take a significant
			 * amount of time, so we need to check if it's finite
			 */
			if (rspamd_re_cache_is_finite (cache, re, hs_flags[i], cbdata->max_time)) {
				hs_flags[i] |= HS_FLAG_PREFILTER;
				hs_ids[i] = rspamd_regexp_get_cache_id (re);
				hs_pats[i] = pat;
				i++;
			}
			else {
				g_free (pat); /* Avoid leak */
			}
		}
		else {
			hs_ids[i] = rspamd_regexp_get_cache_id (re);
			hs_pats[i] = pat;
			i ++;
			hs_free_database (test_db);
		}
	}
	/* Adjust real re number */
	n = i;

#define CLEANUP_ALLOCATED(is_err) do {    \
    g_free (hs_flags);                    \
    g_free (hs_ids);                    \
    for (guint j = 0; j < i; j ++) {    \
        g_free (hs_pats[j]);            \
    }                                    \
    g_free (hs_pats);                    \
    g_free (hs_exts);                    \
    if (is_err) {                         \
        close (fd);                            \
        unlink (path);                        \
        if (hs_errors) hs_free_compile_error (hs_errors); \
    }                                        \
} while(0)

	if (n > 0) {
		/* Create the hs tree */
		hs_errors = NULL;
		if (hs_compile_ext_multi ((const char **)hs_pats,
				hs_flags,
				hs_ids,
				hs_exts,
				n,
				cache->vectorized_hyperscan ? HS_MODE_VECTORED : HS_MODE_BLOCK,
				&cache->plt,
				&test_db,
				&hs_errors) != HS_SUCCESS) {

			err = g_error_new (rspamd_re_cache_quark (), EINVAL,
					"cannot create tree of regexp when processing '%s': %s",
					hs_pats[hs_errors->expression], hs_errors->message);
			CLEANUP_ALLOCATED(true);
			rspamd_re_cache_compile_err (EV_A_ w, err, cbdata, false);

			return;
		}

		if (hs_serialize_database (test_db, &hs_serialized,
				&serialized_len) != HS_SUCCESS) {
			err = g_error_new (rspamd_re_cache_quark (),
					errno,
					"cannot serialize tree of regexp for %s",
					re_class->hash);

			CLEANUP_ALLOCATED(true);
			hs_free_database (test_db);
			rspamd_re_cache_compile_err (EV_A_ w, err, cbdata, false);
			return;
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
		rspamd_cryptobox_fast_hash_init (&crc_st, 0xdeadbabe);
		/* IDs -> Flags -> Hs blob */
		rspamd_cryptobox_fast_hash_update (&crc_st,
				hs_ids, sizeof (*hs_ids) * n);
		rspamd_cryptobox_fast_hash_update (&crc_st,
				hs_flags, sizeof (*hs_flags) * n);
		rspamd_cryptobox_fast_hash_update (&crc_st,
				hs_serialized, serialized_len);
		crc = rspamd_cryptobox_fast_hash_final (&crc_st);

		if (cache->vectorized_hyperscan) {
			iov[0].iov_base = (void *) rspamd_hs_magic_vector;
		}
		else {
			iov[0].iov_base = (void *) rspamd_hs_magic;
		}

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
			err = g_error_new (rspamd_re_cache_quark (),
					errno,
					"cannot serialize tree of regexp to %s: %s",
					path, strerror (errno));

			CLEANUP_ALLOCATED(true);
			g_free (hs_serialized);

			rspamd_re_cache_compile_err (EV_A_ w, err, cbdata, false);
			return;
		}

		if (re_class->type_len > 0) {
			msg_info_re_cache (
					"compiled class %s(%*s) to cache %6s, %d/%d regexps",
					rspamd_re_cache_type_to_string (re_class->type),
					(gint) re_class->type_len - 1,
					re_class->type_data,
					re_class->hash,
					n,
					(gint)g_hash_table_size (re_class->re));
		}
		else {
			msg_info_re_cache (
					"compiled class %s to cache %6s, %d/%d regexps",
					rspamd_re_cache_type_to_string (re_class->type),
					re_class->hash,
					n,
					(gint)g_hash_table_size (re_class->re));
		}

		cbdata->total += n;
		CLEANUP_ALLOCATED(false);

		/* Now rename temporary file to the new .hs file */
		rspamd_snprintf (npath, sizeof (npath), "%s%c%s.hs", cbdata->cache_dir,
				G_DIR_SEPARATOR, re_class->hash);

		if (rename (path, npath) == -1) {
			err = g_error_new (rspamd_re_cache_quark (),
					errno,
					"cannot rename %s to %s: %s",
					path, npath, strerror (errno));
			unlink (path);
			close (fd);

			rspamd_re_cache_compile_err (EV_A_ w, err, cbdata, false);
			return;
		}

		close (fd);
	}
	else {
		err = g_error_new (rspamd_re_cache_quark (),
				errno,
				"no suitable regular expressions %s (%d original): "
				"remove temporary file %s",
				rspamd_re_cache_type_to_string (re_class->type),
				(gint)g_hash_table_size (re_class->re),
				path);

		CLEANUP_ALLOCATED(true);
		rspamd_re_cache_compile_err (EV_A_ w, err, cbdata, false);

		return;
	}

	/* Continue process */
	ev_timer_again (EV_A_ w);
}

#endif

gint
rspamd_re_cache_compile_hyperscan (struct rspamd_re_cache *cache,
								   const char *cache_dir,
								   gdouble max_time,
								   gboolean silent,
								   struct ev_loop *event_loop,
								   void (*cb)(guint ncompiled, GError *err, void *cbd),
								   void *cbd)
{
	g_assert (cache != NULL);
	g_assert (cache_dir != NULL);

#ifndef WITH_HYPERSCAN
	return -1;
#else
	static ev_timer *timer;
	static const ev_tstamp timer_interval = 0.1;
	struct rspamd_re_cache_hs_compile_cbdata *cbdata;

	cbdata = g_malloc0 (sizeof (*cbdata));
	g_hash_table_iter_init (&cbdata->it, cache->re_classes);
	cbdata->cache = cache;
	cbdata->cache_dir = cache_dir;
	cbdata->cb = cb;
	cbdata->cbd = cbd;
	cbdata->max_time = max_time;
	cbdata->silent = silent;
	cbdata->total = 0;
	timer = g_malloc0 (sizeof (*timer));
	timer->data = (void *)cbdata; /* static */

	ev_timer_init (timer, rspamd_re_cache_compile_timer_cb,
			timer_interval, timer_interval);
	ev_timer_start (event_loop, timer);

	return 0;
#endif
}

gboolean
rspamd_re_cache_is_valid_hyperscan_file (struct rspamd_re_cache *cache,
		const char *path, gboolean silent, gboolean try_load)
{
	g_assert (cache != NULL);
	g_assert (path != NULL);

#ifndef WITH_HYPERSCAN
	return FALSE;
#else
	gint fd, n, ret;
	guchar magicbuf[RSPAMD_HS_MAGIC_LEN];
	const guchar *mb;
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_re_class *re_class;
	gsize len;
	const gchar *hash_pos;
	hs_platform_info_t test_plt;
	hs_database_t *test_db = NULL;
	guchar *map, *p, *end;
	rspamd_cryptobox_fast_hash_state_t crc_st;
	guint64 crc, valid_crc;

	len = strlen (path);

	if (len < sizeof (rspamd_cryptobox_HASHBYTES + 3)) {
		if (!silent)  {
			msg_err_re_cache ("cannot open hyperscan cache file %s: too short filename",
					path);
		}
		return FALSE;
	}

	if (memcmp (path + len - 3, ".hs", 3) != 0) {
		if (!silent)  {
			msg_err_re_cache ("cannot open hyperscan cache file %s: not ending with .hs",
					path);
		}
		return FALSE;
	}

	hash_pos = path + len - 3 - (sizeof (re_class->hash) - 1);
	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;

		if (memcmp (hash_pos, re_class->hash, sizeof (re_class->hash) - 1) == 0) {
			/* Open file and check magic */
			gssize r;

			fd = open (path, O_RDONLY);

			if (fd == -1) {
				if (errno != ENOENT || !silent) {
					msg_err_re_cache ("cannot open hyperscan cache file %s: %s",
							path, strerror (errno));
				}
				return FALSE;
			}

			if ((r = read (fd, magicbuf, sizeof (magicbuf))) != sizeof (magicbuf)) {
				if (r == -1) {
					msg_err_re_cache ("cannot read magic from hyperscan "
									  "cache file %s: %s",
							path, strerror (errno));
				}
				else {
					msg_err_re_cache ("truncated read magic from hyperscan "
									  "cache file %s: %z, %z wanted",
							path, r, (gsize)sizeof (magicbuf));
				}
				close (fd);
				return FALSE;
			}

			if (cache->vectorized_hyperscan) {
				mb = rspamd_hs_magic_vector;
			}
			else {
				mb = rspamd_hs_magic;
			}

			if (memcmp (magicbuf, mb, sizeof (magicbuf)) != 0) {
				msg_err_re_cache ("cannot open hyperscan cache file %s: "
						"bad magic ('%*xs', '%*xs' expected)",
						path, (int) RSPAMD_HS_MAGIC_LEN, magicbuf,
						(int) RSPAMD_HS_MAGIC_LEN, mb);

				close (fd);
				return FALSE;
			}

			if ((r = read (fd, &test_plt, sizeof (test_plt))) != sizeof (test_plt)) {
				if (r == -1) {
					msg_err_re_cache ("cannot read platform data from hyperscan "
									  "cache file %s: %s",
							path, strerror (errno));
				}
				else {
					msg_err_re_cache ("truncated read platform data from hyperscan "
									  "cache file %s: %z, %z wanted",
							path, r, (gsize)sizeof (magicbuf));
				}

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

			close (fd);

			if (try_load) {
				map = rspamd_file_xmap (path, PROT_READ, &len, TRUE);

				if (map == NULL) {
					msg_err_re_cache ("cannot mmap hyperscan cache file %s: "
							"%s",
							path, strerror (errno));
					return FALSE;
				}

				p = map + RSPAMD_HS_MAGIC_LEN + sizeof (test_plt);
				end = map + len;
				n = *(gint *)p;
				p += sizeof (gint);

				if (n <= 0 || 2 * n * sizeof (gint) + /* IDs + flags */
						sizeof (guint64) + /* crc */
						RSPAMD_HS_MAGIC_LEN + /* header */
						sizeof (cache->plt) > len) {
					/* Some wrong amount of regexps */
					msg_err_re_cache ("bad number of expressions in %s: %d",
							path, n);
					munmap (map, len);
					return FALSE;
				}

				/*
				 * Magic - 8 bytes
				 * Platform - sizeof (platform)
				 * n - number of regexps
				 * n * <regexp ids>
				 * n * <regexp flags>
				 * crc - 8 bytes checksum
				 * <hyperscan blob>
				 */

				memcpy (&crc, p + n * 2 * sizeof (gint), sizeof (crc));
				rspamd_cryptobox_fast_hash_init (&crc_st, 0xdeadbabe);
				/* IDs */
				rspamd_cryptobox_fast_hash_update (&crc_st, p, n * sizeof (gint));
				/* Flags */
				rspamd_cryptobox_fast_hash_update (&crc_st, p + n * sizeof (gint),
						n * sizeof (gint));
				/* HS database */
				p += n * sizeof (gint) * 2 + sizeof (guint64);
				rspamd_cryptobox_fast_hash_update (&crc_st, p, end - p);
				valid_crc = rspamd_cryptobox_fast_hash_final (&crc_st);

				if (crc != valid_crc) {
					msg_warn_re_cache ("outdated or invalid hs database in %s: "
							"crc read %xL, crc expected %xL", path, crc, valid_crc);
					munmap (map, len);

					return FALSE;
				}

				if ((ret = hs_deserialize_database (p, end - p, &test_db))
						!= HS_SUCCESS) {
					msg_err_re_cache ("bad hs database in %s: %d", path, ret);
					munmap (map, len);

					return FALSE;
				}

				hs_free_database (test_db);
				munmap (map, len);
			}
			/* XXX: add crc check */

			return TRUE;
		}
	}

	if (!silent) {
		msg_warn_re_cache ("unknown hyperscan cache file %s", path);
	}

	return FALSE;
#endif
}


enum rspamd_hyperscan_status
rspamd_re_cache_load_hyperscan (struct rspamd_re_cache *cache,
		const char *cache_dir, bool try_load)
{
	g_assert (cache != NULL);
	g_assert (cache_dir != NULL);

#ifndef WITH_HYPERSCAN
	return RSPAMD_HYPERSCAN_UNSUPPORTED;
#else
	gchar path[PATH_MAX];
	gint fd, i, n, *hs_ids = NULL, *hs_flags = NULL, total = 0, ret;
	GHashTableIter it;
	gpointer k, v;
	guint8 *map, *p, *end;
	struct rspamd_re_class *re_class;
	struct rspamd_re_cache_elt *elt;
	struct stat st;
	gboolean has_valid = FALSE, all_valid = FALSE;

	g_hash_table_iter_init (&it, cache->re_classes);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		re_class = v;
		rspamd_snprintf (path, sizeof (path), "%s%c%s.hs", cache_dir,
				G_DIR_SEPARATOR, re_class->hash);

		if (rspamd_re_cache_is_valid_hyperscan_file (cache, path, try_load, FALSE)) {
			msg_debug_re_cache ("load hyperscan database from '%s'",
					re_class->hash);

			fd = open (path, O_RDONLY);

			/* Read number of regexps */
			g_assert (fd != -1);
			fstat (fd, &st);

			map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

			if (map == MAP_FAILED) {
				if (!try_load) {
					msg_err_re_cache ("cannot mmap %s: %s", path, strerror (errno));
				}
				else {
					msg_debug_re_cache ("cannot mmap %s: %s", path, strerror (errno));
				}

				close (fd);
				all_valid = FALSE;
				continue;
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
				if (!try_load) {
					msg_err_re_cache ("bad number of expressions in %s: %d",
							path, n);
				}
				else {
					msg_debug_re_cache ("bad number of expressions in %s: %d",
							path, n);
				}

				munmap (map, st.st_size);
				all_valid = FALSE;
				continue;
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

			/* Cleanup */
			if (re_class->hs_scratch != NULL) {
				hs_free_scratch (re_class->hs_scratch);
			}

			if (re_class->hs_db != NULL) {
				hs_free_database (re_class->hs_db);
			}

			if (re_class->hs_ids) {
				g_free (re_class->hs_ids);
			}

			re_class->hs_ids = NULL;
			re_class->hs_scratch = NULL;
			re_class->hs_db = NULL;

			if ((ret = hs_deserialize_database (p, end - p, &re_class->hs_db))
					!= HS_SUCCESS) {
				if (!try_load) {
					msg_err_re_cache ("bad hs database in %s: %d", path, ret);
				}
				else {
					msg_debug_re_cache ("bad hs database in %s: %d", path, ret);
				}
				munmap (map, st.st_size);
				g_free (hs_ids);
				g_free (hs_flags);

				re_class->hs_ids = NULL;
				re_class->hs_scratch = NULL;
				re_class->hs_db = NULL;
				all_valid = FALSE;

				continue;
			}

			munmap (map, st.st_size);

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

			if (!has_valid) {
				has_valid = TRUE;
				all_valid = TRUE;
			}
		}
		else {
			if (!try_load) {
				msg_err_re_cache ("invalid hyperscan hash file '%s'",
						path);
			}
			else {
				msg_debug_re_cache ("invalid hyperscan hash file '%s'",
						path);
			}
			all_valid = FALSE;
			continue;
		}
	}

	if (has_valid) {
		if (all_valid) {
			msg_info_re_cache ("full hyperscan database of %d regexps has been loaded", total);
			cache->hyperscan_loaded = RSPAMD_HYPERSCAN_LOADED_FULL;
		}
		else {
			msg_info_re_cache ("partial hyperscan database of %d regexps has been loaded", total);
			cache->hyperscan_loaded = RSPAMD_HYPERSCAN_LOADED_PARTIAL;
		}
	}
	else {
		msg_info_re_cache ("hyperscan database has NOT been loaded; no valid expressions");
		cache->hyperscan_loaded = RSPAMD_HYPERSCAN_LOAD_ERROR;
	}



	return cache->hyperscan_loaded;
#endif
}

void rspamd_re_cache_add_selector (struct rspamd_re_cache *cache,
								   const gchar *sname,
								   gint ref)
{
	khiter_t k;

	k = kh_get (lua_selectors_hash, cache->selectors, (gchar *)sname);

	if (k == kh_end (cache->selectors)) {
		gchar *cpy = g_strdup (sname);
		gint res;

		k = kh_put (lua_selectors_hash, cache->selectors, cpy, &res);

		kh_value (cache->selectors, k) = ref;
	}
	else {
		msg_warn_re_cache ("replacing selector with name %s", sname);

		if (cache->L) {
			luaL_unref (cache->L, LUA_REGISTRYINDEX, kh_value (cache->selectors, k));
		}

		kh_value (cache->selectors, k) = ref;
	}
}
