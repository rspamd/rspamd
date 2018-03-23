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
#include "util.h"
#include "rspamd.h"
#include "message.h"
#include "symbols_cache.h"
#include "cfg_file.h"
#include "lua/lua_common.h"
#include "unix-std.h"
#include "contrib/t1ha/t1ha.h"
#include "libserver/worker_util.h"
#include <math.h>

#define msg_err_cache(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        cache->static_pool->tag.tagname, cache->cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_cache(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        cache->static_pool->tag.tagname, cache->cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_cache(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        cache->static_pool->tag.tagname, cache->cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_cache(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_symcache_log_id, "symcache", cache->cfg->checksum, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(symcache)

static const guchar rspamd_symbols_cache_magic[8] = {'r', 's', 'c', 2, 0, 0, 0, 0 };

static gint rspamd_symbols_cache_find_symbol_parent (struct symbols_cache *cache,
		const gchar *name);

struct rspamd_symbols_cache_header {
	guchar magic[8];
	guint nitems;
	guchar checksum[64];
	guchar unused[128];
};

struct symbols_cache_order {
	GPtrArray *d;
	ref_entry_t ref;
};

struct symbols_cache {
	/* Hash table for fast access */
	GHashTable *items_by_symbol;
	struct symbols_cache_order *items_by_order;
	GPtrArray *items_by_id;
	GPtrArray *prefilters;
	GPtrArray *postfilters;
	GPtrArray *composites;
	GPtrArray *idempotent;
	GList *delayed_deps;
	GList *delayed_conditions;
	rspamd_mempool_t *static_pool;
	guint64 cksum;
	gdouble total_weight;
	guint used_items;
	guint stats_symbols_count;
	guint64 total_hits;
	struct rspamd_config *cfg;
	gdouble reload_time;
	gint peak_cb;
};

struct counter_data {
	gdouble mean;
	gdouble stddev;
	guint64 number;
};

struct item_stat {
	struct counter_data time_counter;
	gdouble avg_time;
	gdouble weight;
	guint hits;
	guint64 total_hits;
	struct counter_data frequency_counter;
	gdouble avg_frequency;
	gdouble stddev_frequency;
};

struct cache_item {
	/* This block is likely shared */
	struct item_stat *st;

	guint64 last_count;

	/* Per process counter */
	struct counter_data *cd;
	gchar *symbol;
	enum rspamd_symbol_type type;

	/* Callback data */
	symbol_func_t func;
	gpointer user_data;

	/* Condition of execution */
	gint condition_cb;
	gboolean enabled;

	/* Parent symbol id for virtual symbols */
	gint parent;
	/* Priority */
	gint priority;
	gint id;
	gint frequency_peaks;

	/* Dependencies */
	GPtrArray *deps;
	GPtrArray *rdeps;
};

struct cache_dependency {
	struct cache_item *item;
	gchar *sym;
	gint id;
};

struct delayed_cache_dependency {
	gchar *from;
	gchar *to;
};

struct delayed_cache_condition {
	gchar *sym;
	gint cbref;
	lua_State *L;
};

enum rspamd_cache_savepoint_stage {
	RSPAMD_CACHE_PASS_INIT = 0,
	RSPAMD_CACHE_PASS_PREFILTERS,
	RSPAMD_CACHE_PASS_WAIT_PREFILTERS,
	RSPAMD_CACHE_PASS_FILTERS,
	RSPAMD_CACHE_PASS_WAIT_FILTERS,
	RSPAMD_CACHE_PASS_POSTFILTERS,
	RSPAMD_CACHE_PASS_WAIT_POSTFILTERS,
	RSPAMD_CACHE_PASS_IDEMPOTENT,
	RSPAMD_CACHE_PASS_WAIT_IDEMPOTENT,
	RSPAMD_CACHE_PASS_DONE,
};

struct cache_savepoint {
	guchar *processed_bits;
	enum rspamd_cache_savepoint_stage pass;
	guint version;
	struct rspamd_metric_result *rs;
	gdouble lim;
	GPtrArray *waitq;
	struct symbols_cache_order *order;
};

struct rspamd_cache_refresh_cbdata {
	gdouble last_resort;
	struct event resort_ev;
	struct symbols_cache *cache;
	struct rspamd_worker *w;
	struct event_base *ev_base;
};

/* weight, frequency, time */
#define TIME_ALPHA (1.0)
#define WEIGHT_ALPHA (0.1)
#define FREQ_ALPHA (0.01)
#define SCORE_FUN(w, f, t) (((w) > 0 ? (w) : WEIGHT_ALPHA) \
		* ((f) > 0 ? (f) : FREQ_ALPHA) \
		/ (t > TIME_ALPHA ? t : TIME_ALPHA))

static gboolean rspamd_symbols_cache_check_symbol (struct rspamd_task *task,
		struct symbols_cache *cache,
		struct cache_item *item,
		struct cache_savepoint *checkpoint,
		gdouble *total_diff);
static gboolean rspamd_symbols_cache_check_deps (struct rspamd_task *task,
		struct symbols_cache *cache,
		struct cache_item *item,
		struct cache_savepoint *checkpoint,
		guint recursion,
		gboolean check_only);
static void rspamd_symbols_cache_disable_symbol_checkpoint (struct rspamd_task *task,
		struct symbols_cache *cache, const gchar *symbol);
static void rspamd_symbols_cache_enable_symbol_checkpoint (struct rspamd_task *task,
		struct symbols_cache *cache, const gchar *symbol);
static void rspamd_symbols_cache_disable_all_symbols (struct rspamd_task *task,
		struct symbols_cache *cache);

static GQuark
rspamd_symbols_cache_quark (void)
{
	return g_quark_from_static_string ("symbols-cache");
}

static void
rspamd_symbols_cache_order_dtor (gpointer p)
{
	struct symbols_cache_order *ord = p;

	g_ptr_array_free (ord->d, TRUE);
	g_free (ord);
}

static void
rspamd_symbols_cache_order_unref (gpointer p)
{
	struct symbols_cache_order *ord = p;

	REF_RELEASE (ord);
}

static struct symbols_cache_order *
rspamd_symbols_cache_order_new (gsize nelts)
{
	struct symbols_cache_order *ord;

	ord = g_malloc0 (sizeof (*ord));
	ord->d = g_ptr_array_sized_new (nelts);
	REF_INIT_RETAIN (ord, rspamd_symbols_cache_order_dtor);

	return ord;
}

static gint
postfilters_cmp (const void *p1, const void *p2, gpointer ud)
{
	const struct cache_item *i1 = *(struct cache_item **)p1,
			*i2 = *(struct cache_item **)p2;
	double w1, w2;

	w1 = i1->priority;
	w2 = i2->priority;

	if (w1 > w2) {
		return 1;
	}
	else if (w1 < w2) {
		return -1;
	}

	return 0;
}

static gint
prefilters_cmp (const void *p1, const void *p2, gpointer ud)
{
	const struct cache_item *i1 = *(struct cache_item **)p1,
			*i2 = *(struct cache_item **)p2;
	double w1, w2;

	w1 = i1->priority;
	w2 = i2->priority;

	if (w1 < w2) {
		return 1;
	}
	else if (w1 > w2) {
		return -1;
	}

	return 0;
}

static gint
cache_logic_cmp (const void *p1, const void *p2, gpointer ud)
{
	const struct cache_item *i1 = *(struct cache_item **)p1,
			*i2 = *(struct cache_item **)p2;
	struct symbols_cache *cache = ud;
	double w1, w2;
	double weight1, weight2;
	double f1 = 0, f2 = 0, t1, t2, avg_freq, avg_weight;

	if (i1->deps->len != 0 || i2->deps->len != 0) {
		/* TODO: handle complex dependencies */
		w1 = 1.0;
		w2 = 1.0;

		if (i1->deps->len != 0) {
			w1 = 1.0 / (i1->deps->len);
		}
		if (i2->deps->len != 0) {
			w2 = 1.0 / (i2->deps->len);
		}
	}
	else if (i1->priority == i2->priority) {
		avg_freq = ((gdouble)cache->total_hits / cache->used_items);
		avg_weight = (cache->total_weight / cache->used_items);
		f1 = (double)i1->st->total_hits / avg_freq;
		f2 = (double)i2->st->total_hits / avg_freq;
		weight1 = fabs (i1->st->weight) / avg_weight;
		weight2 = fabs (i2->st->weight) / avg_weight;
		t1 = i1->st->avg_time;
		t2 = i2->st->avg_time;
		w1 = SCORE_FUN (weight1, f1, t1);
		w2 = SCORE_FUN (weight2, f2, t2);
	}
	else {
		/* Strict sorting */
		w1 = abs (i1->priority);
		w2 = abs (i2->priority);
	}

	if (w2 > w1) {
		return 1;
	}
	else if (w2 < w1) {
		return -1;
	}

	return 0;
}

/**
 * Set counter for a symbol
 */
static double
rspamd_set_counter (struct counter_data *cd, gdouble value)
{
	gdouble cerr;

	/* Cumulative moving average using per-process counter data */
	if (cd->number == 0) {
		cd->mean = 0;
		cd->stddev = 0;
	}

	cd->mean += (value - cd->mean) / (gdouble)(++cd->number);
	cerr = (value - cd->mean) * (value - cd->mean);
	cd->stddev += (cerr - cd->stddev) / (gdouble)(cd->number);

	return cd->mean;
}

static void
rspamd_symbols_cache_resort (struct symbols_cache *cache)
{
	struct symbols_cache_order *ord;
	guint i;
	guint64 total_hits = 0;
	struct cache_item *it;

	ord = rspamd_symbols_cache_order_new (cache->used_items);

	for (i = 0; i < cache->used_items; i ++) {
		it = g_ptr_array_index (cache->items_by_id, i);
		total_hits += it->st->total_hits;

		if (!(it->type & (SYMBOL_TYPE_PREFILTER|
				SYMBOL_TYPE_POSTFILTER|
				SYMBOL_TYPE_COMPOSITE))) {
			g_ptr_array_add (ord->d, it);
		}
	}

	cache->total_hits = total_hits;
	g_ptr_array_sort_with_data (ord->d, cache_logic_cmp, cache);

	if (cache->items_by_order) {
		REF_RELEASE (cache->items_by_order);
	}

	cache->items_by_order = ord;
}

/* Sort items in logical order */
static void
rspamd_symbols_cache_post_init (struct symbols_cache *cache)
{
	struct cache_item *it, *dit;
	struct cache_dependency *dep, *rdep;
	struct delayed_cache_dependency *ddep;
	struct delayed_cache_condition *dcond;
	GList *cur;
	guint i, j;
	gint id;

	rspamd_symbols_cache_resort (cache);

	cur = cache->delayed_deps;
	while (cur) {
		ddep = cur->data;

		id = rspamd_symbols_cache_find_symbol_parent (cache, ddep->from);
		if (id != -1) {
			it = g_ptr_array_index (cache->items_by_id, id);
		}
		else {
			it = NULL;
		}

		if (it == NULL) {
			msg_err_cache ("cannot register delayed dependency between %s and %s, "
					"%s is missing", ddep->from, ddep->to, ddep->from);
		}
		else {
			msg_debug_cache ("delayed between %s(%d) -> %s", ddep->from,
					it->id, ddep->to);
			rspamd_symbols_cache_add_dependency (cache, it->id, ddep->to);
		}

		cur = g_list_next (cur);
	}

	cur = cache->delayed_conditions;
	while (cur) {
		dcond = cur->data;

		id = rspamd_symbols_cache_find_symbol_parent (cache, dcond->sym);
		if (id != -1) {
			it = g_ptr_array_index (cache->items_by_id, id);
		}
		else {
			it = NULL;
		}

		if (it == NULL) {
			msg_err_cache (
					"cannot register delayed condition for %s",
					dcond->sym);
			luaL_unref (dcond->L, LUA_REGISTRYINDEX, dcond->cbref);
		}
		else {
			rspamd_symbols_cache_add_condition (cache, it->id, dcond->L,
					dcond->cbref);
		}

		cur = g_list_next (cur);
	}

	for (i = 0; i < cache->items_by_id->len; i ++) {
		it = g_ptr_array_index (cache->items_by_id, i);

		for (j = 0; j < it->deps->len; j ++) {
			dep = g_ptr_array_index (it->deps, j);
			dit = g_hash_table_lookup (cache->items_by_symbol, dep->sym);

			if (dit != NULL) {
				if (dit->parent != -1) {
					dit = g_ptr_array_index (cache->items_by_id, dit->parent);
				}

				if (dit->id == i) {
					msg_err_cache ("cannot add dependency on self: %s -> %s "
							"(resolved to %s)",
							it->symbol, dep->sym, dit->symbol);
				}
				else {
					rdep = rspamd_mempool_alloc (cache->static_pool,
							sizeof (*rdep));
					rdep->sym = dep->sym;
					rdep->item = it;
					rdep->id = i;
					g_ptr_array_add (dit->rdeps, rdep);
					dep->item = dit;
					dep->id = dit->id;

					msg_debug_cache ("add dependency from %d on %d", it->id,
							dit->id);
				}
			}
			else {
				msg_err_cache ("cannot find dependency on symbol %s", dep->sym);
			}
		}
	}

	g_ptr_array_sort_with_data (cache->prefilters, prefilters_cmp, cache);
	g_ptr_array_sort_with_data (cache->postfilters, postfilters_cmp, cache);
	g_ptr_array_sort_with_data (cache->idempotent, postfilters_cmp, cache);
}

static gboolean
rspamd_symbols_cache_load_items (struct symbols_cache *cache, const gchar *name)
{
	struct rspamd_symbols_cache_header *hdr;
	struct stat st;
	struct ucl_parser *parser;
	ucl_object_t *top;
	const ucl_object_t *cur, *elt;
	ucl_object_iter_t it;
	struct cache_item *item, *parent;
	const guchar *p;
	gint fd;
	gpointer map;

	fd = open (name, O_RDONLY);

	if (fd == -1) {
		msg_info_cache ("cannot open file %s, error %d, %s", name,
			errno, strerror (errno));
		return FALSE;
	}

	rspamd_file_lock (fd, FALSE);

	if (fstat (fd, &st) == -1) {
		rspamd_file_unlock (fd, FALSE);
		close (fd);
		msg_info_cache ("cannot stat file %s, error %d, %s", name,
				errno, strerror (errno));
		return FALSE;
	}

	if (st.st_size < (gint)sizeof (*hdr)) {
		rspamd_file_unlock (fd, FALSE);
		close (fd);
		errno = EINVAL;
		msg_info_cache ("cannot use file %s, error %d, %s", name,
				errno, strerror (errno));
		return FALSE;
	}

	map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

	if (map == MAP_FAILED) {
		rspamd_file_unlock (fd, FALSE);
		close (fd);
		msg_info_cache ("cannot mmap file %s, error %d, %s", name,
				errno, strerror (errno));
		return FALSE;
	}

	hdr = map;

	if (memcmp (hdr->magic, rspamd_symbols_cache_magic,
			sizeof (rspamd_symbols_cache_magic)) != 0) {
		msg_info_cache ("cannot use file %s, bad magic", name);
		munmap (map, st.st_size);
		rspamd_file_unlock (fd, FALSE);
		close (fd);

		return FALSE;
	}

	parser = ucl_parser_new (0);
	p = (const guchar *)(hdr + 1);

	if (!ucl_parser_add_chunk (parser, p, st.st_size - sizeof (*hdr))) {
		msg_info_cache ("cannot use file %s, cannot parse: %s", name,
				ucl_parser_get_error (parser));
		munmap (map, st.st_size);
		ucl_parser_free (parser);
		rspamd_file_unlock (fd, FALSE);
		close (fd);

		return FALSE;
	}

	top = ucl_parser_get_object (parser);
	munmap (map, st.st_size);
	rspamd_file_unlock (fd, FALSE);
	close (fd);
	ucl_parser_free (parser);

	if (top == NULL || ucl_object_type (top) != UCL_OBJECT) {
		msg_info_cache ("cannot use file %s, bad object", name);
		ucl_object_unref (top);
		return FALSE;
	}

	it = ucl_object_iterate_new (top);

	while ((cur = ucl_object_iterate_safe (it, true))) {
		item = g_hash_table_lookup (cache->items_by_symbol, ucl_object_key (cur));

		if (item) {
			/* Copy saved info */
			/*
			 * XXX: don't save or load weight, it should be obtained from the
			 * metric
			 */
#if 0
			elt = ucl_object_lookup (cur, "weight");

			if (elt) {
				w = ucl_object_todouble (elt);
				if (w != 0) {
					item->weight = w;
				}
			}
#endif
			elt = ucl_object_lookup (cur, "time");
			if (elt) {
				item->st->avg_time = ucl_object_todouble (elt);
			}

			elt = ucl_object_lookup (cur, "count");
			if (elt) {
				item->st->total_hits = ucl_object_toint (elt);
				item->last_count = item->st->total_hits;
			}

			elt = ucl_object_lookup (cur, "frequency");
			if (elt && ucl_object_type (elt) == UCL_OBJECT) {
				const ucl_object_t *cur;

				cur = ucl_object_lookup (elt, "avg");

				if (cur) {
					item->st->avg_frequency = ucl_object_todouble (cur);
				}
				cur = ucl_object_lookup (elt, "stddev");

				if (cur) {
					item->st->stddev_frequency = ucl_object_todouble (cur);
				}
			}

			if ((item->type & SYMBOL_TYPE_VIRTUAL) &&
					!(item->type & SYMBOL_TYPE_SQUEEZED) && item->parent != -1) {
				g_assert (item->parent < (gint)cache->items_by_id->len);
				parent = g_ptr_array_index (cache->items_by_id, item->parent);

				if (parent->st->weight < item->st->weight) {
					parent->st->weight = item->st->weight;
				}

				/*
				 * We maintain avg_time for virtual symbols equal to the
				 * parent item avg_time
				 */
				item->st->avg_time = parent->st->avg_time;
			}

			cache->total_weight += fabs (item->st->weight);
			cache->total_hits += item->st->total_hits;
		}
	}

	ucl_object_iterate_free (it);
	ucl_object_unref (top);

	return TRUE;
}

#define ROUND_DOUBLE(x) (floor((x) * 100.0) / 100.0)

static gboolean
rspamd_symbols_cache_save_items (struct symbols_cache *cache, const gchar *name)
{
	struct rspamd_symbols_cache_header hdr;
	ucl_object_t *top, *elt, *freq;
	GHashTableIter it;
	struct cache_item *item;
	struct ucl_emitter_functions *efunc;
	gpointer k, v;
	gint fd;
	bool ret;

	(void)unlink (name);
	fd = open (name, O_CREAT | O_TRUNC | O_WRONLY | O_EXCL, 00644);

	if (fd == -1) {
		msg_info_cache ("cannot open file %s, error %d, %s", name,
				errno, strerror (errno));
		return FALSE;
	}

	rspamd_file_lock (fd, FALSE);

	memset (&hdr, 0, sizeof (hdr));
	memcpy (hdr.magic, rspamd_symbols_cache_magic,
			sizeof (rspamd_symbols_cache_magic));

	if (write (fd, &hdr, sizeof (hdr)) == -1) {
		msg_info_cache ("cannot write to file %s, error %d, %s", name,
				errno, strerror (errno));
		rspamd_file_unlock (fd, FALSE);
		close (fd);

		return FALSE;
	}

	top = ucl_object_typed_new (UCL_OBJECT);
	g_hash_table_iter_init (&it, cache->items_by_symbol);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		item = v;
		elt = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (elt,
				ucl_object_fromdouble (ROUND_DOUBLE (item->st->weight)),
				"weight", 0, false);
		ucl_object_insert_key (elt,
				ucl_object_fromdouble (ROUND_DOUBLE (item->st->time_counter.mean)),
				"time", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromint (item->st->total_hits),
				"count", 0, false);

		freq = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (freq,
				ucl_object_fromdouble (ROUND_DOUBLE (item->st->frequency_counter.mean)),
				"avg", 0, false);
		ucl_object_insert_key (freq,
				ucl_object_fromdouble (ROUND_DOUBLE (item->st->frequency_counter.stddev)),
				"stddev", 0, false);
		ucl_object_insert_key (elt, freq, "frequency", 0, false);

		ucl_object_insert_key (top, elt, k, 0, false);
	}

	efunc = ucl_object_emit_fd_funcs (fd);
	ret = ucl_object_emit_full (top, UCL_EMIT_JSON_COMPACT, efunc, NULL);
	ucl_object_emit_funcs_free (efunc);
	ucl_object_unref (top);
	rspamd_file_unlock (fd, FALSE);
	close (fd);

	return ret;
}

#undef ROUND_DOUBLE

gint
rspamd_symbols_cache_add_symbol (struct symbols_cache *cache,
	const gchar *name,
	gint priority,
	symbol_func_t func,
	gpointer user_data,
	enum rspamd_symbol_type type,
	gint parent)
{
	struct cache_item *item = NULL;

	g_assert (cache != NULL);

	if (name == NULL && !(type & SYMBOL_TYPE_CALLBACK)) {
		msg_warn_cache ("no name for non-callback symbol!");
	}
	else if ((type & SYMBOL_TYPE_VIRTUAL) && parent == -1) {
		msg_warn_cache ("no parent symbol is associated with virtual symbol %s",
			name);
	}

	if (name != NULL && !(type & SYMBOL_TYPE_CALLBACK)) {
		if (g_hash_table_lookup (cache->items_by_symbol, name) != NULL) {
			msg_err_cache ("skip duplicate symbol registration for %s", name);
			return -1;
		}
	}

	if (type & (SYMBOL_TYPE_CLASSIFIER|SYMBOL_TYPE_CALLBACK|
			SYMBOL_TYPE_PREFILTER|SYMBOL_TYPE_POSTFILTER|
			SYMBOL_TYPE_IDEMPOTENT)) {
		type |= SYMBOL_TYPE_NOSTAT;
	}

	item = rspamd_mempool_alloc0 (cache->static_pool,
			sizeof (struct cache_item));
	item->st = rspamd_mempool_alloc0_shared (cache->static_pool,
			sizeof (*item->st));
	item->condition_cb = -1;
	item->enabled = TRUE;

	/*
	 * We do not share cd to skip locking, instead we'll just calculate it on
	 * save or accumulate
	 */
	item->cd = rspamd_mempool_alloc0 (cache->static_pool,
			sizeof (struct counter_data));
	item->func = func;
	item->user_data = user_data;
	item->priority = priority;
	item->type = type;

	if ((type & SYMBOL_TYPE_FINE) && item->priority == 0) {
		/* Make priority for negative weighted symbols */
		item->priority = 1;
	}

	item->id = cache->used_items;
	item->parent = parent;
	cache->used_items ++;

	if (!(item->type &
			(SYMBOL_TYPE_IDEMPOTENT|SYMBOL_TYPE_NOSTAT|SYMBOL_TYPE_CLASSIFIER))) {
		if (name != NULL) {
			cache->cksum = t1ha (name, strlen (name),
					cache->cksum);
		} else {
			cache->cksum = t1ha (&item->id, sizeof (item->id),
					cache->cksum);
		}

		cache->stats_symbols_count ++;
	}

	if (name != NULL) {
		item->symbol = rspamd_mempool_strdup (cache->static_pool, name);
		msg_debug_cache ("used items: %d, added symbol: %s, %d",
				cache->used_items, name, item->id);
	} else {
		msg_debug_cache ("used items: %d, added unnamed symbol: %d",
				cache->used_items, item->id);
	}

	g_ptr_array_add (cache->items_by_id, item);
	item->deps = g_ptr_array_new ();
	item->rdeps = g_ptr_array_new ();
	rspamd_mempool_add_destructor (cache->static_pool,
			rspamd_ptr_array_free_hard, item->deps);
	rspamd_mempool_add_destructor (cache->static_pool,
			rspamd_ptr_array_free_hard, item->rdeps);

	if (name != NULL) {
		g_hash_table_insert (cache->items_by_symbol, item->symbol, item);
	}

	if (item->type & SYMBOL_TYPE_PREFILTER) {
		g_ptr_array_add (cache->prefilters, item);
	}
	else if (item->type & SYMBOL_TYPE_IDEMPOTENT) {
		g_ptr_array_add (cache->idempotent, item);
	}
	else if (item->type & SYMBOL_TYPE_POSTFILTER) {
		g_ptr_array_add (cache->postfilters, item);
	}
	else if (item->type & SYMBOL_TYPE_COMPOSITE) {
		g_ptr_array_add (cache->composites, item);
	}

	return item->id;
}

gboolean
rspamd_symbols_cache_add_condition (struct symbols_cache *cache, gint id,
		lua_State *L, gint cbref)
{
	struct cache_item *item;

	g_assert (cache != NULL);

	if (id < 0 || id >= (gint)cache->items_by_id->len) {
		return FALSE;
	}

	item = g_ptr_array_index (cache->items_by_id, id);

	if (item->condition_cb != -1) {
		/* We already have a condition, so we need to remove old cbref first */
		msg_warn_cache ("rewriting condition for symbol %s", item->symbol);
		luaL_unref (L, LUA_REGISTRYINDEX, item->condition_cb);
	}

	item->condition_cb = cbref;

	msg_debug_cache ("adding condition at lua ref %d to %s (%d)",
			cbref, item->symbol, item->id);

	return TRUE;
}

void
rspamd_symbols_cache_set_peak_callback (struct symbols_cache *cache,
		gint cbref)
{
	g_assert (cache != NULL);

	if (cache->peak_cb != -1) {
		luaL_unref (cache->cfg->lua_state, LUA_REGISTRYINDEX,
				cache->peak_cb);
	}

	cache->peak_cb = cbref;
	msg_info_cache ("registered peak callback");
}

gboolean
rspamd_symbols_cache_add_condition_delayed (struct symbols_cache *cache,
		const gchar *sym, lua_State *L, gint cbref)
{
	gint id;
	struct delayed_cache_condition *ncond;

	g_assert (cache != NULL);
	g_assert (sym != NULL);

	id = rspamd_symbols_cache_find_symbol_parent (cache, sym);

	if (id != -1) {
		/* We already know id, so just register a direct condition */
		return rspamd_symbols_cache_add_condition (cache, id, L, cbref);
	}

	ncond = g_malloc0 (sizeof (*ncond));
	ncond->sym = g_strdup (sym);
	ncond->cbref = cbref;
	ncond->L = L;

	cache->delayed_conditions = g_list_prepend (cache->delayed_conditions, ncond);

	return TRUE;
}

void
rspamd_symbols_cache_save (struct symbols_cache *cache)
{
	if (cache != NULL) {

		if (cache->cfg->cache_filename) {
			/* Try to sync values to the disk */
			if (!rspamd_symbols_cache_save_items (cache,
					cache->cfg->cache_filename)) {
				msg_err_cache ("cannot save cache data to %s",
						cache->cfg->cache_filename);
			}
		}
	}
}

void
rspamd_symbols_cache_destroy (struct symbols_cache *cache)
{
	GList *cur;
	struct delayed_cache_dependency *ddep;
	struct delayed_cache_condition *dcond;

	if (cache != NULL) {
		rspamd_symbols_cache_save (cache);

		if (cache->delayed_deps) {
			cur = cache->delayed_deps;

			while (cur) {
				ddep = cur->data;
				g_free (ddep->from);
				g_free (ddep->to);
				g_free (ddep);
				cur = g_list_next (cur);
			}

			g_list_free (cache->delayed_deps);
		}

		if (cache->delayed_conditions) {
			cur = cache->delayed_conditions;

			while (cur) {
				dcond = cur->data;
				g_free (dcond->sym);
				g_free (dcond);
				cur = g_list_next (cur);
			}

			g_list_free (cache->delayed_conditions);
		}

		g_hash_table_destroy (cache->items_by_symbol);
		rspamd_mempool_delete (cache->static_pool);
		g_ptr_array_free (cache->items_by_id, TRUE);
		g_ptr_array_free (cache->prefilters, TRUE);
		g_ptr_array_free (cache->postfilters, TRUE);
		g_ptr_array_free (cache->idempotent, TRUE);
		g_ptr_array_free (cache->composites, TRUE);
		REF_RELEASE (cache->items_by_order);

		if (cache->peak_cb != -1) {
			luaL_unref (cache->cfg->lua_state, LUA_REGISTRYINDEX, cache->peak_cb);
		}

		g_free (cache);
	}
}

struct symbols_cache*
rspamd_symbols_cache_new (struct rspamd_config *cfg)
{
	struct symbols_cache *cache;

	cache = g_malloc0 (sizeof (struct symbols_cache));
	cache->static_pool =
			rspamd_mempool_new (rspamd_mempool_suggest_size (), "symcache");
	cache->items_by_symbol = g_hash_table_new (rspamd_str_hash,
			rspamd_str_equal);
	cache->items_by_id = g_ptr_array_new ();
	cache->prefilters = g_ptr_array_new ();
	cache->postfilters = g_ptr_array_new ();
	cache->idempotent = g_ptr_array_new ();
	cache->composites = g_ptr_array_new ();
	cache->reload_time = cfg->cache_reload_time;
	cache->total_hits = 1;
	cache->total_weight = 1.0;
	cache->cfg = cfg;
	cache->cksum = 0xdeadbabe;
	cache->peak_cb = -1;

	return cache;
}

gboolean
rspamd_symbols_cache_init (struct symbols_cache* cache)
{
	gboolean res;

	g_assert (cache != NULL);

	cache->reload_time = cache->cfg->cache_reload_time;

	/* Just in-memory cache */
	if (cache->cfg->cache_filename == NULL) {
		rspamd_symbols_cache_post_init (cache);
		return TRUE;
	}

	/* Copy saved cache entries */
	res = rspamd_symbols_cache_load_items (cache, cache->cfg->cache_filename);
	rspamd_symbols_cache_post_init (cache);

	return res;
}


static void
rspamd_symbols_cache_validate_cb (gpointer k, gpointer v, gpointer ud)
{
	struct cache_item *item = v, *parent;
	struct rspamd_config *cfg;
	struct symbols_cache *cache = (struct symbols_cache *)ud;
	struct rspamd_symbol *s;
	gboolean skipped, ghost;
	gint p1, p2;

	ghost = item->st->weight == 0 ? TRUE : FALSE;
	cfg = cache->cfg;

	/* Check whether this item is skipped */
	skipped = !ghost;
	g_assert (cfg != NULL);

	if ((item->type &
			(SYMBOL_TYPE_NORMAL|SYMBOL_TYPE_VIRTUAL|SYMBOL_TYPE_COMPOSITE|SYMBOL_TYPE_CLASSIFIER))
			&& g_hash_table_lookup (cfg->symbols, item->symbol) == NULL) {

		if (cfg->unknown_weight != 0) {

			skipped = FALSE;
			item->st->weight = cfg->unknown_weight;
			s = rspamd_mempool_alloc0 (cache->static_pool,
					sizeof (*s));
			s->name = item->symbol;
			s->weight_ptr = &item->st->weight;
			g_hash_table_insert (cfg->symbols, item->symbol, s);

			msg_info_cache ("adding unknown symbol %s", item->symbol);
			ghost = FALSE;
		}
		else {
			skipped = TRUE;
		}
	}
	else {
		skipped = FALSE;
	}

	if (!ghost && skipped) {
		item->type |= SYMBOL_TYPE_SKIPPED;
		msg_warn_cache ("symbol %s has no score registered, skip its check",
				item->symbol);
	}

	if (ghost) {
		msg_debug_cache ("symbol %s is registered as ghost symbol, it won't be inserted "
				"to any metric", item->symbol);
	}

	if (item->st->weight < 0 && item->priority == 0) {
		item->priority ++;
	}

	if ((item->type & SYMBOL_TYPE_VIRTUAL) &&
			!(item->type & SYMBOL_TYPE_SQUEEZED) && item->parent != -1) {
		g_assert (item->parent < (gint)cache->items_by_id->len);
		parent = g_ptr_array_index (cache->items_by_id, item->parent);

		if (fabs (parent->st->weight) < fabs (item->st->weight)) {
			parent->st->weight = item->st->weight;
		}

		p1 = abs (item->priority);
		p2 = abs (parent->priority);

		if (p1 != p2) {
			parent->priority = MAX (p1, p2);
			item->priority = parent->priority;
		}
	}

	cache->total_weight += fabs (item->st->weight);
}

static void
rspamd_symbols_cache_metric_validate_cb (gpointer k, gpointer v, gpointer ud)
{
	struct symbols_cache *cache = (struct symbols_cache *)ud;
	const gchar *sym = k;
	struct rspamd_symbol *s = (struct rspamd_symbol *)v;
	gdouble weight;
	struct cache_item *item;

	weight = *s->weight_ptr;
	item = g_hash_table_lookup (cache->items_by_symbol, sym);

	if (item) {
		item->st->weight = weight;
	}
}

gboolean
rspamd_symbols_cache_validate (struct symbols_cache *cache,
	struct rspamd_config *cfg,
	gboolean strict)
{
	struct cache_item *item;
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_symbol *sym_def;
	gboolean ignore_symbol = FALSE, ret = TRUE;

	if (cache == NULL) {
		msg_err ("empty cache is invalid");
		return FALSE;
	}

	/* Now adjust symbol weights according to default metric */
	g_hash_table_foreach (cfg->symbols,
			rspamd_symbols_cache_metric_validate_cb,
			cache);

	g_hash_table_foreach (cache->items_by_symbol,
			rspamd_symbols_cache_validate_cb,
			cache);
	/* Now check each metric item and find corresponding symbol in a cache */
	g_hash_table_iter_init (&it, cfg->symbols);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		ignore_symbol = FALSE;
		sym_def = v;

		if (sym_def && (sym_def->flags & RSPAMD_SYMBOL_FLAG_IGNORE)) {
			ignore_symbol = TRUE;
			break;
		}

		if (!ignore_symbol) {
			item = g_hash_table_lookup (cache->items_by_symbol, k);

			if (item == NULL) {
				msg_warn_cache (
						"symbol '%s' has its score defined but there is no "
								"corresponding rule registered",
						k);
				if (strict) {
					ret = FALSE;
				}
			}
		}
	}

	return ret;
}

/* Return true if metric has score that is more than spam score for it */
static gboolean
rspamd_symbols_cache_metric_limit (struct rspamd_task *task,
		struct cache_savepoint *cp)
{
	struct rspamd_metric_result *res;
	double ms;

	if (task->flags & RSPAMD_TASK_FLAG_PASS_ALL) {
		return FALSE;
	}

	if (cp->lim == 0.0) {
		res = task->result;

		if (res) {
			ms = rspamd_task_get_required_score (task, res);

			if (!isnan (ms) && cp->lim < ms) {
				cp->rs = res;
				cp->lim = ms;
			}
		}
	}

	if (cp->rs) {

		if (cp->rs->score > cp->lim) {
			return TRUE;
		}
	}
	else {
		/* No reject score define, always check all rules */
		cp->lim = -1;
	}

	return FALSE;
}

static void
rspamd_symbols_cache_watcher_cb (gpointer sessiond, gpointer ud)
{
	struct rspamd_task *task = sessiond;
	struct cache_item *item = ud, *it;
	struct cache_savepoint *checkpoint;
	struct symbols_cache *cache;
	gint i, remain = 0;

	checkpoint = task->checkpoint;
	cache = task->cfg->cache;

	/* Specify that we are done with this item */
	setbit (checkpoint->processed_bits, item->id * 2 + 1);

	if (checkpoint->pass > 0) {
		for (i = 0; i < (gint)checkpoint->waitq->len; i ++) {
			it = g_ptr_array_index (checkpoint->waitq, i);

			if (!isset (checkpoint->processed_bits, it->id * 2)) {
				if (!rspamd_symbols_cache_check_deps (task, cache, it,
						checkpoint, 0, TRUE)) {
					remain ++;
				}
				else {
					msg_debug_task ("watcher for %d, unblocked item %d",
							item->id,
							it->id);
					rspamd_symbols_cache_check_symbol (task, cache, it,
							checkpoint,
							NULL);
				}
			}
		}
	}

	msg_debug_task ("finished watcher for %d, %ud symbols waiting", item->id,
			remain);
}

static gboolean
rspamd_symbols_cache_check_symbol (struct rspamd_task *task,
		struct symbols_cache *cache,
		struct cache_item *item,
		struct cache_savepoint *checkpoint,
		gdouble *total_diff)
{
	guint pending_before, pending_after;
	double t1 = 0, t2 = 0;
	gdouble diff;
	struct rspamd_task **ptask;
	lua_State *L;
	gboolean check = TRUE;
	const gdouble slow_diff_limit = 1e7;

	if (item->func) {

		g_assert (item->func != NULL);
		/* Check has been started */
		setbit (checkpoint->processed_bits, item->id * 2);

		if (!item->enabled ||
				(RSPAMD_TASK_IS_EMPTY (task) && !(item->type & SYMBOL_TYPE_EMPTY))) {
			check = FALSE;
		}
		else if (item->condition_cb != -1) {
			/* We also executes condition callback to check if we need this symbol */
			L = task->cfg->lua_state;
			lua_rawgeti (L, LUA_REGISTRYINDEX, item->condition_cb);
			ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
			rspamd_lua_setclass (L, "rspamd{task}", -1);
			*ptask = task;

			if (lua_pcall (L, 1, 1, 0) != 0) {
				msg_info_task ("call to condition for %s failed: %s",
						item->symbol, lua_tostring (L, -1));
				lua_pop (L, 1);
			}
			else {
				check = lua_toboolean (L, -1);
				lua_pop (L, 1);
			}
		}

		if (check) {
			pending_before = rspamd_session_events_pending (task->s);
			/* Watch for events appeared */
			rspamd_session_watch_start (task->s,
					item->id,
					rspamd_symbols_cache_watcher_cb,
					item);
			msg_debug_task ("execute %s, %d", item->symbol, item->id);
			t1 = rspamd_get_ticks (TRUE);
			item->func (task, item->user_data);
			t2 = rspamd_get_ticks (TRUE);
			diff = (t2 - t1);

			if (G_UNLIKELY (RSPAMD_TASK_IS_PROFILING (task))) {
				rspamd_task_profile_set (task, item->symbol, diff);
			}

			if (total_diff) {
				*total_diff += diff;
			}

			if (diff > slow_diff_limit && !(item->type & SYMBOL_TYPE_SQUEEZED)) {
				msg_info_task ("slow rule: %s: %.0f ticks", item->symbol,
						diff);
			}

			if (rspamd_worker_is_scanner (task->worker)) {
				rspamd_set_counter (item->cd, diff);
			}

			pending_after = rspamd_session_events_pending (task->s);
			rspamd_session_watch_stop (task->s);

			if (pending_before == pending_after) {
				/* No new events registered */
				setbit (checkpoint->processed_bits, item->id * 2 + 1);

				return TRUE;
			}

			return FALSE;
		}
		else {
			msg_debug_task ("skipping check of %s as its start condition is false",
					item->symbol);
			setbit (checkpoint->processed_bits, item->id * 2 + 1);

			return TRUE;
		}
	}
	else {
		setbit (checkpoint->processed_bits, item->id * 2);
		setbit (checkpoint->processed_bits, item->id * 2 + 1);

		return TRUE;
	}
}

static gboolean
rspamd_symbols_cache_check_deps (struct rspamd_task *task,
		struct symbols_cache *cache,
		struct cache_item *item,
		struct cache_savepoint *checkpoint,
		guint recursion,
		gboolean check_only)
{
	struct cache_dependency *dep;
	guint i;
	gboolean ret = TRUE;
	static const guint max_recursion = 20;

	if (recursion > max_recursion) {
		msg_err_task ("cyclic dependencies: maximum check level %ud exceed when "
				"checking dependencies for %s", max_recursion, item->symbol);

		return TRUE;
	}

	if (item->deps != NULL && item->deps->len > 0) {
		for (i = 0; i < item->deps->len; i ++) {
			dep = g_ptr_array_index (item->deps, i);

			if (dep->item == NULL) {
				/* Assume invalid deps as done */
				msg_debug_task ("symbol %s has invalid dependencies from %s",
						item->symbol, dep->sym);
				continue;
			}

			if (!isset (checkpoint->processed_bits, dep->id * 2 + 1)) {
				if (!isset (checkpoint->processed_bits, dep->id * 2)) {
					/* Not started */
					if (!check_only) {
						if (!rspamd_symbols_cache_check_deps (task, cache,
								dep->item,
								checkpoint,
								recursion + 1,
								check_only)) {
							gboolean found = FALSE;
							guint j;
							struct cache_item *tmp_it;

							PTR_ARRAY_FOREACH (checkpoint->waitq, j, tmp_it) {
								if (item->id == tmp_it->id) {
									found = TRUE;
									break;
								}
							}

							if (!found) {
								g_ptr_array_add (checkpoint->waitq, item);
							}

							ret = FALSE;
							msg_debug_task ("delayed dependency %d for symbol %d",
									dep->id, item->id);
						}
						else if (!rspamd_symbols_cache_check_symbol (task, cache,
								dep->item,
								checkpoint,
								NULL)) {
							/* Now started, but has events pending */
							ret = FALSE;
							msg_debug_task ("started check of %d symbol as dep for "
											"%d",
									dep->id, item->id);
						}
						else {
							msg_debug_task ("dependency %d for symbol %d is "
									"already processed",
									dep->id, item->id);
						}
					}
					else {
						ret = FALSE;
					}
				}
				else {
					/* Started but not finished */
					ret = FALSE;
				}
			}
			else {
				msg_debug_task ("dependency %d for symbol %d is already "
						"checked",
						dep->id, item->id);
			}
		}
	}

	return ret;
}

static void
rspamd_symbols_cache_continuation (void *data)
{
	struct rspamd_task *task = data;

	rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL);
}

static void
rspamd_symbols_cache_tm (gint fd, short what, void *data)
{
	struct rspamd_task *task = data;

	rspamd_session_remove_event (task->s, rspamd_symbols_cache_continuation,
			data);
}

static struct cache_savepoint *
rspamd_symbols_cache_make_checkpoint (struct rspamd_task *task,
		struct symbols_cache *cache)
{
	struct cache_savepoint *checkpoint;
	guint nitems;

	nitems = cache->items_by_id->len - cache->postfilters->len -
			cache->prefilters->len - cache->composites->len -
			cache->idempotent->len;

	if (nitems != cache->items_by_order->d->len) {
		/*
		 * Cache has been modified, need to resort it
		 */
		msg_info_cache ("symbols cache has been modified since last check:"
				" old items: %ud, new items: %ud",
				cache->items_by_order->d->len, nitems);
		rspamd_symbols_cache_resort (cache);
	}

	checkpoint = rspamd_mempool_alloc0 (task->task_pool, sizeof (*checkpoint));
	/* Bit 0: check started, Bit 1: check finished */
	checkpoint->processed_bits = rspamd_mempool_alloc0 (task->task_pool,
			NBYTES (cache->used_items) * 2);
	checkpoint->waitq = g_ptr_array_new ();
	g_assert (cache->items_by_order != NULL);
	checkpoint->version = cache->items_by_order->d->len;
	checkpoint->order = cache->items_by_order;
	REF_RETAIN (checkpoint->order);
	rspamd_mempool_add_destructor (task->task_pool,
			rspamd_symbols_cache_order_unref, checkpoint->order);
	rspamd_mempool_add_destructor (task->task_pool,
			rspamd_ptr_array_free_hard, checkpoint->waitq);
	checkpoint->pass = RSPAMD_CACHE_PASS_INIT;
	task->checkpoint = checkpoint;

	task->result = rspamd_create_metric_result (task);

	return checkpoint;
}

gboolean
rspamd_symbols_cache_process_settings (struct rspamd_task *task,
		struct symbols_cache *cache)
{
	const ucl_object_t *wl, *cur, *disabled, *enabled;
	struct rspamd_symbols_group *gr;
	GHashTableIter gr_it;
	ucl_object_iter_t it = NULL;
	gpointer k, v;

	wl = ucl_object_lookup (task->settings, "whitelist");

	if (wl != NULL) {
		msg_info_task ("<%s> is whitelisted", task->message_id);
		task->flags |= RSPAMD_TASK_FLAG_SKIP;
		return TRUE;
	}

	enabled = ucl_object_lookup (task->settings, "symbols_enabled");

	if (enabled) {
		/* Disable all symbols but selected */
		rspamd_symbols_cache_disable_all_symbols (task, cache);
		it = NULL;

		while ((cur = ucl_iterate_object (enabled, &it, true)) != NULL) {
			rspamd_symbols_cache_enable_symbol_checkpoint (task, cache,
					ucl_object_tostring (cur));
		}
	}

	/* Enable groups of symbols */
	enabled = ucl_object_lookup (task->settings, "groups_enabled");

	if (enabled) {
		it = NULL;
		rspamd_symbols_cache_disable_all_symbols (task, cache);

		while ((cur = ucl_iterate_object (enabled, &it, true)) != NULL) {
			if (ucl_object_type (cur) == UCL_STRING) {
				gr = g_hash_table_lookup (task->cfg->groups,
						ucl_object_tostring (cur));

				if (gr) {
					g_hash_table_iter_init (&gr_it, gr->symbols);

					while (g_hash_table_iter_next (&gr_it, &k, &v)) {
						rspamd_symbols_cache_enable_symbol_checkpoint (task, cache, k);
					}
				}
			}
		}
	}

	disabled = ucl_object_lookup (task->settings, "symbols_disabled");

	if (disabled) {
		it = NULL;

		while ((cur = ucl_iterate_object (disabled, &it, true)) != NULL) {
			rspamd_symbols_cache_disable_symbol_checkpoint (task, cache,
					ucl_object_tostring (cur));
		}
	}

	/* Disable groups of symbols */
	disabled = ucl_object_lookup (task->settings, "groups_disabled");

	if (disabled) {
		it = NULL;

		while ((cur = ucl_iterate_object (disabled, &it, true)) != NULL) {
			if (ucl_object_type (cur) == UCL_STRING) {
				gr = g_hash_table_lookup (task->cfg->groups,
						ucl_object_tostring (cur));

				if (gr) {
					g_hash_table_iter_init (&gr_it, gr->symbols);

					while (g_hash_table_iter_next (&gr_it, &k, &v)) {
						rspamd_symbols_cache_disable_symbol_checkpoint (task, cache, k);
					}
				}
			}
		}
	}

	return FALSE;
}

gboolean
rspamd_symbols_cache_process_symbols (struct rspamd_task * task,
	struct symbols_cache *cache, gint stage)
{
	struct cache_item *item = NULL;
	struct cache_savepoint *checkpoint;
	gint i;
	gdouble total_ticks = 0;
	gboolean all_done;
	gint saved_priority;
	const gdouble max_ticks = 3e8;
	guint start_events_pending;

	g_assert (cache != NULL);

	if (task->checkpoint == NULL) {
		checkpoint = rspamd_symbols_cache_make_checkpoint (task, cache);
		task->checkpoint = checkpoint;
	}
	else {
		checkpoint = task->checkpoint;
	}

	if (stage == RSPAMD_TASK_STAGE_POST_FILTERS && checkpoint->pass <
			RSPAMD_CACHE_PASS_POSTFILTERS) {
		checkpoint->pass = RSPAMD_CACHE_PASS_POSTFILTERS;
	}

	if (stage == RSPAMD_TASK_STAGE_IDEMPOTENT && checkpoint->pass <
			RSPAMD_CACHE_PASS_IDEMPOTENT) {
		checkpoint->pass = RSPAMD_CACHE_PASS_IDEMPOTENT;
	}

	msg_debug_task ("symbols processing stage at pass: %d", checkpoint->pass);
	start_events_pending = rspamd_session_events_pending (task->s);

	switch (checkpoint->pass) {
	case RSPAMD_CACHE_PASS_INIT:
	case RSPAMD_CACHE_PASS_PREFILTERS:
		/* Check for prefilters */
		saved_priority = G_MININT;

		for (i = 0; i < (gint)cache->prefilters->len; i ++) {
			item = g_ptr_array_index (cache->prefilters, i);

			if (!isset (checkpoint->processed_bits, item->id * 2) &&
					!isset (checkpoint->processed_bits, item->id * 2 + 1)) {
				/* Check priorities */
				if (saved_priority == G_MININT) {
					saved_priority = item->priority;
				}
				else {
					if (item->priority < saved_priority &&
							rspamd_session_events_pending (task->s) > start_events_pending) {
						/*
						 * Delay further checks as we have higher
						 * priority filters to be processed
						 */
						checkpoint->pass = RSPAMD_CACHE_PASS_PREFILTERS;
						return TRUE;
					}
				}

				rspamd_symbols_cache_check_symbol (task, cache, item,
						checkpoint, &total_ticks);
			}
		}

		checkpoint->pass = RSPAMD_CACHE_PASS_WAIT_PREFILTERS;
		break;

	case RSPAMD_CACHE_PASS_WAIT_PREFILTERS:
		all_done = TRUE;

		for (i = 0; i < (gint)cache->prefilters->len; i ++) {
			item = g_ptr_array_index (cache->prefilters, i);

			if (!isset (checkpoint->processed_bits, item->id * 2 + 1)) {
				all_done = FALSE;
				break;
			}
		}

		if (all_done || stage == RSPAMD_TASK_STAGE_FILTERS) {
			checkpoint->pass = RSPAMD_CACHE_PASS_FILTERS;
		}

		if (stage == RSPAMD_TASK_STAGE_FILTERS) {
			return rspamd_symbols_cache_process_symbols (task, cache, stage);
		}
		break;
	case RSPAMD_CACHE_PASS_FILTERS:
		/*
		 * On the first pass we check symbols that do not have dependencies
		 * If we figure out symbol that has no dependencies satisfied, then
		 * we just save it for another pass
		 */
		for (i = 0; i < (gint)checkpoint->version; i ++) {
			item = g_ptr_array_index (checkpoint->order->d, i);

			if (item->type & SYMBOL_TYPE_CLASSIFIER) {
				continue;
			}

			if (!(item->type & SYMBOL_TYPE_FINE) &&
					rspamd_session_events_pending (task->s) == 0) {
				if (rspamd_symbols_cache_metric_limit (task, checkpoint)) {
					msg_info_task ("<%s> has already scored more than %.2f, so do "
							"not "
							"plan more checks", task->message_id,
							checkpoint->rs->score);
					continue;
				}
			}

			if (!isset (checkpoint->processed_bits, item->id * 2)) {
				if (!rspamd_symbols_cache_check_deps (task, cache, item,
						checkpoint, 0, FALSE)) {
					gboolean found = FALSE;
					guint j;
					struct cache_item *tmp_it;

					msg_debug_task ("blocked execution of %d unless deps are "
							"resolved",
							item->id);

					PTR_ARRAY_FOREACH (checkpoint->waitq, j, tmp_it) {
						if (item->id == tmp_it->id) {
							found = TRUE;
							break;
						}
					}

					if (!found) {
						g_ptr_array_add (checkpoint->waitq, item);
					}

					continue;
				}

				rspamd_symbols_cache_check_symbol (task, cache, item,
						checkpoint, &total_ticks);
			}

			if (total_ticks > max_ticks) {
				/* Maybe we should stop and check pending events? */
				if (rspamd_session_events_pending (task->s) > start_events_pending) {
					/* Add some timeout event to avoid too long waiting */
#if 0
					struct event *ev;
					struct timeval tv;

					rspamd_session_add_event (task->s,
							rspamd_symbols_cache_continuation, task,
							rspamd_symbols_cache_quark ());
					ev = rspamd_mempool_alloc (task->task_pool, sizeof (*ev));
					event_set (ev, -1, EV_TIMEOUT, rspamd_symbols_cache_tm, task);
					event_base_set (task->ev_base, ev);
					msec_to_tv (50, &tv);
					event_add (ev, &tv);
					rspamd_mempool_add_destructor (task->task_pool,
							(rspamd_mempool_destruct_t)event_del, ev);
#endif
					msg_info_task ("trying to check async events after spending "
							"%.0f ticks processing symbols",
							total_ticks);

					return TRUE;
				}
			}
		}

		checkpoint->pass = RSPAMD_CACHE_PASS_WAIT_FILTERS;
		break;

	case RSPAMD_CACHE_PASS_WAIT_FILTERS:
		/* We just go through the blocked symbols and check if they are ready */
		for (i = 0; i < (gint)checkpoint->waitq->len; i ++) {
			item = g_ptr_array_index (checkpoint->waitq, i);

			if (!isset (checkpoint->processed_bits, item->id * 2)) {
				if (!rspamd_symbols_cache_check_deps (task, cache, item,
						checkpoint, 0, FALSE)) {
					break;
				}

				rspamd_symbols_cache_check_symbol (task, cache, item,
						checkpoint, &total_ticks);
			}

			if (total_ticks > max_ticks) {
				/* Maybe we should stop and check pending events? */
				if (rspamd_session_events_pending (task->s) >
						start_events_pending) {
					msg_debug_task ("trying to check async events after spending "
							"%.0f microseconds processing symbols",
							total_ticks);
					return TRUE;
				}
			}
		}

		if (checkpoint->waitq->len == 0 ||
				stage == RSPAMD_TASK_STAGE_POST_FILTERS) {
			checkpoint->pass = RSPAMD_CACHE_PASS_POSTFILTERS;
		}

		if (stage == RSPAMD_TASK_STAGE_POST_FILTERS) {
			return rspamd_symbols_cache_process_symbols (task, cache, stage);
		}

		break;

	case RSPAMD_CACHE_PASS_POSTFILTERS:
		/* Check for postfilters */
		saved_priority = G_MININT;

		for (i = 0; i < (gint)cache->postfilters->len; i ++) {
			item = g_ptr_array_index (cache->postfilters, i);

			if (!isset (checkpoint->processed_bits, item->id * 2) &&
					!isset (checkpoint->processed_bits, item->id * 2 + 1)) {
				/* Check priorities */
				if (saved_priority == G_MININT) {
					saved_priority = item->priority;
				}
				else {
					if (item->priority > saved_priority &&
							rspamd_session_events_pending (task->s) > start_events_pending) {
						/*
						 * Delay further checks as we have higher
						 * priority filters to be processed
						 */
						checkpoint->pass = RSPAMD_CACHE_PASS_POSTFILTERS;
						return TRUE;
					}
				}

				rspamd_symbols_cache_check_symbol (task, cache, item,
						checkpoint, &total_ticks);
			}
		}
		checkpoint->pass = RSPAMD_CACHE_PASS_WAIT_POSTFILTERS;
		break;

	case RSPAMD_CACHE_PASS_WAIT_POSTFILTERS:
		all_done = TRUE;

		for (i = 0; i < (gint)cache->postfilters->len; i ++) {
			item = g_ptr_array_index (cache->postfilters, i);

			if (!isset (checkpoint->processed_bits, item->id * 2 + 1)) {
				all_done = FALSE;
				break;
			}
		}

		if (all_done) {
			checkpoint->pass = RSPAMD_CACHE_PASS_IDEMPOTENT;
		}

		if (checkpoint->waitq->len == 0 ||
				stage == RSPAMD_TASK_STAGE_IDEMPOTENT) {
			checkpoint->pass = RSPAMD_CACHE_PASS_IDEMPOTENT;
		}

		if (stage == RSPAMD_TASK_STAGE_IDEMPOTENT) {
			return rspamd_symbols_cache_process_symbols (task, cache, stage);
		}

		break;

	case RSPAMD_CACHE_PASS_IDEMPOTENT:
		/* Check for postfilters */
		saved_priority = G_MININT;

		for (i = 0; i < (gint)cache->idempotent->len; i ++) {
			item = g_ptr_array_index (cache->idempotent, i);

			if (!isset (checkpoint->processed_bits, item->id * 2) &&
					!isset (checkpoint->processed_bits, item->id * 2 + 1)) {
				/* Check priorities */
				if (saved_priority == G_MININT) {
					saved_priority = item->priority;
				}
				else {
					if (item->priority > saved_priority &&
							rspamd_session_events_pending (task->s) > start_events_pending) {
						/*
						 * Delay further checks as we have higher
						 * priority filters to be processed
						 */
						checkpoint->pass = RSPAMD_CACHE_PASS_IDEMPOTENT;
						return TRUE;
					}
				}
				rspamd_symbols_cache_check_symbol (task, cache, item,
						checkpoint, &total_ticks);
			}
		}
		checkpoint->pass = RSPAMD_CACHE_PASS_WAIT_IDEMPOTENT;
		break;

	case RSPAMD_CACHE_PASS_WAIT_IDEMPOTENT:
		all_done = TRUE;

		for (i = 0; i < (gint)cache->idempotent->len; i ++) {
			item = g_ptr_array_index (cache->idempotent, i);

			if (!isset (checkpoint->processed_bits, item->id * 2 + 1)) {
				all_done = FALSE;
				break;
			}
		}

		if (all_done) {
			checkpoint->pass = RSPAMD_CACHE_PASS_DONE;

			return TRUE;
		}
		break;

	case RSPAMD_CACHE_PASS_DONE:
		return TRUE;
		break;
	}

	return FALSE;
}

struct counters_cbdata {
	ucl_object_t *top;
	struct symbols_cache *cache;
};

#define ROUND_DOUBLE(x) (floor((x) * 100.0) / 100.0)

static void
rspamd_symbols_cache_counters_cb (gpointer v, gpointer ud)
{
	struct counters_cbdata *cbd = ud;
	ucl_object_t *obj, *top;
	struct cache_item *item = v, *parent;

	top = cbd->top;

	if (!(item->type & SYMBOL_TYPE_CALLBACK)) {
		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, ucl_object_fromstring (item->symbol),
				"symbol", 0, false);

		if ((item->type & SYMBOL_TYPE_VIRTUAL) &&
				!(item->type & SYMBOL_TYPE_SQUEEZED) && item->parent != -1) {
			g_assert (item->parent < (gint)cbd->cache->items_by_id->len);
			parent = g_ptr_array_index (cbd->cache->items_by_id,
					item->parent);
			ucl_object_insert_key (obj,
					ucl_object_fromdouble (ROUND_DOUBLE (item->st->weight)),
					"weight", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromdouble (ROUND_DOUBLE (parent->st->avg_frequency)),
					"frequency", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromint (parent->st->total_hits),
					"hits", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromdouble (ROUND_DOUBLE (parent->st->avg_time)),
					"time", 0, false);
		}
		else {
			ucl_object_insert_key (obj,
					ucl_object_fromdouble (ROUND_DOUBLE (item->st->weight)),
					"weight", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromdouble (ROUND_DOUBLE (item->st->avg_frequency)),
					"frequency", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromint (item->st->total_hits),
					"hits", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromdouble (ROUND_DOUBLE (item->st->avg_time)),
					"time", 0, false);
		}

		ucl_array_append (top, obj);
	}
}

#undef ROUND_DOUBLE

ucl_object_t *
rspamd_symbols_cache_counters (struct symbols_cache * cache)
{
	ucl_object_t *top;
	struct counters_cbdata cbd;

	g_assert (cache != NULL);
	top = ucl_object_typed_new (UCL_ARRAY);
	cbd.top = top;
	cbd.cache = cache;
	g_ptr_array_foreach (cache->items_by_order->d,
			rspamd_symbols_cache_counters_cb, &cbd);

	return top;
}

static void
rspamd_symbols_cache_call_peak_cb (struct event_base *ev_base,
		struct symbols_cache *cache,
		struct cache_item *item,
		gdouble cur_value,
		gdouble cur_err)
{
	lua_State *L = cache->cfg->lua_state;
	struct event_base **pbase;

	lua_rawgeti (L, LUA_REGISTRYINDEX, cache->peak_cb);
	pbase = lua_newuserdata (L, sizeof (*pbase));
	*pbase = ev_base;
	rspamd_lua_setclass (L, "rspamd{ev_base}", -1);
	lua_pushstring (L, item->symbol);
	lua_pushnumber (L, item->st->avg_frequency);
	lua_pushnumber (L, sqrt (item->st->stddev_frequency));
	lua_pushnumber (L, cur_value);
	lua_pushnumber (L, cur_err);

	if (lua_pcall (L, 6, 0, 0) != 0) {
		msg_info_cache ("call to peak function for %s failed: %s",
				item->symbol, lua_tostring (L, -1));
		lua_pop (L, 1);
	}
}

static void
rspamd_symbols_cache_resort_cb (gint fd, short what, gpointer ud)
{
	struct timeval tv;
	gdouble tm;
	struct rspamd_cache_refresh_cbdata *cbdata = ud;
	struct symbols_cache *cache;
	struct cache_item *item, *parent;
	guint i;
	gdouble cur_ticks;

	cache = cbdata->cache;
	/* Plan new event */
	tm = rspamd_time_jitter (cache->reload_time, 0);
	cur_ticks = rspamd_get_ticks (TRUE);
	msg_debug_cache ("resort symbols cache, next reload in %.2f seconds", tm);
	g_assert (cache != NULL);
	evtimer_set (&cbdata->resort_ev, rspamd_symbols_cache_resort_cb, cbdata);
	event_base_set (cbdata->ev_base, &cbdata->resort_ev);
	double_to_tv (tm, &tv);
	event_add (&cbdata->resort_ev, &tv);

	if (rspamd_worker_is_primary_controller (cbdata->w))
		/* Gather stats from shared execution times */
		for (i = 0; i < cache->items_by_id->len; i ++) {
			item = g_ptr_array_index (cache->items_by_id, i);
			item->st->total_hits += item->st->hits;
			item->st->hits = 0;

			if (item->last_count > 0 && cbdata->w->index == 0) {
				/* Calculate frequency */
				gdouble cur_err, cur_value;

				cur_value = (item->st->total_hits - item->last_count) /
						(cur_ticks - cbdata->last_resort);
				rspamd_set_counter (&item->st->frequency_counter,
						cur_value);
				item->st->avg_frequency = item->st->frequency_counter.mean;
				item->st->stddev_frequency = item->st->frequency_counter.stddev;

				if (cur_value > 0) {
					msg_debug_cache ("frequency for %s is %.2f, avg: %.2f",
							item->symbol, cur_value, item->st->avg_frequency);
				}

				cur_err = (item->st->avg_frequency - cur_value);
				cur_err *= cur_err;

				/*
				 * TODO: replace magic number
				 */
				if (item->st->frequency_counter.number > 10 &&
						cur_err > sqrt (item->st->stddev_frequency) * 3) {
					item->frequency_peaks ++;
					msg_debug_cache ("peak found for %s is %.2f, avg: %.2f, "
							"stddev: %.2f, error: %.2f, peaks: %d",
						item->symbol, cur_value,
						item->st->avg_frequency,
						item->st->stddev_frequency,
						cur_err,
						item->frequency_peaks);

					if (cache->peak_cb != -1) {
						rspamd_symbols_cache_call_peak_cb (cbdata->ev_base,
								cache, item,
								cur_value, cur_err);
					}
				}
			}

			item->last_count = item->st->total_hits;

			if (item->cd->number > 0) {
				if (item->type & (SYMBOL_TYPE_CALLBACK|SYMBOL_TYPE_NORMAL)) {
					item->st->avg_time = item->cd->mean;
					rspamd_set_counter (&item->st->time_counter,
							item->st->avg_time);
					item->st->avg_time = item->st->time_counter.mean;
					memset (item->cd, 0, sizeof (*item->cd));
				}
			}
		}

	/* Sync virtual symbols */
	for (i = 0; i < cache->items_by_id->len; i ++) {
		item = g_ptr_array_index (cache->items_by_id, i);

		if (item->parent != -1) {
			parent = g_ptr_array_index (cache->items_by_id, item->parent);

			if (parent) {
				item->st->avg_time = parent->st->avg_time;
			}
		}
	}

	cbdata->last_resort = cur_ticks;
	rspamd_symbols_cache_resort (cache);
}

void
rspamd_symbols_cache_start_refresh (struct symbols_cache * cache,
		struct event_base *ev_base, struct rspamd_worker *w)
{
	struct timeval tv;
	gdouble tm;
	struct rspamd_cache_refresh_cbdata *cbdata;

	cbdata = rspamd_mempool_alloc0 (cache->static_pool, sizeof (*cbdata));
	cbdata->last_resort = rspamd_get_ticks (TRUE);
	cbdata->ev_base = ev_base;
	cbdata->w = w;
	cbdata->cache = cache;
	tm = rspamd_time_jitter (cache->reload_time, 0);
	msg_debug_cache ("next reload in %.2f seconds", tm);
	g_assert (cache != NULL);
	evtimer_set (&cbdata->resort_ev, rspamd_symbols_cache_resort_cb,
			cbdata);
	event_base_set (ev_base, &cbdata->resort_ev);
	double_to_tv (tm, &tv);
	event_add (&cbdata->resort_ev, &tv);
	rspamd_mempool_add_destructor (cache->static_pool,
			(rspamd_mempool_destruct_t) event_del,
			&cbdata->resort_ev);
}

void
rspamd_symbols_cache_inc_frequency (struct symbols_cache *cache,
		const gchar *symbol)
{
	struct cache_item *item;

	g_assert (cache != NULL);

	item = g_hash_table_lookup (cache->items_by_symbol, symbol);

	if (item != NULL) {
		g_atomic_int_inc (&item->st->hits);
	}
}

void
rspamd_symbols_cache_add_dependency (struct symbols_cache *cache,
		gint id_from, const gchar *to)
{
	struct cache_item *source;
	struct cache_dependency *dep;

	g_assert (id_from < (gint)cache->items_by_id->len);

	source = g_ptr_array_index (cache->items_by_id, id_from);
	dep = rspamd_mempool_alloc (cache->static_pool, sizeof (*dep));
	dep->id = id_from;
	dep->sym = rspamd_mempool_strdup (cache->static_pool, to);
	/* Will be filled later */
	dep->item = NULL;
	g_ptr_array_add (source->deps, dep);
}

void
rspamd_symbols_cache_add_delayed_dependency (struct symbols_cache *cache,
		const gchar *from, const gchar *to)
{
	struct delayed_cache_dependency *ddep;

	g_assert (from != NULL);
	g_assert (to != NULL);

	ddep = g_malloc0 (sizeof (*ddep));
	ddep->from = g_strdup (from);
	ddep->to = g_strdup (to);

	cache->delayed_deps = g_list_prepend (cache->delayed_deps, ddep);
}

gint
rspamd_symbols_cache_find_symbol (struct symbols_cache *cache, const gchar *name)
{
	struct cache_item *item;

	g_assert (cache != NULL);

	if (name == NULL) {
		return -1;
	}

	item = g_hash_table_lookup (cache->items_by_symbol, name);

	if (item != NULL) {
		return item->id;
	}

	return -1;
}

gboolean
rspamd_symbols_cache_stat_symbol (struct symbols_cache *cache,
		const gchar *name, gdouble *frequency, gdouble *freq_stddev,
		gdouble *tm, guint *nhits)
{
	struct cache_item *item;

	g_assert (cache != NULL);

	if (name == NULL) {
		return FALSE;
	}

	item = g_hash_table_lookup (cache->items_by_symbol, name);

	if (item != NULL) {
		*frequency = item->st->avg_frequency;
		*freq_stddev = sqrt (item->st->stddev_frequency);
		*tm = item->st->time_counter.mean;

		if (nhits) {
			*nhits = item->st->hits;
		}

		return TRUE;
	}

	return FALSE;
}

static gint
rspamd_symbols_cache_find_symbol_parent (struct symbols_cache *cache,
		const gchar *name)
{
	struct cache_item *item;

	g_assert (cache != NULL);

	if (name == NULL) {
		return -1;
	}

	item = g_hash_table_lookup (cache->items_by_symbol, name);

	if (item != NULL) {

		while (item != NULL && item->parent != -1) {
			item = g_ptr_array_index (cache->items_by_id, item->parent);
		}

		return item ? item->id : -1;
	}

	return -1;
}

const gchar *
rspamd_symbols_cache_symbol_by_id (struct symbols_cache *cache,
		gint id)
{
	struct cache_item *item;

	g_assert (cache != NULL);

	if (id < 0 || id >= (gint)cache->items_by_id->len) {
		return NULL;
	}

	item = g_ptr_array_index (cache->items_by_id, id);

	return item->symbol;
}

guint
rspamd_symbols_cache_stats_symbols_count (struct symbols_cache *cache)
{
	g_assert (cache != NULL);

	return cache->stats_symbols_count;
}

static void
rspamd_symbols_cache_disable_all_symbols (struct rspamd_task *task,
		struct symbols_cache *cache)
{
	struct cache_savepoint *checkpoint;

	if (task->checkpoint == NULL) {
		checkpoint = rspamd_symbols_cache_make_checkpoint (task, cache);
		task->checkpoint = checkpoint;
	}
	else {
		checkpoint = task->checkpoint;
	}

	/* Set all symbols as started + finished to disable their execution */
	memset (checkpoint->processed_bits, 0xff,
			NBYTES (cache->used_items) * 2);
}

static void
rspamd_symbols_cache_disable_symbol_checkpoint (struct rspamd_task *task,
		struct symbols_cache *cache, const gchar *symbol)
{
	struct cache_savepoint *checkpoint;
	struct cache_item *item;
	gint id;

	if (task->checkpoint == NULL) {
		checkpoint = rspamd_symbols_cache_make_checkpoint (task, cache);
		task->checkpoint = checkpoint;
	}
	else {
		checkpoint = task->checkpoint;
	}

	id = rspamd_symbols_cache_find_symbol_parent (cache, symbol);

	if (id >= 0) {
		/* Set executed and finished flags */
		item = g_ptr_array_index (cache->items_by_id, id);

		if (!(item->type & SYMBOL_TYPE_SQUEEZED)) {
			setbit (checkpoint->processed_bits, item->id * 2);
			setbit (checkpoint->processed_bits, item->id * 2 + 1);

			msg_debug_task ("disable execution of %s", symbol);
		}
		else {
			msg_debug_task ("skip squeezed symbol %s", symbol);
		}
	}
	else {
		msg_info_task ("cannot disable %s: not found", symbol);
	}
}

static void
rspamd_symbols_cache_enable_symbol_checkpoint (struct rspamd_task *task,
		struct symbols_cache *cache, const gchar *symbol)
{
	struct cache_savepoint *checkpoint;
	struct cache_item *item;
	gint id;

	if (task->checkpoint == NULL) {
		checkpoint = rspamd_symbols_cache_make_checkpoint (task, cache);
		task->checkpoint = checkpoint;
	}
	else {
		checkpoint = task->checkpoint;
	}

	id = rspamd_symbols_cache_find_symbol_parent (cache, symbol);

	if (id >= 0) {
		/* Set executed and finished flags */
		item = g_ptr_array_index (cache->items_by_id, id);

		clrbit (checkpoint->processed_bits, item->id * 2);
		clrbit (checkpoint->processed_bits, item->id * 2 + 1);

		msg_debug_task ("enable execution of %s (%d)", symbol, id);
	}
	else {
		msg_info_task ("cannot enable %s: not found", symbol);
	}
}

struct rspamd_abstract_callback_data*
rspamd_symbols_cache_get_cbdata (struct symbols_cache *cache,
		const gchar *symbol)
{
	gint id;
	struct cache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	id = rspamd_symbols_cache_find_symbol_parent (cache, symbol);

	if (id < 0) {
		return NULL;
	}

	item = g_ptr_array_index (cache->items_by_id, id);

	return item->user_data;
}

gboolean
rspamd_symbols_cache_set_cbdata (struct symbols_cache *cache,
		const gchar *symbol, struct rspamd_abstract_callback_data *cbdata)
{
	gint id;
	struct cache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	id = rspamd_symbols_cache_find_symbol_parent (cache, symbol);

	if (id < 0) {
		return FALSE;
	}

	item = g_ptr_array_index (cache->items_by_id, id);
	item->user_data = cbdata;

	return TRUE;
}

gboolean
rspamd_symbols_cache_is_checked (struct rspamd_task *task,
		struct symbols_cache *cache, const gchar *symbol)
{
	gint id;
	struct cache_savepoint *checkpoint;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	id = rspamd_symbols_cache_find_symbol_parent (cache, symbol);

	if (id < 0) {
		return FALSE;
	}

	checkpoint = task->checkpoint;

	if (checkpoint) {
		return isset (checkpoint->processed_bits, id * 2);
	}

	return FALSE;
}

void
rspamd_symbols_cache_disable_symbol (struct symbols_cache *cache,
		const gchar *symbol)
{
	gint id;
	struct cache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	id = rspamd_symbols_cache_find_symbol_parent (cache, symbol);

	if (id >= 0) {
		item = g_ptr_array_index (cache->items_by_id, id);
		item->enabled = FALSE;
	}
}

void
rspamd_symbols_cache_enable_symbol (struct symbols_cache *cache,
		const gchar *symbol)
{
	gint id;
	struct cache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	id = rspamd_symbols_cache_find_symbol_parent (cache, symbol);

	if (id >= 0) {
		item = g_ptr_array_index (cache->items_by_id, id);
		item->enabled = TRUE;
	}
}

guint64
rspamd_symbols_cache_get_cksum (struct symbols_cache *cache)
{
	g_assert (cache != NULL);

	return cache->cksum;
}


gboolean
rspamd_symbols_cache_is_symbol_enabled (struct rspamd_task *task,
		struct symbols_cache *cache, const gchar *symbol)
{
	gint id;
	struct cache_savepoint *checkpoint;
	struct cache_item *item;
	lua_State *L;
	struct rspamd_task **ptask;
	gboolean ret = TRUE;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	id = rspamd_symbols_cache_find_symbol_parent (cache, symbol);

	if (id < 0) {
		return FALSE;
	}

	checkpoint = task->checkpoint;
	item = g_ptr_array_index (cache->items_by_id, id);

	if (checkpoint) {
		if (isset (checkpoint->processed_bits, id * 2)) {
			ret = FALSE;
		}
		else {
			if (item->condition_cb != -1) {
				/* We also executes condition callback to check if we need this symbol */
				L = task->cfg->lua_state;
				lua_rawgeti (L, LUA_REGISTRYINDEX, item->condition_cb);
				ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
				rspamd_lua_setclass (L, "rspamd{task}", -1);
				*ptask = task;

				if (lua_pcall (L, 1, 1, 0) != 0) {
					msg_info_task ("call to condition for %s failed: %s",
							item->symbol, lua_tostring (L, -1));
					lua_pop (L, 1);
				}
				else {
					ret = lua_toboolean (L, -1);
					lua_pop (L, 1);
				}
			}
		}
	}

	return ret;
}

void
rspamd_symbols_cache_foreach (struct symbols_cache *cache,
		void (*func)(gint , const gchar *, gint , gpointer ),
		gpointer ud)
{
	guint i;
	struct cache_item *item;

	PTR_ARRAY_FOREACH (cache->items_by_id, i, item) {
		func (item->id, item->symbol, item->type, ud);
	}
}
