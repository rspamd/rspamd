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
#include "rspamd_symcache.h"
#include "cfg_file.h"
#include "lua/lua_common.h"
#include "unix-std.h"
#include "contrib/t1ha/t1ha.h"
#include "libserver/worker_util.h"
#include <math.h>

#if defined(__STDC_VERSION__) &&  __STDC_VERSION__ >= 201112L
# include <stdalign.h>
#endif

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
#define msg_debug_cache_task(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_symcache_log_id, "symcache", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(symcache)

#define CHECK_START_BIT(checkpoint, dyn_item) \
	((dyn_item)->started)
#define SET_START_BIT(checkpoint, dyn_item) \
	(dyn_item)->started = 1

#define CHECK_FINISH_BIT(checkpoint, dyn_item) \
	((dyn_item)->finished)
#define SET_FINISH_BIT(checkpoint, dyn_item) \
	(dyn_item)->finished = 1

static const guchar rspamd_symcache_magic[8] = {'r', 's', 'c', 2, 0, 0, 0, 0 };

struct rspamd_symcache_header {
	guchar magic[8];
	guint nitems;
	guchar checksum[64];
	guchar unused[128];
};

struct symcache_order {
	GPtrArray *d;
	guint id;
	ref_entry_t ref;
};

struct rspamd_symcache {
	/* Hash table for fast access */
	GHashTable *items_by_symbol;
	GPtrArray *items_by_id;
	struct symcache_order *items_by_order;
	GPtrArray *filters;
	GPtrArray *prefilters;
	GPtrArray *postfilters;
	GPtrArray *composites;
	GPtrArray *idempotent;
	GPtrArray *virtual;
	GPtrArray *squeezed;
	GList *delayed_deps;
	GList *delayed_conditions;
	rspamd_mempool_t *static_pool;
	guint64 cksum;
	gdouble total_weight;
	guint used_items;
	guint stats_symbols_count;
	guint64 total_hits;
	guint id;
	struct rspamd_config *cfg;
	gdouble reload_time;
	gint peak_cb;
};

struct item_stat {
	struct rspamd_counter_data time_counter;
	gdouble avg_time;
	gdouble weight;
	guint hits;
	guint64 total_hits;
	struct rspamd_counter_data frequency_counter;
	gdouble avg_frequency;
	gdouble stddev_frequency;
};

struct rspamd_symcache_dynamic_item {
	guint16 start_msec; /* Relative to task time */
	unsigned started:1;
	unsigned finished:1;
	/* unsigned pad:14; */
	guint32 async_events;
};

struct rspamd_symcache_item {
	/* This block is likely shared */
	struct item_stat *st;

	guint64 last_count;
	struct rspamd_counter_data *cd;
	gchar *symbol;
	enum rspamd_symbol_type type;

	/* Callback data */
	union {
		struct {
			symbol_func_t func;
			gpointer user_data;
			gint condition_cb;
		} normal;
		struct {
			gint parent;
		} virtual;
	} specific;

	/* Condition of execution */
	gboolean enabled;
	/* Used for async stuff checks */
	gboolean is_filter;
	gboolean is_virtual;

	/* Priority */
	gint priority;
	/* Topological order */
	guint order;
	gint id;
	gint frequency_peaks;

	/* Dependencies */
	GPtrArray *deps;
	GPtrArray *rdeps;
};

struct cache_dependency {
	struct rspamd_symcache_item *item;
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
	RSPAMD_CACHE_PASS_FILTERS,
	RSPAMD_CACHE_PASS_POSTFILTERS,
	RSPAMD_CACHE_PASS_IDEMPOTENT,
	RSPAMD_CACHE_PASS_WAIT_IDEMPOTENT,
	RSPAMD_CACHE_PASS_DONE,
};

struct cache_savepoint {
	enum rspamd_cache_savepoint_stage pass;
	guint version;
	guint items_inflight;

	struct rspamd_metric_result *rs;
	gdouble lim;

	struct rspamd_symcache_item *cur_item;
	struct symcache_order *order;
	struct rspamd_symcache_dynamic_item dynamic_items[];
};

struct rspamd_cache_refresh_cbdata {
	gdouble last_resort;
	struct event resort_ev;
	struct rspamd_symcache *cache;
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

static gboolean rspamd_symcache_check_symbol (struct rspamd_task *task,
		struct rspamd_symcache *cache,
		struct rspamd_symcache_item *item,
		struct cache_savepoint *checkpoint);
static gboolean rspamd_symcache_check_deps (struct rspamd_task *task,
		struct rspamd_symcache *cache,
		struct rspamd_symcache_item *item,
		struct cache_savepoint *checkpoint,
		guint recursion,
		gboolean check_only);
static void rspamd_symcache_disable_symbol_checkpoint (struct rspamd_task *task,
		struct rspamd_symcache *cache, const gchar *symbol);
static void rspamd_symcache_enable_symbol_checkpoint (struct rspamd_task *task,
		struct rspamd_symcache *cache, const gchar *symbol);
static void rspamd_symcache_disable_all_symbols (struct rspamd_task *task,
		struct rspamd_symcache *cache);

static void
rspamd_symcache_order_dtor (gpointer p)
{
	struct symcache_order *ord = p;

	g_ptr_array_free (ord->d, TRUE);
	g_free (ord);
}

static void
rspamd_symcache_order_unref (gpointer p)
{
	struct symcache_order *ord = p;

	REF_RELEASE (ord);
}

static struct symcache_order *
rspamd_symcache_order_new (struct rspamd_symcache *cache,
		gsize nelts)
{
	struct symcache_order *ord;

	ord = g_malloc0 (sizeof (*ord));
	ord->d = g_ptr_array_sized_new (nelts);
	ord->id = cache->id;
	REF_INIT_RETAIN (ord, rspamd_symcache_order_dtor);

	return ord;
}

static inline struct rspamd_symcache_dynamic_item*
rspamd_symcache_get_dynamic (struct cache_savepoint *checkpoint,
							 struct rspamd_symcache_item *item)
{
	return &checkpoint->dynamic_items[item->id];
}

static inline struct rspamd_symcache_item *
rspamd_symcache_find_filter (struct rspamd_symcache *cache,
							 const gchar *name)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);

	if (name == NULL) {
		return NULL;
	}

	item = g_hash_table_lookup (cache->items_by_symbol, name);

	if (item != NULL) {

		if (item->is_virtual) {
			item = g_ptr_array_index (cache->items_by_id,
					item->specific.virtual.parent);
		}

		return item;
	}

	return NULL;
}

static gint
postfilters_cmp (const void *p1, const void *p2, gpointer ud)
{
	const struct rspamd_symcache_item *i1 = *(struct rspamd_symcache_item **)p1,
			*i2 = *(struct rspamd_symcache_item **)p2;
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
	const struct rspamd_symcache_item *i1 = *(struct rspamd_symcache_item **)p1,
			*i2 = *(struct rspamd_symcache_item **)p2;
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

#define TSORT_MARK_PERM(it) (it)->order |= (1u << 31)
#define TSORT_MARK_TEMP(it) (it)->order |= (1u << 30)
#define TSORT_IS_MARKED_PERM(it) ((it)->order & (1u << 31))
#define TSORT_IS_MARKED_TEMP(it) ((it)->order & (1u << 30))
#define TSORT_UNMASK(it) ((it)->order & ~((1u << 31) | (1u << 30)))

static gint
cache_logic_cmp (const void *p1, const void *p2, gpointer ud)
{
	const struct rspamd_symcache_item *i1 = *(struct rspamd_symcache_item **)p1,
			*i2 = *(struct rspamd_symcache_item **)p2;
	struct rspamd_symcache *cache = ud;
	double w1, w2;
	double weight1, weight2;
	double f1 = 0, f2 = 0, t1, t2, avg_freq, avg_weight;
	guint o1 = TSORT_UNMASK (i1), o2 = TSORT_UNMASK (i2);


	if (o1 == o2) {
		/* Heurstic */
		if (i1->priority == i2->priority) {
			avg_freq = ((gdouble) cache->total_hits / cache->used_items);
			avg_weight = (cache->total_weight / cache->used_items);
			f1 = (double) i1->st->total_hits / avg_freq;
			f2 = (double) i2->st->total_hits / avg_freq;
			weight1 = fabs (i1->st->weight) / avg_weight;
			weight2 = fabs (i2->st->weight) / avg_weight;
			t1 = i1->st->avg_time;
			t2 = i2->st->avg_time;
			w1 = SCORE_FUN (weight1, f1, t1);
			w2 = SCORE_FUN (weight2, f2, t2);
		} else {
			/* Strict sorting */
			w1 = abs (i1->priority);
			w2 = abs (i2->priority);
		}
	}
	else {
		w1 = o1;
		w2 = o2;
	}

	if (w2 > w1) {
		return 1;
	}
	else if (w2 < w1) {
		return -1;
	}

	return 0;
}

static void
rspamd_symcache_tsort_visit (struct rspamd_symcache *cache,
								  struct rspamd_symcache_item *it,
								  guint cur_order)
{
	struct cache_dependency *dep;
	guint i;

	if (TSORT_IS_MARKED_PERM (it)) {
		if (cur_order > TSORT_UNMASK (it)) {
			/* Need to recalculate the whole chain */
			it->order = cur_order; /* That also removes all masking */
		}
		else {
			/* We are fine, stop DFS */
			return;
		}
	}
	else if (TSORT_IS_MARKED_TEMP (it)) {
		msg_err_cache ("cyclic dependencies found when checking '%s'!",
				it->symbol);
		return;
	}

	TSORT_MARK_TEMP (it);
	msg_debug_cache ("visiting node: %s (%d)", it->symbol, cur_order);

	PTR_ARRAY_FOREACH (it->deps, i, dep) {
		msg_debug_cache ("visiting dep: %s (%d)", dep->item->symbol, cur_order + 1);
		rspamd_symcache_tsort_visit (cache, dep->item, cur_order + 1);
	}

	it->order = cur_order;

	TSORT_MARK_PERM (it);
}

static void
rspamd_symcache_resort (struct rspamd_symcache *cache)
{
	struct symcache_order *ord;
	guint i;
	guint64 total_hits = 0;
	struct rspamd_symcache_item *it;

	ord = rspamd_symcache_order_new (cache, cache->filters->len);

	for (i = 0; i < cache->filters->len; i ++) {
		it = g_ptr_array_index (cache->filters, i);
		total_hits += it->st->total_hits;
		it->order = 0;
		g_ptr_array_add (ord->d, it);
	}

	/* Topological sort, intended to be O(N) but my implementation
	 * is not linear (semi-linear usually) as I want to make it as
	 * simple as possible.
	 * On each stage it does DFS for unseen nodes. In theory, that
	 * can be more complicated than linear - O(N^2) for specially
	 * crafted data. But I don't care.
	 */
	PTR_ARRAY_FOREACH (ord->d, i, it) {
		if (it->order == 0) {
			rspamd_symcache_tsort_visit (cache, it, 1);
		}
	}

	/*
	 * Now we have all sorted and can do some heuristical sort, keeping
	 * topological order invariant
	 */
	g_ptr_array_sort_with_data (ord->d, cache_logic_cmp, cache);
	cache->total_hits = total_hits;

	if (cache->items_by_order) {
		REF_RELEASE (cache->items_by_order);
	}

	cache->items_by_order = ord;
}

/* Sort items in logical order */
static void
rspamd_symcache_post_init (struct rspamd_symcache *cache)
{
	struct rspamd_symcache_item *it, *dit;
	struct cache_dependency *dep, *rdep;
	struct delayed_cache_dependency *ddep;
	struct delayed_cache_condition *dcond;
	GList *cur;
	gint i, j;

	cur = cache->delayed_deps;
	while (cur) {
		ddep = cur->data;

		it = rspamd_symcache_find_filter (cache, ddep->from);

		if (it == NULL) {
			msg_err_cache ("cannot register delayed dependency between %s and %s, "
					"%s is missing", ddep->from, ddep->to, ddep->from);
		}
		else {
			msg_debug_cache ("delayed between %s(%d) -> %s", ddep->from,
					it->id, ddep->to);
			rspamd_symcache_add_dependency (cache, it->id, ddep->to);
		}

		cur = g_list_next (cur);
	}

	cur = cache->delayed_conditions;
	while (cur) {
		dcond = cur->data;

		it = rspamd_symcache_find_filter (cache, dcond->sym);

		if (it == NULL) {
			msg_err_cache (
					"cannot register delayed condition for %s",
					dcond->sym);
			luaL_unref (dcond->L, LUA_REGISTRYINDEX, dcond->cbref);
		}
		else {
			it->specific.normal.condition_cb = dcond->cbref;
		}

		cur = g_list_next (cur);
	}

	PTR_ARRAY_FOREACH (cache->items_by_id, i, it) {

		PTR_ARRAY_FOREACH (it->deps, j, dep) {
			dit = rspamd_symcache_find_filter (cache, dep->sym);

			if (dit != NULL) {
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

		if (it->deps) {
			/* Reversed loop to make removal safe */
			for (j = it->deps->len - 1; j >= 0; j--) {
				dep = g_ptr_array_index (it->deps, j);

				if (dep->item == NULL) {
					/* Remove useless dep */
					g_ptr_array_remove_index (it->deps, j);
				}
			}
		}
	}

	g_ptr_array_sort_with_data (cache->prefilters, prefilters_cmp, cache);
	g_ptr_array_sort_with_data (cache->postfilters, postfilters_cmp, cache);
	g_ptr_array_sort_with_data (cache->idempotent, postfilters_cmp, cache);

	rspamd_symcache_resort (cache);
}

static gboolean
rspamd_symcache_load_items (struct rspamd_symcache *cache, const gchar *name)
{
	struct rspamd_symcache_header *hdr;
	struct stat st;
	struct ucl_parser *parser;
	ucl_object_t *top;
	const ucl_object_t *cur, *elt;
	ucl_object_iter_t it;
	struct rspamd_symcache_item *item, *parent;
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

	if (memcmp (hdr->magic, rspamd_symcache_magic,
			sizeof (rspamd_symcache_magic)) != 0) {
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

			if (item->is_virtual) {
				g_assert (item->specific.virtual.parent < (gint)cache->items_by_id->len);
				parent = g_ptr_array_index (cache->items_by_id,
						item->specific.virtual.parent);

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
rspamd_symcache_save_items (struct rspamd_symcache *cache, const gchar *name)
{
	struct rspamd_symcache_header hdr;
	ucl_object_t *top, *elt, *freq;
	GHashTableIter it;
	struct rspamd_symcache_item *item;
	struct ucl_emitter_functions *efunc;
	gpointer k, v;
	gint fd;
	bool ret;
	gchar path[PATH_MAX];

	rspamd_snprintf (path, sizeof (path), "%s.new", name);

	for (;;) {
		fd = open (path, O_CREAT | O_WRONLY | O_EXCL, 00644);

		if (fd == -1) {
			if (errno == EEXIST) {
				/* Some other process is already writing data, give up silently */
				return TRUE;
			}

			msg_info_cache ("cannot open file %s, error %d, %s", path,
					errno, strerror (errno));
			return FALSE;
		}

		break;
	}

	rspamd_file_lock (fd, FALSE);

	memset (&hdr, 0, sizeof (hdr));
	memcpy (hdr.magic, rspamd_symcache_magic,
			sizeof (rspamd_symcache_magic));

	if (write (fd, &hdr, sizeof (hdr)) == -1) {
		msg_info_cache ("cannot write to file %s, error %d, %s", path,
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

	if (rename (path, name) == -1) {
		msg_info_cache ("cannot rename %s -> %s, error %d, %s", path, name,
				errno, strerror (errno));
		(void)unlink (path);
		ret = FALSE;
	}

	return ret;
}

#undef ROUND_DOUBLE

gint
rspamd_symcache_add_symbol (struct rspamd_symcache *cache,
							const gchar *name,
							gint priority,
							symbol_func_t func,
							gpointer user_data,
							enum rspamd_symbol_type type,
							gint parent)
{
	struct rspamd_symcache_item *item = NULL;

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
			sizeof (struct rspamd_symcache_item));
	item->st = rspamd_mempool_alloc0_shared (cache->static_pool,
			sizeof (*item->st));
	item->enabled = TRUE;

	/*
	 * We do not share cd to skip locking, instead we'll just calculate it on
	 * save or accumulate
	 */
	item->cd = rspamd_mempool_alloc0 (cache->static_pool,
			sizeof (struct rspamd_counter_data));
	item->priority = priority;
	item->type = type;

	if ((type & SYMBOL_TYPE_FINE) && item->priority == 0) {
		/* Make priority for negative weighted symbols */
		item->priority = 1;
	}

	if (func) {
		/* Non-virtual symbol */
		g_assert (parent == -1);

		if (item->type & SYMBOL_TYPE_PREFILTER) {
			g_ptr_array_add (cache->prefilters, item);
		}
		else if (item->type & SYMBOL_TYPE_IDEMPOTENT) {
			g_ptr_array_add (cache->idempotent, item);
		}
		else if (item->type & SYMBOL_TYPE_POSTFILTER) {
			g_ptr_array_add (cache->postfilters, item);
		}
		else {
			item->is_filter = TRUE;
			g_ptr_array_add (cache->filters, item);
		}

		item->id = cache->items_by_id->len;
		g_ptr_array_add (cache->items_by_id, item);

		item->specific.normal.func = func;
		item->specific.normal.user_data = user_data;
		item->specific.normal.condition_cb = -1;
	}
	else {
		/*
		 * Three possibilities here when no function is specified:
		 * - virtual symbol
		 * - classifier symbol
		 * - composite symbol
		 */
		if (item->type & SYMBOL_TYPE_COMPOSITE) {
			item->specific.normal.condition_cb = -1;
			g_ptr_array_add (cache->composites, item);

			item->id = cache->items_by_id->len;
			g_ptr_array_add (cache->items_by_id, item);
		}
		else if (item->type & SYMBOL_TYPE_CLASSIFIER) {
			/* Treat it as normal symbol to allow enable/disable */
			item->id = cache->items_by_id->len;
			g_ptr_array_add (cache->items_by_id, item);

			item->is_filter = TRUE;
			item->specific.normal.func = NULL;
			item->specific.normal.user_data = NULL;
			item->specific.normal.condition_cb = -1;
		}
		else {
			/* Require parent */
			g_assert (parent != -1);

			item->is_virtual = TRUE;
			item->specific.virtual.parent = parent;
			item->id = cache->virtual->len;
			g_ptr_array_add (cache->virtual, item);
			/* Not added to items_by_id, handled by parent */
		}
	}

	if (item->type & SYMBOL_TYPE_SQUEEZED) {
		g_ptr_array_add (cache->squeezed, item);
	}

	cache->used_items ++;
	cache->id ++;

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
		g_assert (func != NULL);
		msg_debug_cache ("used items: %d, added unnamed symbol: %d",
				cache->used_items, item->id);
	}

	if (item->is_filter) {
		/* Only plain filters can have deps and rdeps */
		item->deps = g_ptr_array_new ();
		item->rdeps = g_ptr_array_new ();
		rspamd_mempool_add_destructor (cache->static_pool,
				rspamd_ptr_array_free_hard, item->deps);
		rspamd_mempool_add_destructor (cache->static_pool,
				rspamd_ptr_array_free_hard, item->rdeps);
	}

	if (name != NULL) {
		g_hash_table_insert (cache->items_by_symbol, item->symbol, item);
	}

	return item->id;
}

void
rspamd_symcache_set_peak_callback (struct rspamd_symcache *cache,
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
rspamd_symcache_add_condition_delayed (struct rspamd_symcache *cache,
									   const gchar *sym, lua_State *L, gint cbref)
{
	struct delayed_cache_condition *ncond;

	g_assert (cache != NULL);
	g_assert (sym != NULL);

	ncond = g_malloc0 (sizeof (*ncond));
	ncond->sym = g_strdup (sym);
	ncond->cbref = cbref;
	ncond->L = L;
	cache->id ++;

	cache->delayed_conditions = g_list_prepend (cache->delayed_conditions, ncond);

	return TRUE;
}

void
rspamd_symcache_save (struct rspamd_symcache *cache)
{
	if (cache != NULL) {

		if (cache->cfg->cache_filename) {
			/* Try to sync values to the disk */
			if (!rspamd_symcache_save_items (cache,
					cache->cfg->cache_filename)) {
				msg_err_cache ("cannot save cache data to %s",
						cache->cfg->cache_filename);
			}
		}
	}
}

void
rspamd_symcache_destroy (struct rspamd_symcache *cache)
{
	GList *cur;
	struct delayed_cache_dependency *ddep;
	struct delayed_cache_condition *dcond;

	if (cache != NULL) {
		rspamd_symcache_save (cache);

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
		g_ptr_array_free (cache->items_by_id, TRUE);
		rspamd_mempool_delete (cache->static_pool);
		g_ptr_array_free (cache->filters, TRUE);
		g_ptr_array_free (cache->prefilters, TRUE);
		g_ptr_array_free (cache->postfilters, TRUE);
		g_ptr_array_free (cache->idempotent, TRUE);
		g_ptr_array_free (cache->composites, TRUE);
		g_ptr_array_free (cache->squeezed, TRUE);
		REF_RELEASE (cache->items_by_order);

		if (cache->peak_cb != -1) {
			luaL_unref (cache->cfg->lua_state, LUA_REGISTRYINDEX, cache->peak_cb);
		}

		g_free (cache);
	}
}

struct rspamd_symcache*
rspamd_symcache_new (struct rspamd_config *cfg)
{
	struct rspamd_symcache *cache;

	cache = g_malloc0 (sizeof (struct rspamd_symcache));
	cache->static_pool =
			rspamd_mempool_new (rspamd_mempool_suggest_size (), "symcache");
	cache->items_by_symbol = g_hash_table_new (rspamd_str_hash,
			rspamd_str_equal);
	cache->items_by_id = g_ptr_array_new ();
	cache->filters = g_ptr_array_new ();
	cache->prefilters = g_ptr_array_new ();
	cache->postfilters = g_ptr_array_new ();
	cache->idempotent = g_ptr_array_new ();
	cache->composites = g_ptr_array_new ();
	cache->virtual = g_ptr_array_new ();
	cache->squeezed = g_ptr_array_new ();
	cache->reload_time = cfg->cache_reload_time;
	cache->total_hits = 1;
	cache->total_weight = 1.0;
	cache->cfg = cfg;
	cache->cksum = 0xdeadbabe;
	cache->peak_cb = -1;
	cache->id = rspamd_random_uint64_fast ();

	return cache;
}

gboolean
rspamd_symcache_init (struct rspamd_symcache *cache)
{
	gboolean res;

	g_assert (cache != NULL);

	cache->reload_time = cache->cfg->cache_reload_time;

	/* Just in-memory cache */
	if (cache->cfg->cache_filename == NULL) {
		rspamd_symcache_post_init (cache);
		return TRUE;
	}

	/* Copy saved cache entries */
	res = rspamd_symcache_load_items (cache, cache->cfg->cache_filename);
	rspamd_symcache_post_init (cache);

	return res;
}


static void
rspamd_symcache_validate_cb (gpointer k, gpointer v, gpointer ud)
{
	struct rspamd_symcache_item *item = v, *parent;
	struct rspamd_config *cfg;
	struct rspamd_symcache *cache = (struct rspamd_symcache *)ud;
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

	if (item->is_virtual) {
		g_assert (item->specific.virtual.parent < (gint)cache->items_by_id->len);
		parent = g_ptr_array_index (cache->items_by_id,
				item->specific.virtual.parent);

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
rspamd_symcache_metric_validate_cb (gpointer k, gpointer v, gpointer ud)
{
	struct rspamd_symcache *cache = (struct rspamd_symcache *)ud;
	const gchar *sym = k;
	struct rspamd_symbol *s = (struct rspamd_symbol *)v;
	gdouble weight;
	struct rspamd_symcache_item *item;

	weight = *s->weight_ptr;
	item = g_hash_table_lookup (cache->items_by_symbol, sym);

	if (item) {
		item->st->weight = weight;
	}
}

gboolean
rspamd_symcache_validate (struct rspamd_symcache *cache,
						  struct rspamd_config *cfg,
						  gboolean strict)
{
	struct rspamd_symcache_item *item;
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
			rspamd_symcache_metric_validate_cb,
			cache);

	g_hash_table_foreach (cache->items_by_symbol,
			rspamd_symcache_validate_cb,
			cache);
	/* Now check each metric item and find corresponding symbol in a cache */
	g_hash_table_iter_init (&it, cfg->symbols);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		ignore_symbol = FALSE;
		sym_def = v;

		if (sym_def && (sym_def->flags & RSPAMD_SYMBOL_FLAG_IGNORE)) {
			ignore_symbol = TRUE;
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
rspamd_symcache_metric_limit (struct rspamd_task *task,
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

static gboolean
rspamd_symcache_check_symbol (struct rspamd_task *task,
		struct rspamd_symcache *cache,
		struct rspamd_symcache_item *item,
		struct cache_savepoint *checkpoint)
{
	double t1 = 0;
	struct rspamd_task **ptask;
	lua_State *L;
	gboolean check = TRUE;
	struct rspamd_symcache_dynamic_item *dyn_item =
			rspamd_symcache_get_dynamic (checkpoint, item);

	if (item->type & (SYMBOL_TYPE_CLASSIFIER|SYMBOL_TYPE_COMPOSITE)) {
		/* Classifiers are special :( */
		return TRUE;
	}

	if (rspamd_session_blocked (task->s)) {
		/*
		 * We cannot add new events as session is either destroyed or
		 * being cleaned up.
		 */
		return TRUE;
	}

	g_assert (!item->is_virtual);
	g_assert (item->specific.normal.func != NULL);
	if (CHECK_START_BIT (checkpoint, dyn_item)) {
		/*
		 * This can actually happen when deps span over different layers
		 */
		return CHECK_FINISH_BIT (checkpoint, dyn_item);
	}

	/* Check has been started */
	SET_START_BIT (checkpoint, dyn_item);

	if (!item->enabled ||
		(RSPAMD_TASK_IS_EMPTY (task) && !(item->type & SYMBOL_TYPE_EMPTY))) {
		check = FALSE;
	}
	else if (item->specific.normal.condition_cb != -1) {
		/* We also executes condition callback to check if we need this symbol */
		L = task->cfg->lua_state;
		lua_rawgeti (L, LUA_REGISTRYINDEX, item->specific.normal.condition_cb);
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
		msg_debug_cache_task ("execute %s, %d", item->symbol, item->id);
#ifdef HAVE_EVENT_NO_CACHE_TIME_FUNC
		struct timeval tv;

		event_base_update_cache_time (task->ev_base);
		event_base_gettimeofday_cached (task->ev_base, &tv);
		t1 = tv_to_double (&tv);
#else
		t1 = rspamd_get_ticks (FALSE);
#endif
		dyn_item->start_msec = (t1 - task->time_real) * 1e3;
		dyn_item->async_events = 0;
		checkpoint->cur_item = item;
		checkpoint->items_inflight ++;
		/* Callback now must finalize itself */
		item->specific.normal.func (task, item, item->specific.normal.user_data);
		checkpoint->cur_item = NULL;

		if (checkpoint->items_inflight == 0) {

			return TRUE;
		}

		if (dyn_item->async_events == 0 && !CHECK_FINISH_BIT (checkpoint, dyn_item)) {
			msg_err_cache ("critical error: item %s has no async events pending, "
						   "but it is not finalised", item->symbol);
			g_assert_not_reached ();
		}

		return FALSE;
	}
	else {
		msg_debug_cache_task ("skipping check of %s as its start condition is false",
				item->symbol);
		SET_FINISH_BIT (checkpoint, dyn_item);
	}

	return TRUE;
}

static gboolean
rspamd_symcache_check_deps (struct rspamd_task *task,
		struct rspamd_symcache *cache,
		struct rspamd_symcache_item *item,
		struct cache_savepoint *checkpoint,
		guint recursion,
		gboolean check_only)
{
	struct cache_dependency *dep;
	guint i;
	gboolean ret = TRUE;
	static const guint max_recursion = 20;
	struct rspamd_symcache_dynamic_item *dyn_item;

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
				msg_debug_cache_task ("symbol %d(%s) has invalid dependencies on %d(%s)",
						item->id, item->symbol, dep->id, dep->sym);
				continue;
			}

			dyn_item = rspamd_symcache_get_dynamic (checkpoint, dep->item);

			if (!CHECK_FINISH_BIT (checkpoint, dyn_item)) {
				if (!CHECK_START_BIT (checkpoint, dyn_item)) {
					/* Not started */
					if (!check_only) {
						if (!rspamd_symcache_check_deps (task, cache,
								dep->item,
								checkpoint,
								recursion + 1,
								check_only)) {

							ret = FALSE;
							msg_debug_cache_task ("delayed dependency %d(%s) for "
											"symbol %d(%s)",
									dep->id, dep->sym, item->id, item->symbol);
						}
						else if (!rspamd_symcache_check_symbol (task, cache,
								dep->item,
								checkpoint)) {
							/* Now started, but has events pending */
							ret = FALSE;
							msg_debug_cache_task ("started check of %d(%s) symbol "
											"as dep for "
											"%d(%s)",
									dep->id, dep->sym, item->id, item->symbol);
						}
						else {
							msg_debug_cache_task ("dependency %d(%s) for symbol %d(%s) is "
									"already processed",
									dep->id, dep->sym, item->id, item->symbol);
						}
					}
					else {
						msg_debug_cache_task ("dependency %d(%s) for symbol %d(%s) "
										"cannot be started now",
								dep->id, dep->sym,
								item->id, item->symbol);
						ret = FALSE;
					}
				}
				else {
					/* Started but not finished */
					msg_debug_cache_task ("dependency %d(%s) for symbol %d(%s) is "
									"still executing",
							dep->id, dep->sym,
							item->id, item->symbol);
					ret = FALSE;
				}
			}
			else {
				msg_debug_cache_task ("dependency %d(%s) for symbol %d(%s) is already "
						"checked",
						dep->id, dep->sym,
						item->id, item->symbol);
			}
		}
	}

	return ret;
}

static struct cache_savepoint *
rspamd_symcache_make_checkpoint (struct rspamd_task *task,
		struct rspamd_symcache *cache)
{
	struct cache_savepoint *checkpoint;

	if (cache->items_by_order->id != cache->id) {
		/*
		 * Cache has been modified, need to resort it
		 */
		msg_info_cache ("symbols cache has been modified since last check:"
				" old id: %ud, new id: %ud",
				cache->items_by_order->id, cache->id);
		rspamd_symcache_resort (cache);
	}

	checkpoint = rspamd_mempool_alloc0 (task->task_pool,
			sizeof (*checkpoint) +
			sizeof (struct rspamd_symcache_dynamic_item) * cache->items_by_id->len);

	g_assert (cache->items_by_order != NULL);
	checkpoint->version = cache->items_by_order->d->len;
	checkpoint->order = cache->items_by_order;
	REF_RETAIN (checkpoint->order);
	rspamd_mempool_add_destructor (task->task_pool,
			rspamd_symcache_order_unref, checkpoint->order);

	checkpoint->pass = RSPAMD_CACHE_PASS_INIT;
	task->checkpoint = checkpoint;

	task->result = task->result;

	return checkpoint;
}

gboolean
rspamd_symcache_process_settings (struct rspamd_task *task,
								  struct rspamd_symcache *cache)
{
	const ucl_object_t *wl, *cur, *disabled, *enabled;
	struct rspamd_symbols_group *gr;
	GHashTableIter gr_it;
	ucl_object_iter_t it = NULL;
	gboolean already_disabled = FALSE;
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
		rspamd_symcache_disable_all_symbols (task, cache);
		already_disabled = TRUE;
		it = NULL;

		while ((cur = ucl_iterate_object (enabled, &it, true)) != NULL) {
			rspamd_symcache_enable_symbol_checkpoint (task, cache,
					ucl_object_tostring (cur));
		}
	}

	/* Enable groups of symbols */
	enabled = ucl_object_lookup (task->settings, "groups_enabled");

	if (enabled) {
		it = NULL;

		if (!already_disabled) {
			rspamd_symcache_disable_all_symbols (task, cache);
		}

		while ((cur = ucl_iterate_object (enabled, &it, true)) != NULL) {
			if (ucl_object_type (cur) == UCL_STRING) {
				gr = g_hash_table_lookup (task->cfg->groups,
						ucl_object_tostring (cur));

				if (gr) {
					g_hash_table_iter_init (&gr_it, gr->symbols);

					while (g_hash_table_iter_next (&gr_it, &k, &v)) {
						rspamd_symcache_enable_symbol_checkpoint (task, cache, k);
					}
				}
			}
		}
	}

	disabled = ucl_object_lookup (task->settings, "symbols_disabled");

	if (disabled) {
		it = NULL;

		while ((cur = ucl_iterate_object (disabled, &it, true)) != NULL) {
			rspamd_symcache_disable_symbol_checkpoint (task, cache,
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
						rspamd_symcache_disable_symbol_checkpoint (task, cache, k);
					}
				}
			}
		}
	}

	return FALSE;
}

gboolean
rspamd_symcache_process_symbols (struct rspamd_task *task,
								 struct rspamd_symcache *cache, gint stage)
{
	struct rspamd_symcache_item *item = NULL;
	struct rspamd_symcache_dynamic_item *dyn_item;
	struct cache_savepoint *checkpoint;
	gint i;
	gboolean all_done;
	gint saved_priority;
	guint start_events_pending;

	g_assert (cache != NULL);

	if (task->checkpoint == NULL) {
		checkpoint = rspamd_symcache_make_checkpoint (task, cache);
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

	msg_debug_cache_task ("symbols processing stage at pass: %d", checkpoint->pass);
	start_events_pending = rspamd_session_events_pending (task->s);

	switch (checkpoint->pass) {
	case RSPAMD_CACHE_PASS_INIT:
	case RSPAMD_CACHE_PASS_PREFILTERS:
		/* Check for prefilters */
		saved_priority = G_MININT;
		all_done = TRUE;

		for (i = 0; i < (gint)cache->prefilters->len; i ++) {
			item = g_ptr_array_index (cache->prefilters, i);
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (RSPAMD_TASK_IS_SKIPPED (task)) {
				return TRUE;
			}

			if (!CHECK_START_BIT (checkpoint, dyn_item) &&
					!CHECK_FINISH_BIT (checkpoint, dyn_item)) {
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

				rspamd_symcache_check_symbol (task, cache, item,
						checkpoint);
				all_done = FALSE;
			}
		}

		if (all_done || stage == RSPAMD_TASK_STAGE_FILTERS) {
			checkpoint->pass = RSPAMD_CACHE_PASS_FILTERS;
		}

		if (stage == RSPAMD_TASK_STAGE_FILTERS) {
			return rspamd_symcache_process_symbols (task, cache, stage);
		}

		break;

	case RSPAMD_CACHE_PASS_FILTERS:
		/*
		 * On the first pass we check symbols that do not have dependencies
		 * If we figure out symbol that has no dependencies satisfied, then
		 * we just save it for another pass
		 */
		all_done = TRUE;

		for (i = 0; i < (gint)checkpoint->version; i ++) {
			if (RSPAMD_TASK_IS_SKIPPED (task)) {
				return TRUE;
			}

			item = g_ptr_array_index (checkpoint->order->d, i);
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (item->type & SYMBOL_TYPE_CLASSIFIER) {
				continue;
			}

			if (!CHECK_START_BIT (checkpoint, dyn_item)) {
				all_done = FALSE;

				if (!rspamd_symcache_check_deps (task, cache, item,
						checkpoint, 0, FALSE)) {

					msg_debug_cache_task ("blocked execution of %d(%s) unless deps are "
							"resolved",
							item->id, item->symbol);

					continue;
				}

				rspamd_symcache_check_symbol (task, cache, item,
						checkpoint);
			}

			if (!(item->type & SYMBOL_TYPE_FINE)) {
				if (rspamd_symcache_metric_limit (task, checkpoint)) {
					msg_info_task ("<%s> has already scored more than %.2f, so do "
								   "not "
								   "plan more checks", task->message_id,
							checkpoint->rs->score);
					all_done = TRUE;
					break;
				}
			}
		}

		if (all_done || stage == RSPAMD_TASK_STAGE_POST_FILTERS) {
			checkpoint->pass = RSPAMD_CACHE_PASS_POSTFILTERS;
		}

		if (stage == RSPAMD_TASK_STAGE_POST_FILTERS) {

			return rspamd_symcache_process_symbols (task, cache, stage);
		}

		break;

	case RSPAMD_CACHE_PASS_POSTFILTERS:
		/* Check for postfilters */
		saved_priority = G_MININT;
		all_done = TRUE;

		for (i = 0; i < (gint)cache->postfilters->len; i ++) {
			if (RSPAMD_TASK_IS_SKIPPED (task)) {
				return TRUE;
			}

			item = g_ptr_array_index (cache->postfilters, i);
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (!CHECK_START_BIT (checkpoint, dyn_item) &&
					!CHECK_FINISH_BIT (checkpoint, dyn_item)) {
				/* Check priorities */
				all_done = FALSE;

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

				rspamd_symcache_check_symbol (task, cache, item,
						checkpoint);
			}
		}

		if (all_done) {
			checkpoint->pass = RSPAMD_CACHE_PASS_IDEMPOTENT;
		}

		if (checkpoint->items_inflight == 0 ||
				stage == RSPAMD_TASK_STAGE_IDEMPOTENT) {
			checkpoint->pass = RSPAMD_CACHE_PASS_IDEMPOTENT;
		}

		if (stage == RSPAMD_TASK_STAGE_IDEMPOTENT) {
			return rspamd_symcache_process_symbols (task, cache, stage);
		}

		break;

	case RSPAMD_CACHE_PASS_IDEMPOTENT:
		/* Check for postfilters */
		saved_priority = G_MININT;

		for (i = 0; i < (gint)cache->idempotent->len; i ++) {
			item = g_ptr_array_index (cache->idempotent, i);
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (!CHECK_START_BIT (checkpoint, dyn_item) &&
					!CHECK_FINISH_BIT (checkpoint, dyn_item)) {
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
				rspamd_symcache_check_symbol (task, cache, item,
						checkpoint);
			}
		}
		checkpoint->pass = RSPAMD_CACHE_PASS_WAIT_IDEMPOTENT;
		break;

	case RSPAMD_CACHE_PASS_WAIT_IDEMPOTENT:
		all_done = TRUE;

		for (i = 0; i < (gint)cache->idempotent->len; i ++) {
			item = g_ptr_array_index (cache->idempotent, i);
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (!CHECK_FINISH_BIT (checkpoint, dyn_item)) {
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
	struct rspamd_symcache *cache;
};

#define ROUND_DOUBLE(x) (floor((x) * 100.0) / 100.0)

static void
rspamd_symcache_counters_cb (gpointer k, gpointer v, gpointer ud)
{
	struct counters_cbdata *cbd = ud;
	ucl_object_t *obj, *top;
	struct rspamd_symcache_item *item = v, *parent;
	const gchar *symbol = k;

	top = cbd->top;

	obj = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (obj, ucl_object_fromstring (symbol ? symbol : "unknown"),
			"symbol", 0, false);

	if (item->is_virtual) {
		parent = g_ptr_array_index (cbd->cache->items_by_id,
				item->specific.virtual.parent);
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

#undef ROUND_DOUBLE

ucl_object_t *
rspamd_symcache_counters (struct rspamd_symcache *cache)
{
	ucl_object_t *top;
	struct counters_cbdata cbd;

	g_assert (cache != NULL);
	top = ucl_object_typed_new (UCL_ARRAY);
	cbd.top = top;
	cbd.cache = cache;
	g_hash_table_foreach (cache->items_by_symbol,
			rspamd_symcache_counters_cb, &cbd);

	return top;
}

static void
rspamd_symcache_call_peak_cb (struct event_base *ev_base,
		struct rspamd_symcache *cache,
		struct rspamd_symcache_item *item,
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
rspamd_symcache_resort_cb (gint fd, short what, gpointer ud)
{
	struct timeval tv;
	gdouble tm;
	struct rspamd_cache_refresh_cbdata *cbdata = ud;
	struct rspamd_symcache *cache;
	struct rspamd_symcache_item *item;
	guint i;
	gdouble cur_ticks;
	static const double decay_rate = 0.7;

	cache = cbdata->cache;
	/* Plan new event */
	tm = rspamd_time_jitter (cache->reload_time, 0);
	cur_ticks = rspamd_get_ticks (FALSE);
	msg_debug_cache ("resort symbols cache, next reload in %.2f seconds", tm);
	g_assert (cache != NULL);
	evtimer_set (&cbdata->resort_ev, rspamd_symcache_resort_cb, cbdata);
	event_base_set (cbdata->ev_base, &cbdata->resort_ev);
	double_to_tv (tm, &tv);
	event_add (&cbdata->resort_ev, &tv);

	if (rspamd_worker_is_primary_controller (cbdata->w)) {
		/* Gather stats from shared execution times */
		for (i = 0; i < cache->filters->len; i ++) {
			item = g_ptr_array_index (cache->filters, i);
			item->st->total_hits += item->st->hits;
			g_atomic_int_set (&item->st->hits, 0);

			if (item->last_count > 0 && cbdata->w->index == 0) {
				/* Calculate frequency */
				gdouble cur_err, cur_value;

				cur_value = (item->st->total_hits - item->last_count) /
							(cur_ticks - cbdata->last_resort);
				rspamd_set_counter_ema (&item->st->frequency_counter,
						cur_value, decay_rate);
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
						rspamd_symcache_call_peak_cb (cbdata->ev_base,
								cache, item,
								cur_value, cur_err);
					}
				}
			}

			item->last_count = item->st->total_hits;

			if (item->cd->number > 0) {
				if (item->type & (SYMBOL_TYPE_CALLBACK|SYMBOL_TYPE_NORMAL)) {
					item->st->avg_time = item->cd->mean;
					rspamd_set_counter_ema (&item->st->time_counter,
							item->st->avg_time, decay_rate);
					item->st->avg_time = item->st->time_counter.mean;
					memset (item->cd, 0, sizeof (*item->cd));
				}
			}
		}


		cbdata->last_resort = cur_ticks;
		/* We don't do actual sorting due to topological guarantees */
	}
}

void
rspamd_symcache_start_refresh (struct rspamd_symcache *cache,
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
	evtimer_set (&cbdata->resort_ev, rspamd_symcache_resort_cb,
			cbdata);
	event_base_set (ev_base, &cbdata->resort_ev);
	double_to_tv (tm, &tv);
	event_add (&cbdata->resort_ev, &tv);
	rspamd_mempool_add_destructor (cache->static_pool,
			(rspamd_mempool_destruct_t) event_del,
			&cbdata->resort_ev);
}

void
rspamd_symcache_inc_frequency (struct rspamd_symcache *cache,
							   const gchar *symbol)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);

	item = g_hash_table_lookup (cache->items_by_symbol, symbol);

	if (item != NULL) {
		g_atomic_int_inc (&item->st->hits);
	}
}

void
rspamd_symcache_add_dependency (struct rspamd_symcache *cache,
								gint id_from, const gchar *to)
{
	struct rspamd_symcache_item *source;
	struct cache_dependency *dep;

	g_assert (id_from >= 0 && id_from < (gint)cache->items_by_id->len);

	source = g_ptr_array_index (cache->items_by_id, id_from);
	dep = rspamd_mempool_alloc (cache->static_pool, sizeof (*dep));
	dep->id = id_from;
	dep->sym = rspamd_mempool_strdup (cache->static_pool, to);
	/* Will be filled later */
	dep->item = NULL;
	g_ptr_array_add (source->deps, dep);
}

void
rspamd_symcache_add_delayed_dependency (struct rspamd_symcache *cache,
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
rspamd_symcache_find_symbol (struct rspamd_symcache *cache, const gchar *name)
{
	struct rspamd_symcache_item *item;

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
rspamd_symcache_stat_symbol (struct rspamd_symcache *cache,
							 const gchar *name,
							 gdouble *frequency,
							 gdouble *freq_stddev,
							 gdouble *tm,
							 guint *nhits)
{
	struct rspamd_symcache_item *item;

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

const gchar *
rspamd_symcache_symbol_by_id (struct rspamd_symcache *cache,
							  gint id)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);

	if (id < 0 || id >= (gint)cache->items_by_id->len) {
		return NULL;
	}

	item = g_ptr_array_index (cache->items_by_id, id);

	return item->symbol;
}

guint
rspamd_symcache_stats_symbols_count (struct rspamd_symcache *cache)
{
	g_assert (cache != NULL);

	return cache->stats_symbols_count;
}


static void
rspamd_symcache_disable_all_symbols (struct rspamd_task *task,
		struct rspamd_symcache *cache)
{
	struct cache_savepoint *checkpoint;
	guint i;
	struct rspamd_symcache_item *item;
	struct rspamd_symcache_dynamic_item *dyn_item;

	if (task->checkpoint == NULL) {
		checkpoint = rspamd_symcache_make_checkpoint (task, cache);
		task->checkpoint = checkpoint;
	}
	else {
		checkpoint = task->checkpoint;
	}

	/* Enable for squeezed symbols */
	PTR_ARRAY_FOREACH (cache->items_by_id, i, item) {
		dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

		if (!(item->type & SYMBOL_TYPE_SQUEEZED)) {
			SET_FINISH_BIT (checkpoint, dyn_item);
			SET_START_BIT (checkpoint, dyn_item);
		}
	}
}

static void
rspamd_symcache_disable_symbol_checkpoint (struct rspamd_task *task,
		struct rspamd_symcache *cache, const gchar *symbol)
{
	struct cache_savepoint *checkpoint;
	struct rspamd_symcache_item *item;
	struct rspamd_symcache_dynamic_item *dyn_item;

	if (task->checkpoint == NULL) {
		checkpoint = rspamd_symcache_make_checkpoint (task, cache);
		task->checkpoint = checkpoint;
	}
	else {
		checkpoint = task->checkpoint;
	}

	item = rspamd_symcache_find_filter (cache, symbol);

	if (item) {
		if (!(item->type & SYMBOL_TYPE_SQUEEZED)) {
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);
			SET_FINISH_BIT (checkpoint, dyn_item);
			SET_START_BIT (checkpoint, dyn_item);
			msg_debug_cache_task ("disable execution of %s", symbol);
		}
		else {
			msg_debug_cache_task ("skip disabling squeezed symbol %s", symbol);
		}
	}
	else {
		msg_info_task ("cannot disable %s: not found", symbol);
	}
}

static void
rspamd_symcache_enable_symbol_checkpoint (struct rspamd_task *task,
		struct rspamd_symcache *cache, const gchar *symbol)
{
	struct cache_savepoint *checkpoint;
	struct rspamd_symcache_item *item;
	struct rspamd_symcache_dynamic_item *dyn_item;

	if (task->checkpoint == NULL) {
		checkpoint = rspamd_symcache_make_checkpoint (task, cache);
		task->checkpoint = checkpoint;
	}
	else {
		checkpoint = task->checkpoint;
	}

	item = rspamd_symcache_find_filter (cache, symbol);

	if (item) {
		if (!(item->type & SYMBOL_TYPE_SQUEEZED)) {
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);
			dyn_item->finished = 0;
			dyn_item->started = 0;
			msg_debug_cache_task ("enable execution of %s", symbol);
		}
		else {
			msg_debug_cache_task ("skip enabling squeezed symbol %s", symbol);
		}
	}
	else {
		msg_info_task ("cannot enable %s: not found", symbol);
	}
}

struct rspamd_abstract_callback_data*
rspamd_symcache_get_cbdata (struct rspamd_symcache *cache,
							const gchar *symbol)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	item = rspamd_symcache_find_filter (cache, symbol);

	if (item) {
		return item->specific.normal.user_data;
	}

	return NULL;
}

gboolean
rspamd_symcache_is_checked (struct rspamd_task *task,
							struct rspamd_symcache *cache, const gchar *symbol)
{
	struct cache_savepoint *checkpoint;
	struct rspamd_symcache_item *item;
	struct rspamd_symcache_dynamic_item *dyn_item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	if (task->checkpoint == NULL) {
		checkpoint = rspamd_symcache_make_checkpoint (task, cache);
		task->checkpoint = checkpoint;
	}
	else {
		checkpoint = task->checkpoint;
	}

	item = rspamd_symcache_find_filter (cache, symbol);

	if (item) {
		dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);
		return dyn_item->started;
	}

	return FALSE;
}

void
rspamd_symcache_disable_symbol (struct rspamd_symcache *cache,
								const gchar *symbol)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	item = g_hash_table_lookup (cache->items_by_symbol, symbol);

	if (item) {
		item->enabled = FALSE;
	}
}

void
rspamd_symcache_enable_symbol (struct rspamd_symcache *cache,
							   const gchar *symbol)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	item = g_hash_table_lookup (cache->items_by_symbol, symbol);

	if (item) {
		item->enabled = TRUE;
	}
}

guint64
rspamd_symcache_get_cksum (struct rspamd_symcache *cache)
{
	g_assert (cache != NULL);

	return cache->cksum;
}


gboolean
rspamd_symcache_is_symbol_enabled (struct rspamd_task *task,
								   struct rspamd_symcache *cache,
								   const gchar *symbol)
{
	struct cache_savepoint *checkpoint;
	struct rspamd_symcache_item *item;
	struct rspamd_symcache_dynamic_item *dyn_item;
	lua_State *L;
	struct rspamd_task **ptask;
	gboolean ret = TRUE;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	checkpoint = task->checkpoint;


	if (checkpoint) {
		item = rspamd_symcache_find_filter (cache, symbol);

		if (item) {
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);
			if (CHECK_START_BIT (checkpoint, dyn_item)) {
				ret = FALSE;
			}
			else {
				if (item->specific.normal.condition_cb != -1) {
					/* We also executes condition callback to check if we need this symbol */
					L = task->cfg->lua_state;
					lua_rawgeti (L, LUA_REGISTRYINDEX,
							item->specific.normal.condition_cb);
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
	}

	return ret;
}

void
rspamd_symcache_foreach (struct rspamd_symcache *cache,
						 void (*func) (gint, const gchar *, gint, gpointer),
						 gpointer ud)
{
	struct rspamd_symcache_item *item;
	GHashTableIter it;
	gpointer k, v;

	g_hash_table_iter_init (&it, cache->items_by_symbol);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		item = (struct rspamd_symcache_item *)v;
		func (item->id, item->symbol, item->type, ud);
	}
}

struct rspamd_symcache_item *
rspamd_symcache_get_cur_item (struct rspamd_task *task)
{
	struct cache_savepoint *checkpoint = task->checkpoint;

	if (checkpoint == NULL) {
		return NULL;
	}

	return checkpoint->cur_item;
}

/**
 * Replaces the current item being processed.
 * Returns the current item being processed (if any)
 * @param task
 * @param item
 * @return
 */
struct rspamd_symcache_item *
rspamd_symcache_set_cur_item (struct rspamd_task *task,
							  struct rspamd_symcache_item *item)
{
	struct cache_savepoint *checkpoint = task->checkpoint;
	struct rspamd_symcache_item *ex;

	ex = checkpoint->cur_item;
	checkpoint->cur_item = item;

	return ex;
}


/**
 * Finalize the current async element potentially calling its deps
 */
void
rspamd_symcache_finalize_item (struct rspamd_task *task,
							   struct rspamd_symcache_item *item)
{
	struct cache_savepoint *checkpoint = task->checkpoint;
	struct cache_dependency *rdep;
	struct rspamd_symcache_dynamic_item *dyn_item;
	gdouble t2, diff;
	guint i;
	struct timeval tv;
	const gdouble slow_diff_limit = 300;

	/* Sanity checks */
	g_assert (checkpoint->items_inflight > 0);
	dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

	if (dyn_item->async_events > 0) {
		/*
		 * XXX: Race condition
		 *
		 * It is possible that some async event is still in flight, but we
		 * already know its result, however, it is the responsibility of that
		 * event to decrease async events count and call this function
		 * one more time
		 */
		msg_debug_cache_task ("postpone finalisation of %s(%d) as there are %d "
							  "async events pendning",
							  item->symbol, item->id, dyn_item->async_events);

		return;
	}

	msg_debug_cache_task ("process finalize for item %s(%d)", item->symbol, item->id);
	SET_FINISH_BIT (checkpoint, dyn_item);
	checkpoint->items_inflight --;
	checkpoint->cur_item = NULL;

#ifdef HAVE_EVENT_NO_CACHE_TIME_FUNC
	event_base_update_cache_time (task->ev_base);
	event_base_gettimeofday_cached (task->ev_base, &tv);
	t2 = tv_to_double (&tv);
#else
	t2 = rspamd_get_ticks (FALSE);
#endif

	diff = ((t2 - task->time_real) * 1e3 - dyn_item->start_msec);

	if (G_UNLIKELY (RSPAMD_TASK_IS_PROFILING (task))) {
		rspamd_task_profile_set (task, item->symbol, diff);
	}

	if (!(item->type & SYMBOL_TYPE_SQUEEZED)) {
		if (diff > slow_diff_limit) {
			msg_info_task ("slow rule: %s(%d): %.2f ms", item->symbol, item->id,
					diff);
		}

		if (rspamd_worker_is_scanner (task->worker)) {
			rspamd_set_counter (item->cd, diff);
		}
	}

	/* Process all reverse dependencies */
	PTR_ARRAY_FOREACH (item->rdeps, i, rdep) {
		if (rdep->item) {
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, rdep->item);
			if (!CHECK_START_BIT (checkpoint, dyn_item)) {
				msg_debug_cache_task ("check item %d(%s) rdep of %s ",
						rdep->item->id, rdep->item->symbol, item->symbol);

				if (!rspamd_symcache_check_deps (task, task->cfg->cache,
						rdep->item,
						checkpoint, 0, FALSE)) {
					msg_debug_cache_task ("blocked execution of %d(%s) rdep of %s "
						   "unless deps are resolved",
							rdep->item->id, rdep->item->symbol, item->symbol);
				}
				else {
					rspamd_symcache_check_symbol (task, task->cfg->cache,
							rdep->item,
							checkpoint);
				}
			}
		}
	}
}

guint
rspamd_symcache_item_async_inc_full (struct rspamd_task *task,
								struct rspamd_symcache_item *item,
								const gchar *subsystem,
								const gchar *loc)
{
	struct rspamd_symcache_dynamic_item *dyn_item;
	struct cache_savepoint *checkpoint = task->checkpoint;

	dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);
	msg_debug_cache_task ("increase async events counter for %s(%d) = %d + 1; "
					   "subsystem %s (%s)",
			item->symbol, item->id, dyn_item->async_events, subsystem, loc);
	return ++dyn_item->async_events;
}

guint
rspamd_symcache_item_async_dec_full (struct rspamd_task *task,
								struct rspamd_symcache_item *item,
								const gchar *subsystem,
								const gchar *loc)
{
	struct rspamd_symcache_dynamic_item *dyn_item;
	struct cache_savepoint *checkpoint = task->checkpoint;

	dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);
	msg_debug_cache_task ("decrease async events counter for %s(%d) = %d - 1; "
					   "subsystem %s (%s)",
			item->symbol, item->id, dyn_item->async_events, subsystem, loc);
	g_assert (dyn_item->async_events > 0);

	return --dyn_item->async_events;
}

gboolean
rspamd_symcache_item_async_dec_check_full (struct rspamd_task *task,
									  struct rspamd_symcache_item *item,
									  const gchar *subsystem,
									  const gchar *loc)
{
	if (rspamd_symcache_item_async_dec_full (task, item, subsystem, loc) == 0) {
		rspamd_symcache_finalize_item (task, item);

		return TRUE;
	}

	return FALSE;
}