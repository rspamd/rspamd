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
#include "khash.h"
#include "utlist.h"
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
#define CLR_START_BIT(checkpoint, dyn_item) \
	(dyn_item)->started = 0

#define CHECK_FINISH_BIT(checkpoint, dyn_item) \
	((dyn_item)->finished)
#define SET_FINISH_BIT(checkpoint, dyn_item) \
	(dyn_item)->finished = 1
#define CLR_FINISH_BIT(checkpoint, dyn_item) \
	(dyn_item)->finished = 0
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

/*
 * This structure is optimised to store ids list:
 * - If the first element is -1 then use dynamic part, else use static part
 */
struct rspamd_symcache_id_list {
	union {
		guint32 st[4];
		struct {
			guint32 e; /* First element */
			guint16 len;
			guint16 allocated;
			guint *n;
		} dyn;
	};
};

struct rspamd_symcache_condition {
	gint cb;
	struct rspamd_symcache_condition *prev, *next;
};

struct rspamd_symcache_item {
	/* This block is likely shared */
	struct rspamd_symcache_item_stat *st;

	guint64 last_count;
	struct rspamd_counter_data *cd;
	gchar *symbol;
	const gchar *type_descr;
	gint type;

	/* Callback data */
	union {
		struct {
			symbol_func_t func;
			gpointer user_data;
			struct rspamd_symcache_condition *conditions;
		} normal;
		struct {
			gint parent;
			struct rspamd_symcache_item *parent_item;
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
	/* Settings ids */
	struct rspamd_symcache_id_list allowed_ids;
	/* Allows execution but not symbols insertion */
	struct rspamd_symcache_id_list exec_only_ids;
	struct rspamd_symcache_id_list forbidden_ids;

	/* Dependencies */
	GPtrArray *deps;
	GPtrArray *rdeps;

	/* Container */
	GPtrArray *container;
};

struct rspamd_symcache {
	/* Hash table for fast access */
	GHashTable *items_by_symbol;
	GPtrArray *items_by_id;
	struct symcache_order *items_by_order;
	GPtrArray *connfilters;
	GPtrArray *prefilters;
	GPtrArray *filters;
	GPtrArray *postfilters;
	GPtrArray *composites;
	GPtrArray *idempotent;
	GPtrArray *virtual;
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
	gdouble last_profile;
	gint peak_cb;
};

struct rspamd_symcache_dynamic_item {
	guint16 start_msec; /* Relative to task time */
	unsigned started:1;
	unsigned finished:1;
	/* unsigned pad:14; */
	guint32 async_events;
};



struct cache_dependency {
	struct rspamd_symcache_item *item; /* Real dependency */
	gchar *sym; /* Symbolic dep name */
	gint id; /* Real from */
	gint vid; /* Virtual from */
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

struct cache_savepoint {
	guint version;
	guint items_inflight;
	gboolean profile;
	gboolean has_slow;
	gdouble profile_start;

	struct rspamd_scan_result *rs;
	gdouble lim;

	struct rspamd_symcache_item *cur_item;
	struct symcache_order *order;
	struct rspamd_symcache_dynamic_item dynamic_items[];
};

struct rspamd_cache_refresh_cbdata {
	gdouble last_resort;
	ev_timer resort_ev;
	struct rspamd_symcache *cache;
	struct rspamd_worker *w;
	struct ev_loop *event_loop;
};

/* At least once per minute */
#define PROFILE_MAX_TIME (60.0)
/* For messages larger than 2Mb enable profiling */
#define PROFILE_MESSAGE_SIZE_THRESHOLD (1024 * 1024 * 2)
/* Enable profile at least once per this amount of messages processed */
#define PROFILE_PROBABILITY (0.01)

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

static gint
rspamd_id_cmp (const void * a, const void * b)
{
	return (*(guint32*)a - *(guint32*)b);
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
							 const gchar *name,
							 bool resolve_parent)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);

	if (name == NULL) {
		return NULL;
	}

	item = g_hash_table_lookup (cache->items_by_symbol, name);

	if (item != NULL) {

		if (resolve_parent && item->is_virtual && !(item->type & SYMBOL_TYPE_GHOST)) {
			item =item->specific.virtual.parent_item;
		}

		return item;
	}

	return NULL;
}

const gchar *
rspamd_symcache_get_parent (struct rspamd_symcache *cache,
										 const gchar *symbol)
{
	struct rspamd_symcache_item *item, *parent;

	g_assert (cache != NULL);

	if (symbol == NULL) {
		return NULL;
	}

	item = g_hash_table_lookup (cache->items_by_symbol, symbol);

	if (item != NULL) {

		if (item->is_virtual && !(item->type & SYMBOL_TYPE_GHOST)) {
			parent = item->specific.virtual.parent_item;

			if (!parent) {
				item->specific.virtual.parent_item = g_ptr_array_index (cache->items_by_id,
						item->specific.virtual.parent);
				parent = item->specific.virtual.parent_item;
			}

			item = parent;
		}

		return item->symbol;
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

static void
rspamd_symcache_propagate_dep (struct rspamd_symcache *cache,
							   struct rspamd_symcache_item *it,
							   struct rspamd_symcache_item *dit)
{
	const guint *ids;
	guint nids = 0;

	msg_debug_cache ("check id propagation for dependency %s from %s",
			it->symbol, dit->symbol);
	ids = rspamd_symcache_get_allowed_settings_ids (cache, dit->symbol, &nids);

	/* TODO: merge? */
	if (nids > 0) {
		msg_info_cache ("propagate allowed ids from %s to %s",
				dit->symbol, it->symbol);

		rspamd_symcache_set_allowed_settings_ids (cache, it->symbol, ids,
				nids);
	}

	ids = rspamd_symcache_get_forbidden_settings_ids (cache, dit->symbol, &nids);

	if (nids > 0) {
		msg_info_cache ("propagate forbidden ids from %s to %s",
				dit->symbol, it->symbol);

		rspamd_symcache_set_forbidden_settings_ids (cache, it->symbol, ids,
				nids);
	}
}

static void
rspamd_symcache_process_dep (struct rspamd_symcache *cache,
							 struct rspamd_symcache_item *it,
							 struct cache_dependency *dep)
{
	struct rspamd_symcache_item *dit = NULL, *vdit = NULL;
	struct cache_dependency *rdep;

	if (dep->id >= 0) {
		msg_debug_cache ("process real dependency %s on %s", it->symbol, dep->sym);
		dit = rspamd_symcache_find_filter (cache, dep->sym, true);
	}

	if (dep->vid >= 0) {
		/* Case of the virtual symbol that depends on another (maybe virtual) symbol */
		vdit = rspamd_symcache_find_filter (cache, dep->sym, false);

		if (!vdit) {
			if (dit) {
				msg_err_cache ("cannot add dependency from %s on %s: no dependency symbol registered",
						dep->sym, dit->symbol);
			}
		}
		else {
			msg_debug_cache ("process virtual dependency %s(%d) on %s(%d)", it->symbol,
					dep->vid, vdit->symbol, vdit->id);
		}
	}
	else {
		vdit = dit;
	}

	if (dit != NULL) {
		if (!dit->is_filter) {
			/*
			 * Check sanity:
			 * - filters -> prefilter dependency is OK and always satisfied
			 * - postfilter -> (filter, prefilter) dep is ok
			 * - idempotent -> (any) dep is OK
			 *
			 * Otherwise, emit error
			 * However, even if everything is fine this dep is useless ¯\_(ツ)_/¯
			 */
			gboolean ok_dep = FALSE;

			if (it->is_filter) {
				if (dit->is_filter) {
					ok_dep = TRUE;
				}
				else if (dit->type & SYMBOL_TYPE_PREFILTER) {
					ok_dep = TRUE;
				}
			}
			else if (it->type & SYMBOL_TYPE_POSTFILTER) {
				if (dit->type & SYMBOL_TYPE_PREFILTER) {
					ok_dep = TRUE;
				}
			}
			else if (it->type & SYMBOL_TYPE_IDEMPOTENT) {
				if (dit->type & (SYMBOL_TYPE_PREFILTER|SYMBOL_TYPE_POSTFILTER)) {
					ok_dep = TRUE;
				}
			}
			else if (it->type & SYMBOL_TYPE_PREFILTER) {
				if (it->priority < dit->priority) {
					/* Also OK */
					ok_dep = TRUE;
				}
			}

			if (!ok_dep) {
				msg_err_cache ("cannot add dependency from %s on %s: invalid symbol types",
						dep->sym, dit->symbol);

				return;
			}
		}
		else {
			if (dit->id == it->id) {
				msg_err_cache ("cannot add dependency on self: %s -> %s "
							   "(resolved to %s)",
						it->symbol, dep->sym, dit->symbol);
			} else {
				rdep = rspamd_mempool_alloc (cache->static_pool,
						sizeof (*rdep));

				rdep->sym = dep->sym;
				rdep->item = it;
				rdep->id = it->id;
				g_assert (dit->rdeps != NULL);
				g_ptr_array_add (dit->rdeps, rdep);
				dep->item = dit;
				dep->id = dit->id;

				msg_debug_cache ("add dependency from %d on %d", it->id,
						dit->id);
			}
		}
	}
	else if (dep->id >= 0) {
		msg_err_cache ("cannot find dependency on symbol %s for symbol %s",
				dep->sym, it->symbol);

		return;
	}

	if (vdit) {
		/* Use virtual symbol to propagate deps */
		rspamd_symcache_propagate_dep (cache, it, vdit);
	}
}

/* Sort items in logical order */
static void
rspamd_symcache_post_init (struct rspamd_symcache *cache)
{
	struct rspamd_symcache_item *it, *vit;
	struct cache_dependency *dep;
	struct delayed_cache_dependency *ddep;
	struct delayed_cache_condition *dcond;
	GList *cur;
	gint i, j;

	cur = cache->delayed_deps;
	while (cur) {
		ddep = cur->data;

		vit = rspamd_symcache_find_filter (cache, ddep->from, false);
		it = rspamd_symcache_find_filter (cache, ddep->from, true);

		if (it == NULL || vit == NULL) {
			msg_err_cache ("cannot register delayed dependency between %s and %s: "
					"%s is missing", ddep->from, ddep->to, ddep->from);
		}
		else {
			msg_debug_cache ("delayed between %s(%d:%d) -> %s", ddep->from,
					it->id, vit->id, ddep->to);
			rspamd_symcache_add_dependency (cache, it->id, ddep->to, vit != it ?
																	 vit->id : -1);
		}

		cur = g_list_next (cur);
	}

	cur = cache->delayed_conditions;
	while (cur) {
		dcond = cur->data;

		it = rspamd_symcache_find_filter (cache, dcond->sym, true);

		if (it == NULL) {
			msg_err_cache (
					"cannot register delayed condition for %s",
					dcond->sym);
			luaL_unref (dcond->L, LUA_REGISTRYINDEX, dcond->cbref);
		}
		else {
			struct rspamd_symcache_condition *ncond = rspamd_mempool_alloc0 (cache->static_pool,
					sizeof (*ncond));
			ncond->cb = dcond->cbref;
			DL_APPEND (it->specific.normal.conditions, ncond);
		}

		cur = g_list_next (cur);
	}

	PTR_ARRAY_FOREACH (cache->items_by_id, i, it) {

		PTR_ARRAY_FOREACH (it->deps, j, dep) {
			rspamd_symcache_process_dep (cache, it, dep);
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

	/* Special case for virtual symbols */
	PTR_ARRAY_FOREACH (cache->virtual, i, it) {

		PTR_ARRAY_FOREACH (it->deps, j, dep) {
			rspamd_symcache_process_dep (cache, it, dep);
		}
	}

	g_ptr_array_sort_with_data (cache->connfilters, prefilters_cmp, cache);
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
				const ucl_object_t *freq_elt;

				freq_elt = ucl_object_lookup (elt, "avg");

				if (freq_elt) {
					item->st->avg_frequency = ucl_object_todouble (freq_elt);
				}
				freq_elt = ucl_object_lookup (elt, "stddev");

				if (freq_elt) {
					item->st->stddev_frequency = ucl_object_todouble (freq_elt);
				}
			}

			if (item->is_virtual && !(item->type & SYMBOL_TYPE_GHOST)) {
				g_assert (item->specific.virtual.parent < (gint)cache->items_by_id->len);
				parent = g_ptr_array_index (cache->items_by_id,
						item->specific.virtual.parent);
				item->specific.virtual.parent_item = parent;

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
	FILE *fp;
	bool ret;
	gchar path[PATH_MAX];

	rspamd_snprintf (path, sizeof (path), "%s.new", name);

	fd = open (path, O_CREAT | O_WRONLY | O_EXCL, 00644);

	if (fd == -1) {
		if (errno == EEXIST) {
			/* Some other process is already writing data, give up silently */
			return TRUE;
		}

		msg_err_cache ("cannot open file %s, error %d, %s", path,
				errno, strerror (errno));
		return FALSE;
	}

	rspamd_file_lock (fd, FALSE);
	fp = fdopen (fd, "w");

	memset (&hdr, 0, sizeof (hdr));
	memcpy (hdr.magic, rspamd_symcache_magic,
			sizeof (rspamd_symcache_magic));

	if (fwrite (&hdr, sizeof (hdr), 1, fp) == -1) {
		msg_err_cache ("cannot write to file %s, error %d, %s", path,
				errno, strerror (errno));
		rspamd_file_unlock (fd, FALSE);
		fclose (fp);

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

	efunc = ucl_object_emit_file_funcs (fp);
	ret = ucl_object_emit_full (top, UCL_EMIT_JSON_COMPACT, efunc, NULL);
	ucl_object_emit_funcs_free (efunc);
	ucl_object_unref (top);
	rspamd_file_unlock (fd, FALSE);
	fclose (fp);

	if (rename (path, name) == -1) {
		msg_err_cache ("cannot rename %s -> %s, error %d, %s", path, name,
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
	const gchar *type_str = "normal";

	g_assert (cache != NULL);

	if (name == NULL && !(type & SYMBOL_TYPE_CALLBACK)) {
		msg_warn_cache ("no name for non-callback symbol!");
	}
	else if ((type & SYMBOL_TYPE_VIRTUAL & (~SYMBOL_TYPE_GHOST)) && parent == -1) {
		msg_warn_cache ("no parent symbol is associated with virtual symbol %s",
			name);
	}

	if (name != NULL && !(type & SYMBOL_TYPE_CALLBACK)) {
		struct rspamd_symcache_item *existing;

		if (strcspn (name, " \t\n\r") != strlen (name)) {
			msg_warn_cache ("bogus characters in symbol name: \"%s\"",
					name);
		}

		if ((existing = g_hash_table_lookup (cache->items_by_symbol, name)) != NULL) {

			if (existing->type & SYMBOL_TYPE_GHOST) {
				/*
				 * Complicated part:
				 * - we need to remove the existing ghost symbol
				 * - we need to cleanup containers:
				 *   - symbols hash
				 *   - specific array
				 *   - items_by_it
				 *   - decrement used_items
				 */
				msg_info_cache ("duplicate ghost symbol %s is removed", name);

				if (existing->container) {
					g_ptr_array_remove (existing->container, existing);
				}

				g_ptr_array_remove (cache->items_by_id, existing->container);
				cache->used_items --;
				g_hash_table_remove (cache->items_by_symbol, name);
				/*
				 * Here can be memory leak, but we assume that ghost symbols
				 * are also virtual
				 */
			}
			else {
				msg_err_cache ("skip duplicate symbol registration for %s", name);
				return -1;
			}
		}
	}

	if (type & (SYMBOL_TYPE_CLASSIFIER|SYMBOL_TYPE_CALLBACK|
			SYMBOL_TYPE_PREFILTER|SYMBOL_TYPE_POSTFILTER|
			SYMBOL_TYPE_IDEMPOTENT|SYMBOL_TYPE_GHOST)) {
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
			type_str = "prefilter";
			g_ptr_array_add (cache->prefilters, item);
			item->container = cache->prefilters;
		}
		else if (item->type & SYMBOL_TYPE_IDEMPOTENT) {
			type_str = "idempotent";
			g_ptr_array_add (cache->idempotent, item);
			item->container = cache->idempotent;
		}
		else if (item->type & SYMBOL_TYPE_POSTFILTER) {
			type_str = "postfilter";
			g_ptr_array_add (cache->postfilters, item);
			item->container = cache->postfilters;
		}
		else if (item->type & SYMBOL_TYPE_CONNFILTER) {
			type_str = "connfilter";
			g_ptr_array_add (cache->connfilters, item);
			item->container = cache->connfilters;
		}
		else {
			item->is_filter = TRUE;
			g_ptr_array_add (cache->filters, item);
			item->container = cache->filters;
		}

		item->id = cache->items_by_id->len;
		g_ptr_array_add (cache->items_by_id, item);

		item->specific.normal.func = func;
		item->specific.normal.user_data = user_data;
		item->specific.normal.conditions = NULL;
	}
	else {
		/*
		 * Three possibilities here when no function is specified:
		 * - virtual symbol (beware of ghosts!)
		 * - classifier symbol
		 * - composite symbol
		 */
		if (item->type & SYMBOL_TYPE_COMPOSITE) {
			item->specific.normal.conditions = NULL;
			item->specific.normal.user_data = user_data;
			g_assert (user_data != NULL);
			g_ptr_array_add (cache->composites, item);

			item->id = cache->items_by_id->len;
			g_ptr_array_add (cache->items_by_id, item);
			item->container = cache->composites;
			type_str = "composite";
		}
		else if (item->type & SYMBOL_TYPE_CLASSIFIER) {
			/* Treat it as normal symbol to allow enable/disable */
			item->id = cache->items_by_id->len;
			g_ptr_array_add (cache->items_by_id, item);

			item->is_filter = TRUE;
			item->specific.normal.func = NULL;
			item->specific.normal.user_data = NULL;
			item->specific.normal.conditions = NULL;
			type_str = "classifier";
		}
		else {
			item->is_virtual = TRUE;
			item->specific.virtual.parent = parent;
			item->specific.virtual.parent_item =
					g_ptr_array_index (cache->items_by_id, parent);
			item->id = cache->virtual->len;
			g_ptr_array_add (cache->virtual, item);
			item->container = cache->virtual;
			/* Not added to items_by_id, handled by parent */
			type_str = "virtual";
		}
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
		msg_debug_cache ("used items: %d, added symbol: %s, %d; symbol type: %s",
				cache->used_items, name, item->id, type_str);
	} else {
		g_assert (func != NULL);
		msg_debug_cache ("used items: %d, added unnamed symbol: %d; symbol type: %s",
				cache->used_items, item->id, type_str);
	}

	item->deps = g_ptr_array_new ();
	item->rdeps = g_ptr_array_new ();
	item->type_descr = type_str;
	rspamd_mempool_add_destructor (cache->static_pool,
			rspamd_ptr_array_free_hard, item->deps);
	rspamd_mempool_add_destructor (cache->static_pool,
			rspamd_ptr_array_free_hard, item->rdeps);

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
				msg_err_cache ("cannot save cache data to %s: %s",
						cache->cfg->cache_filename, strerror (errno));
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
		g_ptr_array_free (cache->connfilters, TRUE);
		g_ptr_array_free (cache->prefilters, TRUE);
		g_ptr_array_free (cache->filters, TRUE);
		g_ptr_array_free (cache->postfilters, TRUE);
		g_ptr_array_free (cache->idempotent, TRUE);
		g_ptr_array_free (cache->composites, TRUE);
		g_ptr_array_free (cache->virtual, TRUE);
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
			rspamd_mempool_new (rspamd_mempool_suggest_size (), "symcache", 0);
	cache->items_by_symbol = g_hash_table_new (rspamd_str_hash,
			rspamd_str_equal);
	cache->items_by_id = g_ptr_array_new ();
	cache->connfilters = g_ptr_array_new ();
	cache->prefilters = g_ptr_array_new ();
	cache->filters = g_ptr_array_new ();
	cache->postfilters = g_ptr_array_new ();
	cache->idempotent = g_ptr_array_new ();
	cache->composites = g_ptr_array_new ();
	cache->virtual = g_ptr_array_new ();
	cache->reload_time = cfg->cache_reload_time;
	cache->total_hits = 1;
	cache->total_weight = 1.0;
	cache->cfg = cfg;
	cache->cksum = 0xdeadbabe;
	cache->peak_cb = -1;
	cache->id = (guint)rspamd_random_uint64_fast ();

	return cache;
}

static void
rspamd_symcache_metric_connect_cb (gpointer k, gpointer v, gpointer ud)
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
		s->cache_item = item;
	}
}

gboolean
rspamd_symcache_init (struct rspamd_symcache *cache)
{
	gboolean res = TRUE;

	g_assert (cache != NULL);

	cache->reload_time = cache->cfg->cache_reload_time;

	if (cache->cfg->cache_filename != NULL) {
		res = rspamd_symcache_load_items (cache, cache->cfg->cache_filename);
	}

	rspamd_symcache_post_init (cache);

	/* Connect metric symbols with symcache symbols */
	if (cache->cfg->symbols) {
		g_hash_table_foreach (cache->cfg->symbols,
				rspamd_symcache_metric_connect_cb,
				cache);
	}

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
		if (!(item->type & SYMBOL_TYPE_SKIPPED)) {
			item->type |= SYMBOL_TYPE_SKIPPED;
			msg_warn_cache ("symbol %s has no score registered, skip its check",
					item->symbol);
		}
	}

	if (ghost) {
		msg_debug_cache ("symbol %s is registered as ghost symbol, it won't be inserted "
				"to any metric", item->symbol);
	}

	if (item->st->weight < 0 && item->priority == 0) {
		item->priority ++;
	}

	if (item->is_virtual) {
		if (!(item->type & SYMBOL_TYPE_GHOST)) {
			g_assert (item->specific.virtual.parent != -1);
			g_assert (item->specific.virtual.parent < (gint) cache->items_by_id->len);
			parent = g_ptr_array_index (cache->items_by_id,
					item->specific.virtual.parent);
			item->specific.virtual.parent_item = parent;

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
	}

	cache->total_weight += fabs (item->st->weight);
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


	g_hash_table_foreach (cache->items_by_symbol,
			rspamd_symcache_validate_cb,
			cache);
	/* Now check each metric item and find corresponding symbol in a cache */
	g_hash_table_iter_init (&it, cfg->symbols);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		ignore_symbol = FALSE;
		sym_def = v;

		if (sym_def && (sym_def->flags &
				(RSPAMD_SYMBOL_FLAG_IGNORE_METRIC|RSPAMD_SYMBOL_FLAG_DISABLED))) {
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
		else if (sym_def->flags & RSPAMD_SYMBOL_FLAG_DISABLED) {
			item = g_hash_table_lookup (cache->items_by_symbol, k);

			if (item) {
				item->enabled = FALSE;
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
	struct rspamd_scan_result *res;
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

static inline gboolean
rspamd_symcache_check_id_list (const struct rspamd_symcache_id_list *ls, guint32 id)
{
	guint i;

	if (ls->dyn.e == -1) {
		guint *res = bsearch (&id, ls->dyn.n, ls->dyn.len, sizeof (guint32),
				rspamd_id_cmp);

		if (res) {
			return TRUE;
		}
	}
	else {
		for (i = 0; i < G_N_ELEMENTS (ls->st); i ++) {
			if (ls->st[i] == id) {
				return TRUE;
			}
			else if (ls->st[i] == 0) {
				return FALSE;
			}
		}
	}

	return FALSE;
}

gboolean
rspamd_symcache_is_item_allowed (struct rspamd_task *task,
								 struct rspamd_symcache_item *item,
								 gboolean exec_only)
{
	const gchar *what = "execution";

	if (!exec_only) {
		what = "symbol insertion";
	}

	/* Static checks */
	if (!item->enabled ||
		(RSPAMD_TASK_IS_EMPTY (task) && !(item->type & SYMBOL_TYPE_EMPTY)) ||
		(item->type & SYMBOL_TYPE_MIME_ONLY && !RSPAMD_TASK_IS_MIME(task))) {

		if (!item->enabled) {
			msg_debug_cache_task ("skipping %s of %s as it is permanently disabled; symbol type=%s",
					what, item->symbol, item->type_descr);

			return FALSE;
		}
		else {
			/*
			 * Exclude virtual symbols
			 */
			if (exec_only) {
				msg_debug_cache_task ("skipping check of %s as it cannot be "
									  "executed for this task type; symbol type=%s",
						item->symbol, item->type_descr);

				return FALSE;
			}
		}
	}

	/* Settings checks */
	if (task->settings_elt != 0) {
		guint32 id = task->settings_elt->id;

		if (item->forbidden_ids.st[0] != 0 &&
			rspamd_symcache_check_id_list (&item->forbidden_ids,
					id)) {
			msg_debug_cache_task ("deny %s of %s as it is forbidden for "
						 "settings id %ud; symbol type=%s",
						 what,
						 item->symbol,
						 id,
						 item->type_descr);

			return FALSE;
		}

		if (!(item->type & SYMBOL_TYPE_EXPLICIT_DISABLE)) {
			if (item->allowed_ids.st[0] == 0 ||
				!rspamd_symcache_check_id_list (&item->allowed_ids,
						id)) {

				if (task->settings_elt->policy == RSPAMD_SETTINGS_POLICY_IMPLICIT_ALLOW) {
					msg_debug_cache_task ("allow execution of %s settings id %ud "
										  "allows implicit execution of the symbols;"
										  "symbol type=%s",
							item->symbol,
							id,
							item->type_descr);

					return TRUE;
				}

				if (exec_only) {
					/*
					 * Special case if any of our virtual children are enabled
					 */
					if (rspamd_symcache_check_id_list (&item->exec_only_ids, id)) {
						return TRUE;
					}
				}

				msg_debug_cache_task ("deny %s of %s as it is not listed "
									  "as allowed for settings id %ud; symbol type=%s",
						what,
						item->symbol,
						id,
						item->type_descr);
				return FALSE;
			}
		}
		else {
			msg_debug_cache_task ("allow %s of %s for "
								  "settings id %ud as it can be only disabled explicitly;"
								  " symbol type=%s",
					what,
					item->symbol,
					id,
					item->type_descr);
		}
	}
	else if (item->type & SYMBOL_TYPE_EXPLICIT_ENABLE) {
		msg_debug_cache_task ("deny %s of %s as it must be explicitly enabled; symbol type=%s",
				what,
				item->symbol,
				item->type_descr);
		return FALSE;
	}

	/* Allow all symbols with no settings id */
	return TRUE;
}

static gboolean
rspamd_symcache_check_symbol (struct rspamd_task *task,
		struct rspamd_symcache *cache,
		struct rspamd_symcache_item *item,
		struct cache_savepoint *checkpoint)
{
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

	if (!rspamd_symcache_is_item_allowed (task, item, TRUE)) {
		check = FALSE;
	}
	else if (item->specific.normal.conditions) {
		struct rspamd_symcache_condition *cur_cond;

		DL_FOREACH (item->specific.normal.conditions, cur_cond) {
			/* We also executes condition callback to check if we need this symbol */
			L = task->cfg->lua_state;
			lua_rawgeti (L, LUA_REGISTRYINDEX, cur_cond->cb);
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

			if (!check) {
				break;
			}
		}

		if (!check) {
			msg_debug_cache_task ("skipping check of %s as its start condition is false; "
								  "symbol type = %s",
					item->symbol, item->type_descr);
		}
	}

	if (check) {
		msg_debug_cache_task ("execute %s, %d; symbol type = %s", item->symbol,
				item->id, item->type_descr);

		if (checkpoint->profile) {
			ev_now_update_if_cheap (task->event_loop);
			dyn_item->start_msec = (ev_now (task->event_loop) -
					checkpoint->profile_start) * 1e3;
		}

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

	/* Calculate profile probability */
	ev_now_update_if_cheap (task->event_loop);
	ev_tstamp now = ev_now (task->event_loop);
	checkpoint->profile_start = now;

	if ((cache->last_profile == 0.0 || now > cache->last_profile + PROFILE_MAX_TIME) ||
			(task->msg.len >= PROFILE_MESSAGE_SIZE_THRESHOLD) ||
			(rspamd_random_double_fast () >= (1 - PROFILE_PROBABILITY))) {
		msg_debug_cache_task ("enable profiling of symbols for task");
		checkpoint->profile = TRUE;
		cache->last_profile = now;
	}

	task->checkpoint = checkpoint;

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
		msg_info_task ("task is whitelisted");
		task->flags |= RSPAMD_TASK_FLAG_SKIP;
		return TRUE;
	}

	enabled = ucl_object_lookup (task->settings, "symbols_enabled");

	if (enabled) {
		/* Disable all symbols but selected */
		rspamd_symcache_disable_all_symbols (task, cache,
				SYMBOL_TYPE_EXPLICIT_DISABLE);
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
			rspamd_symcache_disable_all_symbols (task, cache,
					SYMBOL_TYPE_EXPLICIT_DISABLE);
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
								 struct rspamd_symcache *cache,
								 gint stage)
{
	struct rspamd_symcache_item *item = NULL;
	struct rspamd_symcache_dynamic_item *dyn_item;
	struct cache_savepoint *checkpoint;
	gint i;
	gboolean all_done = TRUE;
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

	msg_debug_cache_task ("symbols processing stage at pass: %d", stage);
	start_events_pending = rspamd_session_events_pending (task->s);

	switch (stage) {
	case RSPAMD_TASK_STAGE_CONNFILTERS:
		/* Check for connection filters */
		saved_priority = G_MININT;
		all_done = TRUE;

		for (i = 0; i < (gint) cache->connfilters->len; i++) {
			item = g_ptr_array_index (cache->connfilters, i);
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (RSPAMD_TASK_IS_SKIPPED (task)) {
				return TRUE;
			}

			if (!CHECK_START_BIT (checkpoint, dyn_item) &&
				!CHECK_FINISH_BIT (checkpoint, dyn_item)) {

				if (checkpoint->has_slow) {
					/* Delay */
					checkpoint->has_slow = FALSE;

					return FALSE;
				}
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
						return FALSE;
					}
				}

				rspamd_symcache_check_symbol (task, cache, item,
						checkpoint);
				all_done = FALSE;
			}
		}
		break;

	case RSPAMD_TASK_STAGE_PRE_FILTERS:
		/* Check for prefilters */
		saved_priority = G_MININT;
		all_done = TRUE;

		for (i = 0; i < (gint) cache->prefilters->len; i++) {
			item = g_ptr_array_index (cache->prefilters, i);
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (RSPAMD_TASK_IS_SKIPPED (task)) {
				return TRUE;
			}

			if (!CHECK_START_BIT (checkpoint, dyn_item) &&
				!CHECK_FINISH_BIT (checkpoint, dyn_item)) {
				/* Check priorities */
				if (checkpoint->has_slow) {
					/* Delay */
					checkpoint->has_slow = FALSE;

					return FALSE;
				}

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
						return FALSE;
					}
				}

				rspamd_symcache_check_symbol (task, cache, item,
						checkpoint);
				all_done = FALSE;
			}
		}

		break;

	case RSPAMD_TASK_STAGE_FILTERS:
		all_done = TRUE;

		for (i = 0; i < (gint) checkpoint->version; i++) {
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

				if (checkpoint->has_slow) {
					/* Delay */
					checkpoint->has_slow = FALSE;

					return FALSE;
				}
			}

			if (!(item->type & SYMBOL_TYPE_FINE)) {
				if (rspamd_symcache_metric_limit (task, checkpoint)) {
					msg_info_task ("task has already scored more than %.2f, so do "
								   "not "
								   "plan more checks",
							checkpoint->rs->score);
					all_done = TRUE;
					break;
				}
			}
		}

		break;

	case RSPAMD_TASK_STAGE_POST_FILTERS:
		/* Check for postfilters */
		saved_priority = G_MININT;
		all_done = TRUE;

		for (i = 0; i < (gint) cache->postfilters->len; i++) {
			if (RSPAMD_TASK_IS_SKIPPED (task)) {
				return TRUE;
			}

			item = g_ptr_array_index (cache->postfilters, i);
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (!CHECK_START_BIT (checkpoint, dyn_item) &&
				!CHECK_FINISH_BIT (checkpoint, dyn_item)) {
				/* Check priorities */
				all_done = FALSE;

				if (checkpoint->has_slow) {
					/* Delay */
					checkpoint->has_slow = FALSE;

					return FALSE;
				}

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

						return FALSE;
					}
				}

				rspamd_symcache_check_symbol (task, cache, item,
						checkpoint);
			}
		}

		break;

	case RSPAMD_TASK_STAGE_IDEMPOTENT:
		/* Check for postfilters */
		saved_priority = G_MININT;

		for (i = 0; i < (gint) cache->idempotent->len; i++) {
			item = g_ptr_array_index (cache->idempotent, i);
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (!CHECK_START_BIT (checkpoint, dyn_item) &&
				!CHECK_FINISH_BIT (checkpoint, dyn_item)) {
				/* Check priorities */
				if (checkpoint->has_slow) {
					/* Delay */
					checkpoint->has_slow = FALSE;

					return FALSE;
				}

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
						return FALSE;
					}
				}
				rspamd_symcache_check_symbol (task, cache, item,
						checkpoint);
			}
		}
		break;
	default:
		g_assert_not_reached ();
	}

	return all_done;
}

struct counters_cbdata {
	ucl_object_t *top;
	struct rspamd_symcache *cache;
};

/* Leave several digits */
#define P10(X) (1e##X)
#define ROUND_DOUBLE_DIGITS(x, dig) (floor((x) * P10(dig)) / P10(dig))
#define ROUND_DOUBLE(x) ROUND_DOUBLE_DIGITS(x, 3)

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
		if (!(item->type & SYMBOL_TYPE_GHOST)) {
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
					ucl_object_fromdouble (0.0),
					"frequency", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromdouble (0.0),
					"hits", 0, false);
			ucl_object_insert_key (obj,
					ucl_object_fromdouble (0.0),
					"time", 0, false);
		}
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
rspamd_symcache_call_peak_cb (struct ev_loop *ev_base,
		struct rspamd_symcache *cache,
		struct rspamd_symcache_item *item,
		gdouble cur_value,
		gdouble cur_err)
{
	lua_State *L = cache->cfg->lua_state;
	struct ev_loop **pbase;

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
rspamd_symcache_resort_cb (EV_P_ ev_timer *w, int revents)
{
	gdouble tm;
	struct rspamd_cache_refresh_cbdata *cbdata =
			(struct rspamd_cache_refresh_cbdata *)w->data;
	struct rspamd_symcache *cache;
	struct rspamd_symcache_item *item;
	guint i;
	gdouble cur_ticks;
	static const double decay_rate = 0.25;

	cache = cbdata->cache;
	/* Plan new event */
	tm = rspamd_time_jitter (cache->reload_time, 0);
	cur_ticks = rspamd_get_ticks (FALSE);
	msg_debug_cache ("resort symbols cache, next reload in %.2f seconds", tm);
	g_assert (cache != NULL);
	cbdata->resort_ev.repeat = tm;
	ev_timer_again (EV_A_ w);

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
						rspamd_symcache_call_peak_cb (cbdata->event_loop,
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

static void
rspamd_symcache_refresh_dtor (void *d)
{
	struct rspamd_cache_refresh_cbdata *cbdata =
			(struct rspamd_cache_refresh_cbdata *)d;

	ev_timer_stop (cbdata->event_loop, &cbdata->resort_ev);
}

void
rspamd_symcache_start_refresh (struct rspamd_symcache *cache,
							   struct ev_loop *ev_base, struct rspamd_worker *w)
{
	gdouble tm;
	struct rspamd_cache_refresh_cbdata *cbdata;

	cbdata = rspamd_mempool_alloc0 (cache->static_pool, sizeof (*cbdata));
	cbdata->last_resort = rspamd_get_ticks (TRUE);
	cbdata->event_loop = ev_base;
	cbdata->w = w;
	cbdata->cache = cache;
	tm = rspamd_time_jitter (cache->reload_time, 0);
	msg_debug_cache ("next reload in %.2f seconds", tm);
	g_assert (cache != NULL);
	cbdata->resort_ev.data = cbdata;
	ev_timer_init (&cbdata->resort_ev, rspamd_symcache_resort_cb,
			tm, tm);
	ev_timer_start (cbdata->event_loop, &cbdata->resort_ev);
	rspamd_mempool_add_destructor (cache->static_pool,
			rspamd_symcache_refresh_dtor, cbdata);
}

void
rspamd_symcache_inc_frequency (struct rspamd_symcache *cache,
							   struct rspamd_symcache_item *item)
{
	if (item != NULL) {
		g_atomic_int_inc (&item->st->hits);
	}
}

void
rspamd_symcache_add_dependency (struct rspamd_symcache *cache,
								gint id_from, const gchar *to,
								gint virtual_id_from)
{
	struct rspamd_symcache_item *source, *vsource;
	struct cache_dependency *dep;

	g_assert (id_from >= 0 && id_from < (gint)cache->items_by_id->len);

	source = (struct rspamd_symcache_item *)g_ptr_array_index (cache->items_by_id, id_from);
	dep = rspamd_mempool_alloc (cache->static_pool, sizeof (*dep));
	dep->id = id_from;
	dep->sym = rspamd_mempool_strdup (cache->static_pool, to);
	/* Will be filled later */
	dep->item = NULL;
	dep->vid = -1;
	g_ptr_array_add (source->deps, dep);

	if (virtual_id_from >= 0) {
		g_assert (virtual_id_from < (gint)cache->virtual->len);
		/* We need that for settings id propagation */
		vsource = (struct rspamd_symcache_item *)
				g_ptr_array_index (cache->virtual, virtual_id_from);
		dep = rspamd_mempool_alloc (cache->static_pool, sizeof (*dep));
		dep->vid = virtual_id_from;
		dep->id = -1;
		dep->sym = rspamd_mempool_strdup (cache->static_pool, to);
		/* Will be filled later */
		dep->item = NULL;
		g_ptr_array_add (vsource->deps, dep);
	}
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


void
rspamd_symcache_disable_all_symbols (struct rspamd_task *task,
									 struct rspamd_symcache *cache,
									 guint skip_mask)
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

		if (!(item->type & (skip_mask))) {
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

	item = rspamd_symcache_find_filter (cache, symbol, true);

	if (item) {
		dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);
		SET_FINISH_BIT (checkpoint, dyn_item);
		SET_START_BIT (checkpoint, dyn_item);
		msg_debug_cache_task ("disable execution of %s", symbol);
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

	item = rspamd_symcache_find_filter (cache, symbol, true);

	if (item) {
		dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);
		dyn_item->finished = 0;
		dyn_item->started = 0;
		msg_debug_cache_task ("enable execution of %s", symbol);
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

	item = rspamd_symcache_find_filter (cache, symbol, true);

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

	item = rspamd_symcache_find_filter (cache, symbol, true);

	if (item) {
		dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);
		return dyn_item->started;
	}

	return FALSE;
}

void
rspamd_symcache_disable_symbol_perm (struct rspamd_symcache *cache,
									 const gchar *symbol,
									 gboolean resolve_parent)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	item = rspamd_symcache_find_filter (cache, symbol, resolve_parent);

	if (item) {
		item->enabled = FALSE;
	}
}

void
rspamd_symcache_enable_symbol_perm (struct rspamd_symcache *cache,
									const gchar *symbol)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	item = rspamd_symcache_find_filter (cache, symbol, true);

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
		item = rspamd_symcache_find_filter (cache, symbol, true);

		if (item) {

			if (!rspamd_symcache_is_item_allowed (task, item, TRUE)) {
				ret = FALSE;
			}
			else {
				dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);
				if (CHECK_START_BIT (checkpoint, dyn_item)) {
					ret = FALSE;
				}
				else {
					if (item->specific.normal.conditions) {
						struct rspamd_symcache_condition *cur_cond;

						DL_FOREACH (item->specific.normal.conditions, cur_cond) {
							/*
							 * We also executes condition callback to check
							 * if we need this symbol
							 */
							L = task->cfg->lua_state;
							lua_rawgeti (L, LUA_REGISTRYINDEX, cur_cond->cb);
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

							if (!ret) {
								break;
							}
						}
					}
				}
			}
		}
	}

	return ret;
}


gboolean
rspamd_symcache_enable_symbol (struct rspamd_task *task,
							   struct rspamd_symcache *cache,
							   const gchar *symbol)
{
	struct cache_savepoint *checkpoint;
	struct rspamd_symcache_item *item;
	struct rspamd_symcache_dynamic_item *dyn_item;
	gboolean ret = FALSE;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	checkpoint = task->checkpoint;

	if (checkpoint) {
		item = rspamd_symcache_find_filter (cache, symbol, true);

		if (item) {
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (!CHECK_FINISH_BIT (checkpoint, dyn_item)) {
				ret = TRUE;
				CLR_START_BIT (checkpoint, dyn_item);
				CLR_FINISH_BIT (checkpoint, dyn_item);
			}
			else {
				msg_debug_task ("cannot enable symbol %s: already started", symbol);
			}
		}
	}

	return ret;
}


gboolean
rspamd_symcache_disable_symbol (struct rspamd_task *task,
								struct rspamd_symcache *cache,
								const gchar *symbol)
{
	struct cache_savepoint *checkpoint;
	struct rspamd_symcache_item *item;
	struct rspamd_symcache_dynamic_item *dyn_item;
	gboolean ret = FALSE;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	checkpoint = task->checkpoint;

	if (checkpoint) {
		item = rspamd_symcache_find_filter (cache, symbol, true);

		if (item) {
			dyn_item = rspamd_symcache_get_dynamic (checkpoint, item);

			if (!CHECK_START_BIT (checkpoint, dyn_item)) {
				ret = TRUE;
				SET_START_BIT (checkpoint, dyn_item);
				SET_FINISH_BIT (checkpoint, dyn_item);
			}
			else {
				if (!CHECK_FINISH_BIT (checkpoint, dyn_item)) {
					msg_warn_task ("cannot disable symbol %s: already started",
							symbol);
				}
			}
		}
	}

	return ret;
}

void
rspamd_symcache_foreach (struct rspamd_symcache *cache,
						 void (*func) (struct rspamd_symcache_item *, gpointer),
						 gpointer ud)
{
	struct rspamd_symcache_item *item;
	GHashTableIter it;
	gpointer k, v;

	g_hash_table_iter_init (&it, cache->items_by_symbol);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		item = (struct rspamd_symcache_item *)v;
		func (item, ud);
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

struct rspamd_symcache_delayed_cbdata {
	struct rspamd_symcache_item *item;
	struct rspamd_task *task;
	struct rspamd_async_event *event;
	struct ev_timer tm;
};

static void
rspamd_symcache_delayed_item_fin (gpointer ud)
{
	struct rspamd_symcache_delayed_cbdata *cbd =
			(struct rspamd_symcache_delayed_cbdata *)ud;
	struct rspamd_task *task;
	struct cache_savepoint *checkpoint;

	task = cbd->task;
	checkpoint = task->checkpoint;
	checkpoint->has_slow = FALSE;
	ev_timer_stop (task->event_loop, &cbd->tm);
}

static void
rspamd_symcache_delayed_item_cb (EV_P_ ev_timer *w, int what)
{
	struct rspamd_symcache_delayed_cbdata *cbd =
			(struct rspamd_symcache_delayed_cbdata *)w->data;
	struct rspamd_symcache_item *item;
	struct rspamd_task *task;
	struct cache_dependency *rdep;
	struct cache_savepoint *checkpoint;
	struct rspamd_symcache_dynamic_item *dyn_item;
	guint i;

	item = cbd->item;
	task = cbd->task;
	checkpoint = task->checkpoint;
	cbd->event = NULL;

	/* Timer will be stopped here */
	rspamd_session_remove_event (task->s,
			rspamd_symcache_delayed_item_fin, cbd);

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

static void
rspamd_delayed_timer_dtor (gpointer d)
{
	struct rspamd_symcache_delayed_cbdata *cbd =
			(struct rspamd_symcache_delayed_cbdata *)d;

	if (cbd->event) {
		/* Event has not been executed */
		rspamd_session_remove_event (cbd->task->s,
				rspamd_symcache_delayed_item_fin, cbd);
		cbd->event = NULL;
	}
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
	gdouble diff;
	guint i;
	gboolean enable_slow_timer = FALSE;
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

	if (checkpoint->profile) {
		ev_now_update_if_cheap (task->event_loop);
		diff = ((ev_now (task->event_loop) - checkpoint->profile_start) * 1e3 -
				dyn_item->start_msec);

		if (diff > slow_diff_limit) {

			if (!checkpoint->has_slow) {
				checkpoint->has_slow = TRUE;
				enable_slow_timer = TRUE;
				msg_info_task ("slow rule: %s(%d): %.2f ms; enable slow timer delay",
						item->symbol, item->id,
						diff);
			}
			else {
				msg_info_task ("slow rule: %s(%d): %.2f ms",
						item->symbol, item->id,
						diff);
			}
		}

		if (G_UNLIKELY (RSPAMD_TASK_IS_PROFILING (task))) {
			rspamd_task_profile_set (task, item->symbol, diff);
		}

		if (rspamd_worker_is_scanner (task->worker)) {
			rspamd_set_counter (item->cd, diff);
		}
	}

	if (enable_slow_timer) {
		struct rspamd_symcache_delayed_cbdata *cbd =
				rspamd_mempool_alloc (task->task_pool,sizeof (*cbd));
		/* Add timer to allow something else to be executed */
		ev_timer *tm = &cbd->tm;

		cbd->event = rspamd_session_add_event (task->s,
				rspamd_symcache_delayed_item_fin, cbd,
				"symcache");

		/*
		 * If no event could be added, then we are already in the destruction
		 * phase. So the main issue is to deal with has slow here
		 */
		if (cbd->event) {
			ev_timer_init (tm, rspamd_symcache_delayed_item_cb, 0.1, 0.0);
			ev_set_priority (tm, EV_MINPRI);
			rspamd_mempool_add_destructor (task->task_pool,
					rspamd_delayed_timer_dtor, cbd);

			cbd->task = task;
			cbd->item = item;
			tm->data = cbd;
			ev_timer_start (task->event_loop, tm);
		}
		else {
			/* Just reset as no timer is added */
			checkpoint->has_slow = FALSE;
		}

		return;
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

gboolean
rspamd_symcache_add_symbol_flags (struct rspamd_symcache *cache,
										   const gchar *symbol,
										   guint flags)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	item = rspamd_symcache_find_filter (cache, symbol, true);

	if (item) {
		item->type |= flags;

		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_symcache_set_symbol_flags (struct rspamd_symcache *cache,
										   const gchar *symbol,
										   guint flags)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	item = rspamd_symcache_find_filter (cache, symbol, true);

	if (item) {
		item->type = flags;

		return TRUE;
	}

	return FALSE;
}

guint
rspamd_symcache_get_symbol_flags (struct rspamd_symcache *cache,
										const gchar *symbol)
{
	struct rspamd_symcache_item *item;

	g_assert (cache != NULL);
	g_assert (symbol != NULL);

	item = rspamd_symcache_find_filter (cache, symbol, true);

	if (item) {
		return item->type;
	}

	return 0;
}

void
rspamd_symcache_composites_foreach (struct rspamd_task *task,
										 struct rspamd_symcache *cache,
										 GHFunc func,
										 gpointer fd)
{
	guint i;
	struct rspamd_symcache_item *item;
	struct rspamd_symcache_dynamic_item *dyn_item;

	if (task->checkpoint == NULL) {
		return;
	}

	PTR_ARRAY_FOREACH (cache->composites, i, item) {
		dyn_item = rspamd_symcache_get_dynamic (task->checkpoint, item);

		if (!CHECK_START_BIT (task->checkpoint, dyn_item)) {
			/* Cannot do it due to 2 passes */
			/* SET_START_BIT (task->checkpoint, dyn_item); */
			func (item->symbol, item->specific.normal.user_data, fd);
			SET_FINISH_BIT (task->checkpoint, dyn_item);
		}
	}
}

bool
rspamd_symcache_set_allowed_settings_ids (struct rspamd_symcache *cache,
											   const gchar *symbol,
											   const guint32 *ids,
											   guint nids)
{
	struct rspamd_symcache_item *item;

	item = rspamd_symcache_find_filter (cache, symbol, false);

	if (item == NULL) {
		return false;
	}

	if (nids <= G_N_ELEMENTS (item->allowed_ids.st)) {
		/* Use static version */
		memset (&item->allowed_ids, 0, sizeof (item->allowed_ids));
		for (guint i = 0; i < nids; i++) {
			item->allowed_ids.st[i] = ids[i];
		}
	}
	else {
		/* Need to use a separate list */
		item->allowed_ids.dyn.e = -1; /* Flag */
		item->allowed_ids.dyn.n = rspamd_mempool_alloc (cache->static_pool,
				sizeof (guint32) * nids);
		item->allowed_ids.dyn.len = nids;
		item->allowed_ids.dyn.allocated = nids;

		for (guint i = 0; i < nids; i++) {
			item->allowed_ids.dyn.n[i] = ids[i];
		}

		/* Keep sorted */
		qsort (item->allowed_ids.dyn.n, nids, sizeof (guint32), rspamd_id_cmp);
	}

	return true;
}

bool
rspamd_symcache_set_forbidden_settings_ids (struct rspamd_symcache *cache,
											  const gchar *symbol,
											  const guint32 *ids,
											  guint nids)
{
	struct rspamd_symcache_item *item;

	item = rspamd_symcache_find_filter (cache, symbol, false);

	if (item == NULL) {
		return false;
	}

	g_assert (nids < G_MAXUINT16);

	if (nids <= G_N_ELEMENTS (item->forbidden_ids.st)) {
		/* Use static version */
		memset (&item->forbidden_ids, 0, sizeof (item->forbidden_ids));
		for (guint i = 0; i < nids; i++) {
			item->forbidden_ids.st[i] = ids[i];
		}
	}
	else {
		/* Need to use a separate list */
		item->forbidden_ids.dyn.e = -1; /* Flag */
		item->forbidden_ids.dyn.n = rspamd_mempool_alloc (cache->static_pool,
				sizeof (guint32) * nids);
		item->forbidden_ids.dyn.len = nids;
		item->forbidden_ids.dyn.allocated = nids;

		for (guint i = 0; i < nids; i++) {
			item->forbidden_ids.dyn.n[i] = ids[i];
		}

		/* Keep sorted */
		qsort (item->forbidden_ids.dyn.n, nids, sizeof (guint32), rspamd_id_cmp);
	}

	return true;
}

const guint32*
rspamd_symcache_get_allowed_settings_ids (struct rspamd_symcache *cache,
										  const gchar *symbol,
										  guint *nids)
{
	struct rspamd_symcache_item *item;
	guint cnt = 0;

	item = rspamd_symcache_find_filter (cache, symbol, false);

	if (item == NULL) {
		return NULL;
	}

	if (item->allowed_ids.dyn.e == -1) {
		/* Dynamic list */
		*nids = item->allowed_ids.dyn.len;

		return item->allowed_ids.dyn.n;
	}
	else {
		while (item->allowed_ids.st[cnt] != 0 && cnt < G_N_ELEMENTS (item->allowed_ids.st)) {
			cnt ++;
		}

		*nids = cnt;

		return item->allowed_ids.st;
	}
}

const guint32*
rspamd_symcache_get_forbidden_settings_ids (struct rspamd_symcache *cache,
											const gchar *symbol,
											guint *nids)
{
	struct rspamd_symcache_item *item;
	guint cnt = 0;

	item = rspamd_symcache_find_filter (cache, symbol, false);

	if (item == NULL) {
		return NULL;
	}

	if (item->forbidden_ids.dyn.e == -1) {
		/* Dynamic list */
		*nids = item->allowed_ids.dyn.len;

		return item->allowed_ids.dyn.n;
	}
	else {
		while (item->forbidden_ids.st[cnt] != 0 && cnt < G_N_ELEMENTS (item->allowed_ids.st)) {
			cnt ++;
		}

		*nids = cnt;

		return item->forbidden_ids.st;
	}
}

/* Insertion sort: usable for near-sorted ids list */
static inline void
rspamd_ids_insertion_sort (guint *a, guint n)
{
	for (guint i = 1; i < n; i++) {
		guint32 tmp = a[i];
		guint j = i;

		while (j > 0 && tmp < a[j - 1]) {
			a[j] = a[j - 1];
			j --;
		}

		a[j] = tmp;
	}
}

static inline void
rspamd_symcache_add_id_to_list (rspamd_mempool_t *pool,
								struct rspamd_symcache_id_list *ls,
								guint32 id)
{
	guint cnt = 0;
	guint *new_array;

	if (ls->st[0] == -1) {
		/* Dynamic array */
		if (ls->dyn.len < ls->dyn.allocated) {
			/* Trivial, append + sort */
			ls->dyn.n[ls->dyn.len++] = id;
		}
		else {
			/* Reallocate */
			g_assert (ls->dyn.allocated <= G_MAXINT16);
			ls->dyn.allocated *= 2;

			new_array = rspamd_mempool_alloc (pool,
					ls->dyn.allocated * sizeof (guint32));
			memcpy (new_array, ls->dyn.n, ls->dyn.len * sizeof (guint32));
			ls->dyn.n = new_array;
			ls->dyn.n[ls->dyn.len++] = id;
		}

		rspamd_ids_insertion_sort (ls->dyn.n, ls->dyn.len);
	}
	else {
		/* Static part */
		while (ls->st[cnt] != 0 && cnt < G_N_ELEMENTS (ls->st)) {
			cnt ++;
		}

		if (cnt < G_N_ELEMENTS (ls->st)) {
			ls->st[cnt] = id;
		}
		else {
			/* Switch to dynamic */
			new_array = rspamd_mempool_alloc (pool,
					G_N_ELEMENTS (ls->st) * 2 * sizeof (guint32));
			memcpy (new_array, ls->st,  G_N_ELEMENTS (ls->st) * sizeof (guint32));
			ls->dyn.n = new_array;
			ls->dyn.e = -1;
			ls->dyn.allocated = G_N_ELEMENTS (ls->st) * 2;
			ls->dyn.len = G_N_ELEMENTS (ls->st);

			/* Recursively jump to dynamic branch that will handle insertion + sorting */
			rspamd_symcache_add_id_to_list (pool, ls, id);
		}
	}
}

void
rspamd_symcache_process_settings_elt (struct rspamd_symcache *cache,
									  struct rspamd_config_settings_elt *elt)
{
	guint32 id = elt->id;
	ucl_object_iter_t iter;
	struct rspamd_symcache_item *item, *parent;
	const ucl_object_t *cur;


	if (elt->symbols_disabled) {
		/* Process denied symbols */
		iter = NULL;

		while ((cur = ucl_object_iterate (elt->symbols_disabled, &iter, true)) != NULL) {
			const gchar *sym = ucl_object_key (cur);
			item = rspamd_symcache_find_filter (cache, sym, false);

			if (item) {
				if (item->is_virtual) {
					/*
					 * Virtual symbols are special:
					 * we ignore them in symcache but prevent them from being
					 * inserted.
					 */
					rspamd_symcache_add_id_to_list (cache->static_pool,
							&item->forbidden_ids, id);
					msg_debug_cache ("deny virtual symbol %s for settings %ud (%s); "
									 "parent can still be executed",
							sym, id, elt->name);
				}
				else {
					/* Normal symbol, disable it */
					rspamd_symcache_add_id_to_list (cache->static_pool,
							&item->forbidden_ids, id);
					msg_debug_cache ("deny symbol %s for settings %ud (%s)",
							sym, id, elt->name);
				}
			}
			else {
				msg_warn_cache ("cannot find a symbol to disable %s "
					"when processing settings %ud (%s)",
					sym, id, elt->name);
			}
		}
	}

	if (elt->symbols_enabled) {
		iter = NULL;

		while ((cur = ucl_object_iterate (elt->symbols_enabled, &iter, true)) != NULL) {
			/* Here, we resolve parent and explicitly allow it */
			const gchar *sym = ucl_object_key (cur);
			item = rspamd_symcache_find_filter (cache, sym, false);

			if (item) {
				if (item->is_virtual) {
					if (!(item->type & SYMBOL_TYPE_GHOST)) {
						parent = rspamd_symcache_find_filter (cache, sym, true);

						if (parent) {
							if (elt->symbols_disabled &&
								ucl_object_lookup (elt->symbols_disabled, parent->symbol)) {
								msg_err_cache ("conflict in %s: cannot enable disabled symbol %s, "
											   "wanted to enable symbol %s",
										elt->name, parent->symbol, sym);
								continue;
							}

							rspamd_symcache_add_id_to_list (cache->static_pool,
									&parent->exec_only_ids, id);
							msg_debug_cache ("allow just execution of symbol %s for settings %ud (%s)",
									parent->symbol, id, elt->name);
						}
					}
					/* Ignore ghosts */
				}

				rspamd_symcache_add_id_to_list (cache->static_pool,
						&item->allowed_ids, id);
				msg_debug_cache ("allow execution of symbol %s for settings %ud (%s)",
						sym, id, elt->name);
			}
			else {
				msg_warn_cache ("cannot find a symbol to enable %s "
								"when processing settings %ud (%s)",
						sym, id, elt->name);
			}
		}
	}
}

gint
rspamd_symcache_item_flags (struct rspamd_symcache_item *item)
{
	if (item) {
		return item->type;
	}

	return 0;
}

const gchar*
rspamd_symcache_item_name (struct rspamd_symcache_item *item)
{
	return item ? item->symbol : NULL;
}

const struct rspamd_symcache_item_stat *
rspamd_symcache_item_stat (struct rspamd_symcache_item *item)
{
	return item ? item->st : NULL;
}

gboolean
rspamd_symcache_item_is_enabled (struct rspamd_symcache_item *item)
{
	if (item) {
		if (!item->enabled) {
			return FALSE;
		}

		if (item->is_virtual && item->specific.virtual.parent_item != NULL) {
			return rspamd_symcache_item_is_enabled (item->specific.virtual.parent_item);
		}

		return TRUE;
	}

	return FALSE;
}

struct rspamd_symcache_item * rspamd_symcache_item_get_parent (
		struct rspamd_symcache_item *item)
{
	if (item && item->is_virtual && item->specific.virtual.parent_item != NULL) {
		return item->specific.virtual.parent_item;
	}

	return NULL;
}

const GPtrArray*
rspamd_symcache_item_get_deps (struct rspamd_symcache_item *item)
{
	struct rspamd_symcache_item *parent;

	if (item) {
		parent = rspamd_symcache_item_get_parent (item);

		if (parent) {
			item = parent;
		}

		return item->deps;
	}

	return NULL;
}

const GPtrArray*
rspamd_symcache_item_get_rdeps (struct rspamd_symcache_item *item)
{
	struct rspamd_symcache_item *parent;

	if (item) {
		parent = rspamd_symcache_item_get_parent (item);

		if (parent) {
			item = parent;
		}

		return item->rdeps;
	}

	return NULL;
}

void
rspamd_symcache_enable_profile (struct rspamd_task *task)
{
	struct cache_savepoint *checkpoint = task->checkpoint;

	if (checkpoint && !checkpoint->profile) {
		ev_now_update_if_cheap (task->event_loop);
		ev_tstamp now = ev_now (task->event_loop);
		checkpoint->profile_start = now;

		msg_debug_cache_task ("enable profiling of symbols for task");
		checkpoint->profile = TRUE;
	}
}