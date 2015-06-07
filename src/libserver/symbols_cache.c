/*
 * Copyright (c) 2009-2015, Vsevolod Stakhov
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
#include "util.h"
#include "main.h"
#include "message.h"
#include "symbols_cache.h"
#include "cfg_file.h"

static const guchar rspamd_symbols_cache_magic[8] = {'r', 's', 'c', 1, 0, 0, 0, 0 };

struct rspamd_symbols_cache_header {
	guchar magic[8];
	guint nitems;
	guchar checksum[64];
	guchar unused[128];
};

struct symbols_cache {
	/* Hash table for fast access */
	GHashTable *items_by_symbol;
	GPtrArray *items_by_order;
	GPtrArray *items_by_id;
	rspamd_mempool_t *static_pool;
	gdouble max_weight;
	guint used_items;
	guint64 total_freq;
	struct rspamd_config *cfg;
	rspamd_mempool_mutex_t *mtx;
	gdouble reload_time;
	struct event resort_ev;
};

struct counter_data {
	gdouble value;
	gint number;
};

struct cache_item {
	/* This block is likely shared */
	gdouble avg_time;
	gdouble weight;
	guint32 frequency;
	guint32 avg_counter;

	/* Per process counter */
	struct counter_data *cd;
	gchar *symbol;
	enum rspamd_symbol_type type;

	/* Callback data */
	symbol_func_t func;
	gpointer user_data;

	/* Parent symbol id for virtual symbols */
	gint parent;
	/* Priority */
	gint priority;
	gint id;
	gdouble metric_weight;

	/* Dependencies */
	GPtrArray *deps;
	GPtrArray *rdeps;
};

struct cache_dependency {
	struct cache_item *item;
	gchar *sym;
	gint id;
};

/* XXX: Maybe make it configurable */
#define CACHE_RELOAD_TIME 60.0
/* weight, frequency, time */
#define TIME_ALPHA (1.0)
#define WEIGHT_ALPHA (0.001)
#define FREQ_ALPHA (0.001)
#define SCORE_FUN(w, f, t) (((w) > 0 ? (w) : WEIGHT_ALPHA) \
		* ((f) > 0 ? (f) : FREQ_ALPHA) \
		/ (t > TIME_ALPHA ? t : TIME_ALPHA))

gint
cache_logic_cmp (const void *p1, const void *p2, gpointer ud)
{
	const struct cache_item *i1 = *(struct cache_item **)p1,
			*i2 = *(struct cache_item **)p2;
	struct symbols_cache *cache = ud;
	double w1, w2;
	double weight1, weight2;
	double f1 = 0, f2 = 0, t1, t2;

	if (i1->deps->len != 0 || i2->deps->len != 0) {
		/* TODO: handle complex dependencies */
		w1 = -(i1->deps->len);
		w2 = -(i2->deps->len);
	}
	else if (i1->priority == i2->priority) {
		f1 = (double)i1->frequency / (double)cache->total_freq;
		f2 = (double)i2->frequency / (double)cache->total_freq;
		weight1 = abs (i1->weight) / cache->max_weight;
		weight2 = abs (i2->weight) / cache->max_weight;
		t1 = i1->avg_time;
		t2 = i2->avg_time;
		w1 = SCORE_FUN (weight1, f1, t1);
		w2 = SCORE_FUN (weight2, f2, t2);
		msg_debug ("%s -> %.2f, %s -> %.2f", i1->symbol, w1 * 1000.0,
				i2->symbol, w2 * 1000.0);
	}
	else {
		/* Strict sorting */
		w1 = abs (i1->priority);
		w2 = abs (i2->priority);
		msg_debug ("priority: %s -> %.2f, %s -> %.2f", i1->symbol, w1 * 1000.0,
				i2->symbol, w2 * 1000.0);
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
rspamd_set_counter (struct cache_item *item, guint32 value)
{
	struct counter_data *cd;
	cd = item->cd;

	/* Cumulative moving average using per-process counter data */
	if (cd->number == 0) {
		cd->value = 0;
	}

	cd->value = cd->value + (value - cd->value) / (++cd->number);

	return cd->value;
}

/* Sort items in logical order */
static void
post_cache_init (struct symbols_cache *cache)
{
	struct cache_item *it, *dit;
	struct cache_dependency *dep, *rdep;
	guint i, j;

	g_ptr_array_sort_with_data (cache->items_by_order, cache_logic_cmp, cache);

	for (i = 0; i < cache->items_by_id->len; i ++) {
		it = g_ptr_array_index (cache->items_by_id, i);

		for (j = 0; j < it->deps->len; j ++) {
			dep = g_ptr_array_index (cache->items_by_id, j);
			dit = g_hash_table_lookup (cache->items_by_symbol, dep->sym);

			if (dit != NULL) {
				if (dit->parent != -1) {
					dit = g_ptr_array_index (cache->items_by_order, dit->parent);
				}

				rdep = rspamd_mempool_alloc (cache->static_pool, sizeof (*rdep));
				rdep->sym = dep->sym;
				rdep->item = it;
				rdep->id = i;
				g_ptr_array_add (dit->rdeps, rdep);
				dep->item = dit;
			}
			else {
				msg_warn ("cannot find dependency on symbol %s", dep->sym);
			}
		}
	}
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
	double w;

	fd = open (name, O_RDONLY);

	if (fd == -1) {
		msg_info ("cannot open file %s, error %d, %s", name,
			errno, strerror (errno));
		return FALSE;
	}

	if (fstat (fd, &st) == -1) {
		close (fd);
		msg_info ("cannot stat file %s, error %d, %s", name,
				errno, strerror (errno));
		return FALSE;
	}

	if (st.st_size < (gint)sizeof (*hdr)) {
		close (fd);
		errno = EINVAL;
		msg_info ("cannot use file %s, error %d, %s", name,
				errno, strerror (errno));
		return FALSE;
	}

	map = mmap (NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);

	if (map == MAP_FAILED) {
		close (fd);
		msg_info ("cannot mmap file %s, error %d, %s", name,
				errno, strerror (errno));
		return FALSE;
	}

	close (fd);
	hdr = map;

	if (memcmp (hdr->magic, rspamd_symbols_cache_magic,
			sizeof (rspamd_symbols_cache_magic)) != 0) {
		msg_info ("cannot use file %s, bad magic", name);
		munmap (map, st.st_size);
		return FALSE;
	}

	parser = ucl_parser_new (0);
	p = (const guchar *)(hdr + 1);

	if (!ucl_parser_add_chunk (parser, p, st.st_size - sizeof (*hdr))) {
		msg_info ("cannot use file %s, cannot parse: %s", name,
				ucl_parser_get_error (parser));
		munmap (map, st.st_size);
		ucl_parser_free (parser);
		return FALSE;
	}

	top = ucl_parser_get_object (parser);
	munmap (map, st.st_size);
	ucl_parser_free (parser);

	if (top == NULL || ucl_object_type (top) != UCL_OBJECT) {
		msg_info ("cannot use file %s, bad object", name);
		ucl_object_unref (top);
		return FALSE;
	}

	it = ucl_object_iterate_new (top);

	while ((cur = ucl_object_iterate_safe (it, true))) {
		item = g_hash_table_lookup (cache->items_by_symbol, ucl_object_key (cur));

		if (item) {
			/* Copy saved info */
			elt = ucl_object_find_key (cur, "weight");

			if (elt) {
				w = ucl_object_todouble (elt);
				if (w != 0) {
					item->weight = w;
				}
			}

			elt = ucl_object_find_key (cur, "time");
			if (elt) {
				item->avg_time = ucl_object_todouble (elt);
			}

			elt = ucl_object_find_key (cur, "count");
			if (elt) {
				item->avg_counter = ucl_object_toint (elt);
			}

			elt = ucl_object_find_key (cur, "frequency");
			if (elt) {
				item->frequency = ucl_object_toint (elt);
			}

			if (item->type == SYMBOL_TYPE_VIRTUAL && item->parent != -1) {
				g_assert (item->parent < (gint)cache->items_by_id->len);
				parent = g_ptr_array_index (cache->items_by_id, item->parent);

				if (parent->weight < item->weight) {
					parent->weight = item->weight;
				}

				/*
				 * We maintain avg_time for virtual symbols equal to the
				 * parent item avg_time
				 */
				parent->avg_time = item->avg_time;
				parent->avg_counter = item->avg_counter;
			}

			if (abs (item->weight) > cache->max_weight) {
				cache->max_weight = abs (item->weight);
			}

			cache->total_freq += item->frequency;
		}
	}

	ucl_object_iterate_free (it);
	ucl_object_unref (top);

	return TRUE;
}

static gboolean
rspamd_symbols_cache_save_items (struct symbols_cache *cache, const gchar *name)
{
	struct rspamd_symbols_cache_header hdr;
	ucl_object_t *top, *elt;
	GHashTableIter it;
	struct cache_item *item;
	struct ucl_emitter_functions *efunc;
	gpointer k, v;
	gint fd;
	bool ret;

	fd = open (name, O_CREAT | O_TRUNC | O_WRONLY, 00644);

	if (fd == -1) {
		msg_info ("cannot open file %s, error %d, %s", name,
				errno, strerror (errno));
		return FALSE;
	}

	memset (&hdr, 0, sizeof (hdr));
	memcpy (hdr.magic, rspamd_symbols_cache_magic,
			sizeof (rspamd_symbols_cache_magic));

	if (write (fd, &hdr, sizeof (hdr)) == -1) {
		msg_info ("cannot write to file %s, error %d, %s", name,
				errno, strerror (errno));
		close (fd);

		return FALSE;
	}

	top = ucl_object_typed_new (UCL_OBJECT);
	g_hash_table_iter_init (&it, cache->items_by_symbol);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		item = v;
		elt = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (elt, ucl_object_fromdouble (item->weight),
				"weight", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromdouble (item->avg_time),
				"time", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromdouble (item->avg_counter),
				"count", 0, false);
		ucl_object_insert_key (elt, ucl_object_fromint (item->frequency),
				"frequency", 0, false);

		ucl_object_insert_key (top, elt, k, 0, false);
	}

	efunc = ucl_object_emit_fd_funcs (fd);
	ret = ucl_object_emit_full (top, UCL_EMIT_JSON_COMPACT, efunc);
	ucl_object_emit_funcs_free (efunc);
	close (fd);

	return ret;
}

gint
rspamd_symbols_cache_add_symbol (struct symbols_cache *cache,
	const gchar *name,
	double weight,
	gint priority,
	symbol_func_t func,
	gpointer user_data,
	enum rspamd_symbol_type type,
	gint parent)
{
	struct cache_item *item = NULL;

	g_assert (cache != NULL);

	if (name == NULL && type != SYMBOL_TYPE_CALLBACK) {
		msg_warn ("no name for non-callback symbol!");
	}
	else if (type == SYMBOL_TYPE_VIRTUAL && parent == -1) {
		msg_warn ("no parent symbol is associated with virtual symbol %s",
			name);
	}

	if (name != NULL) {
		if (g_hash_table_lookup (cache->items_by_symbol, name) != NULL) {
			msg_err ("skip duplicate symbol registration for %s", name);
			return -1;
		}
	}

	item = rspamd_mempool_alloc0_shared (cache->static_pool,
			sizeof (struct cache_item));
	/*
	 * We do not share cd to skip locking, instead we'll just calculate it on
	 * save or accumulate
	 */
	item->cd = rspamd_mempool_alloc0 (cache->static_pool,
			sizeof (struct counter_data));

	if (name != NULL) {
		item->symbol = rspamd_mempool_strdup (cache->static_pool, name);
	}

	item->func = func;
	item->user_data = user_data;
	item->priority = priority;
	item->type = type;
	item->weight = weight;

	if (item->weight < 0 && item->priority == 0) {
		/* Make priority for negative weighted symbols */
		item->priority = 1;
	}

	item->id = cache->used_items;
	item->parent = parent;
	cache->used_items ++;
	msg_debug ("used items: %d, added symbol: %s", cache->used_items, name);
	rspamd_set_counter (item, 0);
	g_ptr_array_add (cache->items_by_id, item);
	g_ptr_array_add (cache->items_by_order, item);
	item->deps = g_ptr_array_new ();
	item->rdeps = g_ptr_array_new ();
	rspamd_mempool_add_destructor (cache->static_pool,
			rspamd_ptr_array_free_hard, item->deps);
	rspamd_mempool_add_destructor (cache->static_pool,
			rspamd_ptr_array_free_hard, item->rdeps);

	if (name != NULL) {
		g_hash_table_insert (cache->items_by_symbol, item->symbol, item);
	}

	return item->id;
}

gint
rspamd_symbols_cache_add_symbol_normal (struct symbols_cache *cache,
	const gchar *name, double weight,
	symbol_func_t func, gpointer user_data)
{
	return rspamd_symbols_cache_add_symbol (cache,
		name,
		weight,
		0,
		func,
		user_data,
		SYMBOL_TYPE_NORMAL,
		-1);
}

gint
rspamd_symbols_cache_add_symbol_virtual (struct symbols_cache *cache,
	const gchar *name,
	double weight,
	gint parent)
{
	return rspamd_symbols_cache_add_symbol (cache,
		name,
		weight,
		0,
		NULL,
		NULL,
		SYMBOL_TYPE_VIRTUAL,
		parent);
}

gint
rspamd_symbols_cache_add_symbol_callback (struct symbols_cache *cache,
	double weight,
	symbol_func_t func,
	gpointer user_data)
{
	return rspamd_symbols_cache_add_symbol (cache,
		NULL,
		weight,
		0,
		func,
		user_data,
		SYMBOL_TYPE_CALLBACK,
		-1);
}

gint
rspamd_symbols_cache_add_symbol_callback_prio (struct symbols_cache *cache,
	double weight,
	gint priority,
	symbol_func_t func,
	gpointer user_data)
{
	return rspamd_symbols_cache_add_symbol (cache,
		NULL,
		weight,
		priority,
		func,
		user_data,
		SYMBOL_TYPE_CALLBACK,
		-1);
}

void
rspamd_symbols_cache_destroy (struct symbols_cache *cache)
{
	if (cache != NULL) {

		if (cache->cfg->cache_filename) {
			/* Try to sync values to the disk */
			if (!rspamd_symbols_cache_save_items (cache,
					cache->cfg->cache_filename)) {
				msg_err ("cannot save cache data to %s",
						cache->cfg->cache_filename);
			}
		}

		g_hash_table_destroy (cache->items_by_symbol);
		rspamd_mempool_delete (cache->static_pool);
		g_ptr_array_free (cache->items_by_id, TRUE);
		g_ptr_array_free (cache->items_by_order, TRUE);
		g_slice_free1 (sizeof (*cache), cache);
	}
}

struct symbols_cache*
rspamd_symbols_cache_new (void)
{
	struct symbols_cache *cache;

	cache = g_slice_alloc0 (sizeof (struct symbols_cache));
	cache->static_pool =
			rspamd_mempool_new (rspamd_mempool_suggest_size ());
	cache->items_by_symbol = g_hash_table_new (rspamd_str_hash,
			rspamd_str_equal);
	cache->items_by_order = g_ptr_array_new ();
	cache->items_by_id = g_ptr_array_new ();
	cache->mtx = rspamd_mempool_get_mutex (cache->static_pool);
	cache->reload_time = CACHE_RELOAD_TIME;
	cache->total_freq = 1;
	cache->max_weight = 1.0;

	return cache;
}

gboolean
rspamd_symbols_cache_init (struct symbols_cache* cache,
		struct rspamd_config *cfg)
{
	gboolean res;

	g_assert (cache != NULL);
	cache->cfg = cfg;

	/* Just in-memory cache */
	if (cfg->cache_filename == NULL) {
		post_cache_init (cache);
		return TRUE;
	}

	/* Copy saved cache entries */
	res = rspamd_symbols_cache_load_items (cache, cfg->cache_filename);

	return res;
}

static gboolean
check_debug_symbol (struct rspamd_config *cfg, const gchar *symbol)
{
	GList *cur;

	cur = cfg->debug_symbols;
	while (cur) {
		if (strcmp (symbol, (const gchar *)cur->data) == 0) {
			return TRUE;
		}
		cur = g_list_next (cur);
	}

	return FALSE;
}

static void
rspamd_symbols_cache_validate_cb (gpointer k, gpointer v, gpointer ud)
{
	struct cache_item *item = v, *parent;
	struct symbols_cache *cache = (struct symbols_cache *)ud;
	GList *cur;
	struct metric *m;
	struct rspamd_symbol_def *s;
	gboolean skipped, ghost;
	gint p1, p2;

	ghost = item->weight == 0 ? TRUE : FALSE;

	/* Check whether this item is skipped */
	skipped = !ghost;
	if (item->type == SYMBOL_TYPE_NORMAL &&
			g_hash_table_lookup (cache->cfg->metrics_symbols, item->symbol) == NULL) {
		cur = g_list_first (cache->cfg->metrics_list);
		while (cur) {
			m = cur->data;

			if (m->accept_unknown_symbols) {
				GList *mlist;

				skipped = FALSE;
				item->weight = item->weight * (m->unknown_weight);
				s = rspamd_mempool_alloc0 (cache->static_pool,
						sizeof (*s));
				s->name = item->symbol;
				s->weight_ptr = &item->weight;
				g_hash_table_insert (m->symbols, item->symbol, s);
				mlist = g_hash_table_lookup (cache->cfg->metrics_symbols,
						item->symbol);
				mlist = g_list_prepend (mlist, m);
				g_hash_table_insert (cache->cfg->metrics_symbols,
						item->symbol, mlist);

				msg_info ("adding unknown symbol %s to metric %s", item->symbol,
						m->name);
			}

			cur = g_list_next (cur);
		}
	}
	else {
		skipped = FALSE;
	}

	if (skipped) {
		item->type = SYMBOL_TYPE_SKIPPED;
		msg_warn ("symbol %s is not registered in any metric, so skip its check",
				item->symbol);
	}

	if (ghost) {
		msg_debug ("symbol %s is registered as ghost symbol, it won't be inserted "
				"to any metric", item->symbol);
	}

	if (item->weight < 0 && item->priority == 0) {
		item->priority ++;
	}

	if (item->type == SYMBOL_TYPE_VIRTUAL && item->parent != -1) {
		g_assert (item->parent < (gint)cache->items_by_id->len);
		parent = g_ptr_array_index (cache->items_by_id, item->parent);

		if (abs (parent->weight) < abs (item->weight)) {
			parent->weight = item->weight;
		}

		p1 = abs (item->priority);
		p2 = abs (parent->priority);

		if (p1 != p2) {
			parent->priority = MAX (p1, p2);
			item->priority = parent->priority;
		}
	}

	if (abs (item->weight) > cache->max_weight) {
		cache->max_weight = abs (item->weight);
	}
}

static void
rspamd_symbols_cache_metric_validate_cb (gpointer k, gpointer v, gpointer ud)
{
	struct symbols_cache *cache = (struct symbols_cache *)ud;
	const gchar *sym = k;
	struct rspamd_symbol_def *s = (struct rspamd_symbol_def *)v;
	gdouble weight;
	struct cache_item *item;

	weight = *s->weight_ptr;
	item = g_hash_table_lookup (cache->items_by_symbol, sym);

	if (item) {
		item->metric_weight = weight;

		if (abs (item->weight) < abs (weight) || weight < 0) {
			item->weight = weight;
		}
	}
}

gboolean
rspamd_symbols_cache_validate (struct symbols_cache *cache,
	struct rspamd_config *cfg,
	gboolean strict)
{
	struct cache_item *item;
	GList *cur, *metric_symbols;

	if (cache == NULL) {
		msg_err ("empty cache is invalid");
		return FALSE;
	}

	/* Now adjust symbol weights according to default metric */
	if (cfg->default_metric != NULL) {
		g_hash_table_foreach (cfg->default_metric->symbols,
			rspamd_symbols_cache_metric_validate_cb,
			cache);
	}

	g_hash_table_foreach (cache->items_by_symbol,
			rspamd_symbols_cache_validate_cb,
			cache);
	/* Now check each metric item and find corresponding symbol in a cache */
	metric_symbols = g_hash_table_get_keys (cfg->metrics_symbols);
	cur = metric_symbols;
	while (cur) {
		item = g_hash_table_lookup (cache->items_by_symbol, cur->data);

		if (item == NULL) {
			msg_warn (
				"symbol '%s' has its score defined but there is no "
				"corresponding rule registered",
				cur->data);
			if (strict) {
				g_list_free (metric_symbols);
				return FALSE;
			}
		}
		cur = g_list_next (cur);
	}
	g_list_free (metric_symbols);

	post_cache_init (cache);

	return TRUE;
}

struct cache_savepoint {
	guchar *processed_bits;
	guint processed_num;
	guint pass;
	gint offset;
	struct metric_result *rs;
	gdouble lim;
	GPtrArray *waitq;
};


static gboolean
check_metric_settings (struct rspamd_task *task, struct metric *metric,
	double *score)
{
	const ucl_object_t *mobj, *reject, *act;
	double val;

	if (task->settings == NULL) {
		return FALSE;
	}

	mobj = ucl_object_find_key (task->settings, metric->name);
	if (mobj != NULL) {
		act = ucl_object_find_key (mobj, "actions");
		if (act != NULL) {
			reject = ucl_object_find_key (act,
					rspamd_action_to_str (METRIC_ACTION_REJECT));
			if (reject != NULL && ucl_object_todouble_safe (reject, &val)) {
				*score = val;
				return TRUE;
			}
		}
	}

	return FALSE;
}

/* Return true if metric has score that is more than spam score for it */
static gboolean
rspamd_symbols_cache_metric_limit (struct rspamd_task *task,
		struct cache_savepoint *cp)
{
	struct metric_result *res;
	GList *cur;
	struct metric *metric;
	double ms;

	cur = task->cfg->metrics_list;

	if (cp->lim == 0.0) {
		/*
		 * Look for metric that has the maximum reject score
		 */
		while (cur) {
			metric = cur->data;
			res = g_hash_table_lookup (task->results, metric->name);

			if (res) {
				if (!check_metric_settings (task, metric, &ms)) {
					ms = metric->actions[METRIC_ACTION_REJECT].score;
				}

				if (cp->lim < ms) {
					cp->rs = res;
					cp->lim = ms;
				}
			}

			cur = g_list_next (cur);
		}
	}

	g_assert (cp->rs != NULL);

	if (cp->rs->score > cp->lim) {
		return TRUE;
	}

	return FALSE;
}

gboolean
rspamd_symbols_cache_process_symbols (struct rspamd_task * task,
	struct symbols_cache * cache)
{
	double t1, t2;
	guint64 diff;
	struct cache_item *item = NULL;
	struct cache_savepoint *checkpoint;
	gint idx = -1, i;

	g_assert (cache != NULL);

	if (task->checkpoint == NULL) {
		checkpoint = rspamd_mempool_alloc0 (task->task_pool, sizeof (*checkpoint));
		checkpoint->processed_bits = rspamd_mempool_alloc (task->task_pool,
				NBYTES (cache->used_items));
		/* Inverse to use ffs */
		memset (checkpoint->processed_bits, 0x0, NBYTES (cache->used_items));
		checkpoint->waitq = g_ptr_array_new ();
		rspamd_mempool_add_destructor (task->task_pool,
				rspamd_ptr_array_free_hard, checkpoint->waitq);
		task->checkpoint = checkpoint;

		rspamd_create_metric_result (task, DEFAULT_METRIC);
		if (task->settings) {
			const ucl_object_t *wl;

			wl = ucl_object_find_key (task->settings, "whitelist");
			if (wl != NULL) {
				msg_info ("<%s> is whitelisted", task->message_id);
				task->flags |= RSPAMD_TASK_FLAG_SKIP;
				return TRUE;
			}
		}
	}
	else {
		checkpoint = task->checkpoint;
	}

	if (checkpoint->processed_num >= cache->used_items) {
		/* All symbols are processed */
		return TRUE;
	}

	for (i = checkpoint->offset * NBBY; i < (gint)cache->used_items; i ++) {
		if (rspamd_symbols_cache_metric_limit (task, checkpoint)) {
			msg_info ("<%s> has already scored more than %.2f, so do not "
					"plan any more checks", task->message_id,
					checkpoint->rs->score);
			return TRUE;
		}

		item = g_ptr_array_index (cache->items_by_order, idx);
		if (!isset (checkpoint->processed_bits, i)) {
			if (item->type == SYMBOL_TYPE_NORMAL || item->type == SYMBOL_TYPE_CALLBACK) {
				g_assert (item->func != NULL);
				t1 = rspamd_get_ticks ();

				if (item->symbol != NULL &&
						G_UNLIKELY (check_debug_symbol (task->cfg, item->symbol))) {
					rspamd_log_debug (rspamd_main->logger);
					item->func (task, item->user_data);
					rspamd_log_nodebug (rspamd_main->logger);
				}
				else {
					item->func (task, item->user_data);
				}

				t2 = rspamd_get_ticks ();

				diff = (t2 - t1) * 1000000;
				rspamd_set_counter (item, diff);
			}

			setbit (checkpoint->processed_bits, idx);
			checkpoint->processed_num ++;
		}
	}

	return TRUE;
}

struct counters_cbdata {
	ucl_object_t *top;
	struct symbols_cache *cache;
};

static void
rspamd_symbols_cache_counters_cb (gpointer v, gpointer ud)
{
	struct counters_cbdata *cbd = ud;
	ucl_object_t *obj, *top;
	struct cache_item *item = v, *parent;

	top = cbd->top;

	if (item->type != SYMBOL_TYPE_CALLBACK) {
		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, ucl_object_fromstring (item->symbol),
				"symbol", 0, false);

		if (item->type == SYMBOL_TYPE_VIRTUAL && item->parent != -1) {
			g_assert (item->parent < (gint)cbd->cache->items_by_id->len);
			parent = g_ptr_array_index (cbd->cache->items_by_id,
					item->parent);
			ucl_object_insert_key (obj, ucl_object_fromdouble (item->weight),
					"weight", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromint (item->frequency),
					"frequency", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromdouble (parent->avg_time),
					"time", 0, false);
		}
		else {
			ucl_object_insert_key (obj, ucl_object_fromdouble (item->weight),
					"weight", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromint (item->frequency),
					"frequency", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromdouble (item->avg_time),
					"time", 0, false);
		}

		ucl_array_append (top, obj);
	}
}

ucl_object_t *
rspamd_symbols_cache_counters (struct symbols_cache * cache)
{
	ucl_object_t *top;
	struct counters_cbdata cbd;

	g_assert (cache != NULL);
	top = ucl_object_typed_new (UCL_ARRAY);
	cbd.top = top;
	cbd.cache = cache;
	g_ptr_array_foreach (cache->items_by_order,
			rspamd_symbols_cache_counters_cb, &cbd);

	return top;
}

static void
rspamd_symbols_cache_resort_cb (gint fd, short what, gpointer ud)
{
	struct timeval tv;
	gdouble tm;
	struct symbols_cache *cache = ud;
	struct cache_item *item, *parent;
	guint i;

	/* Plan new event */
	tm = rspamd_time_jitter (cache->reload_time, 0);
	msg_info ("resort symbols cache, next reload in %.2f seconds", tm);
	g_assert (cache != NULL);
	evtimer_set (&cache->resort_ev, rspamd_symbols_cache_resort_cb, cache);
	double_to_tv (tm, &tv);
	event_add (&cache->resort_ev, &tv);

	rspamd_mempool_lock_mutex (cache->mtx);

	/* Gather stats from shared execution times */
	for (i = 0; i < cache->items_by_order->len; i ++) {
		item = g_ptr_array_index (cache->items_by_order, i);

		if (item->type == SYMBOL_TYPE_CALLBACK ||
				item->type == SYMBOL_TYPE_NORMAL) {
			if (item->cd->number > 0) {
				item->avg_counter += item->cd->number + 1;
				item->avg_time = item->avg_time +
						(item->cd->value - item->avg_time) /
						item->avg_counter;
				item->cd->value = item->avg_time;
				item->cd->number = item->avg_counter;
			}
		}
	}
	/* Sync virtual symbols */
	for (i = 0; i < cache->items_by_id->len; i ++) {
		if (item->parent != -1) {
			parent = g_ptr_array_index (cache->items_by_id, item->parent);
			item->avg_time = parent->avg_time;
			item->avg_counter = parent->avg_counter;
		}
	}

	rspamd_mempool_unlock_mutex (cache->mtx);

	post_cache_init (cache);
}

void
rspamd_symbols_cache_start_refresh (struct symbols_cache * cache,
		struct event_base *ev_base)
{
	struct timeval tv;
	gdouble tm;

	tm = rspamd_time_jitter (cache->reload_time, 0);
	g_assert (cache != NULL);
	evtimer_set (&cache->resort_ev, rspamd_symbols_cache_resort_cb, cache);
	event_base_set (ev_base, &cache->resort_ev);
	double_to_tv (tm, &tv);
	event_add (&cache->resort_ev, &tv);
}

void
rspamd_symbols_cache_inc_frequency (struct symbols_cache *cache,
		const gchar *symbol)
{
	struct cache_item *item, *parent;

	g_assert (cache != NULL);

	item = g_hash_table_lookup (cache->items_by_symbol, symbol);

	if (item != NULL) {
		/* We assume ++ as atomic op */
		item->frequency ++;
		cache->total_freq ++;

		/* For virtual symbols we also increase counter for parent */
		if (item->parent != -1) {
			parent = g_ptr_array_index (cache->items_by_id, item->parent);
			parent->frequency ++;
		}
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
