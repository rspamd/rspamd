/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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

#define WEIGHT_MULT 4.0
#define FREQUENCY_MULT 10.0
#define TIME_MULT -1.0

/* After which number of messages try to resort cache */
#define MAX_USES 100
/*
 * Symbols cache utility functions
 */

#define MIN_CACHE 17

static guint64 total_frequency = 0;
static guint32 nsymbols = 0;

gint
cache_cmp (const void *p1, const void *p2)
{
	const struct cache_item *i1 = p1, *i2 = p2;

	return strcmp (i1->s->symbol, i2->s->symbol);
}

/* weight, frequency, time */
#define TIME_ALPHA (1.0 / 10000000.0)
#define SCORE_FUN(w, f, t) (((w) > 0 ? (w) : 1) * ((f) > 0 ? (f) : 1) / (t > TIME_ALPHA ? t : TIME_ALPHA))

gint
cache_logic_cmp (const void *p1, const void *p2)
{
	const struct cache_item *i1 = p1, *i2 = p2;
	double w1, w2;
	double weight1, weight2;
	double f1 = 0, f2 = 0, t1, t2;

	if (i1->priority == 0 && i2->priority == 0) {
		f1 = (double)i1->s->frequency;
		f2 = (double)i2->s->frequency;
		weight1 = i1->metric_weight == 0 ? i1->s->weight : i1->metric_weight;
		weight2 = i2->metric_weight == 0 ? i2->s->weight : i2->metric_weight;
		t1 = i1->s->avg_time / 1000000.0;
		t2 = i2->s->avg_time / 1000000.0;
		w1 = SCORE_FUN (fabs (weight1), f1, t1);
		w2 = SCORE_FUN (fabs (weight2), f2, t2);
		msg_debug ("%s -> %.2f, %s -> %.2f", i1->s->symbol, w1, i2->s->symbol, w2);
	}
	else {
		/* Strict sorting */
		w1 = abs (i1->priority);
		w2 = abs (i2->priority);
	}

	return (gint)w2 - w1;
}

/**
 * Set counter for a symbol
 */
static double
rspamd_set_counter (struct cache_item *item, guint32 value)
{
	struct counter_data *cd;
	cd = item->cd;

	/* Cumulative moving average */
	rspamd_mempool_lock_mutex (item->mtx);

	if (cd->number == 0) {
		cd->value = 0;
	}

	cd->value = cd->value + (value - cd->value) / (++cd->number);

	rspamd_mempool_unlock_mutex (item->mtx);

	return cd->value;
}

static GChecksum *
get_mem_cksum (struct symbols_cache *cache)
{
	GChecksum *result;
	GList *cur, *l;
	struct cache_item *item;

	result = g_checksum_new (G_CHECKSUM_SHA1);

	l = g_list_copy (cache->negative_items);
	l = g_list_sort (l, cache_cmp);
	cur = g_list_first (l);
	while (cur) {
		item = cur->data;
		if (item->s->symbol[0] != '\0') {
			g_checksum_update (result, item->s->symbol,
				strlen (item->s->symbol));
		}
		cur = g_list_next (cur);
	}
	g_list_free (l);


	l = g_list_copy (cache->static_items);
	l = g_list_sort (l, cache_cmp);
	cur = g_list_first (l);
	while (cur) {
		item = cur->data;
		if (item->s->symbol[0] != '\0') {
			g_checksum_update (result, item->s->symbol,
				strlen (item->s->symbol));
		}
		total_frequency += item->s->frequency;
		cur = g_list_next (cur);
	}
	g_list_free (l);

	return result;
}

/* Sort items in logical order */
static void
post_cache_init (struct symbols_cache *cache)
{
	GList *cur;
	struct cache_item *item;

	total_frequency = 0;
	nsymbols = cache->used_items;
	cur = g_list_first (cache->negative_items);
	while (cur) {
		item = cur->data;
		total_frequency += item->s->frequency;
		cur = g_list_next (cur);
	}
	cur = g_list_first (cache->static_items);
	while (cur) {
		item = cur->data;
		total_frequency += item->s->frequency;
		cur = g_list_next (cur);
	}

	cache->negative_items =
		g_list_sort (cache->negative_items, cache_logic_cmp);
	cache->static_items = g_list_sort (cache->static_items, cache_logic_cmp);
}

/* Unmap cache file */
static void
unmap_cache_file (gpointer arg)
{
	struct symbols_cache *cache = arg;

	/* A bit ugly usage */
	munmap (cache->map, cache->used_items * sizeof (struct saved_cache_item));
}

static gboolean
mmap_cache_file (struct symbols_cache *cache, gint fd, rspamd_mempool_t *pool)
{
	guint8 *map;
	gint i;
	GList *cur;
	struct cache_item *item;

	if (cache->used_items > 0) {
		map = mmap (NULL,
				cache->used_items * sizeof (struct saved_cache_item),
				PROT_READ | PROT_WRITE,
				MAP_SHARED,
				fd,
				0);
		if (map == MAP_FAILED) {
			msg_err ("cannot mmap cache file: %d, %s", errno, strerror (errno));
			close (fd);
			return FALSE;
		}
		/* Close descriptor as it would never be used */
		close (fd);
		cache->map = map;
		/* Now free old values for saved cache items and fill them with mmapped ones */
		i = 0;
		cur = g_list_first (cache->negative_items);
		while (cur) {
			item = cur->data;
			item->s =
				(struct saved_cache_item *)(map + i *
				sizeof (struct saved_cache_item));
			cur = g_list_next (cur);
			i++;
		}
		cur = g_list_first (cache->static_items);
		while (cur) {
			item = cur->data;
			item->s =
				(struct saved_cache_item *)(map + i *
				sizeof (struct saved_cache_item));
			cur = g_list_next (cur);
			i++;
		}

		post_cache_init (cache);
	}

	return TRUE;
}

/* Fd must be opened for writing, after creating file is mmapped */
static gboolean
create_cache_file (struct symbols_cache *cache,
	const gchar *filename,
	gint fd,
	rspamd_mempool_t *pool)
{
	GChecksum *cksum;
	u_char *digest;
	gsize cklen;
	GList *cur;
	struct cache_item *item;

	/* Calculate checksum */
	cksum = get_mem_cksum (cache);
	if (cksum == NULL) {
		msg_err ("cannot calculate checksum for symbols");
		close (fd);
		return FALSE;
	}

	cklen = g_checksum_type_get_length (G_CHECKSUM_SHA1);
	digest = g_malloc (cklen);

	g_checksum_get_digest (cksum, digest, &cklen);
	/* Now write data to file */
	cur = g_list_first (cache->negative_items);
	while (cur) {
		item = cur->data;
		if (write (fd, item->s, sizeof (struct saved_cache_item)) == -1) {
			msg_err ("cannot write to file %d, %s", errno, strerror (errno));
			close (fd);
			g_checksum_free (cksum);
			g_free (digest);
			return FALSE;
		}
		cur = g_list_next (cur);
	}
	cur = g_list_first (cache->static_items);
	while (cur) {
		item = cur->data;
		if (write (fd, item->s, sizeof (struct saved_cache_item)) == -1) {
			msg_err ("cannot write to file %d, %s", errno, strerror (errno));
			close (fd);
			g_checksum_free (cksum);
			g_free (digest);
			return FALSE;
		}
		cur = g_list_next (cur);
	}
	/* Write checksum */
	if (write (fd, digest, cklen) == -1) {
		msg_err ("cannot write to file %d, %s", errno, strerror (errno));
		close (fd);
		g_checksum_free (cksum);
		g_free (digest);
		return FALSE;
	}

	close (fd);
	g_checksum_free (cksum);
	g_free (digest);
	/* Reopen for reading */
	if ((fd = open (filename, O_RDWR)) == -1) {
		msg_info ("cannot open file %s, error %d, %s", errno, strerror (errno));
		return FALSE;
	}

	return mmap_cache_file (cache, fd, pool);
}

void
register_symbol_common (struct symbols_cache **cache,
	const gchar *name,
	double weight,
	gint priority,
	symbol_func_t func,
	gpointer user_data,
	enum rspamd_symbol_type type)
{
	struct cache_item *item = NULL;
	struct symbols_cache *pcache = *cache;
	GList **target, *cur;
	struct metric *m;
	struct rspamd_symbol_def *s;
	gboolean skipped, ghost = (weight == 0.0);

	if (*cache == NULL) {
		pcache = g_new0 (struct symbols_cache, 1);
		*cache = pcache;
		pcache->static_pool =
			rspamd_mempool_new (rspamd_mempool_suggest_size ());
		pcache->items_by_symbol = g_hash_table_new (rspamd_str_hash,
				rspamd_str_equal);
	}

	item = rspamd_mempool_alloc0 (pcache->static_pool,
			sizeof (struct cache_item));
	item->s =
		rspamd_mempool_alloc0_shared (pcache->static_pool,
			sizeof (struct saved_cache_item));
	item->cd = rspamd_mempool_alloc0_shared (pcache->static_pool,
			sizeof (struct counter_data));

	item->mtx = rspamd_mempool_get_mutex (pcache->static_pool);

	rspamd_strlcpy (item->s->symbol, name, sizeof (item->s->symbol));
	item->func = func;
	item->user_data = user_data;
	item->priority = priority;

	switch (type) {
	case SYMBOL_TYPE_NORMAL:
		break;
	case SYMBOL_TYPE_VIRTUAL:
		item->is_virtual = TRUE;
		break;
	case SYMBOL_TYPE_CALLBACK:
		item->is_callback = TRUE;
		break;
	}

	/* Handle weight using default metric */
	if (pcache->cfg && pcache->cfg->default_metric &&
		(s =
		g_hash_table_lookup (pcache->cfg->default_metric->symbols,
		name)) != NULL) {
		item->s->weight = weight * (*s->weight_ptr);
	}
	else {
		item->s->weight = weight;
	}

	/* Check whether this item is skipped */
	skipped = !ghost;
	if (!ghost && !item->is_callback && pcache->cfg &&
			g_hash_table_lookup (pcache->cfg->metrics_symbols, name) == NULL) {
		cur = g_list_first (pcache->cfg->metrics_list);
		while (cur) {
			m = cur->data;

			if (m->accept_unknown_symbols) {
				GList *mlist;

				skipped = FALSE;

				item->s->weight = weight * (m->unknown_weight);
				s = rspamd_mempool_alloc0 (pcache->static_pool,
						sizeof (*s));
				s->name = item->s->symbol;
				s->weight_ptr = &item->s->weight;
				g_hash_table_insert (m->symbols, item->s->symbol,
						s);
				mlist = g_hash_table_lookup (pcache->cfg->metrics_symbols, name);
				mlist = g_list_prepend (mlist, m);
				g_hash_table_insert (pcache->cfg->metrics_symbols,
						item->s->symbol, mlist);

				msg_info ("adding unknown symbol %s to metric %s", name,
						m->name);
			}

			cur = g_list_next (cur);
		}
	}
	else {
		skipped = FALSE;
	}

	item->is_skipped = skipped;
	item->is_ghost = ghost;

	if (skipped) {
		msg_warn ("symbol %s is not registered in any metric, so skip its check",
				name);
	}

	if (ghost) {
		msg_debug ("symbol %s is registered as ghost symbol, it won't be inserted "
				"to any metric", name);
	}

	/* If we have undefined priority determine list according to weight */
	if (priority == 0) {
		if (item->s->weight >= 0) {
			target = &(*cache)->static_items;
		}
		else {
			target = &(*cache)->negative_items;
		}
	}
	else {
		/* Items with more priority are called before items with less priority */
		if (priority < 0) {
			target = &(*cache)->negative_items;
		}
		else {
			target = &(*cache)->static_items;
		}
	}

	pcache->used_items++;
	g_hash_table_insert (pcache->items_by_symbol, item->s->symbol, item);
	msg_debug ("used items: %d, added symbol: %s", (*cache)->used_items, name);
	rspamd_set_counter (item, 0);

	*target = g_list_prepend (*target, item);
}

void
register_symbol (struct symbols_cache **cache, const gchar *name, double weight,
	symbol_func_t func, gpointer user_data)
{
	register_symbol_common (cache,
		name,
		weight,
		0,
		func,
		user_data,
		SYMBOL_TYPE_NORMAL);
}

void
register_virtual_symbol (struct symbols_cache **cache,
	const gchar *name,
	double weight)
{
	register_symbol_common (cache,
		name,
		weight,
		0,
		NULL,
		NULL,
		SYMBOL_TYPE_VIRTUAL);
}

void
register_callback_symbol (struct symbols_cache **cache,
	const gchar *name,
	double weight,
	symbol_func_t func,
	gpointer user_data)
{
	register_symbol_common (cache,
		name,
		weight,
		0,
		func,
		user_data,
		SYMBOL_TYPE_CALLBACK);
}

void
register_callback_symbol_priority (struct symbols_cache **cache,
	const gchar *name,
	double weight,
	gint priority,
	symbol_func_t func,
	gpointer user_data)
{
	register_symbol_common (cache,
		name,
		weight,
		priority,
		func,
		user_data,
		SYMBOL_TYPE_CALLBACK);
}



static void
free_cache (gpointer arg)
{
	struct symbols_cache *cache = arg;

	if (cache->map != NULL) {
		unmap_cache_file (cache);
	}

	if (cache->static_items) {
		g_list_free (cache->static_items);
	}
	if (cache->negative_items) {
		g_list_free (cache->negative_items);
	}
	g_hash_table_destroy (cache->items_by_symbol);
	rspamd_mempool_delete (cache->static_pool);

	g_free (cache);
}

gboolean
init_symbols_cache (rspamd_mempool_t * pool,
	struct symbols_cache *cache,
	struct rspamd_config *cfg,
	const gchar *filename,
	gboolean ignore_checksum)
{
	struct stat st;
	gint fd;
	GChecksum *cksum;
	u_char *mem_sum, *file_sum;
	gsize cklen;
	gboolean res;

	if (cache == NULL) {
		return FALSE;
	}

	cache->cfg = cfg;

	/* Just in-memory cache */
	if (filename == NULL) {
		post_cache_init (cache);
		return TRUE;
	}

	/* First of all try to stat file */
	if (stat (filename, &st) == -1) {
		/* Check errno */
		if (errno == ENOENT) {
			/* Try to create file */
			if ((fd =
				open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR |
				S_IRUSR)) == -1) {
				msg_info ("cannot create file %s, error %d, %s",
					filename,
					errno,
					strerror (errno));
				return FALSE;
			}
			else {
				return create_cache_file (cache, filename, fd, pool);
			}
		}
		else {
			msg_info ("cannot stat file %s, error %d, %s",
				filename,
				errno,
				strerror (errno));
			return FALSE;
		}
	}
	else {
		if ((fd = open (filename, O_RDWR)) == -1) {
			msg_info ("cannot open file %s, error %d, %s",
				filename,
				errno,
				strerror (errno));
			return FALSE;
		}
	}

	if (!ignore_checksum) {
		/* Calculate checksum */
		cksum = get_mem_cksum (cache);
		if (cksum == NULL) {
			msg_err ("cannot calculate checksum for symbols");
			close (fd);
			return FALSE;
		}

		cklen = g_checksum_type_get_length (G_CHECKSUM_SHA1);
		mem_sum = g_malloc (cklen);

		g_checksum_get_digest (cksum, mem_sum, &cklen);
		/* Now try to read file sum */
		if (lseek (fd, -(cklen), SEEK_END) == -1) {
			if (errno == EINVAL) {
				/* Try to create file */
				close (fd);
				msg_info ("recreate cache file");
				if ((fd =
					open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR |
					S_IRUSR)) == -1) {
					msg_info ("cannot create file %s, error %d, %s",
						filename,
						errno,
						strerror (errno));
					return FALSE;
				}
				else {
					return create_cache_file (cache, filename, fd, pool);
				}
			}
			close (fd);
			g_free (mem_sum);
			g_checksum_free (cksum);
			msg_err ("cannot seek to read checksum, %d, %s", errno,
				strerror (errno));
			return FALSE;
		}
		file_sum = g_malloc (cklen);
		if (read (fd, file_sum, cklen) == -1) {
			close (fd);
			g_free (mem_sum);
			g_free (file_sum);
			g_checksum_free (cksum);
			msg_err ("cannot read checksum, %d, %s", errno, strerror (errno));
			return FALSE;
		}

		if (memcmp (file_sum, mem_sum, cklen) != 0) {
			close (fd);
			g_free (mem_sum);
			g_free (file_sum);
			g_checksum_free (cksum);
			msg_info ("checksum mismatch, recreating file");
			/* Reopen with rw permissions */
			if ((fd =
				open (filename, O_RDWR | O_TRUNC | O_CREAT, S_IWUSR |
				S_IRUSR)) == -1) {
				msg_info ("cannot create file %s, error %d, %s",
					filename,
					errno,
					strerror (errno));
				return FALSE;
			}
			else {
				return create_cache_file (cache, filename, fd, pool);
			}
		}

		g_free (mem_sum);
		g_free (file_sum);
		g_checksum_free (cksum);
	}
	/* MMap cache file and copy saved_cache structures */
	res = mmap_cache_file (cache, fd, pool);

	rspamd_mempool_add_destructor (pool,
		(rspamd_mempool_destruct_t)free_cache,
		cache);

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
rspamd_symbols_cache_metric_cb (gpointer k, gpointer v, gpointer ud)
{
	struct symbols_cache *cache = (struct symbols_cache *)ud;
	GList *cur;
	const gchar *sym = k;
	struct rspamd_symbol_def *s = (struct rspamd_symbol_def *)v;
	gdouble weight;
	struct cache_item *item;

	weight = *s->weight_ptr;
	cur = cache->negative_items;
	while (cur) {
		item = cur->data;
		if (strcmp (item->s->symbol, sym) == 0) {
			item->metric_weight = weight;
			return;
		}
		cur = g_list_next (cur);
	}
	cur = cache->static_items;
	while (cur) {
		item = cur->data;
		if (strcmp (item->s->symbol, sym) == 0) {
			item->metric_weight = weight;
			return;
		}
		cur = g_list_next (cur);
	}
}

gboolean
validate_cache (struct symbols_cache *cache,
	struct rspamd_config *cfg,
	gboolean strict)
{
	struct cache_item *item;
	GList *cur, *p, *metric_symbols;
	gboolean res;

	if (cache == NULL) {
		msg_err ("empty cache is invalid");
		return FALSE;
	}
#ifndef GLIB_HASH_COMPAT
	/* Now check each metric item and find corresponding symbol in a cache */
	metric_symbols = g_hash_table_get_keys (cfg->metrics_symbols);
	cur = metric_symbols;
	while (cur) {
		res = FALSE;
		p = cache->negative_items;
		while (p) {
			item = p->data;
			if (strcmp (item->s->symbol, cur->data) == 0) {
				res = TRUE;
				break;
			}
			p = g_list_next (p);
		}
		if (!res) {
			p = cache->static_items;
			while (p) {
				item = p->data;
				if (strcmp (item->s->symbol, cur->data) == 0) {
					res = TRUE;
					break;
				}
				p = g_list_next (p);
			}
		}
		if (!res) {
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
#endif /* GLIB_COMPAT */

	/* Now adjust symbol weights according to default metric */
	if (cfg->default_metric != NULL) {
		g_hash_table_foreach (cfg->default_metric->symbols,
			rspamd_symbols_cache_metric_cb,
			cache);
		/* Resort caches */
		cache->negative_items = g_list_sort (cache->negative_items,
				cache_logic_cmp);
		cache->static_items =
			g_list_sort (cache->static_items, cache_logic_cmp);
	}

	return TRUE;
}

struct symbol_callback_data {
	enum {
		CACHE_STATE_NEGATIVE,
		CACHE_STATE_STATIC
	} state;
	struct cache_item *saved_item;
	GList *list_pointer;
};

gboolean
call_symbol_callback (struct rspamd_task * task,
	struct symbols_cache * cache,
	gpointer *save)
{
	double t1, t2;
	guint64 diff;
	struct cache_item *item = NULL;
	struct symbol_callback_data *s = *save;

	if (s == NULL) {
		if (cache == NULL) {
			return FALSE;
		}
		if (cache->uses++ >= MAX_USES) {
			msg_info ("resort symbols cache");
			cache->uses = 0;
			/* Resort while having write lock */
			post_cache_init (cache);
		}
		s =
			rspamd_mempool_alloc0 (task->task_pool,
				sizeof (struct symbol_callback_data));
		*save = s;
		if (cache->negative_items != NULL) {
			s->list_pointer = g_list_first (cache->negative_items);
			s->saved_item = s->list_pointer->data;
			s->state = CACHE_STATE_NEGATIVE;
		}
		else {
			s->state = CACHE_STATE_STATIC;
			s->list_pointer = g_list_first (cache->static_items);
			if (s->list_pointer) {
				s->saved_item = s->list_pointer->data;
			}
			else {
				return FALSE;
			}
		}
		item = s->saved_item;
	}
	else {
		if (cache == NULL) {
			return FALSE;
		}
		switch (s->state) {
		case CACHE_STATE_NEGATIVE:
			s->list_pointer = g_list_next (s->list_pointer);
			if (s->list_pointer == NULL) {
				s->state = CACHE_STATE_STATIC;
				s->list_pointer = g_list_first (cache->static_items);
				if (s->list_pointer) {
					s->saved_item = s->list_pointer->data;
				}
				else {
					return FALSE;
				}
			}
			else {
				s->saved_item = s->list_pointer->data;
			}
			item = s->saved_item;
			break;
		case CACHE_STATE_STATIC:
			/* Next pointer */
			s->list_pointer = g_list_next (s->list_pointer);
			if (s->list_pointer) {
				s->saved_item = s->list_pointer->data;
			}
			else {
				return FALSE;
			}
			item = s->saved_item;
			break;
		}
	}
	if (!item) {
		return FALSE;
	}
	if (!item->is_virtual && !item->is_skipped) {
		t1 = rspamd_get_ticks ();

		if (G_UNLIKELY (check_debug_symbol (task->cfg, item->s->symbol))) {
			rspamd_log_debug (rspamd_main->logger);
			item->func (task, item->user_data);
			rspamd_log_nodebug (rspamd_main->logger);
		}
		else {
			item->func (task, item->user_data);
		}

		t2 = rspamd_get_ticks ();

		diff = (t2 - t1) * 1000000;
		item->s->avg_time = rspamd_set_counter (item, diff);
	}

	s->saved_item = item;

	return TRUE;

}
