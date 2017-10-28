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
#include "hash.h"
#include "util.h"

/**
 * LRU hashing
 */

static const guint log_base = 10;
static const guint eviction_candidates = 16;
static const gdouble lfu_base_value = 5.0;

struct rspamd_lru_hash_s {
	guint maxsize;
	guint eviction_min_prio;
	guint eviction_used;
	GDestroyNotify value_destroy;
	GDestroyNotify key_destroy;
	struct rspamd_lru_element_s **eviction_pool;
	GHashTable *tbl;
};

struct rspamd_lru_element_s {
	guint16 ttl;
	guint16 last;
	guint8 lg_usages;
	guint eviction_pos;
	gpointer data;
	gpointer key;
	rspamd_lru_hash_t *hash;
};

#define TIME_TO_TS(t) ((guint16)(((t) / 60) & 0xFFFFU))

static void
rspamd_lru_destroy_node (gpointer value)
{
	rspamd_lru_element_t *elt = (rspamd_lru_element_t *)value;

	if (elt) {
		if (elt->hash && elt->hash->key_destroy) {
			elt->hash->key_destroy (elt->key);
		}
		if (elt->hash && elt->hash->value_destroy) {
			elt->hash->value_destroy (elt->data);
		}

		g_free (elt);
	}
}

static void
rspamd_lru_hash_remove_evicted (rspamd_lru_hash_t *hash,
		rspamd_lru_element_t *elt)
{
	guint i;
	rspamd_lru_element_t *cur;

	g_assert (hash->eviction_used > 0);
	g_assert (elt->eviction_pos < hash->eviction_used);

	memmove (&hash->eviction_pool[elt->eviction_pos],
			&hash->eviction_pool[elt->eviction_pos + 1],
			sizeof (rspamd_lru_element_t *) *
					(eviction_candidates - elt->eviction_pos - 1));

	hash->eviction_used--;

	if (hash->eviction_used > 0) {
		/* We also need to update min_prio and renumber eviction list */
		hash->eviction_min_prio = G_MAXUINT;

		for (i = 0; i < hash->eviction_used; i ++) {
			cur = hash->eviction_pool[i];

			if (hash->eviction_min_prio > cur->lg_usages) {
				hash->eviction_min_prio = cur->lg_usages;
			}

			cur->eviction_pos = i;
		}
	}
	else {
		hash->eviction_min_prio = G_MAXUINT;
	}


}

static void
rspamd_lru_hash_update_counter (rspamd_lru_element_t *elt)
{
	guint8 counter = elt->lg_usages;

	if (counter != 255) {
		double r, baseval, p;

		r = rspamd_random_double_fast ();
		baseval = counter - lfu_base_value;

		if (baseval < 0) {
			baseval = 0;
		}

		p = 1.0 / (baseval * log_base + 1);

		if (r < p) {
			elt->lg_usages ++;
		}
	}
}

static inline void
rspamd_lru_hash_decrease_counter (rspamd_lru_element_t *elt, time_t now)
{
	if (now - elt->last > lfu_base_value) {
		/* Penalise counters for outdated records */
		elt->lg_usages /= 2;
	}
}

static gboolean
rspamd_lru_hash_maybe_evict (rspamd_lru_hash_t *hash,
		rspamd_lru_element_t *elt)
{
	guint i;
	rspamd_lru_element_t *cur;

	if (elt->eviction_pos == -1) {
		if (hash->eviction_used < eviction_candidates) {
			/* There are free places in eviction pool */
			hash->eviction_pool[hash->eviction_used] = elt;
			elt->eviction_pos = hash->eviction_used;
			hash->eviction_used ++;

			if (hash->eviction_min_prio > elt->lg_usages) {
				hash->eviction_min_prio = elt->lg_usages;
			}

			return TRUE;
		}
		else {
			/* Find any candidate that has higher usage count */
			for (i = 0; i < hash->eviction_used; i ++) {
				cur = hash->eviction_pool[i];

				if (cur->lg_usages > elt->lg_usages) {
					cur->eviction_pos = -1;
					elt->eviction_pos = i;
					hash->eviction_pool[i] = elt;

					if (hash->eviction_min_prio > elt->lg_usages) {
						hash->eviction_min_prio = elt->lg_usages;
					}

					return TRUE;
				}
			}
		}
	}
	else {
		/* Already in the eviction list */
		return TRUE;
	}

	return FALSE;
}

static rspamd_lru_element_t *
rspamd_lru_create_node (rspamd_lru_hash_t *hash,
	gpointer key,
	gpointer value,
	time_t now,
	guint ttl)
{
	rspamd_lru_element_t *node;

	node = g_malloc (sizeof (rspamd_lru_element_t));
	node->data = value;
	node->key = key;
	node->ttl = TIME_TO_TS (ttl);

	if (node->ttl == 0) {
		node->ttl = 1;
	}

	node->hash = hash;
	node->lg_usages = lfu_base_value;
	node->last = TIME_TO_TS (now);
	node->eviction_pos = -1;

	return node;
}

static void
rspamd_lru_hash_remove_node (rspamd_lru_hash_t *hash, rspamd_lru_element_t *elt)
{
	if (elt->eviction_pos != -1) {
		rspamd_lru_hash_remove_evicted (hash, elt);
	}

	g_hash_table_remove (hash->tbl, elt->key);
}

static rspamd_lru_element_t *
rspamd_lru_eviction_full_update (rspamd_lru_hash_t *hash, time_t now)
{
	GHashTableIter it;
	gpointer k, v;
	rspamd_lru_element_t *cur, *selected = NULL;

	g_hash_table_iter_init (&it, hash->tbl);
	now = TIME_TO_TS (now);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		cur = v;

		rspamd_lru_hash_decrease_counter (cur, now);

		if (rspamd_lru_hash_maybe_evict (hash, cur)) {

			if (selected && cur->lg_usages < selected->lg_usages) {
				selected = cur;
			}
			else if (selected == NULL) {
				selected = cur;
			}
		}
	}

	return selected;
}

static void
rspamd_lru_hash_evict (rspamd_lru_hash_t *hash, time_t now)
{
	double r;
	guint i;
	rspamd_lru_element_t *elt = NULL;

	/*
	 * We either evict one node from the eviction list
	 * or, at some probability scan all table and update eviction
	 * list first
	 */

	r = rspamd_random_double_fast ();

	if (r < ((double)eviction_candidates) / hash->maxsize) {
		elt = rspamd_lru_eviction_full_update (hash, now);
	}
	else {
		for (i = 0; i < hash->eviction_used; i ++) {
			elt = hash->eviction_pool[i];

			if (elt->lg_usages <= hash->eviction_min_prio) {
				break;
			}
		}
	}

	g_assert (elt != NULL);
	rspamd_lru_hash_remove_node (hash, elt);
}

rspamd_lru_hash_t *
rspamd_lru_hash_new_full (
	gint maxsize,
	GDestroyNotify key_destroy,
	GDestroyNotify value_destroy,
	GHashFunc hf,
	GEqualFunc cmpf)
{
	rspamd_lru_hash_t *new;

	if (maxsize < eviction_candidates * 2) {
		maxsize = eviction_candidates * 2;
	}

	new = g_malloc0 (sizeof (rspamd_lru_hash_t));
	new->tbl = g_hash_table_new_full (hf, cmpf, NULL, rspamd_lru_destroy_node);
	new->eviction_pool = g_malloc0 (sizeof (rspamd_lru_element_t *) *
			eviction_candidates);
	new->maxsize = maxsize;
	new->value_destroy = value_destroy;
	new->key_destroy = key_destroy;
	new->eviction_min_prio = G_MAXUINT;

	return new;
}

rspamd_lru_hash_t *
rspamd_lru_hash_new (
	gint maxsize,
	GDestroyNotify key_destroy,
	GDestroyNotify value_destroy)
{
	return rspamd_lru_hash_new_full (maxsize,
			key_destroy, value_destroy,
			rspamd_strcase_hash, rspamd_strcase_equal);
}

gpointer
rspamd_lru_hash_lookup (rspamd_lru_hash_t *hash, gconstpointer key, time_t now)
{
	rspamd_lru_element_t *res;

	res = g_hash_table_lookup (hash->tbl, key);
	if (res != NULL) {
		now = TIME_TO_TS(now);

		if (res->ttl != 0) {
			if (now - res->last > res->ttl) {
				rspamd_lru_hash_remove_node (hash, res);

				return NULL;
			}
		}

		res->last = MAX (res->last, now);
		rspamd_lru_hash_update_counter (res);
		rspamd_lru_hash_maybe_evict (hash, res);

		return res->data;
	}

	return NULL;
}

gboolean
rspamd_lru_hash_remove (rspamd_lru_hash_t *hash,
		gconstpointer key)
{
	rspamd_lru_element_t *res;

	res = g_hash_table_lookup (hash->tbl, key);

	if (res != NULL) {
		rspamd_lru_hash_remove_node (hash, res);

		return TRUE;
	}

	return FALSE;
}

void
rspamd_lru_hash_insert (rspamd_lru_hash_t *hash, gpointer key, gpointer value,
	time_t now, guint ttl)
{
	rspamd_lru_element_t *res;

	res = g_hash_table_lookup (hash->tbl, key);

	if (res != NULL) {
		rspamd_lru_hash_remove_node (hash, res);
	}
	else {
		if (g_hash_table_size (hash->tbl) >= hash->maxsize) {
			rspamd_lru_hash_evict (hash, now);
		}
	}

	res = rspamd_lru_create_node (hash, key, value, now, ttl);
	g_hash_table_insert (hash->tbl, key, res);
	rspamd_lru_hash_maybe_evict (hash, res);
}

void
rspamd_lru_hash_destroy (rspamd_lru_hash_t *hash)
{
	g_hash_table_unref (hash->tbl);
	g_free (hash->eviction_pool);
	g_free (hash);
}


GHashTable *
rspamd_lru_hash_get_htable (rspamd_lru_hash_t *hash)
{
	return hash->tbl;
}

gpointer
rspamd_lru_hash_element_data (rspamd_lru_element_t *elt)
{
	return elt->data;
}