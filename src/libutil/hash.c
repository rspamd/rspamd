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

static const guint expire_aggressive_count = 10;

struct rspamd_lru_hash_s {
	guint maxsize;
	GDestroyNotify value_destroy;
	GDestroyNotify key_destroy;
	struct rspamd_min_heap *heap;
	GHashTable *tbl;
};

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

		g_slice_free1 (sizeof (*elt), elt);
	}
}

static inline guint
rspamd_lru_priority (guint ttl, guint usages)
{
	/* 1 day */
	static const  guint max_ttl = 3600 * 24;

	if (ttl > 0 && usages > 0) {
		return G_MAXUINT / (MIN (max_ttl, ttl) * usages);
	}

	return G_MAXUINT;
}

static rspamd_lru_element_t *
rspamd_lru_create_node (rspamd_lru_hash_t *hash,
	gpointer key,
	gpointer value,
	time_t now,
	guint ttl)
{
	rspamd_lru_element_t *node;

	node = g_slice_alloc (sizeof (rspamd_lru_element_t));
	node->data = value;
	node->key = key;
	node->ttl = ttl;
	node->helt.pri = now;
	node->hash = hash;
	node->usages = 1;
	node->storage = now;
	node->helt.pri = rspamd_lru_priority (ttl, 1);

	return node;
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

	new = g_slice_alloc (sizeof (rspamd_lru_hash_t));
	new->tbl = g_hash_table_new_full (hf, cmpf, NULL, rspamd_lru_destroy_node);
	new->heap = rspamd_min_heap_create (maxsize);
	new->maxsize = maxsize;
	new->value_destroy = value_destroy;
	new->key_destroy = key_destroy;

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
		if (res->ttl != 0) {
			if (((guint)now) - res->helt.pri > res->ttl) {
				rspamd_min_heap_remove_elt (hash->heap, &res->helt);
				g_hash_table_remove (hash->tbl, key);
				return NULL;
			}
		}

		rspamd_min_heap_update_elt (hash->heap, &res->helt,
				rspamd_lru_priority (res->ttl, ++res->usages));

		return res->data;
	}

	return NULL;
}

void
rspamd_lru_hash_insert (rspamd_lru_hash_t *hash, gpointer key, gpointer value,
	time_t now, guint ttl)
{
	rspamd_lru_element_t *res;
	guint i;

	res = g_hash_table_lookup (hash->tbl, key);

	if (res != NULL) {
		rspamd_min_heap_remove_elt (hash->heap, &res->helt);
		g_hash_table_remove (hash->tbl, key);
	}
	else {
		if (hash->maxsize > 0 &&
				g_hash_table_size (hash->tbl) >= hash->maxsize) {

			for (i = 0; i < MIN (hash->maxsize, expire_aggressive_count); i ++) {
				res = (rspamd_lru_element_t *)rspamd_min_heap_pop (hash->heap);

				if (res) {
					g_hash_table_remove (hash->tbl, res->key);
				}
				else {
					break;
				}
			}
		}
	}

	res = rspamd_lru_create_node (hash, key, value, now, ttl);
	g_hash_table_insert (hash->tbl, key, res);
	rspamd_min_heap_push (hash->heap, &res->helt);
}

void
rspamd_lru_hash_destroy (rspamd_lru_hash_t *hash)
{
	rspamd_min_heap_destroy (hash->heap);
	g_hash_table_unref (hash->tbl);
	g_slice_free1 (sizeof (rspamd_lru_hash_t), hash);
}


GHashTable *
rspamd_lru_hash_get_htable (rspamd_lru_hash_t *hash)
{
	return hash->tbl;
}
