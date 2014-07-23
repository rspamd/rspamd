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
#include "hash.h"

#define HASH_TABLE_MIN_SIZE 19
#define HASH_TABLE_MAX_SIZE 13845163

/*
 * Performs a lookup in the hash table.  Virtually all hash operations
 * will use this function internally.
 */
static inline struct rspamd_hash_node **
rspamd_hash_lookup_node (rspamd_hash_t * hash,
	gconstpointer key,
	guint * hash_return)
{
	struct rspamd_hash_node **node_ptr, *node;
	guint hash_value;
	hash_value = (*hash->hash_func)(key);

	if (hash->shared) {
		rspamd_mempool_rlock_rwlock (hash->lock);
	}
	node_ptr = &hash->nodes[hash_value % hash->size];

	if (hash_return)
		*hash_return = hash_value;

	/* Hash table lookup needs to be fast.
	 *  We therefore remove the extra conditional of testing
	 *  whether to call the key_equal_func or not from
	 *  the inner loop.
	 *
	 *  Additional optimisation: first check if our full hash
	 *  values are equal so we can avoid calling the full-blown
	 *  key equality function in most cases.
	 */
	if (hash->key_equal_func) {
		while ((node = *node_ptr)) {
			if (node->key_hash == hash_value &&
				hash->key_equal_func (node->key, key)) {
				break;
			}
			node_ptr = &(*node_ptr)->next;
		}
	}
	else {
		while ((node = *node_ptr)) {
			if (node->key == key) {
				break;
			}
			node_ptr = &(*node_ptr)->next;
		}
	}
	if (hash->shared) {
		rspamd_mempool_runlock_rwlock (hash->lock);
	}
	return node_ptr;
}

/*
 * Removes a node from the hash table and updates the node count.
 * No table resize is performed.
 */
static void
rspamd_hash_remove_node (rspamd_hash_t * hash,
	struct rspamd_hash_node ***node_ptr_ptr)
{
	struct rspamd_hash_node **node_ptr, *node;

	if (hash->shared) {
		rspamd_mempool_wlock_rwlock (hash->lock);
	}
	node_ptr = *node_ptr_ptr;
	node = *node_ptr;

	*node_ptr = node->next;

	hash->nnodes--;
	if (hash->shared) {
		rspamd_mempool_wunlock_rwlock (hash->lock);
	}
}

/*
 * Resizes the hash table to the optimal size based on the number of
 * nodes currently held.
 */
static void
rspamd_hash_resize (rspamd_hash_t * hash)
{
	struct rspamd_hash_node **new_nodes;
	struct rspamd_hash_node *node, *next;
	guint hash_val;
	gint new_size, i;

	new_size = g_spaced_primes_closest (hash->nnodes);
	new_size = CLAMP (new_size, HASH_TABLE_MIN_SIZE, HASH_TABLE_MAX_SIZE);

	if (hash->shared) {
		new_nodes =
			rspamd_mempool_alloc_shared (hash->pool,
				sizeof (struct rspamd_hash_node *) * new_size);
	}
	else {
		new_nodes =
			rspamd_mempool_alloc (hash->pool,
				sizeof (struct rspamd_hash_node *) * new_size);
	}

	if (hash->shared) {
		rspamd_mempool_wlock_rwlock (hash->lock);
	}

	for (i = 0; i < hash->size; i++) {
		for (node = hash->nodes[i]; node; node = next) {
			next = node->next;
			hash_val = node->key_hash % new_size;
			node->next = new_nodes[hash_val];
			new_nodes[hash_val] = node;
		}
	}

	hash->nodes = new_nodes;
	hash->size = new_size;

	if (hash->shared) {
		rspamd_mempool_wunlock_rwlock (hash->lock);
	}
}

/*
 * Resizes the hash table, if needed.
 */
static inline void
rspamd_hash_maybe_resize (rspamd_hash_t * hash)
{
	gint nnodes = hash->nnodes;
	gint size = hash->size;

	if ((size >= 3 * nnodes &&
		size > HASH_TABLE_MIN_SIZE) ||
		(3 * size <= nnodes && size < HASH_TABLE_MAX_SIZE)) {
		rspamd_hash_resize (hash);
	}
}

/* Create new hash in specified pool */
rspamd_hash_t *
rspamd_hash_new (rspamd_mempool_t * pool,
	GHashFunc hash_func,
	GEqualFunc key_equal_func)
{
	rspamd_hash_t *hash;

	hash = rspamd_mempool_alloc (pool, sizeof (rspamd_hash_t));
	hash->size = HASH_TABLE_MIN_SIZE;
	hash->nnodes = 0;
	hash->hash_func = hash_func ? hash_func : g_direct_hash;
	hash->key_equal_func = key_equal_func;
	hash->nodes = rspamd_mempool_alloc0 (pool,
			sizeof (struct rspamd_hash_node *) * hash->size);
	hash->shared = 0;
	hash->pool = pool;

	return hash;
}

/*
 * Create new hash in specified pool using shared memory
 */
rspamd_hash_t *
rspamd_hash_new_shared (rspamd_mempool_t * pool,
	GHashFunc hash_func,
	GEqualFunc key_equal_func,
	gint size)
{
	rspamd_hash_t *hash;

	hash = rspamd_mempool_alloc_shared (pool, sizeof (rspamd_hash_t));
	hash->size = size;
	hash->nnodes = 0;
	hash->hash_func = hash_func ? hash_func : g_direct_hash;
	hash->key_equal_func = key_equal_func;
	hash->nodes =
		rspamd_mempool_alloc0_shared (pool,
			sizeof (struct rspamd_hash_node *) * hash->size);
	hash->shared = 1;
	/* Get mutex from pool for locking on insert/remove operations */
	hash->lock = rspamd_mempool_get_rwlock (pool);
	hash->pool = pool;

	return hash;
}

/*
 * Insert item in hash
 */
void
rspamd_hash_insert (rspamd_hash_t * hash, gpointer key, gpointer value)
{
	struct rspamd_hash_node **node_ptr, *node;
	guint key_hash;

	g_return_if_fail (hash != NULL);
	node_ptr = rspamd_hash_lookup_node (hash, key, &key_hash);

	if (hash->shared) {
		rspamd_mempool_wlock_rwlock (hash->lock);
	}
	if ((node = *node_ptr)) {
		node->key = key;
		node->value = value;
	}
	else {
		if (hash->shared) {
			node =
				rspamd_mempool_alloc_shared (hash->pool,
					sizeof (struct rspamd_hash_node));
		}
		else {
			node =
				rspamd_mempool_alloc (hash->pool,
					sizeof (struct rspamd_hash_node));
		}

		node->key = key;
		node->value = value;
		node->key_hash = key_hash;
		node->next = NULL;

		*node_ptr = node;
		hash->nnodes++;
	}
	if (hash->shared) {
		rspamd_mempool_wunlock_rwlock (hash->lock);
	}

	if (!hash->shared) {
		rspamd_hash_maybe_resize (hash);
	}
}

/*
 * Remove item from hash
 */
gboolean
rspamd_hash_remove (rspamd_hash_t * hash, gpointer key)
{
	struct rspamd_hash_node **node_ptr;

	g_return_val_if_fail (hash != NULL, FALSE);

	node_ptr = rspamd_hash_lookup_node (hash, key, NULL);
	if (*node_ptr == NULL)
		return FALSE;

	rspamd_hash_remove_node (hash, &node_ptr);
	rspamd_hash_maybe_resize (hash);

	return TRUE;
}

/*
 * Lookup item from hash
 */
gpointer
rspamd_hash_lookup (rspamd_hash_t * hash, gpointer key)
{
	struct rspamd_hash_node *node;
	g_return_val_if_fail (hash != NULL, NULL);

	node = *rspamd_hash_lookup_node (hash, key, NULL);

	return node ? node->value : NULL;
}

/*
 * Iterate throught hash
 */
void
rspamd_hash_foreach (rspamd_hash_t * hash, GHFunc func, gpointer user_data)
{
	struct rspamd_hash_node *node;
	gint i;

	g_return_if_fail (hash != NULL);
	g_return_if_fail (func != NULL);

	if (hash->shared) {
		rspamd_mempool_rlock_rwlock (hash->lock);
	}
	for (i = 0; i < hash->size; i++) {
		for (node = hash->nodes[i]; node; node = node->next) {
			(*func)(node->key, node->value, user_data);
		}
	}
	if (hash->shared) {
		rspamd_mempool_runlock_rwlock (hash->lock);
	}
}

/**
 * LRU hashing
 */

static void
rspamd_lru_hash_destroy_node (gpointer v)
{
	rspamd_lru_element_t *node = v;

	if (node->hash->value_destroy) {
		node->hash->value_destroy (node->data);
	}
	g_queue_delete_link (node->hash->q, node->link);
	g_slice_free1 (sizeof (rspamd_lru_element_t), node);
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
	node->store_time = now;
	node->ttl = ttl;
	node->hash = hash;

	return node;
}

/**
 * Create new lru hash with GHashTable as storage
 * @param maxsize maximum elements in a hash
 * @param maxage maximum age of elemnt
 * @param hash_func pointer to hash function
 * @param key_equal_func pointer to function for comparing keys
 * @return new rspamd_hash object
 */
rspamd_lru_hash_t *
rspamd_lru_hash_new (GHashFunc hash_func,
	GEqualFunc key_equal_func,
	gint maxsize,
	gint maxage,
	GDestroyNotify key_destroy,
	GDestroyNotify value_destroy)
{
	rspamd_lru_hash_t *new;

	new = g_malloc (sizeof (rspamd_lru_hash_t));
	new->storage = g_hash_table_new_full (hash_func,
			key_equal_func,
			key_destroy,
			rspamd_lru_hash_destroy_node);
	new->maxage = maxage;
	new->maxsize = maxsize;
	new->value_destroy = value_destroy;
	new->key_destroy = NULL;
	new->q = g_queue_new ();
	new->insert_func = (lru_cache_insert_func)g_hash_table_replace;
	new->lookup_func = (lru_cache_lookup_func)g_hash_table_lookup;
	new->delete_func = (lru_cache_delete_func)g_hash_table_remove;
	new->destroy_func = (lru_cache_destroy_func)g_hash_table_destroy;

	return new;
}
/**
 * Create new lru hash with custom storage
 * @param maxsize maximum elements in a hash
 * @param maxage maximum age of elemnt
 * @param hash_func pointer to hash function
 * @param key_equal_func pointer to function for comparing keys
 * @return new rspamd_hash object
 */
rspamd_lru_hash_t *
rspamd_lru_hash_new_full (GHashFunc hash_func,
	GEqualFunc key_equal_func,
	gint maxsize,
	gint maxage,
	GDestroyNotify key_destroy,
	GDestroyNotify value_destroy,
	gpointer storage,
	lru_cache_insert_func insert_func,
	lru_cache_lookup_func lookup_func,
	lru_cache_delete_func delete_func)
{
	rspamd_lru_hash_t *new;

	new = g_malloc (sizeof (rspamd_lru_hash_t));
	new->storage = storage;
	new->maxage = maxage;
	new->maxsize = maxsize;
	new->value_destroy = value_destroy;
	new->key_destroy = key_destroy;
	new->q = g_queue_new ();
	new->insert_func = insert_func;
	new->lookup_func = lookup_func;
	new->delete_func = delete_func;
	new->destroy_func = NULL;

	return new;
}

/**
 * Lookup item from hash
 * @param hash hash object
 * @param key key to find
 * @return value of key or NULL if key is not found
 */
gpointer
rspamd_lru_hash_lookup (rspamd_lru_hash_t *hash, gpointer key, time_t now)
{
	rspamd_lru_element_t *res;

	if ((res = hash->lookup_func (hash->storage, key)) != NULL) {
		if (res->ttl != 0) {
			if (now - res->store_time > res->ttl) {
				hash->delete_func (hash->storage, key);
				return NULL;
			}
		}
		if (hash->maxage > 0) {
			if (now - res->store_time > hash->maxage) {
				res = g_queue_peek_tail (hash->q);
				/* Expire elements from queue tail */
				while (res != NULL && now - res->store_time > hash->maxage) {
					hash->delete_func (hash->storage, res->key);
					res = g_queue_peek_tail (hash->q);
				}

				return NULL;
			}
		}
		return res->data;
	}

	return NULL;
}
/**
 * Insert item in hash
 * @param hash hash object
 * @param key key to insert
 * @param value value of key
 */
void
rspamd_lru_hash_insert (rspamd_lru_hash_t *hash, gpointer key, gpointer value,
	time_t now, guint ttl)
{
	rspamd_lru_element_t *res;
	gint removed = 0;

	if ((res = hash->lookup_func (hash->storage, key)) != NULL) {
		hash->delete_func (hash->storage, res->key);
	}
	else {
		if (hash->maxsize > 0 &&
			(gint)g_queue_get_length (hash->q) >= hash->maxsize) {
			/* Expire some elements */
			res = g_queue_peek_tail (hash->q);
			if (hash->maxage > 0) {
				while (res != NULL && now - res->store_time > hash->maxage) {
					if (res->key != NULL) {
						hash->delete_func (hash->storage, res->key);
					}
					else {
						break;
					}
					res = g_queue_peek_tail (hash->q);
					removed++;
				}
			}
			if (removed == 0) {
				/* Remove explicitly */
				if (res->key != NULL) {
					hash->delete_func (hash->storage, res->key);
				}
			}
		}
	}

	res = rspamd_lru_create_node (hash, key, value, now, ttl);
	hash->insert_func (hash->storage, key, res);
	g_queue_push_head (hash->q, res);
	res->link = g_queue_peek_head_link (hash->q);
}

void
rspamd_lru_hash_destroy (rspamd_lru_hash_t *hash)
{
	if (hash->destroy_func) {
		hash->destroy_func (hash->storage);
	}
	g_queue_free (hash->q);
	g_free (hash);
}

/*
 * vi:ts=4
 */
