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
#include "uthash_strcase.h"
#include "utlist.h"

/**
 * LRU hashing
 */

typedef struct rspamd_lru_element_s {
	gpointer data;
	gpointer key;
	time_t store_time;
	guint ttl;
	rspamd_lru_hash_t *hash;

	UT_hash_handle hh;
} rspamd_lru_element_t;

struct rspamd_lru_hash_s {
	gint maxsize;
	gint maxage;
	GDestroyNotify value_destroy;
	GDestroyNotify key_destroy;

	rspamd_lru_element_t *elements;
};


static void
rspamd_lru_hash_destroy_node (gpointer v)
{
	rspamd_lru_element_t *node = v;
	rspamd_lru_hash_t *hash;

	hash = node->hash;

	HASH_DELETE(hh, hash->elements, node);
	if (hash->value_destroy) {
		hash->value_destroy (node->data);
	}
	if (hash->key_destroy) {
		hash->key_destroy (node->key);
	}

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
rspamd_lru_hash_new (
	gint maxsize,
	gint maxage,
	GDestroyNotify key_destroy,
	GDestroyNotify value_destroy)
{
	rspamd_lru_hash_t *new;

	new = g_slice_alloc (sizeof (rspamd_lru_hash_t));
	new->elements = NULL;
	new->maxage = maxage;
	new->maxsize = maxsize;
	new->value_destroy = value_destroy;
	new->key_destroy = key_destroy;

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
	rspamd_lru_element_t *res, *tmp;

	HASH_FIND_STR (hash->elements, key, res);
	if (res != NULL) {
		if (res->ttl != 0) {
			if (now - res->store_time > res->ttl) {
				rspamd_lru_hash_destroy_node (res);
				return NULL;
			}
		}
		if (hash->maxage > 0) {
			if (now - res->store_time > hash->maxage) {
				/* Expire elements from queue tail */
				HASH_ITER (hh, hash->elements, res, tmp) {
					if (now - res->store_time > hash->maxage) {
						rspamd_lru_hash_destroy_node (res);
					}
					else {
						break;
					}
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
	rspamd_lru_element_t *res, *tmp;
	gint removed = 0;

	HASH_FIND_STR (hash->elements, key, res);
	if (res != NULL) {
		rspamd_lru_hash_destroy_node (res);
	}
	else {
		if (hash->maxsize > 0 &&
			(gint)HASH_COUNT (hash->elements) >= hash->maxsize) {
			/* Expire some elements */
			if (hash->maxage > 0) {
				HASH_ITER (hh, hash->elements, res, tmp) {
					if (now - res->store_time > hash->maxage) {
						rspamd_lru_hash_destroy_node (res);
						removed ++;
					}
					else {
						break;
					}
				}
			}
			if (removed == 0) {
				rspamd_lru_hash_destroy_node (hash->elements);
			}
		}
	}

	res = rspamd_lru_create_node (hash, key, value, now, ttl);
	HASH_ADD (hh, hash->elements, key, strlen (key), res);
}

void
rspamd_lru_hash_destroy (rspamd_lru_hash_t *hash)
{
	rspamd_lru_element_t *res, *tmp;

	HASH_ITER (hh, hash->elements, res, tmp) {
		rspamd_lru_hash_destroy_node (res);
	}
	g_slice_free1 (sizeof (rspamd_lru_hash_t), hash);
}

/*
 * vi:ts=4
 */
