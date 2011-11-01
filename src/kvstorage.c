/* Copyright (c) 2011, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#include "kvstorage.h"
#include "main.h"
#include "radix.h"

#define MAX_EXPIRE_STEPS 10

/** Create new kv storage */
struct rspamd_kv_storage *
rspamd_kv_storage_new (gint id, const gchar *name, struct rspamd_kv_cache *cache, struct rspamd_kv_backend *backend, struct rspamd_kv_expire *expire,
		gsize max_elts, gsize max_memory)
{
	struct rspamd_kv_storage 			*new;

	new = g_slice_alloc (sizeof (struct rspamd_kv_storage));
	new->elts = 0;
	new->memory = 0;

	new->cache = cache;
	new->backend = backend;
	new->expire = expire;

	new->max_elts = max_elts;
	new->max_memory = max_memory;

	new->id = id;

	if (name != NULL) {
		new->name = g_strdup (name);
	}
	else {
		/* Name is absent, use ID as name */
		new->name = g_malloc (sizeof ("18446744073709551616"));
		rspamd_snprintf (new->name, sizeof ("18446744073709551616"), "%d", id);
	}

	g_static_rw_lock_init (&new->rwlock);

	/* Init structures */
	if (new->cache->init_func) {
		new->cache->init_func (new->cache);
	}
	if (new->backend && new->backend->init_func) {
		new->backend->init_func (new->backend);
	}
	if (new->expire && new->expire->init_func) {
		new->expire->init_func (new->expire);
	}

	return new;
}

/** Internal insertion to the kv storage from backend */
gboolean
rspamd_kv_storage_insert_internal (struct rspamd_kv_storage *storage, gpointer key,
		gpointer data, gsize len, gint flags, guint expire, struct rspamd_kv_element **pelt)
{
	gint 								steps = 0;
	struct rspamd_kv_element		 	*elt = *pelt;

	/* Hard limit */
	if (storage->max_memory > 0) {
		if (len > storage->max_memory) {
			msg_info ("<%s>: trying to insert value of length %z while limit is %z", storage->name,
					len, storage->max_memory);
			return FALSE;
		}

		/* Now check limits */
		while (storage->memory + len > storage->max_memory || storage->elts >= storage->max_elts) {
			if (storage->expire) {
				storage->expire->step_func (storage->expire, storage, time (NULL));
			}
			else {
				msg_warn ("<%s>: storage is full and no expire function is defined", storage->name);
			}
			if (++steps > MAX_EXPIRE_STEPS) {
				msg_warn ("<%s>: cannot expire enough keys in storage", storage->name);
				return FALSE;
			}
		}
	}

	/* Insert elt to the cache */
	elt = storage->cache->insert_func (storage->cache, key, data, len);
	if (elt == NULL) {
		return FALSE;
	}
	/* Copy data */
	elt->flags = flags;
	elt->expire = expire;
	*pelt = elt;

	/* Insert to the expire */
	if (storage->expire) {
		storage->expire->insert_func (storage->expire, elt);
	}

	storage->elts ++;
	storage->memory += elt->size + sizeof (struct rspamd_kv_element);

	return TRUE;
}

/** Insert new element to the kv storage */
gboolean
rspamd_kv_storage_insert (struct rspamd_kv_storage *storage, gpointer key,
		gpointer data, gsize len, gint flags, guint expire)
{
	gint 								steps = 0;
	struct rspamd_kv_element           *elt;
	gboolean							res = TRUE;

	/* Hard limit */
	if (storage->max_memory > 0) {
		if (len > storage->max_memory) {
			msg_info ("<%s>: trying to insert value of length %z while limit is %z", storage->name,
					len, storage->max_memory);
			return FALSE;
		}

		/* Now check limits */
		while (storage->memory + len > storage->max_memory || storage->elts >= storage->max_elts) {
			if (storage->expire) {
				storage->expire->step_func (storage->expire, storage, time (NULL));
			}
			else {
				msg_warn ("<%s>: storage is full and no expire function is defined", storage->name);
			}
			if (++steps > MAX_EXPIRE_STEPS) {
				msg_warn ("<%s>: cannot expire enough keys in storage", storage->name);
				return FALSE;
			}
		}
	}

	/* Insert elt to the cache */
	elt = storage->cache->insert_func (storage->cache, key, data, len);
	if (elt == NULL) {
		return FALSE;
	}
	elt->flags = flags;
	elt->size = len;
	elt->expire = expire;

	/* Place to the backend */
	if (storage->backend) {
		res = storage->backend->insert_func (storage->backend, key, elt);
	}

	/* Insert to the expire */
	if (storage->expire) {
		storage->expire->insert_func (storage->expire, elt);
	}

	storage->elts ++;
	storage->memory += len + sizeof (struct rspamd_kv_element);

	return res;
}

/** Replace an element in the kv storage */
gboolean
rspamd_kv_storage_replace (struct rspamd_kv_storage *storage, gpointer key, struct rspamd_kv_element *elt)
{
	gboolean						res = TRUE;
	gint							steps = 0;

	/* Hard limit */
	if (storage->max_memory > 0) {
		if (elt->size > storage->max_memory) {
			msg_info ("<%s>: trying to replace value of length %z while limit is %z", storage->name,
					elt->size, storage->max_memory);
			return FALSE;
		}

		/* Now check limits */
		while (storage->memory + elt->size > storage->max_memory) {
			if (storage->expire) {
				storage->expire->step_func (storage->expire, storage, time (NULL));
			}
			else {
				msg_warn ("<%s>: storage is full and no expire function is defined", storage->name);
			}
			if (++steps > MAX_EXPIRE_STEPS) {
				msg_warn ("<%s>: cannot expire enough keys in storage", storage->name);
				return FALSE;
			}
		}
	}

	/* Insert elt to the cache */
	res = storage->cache->replace_func (storage->cache, key, elt);

	/* Place to the backend */
	if (res && storage->backend) {
		res = storage->backend->replace_func (storage->backend, key, elt);
	}

	return res;
}

/** Lookup an element inside kv storage */
struct rspamd_kv_element*
rspamd_kv_storage_lookup (struct rspamd_kv_storage *storage, gpointer key, time_t now)
{
	struct rspamd_kv_element			*elt = NULL, *belt;

	/* First try to look at cache */
	elt = storage->cache->lookup_func (storage->cache, key);

	/* Next look at the backend */
	if (elt == NULL && storage->backend) {
		belt = storage->backend->lookup_func (storage->backend, key);
		if (belt) {
			/* Put this element into cache */
			rspamd_kv_storage_insert_internal (storage, ELT_KEY (belt), ELT_DATA (belt),
					belt->size, belt->flags,
					belt->expire, &elt);
			if ((belt->flags & KV_ELT_DIRTY) == 0) {
				g_free (belt);
			}
		}
	}

	if (elt && (elt->flags & KV_ELT_PERSISTENT) == 0) {
		/* Check expiration */
		if (now - elt->age > elt->expire) {
			rspamd_kv_storage_delete (storage, key);
			elt = NULL;
		}
	}

	return elt;
}

/** Expire an element from kv storage */
struct rspamd_kv_element *
rspamd_kv_storage_delete (struct rspamd_kv_storage *storage, gpointer key)
{
	struct rspamd_kv_element           *elt;

	/* First delete key from cache */
	elt = storage->cache->delete_func (storage->cache, key);

	/* Now delete from backend */
	if (storage->backend) {
		storage->backend->delete_func (storage->backend, key);
	}
	/* Notify expire */
	if (elt) {
		storage->expire->delete_func (storage->expire, elt);
		storage->elts --;
		storage->memory -= elt->size;
	}

	return elt;
}

/** Destroy kv storage */
void
rspamd_kv_storage_destroy (struct rspamd_kv_storage *storage)
{
	if (storage->cache && storage->cache->destroy_func) {
		storage->cache->destroy_func (storage->cache);
	}
	if (storage->backend && storage->backend->destroy_func) {
		storage->backend->destroy_func (storage->backend);
	}
	if (storage->expire && storage->expire->destroy_func) {
		storage->expire->destroy_func (storage->expire);
	}

	g_free (storage->name);
	g_slice_free1 (sizeof (struct rspamd_kv_storage), storage);
}

/** Insert array */
gboolean
rspamd_kv_storage_insert_array (struct rspamd_kv_storage *storage, gpointer key,
		guint elt_size, gpointer data, gsize len, gint flags, guint expire)
{
	struct rspamd_kv_element			*elt;
	guint								*es;
	gpointer 							 arr_data;

	/* Make temporary copy */
	arr_data = g_slice_alloc (len + sizeof (guint));
	es = arr_data;
	*es = elt_size;
	memcpy (arr_data, (gchar *)data + sizeof (guint), len);
	if (!rspamd_kv_storage_insert_internal (storage, key, arr_data, len + sizeof (guint),
			flags, expire, &elt)) {
		g_slice_free1 (len + sizeof (guint), arr_data);
		return FALSE;
	}
	/* Now set special data of element */
	elt->flags |= KV_ELT_ARRAY;
	g_slice_free1 (len + sizeof (guint), arr_data);
	/* Place to the backend */
	if (storage->backend) {
		return storage->backend->insert_func (storage->backend, key, elt);
	}

	return TRUE;
}

/** Set element inside array */
gboolean
rspamd_kv_storage_set_array (struct rspamd_kv_storage *storage, gpointer key,
		guint elt_num, gpointer data, gsize len, time_t now)
{
	struct rspamd_kv_element			*elt;
	guint								*es;
	gpointer							 target;

	elt = rspamd_kv_storage_lookup (storage, key, now);
	if (elt == NULL) {
		return FALSE;
	}

	if ((elt->flags & KV_ELT_ARRAY) == 0) {
		return FALSE;
	}
	/* Get element size */
	es = (guint *)elt->data;
	if (elt_num > (elt->size - sizeof (guint)) / (*es)) {
		/* Invalid index */
		return FALSE;
	}
	target = (gchar *)elt->data + sizeof (guint) + (*es) * elt_num;
	if (len != *es) {
		/* Invalid size */
		return FALSE;
	}
	memcpy (target, data, len);
	/* Place to the backend */
	if (storage->backend) {
		return storage->backend->replace_func (storage->backend, key, elt);
	}

	return TRUE;
}

/** Get element inside array */
gboolean
rspamd_kv_storage_get_array (struct rspamd_kv_storage *storage, gpointer key,
		guint elt_num, gpointer *data, gsize *len, time_t now)
{
	struct rspamd_kv_element			*elt;
	guint								*es;
	gpointer							 target;

	elt = rspamd_kv_storage_lookup (storage, key, now);
	if (elt == NULL) {
		return FALSE;
	}

	if ((elt->flags & KV_ELT_ARRAY) == 0) {
		return FALSE;
	}
	/* Get element size */
	es = (guint *)elt->data;
	if (elt_num > (elt->size - sizeof (guint)) / (*es)) {
		/* Invalid index */
		return FALSE;
	}
	target = elt->data + sizeof (guint) + (*es) * elt_num;

	*len = *es;
	*data = target;

	return TRUE;
}

/**
 * LRU expire functions
 */

struct rspamd_kv_lru_expire {
	expire_init init_func;						/*< this callback is called on kv storage initialization */
	expire_insert insert_func;					/*< this callback is called when element is inserted */
	expire_step step_func;						/*< this callback is used when cache is full */
	expire_delete delete_func;					/*< this callback is called when an element is deleted */
	expire_destroy destroy_func;				/*< this callback is used for destroying all elements inside expire */

	guint queues;
	TAILQ_HEAD (eltq, rspamd_kv_element) *heads;
	guint *heads_elts;
};

/**
 * Insert an element into expire queue
 */
static void
rspamd_lru_insert (struct rspamd_kv_expire *e, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_lru_expire			*expire = (struct rspamd_kv_lru_expire *)e;
	guint                                sel_head;

	/* Get a proper queue */
	sel_head = elt->hash % expire->queues;
	TAILQ_INSERT_HEAD (&expire->heads[sel_head], elt, entry);
	expire->heads_elts[sel_head] ++;
}
/**
 * Delete an element from expire queue
 */
static void
rspamd_lru_delete (struct rspamd_kv_expire *e, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_lru_expire			*expire = (struct rspamd_kv_lru_expire *)e;
	guint                                sel_head;

	/* Get a proper queue */
	sel_head = elt->hash % expire->queues;
	/* Unlink element */
	TAILQ_REMOVE (&expire->heads[sel_head], elt, entry);
	expire->heads_elts[sel_head] --;
}

/**
 * Expire elements
 */
static gboolean
rspamd_lru_expire_step (struct rspamd_kv_expire *e, struct rspamd_kv_storage *storage, time_t now)
{
	guint								 i;
	struct rspamd_kv_lru_expire			*expire = (struct rspamd_kv_lru_expire *)e;
	struct rspamd_kv_element            *elt, *oldest_elt, *temp;
	time_t                               min_diff = G_MAXLONG, diff;
	gboolean                             res = FALSE;

	for (i = 0; i < expire->queues; i ++) {
		elt = expire->heads[i].tqh_first;
		if (elt && (elt->flags & KV_ELT_PERSISTENT) == 0) {
			diff = elt->expire - (now - elt->age);
			if (diff > 0) {
				/* This element is not expired */
				if (diff < min_diff) {
					min_diff = diff;
					oldest_elt = elt;
				}
			}
			else {
				/* This element is already expired */
				rspamd_kv_storage_delete (storage, ELT_KEY (elt));
				res = TRUE;
				/* Check other elements in this queue */
				TAILQ_FOREACH_SAFE (elt, &expire->heads[i], entry, temp) {
					if ((elt->flags & KV_ELT_PERSISTENT) != 0 || elt->expire < (now - elt->age)) {
						break;
					}
					rspamd_kv_storage_delete (storage, ELT_KEY (elt));
				}
				break;
			}
		}
	}

	if (!res) {
		/* Oust the oldest element from cache */
		storage->cache->delete_func (storage->cache, ELT_KEY (oldest_elt));
		oldest_elt->flags |= KV_ELT_OUSTED;
		storage->memory -= oldest_elt->size + sizeof (*elt);
		storage->elts --;
		rspamd_lru_delete (e, oldest_elt);
	}

	return TRUE;
}

/**
 * Destroy LRU expire memory
 */
static void
rspamd_lru_destroy (struct rspamd_kv_expire *e)
{
	struct rspamd_kv_lru_expire			*expire = (struct rspamd_kv_lru_expire *)e;

	g_slice_free1 (sizeof (struct eltq) * expire->queues, expire->heads);
	g_slice_free1 (sizeof (guint) * expire->queues, expire->heads_elts);
	g_slice_free1 (sizeof (struct rspamd_kv_lru_expire), expire);
}

/**
 * Create new LRU cache
 */
struct rspamd_kv_expire*
rspamd_lru_expire_new (guint queues)
{
	struct rspamd_kv_lru_expire			*new;
	guint								 i;

	new = g_slice_alloc (sizeof (struct rspamd_kv_lru_expire));
	new->queues = queues;
	new->heads = g_slice_alloc (sizeof (struct eltq) * queues);
	new->heads_elts = g_slice_alloc0 (sizeof (guint) * queues);

	for (i = 0; i < queues; i ++) {
		TAILQ_INIT (&new->heads[i]);
	}

	/* Set callbacks */
	new->init_func = NULL;
	new->insert_func = rspamd_lru_insert;
	new->delete_func = rspamd_lru_delete;
	new->step_func = rspamd_lru_expire_step;
	new->destroy_func = rspamd_lru_destroy;

	return (struct rspamd_kv_expire *)new;
}

/*
 * KV cache hash table
 */
struct rspamd_kv_hash_cache {
	cache_init init_func;						/*< this callback is called on kv storage initialization */
	cache_insert insert_func;					/*< this callback is called when element is inserted */
	cache_replace replace_func;					/*< this callback is called when element is replace */
	cache_lookup lookup_func;					/*< this callback is used for lookup of element */
	cache_delete delete_func;					/*< this callback is called when an element is deleted */
	cache_destroy destroy_func;					/*< this callback is used for destroying all elements inside cache */
	GHashTable *hash;
};

/**
 * Insert an element inside cache
 */
static struct rspamd_kv_element*
rspamd_kv_hash_insert (struct rspamd_kv_cache *c, gpointer key, gpointer value, gsize len)
{
	struct rspamd_kv_element 			*elt;
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;
	guint								 keylen;

	if ((elt = g_hash_table_lookup (cache->hash, key)) == NULL) {
		keylen = strlen (key);
		elt = g_slice_alloc0 (sizeof (struct rspamd_kv_element) + len + keylen + 1);
		elt->age = time (NULL);
		elt->keylen = keylen;
		elt->size = len;
		elt->hash = rspamd_strcase_hash (key);
		memcpy (elt->data, key, keylen + 1);
		memcpy (ELT_DATA (elt), value, len);
		g_hash_table_insert (cache->hash, ELT_KEY (elt), elt);
	}

	return elt;
}

/**
 * Lookup an item inside hash
 */
static struct rspamd_kv_element*
rspamd_kv_hash_lookup (struct rspamd_kv_cache *c, gpointer key)
{
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;

	return g_hash_table_lookup (cache->hash, key);
}

/**
 * Replace an element inside cache
 */
static gboolean
rspamd_kv_hash_replace (struct rspamd_kv_cache *c, gpointer key, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;

	g_hash_table_replace (cache->hash, key, elt);

	return TRUE;
}

/**
 * Delete an element from cache
 */
static struct rspamd_kv_element *
rspamd_kv_hash_delete (struct rspamd_kv_cache *c, gpointer key)
{
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;
	struct rspamd_kv_element            *elt;

	elt = g_hash_table_lookup (cache->hash, key);
	if (elt) {
		g_hash_table_steal (cache->hash, key);
	}
	return elt;
}

/**
 * Destroy the whole cache
 */
static void
rspamd_kv_hash_destroy (struct rspamd_kv_cache *c)
{
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;

	g_hash_table_destroy (cache->hash);
	g_slice_free1 (sizeof (struct rspamd_kv_hash_cache), cache);
}

/**
 * Destroy kv_element structure
 */
static void
kv_elt_destroy_func (gpointer e)
{
	struct rspamd_kv_element 			*elt = e;
	g_slice_free1 (sizeof (struct rspamd_kv_element) + elt->size, elt);
}

/**
 * Create new hash kv cache
 */
struct rspamd_kv_cache*
rspamd_kv_hash_new (void)
{
	struct rspamd_kv_hash_cache			*new;

	new = g_slice_alloc (sizeof (struct rspamd_kv_hash_cache));
	new->hash = g_hash_table_new_full (rspamd_strcase_hash, rspamd_strcase_equal, NULL, NULL);
	new->init_func = NULL;
	new->insert_func = rspamd_kv_hash_insert;
	new->lookup_func = rspamd_kv_hash_lookup;
	new->replace_func = rspamd_kv_hash_replace;
	new->delete_func = rspamd_kv_hash_delete;
	new->destroy_func = rspamd_kv_hash_destroy;

	return (struct rspamd_kv_cache *)new;
}

/*
 * Radix cache hash table
 */
struct rspamd_kv_radix_cache {
	cache_init init_func;						/*< this callback is called on kv storage initialization */
	cache_insert insert_func;					/*< this callback is called when element is inserted */
	cache_replace replace_func;					/*< this callback is called when element is replace */
	cache_lookup lookup_func;					/*< this callback is used for lookup of element */
	cache_delete delete_func;					/*< this callback is called when an element is deleted */
	cache_destroy destroy_func;					/*< this callback is used for destroying all elements inside cache */
	radix_tree_t *tree;
};

/**
 * Validate a key for radix
 */
static guint32
rspamd_kv_radix_validate (gpointer key)
{
	struct in_addr				addr;

	if (inet_aton (key, &addr) == 0) {
		return 0;
	}

	return addr.s_addr;
}

/**
 * Insert an element inside cache
 */
static struct rspamd_kv_element*
rspamd_kv_radix_insert (struct rspamd_kv_cache *c, gpointer key, gpointer value, gsize len)
{
	struct rspamd_kv_element 			*elt;
	struct rspamd_kv_radix_cache		*cache = (struct rspamd_kv_radix_cache *)c;
	guint32								 rkey = rspamd_kv_radix_validate (key);
	guint								 keylen;

	if (rkey == 0) {
		return NULL;
	}
	elt = (struct rspamd_kv_element *)radix32tree_find (cache->tree, rkey);
	if ((uintptr_t)elt == RADIX_NO_VALUE) {
		keylen = strlen (key);
		elt = g_slice_alloc0 (sizeof (struct rspamd_kv_element) + len + keylen + 1);
		elt->age = time (NULL);
		elt->size = len;
		elt->hash = rkey;
		memcpy (elt->data, key, keylen + 1);
		memcpy (ELT_DATA (elt), value, len);
		radix32tree_insert (cache->tree, rkey, 0xffffffff, (uintptr_t)elt);
	}

	return elt;
}

/**
 * Lookup an item inside radix
 */
static struct rspamd_kv_element*
rspamd_kv_radix_lookup (struct rspamd_kv_cache *c, gpointer key)
{
	struct rspamd_kv_radix_cache		*cache = (struct rspamd_kv_radix_cache *)c;
	guint32								 rkey = rspamd_kv_radix_validate (key);
	struct rspamd_kv_element 			*elt;

	elt = (struct rspamd_kv_element *)radix32tree_find (cache->tree, rkey);
	if ((uintptr_t)elt == RADIX_NO_VALUE) {
		return NULL;
	}

	return elt;
}

/**
 * Replace an element inside cache
 */
static gboolean
rspamd_kv_radix_replace (struct rspamd_kv_cache *c, gpointer key, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_radix_cache		*cache = (struct rspamd_kv_radix_cache *)c;
	guint32								 rkey = rspamd_kv_radix_validate (key);

	radix32tree_replace (cache->tree, rkey, 0xffffffff, (uintptr_t)elt);

	return TRUE;
}

/**
 * Delete an element from cache
 */
static struct rspamd_kv_element *
rspamd_kv_radix_delete (struct rspamd_kv_cache *c, gpointer key)
{
	struct rspamd_kv_radix_cache		*cache = (struct rspamd_kv_radix_cache *)c;
	struct rspamd_kv_element            *elt;
	guint32								 rkey = rspamd_kv_radix_validate (key);

	elt = (struct rspamd_kv_element *)radix32tree_find (cache->tree, rkey);
	if ((uintptr_t)elt != RADIX_NO_VALUE) {
		radix32tree_delete (cache->tree, rkey, 0xffffffff);
	}
	else {
		return NULL;
	}
	return elt;
}

/**
 * Destroy the whole cache
 */
static void
rspamd_kv_radix_destroy (struct rspamd_kv_cache *c)
{
	struct rspamd_kv_radix_cache			*cache = (struct rspamd_kv_radix_cache *)c;

	radix_tree_free (cache->tree);
	g_slice_free1 (sizeof (struct rspamd_kv_radix_cache), cache);
}

/**
 * Create new radix kv cache
 */
struct rspamd_kv_cache*
rspamd_kv_radix_new (void)
{
	struct rspamd_kv_radix_cache			*new;

	new = g_slice_alloc (sizeof (struct rspamd_kv_radix_cache));
	new->tree = radix_tree_create ();
	new->init_func = NULL;
	new->insert_func = rspamd_kv_radix_insert;
	new->lookup_func = rspamd_kv_radix_lookup;
	new->replace_func = rspamd_kv_radix_replace;
	new->delete_func = rspamd_kv_radix_delete;
	new->destroy_func = rspamd_kv_radix_destroy;

	return (struct rspamd_kv_cache *)new;
}
