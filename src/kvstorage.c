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
#ifdef WITH_JUDY
#include <Judy.h>
#endif

#define MAX_EXPIRE_STEPS 10

/** Create new kv storage */
struct rspamd_kv_storage *
rspamd_kv_storage_new (gint id, const gchar *name, struct rspamd_kv_cache *cache, struct rspamd_kv_backend *backend, struct rspamd_kv_expire *expire,
		gsize max_elts, gsize max_memory, gboolean no_overwrite)
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

	new->no_overwrite = no_overwrite;

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
rspamd_kv_storage_insert_cache (struct rspamd_kv_storage *storage, gpointer key, guint keylen,
		gpointer data, gsize len, gint flags, guint expire, struct rspamd_kv_element **pelt)
{
	gint 								steps = 0;
	struct rspamd_kv_element		 	*elt;

	g_static_rw_lock_writer_lock (&storage->rwlock);
	/* Hard limit */
	if (storage->max_memory > 0) {
		if (len > storage->max_memory) {
			msg_info ("<%s>: trying to insert value of length %z while limit is %z", storage->name,
					len, storage->max_memory);
			g_static_rw_lock_writer_unlock (&storage->rwlock);
			return FALSE;
		}

		/* Now check limits */
		while (storage->memory + len > storage->max_memory) {
			if (storage->expire) {
				storage->expire->step_func (storage->expire, storage, time (NULL), steps);
			}
			else {
				msg_warn ("<%s>: storage is full and no expire function is defined", storage->name);
			}
			if (++steps > MAX_EXPIRE_STEPS) {
				g_static_rw_lock_writer_unlock (&storage->rwlock);
				msg_warn ("<%s>: cannot expire enough keys in storage", storage->name);
				return FALSE;
			}
		}
	}

	/* Insert elt to the cache */

	elt = storage->cache->insert_func (storage->cache, key, keylen, data, len);


	/* Copy data */
	elt->flags = flags;
	elt->expire = expire;

	if (pelt != NULL) {
		*pelt = elt;
	}

	/* Insert to the expire */
	if (storage->expire) {
		storage->expire->insert_func (storage->expire, elt);
	}

	storage->elts ++;
	storage->memory += ELT_SIZE (elt);
	g_static_rw_lock_writer_unlock (&storage->rwlock);

	return TRUE;
}

/** Insert new element to the kv storage */
gboolean
rspamd_kv_storage_insert (struct rspamd_kv_storage *storage, gpointer key, guint keylen,
		gpointer data, gsize len, gint flags, guint expire)
{
	gint 								steps = 0;
	struct rspamd_kv_element           *elt;
	gboolean							res = TRUE;
	glong								longval;

	/* Hard limit */
	g_static_rw_lock_writer_lock (&storage->rwlock);
	if (storage->max_memory > 0) {
		if (len + sizeof (struct rspamd_kv_element) + keylen >= storage->max_memory) {
			msg_warn ("<%s>: trying to insert value of length %z while limit is %z", storage->name,
					len, storage->max_memory);
			g_static_rw_lock_writer_unlock (&storage->rwlock);
			return FALSE;
		}

		/* Now check limits */
		while (storage->memory + len + keylen > storage->max_memory) {
			if (storage->expire) {
				storage->expire->step_func (storage->expire, storage, time (NULL), steps);
			}
			else {
				msg_warn ("<%s>: storage is full and no expire function is defined", storage->name);
			}
			if (++steps > MAX_EXPIRE_STEPS) {
				g_static_rw_lock_writer_unlock (&storage->rwlock);
				msg_warn ("<%s>: cannot expire enough keys in storage", storage->name);
				return FALSE;
			}
		}
	}
	if (storage->max_elts > 0 && storage->elts > storage->max_elts) {
		/* More expire */
		steps = 0;
		while (storage->elts > storage->max_elts) {
			if (storage->expire) {
				storage->expire->step_func (storage->expire, storage, time (NULL), steps);
			}
			else {
				msg_warn ("<%s>: storage is full and no expire function is defined", storage->name);
			}
			if (++steps > MAX_EXPIRE_STEPS) {
				g_static_rw_lock_writer_unlock (&storage->rwlock);
				msg_warn ("<%s>: cannot expire enough keys in storage", storage->name);
				return FALSE;
			}
		}
	}

	/* First try to search it in cache */

	elt = storage->cache->lookup_func (storage->cache, key, keylen);
	if (elt) {
		if (!storage->no_overwrite) {
			/* Remove old elt */
			if (storage->expire) {
				storage->expire->delete_func (storage->expire, elt);
			}
			storage->memory -= ELT_SIZE (elt);
			storage->cache->steal_func (storage->cache, elt);
			if (elt->flags & KV_ELT_DIRTY) {
				/* Element is in backend storage queue */
				elt->flags |= KV_ELT_NEED_FREE;
			}
			else {
				g_slice_free1 (ELT_SIZE (elt), elt);
			}
		}
		else {
			/* Just do incref and nothing more */
			if (storage->backend && storage->backend->incref_func) {
				if (storage->backend->incref_func (storage->backend, key, keylen)) {
					g_static_rw_lock_writer_unlock (&storage->rwlock);
					return TRUE;
				}
				else {
					g_static_rw_lock_writer_unlock (&storage->rwlock);
					return FALSE;
				}
			}
		}
	}

	/* Insert elt to the cache */

	/* First of all check element for integer */
	if (rspamd_strtol (data, len, &longval)) {
		elt = storage->cache->insert_func (storage->cache, key, keylen, &longval, sizeof (glong));
		if (elt == NULL) {
			return FALSE;
		}
		else {
			elt->flags |= KV_ELT_INTEGER;
		}
	}
	else {
		elt = storage->cache->insert_func (storage->cache, key, keylen, data, len);
		if (elt == NULL) {
			g_static_rw_lock_writer_unlock (&storage->rwlock);
			return FALSE;
		}
	}

	elt->flags |= flags;
	elt->expire = expire;
	if (expire == 0) {
		elt->flags |= KV_ELT_PERSISTENT;
	}

	/* Place to the backend */
	if (storage->backend) {
		res = storage->backend->insert_func (storage->backend, key, keylen, elt);
	}

	/* Insert to the expire */
	if (storage->expire) {
		storage->expire->insert_func (storage->expire, elt);
	}

	storage->elts ++;
	storage->memory += ELT_SIZE (elt);
	g_static_rw_lock_writer_unlock (&storage->rwlock);

	return res;
}

/** Replace an element in the kv storage */
gboolean
rspamd_kv_storage_replace (struct rspamd_kv_storage *storage, gpointer key, guint keylen, struct rspamd_kv_element *elt)
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
		while (storage->memory + ELT_SIZE (elt) > storage->max_memory) {
			if (storage->expire) {
				g_static_rw_lock_writer_lock (&storage->rwlock);
				storage->expire->step_func (storage->expire, storage, time (NULL), steps);
				g_static_rw_lock_writer_unlock (&storage->rwlock);
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

	g_static_rw_lock_writer_lock (&storage->rwlock);
	/* Insert elt to the cache */
	res = storage->cache->replace_func (storage->cache, key, keylen, elt);

	/* Place to the backend */
	if (res && storage->backend) {
		res = storage->backend->replace_func (storage->backend, key, keylen, elt);
	}
	g_static_rw_lock_writer_unlock (&storage->rwlock);

	return res;
}

/** Increment value in kvstorage */
gboolean
rspamd_kv_storage_increment (struct rspamd_kv_storage *storage, gpointer key, guint keylen, glong *value)
{
	struct rspamd_kv_element			*elt = NULL, *belt;
	glong								*lp;

	/* First try to look at cache */
	g_static_rw_lock_writer_lock (&storage->rwlock);
	elt = storage->cache->lookup_func (storage->cache, key, keylen);

	if (elt == NULL && storage->backend) {
		belt = storage->backend->lookup_func (storage->backend, key, keylen);
		if (belt) {
			/* Put this element into cache */
			if ((belt->flags & KV_ELT_INTEGER) != 0) {
				g_static_rw_lock_writer_unlock (&storage->rwlock);
				rspamd_kv_storage_insert_cache (storage, ELT_KEY (belt), keylen, ELT_DATA (belt),
					belt->size, belt->flags,
					belt->expire, &elt);
				g_static_rw_lock_writer_lock (&storage->rwlock);
			}
			if ((belt->flags & KV_ELT_DIRTY) == 0) {
				g_free (belt);
			}
		}
	}
	if (elt && (elt->flags & KV_ELT_INTEGER) != 0) {
		lp = &ELT_LONG (elt);
		/* Handle need expire here */
		if (elt->flags & KV_ELT_NEED_EXPIRE) {
			*lp = *value;
		}
		else {
			*lp += *value;
			*value = *lp;
		}
		elt->age = time (NULL);
		if (storage->backend) {
			if (storage->backend->replace_func (storage->backend, key, keylen, elt)) {
				g_static_rw_lock_writer_unlock (&storage->rwlock);
				return TRUE;
			}
			else {
				g_static_rw_lock_writer_unlock (&storage->rwlock);
				return FALSE;
			}
		}
		else {
			g_static_rw_lock_writer_unlock (&storage->rwlock);
			return TRUE;
		}
	}

	g_static_rw_lock_writer_unlock (&storage->rwlock);

	return FALSE;
}

/** Lookup an element inside kv storage */
struct rspamd_kv_element*
rspamd_kv_storage_lookup (struct rspamd_kv_storage *storage, gpointer key, guint keylen, time_t now)
{
	struct rspamd_kv_element			*elt = NULL, *belt;

	/* First try to look at cache */
	g_static_rw_lock_reader_lock (&storage->rwlock);
	elt = storage->cache->lookup_func (storage->cache, key, keylen);

	/* Next look at the backend */
	if (elt == NULL && storage->backend) {
		belt = storage->backend->lookup_func (storage->backend, key, keylen);

		if (belt) {
			/* Put this element into cache */
			if ((belt->flags & KV_ELT_DIRTY) == 0) {
				belt->flags |= KV_ELT_NEED_INSERT;
				return belt;
			}
			else {
				elt = belt;
			}
		}
	}

	if (elt && (elt->flags & KV_ELT_PERSISTENT) == 0 && elt->expire > 0) {
		/* Check expiration */
		if (now - elt->age > elt->expire) {
			/* Set need expire as we have no write lock here */
			elt->flags |= KV_ELT_NEED_EXPIRE;
			elt = NULL;
		}
	}

	/* RWlock is still locked */
	return elt;
}

/** Expire an element from kv storage */
struct rspamd_kv_element *
rspamd_kv_storage_delete (struct rspamd_kv_storage *storage, gpointer key, guint keylen)
{
	struct rspamd_kv_element           *elt;

	/* First delete key from cache */
	g_static_rw_lock_writer_lock (&storage->rwlock);
	elt = storage->cache->delete_func (storage->cache, key, keylen);

	/* Now delete from backend */
	if (storage->backend) {
		storage->backend->delete_func (storage->backend, key, keylen);
	}
	/* Notify expire */
	if (elt) {
		if (storage->expire) {
			storage->expire->delete_func (storage->expire, elt);
		}
		storage->elts --;
		storage->memory -= elt->size;
		if ((elt->flags & KV_ELT_DIRTY) != 0) {
			elt->flags |= KV_ELT_NEED_FREE;
		}
		else {
			g_slice_free1 (ELT_SIZE (elt), elt);
		}
	}

	g_static_rw_lock_writer_unlock (&storage->rwlock);

	return elt;
}

/** Destroy kv storage */
void
rspamd_kv_storage_destroy (struct rspamd_kv_storage *storage)
{
	g_static_rw_lock_writer_lock (&storage->rwlock);
	if (storage->backend && storage->backend->destroy_func) {
		storage->backend->destroy_func (storage->backend);
	}
	if (storage->expire && storage->expire->destroy_func) {
		storage->expire->destroy_func (storage->expire);
	}
	if (storage->cache && storage->cache->destroy_func) {
		storage->cache->destroy_func (storage->cache);
	}

	g_free (storage->name);

	g_static_rw_lock_writer_unlock (&storage->rwlock);
	g_slice_free1 (sizeof (struct rspamd_kv_storage), storage);
}

/** Insert array */
gboolean
rspamd_kv_storage_insert_array (struct rspamd_kv_storage *storage, gpointer key, guint keylen,
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
	if (!rspamd_kv_storage_insert_cache (storage, key, keylen, arr_data, len + sizeof (guint),
			flags, expire, &elt)) {
		g_slice_free1 (len + sizeof (guint), arr_data);
		return FALSE;
	}
	/* Now set special data of element */
	elt->flags |= KV_ELT_ARRAY;
	g_slice_free1 (len + sizeof (guint), arr_data);
	/* Place to the backend */

	if (storage->backend) {
		return storage->backend->insert_func (storage->backend, key, keylen, elt);
	}

	return TRUE;
}

/** Set element inside array */
gboolean
rspamd_kv_storage_set_array (struct rspamd_kv_storage *storage, gpointer key, guint keylen,
		guint elt_num, gpointer data, gsize len, time_t now)
{
	struct rspamd_kv_element			*elt;
	guint								*es;
	gpointer							 target;

	elt = rspamd_kv_storage_lookup (storage, key, keylen, now);
	if (elt == NULL) {
		return FALSE;
	}

	if ((elt->flags & KV_ELT_ARRAY) == 0) {
		return FALSE;
	}
	/* Get element size */
	es = (guint *)ELT_DATA (elt);
	if (elt_num > (elt->size - sizeof (guint)) / (*es)) {
		/* Invalid index */
		return FALSE;
	}
	target = (gchar *)ELT_DATA (elt) + sizeof (guint) + (*es) * elt_num;
	if (len != *es) {
		/* Invalid size */
		return FALSE;
	}
	memcpy (target, data, len);
	/* Place to the backend */
	if (storage->backend) {
		return storage->backend->replace_func (storage->backend, key, keylen, elt);
	}

	return TRUE;
}

/** Get element inside array */
gboolean
rspamd_kv_storage_get_array (struct rspamd_kv_storage *storage, gpointer key, guint keylen,
		guint elt_num, gpointer *data, gsize *len, time_t now)
{
	struct rspamd_kv_element			*elt;
	guint								*es;
	gpointer							 target;

	elt = rspamd_kv_storage_lookup (storage, key, keylen, now);
	if (elt == NULL) {
		return FALSE;
	}

	if ((elt->flags & KV_ELT_ARRAY) == 0) {
		return FALSE;
	}
	/* Get element size */
	es = (guint *)ELT_DATA (elt);
	if (elt_num > (elt->size - sizeof (guint)) / (*es)) {
		/* Invalid index */
		return FALSE;
	}
	target = ELT_DATA (elt) + sizeof (guint) + (*es) * elt_num;

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

	TAILQ_HEAD (eltq, rspamd_kv_element) head;
};

/**
 * Insert an element into expire queue
 */
static void
rspamd_lru_insert (struct rspamd_kv_expire *e, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_lru_expire			*expire = (struct rspamd_kv_lru_expire *)e;

	/* Get a proper queue */
	TAILQ_INSERT_TAIL (&expire->head, elt, entry);
}
/**
 * Delete an element from expire queue
 */
static void
rspamd_lru_delete (struct rspamd_kv_expire *e, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_lru_expire			*expire = (struct rspamd_kv_lru_expire *)e;

	/* Unlink element */
	TAILQ_REMOVE (&expire->head, elt, entry);
}

/**
 * Expire elements
 */
static gboolean
rspamd_lru_expire_step (struct rspamd_kv_expire *e, struct rspamd_kv_storage *storage, time_t now, gboolean forced)
{
	struct rspamd_kv_lru_expire			*expire = (struct rspamd_kv_lru_expire *)e;
	struct rspamd_kv_element            *elt, *oldest_elt = NULL, *temp;
	time_t                               diff;
	gboolean                             res = FALSE;

	elt = TAILQ_FIRST (&expire->head);
	if (elt && (forced || (elt->flags & (KV_ELT_PERSISTENT|KV_ELT_DIRTY)) == 0)) {
		diff = elt->expire - (now - elt->age);
		if (diff > 0 || (forced && elt->expire == 0)) {
			oldest_elt = elt;
		}
		else {
			/* This element is already expired */
			storage->cache->steal_func (storage->cache, elt);
			storage->memory -= ELT_SIZE (elt);
			storage->elts --;
			TAILQ_REMOVE (&expire->head, elt, entry);
			/* Free memory */
			if ((elt->flags & (KV_ELT_DIRTY|KV_ELT_NEED_INSERT)) != 0) {
				elt->flags |= KV_ELT_NEED_FREE;
			}
			else {
				g_slice_free1 (ELT_SIZE (elt), elt);
			}
			res = TRUE;
			/* Check other elements in this queue */
			TAILQ_FOREACH_SAFE (elt, &expire->head, entry, temp) {
				if ((!forced &&
					(elt->flags & (KV_ELT_PERSISTENT|KV_ELT_DIRTY)) != 0) || elt->expire < (now - elt->age)) {
					break;
				}
				storage->memory -= ELT_SIZE (elt);
				storage->elts --;
				storage->cache->steal_func (storage->cache, elt);
				TAILQ_REMOVE (&expire->head, elt, entry);
				/* Free memory */
				if ((elt->flags & (KV_ELT_DIRTY|KV_ELT_NEED_INSERT)) != 0) {
					elt->flags |= KV_ELT_NEED_FREE;
				}
				else {
					g_slice_free1 (ELT_SIZE (elt), elt);
				}

			}
		}
	}

	if (!res && oldest_elt != NULL) {
		storage->memory -= ELT_SIZE (oldest_elt);
		storage->elts --;
		storage->cache->steal_func (storage->cache, oldest_elt);
		TAILQ_REMOVE (&expire->head, oldest_elt, entry);
		/* Free memory */
		if ((oldest_elt->flags & (KV_ELT_DIRTY|KV_ELT_NEED_INSERT)) != 0) {
			oldest_elt->flags |= KV_ELT_NEED_FREE;
		}
		else {
			g_slice_free1 (ELT_SIZE (oldest_elt), oldest_elt);
		}
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

	g_slice_free1 (sizeof (struct rspamd_kv_lru_expire), expire);
}

/**
 * Create new LRU cache
 */
struct rspamd_kv_expire*
rspamd_lru_expire_new ()
{
	struct rspamd_kv_lru_expire			*new;

	new = g_slice_alloc (sizeof (struct rspamd_kv_lru_expire));
	TAILQ_INIT (&new->head);

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
	cache_steal steal_func;						/*< this callback is used to replace duplicates in cache */
	cache_destroy destroy_func;					/*< this callback is used for destroying all elements inside cache */
	GHashTable *hash;
};

/**
 * Insert an element inside cache
 */
static struct rspamd_kv_element*
rspamd_kv_hash_insert (struct rspamd_kv_cache *c, gpointer key, guint keylen, gpointer value, gsize len)
{
	struct rspamd_kv_element 			*elt;
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;
	struct rspamd_kv_element			 search_elt;

	search_elt.keylen = keylen;
	search_elt.p = key;

	if ((elt = g_hash_table_lookup (cache->hash, &search_elt)) == NULL) {
		elt = g_slice_alloc (sizeof (struct rspamd_kv_element) + len + keylen + 1);
		elt->age = time (NULL);
		elt->keylen = keylen;
		elt->size = len;
		elt->flags = 0;
		memcpy (ELT_KEY (elt), key, keylen + 1);
		memcpy (ELT_DATA (elt), value, len);
		elt->p = &elt->data;
		g_hash_table_insert (cache->hash, elt, elt);
	}
	else {
		g_hash_table_steal (cache->hash, elt);
		if ((elt->flags & KV_ELT_DIRTY) != 0) {
			elt->flags |= KV_ELT_NEED_FREE;
		}
		else {
			/* Free it by self */
			g_slice_free1 (ELT_SIZE (elt), elt);
		}
		elt = g_slice_alloc (sizeof (struct rspamd_kv_element) + len + keylen + 1);
		elt->age = time (NULL);
		elt->keylen = keylen;
		elt->size = len;
		elt->flags = 0;
		memcpy (ELT_KEY (elt), key, keylen + 1);
		memcpy (ELT_DATA (elt), value, len);
		elt->p = &elt->data;
		g_hash_table_insert (cache->hash, elt, elt);
	}

	return elt;
}

/**
 * Lookup an item inside hash
 */
static struct rspamd_kv_element*
rspamd_kv_hash_lookup (struct rspamd_kv_cache *c, gpointer key, guint keylen)
{
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;
	struct rspamd_kv_element			 search_elt;

	search_elt.keylen = keylen;
	search_elt.p = key;

	return g_hash_table_lookup (cache->hash, &search_elt);
}

/**
 * Replace an element inside cache
 */
static gboolean
rspamd_kv_hash_replace (struct rspamd_kv_cache *c, gpointer key, guint keylen, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;
	struct rspamd_kv_element 			*oldelt, search_elt;

	search_elt.keylen = keylen;
	search_elt.p = key;

	if ((oldelt = g_hash_table_lookup (cache->hash, &search_elt)) != NULL) {
		g_hash_table_steal (cache->hash, oldelt);

		if ((oldelt->flags & KV_ELT_DIRTY) != 0) {
			oldelt->flags |= KV_ELT_NEED_FREE;
		}
		else {
			/* Free it by self */
			g_slice_free1 (ELT_SIZE (oldelt), oldelt);
		}
		g_hash_table_insert (cache->hash, elt, elt);
		return TRUE;
	}

	return FALSE;
}

/**
 * Delete an element from cache
 */
static struct rspamd_kv_element *
rspamd_kv_hash_delete (struct rspamd_kv_cache *c, gpointer key, guint keylen)
{
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;
	struct rspamd_kv_element            *elt;
	struct rspamd_kv_element			 search_elt;

	search_elt.keylen = keylen;
	search_elt.p = key;

	elt = g_hash_table_lookup (cache->hash, &search_elt);
	if (elt) {
		g_hash_table_steal (cache->hash, &search_elt);
	}
	return elt;
}

/**
 * Steal an element from cache
 */
static void
rspamd_kv_hash_steal (struct rspamd_kv_cache *c, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;

	g_hash_table_steal (cache->hash, elt);
}

/**
 * Destroy the whole cache
 */

static void
rspamd_kv_hash_destroy_cb (gpointer key, gpointer value, gpointer unused)
{
	struct rspamd_kv_element 			*elt = value;

	g_slice_free1 (ELT_SIZE (elt), elt);
}

static void
rspamd_kv_hash_destroy (struct rspamd_kv_cache *c)
{
	struct rspamd_kv_hash_cache			*cache = (struct rspamd_kv_hash_cache *)c;

	g_hash_table_foreach (cache->hash, rspamd_kv_hash_destroy_cb, NULL);
	g_hash_table_destroy (cache->hash);
	g_slice_free1 (sizeof (struct rspamd_kv_hash_cache), cache);
}

/**
 * Make hash for element
 */
#define rot(x,k) (((x)<<(k)) ^ ((x)>>(32-(k))))
#define mix(a,b,c) \
{ \
  a -= c;  a ^= rot(c, 4);  c += b; \
  b -= a;  b ^= rot(a, 6);  a += c; \
  c -= b;  c ^= rot(b, 8);  b += a; \
  a -= c;  a ^= rot(c,16);  c += b; \
  b -= a;  b ^= rot(a,19);  a += c; \
  c -= b;  c ^= rot(b, 4);  b += a; \
}
#define final(a,b,c) \
{ \
  c ^= b; c -= rot(b,14); \
  a ^= c; a -= rot(c,11); \
  b ^= a; b -= rot(a,25); \
  c ^= b; c -= rot(b,16); \
  a ^= c; a -= rot(c,4);  \
  b ^= a; b -= rot(a,14); \
  c ^= b; c -= rot(b,24); \
}
/*
 *    The hash function used here is by Bob Jenkins, 1996:
 *    <http://burtleburtle.net/bob/hash/doobs.html>
 *       "By Bob Jenkins, 1996.  bob_jenkins@burtleburtle.net.
 *       You may use this code any way you wish, private, educational,
 *       or commercial.  It's free."
 *
 */
guint
kv_elt_hash_func (gconstpointer e)
{
	struct rspamd_kv_element 			*elt = (struct rspamd_kv_element *)e;
	guint32 							 a, b, c;
	union { const void *ptr; size_t i; } u;
	guint								 length;

	/* Set up the internal state */
	length = elt->keylen;
	a = b = c = 0xdeadbeef + length;

	u.ptr = elt->p;
	if (((u.i & 0x3) == 0)) {
		const guint32 *k = (const guint32 *)elt->p; /* read 32-bit chunks */

		/*------ all but last block: aligned reads and affect 32 bits of (a,b,c) */
		while (length > 12) {
			a += k[0];
			b += k[1];
			c += k[2];
			mix (a,b,c);
			length -= 12;
			k += 3;
		}

		/*----------------------------- handle the last (probably partial) block */
		/*
		 * "k[2]&0xffffff" actually reads beyond the end of the string, but
		 * then masks off the part it's not allowed to read.  Because the
		 * string is aligned, the masked-off tail is in the same word as the
		 * rest of the string.  Every machine with memory protection I've seen
		 * does it on word boundaries, so is OK with this.  But VALGRIND will
		 * still catch it and complain.  The masking trick does make the hash
		 * noticably faster for short strings (like English words).
		 */
		switch (length)
		{
		case 12: c+=k[2]; b+=k[1]; a+=k[0]; break;
		case 11: c+=k[2]&0xffffff; b+=k[1]; a+=k[0]; break;
		case 10: c+=k[2]&0xffff; b+=k[1]; a+=k[0]; break;
		case 9 : c+=k[2]&0xff; b+=k[1]; a+=k[0]; break;
		case 8 : b+=k[1]; a+=k[0]; break;
		case 7 : b+=k[1]&0xffffff; a+=k[0]; break;
		case 6 : b+=k[1]&0xffff; a+=k[0]; break;
		case 5 : b+=k[1]&0xff; a+=k[0]; break;
		case 4 : a+=k[0]; break;
		case 3 : a+=k[0]&0xffffff; break;
		case 2 : a+=k[0]&0xffff; break;
		case 1 : a+=k[0]&0xff; break;
		case 0 : return c;  /* zero length strings require no mixing */
		}

	} else if (((u.i & 0x1) == 0)) {
		const guint16 *k = (const guint16 *)elt->p;                           /* read 16-bit chunks */
		const guint8  *k8;

		/*--------------- all but last block: aligned reads and different mixing */
		while (length > 12) {
			a += k[0] + (((guint32)k[1])<<16);
			b += k[2] + (((guint32)k[3])<<16);
			c += k[4] + (((guint32)k[5])<<16);
			mix (a,b,c);
			length -= 12;
			k += 6;
		}

		/*----------------------------- handle the last (probably partial) block */
		k8 = (const guint8 *)k;
		switch (length)
		{
		case 12: c+=k[4]+(((guint32)k[5])<<16);
		b+=k[2]+(((guint32)k[3])<<16);
		a+=k[0]+(((guint32)k[1])<<16);
		break;
		case 11: c+=((guint32)k8[10])<<16;     /* @fallthrough */
		case 10: c+=k[4];                       /* @fallthrough@ */
		b+=k[2]+(((guint32)k[3])<<16);
		a+=k[0]+(((guint32)k[1])<<16);
		break;
		case 9 : c+=k8[8];                      /* @fallthrough */
		case 8 : b+=k[2]+(((guint32)k[3])<<16);
		a+=k[0]+(((guint32)k[1])<<16);
		break;
		case 7 : b+=((guint32)k8[6])<<16;      /* @fallthrough */
		case 6 : b+=k[2];
		a+=k[0]+(((guint32)k[1])<<16);
		break;
		case 5 : b+=k8[4];                      /* @fallthrough */
		case 4 : a+=k[0]+(((guint32)k[1])<<16);
		break;
		case 3 : a+=((guint32)k8[2])<<16;      /* @fallthrough */
		case 2 : a+=k[0];
		break;
		case 1 : a+=k8[0];
		break;
		case 0 : return c;  /* zero length strings require no mixing */
		}

	} else {                        /* need to read the key one byte at a time */
		const guint8 *k = elt->p;

		/*--------------- all but the last block: affect some 32 bits of (a,b,c) */
		while (length > 12)
		{
			a += k[0];
			a += ((guint32)k[1])<<8;
			a += ((guint32)k[2])<<16;
			a += ((guint32)k[3])<<24;
			b += k[4];
			b += ((guint32)k[5])<<8;
			b += ((guint32)k[6])<<16;
			b += ((guint32)k[7])<<24;
			c += k[8];
			c += ((guint32)k[9])<<8;
			c += ((guint32)k[10])<<16;
			c += ((guint32)k[11])<<24;
			mix(a,b,c);
			length -= 12;
			k += 12;
		}

		/*-------------------------------- last block: affect all 32 bits of (c) */
		switch (length)                   /* all the case statements fall through */
		{
		case 12: c+=((guint32)k[11])<<24;
		case 11: c+=((guint32)k[10])<<16;
		case 10: c+=((guint32)k[9])<<8;
		case 9 : c+=k[8];
		case 8 : b+=((guint32)k[7])<<24;
		case 7 : b+=((guint32)k[6])<<16;
		case 6 : b+=((guint32)k[5])<<8;
		case 5 : b+=k[4];
		case 4 : a+=((guint32)k[3])<<24;
		case 3 : a+=((guint32)k[2])<<16;
		case 2 : a+=((guint32)k[1])<<8;
		case 1 : a+=k[0];
		break;
		case 0 : return c;  /* zero length strings require no mixing */
		}
	}

	final (a,b,c);
	return c;             /* zero length strings require no mixing */
}

gboolean
kv_elt_compare_func (gconstpointer e1, gconstpointer e2)
{
	struct rspamd_kv_element 			*elt1 = (struct rspamd_kv_element *) e1,
										*elt2 = (struct rspamd_kv_element *) e2;

	if (elt1->keylen == elt2->keylen) {
		return memcmp (elt1->p, elt2->p, elt1->keylen) == 0;
	}

	return FALSE;
}

/**
 * Create new hash kv cache
 */
struct rspamd_kv_cache*
rspamd_kv_hash_new (void)
{
	struct rspamd_kv_hash_cache			*new;

	new = g_slice_alloc (sizeof (struct rspamd_kv_hash_cache));
	new->hash = g_hash_table_new_full (kv_elt_hash_func, kv_elt_compare_func, NULL, NULL);
	new->init_func = NULL;
	new->insert_func = rspamd_kv_hash_insert;
	new->lookup_func = rspamd_kv_hash_lookup;
	new->replace_func = rspamd_kv_hash_replace;
	new->delete_func = rspamd_kv_hash_delete;
	new->steal_func = rspamd_kv_hash_steal;
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
	cache_steal steal_func;						/*< this callback is used to replace duplicates in cache */
	cache_destroy destroy_func;					/*< this callback is used for destroying all elements inside cache */
	radix_tree_t *tree;
};

/**
 * Validate a key for radix
 */
static guint32
rspamd_kv_radix_validate (gpointer key, guint keylen)
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
rspamd_kv_radix_insert (struct rspamd_kv_cache *c, gpointer key, guint keylen, gpointer value, gsize len)
{
	struct rspamd_kv_element 			*elt;
	struct rspamd_kv_radix_cache		*cache = (struct rspamd_kv_radix_cache *)c;
	guint32								 rkey = rspamd_kv_radix_validate (key, keylen);

	if (rkey == 0) {
		return NULL;
	}

	elt = (struct rspamd_kv_element *)radix32tree_find (cache->tree, rkey);
	if ((uintptr_t)elt == RADIX_NO_VALUE) {
		elt = g_slice_alloc (sizeof (struct rspamd_kv_element) + len + keylen + 1);
		elt->age = time (NULL);
		elt->keylen = keylen;
		elt->size = len;
		elt->flags = 0;
		memcpy (ELT_KEY (elt), key, keylen + 1);
		memcpy (ELT_DATA (elt), value, len);
		elt->p = &elt->data;
		radix32tree_insert (cache->tree, rkey, 0xffffffff, (uintptr_t)elt);
	}
	else {
		radix32tree_delete (cache->tree, rkey, 0xffffffff);
		if ((elt->flags & KV_ELT_DIRTY) != 0) {
			elt->flags |= KV_ELT_NEED_FREE;
		}
		else {
			/* Free it by self */
			g_slice_free1 (ELT_SIZE (elt), elt);
		}
		elt = g_slice_alloc (sizeof (struct rspamd_kv_element) + len + keylen + 1);
		elt->age = time (NULL);
		elt->keylen = keylen;
		elt->size = len;
		elt->flags = 0;
		memcpy (ELT_KEY (elt), key, keylen + 1);
		memcpy (ELT_DATA (elt), value, len);
		elt->p = &elt->data;
		radix32tree_insert (cache->tree, rkey, 0xffffffff, (uintptr_t)elt);
	}

	return elt;
}

/**
 * Lookup an item inside radix
 */
static struct rspamd_kv_element*
rspamd_kv_radix_lookup (struct rspamd_kv_cache *c, gpointer key, guint keylen)
{
	struct rspamd_kv_radix_cache		*cache = (struct rspamd_kv_radix_cache *)c;
	guint32								 rkey = rspamd_kv_radix_validate (key, keylen);
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
rspamd_kv_radix_replace (struct rspamd_kv_cache *c, gpointer key, guint keylen, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_radix_cache		*cache = (struct rspamd_kv_radix_cache *)c;
	guint32								 rkey = rspamd_kv_radix_validate (key, keylen);
	struct rspamd_kv_element 			*oldelt;

	oldelt = (struct rspamd_kv_element *)radix32tree_find (cache->tree, rkey);
	if ((uintptr_t)oldelt != RADIX_NO_VALUE) {
		radix32tree_delete (cache->tree, rkey, 0xffffffff);

		if ((oldelt->flags & KV_ELT_DIRTY) != 0) {
			oldelt->flags |= KV_ELT_NEED_FREE;
		}
		else {
			/* Free it by self */
			g_slice_free1 (ELT_SIZE (oldelt), oldelt);
		}
		radix32tree_insert (cache->tree, rkey, 0xffffffff, (uintptr_t)elt);
		return TRUE;
	}

	return FALSE;
}

/**
 * Delete an element from cache
 */
static struct rspamd_kv_element *
rspamd_kv_radix_delete (struct rspamd_kv_cache *c, gpointer key, guint keylen)
{
	struct rspamd_kv_radix_cache		*cache = (struct rspamd_kv_radix_cache *)c;
	struct rspamd_kv_element            *elt;
	guint32								 rkey = rspamd_kv_radix_validate (key, keylen);

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
 * Delete an element from cache
 */
static void
rspamd_kv_radix_steal (struct rspamd_kv_cache *c, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_radix_cache		*cache = (struct rspamd_kv_radix_cache *)c;
	guint32								 rkey = rspamd_kv_radix_validate (ELT_KEY (elt), elt->keylen);


	radix32tree_delete (cache->tree, rkey, 0xffffffff);
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
	new->steal_func = rspamd_kv_radix_steal;
	new->destroy_func = rspamd_kv_radix_destroy;

	return (struct rspamd_kv_cache *)new;
}


#ifdef WITH_JUDY
/*
 * KV cache hash table
 */
struct rspamd_kv_judy_cache {
	cache_init init_func;						/*< this callback is called on kv storage initialization */
	cache_insert insert_func;					/*< this callback is called when element is inserted */
	cache_replace replace_func;					/*< this callback is called when element is replace */
	cache_lookup lookup_func;					/*< this callback is used for lookup of element */
	cache_delete delete_func;					/*< this callback is called when an element is deleted */
	cache_steal steal_func;						/*< this callback is used to replace duplicates in cache */
	cache_destroy destroy_func;					/*< this callback is used for destroying all elements inside cache */
	Pvoid_t judy;
};


/**
 * Lookup an item inside judy
 */
static struct rspamd_kv_element*
rspamd_kv_judy_lookup (struct rspamd_kv_cache *c, gpointer key, guint keylen)
{
	struct rspamd_kv_judy_cache			*cache = (struct rspamd_kv_judy_cache *)c;
	struct rspamd_kv_element			*elt = NULL, **pelt;

	JHSG (pelt, cache->judy, key, keylen);
	if (pelt != NULL) {
		elt = *pelt;
	}
	return elt;
}

/**
 * Delete an element from cache
 */
static struct rspamd_kv_element *
rspamd_kv_judy_delete (struct rspamd_kv_cache *c, gpointer key, guint keylen)
{
	struct rspamd_kv_judy_cache			*cache = (struct rspamd_kv_judy_cache *)c;
	struct rspamd_kv_element            *elt;
	gint								 rc;

	elt = rspamd_kv_judy_lookup (c, key, keylen);
	if (elt) {
		JHSD (rc, cache->judy, ELT_KEY (elt), elt->keylen);
	}
	return elt;
}

/**
 * Steal an element from cache
 */
static void
rspamd_kv_judy_steal (struct rspamd_kv_cache *c, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_judy_cache			*cache = (struct rspamd_kv_judy_cache *)c;
	gint								 rc;

	JHSD (rc, cache->judy, ELT_KEY (elt), elt->keylen);
}

/**
 * Insert an element inside cache
 */
static struct rspamd_kv_element*
rspamd_kv_judy_insert (struct rspamd_kv_cache *c, gpointer key, guint keylen, gpointer value, gsize len)
{
	struct rspamd_kv_element 			*elt, **pelt;
	struct rspamd_kv_judy_cache			*cache = (struct rspamd_kv_judy_cache *)c;

	if ((elt = rspamd_kv_judy_lookup (c, key, keylen)) == NULL) {
		elt = g_slice_alloc (sizeof (struct rspamd_kv_element) + len + keylen + 1);
		elt->age = time (NULL);
		elt->keylen = keylen;
		elt->size = len;
		elt->flags = 0;
		memcpy (ELT_KEY (elt), key, keylen);
		memcpy (ELT_DATA (elt), value, len);
		JHSI (pelt, cache->judy, ELT_KEY (elt), elt->keylen);
		elt->p = &elt->data;
		*pelt = elt;
	}
	else {
		rspamd_kv_judy_steal (c, elt);
		if ((elt->flags & KV_ELT_DIRTY) != 0) {
			elt->flags |= KV_ELT_NEED_FREE;
		}
		else {
			/* Free it by self */
			g_slice_free1 (ELT_SIZE (elt), elt);
		}
		elt = g_slice_alloc0 (sizeof (struct rspamd_kv_element) + len + keylen + 1);
		elt->age = time (NULL);
		elt->keylen = keylen;
		elt->size = len;
		elt->flags = 0;
		memcpy (ELT_KEY (elt), key, keylen);
		memcpy (ELT_DATA (elt), value, len);
		elt->p = &elt->data;
		JHSI (pelt, cache->judy, ELT_KEY (elt), elt->keylen);
		*pelt = elt;
	}

	return elt;
}

/**
 * Replace an element inside cache
 */
static gboolean
rspamd_kv_judy_replace (struct rspamd_kv_cache *c, gpointer key, guint keylen, struct rspamd_kv_element *elt)
{
	struct rspamd_kv_judy_cache			*cache = (struct rspamd_kv_judy_cache *)c;
	struct rspamd_kv_element 			*oldelt, **pelt;

	if ((oldelt = rspamd_kv_judy_lookup (c, key, keylen)) != NULL) {
		rspamd_kv_judy_steal (c, elt);

		if ((oldelt->flags & KV_ELT_DIRTY) != 0) {
			oldelt->flags |= KV_ELT_NEED_FREE;
		}
		else {
			/* Free it by self */
			g_slice_free1 (ELT_SIZE (oldelt), oldelt);
		}
		JHSI (pelt, cache->judy, ELT_KEY (elt), elt->keylen);
		*pelt = elt;
		return TRUE;
	}

	return FALSE;
}

/**
 * Destroy the whole cache
 */
static void
rspamd_kv_judy_destroy (struct rspamd_kv_cache *c)
{
	struct rspamd_kv_judy_cache			*cache = (struct rspamd_kv_judy_cache *)c;
	glong								 bytes;

	JHSFA (bytes, cache->judy);
	g_slice_free1 (sizeof (struct rspamd_kv_judy_cache), cache);
}

/**
 * Judy tree
 */
struct rspamd_kv_cache*
rspamd_kv_judy_new (void)
{
	struct rspamd_kv_judy_cache			*new;

	new = g_slice_alloc (sizeof (struct rspamd_kv_judy_cache));
	new->judy = NULL;
	new->init_func = NULL;
	new->insert_func = rspamd_kv_judy_insert;
	new->lookup_func = rspamd_kv_judy_lookup;
	new->replace_func = rspamd_kv_judy_replace;
	new->delete_func = rspamd_kv_judy_delete;
	new->steal_func = rspamd_kv_judy_steal;
	new->destroy_func = rspamd_kv_judy_destroy;

	return (struct rspamd_kv_cache *)new;
}
#endif
