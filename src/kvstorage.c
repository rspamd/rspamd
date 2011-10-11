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

	return new;
}

/** Insert new element to the kv storage */
gboolean
rspamd_kv_storage_insert (struct rspamd_kv_storage *storage, gpointer key, gpointer data, gsize len, gint flags)
{
	gint 								steps = 0;
	struct rspamd_kv_element           *elt;
	gboolean							res = TRUE;

	/* Hard limit */
	if (len > storage->max_memory) {
		msg_info ("<%s>: trying to insert value of length %z while limit is %z", len, storage->max_memory);
		return FALSE;
	}

	/* Now check limits */
	while (storage->memory + len > storage->max_memory || storage->elts >= storage->max_elts) {
		if (storage->expire) {
			storage->expire->step_func (storage->expire, storage);
		}
		else {
			msg_warn ("<%s>: storage %s is full and no expire function is defined", storage->name);
		}
		if (++steps > MAX_EXPIRE_STEPS) {
			msg_warn ("<%s>: cannot expire enough keys in storage", storage->name);
			return FALSE;
		}
	}

	/* Insert elt to the cache */
	elt = storage->cache->insert_func (storage->cache, key, data, len);
	if (elt == NULL) {
		return FALSE;
	}
	elt->flags = flags;

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
	if (elt->size > storage->max_memory) {
		msg_info ("<%s>: trying to replace value of length %z while limit is %z", elt->size, storage->max_memory);
		return FALSE;
	}

	/* Now check limits */
	while (storage->memory + elt->size > storage->max_memory) {
		if (storage->expire) {
			storage->expire->step_func (storage->expire, storage);
		}
		else {
			msg_warn ("<%s>: storage %s is full and no expire function is defined", storage->name);
		}
		if (++steps > MAX_EXPIRE_STEPS) {
			msg_warn ("<%s>: cannot expire enough keys in storage", storage->name);
			return FALSE;
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
rspamd_kv_storage_lookup (struct rspamd_kv_storage *storage, gpointer key)
{
	struct rspamd_kv_element			*elt = NULL;

	/* First try to look at cache */
	elt = storage->cache->lookup_func (storage->cache, key);

	/* Next look at the backend */
	if (storage->backend) {
		elt = storage->backend->lookup_func (storage->backend, key);
	}

	return elt;
}

/** Expire an element from kv storage */
gboolean
rspamd_kv_storage_delete (struct rspamd_kv_storage *storage, gpointer key)
{
	gboolean							res = TRUE;

	/* First delete key from cache */
	res = storage->cache->delete_func (storage->cache, key);

	/* Now delete from backend */
	if (storage->backend) {
		res = storage->backend->delete_func (storage->backend, key);
	}
	/* Notify expire */
	/* XXX: implement this */

	return res;
}

/** Destroy kv storage */
void
rspamd_kv_storage_destroy (struct rspamd_kv_storage *storage)
{
	if (storage->cache) {
		storage->cache->destroy_func (storage->cache);
	}
	if (storage->backend) {
		storage->backend->destroy_func (storage->backend);
	}
	if (storage->expire) {
		storage->expire->destroy_func (storage->expire);
	}

	g_free (storage->name);
	g_slice_free1 (sizeof (struct rspamd_kv_storage), storage);
}
