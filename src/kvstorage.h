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

#ifndef KVSTORAGE_H_
#define KVSTORAGE_H_

#include "config.h"

struct rspamd_kv_cache;
struct rspamd_kv_backend;
struct rspamd_kv_storage;
struct rspamd_kv_expire;
struct rspamd_kv_element;

/* Callbacks for cache */
typedef void (*cache_init)(struct rspamd_kv_cache *cache);
typedef struct rspamd_kv_element* (*cache_insert)(struct rspamd_kv_cache *cache, gpointer key, gpointer value, gsize len);
typedef gboolean (*cache_replace)(struct rspamd_kv_cache *cache, gpointer key, struct rspamd_kv_element *elt);
typedef struct rspamd_kv_element* (*cache_lookup)(struct rspamd_kv_cache *cache, gpointer key);
typedef struct rspamd_kv_element* (*cache_delete)(struct rspamd_kv_cache *cache, gpointer key);
typedef void (*cache_destroy)(struct rspamd_kv_cache *cache);

/* Callbacks for backend */
typedef void (*backend_init)(struct rspamd_kv_backend *backend);
typedef gboolean (*backend_insert)(struct rspamd_kv_backend *backend, gpointer key, struct rspamd_kv_element *elt);
typedef gboolean (*backend_replace)(struct rspamd_kv_backend *backend, gpointer key, struct rspamd_kv_element *elt);
typedef struct rspamd_kv_element* (*backend_lookup)(struct rspamd_kv_backend *backend, gpointer key);
typedef struct rspamd_kv_element* (*backend_delete)(struct rspamd_kv_backend *backend, gpointer key);
typedef void (*backend_destroy)(struct rspamd_kv_backend *backend);

/* Callbacks for expire */
typedef void (*expire_init)(struct rspamd_kv_expire *expire);
typedef void (*expire_insert)(struct rspamd_kv_expire *expire, struct rspamd_kv_element *elt);
typedef void (*expire_delete)(struct rspamd_kv_expire *expire, struct rspamd_kv_element *elt);
typedef gboolean (*expire_step)(struct rspamd_kv_expire *expire, struct rspamd_kv_storage *storage, time_t now);
typedef void (*expire_destroy)(struct rspamd_kv_expire *expire);


/* Flags of element */
enum rspamd_kv_flags {
	KV_ELT_ARRAY = 1 << 0,
	KV_ELT_PERSISTENT = 1 << 1,
	KV_ELT_DIRTY = 1 << 2,
	KV_ELT_OUSTED = 1 << 3
};

/* Common structures description */

struct rspamd_kv_element {
	time_t age;									/*< age of element */
	guint32 expire;								/*< expire of element */
	enum rspamd_kv_flags flags;					/*< element flags  */
	gsize size;									/*< size of element */
	TAILQ_ENTRY (rspamd_kv_element) entry;		/*< list entry */
	guint32 hash;								/*< numeric hash */
	gpointer key;								/*< pointer to key */

	gchar data[1];								/*< expandable data */
};

struct rspamd_kv_cache {
	cache_init init_func;						/*< this callback is called on kv storage initialization */
	cache_insert insert_func;					/*< this callback is called when element is inserted */
	cache_replace replace_func;					/*< this callback is called when element is replace */
	cache_lookup lookup_func;					/*< this callback is used for lookup of element */
	cache_delete delete_func;					/*< this callback is called when an element is deleted */
	cache_destroy destroy_func;					/*< this callback is used for destroying all elements inside cache */
};
struct rspamd_kv_backend {
	backend_init init_func;						/*< this callback is called on kv storage initialization */
	backend_insert insert_func;					/*< this callback is called when element is inserted */
	backend_replace replace_func;				/*< this callback is called when element is replaced */
	backend_lookup lookup_func;					/*< this callback is used for lookup of element */
	backend_delete delete_func;					/*< this callback is called when an element is deleted */
	backend_destroy destroy_func;				/*< this callback is used for destroying all elements inside backend */
};
struct rspamd_kv_expire {
	expire_init init_func;						/*< this callback is called on kv storage initialization */
	expire_insert insert_func;					/*< this callback is called when element is inserted */
	expire_step step_func;						/*< this callback is used when cache is full */
	expire_delete delete_func;					/*< this callback is called when an element is deleted */
	expire_destroy destroy_func;				/*< this callback is used for destroying all elements inside expire */
};

/* Main kv storage structure */

struct rspamd_kv_storage {
	struct rspamd_kv_cache *cache;
	struct rspamd_kv_backend *backend;
	struct rspamd_kv_expire *expire;

	gsize elts;									/*< current elements count in a storage */
	gsize max_elts;								/*< maximum number of elements in a storage */

	gsize memory;								/*< memory eaten */
	gsize max_memory;							/*< memory limit */

	gint id;									/* char ID */
	gchar *name;								/* numeric ID */
	GStaticRWLock rwlock;						/* rwlock for threaded access */
};

/** Create new kv storage */
struct rspamd_kv_storage *rspamd_kv_storage_new (gint id, const gchar *name,
		struct rspamd_kv_cache *cache, struct rspamd_kv_backend *backend, struct rspamd_kv_expire *expire,
		gsize max_elts, gsize max_memory);

/** Insert new element to the kv storage */
gboolean rspamd_kv_storage_insert (struct rspamd_kv_storage *storage, gpointer key, gpointer data, gsize len, gint flags, guint expire);

/** Replace an element in the kv storage */
gboolean rspamd_kv_storage_replace (struct rspamd_kv_storage *storage, gpointer key, struct rspamd_kv_element *elt);

/** Lookup an element inside kv storage */
struct rspamd_kv_element* rspamd_kv_storage_lookup (struct rspamd_kv_storage *storage, gpointer key, time_t now);

/** Expire an element from kv storage */
struct rspamd_kv_element* rspamd_kv_storage_delete (struct rspamd_kv_storage *storage, gpointer key);

/** Destroy kv storage */
void rspamd_kv_storage_destroy (struct rspamd_kv_storage *storage);

/** Insert array */
gboolean rspamd_kv_storage_insert_array (struct rspamd_kv_storage *storage, gpointer key, guint elt_size, gpointer data, gsize len, gint flags, guint expire);

/** Set element inside array */
gboolean rspamd_kv_storage_set_array (struct rspamd_kv_storage *storage, gpointer key, guint elt_num,
		gpointer data, gsize len, time_t now);

/** Get element inside array */
gboolean rspamd_kv_storage_get_array (struct rspamd_kv_storage *storage, gpointer key, guint elt_num,
		gpointer *data, gsize *len, time_t now);

/**
 * LRU expire
 */
struct rspamd_kv_expire* rspamd_lru_expire_new (guint queues);

/**
 * Ordinary hash
 */
struct rspamd_kv_cache* rspamd_kv_hash_new (void);

/**
 * Radix tree
 */
struct rspamd_kv_cache* rspamd_kv_radix_new (void);


#endif /* KVSTORAGE_H_ */
