/**
 * @file hash.h
 * Hash table implementation that allows using memory pools for storage as well as using
 * shared memory for this purpose
 */

#ifndef RSPAMD_HASH_H
#define RSPAMD_HASH_H

#include <sys/types.h>
#include <glib.h>
#include "mem_pool.h"

struct rspamd_hash_node {
	gpointer                 key;
	gpointer                 value;
	guint                    key_hash;
	struct rspamd_hash_node *next;
};

typedef struct rspamd_hash_s {
	gint                      size;
	gint                      nnodes;
	struct rspamd_hash_node **nodes;

	GHashFunc                 hash_func;
	GEqualFunc                key_equal_func;
	gint                      shared;
	memory_pool_rwlock_t     *lock;
	memory_pool_t            *pool;
} rspamd_hash_t;

#define rspamd_hash_size(x) (x)->nnodes

/**
 * Create new hash in specified pool
 * @param pool memory pool object
 * @param hash_func pointer to hash function
 * @param key_equal_func pointer to function for comparing keys
 * @return new rspamd_hash object
 */
rspamd_hash_t* rspamd_hash_new (memory_pool_t *pool, GHashFunc hash_func, GEqualFunc key_equal_func);

/**
 * Create new hash in specified pool using shared memory
 * @param pool memory pool object
 * @param hash_func pointer to hash function
 * @param key_equal_func pointer to function for comparing keys
 * @return new rspamd_hash object
 */
rspamd_hash_t* rspamd_hash_new_shared (memory_pool_t *pool, GHashFunc hash_func, GEqualFunc key_equal_func);

/**
 * Insert item in hash
 * @param hash hash object
 * @param key key to insert
 * @param value value of key
 */
void rspamd_hash_insert (rspamd_hash_t *hash, gpointer key, gpointer value);

/**
 * Remove item from hash
 * @param hash hash object
 * @param key key to delete
 */
gboolean rspamd_hash_remove (rspamd_hash_t *hash, gpointer key);

/**
 * Lookup item from hash
 * @param hash hash object
 * @param key key to find
 * @return value of key or NULL if key is not found
 */
gpointer rspamd_hash_lookup (rspamd_hash_t *hash, gpointer key);

/** 
 * Iterate throught hash
 * @param hash hash object
 * @param func user's function that would be called for each key/value pair
 * @param user_data pointer to user's data that would be passed to user's function
 */
void rspamd_hash_foreach (rspamd_hash_t *hash, GHFunc func, gpointer user_data);

#endif

/*
 * vi:ts=4
 */
