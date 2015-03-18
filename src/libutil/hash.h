/**
 * @file hash.h
 * Hash table implementation that allows using memory pools for storage as well as using
 * shared memory for this purpose
 */

#ifndef RSPAMD_HASH_H
#define RSPAMD_HASH_H

#include "config.h"

struct rspamd_lru_hash_s;
typedef struct rspamd_lru_hash_s rspamd_lru_hash_t;

/**
 * Create new lru hash
 * @param maxsize maximum elements in a hash
 * @param maxage maximum age of elemnt
 * @param hash_func pointer to hash function
 * @param key_equal_func pointer to function for comparing keys
 * @return new rspamd_hash object
 */
rspamd_lru_hash_t * rspamd_lru_hash_new (
	gint maxsize,
	gint maxage,
	GDestroyNotify key_destroy,
	GDestroyNotify value_destroy);


/**
 * Create new lru hash
 * @param maxsize maximum elements in a hash
 * @param maxage maximum age of elemnt
 * @param hash_func pointer to hash function
 * @param key_equal_func pointer to function for comparing keys
 * @return new rspamd_hash object
 */
rspamd_lru_hash_t * rspamd_lru_hash_new_full (
	gint maxsize,
	gint maxage,
	GDestroyNotify key_destroy,
	GDestroyNotify value_destroy,
	GHashFunc hfunc,
	GEqualFunc eqfunc);

/**
 * Lookup item from hash
 * @param hash hash object
 * @param key key to find
 * @return value of key or NULL if key is not found
 */
gpointer rspamd_lru_hash_lookup (rspamd_lru_hash_t *hash,
	gconstpointer key,
	time_t now);
/**
 * Insert item in hash
 * @param hash hash object
 * @param key key to insert
 * @param value value of key
 */
void rspamd_lru_hash_insert (rspamd_lru_hash_t *hash,
	gpointer key,
	gpointer value,
	time_t now,
	guint ttl);

/**
 * Remove lru hash
 * @param hash hash object
 */

void rspamd_lru_hash_destroy (rspamd_lru_hash_t *hash);

#endif

/*
 * vi:ts=4
 */
