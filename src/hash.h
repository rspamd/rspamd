/*
 * =====================================================================================
 *
 *       Filename:  hash.h
 *
 *    Description:  Hash table implementation that uses memory pools from mem_pool library
 *
 *        Created:  27.01.2009 16:31:11
 *       Compiler:  gcc
 *
 *         Author:  Vsevolod Stakhov
 *        Company:  Rambler
 *
 * =====================================================================================
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

/* Create new hash in specified pool */
rspamd_hash_t* rspamd_hash_new (memory_pool_t *pool, GHashFunc hash_func, GEqualFunc key_equal_func);
/* Create new hash in specified pool using shared memory */
rspamd_hash_t* rspamd_hash_new_shared (memory_pool_t *pool, GHashFunc hash_func, GEqualFunc key_equal_func);
/* Insert item in hash */
void rspamd_hash_insert (rspamd_hash_t *hash, gpointer key, gpointer value);
/* Remove item from hash */
gboolean rspamd_hash_remove (rspamd_hash_t *hash, gpointer key);
/* Lookup item from hash */
gpointer rspamd_hash_lookup (rspamd_hash_t *hash, gpointer key);
/* Iterate throught hash */
void rspamd_hash_foreach (rspamd_hash_t *hash, GHFunc func, gpointer user_data);

#endif

/*
 * vi:ts=4
 */
