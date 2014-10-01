#ifndef RADIX_H
#define RADIX_H

#include "config.h"
#include "mem_pool.h"
#include "util.h"

#define RADIX_NO_VALUE   (uintptr_t)-1

typedef struct radix_node_s radix_node_t;
typedef struct radix_tree_s radix_tree_t;
typedef struct radix_tree_compressed radix_compressed_t;

enum radix_insert_type {
	RADIX_INSERT,
	RADIX_ADD,
	RADIX_REPLACE
};

typedef gboolean (*radix_tree_traverse_func)(guint32 key, guint32 mask,
	uintptr_t value, void *user_data);

/**
 * Create new radix tree
 */
radix_tree_t * radix_tree_create (void);

/**
 * Insert value to radix tree
 * returns: 1 if value already exists
 *          0 if operation was successfull
 *          -1 if there was some error
 */
gint radix32tree_insert (radix_tree_t *tree,
	guint32 key,
	guint32 mask,
	uintptr_t value);

/**
 * Add value to radix tree or insert it if value does not exists
 * returns: value if value already exists and was added
 *          0 if value was inserted
 *          -1 if there was some error
 */
uintptr_t radix32tree_add (radix_tree_t *tree,
	guint32 key,
	guint32 mask,
	uintptr_t value);

/**
 * Replace value in radix tree or insert it if value does not exists
 * returns: 1 if value already exists and was replaced
 *          0 if value was inserted
 *          -1 if there was some error
 */
gint radix32tree_replace (radix_tree_t *tree,
	guint32 key,
	guint32 mask,
	uintptr_t value);

/**
 * Delete value from radix tree
 * returns: 1 if value does not exist
 *          0 if value was deleted
 *          -1 if there was some error
 */
gint radix32tree_delete (radix_tree_t *tree, guint32 key, guint32 mask);

/**
 * Find value in radix tree
 * returns: value if value was found
 *			RADIX_NO_VALUE if value was not found
 */
uintptr_t radix32tree_find (radix_tree_t *tree, guint32 key);

/**
 * Find specified address in tree (works only for ipv4 addresses)
 * @param tree
 * @param addr
 * @return
 */
uintptr_t radix32_tree_find_addr (radix_tree_t *tree, rspamd_inet_addr_t *addr);



/**
 * Traverse via the whole tree calling specified callback
 */
void radix32tree_traverse (radix_tree_t *tree,
	radix_tree_traverse_func func,
	void *user_data);

/**
 * Frees radix tree
 */
void radix_tree_free (radix_tree_t *tree);

uintptr_t
radix_insert_compressed (radix_compressed_t * tree,
	guint8 *key, gsize keylen,
	gsize masklen,
	uintptr_t value);

uintptr_t radix_find_compressed (radix_compressed_t * tree, guint8 *key,
		gsize keylen);

/**
 * Find specified address in tree (works for any address)
 * @param tree
 * @param addr
 * @return
 */
uintptr_t radix_find_compressed_addr (radix_compressed_t *tree,
		rspamd_inet_addr_t *addr);

void radix_destroy_compressed (radix_compressed_t *tree);

radix_compressed_t *radix_create_compressed (void);

#endif
