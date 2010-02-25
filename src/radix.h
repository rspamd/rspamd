#ifndef RADIX_H
#define RADIX_H

#include "config.h"
#include "mem_pool.h"

#define RADIX_NO_VALUE   (uintptr_t)-1

typedef struct radix_node_s  radix_node_t;

struct radix_node_s {
    radix_node_t *right;
    radix_node_t *left;
    radix_node_t *parent;
    uintptr_t value;
	uint32_t key;
};


typedef struct {
    radix_node_t  *root;
    size_t         size;
	memory_pool_t *pool;
} radix_tree_t;

typedef gboolean (*radix_tree_traverse_func)(uint32_t key, uint32_t mask, uintptr_t value, void *user_data);

/**
 * Create new radix tree
 */
radix_tree_t *radix_tree_create ();

/**
 * Insert value to radix tree
 * returns: 1 if value already exists
 *          0 if operation was successfull
 *          -1 if there was some error
 */
int radix32tree_insert (radix_tree_t *tree, uint32_t key, uint32_t mask, uintptr_t value);

/**
 * Add value to radix tree or insert it if value does not exists
 * returns: value if value already exists and was added
 *          0 if value was inserted
 *          -1 if there was some error
 */
uintptr_t radix32tree_add (radix_tree_t *tree, uint32_t key, uint32_t mask, uintptr_t value);

/**
 * Replace value in radix tree or insert it if value does not exists
 * returns: 1 if value already exists and was replaced
 *          0 if value was inserted
 *          -1 if there was some error
 */
int radix32tree_replace (radix_tree_t *tree, uint32_t key, uint32_t mask, uintptr_t value);

/**
 * Delete value from radix tree
 * returns: 1 if value does not exist
 *          0 if value was deleted
 *          -1 if there was some error
 */
int radix32tree_delete (radix_tree_t *tree, uint32_t key, uint32_t mask);

/**
 * Find value in radix tree
 * returns: value if value was found
 *			RADIX_NO_VALUE if value was not found
 */
uintptr_t radix32tree_find (radix_tree_t *tree, uint32_t key);

/**
 * Traverse via the whole tree calling specified callback
 */
void radix32tree_traverse (radix_tree_t *tree, radix_tree_traverse_func func, void *user_data);

/**
 * Frees radix tree
 */
void radix_tree_free (radix_tree_t *tree);

#endif
