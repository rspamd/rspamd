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
#include "radix.h"
#include "mem_pool.h"

static void                    *radix_alloc (radix_tree_t * tree);

radix_tree_t                   *
radix_tree_create (void)
{
	radix_tree_t                   *tree;

	tree = g_malloc (sizeof (radix_tree_t));
	if (tree == NULL) {
		return NULL;
	}

	tree->pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	tree->size = 0;

	tree->root = radix_alloc (tree);
	if (tree->root == NULL) {
		return NULL;
	}

	tree->root->right = NULL;
	tree->root->left = NULL;
	tree->root->parent = NULL;
	tree->root->value = RADIX_NO_VALUE;

	return tree;
}

enum radix_insert_type {
	RADIX_INSERT,
	RADIX_ADD,
	RADIX_REPLACE
};

static uintptr_t
radix32tree_insert_common (radix_tree_t * tree, guint32 key, guint32 mask, uintptr_t value, enum radix_insert_type type)
{
	guint32                         bit;
	radix_node_t                   *node, *next;

	bit = 0x80000000;

	node = tree->root;
	next = tree->root;
	/* Find a place in trie to insert */
	while (bit & mask) {
		if (key & bit) {
			next = node->right;
		}
		else {
			next = node->left;
		}

		if (next == NULL) {
			break;
		}

		bit >>= 1;
		node = next;
	}

	if (next) {
		if (node->value != RADIX_NO_VALUE) {
			/* Value was found, switch on insert type */
			switch (type) {
				case RADIX_INSERT:
					return 1;
				case RADIX_ADD:
					node->value += value;
					return value;
				case RADIX_REPLACE:
					node->value = value;
					return 1;
			}
		}

		node->value = value;
		node->key = key;
		return 0;
	}
	/* Inserting value in trie creating all path components */
	while (bit & mask) {
		next = radix_alloc (tree);
		if (next == NULL) {
			return -1;
		}

		next->right = NULL;
		next->left = NULL;
		next->parent = node;
		next->value = RADIX_NO_VALUE;

		if (key & bit) {
			node->right = next;

		}
		else {
			node->left = next;
		}

		bit >>= 1;
		node = next;
	}

	node->value = value;
	node->key = key;

	return 0;
}

gint 
radix32tree_insert (radix_tree_t *tree, guint32 key, guint32 mask, uintptr_t value)
{
	return (gint)radix32tree_insert_common (tree, key, mask, value, RADIX_INSERT);
}

uintptr_t 
radix32tree_add (radix_tree_t *tree, guint32 key, guint32 mask, uintptr_t value)
{
	return radix32tree_insert_common (tree, key, mask, value, RADIX_ADD);
}

gint 
radix32tree_replace (radix_tree_t *tree, guint32 key, guint32 mask, uintptr_t value)
{
	return (gint)radix32tree_insert_common (tree, key, mask, value, RADIX_REPLACE);
}

/*
 * per recursion step:
 * ptr + ptr + ptr + gint = 4 words
 * result = 1 word
 * 5 words total in stack
 */
static gboolean
radix_recurse_nodes (radix_node_t *node, radix_tree_traverse_func func, void *user_data, gint level)
{
	if (node->left) {
		if (radix_recurse_nodes (node->left, func, user_data, level + 1)) {
			return TRUE;
		}
	}
	
	if (node->value != RADIX_NO_VALUE) {
		if (func (node->key, level, node->value, user_data)) {
			return TRUE;
		}
	}

	if (node->right) {
		if (radix_recurse_nodes (node->right, func, user_data, level + 1)) {
			return TRUE;
		}
	}

	return FALSE;
}

void
radix32tree_traverse (radix_tree_t *tree, radix_tree_traverse_func func, void *user_data)
{
	radix_recurse_nodes (tree->root, func, user_data, 0); 
}


gint
radix32tree_delete (radix_tree_t * tree, guint32 key, guint32 mask)
{
	guint32                         bit;
	radix_node_t                   *node;

	bit = 0x80000000;
	node = tree->root;

	while (node && (bit & mask)) {
		if (key & bit) {
			node = node->right;

		}
		else {
			node = node->left;
		}

		bit >>= 1;
	}

	if (node == NULL || node->parent == NULL) {
		return -1;
	}

	if (node->right || node->left) {
		if (node->value != RADIX_NO_VALUE) {
			node->value = RADIX_NO_VALUE;
			return 0;
		}

		return -1;
	}

	for (;;) {
		if (node->parent->right == node) {
			node->parent->right = NULL;

		}
		else {
			node->parent->left = NULL;
		}

		node = node->parent;

		if (node->right || node->left) {
			break;
		}

		if (node->value != RADIX_NO_VALUE) {
			break;
		}

		if (node->parent == NULL) {
			break;
		}
	}

	return 0;
}


uintptr_t
radix32tree_find (radix_tree_t * tree, guint32 key)
{
	guint32                         bit;
	uintptr_t                       value;
	radix_node_t                   *node;

	bit = 0x80000000;
	value = RADIX_NO_VALUE;
	node = tree->root;

	while (node) {
		if (node->value != RADIX_NO_VALUE) {
			value = node->value;
		}

		if (key & bit) {
			node = node->right;

		}
		else {
			node = node->left;
		}

		bit >>= 1;
	}

	return value;
}


static void                    *
radix_alloc (radix_tree_t * tree)
{
	gchar                           *p;

	p = rspamd_mempool_alloc (tree->pool, sizeof (radix_node_t));

	tree->size += sizeof (radix_node_t);

	return p;
}

void
radix_tree_free (radix_tree_t * tree)
{

	g_return_if_fail (tree != NULL);
	rspamd_mempool_delete (tree->pool);
	g_free (tree);
}

/* 
 * vi:ts=4 
 */
