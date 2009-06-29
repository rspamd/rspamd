/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
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

static void *radix_alloc (radix_tree_t *tree);

radix_tree_t *
radix_tree_create (memory_pool_t *pool)
{
	radix_tree_t  *tree;

	tree = memory_pool_alloc (pool, sizeof(radix_tree_t));
	if (tree == NULL) {
		return NULL;
	}

	tree->size = 0;

	tree->root = radix_alloc (tree);
	if (tree->root == NULL) {
		return NULL;
	}

	tree->root->right = NULL;
	tree->root->left = NULL;
	tree->root->parent = NULL;
	tree->root->value = RADIX_NO_VALUE;
	tree->pool = pool;
	
	return tree;
}


int
radix32tree_insert (radix_tree_t *tree, uint32_t key, uint32_t mask,
	unsigned char value)
{
	uint32_t		   bit;
	radix_node_t  *node, *next;

	bit = 0x80000000;

	node = tree->root;
	next = tree->root;
	/* Find a place in trie to insert */
	while (bit & mask) {
		if (key & bit) {
			next = node->right;

		} else {
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
			return 1;
		}

		node->value = value;
		return 0;
	}
	/* Inserting value in trie creating all path components */
	while (bit & mask) {
		next = radix_alloc(tree);
		if (next == NULL) {
			return -1;
		}

		next->right = NULL;
		next->left = NULL;
		next->parent = node;
		next->value = RADIX_NO_VALUE;

		if (key & bit) {
			node->right = next;

		} else {
			node->left = next;
		}

		bit >>= 1;
		node = next;
	}

	node->value = value;

	return 0;
}


int
radix32tree_delete (radix_tree_t *tree, uint32_t key, uint32_t mask)
{
	uint32_t	   bit;
	radix_node_t  *node;
	radix_node_t  *tmp;

	bit = 0x80000000;
	node = tree->root;

	while (node && (bit & mask)) {
		if (key & bit) {
			node = node->right;

		} else {
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

	for ( ;; ) {
		if (node->parent->right == node) {
			node->parent->right = NULL;

		} else {
			node->parent->left = NULL;
		}

		tmp = node;
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


unsigned char
radix32tree_find (radix_tree_t *tree, uint32_t key)
{
	uint32_t		   bit;
	uintptr_t		  value;
	radix_node_t  *node;

	bit = 0x80000000;
	value = RADIX_NO_VALUE;
	node = tree->root;

	while (node) {
		if (node->value != RADIX_NO_VALUE) {
			value = node->value;
		}

		if (key & bit) {
			node = node->right;

		} else {
			node = node->left;
		}

		bit >>= 1;
	}

	return value;
}


static void *
radix_alloc (radix_tree_t *tree)
{
	char  *p;

	p = memory_pool_alloc (tree->pool, sizeof(radix_node_t));

	tree->size += sizeof (radix_node_t);

	return p;
}

void
radix_tree_free (radix_tree_t *tree) 
{
	radix_node_t  *node, *tmp;

	node = tree->root;

	for (;;) {
		/* We are at the trie root and we have no more leaves, end of algorithm */
		if (!node->left && !node->right && !node->parent) {
			break;
		}

		/* Traverse to the end of trie */
		while (node->left || node->right) {
			if (node->left) {
				node = node->left;
			}
			else {
				node = node->right;
			}
		}
		/* Found leaf node, free it */
		if (node->parent->right == node) {
			node->parent->right = NULL;

		} else {
			node->parent->left = NULL;
		}

		tmp = node;
		/* Go up */
		node = node->parent;
	}
}

/* 
 * vi:ts=4 
 */
