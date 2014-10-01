/*
 * Copyright (c) 2009-2014, Vsevolod Stakhov
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
#include "main.h"
#include "mem_pool.h"

static void * radix_alloc (radix_tree_t * tree);

#undef RADIX_DEBUG
#ifndef RADIX_DEBUG
#undef msg_debug
#define msg_debug(...) do {} while (0)
#endif

struct radix_node_s {
	radix_node_t *right;
	radix_node_t *left;
	radix_node_t *parent;
	uintptr_t value;
	guint32 key;
};

struct radix_tree_s {
	radix_node_t *root;
	size_t size;
	rspamd_mempool_t *pool;
};

struct radix_compressed_node {
	union {
		struct {
			struct radix_compressed_node *right;
			struct radix_compressed_node *left;
		} n;
		struct {
			uint8_t *key;
			guint keylen;
			guint level;
		} s;
	} d;
	uintptr_t value;
	gboolean skipped;
};


struct radix_tree_compressed {
	struct radix_compressed_node *root;
	rspamd_mempool_t *pool;
	size_t size;
};

radix_tree_t *
radix_tree_create (void)
{
	radix_tree_t *tree;

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

static uintptr_t
radix32tree_insert_common (radix_tree_t * tree,
	guint32 key,
	guint32 mask,
	uintptr_t value,
	enum radix_insert_type type)
{
	guint32 bit;
	radix_node_t *node, *next;

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
radix32tree_insert (radix_tree_t *tree,
	guint32 key,
	guint32 mask,
	uintptr_t value)
{
	return (gint)radix32tree_insert_common (tree, key, mask, value,
			   RADIX_INSERT);
}

uintptr_t
radix32tree_add (radix_tree_t *tree, guint32 key, guint32 mask, uintptr_t value)
{
	return radix32tree_insert_common (tree, key, mask, value, RADIX_ADD);
}

gint
radix32tree_replace (radix_tree_t *tree,
	guint32 key,
	guint32 mask,
	uintptr_t value)
{
	return (gint)radix32tree_insert_common (tree,
			   key,
			   mask,
			   value,
			   RADIX_REPLACE);
}

/*
 * per recursion step:
 * ptr + ptr + ptr + gint = 4 words
 * result = 1 word
 * 5 words total in stack
 */
static gboolean
radix_recurse_nodes (radix_node_t *node,
	radix_tree_traverse_func func,
	void *user_data,
	gint level)
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
radix32tree_traverse (radix_tree_t *tree,
	radix_tree_traverse_func func,
	void *user_data)
{
	radix_recurse_nodes (tree->root, func, user_data, 0);
}


gint
radix32tree_delete (radix_tree_t * tree, guint32 key, guint32 mask)
{
	guint32 bit;
	radix_node_t *node;

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

	for (;; ) {
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
	guint32 bit;
	uintptr_t value;
	radix_node_t *node;

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


static void *
radix_alloc (radix_tree_t * tree)
{
	gchar *p;

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

uintptr_t
radix32_tree_find_addr (radix_tree_t *tree, rspamd_inet_addr_t *addr)
{
	if (addr == NULL || addr->af != AF_INET) {
		return RADIX_NO_VALUE;
	}

	return radix32tree_find (tree, ntohl (addr->addr.s4.sin_addr.s_addr));
}

static gboolean
radix_compare_compressed (struct radix_compressed_node *node,
		guint8 *key, guint keylen, guint cur_level)
{
	guint8 *nk;
	guint8 *k;
	guint8 bit;
	guint shift, rbits, skip;

	if (node->d.s.keylen > keylen) {
		/* Obvious case */
		return FALSE;
	}


	/* Compare byte aligned levels of a compressed node */
	shift = node->d.s.level / NBBY;
	/*
	 * We know that at least of cur_level bits are the same,
	 * se we can optimize search slightly
	 */
	if (shift > 0) {
		skip = cur_level / NBBY;
		if (shift > skip &&
				memcmp (node->d.s.key + skip, key + skip, shift - skip) != 0) {
			return FALSE;
		}
		else {
			/* We already know that we checked all elements prior to this one */
			return TRUE;
		}
	}

	rbits = node->d.s.level % NBBY;
	if (rbits > 0) {
		/* Precisely compare remaining bits */
		nk = node->d.s.key + shift;
		k = key + shift;

		bit = 1U << 7;

		while (rbits > 0) {
			if ((*nk & bit) != (*k & bit)) {
				return FALSE;
			}
			bit >>= 1;
			rbits --;
		}
	}

	return TRUE;
}

uintptr_t
radix_find_compressed (radix_compressed_t * tree, guint8 *key, gsize keylen)
{
	struct radix_compressed_node *node;
	guint32 bit;
	gsize kremain = keylen / sizeof (guint32);
	uintptr_t value;
	guint32 *k = (guint32 *)key;
	guint32 kv = ntohl (*k);
	guint cur_level = 0;

	bit = 1U << 31;
	value = RADIX_NO_VALUE;
	node = tree->root;

	msg_debug ("trying to find key");
	while (node && kremain) {
		if (node->skipped) {
			/* It is obviously a leaf node */
			if (radix_compare_compressed (node, key, keylen, cur_level)) {
				return node->value;
			}
			else {
				return value;
			}
		}
		if (node->value != RADIX_NO_VALUE) {
			value = node->value;
		}

		msg_debug ("finding value cur value: %ul, left: %p, "
						"right: %p, go %s", value, node->d.n.left,
						node->d.n.right, (*k & bit) ? "right" : "left");
		if (kv & bit) {
			node = node->d.n.right;
		}
		else {
			node = node->d.n.left;
		}

		bit >>= 1;
		if (bit == 0) {
			k ++;
			bit = 1U << 31;
			kv = ntohl (*k);
			kremain --;
		}
		cur_level ++;
	}

	return value;
}


static struct radix_compressed_node *
radix_uncompress_path (radix_compressed_t *tree,
		struct radix_compressed_node *node,
		guint start_level,
		guint levels_uncompress)
{
	guint8 *nkey = node->d.s.key + start_level / NBBY;
	guint8 bit = 1U << (7 - start_level % NBBY);
	struct radix_compressed_node *leaf, *next;

	/* Make compressed leaf */
	leaf = rspamd_mempool_alloc (tree->pool, sizeof (*node));
	memcpy (leaf, node, sizeof (*node));

	/* Make compressed node as uncompressed */
	node->skipped = FALSE;
	node->value = RADIX_NO_VALUE;

	msg_debug ("uncompress %ud levels of tree", levels_uncompress);

	/* Uncompress the desired path */
	while (levels_uncompress) {
		next = rspamd_mempool_alloc (tree->pool, sizeof (*node));

		next->skipped = FALSE;
		next->d.n.right = NULL;
		next->d.n.left = NULL;
		next->value = RADIX_NO_VALUE;

		if (*nkey & bit) {
			node->d.n.right = next;
			node->d.n.left = NULL;
		}
		else {
			node->d.n.left = next;
			node->d.n.right = NULL;
		}

		bit >>= 1;
		if (bit == 0) {
			nkey ++;
			bit = 1U << 7;
		}
		node = next;
		levels_uncompress --;
	}

	/* Attach leaf node, that was previously a compressed node */
	msg_debug ("attach leaf node to %s with value %p", (*nkey & bit) ? "right" : "left",
			leaf->value);
	if (*nkey & bit) {
		node->d.n.right = leaf;
		node->d.n.left = NULL;
	}
	else {
		node->d.n.left = leaf;
		node->d.n.right = NULL;
	}

	/* Return node */
	return node;
}


static struct radix_compressed_node *
radix_make_leaf_node (radix_compressed_t *tree,
		guint8 *key, guint keylen, guint level,
		uintptr_t value,
		gboolean compressed)
{
	struct radix_compressed_node *node;

	node = rspamd_mempool_alloc (tree->pool, sizeof (struct radix_compressed_node));
	if (compressed) {
		node->skipped = TRUE;
		node->d.s.keylen = keylen;
		node->d.s.key = rspamd_mempool_alloc (tree->pool, node->d.s.keylen);
		node->d.s.level = level;
		memcpy (node->d.s.key, key, node->d.s.keylen);
	}
	else {
		/* Uncompressed leaf node */
		memset (node, 0, sizeof (*node));
	}
	node->value = value;
	msg_debug ("insert new leaf node with value %p", value);

	return node;
}

static void
radix_move_up_compressed_leaf (radix_compressed_t *tree,
		struct radix_compressed_node *leaf,
		struct radix_compressed_node *parent, uintptr_t value,
		guint8 *key, guint keylen, guint leaf_level)
{
	parent->value = leaf->value;

	leaf->value = value;
	//g_slice_free1 (leaf->d.s.keylen, leaf->d.s.key);
	leaf->d.s.keylen = keylen;
	leaf->d.s.key = rspamd_mempool_alloc (tree->pool, leaf->d.s.keylen);
	memcpy (leaf->d.s.key, key, keylen);
	leaf->d.s.level = leaf_level;
}

static uintptr_t
radix_replace_node (radix_compressed_t *tree,
		struct radix_compressed_node *node,
		guint8 *key, gsize keylen,
		uintptr_t value)
{
	uintptr_t oldval;

	if (node->skipped) {
		/*
		 * For leaf nodes we have to deal with the keys as well, since
		 * we might find that keys are different for the same leaf node
		 */
		//g_slice_free1 (node->d.s.keylen, node->d.s.key);
		node->d.s.keylen = keylen;
		node->d.s.key = rspamd_mempool_alloc (tree->pool, node->d.s.keylen);
		memcpy (node->d.s.key, key, node->d.s.keylen);
		oldval = node->value;
		node->value = value;
		msg_debug ("replace value for leaf node with: %p, old value: %p",
				value, oldval);
	}
	else {
		oldval = node->value;
		node->value = value;
		msg_debug ("replace value for node with: %p, old value: %p",
							value, oldval);
	}

	return oldval;
}

static uintptr_t
radix_uncompress_node (radix_compressed_t *tree,
		struct radix_compressed_node *node,
		guint8 *key, gsize keylen,
		uintptr_t value,
		guint cur_level,
		guint target_level,
		guint8 bit)
{
	/* Find the largest common prefix of the compressed node and target node */
	gsize kremain = keylen - cur_level / NBBY;
	guint8 *nkey = node->d.s.key + cur_level / NBBY;
	guint8 *k = key + cur_level / NBBY;
	guint levels_uncompress = 0, start_level = cur_level;
	gboolean masked = FALSE;
	struct radix_compressed_node *leaf;

	msg_debug ("want to uncompress nodes from level %ud to level %ud, "
			"compressed node level: %ud",
			cur_level, target_level, node->d.s.level);
	while (cur_level < target_level) {
		guint8 kb = *k & bit;
		guint8 nb = *nkey & bit;

		if (cur_level >= node->d.s.level) {
			msg_debug ("found available masked path at level %ud", cur_level);
			masked = TRUE;
			break;
		}
		if (kb != nb) {
			msg_debug ("found available path at level %ud", cur_level);
			break;
		}

		cur_level ++;
		levels_uncompress ++;
		bit >>= 1;
		if (bit == 0) {
			k ++;
			nkey ++;
			bit = 1U << 7;
			kremain --;
		}
	}

	if (kremain == 0) {
		/* Nodes are equal */
		return radix_replace_node (tree, node, key, keylen, value);
	}
	else {
		/*
		 * We need to uncompress the common path
		 */
		struct radix_compressed_node *nnode;

		nnode = radix_uncompress_path (tree, node, start_level, levels_uncompress);

		/*
		 * Now nnode is the last uncompressed node with compressed leaf inside
		 * and we also know that the current bit is different
		 *
		 * - if we have target_level == cur_level, then we can safely assign the
		 * value of that parent node
		 * - otherwise we insert new compressed leaf node
		 */
		if (cur_level == target_level) {
			msg_debug ("insert detached leaf node with value: %p", value);
			nnode->value = value;
		}
		else if (masked) {
			/*
			 * Here we just add the previous value of node to the current node
			 * and replace value in the leaf
			 */
			if (nnode->d.n.left != NULL) {
				leaf = nnode->d.n.left;
			}
			else {
				leaf = nnode->d.n.right;
			}
			msg_debug ("move leaf node with value: %p, to level %ud, "
					"set leaf node value to %p and level %ud", nnode->value,
					cur_level, value, target_level);
			radix_move_up_compressed_leaf (tree, leaf, nnode, value, key, keylen,
					target_level);
		}
		else {
			node = radix_make_leaf_node (tree, key, keylen,
					target_level, value, TRUE);
			if (nnode->d.n.left == NULL) {
				nnode->d.n.left = node;
			}
			else {
				nnode->d.n.right = node;
			}
		}
	}

	return value;
}


uintptr_t
radix_insert_compressed (radix_compressed_t * tree,
	guint8 *key, gsize keylen,
	gsize masklen,
	uintptr_t value)
{
	struct radix_compressed_node *node, *next = NULL, **prev;
	gsize keybits = keylen * NBBY;
	guint target_level = (keylen * NBBY - masklen);
	guint cur_level = 0;
	guint8 bit, *k = key;
	gsize kremain = keylen;
	uintptr_t oldval = RADIX_NO_VALUE;

	bit = 1U << 7;
	node = tree->root;

	g_assert (keybits >= masklen);
	msg_debug ("want insert value %p with mask %z", value, masklen);

	node = tree->root;
	next = node;
	prev = &tree->root;

	/* Search for the place to insert element */
	while (node && cur_level < target_level) {
		if (node->skipped) {
			/* We have found skipped node and we need to uncompress it */
			return radix_uncompress_node (tree, node, key, keylen, value,
					cur_level, target_level, bit);
		}
		if (*k & bit) {
			next = node->d.n.right;
			prev = &node->d.n.right;
		}
		else {
			next = node->d.n.left;
			prev = &node->d.n.left;
		}

		if (next == NULL) {
			/* Need to insert some nodes */
			break;
		}

		bit >>= 1;
		if (bit == 0) {
			k ++;
			bit = 1U << 7;
			kremain --;
		}
		cur_level ++;
		node = next;
	}

	if (next == NULL) {
		next = radix_make_leaf_node (tree, key, keylen, target_level, value,
				TRUE);
		*prev = next;
		tree->size ++;
	}
	else if (next->value == RADIX_NO_VALUE) {
		msg_debug ("insert value node with %p", value);
		next->value = value;
	}
	else {
		if (next->skipped) {
			/*
			 * For skipped node we replace value if the level of skipped node
			 * is equal to the target level
			 */
			if (next->d.s.level == target_level) {
				oldval = radix_replace_node (tree, next, key, keylen, value);
			}
			else if (next->d.s.level > target_level) {
				/*
				 * Here we must create new normal node and insert compressed leaf
				 * one level below
				 */
				node = radix_make_leaf_node (tree, key, keylen,
						target_level, value, FALSE);
				*prev = node;
				if (*k & bit) {
					node->d.n.right = next;
				}
				else {
					node->d.n.left = next;
				}
				oldval = next->value;
			}
			else {
				/*
				 * We must convert old compressed node to a normal node and
				 * create new compressed leaf attached to that normal node
				 */
				node = radix_make_leaf_node (tree, key, keylen,
						target_level, value, TRUE);
				*prev = next;
				msg_debug ("move leaf node with value: %p, to level %ud, "
						"set leaf node value to %p and level %ud", next->value,
						cur_level, value, target_level);
				next->skipped = FALSE;
				if (*k & bit) {
					next->d.n.right = node;
					next->d.n.left = NULL;
				}
				else {
					next->d.n.left = node;
					next->d.n.right = NULL;
				}
				oldval = next->value;
			}
		}
		else {
			oldval = radix_replace_node (tree, next, key, keylen, value);
		}
		return oldval;
	}

	return next->value;
}


radix_compressed_t *
radix_create_compressed (void)
{
	radix_compressed_t *tree;

	tree = g_slice_alloc (sizeof (*tree));
	if (tree == NULL) {
		return NULL;
	}

	tree->pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	tree->size = 0;
	tree->root = NULL;

	return tree;
}

void
radix_destroy_compressed (radix_compressed_t *tree)
{
	rspamd_mempool_delete (tree->pool);
	g_slice_free1 (sizeof (*tree), tree);
}

uintptr_t
radix_find_compressed_addr (radix_compressed_t *tree, rspamd_inet_addr_t *addr)
{
	if (addr == NULL) {
		return RADIX_NO_VALUE;
	}

	if (addr->af == AF_INET) {
		return radix_find_compressed (tree, (guint8 *)&addr->addr.s4.sin_addr,
				sizeof (addr->addr.s4.sin_addr));
	}
	else if (addr->af == AF_INET6) {
		return radix_find_compressed (tree, (guint8 *)&addr->addr.s6.sin6_addr,
				sizeof (addr->addr.s6.sin6_addr));
	}

	return RADIX_NO_VALUE;
}

/*
 * vi:ts=4
 */
