/*
 * Copyright (c) 2009-2015, Vsevolod Stakhov
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
	guchar *key;
	guint klen = 0;

	if (addr == NULL) {
		return RADIX_NO_VALUE;
	}

	key = rspamd_inet_address_get_radix_key (addr, &klen);

	if (key && klen) {
		return radix_find_compressed (tree, key, klen);
	}

	return RADIX_NO_VALUE;
}

gint
rspamd_radix_add_iplist (const gchar *list, const gchar *separators,
		radix_compressed_t *tree)
{
	gchar *token, *ipnet, *err_str, **strv, **cur;
	struct in_addr ina;
	struct in6_addr ina6;
	guint k = G_MAXINT;
	gint af;
	gint res = 0;

	/* Split string if there are multiple items inside a single string */
	strv = g_strsplit_set (list, separators, 0);
	cur = strv;
	while (*cur) {
		af = AF_UNSPEC;
		if (**cur == '\0') {
			cur++;
			continue;
		}
		/* Extract ipnet */
		ipnet = *cur;
		token = strsep (&ipnet, "/");

		if (ipnet != NULL) {
			errno = 0;
			/* Get mask */
			k = strtoul (ipnet, &err_str, 10);
			if (errno != 0) {
				msg_warn (
						"invalid netmask, error detected on symbol: %s, erorr: %s",
						err_str,
						strerror (errno));
				k = G_MAXINT;
			}
		}

		/* Check IP */
		if (inet_pton (AF_INET, token, &ina) == 1) {
			af = AF_INET;
		}
		else if (inet_pton (AF_INET6, token, &ina6) == 1) {
			af = AF_INET6;
		}
		else {
			msg_warn ("invalid IP address: %s", token);
		}

		if (af == AF_INET) {
			if (k > 32) {
				k = 32;
			}
			radix_insert_compressed (tree, (guint8 *)&ina, sizeof (ina),
					32 - k, 1);
			res ++;
		}
		else if (af == AF_INET6){
			if (k > 128) {
				k = 128;
			}
			radix_insert_compressed (tree, (guint8 *)&ina6, sizeof (ina6),
					128 - k, 1);
			res ++;
		}
		cur++;
	}

	g_strfreev (strv);

	return res;
}

gboolean
radix_add_generic_iplist (const gchar *ip_list, radix_compressed_t **tree)
{
	if (*tree == NULL) {
		*tree = radix_create_compressed ();
	}

	return (rspamd_radix_add_iplist (ip_list, ",; ", *tree) > 0);
}

/*
 * vi:ts=4
 */
