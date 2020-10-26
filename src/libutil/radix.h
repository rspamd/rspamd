/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef RADIX_H
#define RADIX_H

#include "config.h"
#include "mem_pool.h"
#include "util.h"

#define RADIX_NO_VALUE   (uintptr_t)-1

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct radix_tree_compressed radix_compressed_t;

/**
 * Insert new key to the radix trie
 * @param tree radix trie
 * @param key key to insert (bitstring)
 * @param keylen length of the key (in bytes)
 * @param masklen length of mask that should be applied to the key (in bits)
 * @param value opaque value pointer
 * @return previous value of the key or `RADIX_NO_VALUE`
 */
uintptr_t
radix_insert_compressed (radix_compressed_t *tree,
						 guint8 *key, gsize keylen,
						 gsize masklen,
						 uintptr_t value);

/**
 * Find a key in a radix trie
 * @param tree radix trie
 * @param key key to find (bitstring)
 * @param keylen length of a key
 * @return opaque pointer or `RADIX_NO_VALUE` if no value has been found
 */
uintptr_t radix_find_compressed (radix_compressed_t *tree, const guint8 *key,
								 gsize keylen);

/**
 * Find specified address in tree (works for IPv4 or IPv6 addresses)
 * @param tree
 * @param addr
 * @return
 */
uintptr_t radix_find_compressed_addr (radix_compressed_t *tree,
									  const rspamd_inet_addr_t *addr);

/**
 * Destroy the complete radix trie
 * @param tree
 */
void radix_destroy_compressed (radix_compressed_t *tree);

/**
 * Create new radix trie
 * @return
 */
radix_compressed_t *radix_create_compressed (const gchar *tree_name);

radix_compressed_t *radix_create_compressed_with_pool (rspamd_mempool_t *pool, const gchar *tree_name);

/**
 * Insert list of ip addresses and masks to the radix tree
 * @param list string line of addresses
 * @param separators string of characters used as separators
 * @param tree target tree
 * @return number of elements inserted
 */
gint rspamd_radix_add_iplist (const gchar *list, const gchar *separators,
							  radix_compressed_t *tree, gconstpointer value,
							  gboolean resolve, const gchar *tree_name);

/**
 * Generic version of @see rspamd_radix_add_iplist. This function creates tree
 * if `tree` is NULL.
 */
gboolean
radix_add_generic_iplist (const gchar *ip_list,
						  radix_compressed_t **tree,
						  gboolean resolve,
						  const gchar *tree_name);

/**
 * Returns number of elements in the tree
 * @param tree
 * @return
 */
gsize radix_get_size (radix_compressed_t *tree);

/**
 * Return string that describes this radix tree (memory, nodes, compression etc)
 * @param tree
 * @return constant string
 */
const gchar *radix_get_info (radix_compressed_t *tree);

/**
 * Returns memory pool associated with the radix tree
 */
rspamd_mempool_t *radix_get_pool (radix_compressed_t *tree);

#ifdef  __cplusplus
}
#endif

#endif
