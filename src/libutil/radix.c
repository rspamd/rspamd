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
#include "config.h"
#include "radix.h"
#include "rspamd.h"
#include "mem_pool.h"
#include "btrie.h"

#define msg_err_radix(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "radix", tree->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_radix(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "radix", tree->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_radix(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "radix", tree->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_radix(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "radix", tree->pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

struct radix_tree_compressed {
	rspamd_mempool_t *pool;
	size_t size;
	struct btrie *tree;
};

uintptr_t
radix_find_compressed (radix_compressed_t * tree, const guint8 *key, gsize keylen)
{
	gconstpointer ret;

	g_assert (tree != NULL);

	ret = btrie_lookup (tree->tree, key, keylen * NBBY);

	if (ret == NULL) {
		return RADIX_NO_VALUE;
	}

	return (uintptr_t)ret;
}


uintptr_t
radix_insert_compressed (radix_compressed_t * tree,
	guint8 *key, gsize keylen,
	gsize masklen,
	uintptr_t value)
{
	guint keybits = keylen * NBBY;
	uintptr_t old;
	gchar ip_str[INET6_ADDRSTRLEN + 1];
	int ret;

	g_assert (tree != NULL);
	g_assert (keybits >= masklen);

	msg_debug_radix ("want insert value %p with mask %z, key: %*xs",
			(gpointer)value, keybits - masklen, (int)keylen, key);

	old = radix_find_compressed (tree, key, keylen);

	ret = btrie_add_prefix (tree->tree, key, keybits - masklen,
			(gconstpointer)value);

	if (ret != BTRIE_OKAY) {
		memset (ip_str, 0, sizeof (ip_str));

		if (keybits == 32) {
			msg_err_radix ("cannot insert %p, key: %s/%d, duplicate value",
					(gpointer)value,
					inet_ntop (AF_INET, key, ip_str, sizeof (ip_str) - 1),
					keybits - masklen);
		}
		else if (keybits == 128) {
			msg_err_radix ("cannot insert %p, key: [%s]/%d, duplicate value",
					(gpointer)value,
					inet_ntop (AF_INET6, key, ip_str, sizeof (ip_str) - 1),
					keybits - masklen);
		}
		else {
			msg_err_radix ("cannot insert %p with mask %z, key: %*xs, duplicate value",
				(gpointer)value, keybits - masklen, (int)keylen, key);
		}
	}
	else {
		tree->size ++;
	}

	return old;
}


radix_compressed_t *
radix_create_compressed (void)
{
	radix_compressed_t *tree;

	tree = g_slice_alloc (sizeof (*tree));
	if (tree == NULL) {
		return NULL;
	}

	tree->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
	tree->size = 0;
	tree->tree = btrie_init (tree->pool);

	return tree;
}

void
radix_destroy_compressed (radix_compressed_t *tree)
{
	if (tree) {
		rspamd_mempool_delete (tree->pool);
		g_slice_free1 (sizeof (*tree), tree);
	}
}

uintptr_t
radix_find_compressed_addr (radix_compressed_t *tree,
		const rspamd_inet_addr_t *addr)
{
	const guchar *key;
	guint klen = 0;

	if (addr == NULL) {
		return RADIX_NO_VALUE;
	}

	key = rspamd_inet_address_get_hash_key (addr, &klen);

	if (key && klen) {
		return radix_find_compressed (tree, key, klen);
	}

	return RADIX_NO_VALUE;
}

gint
rspamd_radix_add_iplist (const gchar *list, const gchar *separators,
		radix_compressed_t *tree, gconstpointer value, gboolean resolve)
{
	gchar *token, *ipnet, *err_str, **strv, **cur, *brace;
	struct in_addr ina;
	struct in6_addr ina6;
	guint k = G_MAXINT;
	gint af;
	gint res = 0, r;
	struct addrinfo hints, *ai_res, *cur_ai;

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
				msg_warn_radix (
						"invalid netmask, error detected on symbol: %s, erorr: %s",
						err_str,
						strerror (errno));
				k = G_MAXINT;
			}
		}

		/* Check IP */
		if (token[0] == '[') {
			/* Braced IPv6 */
			brace = strrchr (token, ']');

			if (brace != NULL) {
				token ++;
				*brace = '\0';

				if (inet_pton (AF_INET6, token, &ina6) == 1) {
					af = AF_INET6;
				}
				else {
					msg_warn_radix ("invalid IP address: %s", token);

					cur ++;
					continue;
				}
			}
			else {
				msg_warn_radix ("invalid IP address: %s", token);

				cur ++;
				continue;
			}
		}
		else {
			if (inet_pton (AF_INET, token, &ina) == 1) {
				af = AF_INET;
			}
			else if (inet_pton (AF_INET6, token, &ina6) == 1) {
				af = AF_INET6;
			}
			else {

				if (resolve) {
					memset (&hints, 0, sizeof (hints));
					hints.ai_socktype = SOCK_STREAM; /* Type of the socket */
					hints.ai_flags = AI_NUMERICSERV;
					hints.ai_family = AF_UNSPEC;

					if ((r = getaddrinfo (token, NULL, &hints, &ai_res)) == 0) {
						for (cur_ai = ai_res; cur_ai != NULL;
								cur_ai = cur_ai->ai_next) {

							if (cur_ai->ai_family == AF_INET) {
								struct sockaddr_in *sin;

								sin = (struct sockaddr_in *)cur_ai->ai_addr;
								if (k > 32) {
									k = 32;
								}

								radix_insert_compressed (tree,
										(guint8 *)&sin->sin_addr,
										sizeof (sin->sin_addr),
										32 - k, (uintptr_t)value);
								res ++;
							}
							else if (cur_ai->ai_family == AF_INET6) {
								struct sockaddr_in6 *sin6;

								sin6 = (struct sockaddr_in6 *)cur_ai->ai_addr;
								if (k > 128) {
									k = 128;
								}

								radix_insert_compressed (tree,
										(guint8 *)&sin6->sin6_addr,
										sizeof (sin6->sin6_addr),
										128 - k, (uintptr_t)value);
								res ++;
							}
						}

						freeaddrinfo (ai_res);
					}
					else {
						msg_warn_radix ("getaddrinfo failed for %s: %s", token,
								gai_strerror (r));
					}

					cur ++;
					continue;
				}
				else {
					msg_warn_radix ("invalid IP address: %s", token);

					cur ++;
					continue;
				}
			}
		}

		if (af == AF_INET) {
			if (k > 32) {
				k = 32;
			}
			radix_insert_compressed (tree, (guint8 *)&ina, sizeof (ina),
					32 - k, (uintptr_t)value);
			res ++;
		}
		else if (af == AF_INET6){
			if (k > 128) {
				k = 128;
			}
			radix_insert_compressed (tree, (guint8 *)&ina6, sizeof (ina6),
					128 - k, (uintptr_t)value);
			res ++;
		}
		cur++;
	}

	g_strfreev (strv);

	return res;
}

gboolean
radix_add_generic_iplist (const gchar *ip_list, radix_compressed_t **tree,
		gboolean resolve)
{
	if (*tree == NULL) {
		*tree = radix_create_compressed ();
	}

	return (rspamd_radix_add_iplist (ip_list, ",; ", *tree,
			GINT_TO_POINTER (1), resolve) > 0);
}


gsize
radix_get_size (radix_compressed_t *tree)
{
	if (tree != NULL) {
		return tree->size;
	}

	return 0;
}


rspamd_mempool_t *
radix_get_pool (radix_compressed_t *tree)
{

	if (tree != NULL) {
		return tree->pool;
	}

	return NULL;
}

const gchar *
radix_get_info (radix_compressed_t *tree)
{
	if (tree == NULL) {
		return NULL;
	}

	return btrie_stats (tree->tree);
}
