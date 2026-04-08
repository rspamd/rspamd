/*-
 * Copyright 2018 Vsevolod Stakhov
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

#ifndef RSPAMD_MAP_HELPERS_H
#define RSPAMD_MAP_HELPERS_H

#include "config.h"
#include "map.h"
#include "addr.h"

/**
 * @file map_helpers.h
 *
 * Defines helper structures to deal with different map types
 */


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Common structures, abstract for simplicity
 */
struct rspamd_radix_map_helper;
struct rspamd_hash_map_helper;
struct rspamd_regexp_map_helper;
struct ev_loop;
struct rspamd_cdb_map_helper;
struct rspamd_map_helper_value;

enum rspamd_regexp_map_flags {
	RSPAMD_REGEXP_MAP_FLAG_UTF = (1u << 0),
	RSPAMD_REGEXP_MAP_FLAG_MULTIPLE = (1u << 1),
	RSPAMD_REGEXP_MAP_FLAG_GLOB = (1u << 2),
};

typedef void (*rspamd_map_insert_func)(gpointer st, gconstpointer key,
									   gconstpointer value);

/**
 * Radix list is a list like ip/mask
 */
char *rspamd_radix_read(
	char *chunk,
	int len,
	struct map_cb_data *data,
	gboolean final);

void rspamd_radix_fin(struct map_cb_data *data, void **target);

void rspamd_radix_dtor(struct map_cb_data *data);

/**
 * Kv list is an ordinal list of keys and values separated by whitespace
 */
char *rspamd_kv_list_read(
	char *chunk,
	int len,
	struct map_cb_data *data,
	gboolean final);

void rspamd_kv_list_fin(struct map_cb_data *data, void **target);

void rspamd_kv_list_dtor(struct map_cb_data *data);

/**
 * Cdb is a cdb mapped file with shared data
 * chunk must be filename!
 */
char *rspamd_cdb_list_read(
	char *chunk,
	int len,
	struct map_cb_data *data,
	gboolean final);
void rspamd_cdb_list_fin(struct map_cb_data *data, void **target);
void rspamd_cdb_list_dtor(struct map_cb_data *data);

/**
 * Regexp list is a list of regular expressions
 */

char *rspamd_regexp_list_read_single(
	char *chunk,
	int len,
	struct map_cb_data *data,
	gboolean final);

char *rspamd_regexp_list_read_multiple(
	char *chunk,
	int len,
	struct map_cb_data *data,
	gboolean final);

char *rspamd_glob_list_read_single(
	char *chunk,
	int len,
	struct map_cb_data *data,
	gboolean final);

char *rspamd_glob_list_read_multiple(
	char *chunk,
	int len,
	struct map_cb_data *data,
	gboolean final);

void rspamd_regexp_list_fin(struct map_cb_data *data, void **target);

void rspamd_regexp_list_dtor(struct map_cb_data *data);

/**
 * FSM for lists parsing (support comments, blank lines and partial replies)
 */
char *
rspamd_parse_kv_list(
	char *chunk,
	int len,
	struct map_cb_data *data,
	rspamd_map_insert_func func,
	const char *default_value,
	gboolean final);

/**
 * Find a single (any) matching regexp for the specified text or NULL if
 * no matches found
 * @param map
 * @param in
 * @param len
 * @return
 */
gconstpointer rspamd_match_regexp_map_single(struct rspamd_regexp_map_helper *map,
											 const char *in, gsize len);

/**
 * Find a multiple (all) matching regexp for the specified text or NULL if
 * no matches found. Returns GPtrArray that *must* be freed by a caller if not NULL
 * @param map
 * @param in
 * @param len
 * @return
 */
GPtrArray *rspamd_match_regexp_map_all(struct rspamd_regexp_map_helper *map,
									   const char *in, gsize len);

/**
 * Find value matching specific key in a hash map
 * @param map
 * @param in
 * @param len
 * @return
 */
gconstpointer rspamd_match_hash_map(struct rspamd_hash_map_helper *map,
									const char *in, gsize len);

/**
 * Find value matching specific key in a cdb map
 * @param map
 * @param in
 * @param len
 * @return rspamd_ftok_t pointer (allocated in a static buffer!)
 */
gconstpointer rspamd_match_cdb_map(struct rspamd_cdb_map_helper *map,
								   const char *in, gsize len);

/**
 * Find value matching specific key in a hash map
 * @param map
 * @param in raw ip address
 * @param inlen ip address length (4 for IPv4 and 16 for IPv6)
 * @return
 */
gconstpointer rspamd_match_radix_map(struct rspamd_radix_map_helper *map,
									 const unsigned char *in, gsize inlen);

gconstpointer rspamd_match_radix_map_addr(struct rspamd_radix_map_helper *map,
										  const rspamd_inet_addr_t *addr);

/**
 * Creates radix map helper
 * @param map
 * @return
 */
struct rspamd_radix_map_helper *rspamd_map_helper_new_radix(struct rspamd_map *map);

/**
 * Inserts new value into radix map
 * @param st
 * @param key
 * @param value
 */
void rspamd_map_helper_insert_radix(gpointer st, gconstpointer key, gconstpointer value);

/**
 * Inserts new value into radix map performing synchronous resolving
 * @param st
 * @param key
 * @param value
 */
void rspamd_map_helper_insert_radix_resolve(gpointer st, gconstpointer key,
											gconstpointer value);

/**
 * Destroys radix map helper
 * @param r
 */
void rspamd_map_helper_destroy_radix(struct rspamd_radix_map_helper *r);


/**
 * Creates hash map helper
 * @param map
 * @return
 */
struct rspamd_hash_map_helper *rspamd_map_helper_new_hash(struct rspamd_map *map);

/**
 * Inserts a new value into a hash map
 * @param st
 * @param key
 * @param value
 */
void rspamd_map_helper_insert_hash(gpointer st, gconstpointer key, gconstpointer value);

/**
 * Destroys hash map helper
 * @param r
 */
void rspamd_map_helper_destroy_hash(struct rspamd_hash_map_helper *r);

/**
 * Create new regexp map
 * @param map
 * @param flags
 * @return
 */
struct rspamd_regexp_map_helper *rspamd_map_helper_new_regexp(struct rspamd_map *map,
															  enum rspamd_regexp_map_flags flags);

/**
 * Inserts a new regexp into regexp map
 * @param st
 * @param key
 * @param value
 */
void rspamd_map_helper_insert_re(gpointer st, gconstpointer key, gconstpointer value);

/**
 * Destroy regexp map
 * @param re_map
 */
void rspamd_map_helper_destroy_regexp(struct rspamd_regexp_map_helper *re_map);

/**
 * Pending regexp map entry for deferred HS compilation
 */
struct rspamd_regexp_map_pending {
	struct rspamd_regexp_map_helper *re_map;
	char *name;             /* Map identifier for logging/IPC */
	unsigned char hash[64]; /* Cache key hash (rspamd_cryptobox_HASHBYTES) */
};

/**
 * Add regexp map to pending compilation queue.
 * Called during initialization when hs_helper is not yet available.
 * @param re_map regexp map helper
 * @param name identifier for this map (e.g., map name)
 */
void rspamd_regexp_map_add_pending(struct rspamd_regexp_map_helper *re_map,
								   const char *name);

/**
 * Get list of pending regexp map compilations.
 * Returns array of rspamd_regexp_map_pending, caller must free array (not contents).
 * @param count output: number of pending entries
 * @return array of pending entries or NULL if none
 */
struct rspamd_regexp_map_pending *rspamd_regexp_map_get_pending(unsigned int *count);

/**
 * Clear pending queue after hs_helper has processed it.
 */
void rspamd_regexp_map_clear_pending(void);

/**
 * Find a pending regexp map by name.
 * @param name identifier
 * @return regexp map helper or NULL if not found
 */
struct rspamd_regexp_map_helper *rspamd_regexp_map_find_pending(const char *name);

/**
 * Get hash/digest from regexp map for cache key generation.
 * @param re_map
 * @param hash_out output buffer (must be rspamd_cryptobox_HASHBYTES)
 */
void rspamd_regexp_map_get_hash(struct rspamd_regexp_map_helper *re_map,
								unsigned char *hash_out);

/**
 * Compile hyperscan database for regexp map and save to cache.
 * This is called by hs_helper for async compilation.
 * @param re_map regexp map helper
 * @param cache_dir directory to save cache file
 * @param err error output
 * @return TRUE on success
 */
gboolean rspamd_regexp_map_compile_hs_to_cache(struct rspamd_regexp_map_helper *re_map,
											   const char *cache_dir,
											   GError **err);

typedef void (*rspamd_regexp_map_hs_cache_cb_t)(struct rspamd_regexp_map_helper *re_map,
												gboolean success,
												GError *err,
												void *ud);

/**
 * Compile regexp map HS database and store it in the configured HS cache backend.
 * If Lua backend is enabled, store is done asynchronously and callback is invoked on completion.
 * For file backend, compilation+store is synchronous and callback is invoked immediately.
 */
void rspamd_regexp_map_compile_hs_to_cache_async(struct rspamd_regexp_map_helper *re_map,
												 const char *cache_dir,
												 struct ev_loop *event_loop,
												 rspamd_regexp_map_hs_cache_cb_t cb,
												 void *ud);

/**
 * Load hyperscan database from cache for regexp map.
 * This is called by workers when they receive notification that
 * hs_helper has compiled a regexp map database.
 * @param re_map regexp map helper
 * @param cache_dir directory containing cache files
 * @return TRUE if loaded successfully
 */
gboolean rspamd_regexp_map_load_from_cache(struct rspamd_regexp_map_helper *re_map,
										   const char *cache_dir);

/**
 * Asynchronously load hyperscan database for a regexp map from the configured
 * HS cache backend (Lua backend if present, otherwise filesystem).
 *
 * The callback is invoked when hot-swap has been attempted.
 */
void rspamd_regexp_map_load_from_cache_async(struct rspamd_regexp_map_helper *re_map,
											 const char *cache_dir,
											 struct ev_loop *event_loop,
											 void (*cb)(gboolean success, void *ud),
											 void *ud);

#ifdef __cplusplus
}
#endif

#endif
