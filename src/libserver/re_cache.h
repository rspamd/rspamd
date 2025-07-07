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
#ifndef RSPAMD_RE_CACHE_H
#define RSPAMD_RE_CACHE_H

#include "config.h"
#include "libutil/regexp.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_re_cache;
struct rspamd_re_runtime;
struct rspamd_task;
struct rspamd_config;

/* Re cache flags */
#define RSPAMD_RE_CACHE_FLAG_LOADED (1U << 0) /* Scope is fully loaded and ready for use */

enum rspamd_re_type {
	RSPAMD_RE_HEADER,
	RSPAMD_RE_RAWHEADER,
	RSPAMD_RE_ALLHEADER,
	RSPAMD_RE_MIMEHEADER,
	RSPAMD_RE_MIME,
	RSPAMD_RE_RAWMIME,
	RSPAMD_RE_URL,
	RSPAMD_RE_EMAIL,
	RSPAMD_RE_BODY,      /* full in SA */
	RSPAMD_RE_SABODY,    /* body in SA */
	RSPAMD_RE_SARAWBODY, /* rawbody in SA */
	RSPAMD_RE_WORDS,     /* normalized words */
	RSPAMD_RE_RAWWORDS,  /* raw words */
	RSPAMD_RE_STEMWORDS, /* stemmed words */
	RSPAMD_RE_SELECTOR,  /* use lua selector to process regexp */
	RSPAMD_RE_MAX
};

struct rspamd_re_cache_stat {
	uint64_t bytes_scanned;
	uint64_t bytes_scanned_pcre;
	unsigned int regexp_checked;
	unsigned int regexp_matched;
	unsigned int regexp_total;
	unsigned int regexp_fast_cached;
};

/**
 * Initialize re_cache persistent structure
 */
struct rspamd_re_cache *rspamd_re_cache_new(void);

/**
 * Add the existing regexp to the cache
 * @param cache cache object
 * @param re regexp object
 * @param type type of object
 * @param type_data associated data with the type (e.g. header name)
 * @param datalen associated data length
 * @param lua_cbref optional lua callback reference for matching purposes
 */
rspamd_regexp_t *
rspamd_re_cache_add(struct rspamd_re_cache *cache, rspamd_regexp_t *re,
					enum rspamd_re_type type,
					gconstpointer type_data, gsize datalen,
					int lua_cbref);

/**
 * Add the existing regexp to the cache with specified scope
 * @param cache_head head of cache list
 * @param scope scope name
 * @param re regexp object
 * @param type type of object
 * @param type_data associated data with the type (e.g. header name)
 * @param datalen associated data length
 * @param lua_cbref optional lua callback reference for matching purposes
 */
rspamd_regexp_t *
rspamd_re_cache_add_scoped(struct rspamd_re_cache **cache_head, const char *scope,
						   rspamd_regexp_t *re, enum rspamd_re_type type,
						   gconstpointer type_data, gsize datalen,
						   int lua_cbref);

/**
 * Replace regexp in the cache with another regexp
 * @param cache cache object
 * @param what re to replace
 * @param with regexp object to replace the origin
 */
void rspamd_re_cache_replace(struct rspamd_re_cache *cache,
							 rspamd_regexp_t *what,
							 rspamd_regexp_t *with);

/**
 * Replace regexp in the scoped cache with another regexp
 * @param cache_head head of cache list
 * @param scope scope name
 * @param what re to replace
 * @param with regexp object to replace the origin
 */
void rspamd_re_cache_replace_scoped(struct rspamd_re_cache **cache_head, const char *scope,
									rspamd_regexp_t *what,
									rspamd_regexp_t *with);

/**
 * Initialize and optimize re cache structure
 */
void rspamd_re_cache_init(struct rspamd_re_cache *cache,
						  struct rspamd_config *cfg);

/**
 * Initialize and optimize re cache structures for all scopes
 */
void rspamd_re_cache_init_scoped(struct rspamd_re_cache *cache_head,
								 struct rspamd_config *cfg);

enum rspamd_hyperscan_status {
	RSPAMD_HYPERSCAN_UNKNOWN = 0,
	RSPAMD_HYPERSCAN_UNSUPPORTED,
	RSPAMD_HYPERSCAN_LOADED_PARTIAL,
	RSPAMD_HYPERSCAN_LOADED_FULL,
	RSPAMD_HYPERSCAN_LOAD_ERROR,
};

/**
 * Returns true when hyperscan is loaded
 * @param cache
 * @return
 */
enum rspamd_hyperscan_status rspamd_re_cache_is_hs_loaded(struct rspamd_re_cache *cache);

/**
 * Get runtime data for a cache - automatically creates runtimes for all scopes in the chain
 * This is the main function used for task runtime creation
 */
struct rspamd_re_runtime *rspamd_re_cache_runtime_new(struct rspamd_re_cache *cache);

/**
 * Get runtime data for all scoped caches (same as rspamd_re_cache_runtime_new)
 */
struct rspamd_re_runtime *rspamd_re_cache_runtime_new_all_scopes(struct rspamd_re_cache *cache_head);

/**
 * Get runtime data for a specific scoped cache only
 */
struct rspamd_re_runtime *rspamd_re_cache_runtime_new_scoped(struct rspamd_re_cache *cache_head, const char *scope);

/**
 * Get runtime statistics
 */
const struct rspamd_re_cache_stat *
rspamd_re_cache_get_stat(struct rspamd_re_runtime *rt);

/**
 * Process regexp runtime and return the result for a specific regexp
 * @param task task object
 * @param rt cache runtime object
 * @param re regexp object
 * @param type type of object
 * @param type_data associated data with the type (e.g. header name)
 * @param datalen associated data length
 * @param is_strong use case sensitive match when looking for headers
 */
int rspamd_re_cache_process(struct rspamd_task *task,
							rspamd_regexp_t *re,
							enum rspamd_re_type type,
							gconstpointer type_data,
							gsize datalen,
							gboolean is_strong);

int rspamd_re_cache_process_ffi(void *ptask,
								void *pre,
								int type,
								void *type_data,
								int is_strong);

/**
 * Destroy runtime data
 */
void rspamd_re_cache_runtime_destroy(struct rspamd_re_runtime *rt);

/**
 * Unref re cache
 */
void rspamd_re_cache_unref(struct rspamd_re_cache *cache);

/**
 * Unref re cache list (all scopes)
 */
void rspamd_re_cache_unref_scoped(struct rspamd_re_cache *cache_head);

/**
 * Retain reference to re cache
 */
struct rspamd_re_cache *rspamd_re_cache_ref(struct rspamd_re_cache *cache);

/**
 * Set limit for all regular expressions in the cache, returns previous limit
 */
unsigned int rspamd_re_cache_set_limit(struct rspamd_re_cache *cache, unsigned int limit);

/**
 * Set limit for all regular expressions in the scoped cache, returns previous limit
 */
unsigned int rspamd_re_cache_set_limit_scoped(struct rspamd_re_cache *cache_head, const char *scope, unsigned int limit);

/**
 * Convert re type to a human readable string (constant one)
 */
const char *rspamd_re_cache_type_to_string(enum rspamd_re_type type);

/**
 * Convert re type string to the type enum
 */
enum rspamd_re_type rspamd_re_cache_type_from_string(const char *str);

struct ev_loop;
/**
 * Compile expressions to the hyperscan tree and store in the `cache_dir`
 */
int rspamd_re_cache_compile_hyperscan(struct rspamd_re_cache *cache,
									  const char *cache_dir,
									  double max_time,
									  gboolean silent,
									  struct ev_loop *event_loop,
									  void (*cb)(unsigned int ncompiled, GError *err, void *cbd),
									  void *cbd);

/**
 * Compile expressions to the hyperscan tree and store in the `cache_dir` for all scopes
 */
int rspamd_re_cache_compile_hyperscan_scoped(struct rspamd_re_cache *cache_head,
											 const char *cache_dir,
											 double max_time,
											 gboolean silent,
											 struct ev_loop *event_loop,
											 void (*cb)(unsigned int ncompiled, GError *err, void *cbd),
											 void *cbd);

/**
 * Returns TRUE if the specified file is valid hyperscan cache
 */
gboolean rspamd_re_cache_is_valid_hyperscan_file(struct rspamd_re_cache *cache,
												 const char *path,
												 gboolean silent,
												 gboolean try_load,
												 GError **err);

/**
 * Loads all hyperscan regexps precompiled
 */
enum rspamd_hyperscan_status rspamd_re_cache_load_hyperscan(
	struct rspamd_re_cache *cache,
	const char *cache_dir, bool try_load);

/**
 * Loads all hyperscan regexps precompiled for all scopes
 */
enum rspamd_hyperscan_status rspamd_re_cache_load_hyperscan_scoped(
	struct rspamd_re_cache *cache_head,
	const char *cache_dir, bool try_load);

/**
 * Compile expressions to the hyperscan tree for a single scope with locking
 */
int rspamd_re_cache_compile_hyperscan_scoped_single(struct rspamd_re_cache *cache,
													const char *scope,
													const char *cache_dir,
													double max_time,
													gboolean silent,
													struct ev_loop *event_loop,
													void (*cb)(const char *scope, unsigned int ncompiled, GError *err, void *cbd),
													void *cbd);

/**
 * Registers lua selector in the cache
 */
void rspamd_re_cache_add_selector(struct rspamd_re_cache *cache,
								  const char *sname, int ref);

/**
 * Registers lua selector in the scoped cache
 */
void rspamd_re_cache_add_selector_scoped(struct rspamd_re_cache **cache_head, const char *scope,
										 const char *sname, int ref);

/**
 * Find a cache by scope name
 */
struct rspamd_re_cache *rspamd_re_cache_find_scope(struct rspamd_re_cache *cache_head, const char *scope);

/**
 * Remove a cache scope from the list
 */
gboolean rspamd_re_cache_remove_scope(struct rspamd_re_cache **cache_head, const char *scope);

/**
 * Get array of scope names from the cache list
 * @param cache_head head of cache list
 * @return NULL-terminated array of scope names (must be freed with g_strfreev), or NULL if no scopes
 */
char **rspamd_re_cache_get_scope_names(struct rspamd_re_cache *cache_head);

/**
 * Count the number of scopes in the cache list
 */
unsigned int rspamd_re_cache_count_scopes(struct rspamd_re_cache *cache_head);

/**
 * Get the first scope in the cache list for iteration
 * @param cache_head head of cache list
 * @return first scope, or NULL if no scopes
 */
struct rspamd_re_cache *rspamd_re_cache_scope_first(struct rspamd_re_cache *cache_head);

/**
 * Get the next scope in iteration
 * @param current current scope
 * @return next scope, or NULL if at end
 */
struct rspamd_re_cache *rspamd_re_cache_scope_next(struct rspamd_re_cache *current);

/**
 * Get the scope name (for display/logging purposes)
 * @param scope the scope
 * @return scope name ("default" for NULL scope name), never returns NULL
 */
const char *rspamd_re_cache_scope_name(struct rspamd_re_cache *scope);

/**
 * Set flags on a scope (efficient version that works directly on scope object)
 * @param scope the scope object (from iterator)
 * @param flags flags to set
 */
void rspamd_re_cache_scope_set_flags(struct rspamd_re_cache *scope, unsigned int flags);

/**
 * Clear flags on a scope (efficient version that works directly on scope object)
 * @param scope the scope object (from iterator)
 * @param flags flags to clear
 */
void rspamd_re_cache_scope_clear_flags(struct rspamd_re_cache *scope, unsigned int flags);

/**
 * Get flags from a scope (efficient version that works directly on scope object)
 * @param scope the scope object (from iterator)
 * @return flags value
 */
unsigned int rspamd_re_cache_scope_get_flags(struct rspamd_re_cache *scope);

/**
 * Check if a scope is loaded (efficient version that works directly on scope object)
 * @param scope the scope object (from iterator)
 * @return TRUE if scope is loaded
 */
gboolean rspamd_re_cache_scope_is_loaded(struct rspamd_re_cache *scope);

/**
 * Set flags for a specific scope (legacy function - less efficient, searches by name)
 * @param cache_head head of cache list
 * @param scope scope name (NULL for default scope)
 * @param flags flags to set
 */
void rspamd_re_cache_set_flags(struct rspamd_re_cache *cache_head, const char *scope, unsigned int flags);

/**
 * Clear flags for a specific scope (legacy function - less efficient, searches by name)
 * @param cache_head head of cache list
 * @param scope scope name (NULL for default scope)
 * @param flags flags to clear
 */
void rspamd_re_cache_clear_flags(struct rspamd_re_cache *cache_head, const char *scope, unsigned int flags);

/**
 * Get flags for a specific scope (legacy function - less efficient, searches by name)
 * @param cache_head head of cache list
 * @param scope scope name (NULL for default scope)
 * @return flags value
 */
unsigned int rspamd_re_cache_get_flags(struct rspamd_re_cache *cache_head, const char *scope);

/**
 * Check if a scope is loaded (legacy function - less efficient, searches by name)
 * @param cache_head head of cache list
 * @param scope scope name (NULL for default scope)
 * @return TRUE if scope is loaded and ready for use
 */
gboolean rspamd_re_cache_is_loaded(struct rspamd_re_cache *cache_head, const char *scope);

#ifdef __cplusplus
}
#endif

#endif
