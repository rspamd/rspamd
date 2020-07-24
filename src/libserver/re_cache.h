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

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_re_cache;
struct rspamd_re_runtime;
struct rspamd_task;
struct rspamd_config;

enum rspamd_re_type {
	RSPAMD_RE_HEADER,
	RSPAMD_RE_RAWHEADER,
	RSPAMD_RE_ALLHEADER,
	RSPAMD_RE_MIMEHEADER,
	RSPAMD_RE_MIME,
	RSPAMD_RE_RAWMIME,
	RSPAMD_RE_URL,
	RSPAMD_RE_EMAIL,
	RSPAMD_RE_BODY, /* full in SA */
	RSPAMD_RE_SABODY, /* body in SA */
	RSPAMD_RE_SARAWBODY, /* rawbody in SA */
	RSPAMD_RE_WORDS, /* normalized words */
	RSPAMD_RE_RAWWORDS, /* raw words */
	RSPAMD_RE_STEMWORDS, /* stemmed words */
	RSPAMD_RE_SELECTOR, /* use lua selector to process regexp */
	RSPAMD_RE_MAX
};

struct rspamd_re_cache_stat {
	guint64 bytes_scanned;
	guint64 bytes_scanned_pcre;
	guint regexp_checked;
	guint regexp_matched;
	guint regexp_total;
	guint regexp_fast_cached;
};

/**
 * Initialize re_cache persistent structure
 */
struct rspamd_re_cache *rspamd_re_cache_new (void);

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
rspamd_re_cache_add (struct rspamd_re_cache *cache, rspamd_regexp_t *re,
					 enum rspamd_re_type type,
					 gconstpointer type_data, gsize datalen,
					 gint lua_cbref);

/**
 * Replace regexp in the cache with another regexp
 * @param cache cache object
 * @param what re to replace
 * @param with regexp object to replace the origin
 */
void rspamd_re_cache_replace (struct rspamd_re_cache *cache,
							  rspamd_regexp_t *what,
							  rspamd_regexp_t *with);

/**
 * Initialize and optimize re cache structure
 */
void rspamd_re_cache_init (struct rspamd_re_cache *cache,
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
enum rspamd_hyperscan_status rspamd_re_cache_is_hs_loaded (struct rspamd_re_cache *cache);

/**
 * Get runtime data for a cache
 */
struct rspamd_re_runtime *rspamd_re_cache_runtime_new (struct rspamd_re_cache *cache);

/**
 * Get runtime statistics
 */
const struct rspamd_re_cache_stat *
rspamd_re_cache_get_stat (struct rspamd_re_runtime *rt);

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
gint rspamd_re_cache_process (struct rspamd_task *task,
							  rspamd_regexp_t *re,
							  enum rspamd_re_type type,
							  gconstpointer type_data,
							  gsize datalen,
							  gboolean is_strong);

int rspamd_re_cache_process_ffi (void *ptask,
								 void *pre,
								 int type,
								 void *type_data,
								 int is_strong);

/**
 * Destroy runtime data
 */
void rspamd_re_cache_runtime_destroy (struct rspamd_re_runtime *rt);

/**
 * Unref re cache
 */
void rspamd_re_cache_unref (struct rspamd_re_cache *cache);

/**
 * Retain reference to re cache
 */
struct rspamd_re_cache *rspamd_re_cache_ref (struct rspamd_re_cache *cache);

/**
 * Set limit for all regular expressions in the cache, returns previous limit
 */
guint rspamd_re_cache_set_limit (struct rspamd_re_cache *cache, guint limit);

/**
 * Convert re type to a human readable string (constant one)
 */
const gchar *rspamd_re_cache_type_to_string (enum rspamd_re_type type);

/**
 * Convert re type string to the type enum
 */
enum rspamd_re_type rspamd_re_cache_type_from_string (const char *str);

struct ev_loop;
/**
 * Compile expressions to the hyperscan tree and store in the `cache_dir`
 */
gint rspamd_re_cache_compile_hyperscan (struct rspamd_re_cache *cache,
										const char *cache_dir,
										gdouble max_time,
										gboolean silent,
										struct ev_loop *event_loop,
										void (*cb)(guint ncompiled, GError *err, void *cbd),
										void *cbd);

/**
 * Returns TRUE if the specified file is valid hyperscan cache
 */
gboolean rspamd_re_cache_is_valid_hyperscan_file (struct rspamd_re_cache *cache,
												  const char *path,
												  gboolean silent,
												  gboolean try_load);

/**
 * Loads all hyperscan regexps precompiled
 */
enum rspamd_hyperscan_status rspamd_re_cache_load_hyperscan (
		struct rspamd_re_cache *cache,
		const char *cache_dir, bool try_load);

/**
 * Registers lua selector in the cache
 */
void rspamd_re_cache_add_selector (struct rspamd_re_cache *cache,
								   const gchar *sname, gint ref);

#ifdef  __cplusplus
}
#endif

#endif
