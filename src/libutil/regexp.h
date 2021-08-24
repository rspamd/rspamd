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
#ifndef REGEXP_H_
#define REGEXP_H_

#include "config.h"

#ifndef WITH_PCRE2
#define PCRE_FLAG(x) G_PASTE(PCRE_, x)
#else
#ifndef PCRE2_CODE_UNIT_WIDTH
#define PCRE2_CODE_UNIT_WIDTH 8
#endif
#define PCRE_FLAG(x) G_PASTE(PCRE2_, x)
#endif

#define RSPAMD_INVALID_ID ((guint64)-1LL)
#define RSPAMD_REGEXP_FLAG_RAW (1 << 1)
#define RSPAMD_REGEXP_FLAG_NOOPT (1 << 2)
#define RSPAMD_REGEXP_FLAG_FULL_MATCH (1 << 3)
#define RSPAMD_REGEXP_FLAG_PCRE_ONLY (1 << 4)
#define RSPAMD_REGEXP_FLAG_DISABLE_JIT (1 << 5)
#define RSPAMD_REGEXP_FLAG_UTF (1 << 6)
#define RSPAMD_REGEXP_FLAG_LEFTMOST (1 << 7)


#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_config;

typedef struct rspamd_regexp_s rspamd_regexp_t;
struct rspamd_regexp_cache;
struct rspamd_re_capture {
	const char *p;
	gsize len;
};

/**
 * Create new rspamd regexp
 * @param pattern regexp pattern
 * @param flags flags (may be enclosed inside pattern)
 * @param err error pointer set if compilation failed
 * @return new regexp object
 */
rspamd_regexp_t *rspamd_regexp_new (const gchar *pattern, const gchar *flags,
									GError **err);

/**
 * Create new rspamd regexp
 * @param pattern regexp pattern
 * @param flags flags (may be enclosed inside pattern)
 * @param err error pointer set if compilation failed
 * @return new regexp object
 */
rspamd_regexp_t *rspamd_regexp_new_len (const gchar *pattern, gsize len, const gchar *flags,
									GError **err);

/**
 * Search the specified regexp in the text
 * @param re
 * @param text
 * @param len
 * @param start position of start of match
 * @param start position of end of match
 * @param raw
 * @param captures array of captured strings of type rspamd_fstring_capture or NULL
 * @return
 */
gboolean rspamd_regexp_search (const rspamd_regexp_t *re,
							   const gchar *text, gsize len,
							   const gchar **start, const gchar **end, gboolean raw,
							   GArray *captures);


/**
 * Exact match of the specified text against the regexp
 * @param re
 * @param text
 * @param len
 * @return
 */
gboolean rspamd_regexp_match (const rspamd_regexp_t *re,
							  const gchar *text, gsize len, gboolean raw);

/**
 * Increase refcount for a regexp object
 */
rspamd_regexp_t *rspamd_regexp_ref (rspamd_regexp_t *re);

/**
 * Unref regexp object
 * @param re
 */
void rspamd_regexp_unref (rspamd_regexp_t *re);

/**
 * Set auxiliary userdata for the specified regexp
 * @param re regexp object
 * @param ud opaque pointer
 */
void rspamd_regexp_set_ud (rspamd_regexp_t *re, gpointer ud);

/**
 * Get userdata for a regexp object
 * @param re regexp object
 * @return opaque pointer
 */
gpointer rspamd_regexp_get_ud (const rspamd_regexp_t *re);

/**
 * Get regexp ID suitable for hashing
 * @param re
 * @return
 */
gpointer rspamd_regexp_get_id (const rspamd_regexp_t *re);

/**
 * Get pattern for the specified regexp object
 * @param re
 * @return
 */
const char *rspamd_regexp_get_pattern (const rspamd_regexp_t *re);

/**
 * Get PCRE flags for the regexp
 */
guint rspamd_regexp_get_pcre_flags (const rspamd_regexp_t *re);

/**
 * Get rspamd flags for the regexp
 */
guint rspamd_regexp_get_flags (const rspamd_regexp_t *re);

/**
 * Set rspamd flags for the regexp
 */
guint rspamd_regexp_set_flags (rspamd_regexp_t *re, guint new_flags);

/**
 * Set regexp maximum hits
 */
guint rspamd_regexp_get_maxhits (const rspamd_regexp_t *re);

/**
 * Get regexp maximum hits
 */
guint rspamd_regexp_set_maxhits (rspamd_regexp_t *re, guint new_maxhits);

/**
 * Returns cache id for a regexp
 */
guint64 rspamd_regexp_get_cache_id (const rspamd_regexp_t *re);

/**
 * Sets cache id for a regexp
 */
guint64 rspamd_regexp_set_cache_id (rspamd_regexp_t *re, guint64 id);

/**
 * Returns match limit for a regexp
 */
gsize rspamd_regexp_get_match_limit (const rspamd_regexp_t *re);

/**
 * Sets cache id for a regexp
 */
gsize rspamd_regexp_set_match_limit (rspamd_regexp_t *re, gsize lim);

/**
 * Get regexp class for the re object
 */
gpointer rspamd_regexp_get_class (const rspamd_regexp_t *re);

/**
 * Set regexp class for the re object
 * @return old re class value
 */
gpointer rspamd_regexp_set_class (rspamd_regexp_t *re, gpointer re_class);

/**
 * Create new regexp cache
 * @return
 */
struct rspamd_regexp_cache *rspamd_regexp_cache_new (void);

/**
 * Query rspamd cache for a specified regexp
 * @param cache regexp cache. if NULL, the superglobal cache is used (*not* thread-safe)
 * @param pattern
 * @param flags
 * @return
 */
rspamd_regexp_t *rspamd_regexp_cache_query (struct rspamd_regexp_cache *cache,
											const gchar *pattern,
											const gchar *flags);

/**
 * Insert item to the cache using custom pattern and flags
 * @param cache
 * @param pattern
 * @param flags
 * @param re
 */
void rspamd_regexp_cache_insert (struct rspamd_regexp_cache *cache,
								 const gchar *pattern,
								 const gchar *flags, rspamd_regexp_t *re);

/**
 * Create or get cached regexp from the specified cache
 * @param cache regexp cache. if NULL, the superglobal cache is used (*not* thread-safe)
 * @param pattern regexp pattern
 * @param flags flags (may be enclosed inside pattern)
 * @param err error pointer set if compilation failed
 * @return new regexp object
 */
rspamd_regexp_t *rspamd_regexp_cache_create (struct rspamd_regexp_cache *cache,
											 const gchar *pattern,
											 const gchar *flags, GError **err);

/**
 * Remove regexp from the cache
 * @param cache regexp cache. if NULL, the superglobal cache is used (*not* thread-safe)
 * @param re re to remove
 * @return TRUE if a regexp has been removed
 */
gboolean rspamd_regexp_cache_remove (struct rspamd_regexp_cache *cache,
									 rspamd_regexp_t *re);

/**
 * Destroy regexp cache and unref all elements inside it
 * @param cache
 */
void rspamd_regexp_cache_destroy (struct rspamd_regexp_cache *cache);

/**
 * Return the value for regexp hash based on its ID
 * @param a
 * @return
 */
guint32 rspamd_regexp_hash (gconstpointer a);

/**
 * Compare two regexp objects based on theirs ID
 * @param a
 * @param b
 * @return
 */
gboolean rspamd_regexp_equal (gconstpointer a, gconstpointer b);

/**
 * Acts like memcmp but for regexp
 */
gint rspamd_regexp_cmp (gconstpointer a, gconstpointer b);

/**
 * Initialize superglobal regexp cache and library
 */
void rspamd_regexp_library_init (struct rspamd_config *cfg);

/**
 * Create regexp from glob
 * @param gl
 * @param err
 * @return
 */
rspamd_regexp_t *rspamd_regexp_from_glob (const gchar *gl, gsize sz, GError **err);

#ifdef  __cplusplus
}
#endif

#endif /* REGEXP_H_ */
