/*
 * Copyright (c) 2015, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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
#ifndef REGEXP_H_
#define REGEXP_H_

#include "config.h"

typedef struct rspamd_regexp_s rspamd_regexp_t;
struct rspamd_regexp_cache;

/**
 * Create new rspamd regexp
 * @param pattern regexp pattern
 * @param flags flags (may be enclosed inside pattern)
 * @param err error pointer set if compilation failed
 * @return new regexp object
 */
rspamd_regexp_t* rspamd_regexp_new (const gchar *pattern, const gchar *flags,
		GError **err);

/**
 * Search the specified regexp in the text
 * @param re
 * @param text
 * @param len
 * @param start position of start of match
 * @param start position of end of match
 * @return
 */
gboolean rspamd_regexp_search (rspamd_regexp_t *re,
		const gchar *text, gsize len,
		const gchar **start, const gchar **end, gboolean raw);


/**
 * Exact match of the specified text against the regexp
 * @param re
 * @param text
 * @param len
 * @return
 */
gboolean rspamd_regexp_match (rspamd_regexp_t *re,
		const gchar *text, gsize len, gboolean raw);

/**
 * Increase refcount for a regexp object
 */
rspamd_regexp_t* rspamd_regexp_ref (rspamd_regexp_t *re);

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
gpointer rspamd_regexp_get_ud (rspamd_regexp_t *re);

/**
 * Get regexp ID suitable for hashing
 * @param re
 * @return
 */
gpointer rspamd_regexp_get_id (rspamd_regexp_t *re);

/**
 * Get pattern for the specified regexp object
 * @param re
 * @return
 */
const char* rspamd_regexp_get_pattern (rspamd_regexp_t *re);

/**
 * Create new regexp cache
 * @return
 */
struct rspamd_regexp_cache* rspamd_regexp_cache_new (void);

/**
 * Query rspamd cache for a specified regexp
 * @param cache regexp cache. if NULL, the superglobal cache is used (*not* thread-safe)
 * @param pattern
 * @param flags
 * @return
 */
rspamd_regexp_t* rspamd_regexp_cache_query (struct rspamd_regexp_cache* cache,
		const gchar *pattern,
		const gchar *flags);

/**
 * Insert item to the cache using custom pattern and flags
 * @param cache
 * @param pattern
 * @param flags
 * @param re
 */
void rspamd_regexp_cache_insert (struct rspamd_regexp_cache* cache,
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
rspamd_regexp_t* rspamd_regexp_cache_create (struct rspamd_regexp_cache *cache,
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
 * Initialize superglobal regexp cache and library
 */
void rspamd_regexp_library_init (void);

/**
 * Cleanup internal library structures
 */
void rspamd_regexp_library_finalize (void);

#endif /* REGEXP_H_ */
