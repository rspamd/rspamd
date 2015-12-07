/*
 * Copyright (c) 2015, Vsevolod Stakhov
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
#ifndef RSPAMD_RE_CACHE_H
#define RSPAMD_RE_CACHE_H

#include "config.h"
#include "libutil/regexp.h"

struct rspamd_re_cache;
struct rspamd_re_runtime;
struct rspamd_task;

enum rspamd_re_type {
	RSPAMD_RE_HEADER,
	RSPAMD_RE_RAWHEADER,
	RSPAMD_RE_ALLHEADER,
	RSPAMD_RE_MIME,
	RSPAMD_RE_URL,
	RSPAMD_RE_BODY,
	RSPAMD_RE_MAX
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
 */
void rspamd_re_cache_add (struct rspamd_re_cache *cache, rspamd_regexp_t *re,
		enum rspamd_re_type type, gpointer type_data, gsize datalen);

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
void rspamd_re_cache_init (struct rspamd_re_cache *cache);

/**
 * Get runtime data for a cache
 */
struct rspamd_re_runtime* rspamd_re_cache_runtime_new (struct rspamd_re_cache *cache);

/**
 * Process regexp runtime and return the result for a specific regexp
 * @param task task object
 * @param rt cache runtime object
 * @param re regexp object
 * @param type type of object
 * @param type_data associated data with the type (e.g. header name)
 * @param datalen associated data length
 * @param is_strong use case sensitive match when looking for headers
 * @param is_multiple return multiple possible occurrences of the specified re
 */
gint rspamd_re_cache_process (struct rspamd_task *task,
		struct rspamd_re_runtime *rt,
		rspamd_regexp_t *re,
		enum rspamd_re_type type,
		gpointer type_data,
		gsize datalen,
		gboolean is_strong,
		gboolean is_multiple);

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
const gchar * rspamd_re_cache_type_to_string (enum rspamd_re_type type);

/**
 * Convert re type string to the type enum
 */
enum rspamd_re_type rspamd_re_cache_type_from_string (const char *str);

/**
 * Compile expressions to the hyperscan tree and store in the `cache_dir`
 */
gboolean rspamd_re_cache_compile_hyperscan (struct rspamd_re_cache *cache,
		const char *cache_dir,
		GError **err);

#endif
