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

#ifndef SRC_LIBUTIL_MULTIPATTERN_H_
#define SRC_LIBUTIL_MULTIPATTERN_H_

#include "config.h"

/**
 * @file multipattern.h
 *
 * This file defines structure that acts like a transparent bridge between
 * hyperscan and ac-trie
 */

#ifdef  __cplusplus
extern "C" {
#endif

enum rspamd_multipattern_flags {
	RSPAMD_MULTIPATTERN_DEFAULT = 0,
	RSPAMD_MULTIPATTERN_ICASE = (1 << 0),
	RSPAMD_MULTIPATTERN_UTF8 = (1 << 1),
	RSPAMD_MULTIPATTERN_TLD = (1 << 2),
	/* Not supported by acism */
	RSPAMD_MULTIPATTERN_GLOB = (1 << 3),
	RSPAMD_MULTIPATTERN_RE = (1 << 4),
	RSPAMD_MULTIPATTERN_DOTALL = (1 << 5),
	RSPAMD_MULTIPATTERN_SINGLEMATCH = (1 << 6),
	RSPAMD_MULTIPATTERN_NO_START = (1 << 7),
};

struct rspamd_multipattern;
struct rspamd_cryptobox_library_ctx;

/**
 * Called on pattern match
 * @param mp multipattern structure
 * @param strnum number of pattern matched
 * @param textpos position in the text
 * @param text input text
 * @param len length of input text
 * @param context userdata
 * @return if 0 then search for another pattern, otherwise return this value to caller
 */
typedef gint (*rspamd_multipattern_cb_t) (struct rspamd_multipattern *mp,
										  guint strnum,
										  gint match_start,
										  gint match_pos,
										  const gchar *text,
										  gsize len,
										  void *context);

/**
 * Init multipart library and set the appropriate cache dir
 * @param cache_dir
 */
void rspamd_multipattern_library_init (const gchar *cache_dir);

/**
 * Creates empty multipattern structure
 * @param flags
 * @return
 */
struct rspamd_multipattern *rspamd_multipattern_create (
		enum rspamd_multipattern_flags flags);

/**
 * Creates multipattern with preallocated number of patterns to speed up loading
 * @param flags
 * @param reserved
 * @return
 */
struct rspamd_multipattern *rspamd_multipattern_create_sized (guint reserved,
															  enum rspamd_multipattern_flags flags);

/**
 * Creates new multipattern structure
 * @param patterns vector of null terminated strings
 * @param npatterns number of patterns
 * @param flags flags applied to all patterns
 * @return new multipattern structure
 */
struct rspamd_multipattern *rspamd_multipattern_create_full (
		const gchar **patterns,
		guint npatterns,
		enum rspamd_multipattern_flags flags);

/**
 * Adds new pattern to match engine from zero-terminated string
 * @param mp
 * @param pattern
 */
void rspamd_multipattern_add_pattern (struct rspamd_multipattern *mp,
									  const gchar *pattern, gint flags);

/**
 * Adds new pattern from arbitrary string
 * @param mp
 * @param pattern
 * @param patlen
 * @param flags
 */
void rspamd_multipattern_add_pattern_len (struct rspamd_multipattern *mp,
										  const gchar *pattern, gsize patlen, gint flags);

/**
 * Compiles multipattern structure
 * @param mp
 * @return
 */
gboolean rspamd_multipattern_compile (struct rspamd_multipattern *mp,
									  GError **err);

/**
 * Lookups for patterns in a text using the specified callback function
 * @param mp
 * @param in
 * @param len
 * @param cb if callback returns non-zero, then search is terminated and that value is returned
 * @param ud callback data
 * @return
 */
gint rspamd_multipattern_lookup (struct rspamd_multipattern *mp,
								 const gchar *in, gsize len, rspamd_multipattern_cb_t cb,
								 gpointer ud, guint *pnfound);

/**
 * Get pattern string from multipattern identified by index
 * @param mp
 * @param index
 * @return
 */
const gchar *rspamd_multipattern_get_pattern (struct rspamd_multipattern *mp,
											  guint index);

/**
 * Returns number of patterns in a multipattern matcher
 * @param mp
 * @return
 */
guint rspamd_multipattern_get_npatterns (struct rspamd_multipattern *mp);

/**
 * Destroys multipattern structure
 * @param mp
 */
void rspamd_multipattern_destroy (struct rspamd_multipattern *mp);

/**
 * Returns TRUE if hyperscan is supported
 * @return
 */
gboolean rspamd_multipattern_has_hyperscan (void);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBUTIL_MULTIPATTERN_H_ */
