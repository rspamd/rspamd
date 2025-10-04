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
#ifndef SHINGLES_H_
#define SHINGLES_H_

#include "config.h"
#include "mem_pool.h"
#include "libserver/word.h"
#include "cryptobox.h"

#define RSPAMD_SHINGLE_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_shingle {
	uint64_t hashes[RSPAMD_SHINGLE_SIZE];
};

/**
 * HTML-specific shingle structure with additional metadata hashes
 * for fuzzy matching of HTML structure, domains, and features.
 */
struct rspamd_html_shingle {
	struct rspamd_shingle structure_shingles;              /* Main shingles from HTML DOM structure */
	unsigned char direct_hash[rspamd_cryptobox_HASHBYTES]; /* Direct hash of all tokens for exact matching */
	uint64_t cta_domains_hash;                             /* Hash of CTA (Call-To-Action) domains */
	uint64_t all_domains_hash;                             /* Hash of all link domains (sorted, top-N) */
	uint64_t features_hash;                                /* Hash of bucketed statistical features */

	/* Metadata for filtering/matching */
	uint16_t tags_count;
	uint16_t links_count;
	uint8_t dom_depth;
	uint8_t reserved[3];
};

enum rspamd_shingle_alg {
	RSPAMD_SHINGLES_OLD = 0,
	RSPAMD_SHINGLES_XXHASH,
	RSPAMD_SHINGLES_MUMHASH,
	RSPAMD_SHINGLES_FAST
};

/**
 * Shingles filtering function
 * @param input input array of hashes
 * @param count number of hashes in the vector
 * @return shingle value
 */
typedef uint64_t (*rspamd_shingles_filter)(uint64_t *input, gsize count,
										   int shno, const unsigned char *key, gpointer ud);

/**
 * Generate shingles from the input of fixed size strings using lemmatizer
 * if needed
 * @param input kvec of `rspamd_word_t`
 * @param key secret key used to generate shingles
 * @param pool pool to allocate shingles array
 * @param filter hashes filtering function
 * @param filterd opaque data for filtering function
 * @return shingles array
 */
struct rspamd_shingle *rspamd_shingles_from_text(rspamd_words_t *input,
												 const unsigned char key[16],
												 rspamd_mempool_t *pool,
												 rspamd_shingles_filter filter,
												 gpointer filterd,
												 enum rspamd_shingle_alg alg);

/**
 * Generate shingles from the DCT matrix of an image
 * @param dct discrete cosine transfor matrix (must be 64x64)
 * @param key secret key used to generate shingles
 * @param pool pool to allocate shingles array
 * @param filter hashes filtering function
 * @param filterd opaque data for filtering function
 * @return shingles array
 */
struct rspamd_shingle *rspamd_shingles_from_image(unsigned char *dct,
												  const unsigned char key[16],
												  rspamd_mempool_t *pool,
												  rspamd_shingles_filter filter,
												  gpointer filterd,
												  enum rspamd_shingle_alg alg);

/**
 * Generate HTML shingles from parsed HTML content.
 * Extracts structural tokens (tag sequence + domains + classes),
 * identifies CTA domains using button weights, and creates multiple
 * hash layers for fuzzy matching.
 *
 * @param html_content parsed HTML structure (void* to html_content from html.hxx)
 * @param key secret key (16 bytes) for shingle generation
 * @param pool memory pool for allocation
 * @param filter shingles filter function (typically rspamd_shingles_default_filter)
 * @param filterd opaque data for filter
 * @param alg hashing algorithm (RSPAMD_SHINGLES_MUMHASH recommended)
 * @return HTML shingle structure or NULL on error
 */
struct rspamd_html_shingle *rspamd_shingles_from_html(void *html_content,
													  const unsigned char key[16],
													  rspamd_mempool_t *pool,
													  rspamd_shingles_filter filter,
													  gpointer filterd,
													  enum rspamd_shingle_alg alg);

/**
 * Compares two shingles and return result as a floating point value - 1.0
 * for completely similar shingles and 0.0 for completely different ones
 * @param a
 * @param b
 * @return
 */
double rspamd_shingles_compare(const struct rspamd_shingle *a,
							   const struct rspamd_shingle *b);

/**
 * Compare two HTML shingles using multi-layer approach:
 * - Structure similarity (main DOM skeleton)
 * - CTA domains match (critical for phishing detection)
 * - All domains similarity
 * - Statistical features
 *
 * @param a first HTML shingle
 * @param b second HTML shingle
 * @return similarity score 0.0 (different) to 1.0 (identical)
 */
double rspamd_html_shingles_compare(const struct rspamd_html_shingle *a,
									const struct rspamd_html_shingle *b);

/**
 * Default filtering function
 */
uint64_t rspamd_shingles_default_filter(uint64_t *input, gsize count,
										int shno, const unsigned char *key, gpointer ud);

#ifdef __cplusplus
}
#endif

#endif /* SHINGLES_H_ */
