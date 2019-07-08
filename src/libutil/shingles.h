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

#define RSPAMD_SHINGLE_SIZE 32

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_shingle {
	guint64 hashes[RSPAMD_SHINGLE_SIZE];
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
typedef guint64 (*rspamd_shingles_filter) (guint64 *input, gsize count,
										   gint shno, const guchar *key, gpointer ud);

/**
 * Generate shingles from the input of fixed size strings using lemmatizer
 * if needed
 * @param input array of `rspamd_fstring_t`
 * @param key secret key used to generate shingles
 * @param pool pool to allocate shigles array
 * @param filter hashes filtering function
 * @param filterd opaque data for filtering function
 * @return shingles array
 */
struct rspamd_shingle *rspamd_shingles_from_text (GArray *input,
												  const guchar key[16],
												  rspamd_mempool_t *pool,
												  rspamd_shingles_filter filter,
												  gpointer filterd,
												  enum rspamd_shingle_alg alg);

/**
 * Generate shingles from the DCT matrix of an image
 * @param dct discrete cosine transfor matrix (must be 64x64)
 * @param key secret key used to generate shingles
 * @param pool pool to allocate shigles array
 * @param filter hashes filtering function
 * @param filterd opaque data for filtering function
 * @return shingles array
 */
struct rspamd_shingle *rspamd_shingles_from_image (guchar *dct,
												   const guchar key[16],
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
gdouble rspamd_shingles_compare (const struct rspamd_shingle *a,
								 const struct rspamd_shingle *b);

/**
 * Default filtering function
 */
guint64 rspamd_shingles_default_filter (guint64 *input, gsize count,
										gint shno, const guchar *key, gpointer ud);

#ifdef  __cplusplus
}
#endif

#endif /* SHINGLES_H_ */
