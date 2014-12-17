/* Copyright (c) 2014, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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
#ifndef SHINGLES_H_
#define SHINGLES_H_

#include "config.h"
#include "mem_pool.h"

#define RSPAMD_SHINGLE_SIZE 84

struct rspamd_shingle {
	guint64 hashes[RSPAMD_SHINGLE_SIZE];
};

/**
 * Shingles filtering function
 * @param input input array of hashes
 * @param count number of hashes in the vector
 * @return shingle value
 */
typedef guint64 (*rspamd_shingles_filter) (guint64 *input, gsize count,
		gpointer ud);

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
struct rspamd_shingle* rspamd_shingles_generate (GArray *input,
		const guchar key[16],
		rspamd_mempool_t *pool,
		rspamd_shingles_filter filter,
		gpointer filterd);

/**
 * Default filtering function
 */
guint64 rspamd_shingles_default_filter (guint64 *input, gsize count,
		gpointer ud);

#endif /* SHINGLES_H_ */
