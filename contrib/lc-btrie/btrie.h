/* Level-Compressed Tree Bitmap (LC-TBM) Trie implementation
 *
 * Contributed by Geoffrey T. Dairiki <dairiki@dairiki.org>
 *
 * This file is released under a "Three-clause BSD License".
 *
 * Copyright (c) 2013, Geoffrey T. Dairiki
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 *   * Neither the name of Geoffrey T. Dairiki nor the names of other
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GEOFFREY
 * T. DAIRIKI BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
#ifndef _BTRIE_H_INCLUDED
#define _BTRIE_H_INCLUDED

#include "config.h"

#include <stdint.h>
typedef uint8_t btrie_oct_t;

/* maximum length of bit string btrie_walk() can handle
 *
 * note: this limit is necessitated by the use of fixed length buffers
 * in btrie_walk() --- btrie_add_prefix() and btrie_lookup() impose no
 * limit on the length of bitstrings
 */
#define BTRIE_MAX_PREFIX          128

struct btrie;
struct memory_pool_s;

struct btrie * btrie_init(struct memory_pool_s *mp);

enum btrie_result
{
	BTRIE_OKAY = 0,
	BTRIE_ALLOC_FAILED = -1,
	BTRIE_DUPLICATE_PREFIX = 1
};

enum btrie_result btrie_add_prefix(struct btrie *btrie,
		const btrie_oct_t *prefix, unsigned len, const void *data);

const void *btrie_lookup(const struct btrie *btrie, const btrie_oct_t *pfx,
		unsigned len);

const char *btrie_stats(const struct btrie *btrie, guint duplicates);

#ifndef NO_MASTER_DUMP
typedef void btrie_walk_cb_t(const btrie_oct_t *prefix, unsigned len,
		const void *data, int post, void *user_data);

void btrie_walk(const struct btrie *btrie, btrie_walk_cb_t *callback,
		void *user_data);
#endif /* not NO_MASTER_DUMP */

#endif /* _BTRIE_H_INCLUDED */
