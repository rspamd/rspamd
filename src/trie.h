/* Copyright (c) 2010, Vsevolod Stakhov
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef TRIE_H_
#define TRIE_H_

#include "config.h"
#include "mem_pool.h"

/*
 * Rspamd implements basic bitwise prefixed trie structure
 */

struct rspamd_trie_match;

struct rspamd_trie_state {
	struct rspamd_trie_state *next;
	struct rspamd_trie_state *fail;
	struct rspamd_trie_match *match;
	guint final;
	gint id;
};

struct rspamd_trie_match {
	struct rspamd_trie_match *next;
	struct rspamd_trie_state *state;
	gchar c;
};

typedef struct rspamd_trie_s {
	struct rspamd_trie_state root;
	GPtrArray *fail_states;
	gboolean icase;
	memory_pool_t *pool;
} rspamd_trie_t;

/*
 * Create a new suffix trie
 */
rspamd_trie_t*	rspamd_trie_create (gboolean icase);

/*
 * Insert a pattern into the trie
 * @param trie suffix trie
 * @param pattern text of element
 * @param pattern_id id of element
 */
void rspamd_trie_insert (rspamd_trie_t *trie, const gchar *pattern, gint pattern_id);

/*
 * Search for a text using suffix trie
 * @param trie suffix trie
 * @param buffer a text where to search for trie patterns
 * @param buflen a length of text
 * @param mached_id on a successfull search here would be stored id of pattern found
 * @return Position in a text where pattern was found or NULL if no patterns were found
 */
const gchar* rspamd_trie_lookup (rspamd_trie_t *trie, const gchar *buffer, gsize buflen, gint *matched_id);

/*
 * Deallocate suffix trie
 */
void rspamd_trie_free (rspamd_trie_t *trie);

#endif /* TRIE_H_ */
