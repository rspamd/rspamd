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

#include "config.h"
#include "mem_pool.h"
#include "trie.h"

rspamd_trie_t *
rspamd_trie_create (gboolean icase)
{
	rspamd_trie_t *new;

	new = g_malloc (sizeof (rspamd_trie_t));

	new->icase = icase;
	new->pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	new->root.fail = NULL;
	new->root.final = 0;
	new->root.id = 0;
	new->root.next = NULL;
	new->root.match = NULL;
	new->fail_states = g_ptr_array_sized_new (8);

	return new;
}

/*
 * Insert a single character as the specified level of the suffix tree
 */
static struct rspamd_trie_state *
rspamd_trie_insert_char (rspamd_trie_t *trie,
	guint depth,
	struct rspamd_trie_state *pos,
	gchar c)
{
	struct rspamd_trie_match *new_match;
	struct rspamd_trie_state *new_pos;

	/* New match is inserted before pos */
	new_match =
		rspamd_mempool_alloc (trie->pool, sizeof (struct rspamd_trie_match));
	new_match->next = pos->match;
	new_match->c = c;

	/* Now set match link */
	pos->match = new_match;

	new_match->state =
		rspamd_mempool_alloc (trie->pool, sizeof (struct rspamd_trie_state));
	new_pos = new_match->state;
	new_pos->match = NULL;
	new_pos->fail = &trie->root;
	new_pos->final = 0;
	new_pos->id = -1;

	if (trie->fail_states->len < depth + 1) {
		/* Grow fail states array if depth is more than its size */
		guint size = trie->fail_states->len;

		size = MAX (size * 2, depth + 1);
		g_ptr_array_set_size (trie->fail_states, size);
	}

	new_pos->next = trie->fail_states->pdata[depth];
	trie->fail_states->pdata[depth] = new_pos;

	return new_pos;
}

/* Traverse the specified node to find corresponding match */
static inline struct rspamd_trie_match *
check_match (struct rspamd_trie_state *s, gchar c)
{
	struct rspamd_trie_match *match = s->match;

	while (match && match->c != c) {
		match = match->next;
	}

	return match;
}

void
rspamd_trie_insert (rspamd_trie_t *trie, const gchar *pattern, gint pattern_id)
{
	const guchar *p = pattern;
	struct rspamd_trie_state *q, *q1, *r, *cur_node;
	struct rspamd_trie_match *m, *n;
	guint i, depth = 0;
	gchar c;

	/* Insert pattern to the trie */

	cur_node = &trie->root;

	while (*p) {
		c = trie->icase ? g_ascii_tolower (*p) : *p;
		m = check_match (cur_node, c);
		if (m == NULL) {
			/* Insert a character at specified level depth */
			cur_node = rspamd_trie_insert_char (trie, depth, cur_node, c);
		}
		else {
			cur_node = m->state;
		}
		p++;
		depth++;
	}

	cur_node->final = depth;
	cur_node->id = pattern_id;

	/* Update fail states and build fail states graph */
	/* Go through the whole depth of prefixes */
	for (i = 0; i < trie->fail_states->len; i++) {
		q = trie->fail_states->pdata[i];
		while (q) {
			m = q->match;
			while (m) {
				c = m->c;
				q1 = m->state;
				r = q->fail;
				/* Move q->fail to last known fail location for this character (or to NULL) */
				while (r && (n = check_match (r, c)) == NULL) {
					r = r->fail;
				}

				/* We have found new fail location for character c, so set it in q1 */
				if (r != NULL) {
					q1->fail = n->state;
					if (q1->fail->final > q1->final) {
						q1->final = q1->fail->final;

						if (q1->id == -1) {
							q1->id = q1->fail->id;
						}
					}
				}
				else {
					/* Search from root */
					if ((n = check_match (&trie->root, c))) {
						q1->fail = n->state;
					}
					else {
						q1->fail = &trie->root;
					}
				}

				m = m->next;
			}

			q = q->next;
		}
	}
}

const gchar *
rspamd_trie_lookup (rspamd_trie_t *trie,
	const gchar *buffer,
	gsize buflen,
	gint *matched_id)
{
	const guchar *p = buffer, *prev, *ret;
	struct rspamd_trie_state *cur_node;
	struct rspamd_trie_match *m = NULL;
	gchar c;


	cur_node = &trie->root;
	prev = p;
	ret = p;

	while (buflen) {
		c = trie->icase ? g_ascii_tolower (*p) : *p;

		/* Match pattern or use fail-path to restore state */
		while (cur_node != NULL && (m = check_match (cur_node, c)) == NULL) {
			cur_node = cur_node->fail;
		}

		/* Shift left in the text */
		if (cur_node == &trie->root) {
			/* 1 character pattern found */
			ret = prev;
		}
		else if (cur_node == NULL) {
			/* We have tried the pattern but eventually it was not found */
			cur_node = &trie->root;
			ret = p;
			p++;
			prev = p;
			buflen--;
			continue;
		}

		if (m != NULL) {
			/* Match found */
			cur_node = m->state;

			if (cur_node->final) {
				/* The complete pattern found */
				if (matched_id != NULL) {
					*matched_id = cur_node->id;
				}
				return (const gchar *) ret;
			}
		}
		p++;
		prev = p;
		buflen--;
	}

	return NULL;
}

void
rspamd_trie_free (rspamd_trie_t *trie)
{
	g_ptr_array_free (trie->fail_states, TRUE);
	rspamd_mempool_delete (trie->pool);
	g_free (trie);
}
