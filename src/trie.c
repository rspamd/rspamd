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

/*
 * XXX: This code was derived from CamelTrie implementation (lgpl code) and
 * is subject to be rewritten completely from scratch (or from bsd grep)
 */

#include "config.h"
#include "mem_pool.h"
#include "trie.h"


rspamd_trie_t*
rspamd_trie_create (gboolean icase)
{
	rspamd_trie_t                 *new;

	new = g_malloc (sizeof (rspamd_trie_t));

	new->icase = icase;
	new->pool = memory_pool_new (memory_pool_get_size ());
	new->root.fail = NULL;
	new->root.final = 0;
	new->root.id = 0;
	new->root.next = NULL;
	new->root.match = NULL;
	new->fail_states = g_ptr_array_sized_new (8);

	return new;
}

/*
 * Insert a single character as level of binary trie
 */
static struct rspamd_trie_state *
rspamd_trie_insert_char (rspamd_trie_t *trie, gint depth, struct rspamd_trie_state *q, gchar c)
{
	struct rspamd_trie_match     *m;

	/* Insert new match into a chain */
	m = memory_pool_alloc (trie->pool, sizeof (struct rspamd_trie_match));
	m->next = q->match;
	m->c = c;

	q->match = m;
	m->state = memory_pool_alloc (trie->pool, sizeof (struct rspamd_trie_state));
	q = m->state;
	q->match = NULL;
	q->fail = &trie->root;
	q->final = 0;
	q->id = -1;

	if (trie->fail_states->len < depth + 1) {
		/* Grow fail states array */
		guint size = trie->fail_states->len;

		size = MAX (size + 64, depth + 1);
		g_ptr_array_set_size (trie->fail_states, size);
	}

	q->next = trie->fail_states->pdata[depth];
	trie->fail_states->pdata[depth] = q;

	return q;
}

static inline struct rspamd_trie_match *
check_match (struct rspamd_trie_state *s, gchar c)
{
	struct rspamd_trie_match         *m = s->match;

	while (m && m->c != c) {
		m = m->next;
	}

	return m;
}

void
rspamd_trie_insert (rspamd_trie_t *trie, const gchar *pattern, gint pattern_id)
{
	const guchar               *p =  pattern;
	struct rspamd_trie_state   *q, *q1, *r;
	struct rspamd_trie_match   *m, *n;
	gint                        i, depth = 0;
	gchar                       c;

	/* Insert pattern to the trie */

	q = &trie->root;

	while (*p) {
		c = trie->icase ? g_ascii_tolower (*p) : *p;
		m = check_match (q, c);
		if (m == NULL) {
			/* Insert gchar at specified level depth */
			q = rspamd_trie_insert_char (trie, depth, q, c);
		}
		else {
			/* Switch current state to matched state */
			q = m->state;
		}
		p ++;
		depth ++;
	}

	q->final = depth;
	q->id = pattern_id;

	/* Update fail states and build fail states graph */
	/* Go throught the whole depth of prefixes */
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

const gchar*
rspamd_trie_lookup (rspamd_trie_t *trie, const gchar *buffer, gsize buflen, gint *matched_id)
{
	const guchar               *p = buffer, *prev, *pat;
	struct rspamd_trie_state   *q;
	struct rspamd_trie_match   *m = NULL;
	gchar                       c;


	q = &trie->root;
	prev = p;
	pat = p;

	while (buflen) {
		c = trie->icase ? g_ascii_tolower (*p) : *p;

		while (q != NULL && (m = check_match (q, c)) == NULL) {
			q = q->fail;
		}

		if (q == &trie->root) {
			pat = prev;
		}

		if (q == NULL) {
			q = &trie->root;
			pat = p;
		}
		else if (m != NULL) {
			q = m->state;

			if (q->final) {
				if (matched_id) {
					*matched_id = q->id;
				}
				return (const gchar *) pat;
			}
		}
		p ++;
		prev = p;
		buflen --;
	}

	return NULL;
}

void
rspamd_trie_free (rspamd_trie_t *trie)
{
	g_ptr_array_free (trie->fail_states, TRUE);
	memory_pool_delete (trie->pool);
	g_free (trie);
}
