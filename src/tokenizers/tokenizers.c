/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
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

/*
 * Common tokenization functions
 */

#include <sys/types.h>
#include "main.h"
#include "tokenizers.h"

struct tokenizer                tokenizers[] = {
	{"osb-text", osb_tokenize_text, get_next_word},
};

const int                       primes[] = {
	1, 7,
	3, 13,
	5, 29,
	11, 51,
	23, 101,
	47, 203,
	97, 407,
	197, 817,
	397, 1637,
	797, 3277,
};

const gchar t_delimiters[255] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 1, 0, 1, 1, 1, 1, 1, 0,
		1, 1, 1, 1, 1, 1, 1, 1, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
		1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 1, 1, 1, 1, 1, 1, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 1, 1, 1, 1, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0
};

struct tokenizer               *
get_tokenizer (const char *name)
{
	guint                            i;

	for (i = 0; i < sizeof (tokenizers) / sizeof (tokenizers[0]); i++) {
		if (strcmp (tokenizers[i].name, name) == 0) {
			return &tokenizers[i];
		}
	}

	return NULL;
}

int
token_node_compare_func (gconstpointer a, gconstpointer b)
{
	const token_node_t             *aa = a, *bb = b;

	if (aa->h1 == bb->h1) {
		return aa->h2 - bb->h2;
	}

	return aa->h1 - bb->h1;
}

/* Get next word from specified f_str_t buf */
gchar *
get_next_word (f_str_t * buf, f_str_t * token, GList **exceptions)
{
	gsize                           remain, pos;
	guchar                         *p;
	struct process_exception	   *ex = NULL;

	if (buf == NULL) {
		return NULL;
	}

	if (*exceptions != NULL) {
		ex = (*exceptions)->data;
	}

	if (token->begin == NULL) {
		if (ex != NULL) {
			if (ex->pos == 0) {
				token->begin = buf->begin + ex->len;
				token->len = ex->len;
			}
			else {
				token->begin = buf->begin;
				token->len = 0;
			}
		}
		else {
			token->begin = buf->begin;
			token->len = 0;
		}
	}

	token->len = 0;

	remain = buf->len - (token->begin - buf->begin);
	if (remain == 0) {
		return NULL;
	}
	pos = token->begin - buf->begin;
	p = token->begin;
	/* Skip non delimiters symbols */
	do {
		if (ex != NULL && ex->pos == pos) {
			/* Go to the next exception */
			*exceptions = g_list_next (*exceptions);
			return p + ex->len;
		}
		pos++;
		p++;
		remain--;
	} while (remain > 0 && t_delimiters[*p]);

	token->begin = p;

	while (remain > 0 && !t_delimiters[*p]) {
		if (ex != NULL && ex->pos == pos) {
			*exceptions = g_list_next (*exceptions);
			return p + ex->len;
		}
		token->len++;
		pos++;
		remain--;
		p ++;
	}

	if (remain == 0) {
		return NULL;
	}

	return p;
}

/* Struct to access gmime headers */
struct raw_header {
	struct raw_header              *next;
	char                           *name;
	char                           *value;
};

typedef struct _GMimeHeader {
	GHashTable                     *hash;
	GHashTable                     *writers;
	struct raw_header              *headers;
} local_GMimeHeader;

int
tokenize_headers (rspamd_mempool_t * pool, struct worker_task *task, GTree ** tree)
{
	token_node_t                   *new = NULL;
	f_str_t                         headername;
	f_str_t                         headervalue;

	if (*tree == NULL) {
		*tree = g_tree_new (token_node_compare_func);
		rspamd_mempool_add_destructor (pool, (rspamd_mempool_destruct_t) g_tree_destroy, *tree);
	}
#ifndef GMIME24
	struct raw_header              *h;

	h = GMIME_OBJECT (task->message)->headers->headers;
	while (h) {
		if (h->name && h->value) {
			new = rspamd_mempool_alloc (pool, sizeof (token_node_t));
			headername.begin = h->name;
			headername.len = strlen (h->name);
			headervalue.begin = h->value;
			headervalue.len = strlen (h->value);
			new->h1 = fstrhash (&headername) * primes[0];
			new->h2 = fstrhash (&headervalue) * primes[1];
			if (g_tree_lookup (*tree, new) == NULL) {
				g_tree_insert (*tree, new, new);
			}
		}
		h = h->next;
	}
#else
	GMimeHeaderList                *ls;
	GMimeHeaderIter                *iter;
	const char                     *name;
	const char                     *value;

	ls = GMIME_OBJECT (task->message)->headers;
	iter = g_mime_header_iter_new ();

	if (g_mime_header_list_get_iter (ls, iter)) {
		while (g_mime_header_iter_is_valid (iter)) {
			new = rspamd_mempool_alloc (pool, sizeof (token_node_t));
			name = g_mime_header_iter_get_name (iter);
			value = g_mime_header_iter_get_value (iter);
			headername.begin = (u_char *)name;
			headername.len = strlen (name);
			headervalue.begin = (u_char *)value;
			headervalue.len = strlen (value);
			new->h1 = fstrhash (&headername) * primes[0];
			new->h2 = fstrhash (&headervalue) * primes[1];
			if (g_tree_lookup (*tree, new) == NULL) {
				g_tree_insert (*tree, new, new);
			}
			if (!g_mime_header_iter_next (iter)) {
				break;
			}
		}
	}
	g_mime_header_iter_free (iter);
#endif
	return TRUE;
}

void
tokenize_subject (struct worker_task *task, GTree ** tree)
{
	f_str_t                         subject;
	const gchar                    *sub;
	struct tokenizer               *osb_tokenizer;

	if (*tree == NULL) {
		*tree = g_tree_new (token_node_compare_func);
		rspamd_mempool_add_destructor (task->task_pool, (rspamd_mempool_destruct_t) g_tree_destroy, *tree);
	}

	osb_tokenizer = get_tokenizer ("osb-text");

	/* Try to use pre-defined subject */
	if (task->subject != NULL) {
		subject.begin = task->subject;
		subject.len = strlen (task->subject);
		osb_tokenizer->tokenize_func (osb_tokenizer, task->task_pool, &subject, tree, FALSE, TRUE, NULL);
	}
	if ((sub = g_mime_message_get_subject (task->message)) != NULL) {
		subject.begin = (gchar *)sub;
		subject.len = strlen (sub);
		osb_tokenizer->tokenize_func (osb_tokenizer, task->task_pool, &subject, tree, FALSE, TRUE, NULL);
	}
}

/*
 * vi:ts=4
 */
