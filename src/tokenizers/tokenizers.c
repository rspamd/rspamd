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

struct tokenizer tokenizers[] = {
	{"osb-text", osb_tokenize_text, rspamd_tokenizer_get_word},
};

const int primes[] = {
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

struct tokenizer *
get_tokenizer (const char *name)
{
	guint i;

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
	const token_node_t *aa = a, *bb = b;

	if (aa->h1 == bb->h1) {
		return aa->h2 - bb->h2;
	}

	return aa->h1 - bb->h1;
}

/* Get next word from specified f_str_t buf */
gchar *
rspamd_tokenizer_get_word (rspamd_fstring_t * buf, rspamd_fstring_t * token, GList **exceptions)
{
	gsize remain, pos;
	guchar *p;
	struct process_exception *ex = NULL;

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

	pos = token->begin - buf->begin;
	if (pos >= buf->len) {
		return NULL;
	}

	remain = buf->len - pos;
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
		p++;
	}

	if (remain == 0) {
		return NULL;
	}

	return p;
}

GArray *
rspamd_tokenize_text (gchar *text, gsize len, gboolean is_utf,
		gsize min_len, GList **exceptions)
{
	rspamd_fstring_t token, buf;
	gchar *pos;
	gsize l;
	GArray *res;

	if (len == 0 || text == NULL) {
		return NULL;
	}

	buf.begin = text;
	buf.len = len;
	buf.size = buf.len;
	token.begin = NULL;
	token.len = 0;

	res = g_array_new (FALSE, FALSE, sizeof (rspamd_fstring_t));
	while ((pos = rspamd_tokenizer_get_word (&buf,
			&token, exceptions)) != NULL) {
		if (is_utf) {
			l = g_utf8_strlen (token.begin, token.len);
		}
		else {
			l = token.len;
		}
		if (min_len > 0 && l < min_len) {
			token.begin = pos;
			continue;
		}
		g_array_append_val (res, token);

		token.begin = pos;
	}

	return res;
}


void
tokenize_subject (struct rspamd_task *task, GTree ** tree)
{
	rspamd_fstring_t subject;
	const gchar *sub;
	struct tokenizer *osb_tokenizer;

	if (*tree == NULL) {
		*tree = g_tree_new (token_node_compare_func);
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_tree_destroy, *tree);
	}

	osb_tokenizer = get_tokenizer ("osb-text");

	/* Try to use pre-defined subject */
	if (task->subject != NULL) {
		subject.begin = task->subject;
		subject.len = strlen (task->subject);
		osb_tokenizer->tokenize_func (osb_tokenizer,
			task->task_pool,
			&subject,
			tree,
			FALSE,
			TRUE,
			NULL);
	}
	if ((sub = g_mime_message_get_subject (task->message)) != NULL) {
		subject.begin = (gchar *)sub;
		subject.len = strlen (sub);
		osb_tokenizer->tokenize_func (osb_tokenizer,
			task->task_pool,
			&subject,
			tree,
			FALSE,
			TRUE,
			NULL);
	}
}

/*
 * vi:ts=4
 */
