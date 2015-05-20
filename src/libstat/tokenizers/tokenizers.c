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

#include "main.h"
#include "tokenizers.h"
#include "stat_internal.h"

typedef gboolean (*token_get_function) (rspamd_fstring_t * buf, gchar **pos,
		rspamd_fstring_t * token,
		GList **exceptions, gboolean is_utf, gsize *rl);

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

gint
token_node_compare_func (gconstpointer a, gconstpointer b)
{
	const rspamd_token_t *aa = a, *bb = b;

	if (aa->datalen != bb->datalen) {
		return aa->datalen - bb->datalen;
	}

	return memcmp (aa->data, bb->data, aa->datalen);
}

/* Get next word from specified f_str_t buf */
static gboolean
rspamd_tokenizer_get_word_compat (rspamd_fstring_t * buf,
		gchar **cur, rspamd_fstring_t * token,
		GList **exceptions, gboolean is_utf, gsize *rl)
{
	gsize remain, pos;
	guchar *p;
	struct process_exception *ex = NULL;

	if (buf == NULL) {
		return FALSE;
	}

	g_assert (cur != NULL);

	if (exceptions != NULL && *exceptions != NULL) {
		ex = (*exceptions)->data;
	}

	if (token->begin == NULL || *cur == NULL) {
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
		*cur = token->begin;
	}

	token->len = 0;

	pos = *cur - buf->begin;
	if (pos >= buf->len) {
		return FALSE;
	}

	remain = buf->len - pos;
	p = *cur;

	/* Skip non delimiters symbols */
	do {
		if (ex != NULL && ex->pos == pos) {
			/* Go to the next exception */
			*exceptions = g_list_next (*exceptions);
			*cur = p + ex->len;
			return TRUE;
		}
		pos++;
		p++;
		remain--;
	} while (remain > 0 && t_delimiters[*p]);

	token->begin = p;

	while (remain > 0 && !t_delimiters[*p]) {
		if (ex != NULL && ex->pos == pos) {
			*exceptions = g_list_next (*exceptions);
			*cur = p + ex->len;
			return TRUE;
		}
		token->len++;
		pos++;
		remain--;
		p++;
	}

	if (remain == 0) {
		return FALSE;
	}

	if (rl) {
		if (is_utf) {
			*rl = g_utf8_strlen (token->begin, token->len);
		}
		else {
			*rl = token->len;
		}
	}

	*cur = p;

	return TRUE;
}

static gboolean
rspamd_tokenizer_get_word (rspamd_fstring_t * buf,
		gchar **cur, rspamd_fstring_t * token,
		GList **exceptions, gboolean is_utf, gsize *rl)
{
	gsize remain, pos;
	gchar *p, *next_p;
	gunichar uc;
	guint processed = 0;
	struct process_exception *ex = NULL;
	enum {
		skip_delimiters = 0,
		feed_token,
		skip_exception
	} state = skip_delimiters;

	if (buf == NULL) {
		return FALSE;
	}

	if (exceptions != NULL && *exceptions != NULL) {
		ex = (*exceptions)->data;
	}

	g_assert (is_utf);
	g_assert (cur != NULL);

	if (*cur == NULL) {
		*cur = buf->begin;
	}

	token->len = 0;

	pos = *cur - buf->begin;
	if (pos >= buf->len) {
		return FALSE;
	}

	remain = buf->len - pos;
	p = *cur;
	token->begin = p;

	while (remain > 0) {
		uc = g_utf8_get_char (p);
		next_p = g_utf8_next_char (p);

		if (next_p - p > (gint)remain) {
			return FALSE;
		}

		switch (state) {
		case skip_delimiters:
			if (ex != NULL && p - buf->begin == (gint)ex->pos) {
				token->begin = "exception";
				token->len = sizeof ("exception") - 1;
				state = skip_exception;
				continue;
			}
			else if (g_unichar_isgraph (uc) && !g_unichar_ispunct (uc)) {
				state = feed_token;
				token->begin = p;
				continue;
			}
			break;
		case feed_token:
			if (ex != NULL && p - buf->begin == (gint)ex->pos) {
				goto set_token;
			}
			else if (!g_unichar_isgraph (uc) || g_unichar_ispunct (uc)) {
				goto set_token;
			}
			processed ++;
			break;
		case skip_exception:
			*cur = p + ex->len;
			*exceptions = g_list_next (*exceptions);
			goto set_token;
			break;
		}

		remain -= next_p - p;
		p = next_p;
	}

set_token:
	if (rl) {
		*rl = processed;
	}

	token->len = p - token->begin;
	g_assert (token->len > 0);
	*cur = p;

	return TRUE;
}

GArray *
rspamd_tokenize_text (gchar *text, gsize len, gboolean is_utf,
		gsize min_len, GList *exceptions, gboolean compat)
{
	rspamd_fstring_t token, buf;
	gchar *pos = NULL;
	gsize l;
	GArray *res;
	GList *cur = exceptions;
	token_get_function func;

	if (len == 0 || text == NULL) {
		return NULL;
	}

	buf.begin = text;
	buf.len = len;
	buf.size = buf.len;
	token.begin = NULL;
	token.len = 0;

	if (compat || !is_utf) {
		func = rspamd_tokenizer_get_word_compat;
	}
	else {
		func = rspamd_tokenizer_get_word;
	}

	res = g_array_sized_new (FALSE, FALSE, sizeof (rspamd_fstring_t), 128);

	while (func (&buf, &pos, &token, &cur, is_utf, &l)) {
		if (l == 0 || (min_len > 0 && l < min_len)) {
			token.begin = pos;
			continue;
		}

		g_array_append_val (res, token);
		token.begin = pos;
	}

	return res;
}

/*
 * vi:ts=4
 */
