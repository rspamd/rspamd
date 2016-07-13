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
/*
 * Common tokenization functions
 */

#include "rspamd.h"
#include "tokenizers.h"
#include "stat_internal.h"
#include "../../../contrib/mumhash/mum.h"

typedef gboolean (*token_get_function) (rspamd_ftok_t * buf, gchar const **pos,
		rspamd_ftok_t * token,
		GList **exceptions, gboolean is_utf, gsize *rl, gboolean check_signature);

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
rspamd_tokenizer_get_word_compat (rspamd_ftok_t * buf,
		gchar const **cur, rspamd_ftok_t * token,
		GList **exceptions, gboolean is_utf, gsize *rl, gboolean unused)
{
	gsize remain, pos;
	const gchar *p;
	struct rspamd_process_exception *ex = NULL;

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
	} while (remain > 0 && t_delimiters[(guchar)*p]);

	token->begin = p;

	while (remain > 0 && !t_delimiters[(guchar)*p]) {
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
rspamd_tokenizer_get_word (rspamd_ftok_t * buf,
		gchar const **cur, rspamd_ftok_t * token,
		GList **exceptions, gboolean is_utf, gsize *rl,
		gboolean check_signature)
{
	gsize remain, siglen = 0;
	goffset pos;
	const gchar *p, *next_p, *sig = NULL;
	gunichar uc;
	guint processed = 0;
	struct rspamd_process_exception *ex = NULL;
	enum {
		skip_delimiters = 0,
		feed_token,
		skip_exception,
		process_signature
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
			if (ex != NULL && p - buf->begin == ex->pos) {
				if (ex->type == RSPAMD_EXCEPTION_URL) {
					token->begin = "!!EX!!";
					token->len = sizeof ("!!EX!!") - 1;
					processed = token->len;
				}
				state = skip_exception;
				continue;
			}
			else if (g_unichar_isgraph (uc)) {
				if (!g_unichar_ispunct (uc)) {
					state = feed_token;
					token->begin = p;
					continue;
				}
				else if (check_signature && pos != 0 && (*p == '_' || *p == '-')) {
					sig = p;
					siglen = remain;
					state = process_signature;
					continue;
				}
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
		case process_signature:
			if (*p == '\r' || *p == '\n') {
				msg_debug ("signature found: %*s", (gint)siglen, sig);
				return FALSE;
			}
			else if (*p != ' ' && *p != '-' && *p != '_') {
				state = skip_delimiters;
				continue;
			}
			break;
		}

		remain -= next_p - p;
		p = next_p;
	}

set_token:
	if (rl) {
		*rl = processed;
	}

	if (token->len == 0 && processed > 0) {
		token->len = p - token->begin;
		g_assert (token->len > 0);
	}

	*cur = p;

	return TRUE;
}

GArray *
rspamd_tokenize_text (gchar *text, gsize len, gboolean is_utf,
		struct rspamd_config *cfg, GList *exceptions, gboolean compat,
		guint64 *hash)
{
	rspamd_ftok_t token, buf;
	const gchar *pos = NULL;
	gsize l;
	GArray *res;
	GList *cur = exceptions;
	token_get_function func;
	guint min_len = 0, max_len = 0, word_decay = 0, initial_size = 128;
	guint64 hv = 0;
	gboolean decay = FALSE;
	guint64 prob;

	if (text == NULL) {
		return NULL;
	}

	buf.begin = text;
	buf.len = len;
	token.begin = NULL;
	token.len = 0;

	if (compat || !is_utf) {
		func = rspamd_tokenizer_get_word_compat;
	}
	else {
		func = rspamd_tokenizer_get_word;
	}

	if (cfg != NULL) {
		min_len = cfg->min_word_len;
		max_len = cfg->max_word_len;
		word_decay = cfg->words_decay;
		initial_size = word_decay * 2;
	}

	res = g_array_sized_new (FALSE, FALSE, sizeof (rspamd_ftok_t), initial_size);

	while (func (&buf, &pos, &token, &cur, is_utf, &l, FALSE)) {
		if (l == 0 || (min_len > 0 && l < min_len) ||
					(max_len > 0 && l > max_len)) {
			token.begin = pos;
			continue;
		}

		if (!decay) {
			if (token.len >= sizeof (guint64)) {
#ifdef _MUM_UNALIGNED_ACCESS
				hv = mum_hash_step (hv, *(guint64 *)token.begin);
#else
				guint64 tmp;
				memcpy (&tmp, token.begin, sizeof (tmp));
				hv = mum_hash_step (hv, tmp);
#endif
			}

			/* Check for decay */
			if (word_decay > 0 && res->len > word_decay && pos - text < (gssize)len) {
				/* Start decay */
				gdouble decay_prob;

				decay = TRUE;
				hv = mum_hash_finish (hv);

				/* We assume that word is 6 symbols length in average */
				decay_prob = (gdouble)word_decay / ((len - (pos - text)) / 6.0);

				if (decay_prob >= 1.0) {
					prob = G_MAXUINT64;
				}
				else {
					prob = decay_prob * G_MAXUINT64;
				}
			}
		}
		else {
			/* Decaying probability */
			/* LCG64 x[n] = a x[n - 1] + b mod 2^64 */
			hv = 2862933555777941757ULL * hv + 3037000493ULL;

			if (hv > prob) {
				token.begin = pos;
				continue;
			}
		}

		g_array_append_val (res, token);
		token.begin = pos;
	}

	if (!decay) {
		hv = mum_hash_finish (hv);
	}

	if (hash) {
		*hash = hv;
	}

	return res;
}

/*
 * vi:ts=4
 */
