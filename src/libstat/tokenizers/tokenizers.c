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
#include <unicode/utf8.h>
#include <unicode/uchar.h>
#include <unicode/uiter.h>
#include <unicode/ubrk.h>

typedef gboolean (*token_get_function) (rspamd_stat_token_t * buf, gchar const **pos,
		rspamd_stat_token_t * token,
		GList **exceptions, gsize *rl, gboolean check_signature);

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

/* Get next word from specified f_str_t buf */
static gboolean
rspamd_tokenizer_get_word_raw (rspamd_stat_token_t * buf,
		gchar const **cur, rspamd_stat_token_t * token,
		GList **exceptions, gsize *rl, gboolean unused)
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
				token->flags = RSPAMD_STAT_TOKEN_FLAG_EXCEPTION;
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
		*rl = token->len;
	}

	token->flags = RSPAMD_STAT_TOKEN_FLAG_TEXT;

	*cur = p;

	return TRUE;
}

static inline gboolean
rspamd_tokenize_check_limit (gboolean decay,
							 guint word_decay,
							 guint nwords,
							 guint64 *hv,
							 guint64 *prob,
							 const rspamd_stat_token_t *token,
							 gssize remain,
							 gssize total)
{
	static const gdouble avg_word_len = 6.0;

	if (!decay) {
		if (token->len >= sizeof (guint64)) {
#ifdef _MUM_UNALIGNED_ACCESS
			*hv = mum_hash_step (*hv, *(guint64 *)token->begin);
#else
			guint64 tmp;
			memcpy (&tmp, token->begin, sizeof (tmp));
			*hv = mum_hash_step (*hv, tmp);
#endif
		}

		/* Check for decay */
		if (word_decay > 0 && nwords > word_decay && remain < (gssize)total) {
			/* Start decay */
			gdouble decay_prob;

			*hv = mum_hash_finish (*hv);

			/* We assume that word is 6 symbols length in average */
			decay_prob = (gdouble)word_decay / ((total - (remain)) / avg_word_len);

			if (decay_prob >= 1.0) {
				*prob = G_MAXUINT64;
			}
			else {
				*prob = decay_prob * G_MAXUINT64;
			}

			return TRUE;
		}
	}
	else {
		/* Decaying probability */
		/* LCG64 x[n] = a x[n - 1] + b mod 2^64 */
		*hv = (*hv) * 2862933555777941757ULL + 3037000493ULL;

		if (*hv > *prob) {
			return TRUE;
		}
	}

	return FALSE;
}

static inline gboolean
rspamd_utf_word_valid (const gchar *text, const gchar *end,
		gint32 start, gint32 finish)
{
	const gchar *st = text + start, *fin = text + finish;
	UChar32 c;

	if (st >= end || fin > end || st >= fin) {
		return FALSE;
	}

	U8_NEXT (text, start, finish, c);

	if (u_isalnum (c)) {
		return TRUE;
	}

	return FALSE;
}
#define SHIFT_EX do { \
    cur = g_list_next (cur); \
    if (cur) { \
        ex = (struct rspamd_process_exception *) cur->data; \
    } \
    else { \
        ex = NULL; \
    } \
} while(0)

GArray *
rspamd_tokenize_text (const gchar *text, gsize len,
					  const UText *utxt,
					  enum rspamd_tokenize_type how,
					  struct rspamd_config *cfg,
					  GList *exceptions,
					  guint64 *hash)
{
	rspamd_stat_token_t token, buf;
	const gchar *pos = NULL;
	gsize l = 0;
	GArray *res;
	GList *cur = exceptions;
	guint min_len = 0, max_len = 0, word_decay = 0, initial_size = 128;
	guint64 hv = 0;
	gboolean decay = FALSE;
	guint64 prob;
	static UBreakIterator* bi = NULL;

	if (text == NULL) {
		return NULL;
	}

	buf.begin = text;
	buf.len = len;
	buf.flags = 0;
	token.begin = NULL;
	token.len = 0;
	token.flags = 0;

	if (cfg != NULL) {
		min_len = cfg->min_word_len;
		max_len = cfg->max_word_len;
		word_decay = cfg->words_decay;
		initial_size = word_decay * 2;
	}

	res = g_array_sized_new (FALSE, FALSE, sizeof (rspamd_stat_token_t),
			initial_size);

	if (G_UNLIKELY (how == RSPAMD_TOKENIZE_RAW || utxt == NULL)) {
		while (rspamd_tokenizer_get_word_raw (&buf, &pos, &token, &cur, &l, FALSE)) {
			if (l == 0 || (min_len > 0 && l < min_len) ||
				(max_len > 0 && l > max_len)) {
				token.begin = pos;
				continue;
			}

			if (rspamd_tokenize_check_limit (decay, word_decay, res->len,
					&hv, &prob, &token, pos - text, len)) {
				if (!decay) {
					decay = TRUE;
				}
				else {
					token.begin = pos;
					continue;
				}
			}

			g_array_append_val (res, token);
			token.begin = pos;
		}
	}
	else {
		/* UTF8 boundaries */
		UErrorCode uc_err = U_ZERO_ERROR;
		int32_t last, p;
		struct rspamd_process_exception *ex = NULL;

		if (bi == NULL) {
			bi = ubrk_open (UBRK_WORD, NULL, NULL, 0, &uc_err);

			g_assert (U_SUCCESS (uc_err));
		}

		ubrk_setUText (bi, (UText*)utxt, &uc_err);
		last = ubrk_first (bi);
		p = last;

		if (cur) {
			ex = (struct rspamd_process_exception *)cur->data;
		}

		while (p != UBRK_DONE) {
start_over:
			token.len = 0;

			if (p > last) {
				if (ex && cur) {
					/* Check exception */
					if (ex->pos >= last && ex->pos <= p) {
						/* We have an exception within boundary */
						/* First, start to drain exceptions from the start */
						while (cur && ex->pos <= last) {
							/* We have an exception at the beginning, skip those */
							last += ex->len;

							if (ex->type == RSPAMD_EXCEPTION_URL) {
								token.begin = "!!EX!!";
								token.len = sizeof ("!!EX!!") - 1;
								token.flags = RSPAMD_STAT_TOKEN_FLAG_EXCEPTION;

								g_array_append_val (res, token);
								token.flags = 0;
							}

							if (last > p) {
								/* Exception spread over the boundaries */
								while (last > p && p != UBRK_DONE) {
									p = ubrk_next (bi);
								}

								/* We need to reset our scan with new p and last */
								SHIFT_EX;
								goto start_over;
							}

							SHIFT_EX;
						}

						/* Now, we can have an exception within boundary again */
						if (cur && ex->pos >= last && ex->pos <= p) {
							/* Append the first part */
							if (rspamd_utf_word_valid (text, text + len, last,
									ex->pos)) {
								token.begin = text + last;
								token.len = ex->pos - last;
								token.flags = 0;
								g_array_append_val (res, token);
							}

							/* Process the current exception */
							last += ex->len + (ex->pos - last);

							if (ex->type == RSPAMD_EXCEPTION_URL) {
								token.begin = "!!EX!!";
								token.len = sizeof ("!!EX!!") - 1;
								token.flags = RSPAMD_STAT_TOKEN_FLAG_EXCEPTION;

								g_array_append_val (res, token);
							}

							if (last > p) {
								/* Exception spread over the boundaries */
								while (last > p && p != UBRK_DONE) {
									p = ubrk_next (bi);
								}
								/* We need to reset our scan with new p and last */
								SHIFT_EX;
								goto start_over;
							}

							SHIFT_EX;
						}
						else if (p > last) {
							if (rspamd_utf_word_valid (text, text + len, last, p)) {
								token.begin = text + last;
								token.len = p - last;
								token.flags = RSPAMD_STAT_TOKEN_FLAG_TEXT;
							}
						}
					}
					else if (ex->pos < last) {
						/* Forward exceptions list */
						while (cur && ex->pos <= last) {
							/* We have an exception at the beginning, skip those */
							SHIFT_EX;
						}

						if (rspamd_utf_word_valid (text, text + len, last, p)) {
							token.begin = text + last;
							token.len = p - last;
							token.flags = RSPAMD_STAT_TOKEN_FLAG_TEXT;
						}
					}
					else {
						/* No exceptions within boundary */
						if (rspamd_utf_word_valid (text, text + len, last, p)) {
							token.begin = text + last;
							token.len = p - last;
							token.flags = RSPAMD_STAT_TOKEN_FLAG_TEXT;
						}
					}
				}
				else {
					if (rspamd_utf_word_valid (text, text + len, last, p)) {
						token.begin = text + last;
						token.len = p - last;
						token.flags = RSPAMD_STAT_TOKEN_FLAG_TEXT;
					}
				}

				if (rspamd_tokenize_check_limit (decay, word_decay, res->len,
						&hv, &prob, &token, p, len)) {
					if (!decay) {
						decay = TRUE;
					} else {
						token.len = 0;
					}
				}
			}

			if (token.len > 0) {
				g_array_append_val (res, token);
			}

			last = p;
			p = ubrk_next (bi);
		}
	}

	if (!decay) {
		hv = mum_hash_finish (hv);
	}

	if (hash) {
		*hash = hv;
	}

	return res;
}

#undef SHIFT_EX

/*
 * vi:ts=4
 */
