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
#include "contrib/mumhash/mum.h"
#include "libmime/lang_detection.h"
#include "libstemmer.h"

#include <unicode/utf8.h>
#include <unicode/uchar.h>
#include <unicode/uiter.h>
#include <unicode/ubrk.h>
#include <unicode/ucnv.h>
#if U_ICU_VERSION_MAJOR_NUM >= 44
#include <unicode/unorm2.h>
#endif

#include <math.h>

typedef gboolean (*token_get_function) (rspamd_stat_token_t * buf, gchar const **pos,
		rspamd_stat_token_t * token,
		GList **exceptions, gsize *rl, gboolean check_signature);

const gchar t_delimiters[256] = {
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
	0, 0, 0, 0, 0, 0
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

	if (token->original.begin == NULL || *cur == NULL) {
		if (ex != NULL) {
			if (ex->pos == 0) {
				token->original.begin = buf->original.begin + ex->len;
				token->original.len = ex->len;
				token->flags = RSPAMD_STAT_TOKEN_FLAG_EXCEPTION;
			}
			else {
				token->original.begin = buf->original.begin;
				token->original.len = 0;
			}
		}
		else {
			token->original.begin = buf->original.begin;
			token->original.len = 0;
		}
		*cur = token->original.begin;
	}

	token->original.len = 0;

	pos = *cur - buf->original.begin;
	if (pos >= buf->original.len) {
		return FALSE;
	}

	remain = buf->original.len - pos;
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

	token->original.begin = p;

	while (remain > 0 && !t_delimiters[(guchar)*p]) {
		if (ex != NULL && ex->pos == pos) {
			*exceptions = g_list_next (*exceptions);
			*cur = p + ex->len;
			return TRUE;
		}
		token->original.len++;
		pos++;
		remain--;
		p++;
	}

	if (remain == 0) {
		return FALSE;
	}

	if (rl) {
		*rl = token->original.len;
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
		if (token->original.len >= sizeof (guint64)) {
			guint64 tmp;
			memcpy (&tmp, token->original.begin, sizeof (tmp));
			*hv = mum_hash_step (*hv, tmp);
		}

		/* Check for decay */
		if (word_decay > 0 && nwords > word_decay && remain < (gssize)total) {
			/* Start decay */
			gdouble decay_prob;

			*hv = mum_hash_finish (*hv);

			/* We assume that word is 6 symbols length in average */
			decay_prob = (gdouble)word_decay / ((total - (remain)) / avg_word_len) * 10;
			decay_prob = floor (decay_prob) / 10.0;

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
rspamd_utf_word_valid (const guchar *text, const guchar *end,
		gint32 start, gint32 finish)
{
	const guchar *st = text + start, *fin = text + finish;
	UChar32 c;

	if (st >= end || fin > end || st >= fin) {
		return FALSE;
	}

	U8_NEXT (text, start, finish, c);

	if (u_isJavaIDPart (c)) {
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

static inline void
rspamd_tokenize_exception (struct rspamd_process_exception *ex, GArray *res)
{
	rspamd_stat_token_t token;

	memset (&token, 0, sizeof (token));

	if (ex->type == RSPAMD_EXCEPTION_GENERIC) {
		token.original.begin = "!!EX!!";
		token.original.len = sizeof ("!!EX!!") - 1;
		token.flags = RSPAMD_STAT_TOKEN_FLAG_EXCEPTION;

		g_array_append_val (res, token);
		token.flags = 0;
	}
	else if (ex->type == RSPAMD_EXCEPTION_URL) {
		struct rspamd_url *uri;

		uri = ex->ptr;

		if (uri && uri->tldlen > 0) {
			token.original.begin = rspamd_url_tld_unsafe (uri);
			token.original.len = uri->tldlen;

		}
		else {
			token.original.begin = "!!EX!!";
			token.original.len = sizeof ("!!EX!!") - 1;
		}

		token.flags = RSPAMD_STAT_TOKEN_FLAG_EXCEPTION;
		g_array_append_val (res, token);
		token.flags = 0;
	}
}


GArray *
rspamd_tokenize_text (const gchar *text, gsize len,
					  const UText *utxt,
					  enum rspamd_tokenize_type how,
					  struct rspamd_config *cfg,
					  GList *exceptions,
					  guint64 *hash,
					  GArray *cur_words,
					  rspamd_mempool_t *pool)
{
	rspamd_stat_token_t token, buf;
	const gchar *pos = NULL;
	gsize l = 0;
	GArray *res;
	GList *cur = exceptions;
	guint min_len = 0, max_len = 0, word_decay = 0, initial_size = 128;
	guint64 hv = 0;
	gboolean decay = FALSE, long_text_mode = FALSE;
	guint64 prob = 0;
	static UBreakIterator* bi = NULL;
	static const gsize long_text_limit = 1 * 1024 * 1024;
	static const ev_tstamp max_exec_time = 0.2; /* 200 ms */
	ev_tstamp start;

	if (text == NULL) {
		return cur_words;
	}

	if (len > long_text_limit) {
		/*
		 * In this mode we do additional checks to avoid performance issues
		 */
		long_text_mode = TRUE;
		start = ev_time ();
	}

	buf.original.begin = text;
	buf.original.len = len;
	buf.flags = 0;

	memset (&token, 0, sizeof (token));

	if (cfg != NULL) {
		min_len = cfg->min_word_len;
		max_len = cfg->max_word_len;
		word_decay = cfg->words_decay;
		initial_size = word_decay * 2;
	}

	if (!cur_words) {
		res = g_array_sized_new (FALSE, FALSE, sizeof (rspamd_stat_token_t),
				initial_size);
	}
	else {
		res = cur_words;
	}

	if (G_UNLIKELY (how == RSPAMD_TOKENIZE_RAW || utxt == NULL)) {
		while (rspamd_tokenizer_get_word_raw (&buf, &pos, &token, &cur, &l, FALSE)) {
			if (l == 0 || (min_len > 0 && l < min_len) ||
				(max_len > 0 && l > max_len)) {
				token.original.begin = pos;
				continue;
			}

			if (token.original.len > 0 &&
				rspamd_tokenize_check_limit (decay, word_decay, res->len,
					&hv, &prob, &token, pos - text, len)) {
				if (!decay) {
					decay = TRUE;
				}
				else {
					token.original.begin = pos;
					continue;
				}
			}

			if (long_text_mode) {
				if ((res->len + 1) % 16 == 0) {
					ev_tstamp now = ev_time ();

					if (now - start > max_exec_time) {
						msg_warn_pool_check (
								"too long time has been spent on tokenization:"
								  " %.1f ms, limit is %.1f ms; %d words added so far",
								(now - start) * 1e3, max_exec_time * 1e3,
								res->len);

						goto end;
					}
				}
			}

			g_array_append_val (res, token);

			if (((gsize)res->len) * sizeof (token) > (0x1ull << 30u)) {
				/* Due to bug in glib ! */
				msg_err_pool_check (
						"too many words found: %d, stop tokenization to avoid DoS",
						res->len);

				goto end;
			}

			token.original.begin = pos;
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
			token.original.len = 0;

			if (p > last) {
				if (ex && cur) {
					/* Check exception */
					if (ex->pos >= last && ex->pos <= p) {
						/* We have an exception within boundary */
						/* First, start to drain exceptions from the start */
						while (cur && ex->pos <= last) {
							/* We have an exception at the beginning, skip those */
							last += ex->len;
							rspamd_tokenize_exception (ex, res);

							if (last > p) {
								/* Exception spread over the boundaries */
								while (last > p && p != UBRK_DONE) {
									gint32 old_p = p;
									p = ubrk_next (bi);

									if (p != UBRK_DONE && p <= old_p) {
										msg_warn_pool_check (
												"tokenization reversed back on position %d,"
												"%d new position (%d backward), likely libicu bug!",
												(gint)(p), (gint)(old_p), old_p - p);

										goto end;
									}
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
								token.original.begin = text + last;
								token.original.len = ex->pos - last;
								token.flags = RSPAMD_STAT_TOKEN_FLAG_TEXT |
											  RSPAMD_STAT_TOKEN_FLAG_UTF;
							}

							/* Process the current exception */
							last += ex->len + (ex->pos - last);

							rspamd_tokenize_exception (ex, res);

							if (last > p) {
								/* Exception spread over the boundaries */
								while (last > p && p != UBRK_DONE) {
									gint32 old_p = p;
									p = ubrk_next (bi);
									if (p != UBRK_DONE && p <= old_p) {
										msg_warn_pool_check (
												"tokenization reversed back on position %d,"
												"%d new position (%d backward), likely libicu bug!",
												(gint)(p), (gint)(old_p), old_p - p);

										goto end;
									}
								}
								/* We need to reset our scan with new p and last */
								SHIFT_EX;
								goto start_over;
							}

							SHIFT_EX;
						}
						else if (p > last) {
							if (rspamd_utf_word_valid (text, text + len, last, p)) {
								token.original.begin = text + last;
								token.original.len = p - last;
								token.flags = RSPAMD_STAT_TOKEN_FLAG_TEXT |
											  RSPAMD_STAT_TOKEN_FLAG_UTF;
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
							token.original.begin = text + last;
							token.original.len = p - last;
							token.flags = RSPAMD_STAT_TOKEN_FLAG_TEXT |
										  RSPAMD_STAT_TOKEN_FLAG_UTF;
						}
					}
					else {
						/* No exceptions within boundary */
						if (rspamd_utf_word_valid (text, text + len, last, p)) {
							token.original.begin = text + last;
							token.original.len = p - last;
							token.flags = RSPAMD_STAT_TOKEN_FLAG_TEXT |
										  RSPAMD_STAT_TOKEN_FLAG_UTF;
						}
					}
				}
				else {
					if (rspamd_utf_word_valid (text, text + len, last, p)) {
						token.original.begin = text + last;
						token.original.len = p - last;
						token.flags = RSPAMD_STAT_TOKEN_FLAG_TEXT |
									  RSPAMD_STAT_TOKEN_FLAG_UTF;
					}
				}

				if (token.original.len > 0 &&
					rspamd_tokenize_check_limit (decay, word_decay, res->len,
						&hv, &prob, &token, p, len)) {
					if (!decay) {
						decay = TRUE;
					} else {
						token.flags |= RSPAMD_STAT_TOKEN_FLAG_SKIPPED;
					}
				}
			}

			if (token.original.len > 0) {
				/* Additional check for number of words */
				if (((gsize)res->len) * sizeof (token) > (0x1ull << 30u)) {
					/* Due to bug in glib ! */
					msg_err ("too many words found: %d, stop tokenization to avoid DoS",
							res->len);

					goto end;
				}

				g_array_append_val (res, token);
			}

			/* Also check for long text mode */
			if (long_text_mode) {
				/* Check time each 128 words added */
				const int words_check_mask = 0x7F;

				if ((res->len & words_check_mask) == words_check_mask) {
					ev_tstamp now = ev_time ();

					if (now - start > max_exec_time) {
						msg_warn_pool_check (
								"too long time has been spent on tokenization:"
								  " %.1f ms, limit is %.1f ms; %d words added so far",
								(now - start) * 1e3, max_exec_time * 1e3,
								res->len);

						goto end;
					}
				}
			}

			last = p;
			p = ubrk_next (bi);

			if (p != UBRK_DONE && p <= last) {
				msg_warn_pool_check ("tokenization reversed back on position %d,"
						 "%d new position (%d backward), likely libicu bug!",
						(gint)(p), (gint)(last), last - p);

				goto end;
			}
		}
	}

end:
	if (!decay) {
		hv = mum_hash_finish (hv);
	}

	if (hash) {
		*hash = hv;
	}

	return res;
}

#undef SHIFT_EX

static void
rspamd_add_metawords_from_str (const gchar *beg, gsize len,
								struct rspamd_task *task)
{
	UText utxt = UTEXT_INITIALIZER;
	UErrorCode uc_err = U_ZERO_ERROR;
	guint i = 0;
	UChar32 uc;
	gboolean valid_utf = TRUE;

	while (i < len) {
		U8_NEXT (beg, i, len, uc);

		if (((gint32) uc) < 0) {
			valid_utf = FALSE;
			break;
		}

#if U_ICU_VERSION_MAJOR_NUM < 50
		if (u_isalpha (uc)) {
			gint32 sc = ublock_getCode (uc);

			if (sc == UBLOCK_THAI) {
				valid_utf = FALSE;
				msg_info_task ("enable workaround for Thai characters for old libicu");
				break;
			}
		}
#endif
	}

	if (valid_utf) {
		utext_openUTF8 (&utxt,
				beg,
				len,
				&uc_err);

		task->meta_words = rspamd_tokenize_text (beg, len,
				&utxt, RSPAMD_TOKENIZE_UTF,
				task->cfg, NULL, NULL,
				task->meta_words,
				task->task_pool);

		utext_close (&utxt);
	}
	else {
		task->meta_words = rspamd_tokenize_text (beg, len,
				NULL, RSPAMD_TOKENIZE_RAW,
				task->cfg, NULL, NULL, task->meta_words,
				task->task_pool);
	}
}

void
rspamd_tokenize_meta_words (struct rspamd_task *task)
{
	guint i = 0;
	rspamd_stat_token_t *tok;

	if (MESSAGE_FIELD (task, subject)) {
		rspamd_add_metawords_from_str (MESSAGE_FIELD (task, subject),
				strlen (MESSAGE_FIELD (task, subject)), task);
	}

	if (MESSAGE_FIELD (task, from_mime) && MESSAGE_FIELD (task, from_mime)->len > 0) {
		struct rspamd_email_address *addr;

		addr = g_ptr_array_index (MESSAGE_FIELD (task, from_mime), 0);

		if (addr->name) {
			rspamd_add_metawords_from_str (addr->name, strlen (addr->name), task);
		}
	}

	if (task->meta_words != NULL) {
		const gchar *language = NULL;

		if (MESSAGE_FIELD (task, text_parts) &&
				MESSAGE_FIELD (task, text_parts)->len > 0) {
			struct rspamd_mime_text_part *tp = g_ptr_array_index (
					MESSAGE_FIELD (task, text_parts), 0);

			if (tp->language) {
				language = tp->language;
			}
		}

		rspamd_normalize_words (task->meta_words, task->task_pool);
		rspamd_stem_words (task->meta_words, task->task_pool, language,
				task->lang_det);

		for (i = 0; i < task->meta_words->len; i++) {
			tok = &g_array_index (task->meta_words, rspamd_stat_token_t, i);
			tok->flags |= RSPAMD_STAT_TOKEN_FLAG_HEADER;
		}
	}
}

static inline void
rspamd_uchars_to_ucs32 (const UChar *src, gsize srclen,
						rspamd_stat_token_t *tok,
						rspamd_mempool_t *pool)
{
	UChar32 *dest, t, *d;
	gint32 i = 0;

	dest = rspamd_mempool_alloc (pool, srclen * sizeof (UChar32));
	d = dest;

	while (i < srclen) {
		U16_NEXT_UNSAFE (src, i, t);

		if (u_isgraph (t)) {
			UCharCategory cat;

			cat = u_charType (t);
#if U_ICU_VERSION_MAJOR_NUM >= 57
			if (u_hasBinaryProperty (t, UCHAR_EMOJI)) {
				tok->flags |= RSPAMD_STAT_TOKEN_FLAG_EMOJI;
			}
#endif

			if ((cat >= U_UPPERCASE_LETTER && cat <= U_OTHER_NUMBER) ||
					cat == U_CONNECTOR_PUNCTUATION ||
					cat == U_MATH_SYMBOL ||
					cat == U_CURRENCY_SYMBOL) {
				*d++ = u_tolower (t);
			}
		}
		else {
			/* Invisible spaces ! */
			tok->flags |= RSPAMD_STAT_TOKEN_FLAG_INVISIBLE_SPACES;
		}
	}

	tok->unicode.begin = dest;
	tok->unicode.len = d - dest;
}

static inline void
rspamd_ucs32_to_normalised (rspamd_stat_token_t *tok,
							rspamd_mempool_t *pool)
{
	guint i, doff = 0;
	gsize utflen = 0;
	gchar *dest;
	UChar32 t;

	for (i = 0; i < tok->unicode.len; i ++) {
		utflen += U8_LENGTH (tok->unicode.begin[i]);
	}

	dest = rspamd_mempool_alloc (pool, utflen + 1);

	for (i = 0; i < tok->unicode.len; i ++) {
		t = tok->unicode.begin[i];
		U8_APPEND_UNSAFE (dest, doff, t);
	}

	g_assert (doff <= utflen);
	dest[doff] = '\0';

	tok->normalized.len = doff;
	tok->normalized.begin = dest;
}

void
rspamd_normalize_single_word (rspamd_stat_token_t *tok, rspamd_mempool_t *pool)
{
	UErrorCode uc_err = U_ZERO_ERROR;
	UConverter *utf8_converter;
	UChar tmpbuf[1024]; /* Assume that we have no longer words... */
	gsize ulen;

	utf8_converter = rspamd_get_utf8_converter ();

	if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_UTF) {
		ulen = ucnv_toUChars (utf8_converter,
				tmpbuf,
				G_N_ELEMENTS (tmpbuf),
				tok->original.begin,
				tok->original.len,
				&uc_err);

		/* Now, we need to understand if we need to normalise the word */
		if (!U_SUCCESS (uc_err)) {
			tok->flags |= RSPAMD_STAT_TOKEN_FLAG_BROKEN_UNICODE;
			tok->unicode.begin = NULL;
			tok->unicode.len = 0;
			tok->normalized.begin = NULL;
			tok->normalized.len = 0;
		}
		else {
#if U_ICU_VERSION_MAJOR_NUM >= 44
			const UNormalizer2 *norm = rspamd_get_unicode_normalizer ();
			gint32 end;

			/* We can now check if we need to decompose */
			end = unorm2_spanQuickCheckYes (norm, tmpbuf, ulen, &uc_err);

			if (!U_SUCCESS (uc_err)) {
				rspamd_uchars_to_ucs32 (tmpbuf, ulen, tok, pool);
				tok->normalized.begin = NULL;
				tok->normalized.len = 0;
				tok->flags |= RSPAMD_STAT_TOKEN_FLAG_BROKEN_UNICODE;
			}
			else {
				if (end == ulen) {
					/* Already normalised, just lowercase */
					rspamd_uchars_to_ucs32 (tmpbuf, ulen, tok, pool);
					rspamd_ucs32_to_normalised (tok, pool);
				}
				else {
					/* Perform normalization */
					UChar normbuf[1024];

					g_assert (end < G_N_ELEMENTS (normbuf));
					/* First part */
					memcpy (normbuf, tmpbuf, end * sizeof (UChar));
					/* Second part */
					ulen = unorm2_normalizeSecondAndAppend (norm,
							normbuf, end,
							G_N_ELEMENTS (normbuf),
							tmpbuf + end,
							ulen - end,
							&uc_err);

					if (!U_SUCCESS (uc_err)) {
						if (uc_err != U_BUFFER_OVERFLOW_ERROR) {
							msg_warn_pool_check ("cannot normalise text '%*s': %s",
									(gint)tok->original.len, tok->original.begin,
									u_errorName (uc_err));
							rspamd_uchars_to_ucs32 (tmpbuf, ulen, tok, pool);
							rspamd_ucs32_to_normalised (tok, pool);
							tok->flags |= RSPAMD_STAT_TOKEN_FLAG_BROKEN_UNICODE;
						}
					}
					else {
						/* Copy normalised back */
						rspamd_uchars_to_ucs32 (normbuf, ulen, tok, pool);
						tok->flags |= RSPAMD_STAT_TOKEN_FLAG_NORMALISED;
						rspamd_ucs32_to_normalised (tok, pool);
					}
				}
			}
#else
			/* Legacy version with no unorm2 interface */
			rspamd_uchars_to_ucs32 (tmpbuf, ulen, tok, pool);
			rspamd_ucs32_to_normalised (tok, pool);
#endif
		}
	}
	else {
		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_TEXT) {
			/* Simple lowercase */
			gchar *dest;

			dest = rspamd_mempool_alloc (pool, tok->original.len + 1);
			rspamd_strlcpy (dest, tok->original.begin, tok->original.len + 1);
			rspamd_str_lc (dest, tok->original.len);
			tok->normalized.len = tok->original.len;
			tok->normalized.begin = dest;
		}
	}
}

void
rspamd_normalize_words (GArray *words, rspamd_mempool_t *pool)
{
	rspamd_stat_token_t *tok;
	guint i;

	for (i = 0; i < words->len; i++) {
		tok = &g_array_index (words, rspamd_stat_token_t, i);
		rspamd_normalize_single_word (tok, pool);
	}
}

void
rspamd_stem_words (GArray *words, rspamd_mempool_t *pool,
				   const gchar *language,
				   struct rspamd_lang_detector *d)
{
	static GHashTable *stemmers = NULL;
	struct sb_stemmer *stem = NULL;
	guint i;
	rspamd_stat_token_t *tok;
	gchar *dest;
	gsize dlen;

	if (!stemmers) {
		stemmers = g_hash_table_new (rspamd_strcase_hash,
				rspamd_strcase_equal);
	}

	if (language && language[0] != '\0') {
		stem = g_hash_table_lookup (stemmers, language);

		if (stem == NULL) {

			stem = sb_stemmer_new (language, "UTF_8");

			if (stem == NULL) {
				msg_debug_pool (
						"<%s> cannot create lemmatizer for %s language",
						language);
				g_hash_table_insert (stemmers, g_strdup (language),
						GINT_TO_POINTER (-1));
			}
			else {
				g_hash_table_insert (stemmers, g_strdup (language),
						stem);
			}
		}
		else if (stem == GINT_TO_POINTER (-1)) {
			/* Negative cache */
			stem = NULL;
		}
	}
	for (i = 0; i < words->len; i++) {
		tok = &g_array_index (words, rspamd_stat_token_t, i);

		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_UTF) {
			if (stem) {
				const gchar *stemmed = NULL;

				stemmed = sb_stemmer_stem (stem,
						tok->normalized.begin, tok->normalized.len);

				dlen = stemmed ? strlen (stemmed) : 0;

				if (dlen > 0) {
					dest = rspamd_mempool_alloc (pool, dlen + 1);
					memcpy (dest, stemmed, dlen);
					dest[dlen] = '\0';
					tok->stemmed.len = dlen;
					tok->stemmed.begin = dest;
					tok->flags |= RSPAMD_STAT_TOKEN_FLAG_STEMMED;
				}
				else {
					/* Fallback */
					tok->stemmed.len = tok->normalized.len;
					tok->stemmed.begin = tok->normalized.begin;
				}
			}
			else {
				tok->stemmed.len = tok->normalized.len;
				tok->stemmed.begin = tok->normalized.begin;
			}

			if (tok->stemmed.len > 0 && d != NULL &&
				rspamd_language_detector_is_stop_word (d, tok->stemmed.begin, tok->stemmed.len)) {
				tok->flags |= RSPAMD_STAT_TOKEN_FLAG_STOP_WORD;
			}
		}
		else {
			if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_TEXT) {
				/* Raw text, lowercase */
				tok->stemmed.len = tok->normalized.len;
				tok->stemmed.begin = tok->normalized.begin;
			}
		}
	}
}