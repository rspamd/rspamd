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
#include "config.h"
#include "util.h"
#include "rspamd.h"
#include "message.h"
#include "html.h"
#include "images.h"
#include "archives.h"
#include "tokenizers/tokenizers.h"
#include "smtp_parsers.h"
#include "mime_parser.h"
#include "mime_encoding.h"
#include "lang_detection.h"
#include "libutil/multipattern.h"
#include "libserver/mempool_vars_internal.h"

#ifdef WITH_SNOWBALL
#include "libstemmer.h"
#endif

#include <math.h>
#include <unicode/uchar.h>

#define GTUBE_SYMBOL "GTUBE"

#define SET_PART_RAW(part) ((part)->flags &= ~RSPAMD_MIME_TEXT_PART_FLAG_UTF)
#define SET_PART_UTF(part) ((part)->flags |= RSPAMD_MIME_TEXT_PART_FLAG_UTF)

static const gchar gtube_pattern_reject[] = "XJS*C4JDBQADN1.NSBN3*2IDNEN*"
		"GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
static const gchar gtube_pattern_add_header[] = "YJS*C4JDBQADN1.NSBN3*2IDNEN*"
		"GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
static const gchar gtube_pattern_rewrite_subject[] = "ZJS*C4JDBQADN1.NSBN3*2IDNEN*"
		"GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
struct rspamd_multipattern *gtube_matcher = NULL;
static const guint64 words_hash_seed = 0xdeadbabe;


static void
free_byte_array_callback (void *pointer)
{
	GByteArray *arr = (GByteArray *) pointer;
	g_byte_array_free (arr, TRUE);
}

static void
rspamd_mime_part_extract_words (struct rspamd_task *task,
		struct rspamd_mime_text_part *part)
{
	rspamd_stat_token_t *w;
	guint i, total_len = 0, short_len = 0;

	if (part->utf_words) {
		rspamd_stem_words (part->utf_words, task->task_pool, part->language,
					task->lang_det);

		for (i = 0; i < part->utf_words->len; i++) {
			guint64 h;

			w = &g_array_index (part->utf_words, rspamd_stat_token_t, i);

			if (w->stemmed.len > 0) {
				/*
				 * We use static hash seed if we would want to use that in shingles
				 * computation in future
				 */
				h = rspamd_cryptobox_fast_hash_specific (
						RSPAMD_CRYPTOBOX_HASHFAST_INDEPENDENT,
						w->stemmed.begin, w->stemmed.len, words_hash_seed);
				g_array_append_val (part->normalized_hashes, h);
				total_len += w->stemmed.len;

				if (w->stemmed.len <= 3) {
					short_len++;
				}
			}

			if (w->flags & RSPAMD_STAT_TOKEN_FLAG_TEXT) {
				part->nwords ++;
			}

			if (w->flags & (RSPAMD_STAT_TOKEN_FLAG_BROKEN_UNICODE|
						RSPAMD_STAT_TOKEN_FLAG_NORMALISED|
					RSPAMD_STAT_TOKEN_FLAG_INVISIBLE_SPACES)) {
				task->flags |= RSPAMD_TASK_FLAG_BAD_UNICODE;
			}
		}

		if (part->utf_words->len) {
			gdouble *avg_len_p, *short_len_p;

			avg_len_p = rspamd_mempool_get_variable (task->task_pool,
					RSPAMD_MEMPOOL_AVG_WORDS_LEN);

			if (avg_len_p == NULL) {
				avg_len_p = rspamd_mempool_alloc (task->task_pool,
						sizeof (double));
				*avg_len_p = total_len;
				rspamd_mempool_set_variable (task->task_pool,
						RSPAMD_MEMPOOL_AVG_WORDS_LEN, avg_len_p, NULL);
			}
			else {
				*avg_len_p += total_len;
			}

			short_len_p = rspamd_mempool_get_variable (task->task_pool,
					RSPAMD_MEMPOOL_SHORT_WORDS_CNT);

			if (short_len_p == NULL) {
				short_len_p = rspamd_mempool_alloc (task->task_pool,
						sizeof (double));
				*short_len_p = short_len;
				rspamd_mempool_set_variable (task->task_pool,
						RSPAMD_MEMPOOL_SHORT_WORDS_CNT, avg_len_p, NULL);
			}
			else {
				*short_len_p += short_len;
			}
		}
	}
}

static void
rspamd_mime_part_create_words (struct rspamd_task *task,
		struct rspamd_mime_text_part *part)
{
	enum rspamd_tokenize_type tok_type;

	if (IS_PART_UTF (part)) {

#if U_ICU_VERSION_MAJOR_NUM < 50
		/* Hack to prevent hang with Thai in old libicu */
		const gchar *p = part->utf_stripped_content->data, *end;
		guint i = 0;
		end = p + part->utf_stripped_content->len;
		gint32 uc, sc;

		tok_type = RSPAMD_TOKENIZE_UTF;

		while (p + i < end) {
			U8_NEXT (p, i, part->utf_stripped_content->len, uc);

			if (((gint32) uc) < 0) {
				tok_type = RSPAMD_TOKENIZE_RAW;
				break;
			}

			if (u_isalpha (uc)) {
				sc = ublock_getCode (uc);

				if (sc == UBLOCK_THAI) {
					msg_info_task ("enable workaround for Thai characters for old libicu");
					tok_type = RSPAMD_TOKENIZE_RAW;
					break;
				}
			}
		}
#else
		tok_type = RSPAMD_TOKENIZE_UTF;
#endif
	}
	else {
		tok_type = RSPAMD_TOKENIZE_RAW;
	}

	part->utf_words = rspamd_tokenize_text (
			part->utf_stripped_content->data,
			part->utf_stripped_content->len,
			&part->utf_stripped_text,
			tok_type, task->cfg,
			part->exceptions,
			NULL, NULL);


	if (part->utf_words) {
		part->normalized_hashes = g_array_sized_new (FALSE, FALSE,
				sizeof (guint64), part->utf_words->len);
		rspamd_normalize_words (part->utf_words, task->task_pool);
	}

}

static void
rspamd_mime_part_detect_language (struct rspamd_task *task,
		struct rspamd_mime_text_part *part)
{
	struct rspamd_lang_detector_res *lang;

	if (!IS_PART_EMPTY (part) && part->utf_words && part->utf_words->len > 0 &&
			task->lang_det) {
		if (rspamd_language_detector_detect (task, task->lang_det, part)) {
			lang = g_ptr_array_index (part->languages, 0);
			part->language = lang->lang;

			msg_info_task ("detected part language: %s", part->language);
		}
		else {
			part->language = "en"; /* Safe fallback */
		}
	}
}

static void
rspamd_strip_newlines_parse (const gchar *begin, const gchar *pe,
		struct rspamd_mime_text_part *part)
{
	const gchar *p = begin, *c = begin;
	gchar last_c = '\0';
	gboolean crlf_added = FALSE;
	gboolean url_open_bracket = FALSE;

	enum {
		normal_char,
		seen_cr,
		seen_lf,
	} state = normal_char;

	while (p < pe) {
		if (G_UNLIKELY (*p) == '\r') {
			switch (state) {
			case normal_char:
				state = seen_cr;
				if (p > c) {
					last_c = *(p - 1);
					g_byte_array_append (part->utf_stripped_content,
							(const guint8 *)c, p - c);
				}

				crlf_added = FALSE;
				c = p + 1;
				break;
			case seen_cr:
				/* Double \r\r */
				if (!crlf_added) {
					g_byte_array_append (part->utf_stripped_content,
							(const guint8 *)" ", 1);
					crlf_added = TRUE;
					g_ptr_array_add (part->newlines,
							(((gpointer) (goffset) (part->utf_stripped_content->len))));
				}

				part->nlines ++;
				part->empty_lines ++;
				c = p + 1;
				break;
			case seen_lf:
				/* Likely \r\n\r...*/
				state = seen_cr;
				c = p + 1;
				break;
			}

			url_open_bracket = FALSE;

			p ++;
		}
		else if (G_UNLIKELY (*p == '\n')) {
			switch (state) {
			case normal_char:
				state = seen_lf;

				if (p > c) {
					last_c = *(p - 1);
					g_byte_array_append (part->utf_stripped_content,
							(const guint8 *)c, p - c);
				}

				c = p + 1;

				if (IS_PART_HTML (part) || !url_open_bracket) {
					g_byte_array_append (part->utf_stripped_content,
							(const guint8 *)" ", 1);
					g_ptr_array_add (part->newlines,
							(((gpointer) (goffset) (part->utf_stripped_content->len))));
					crlf_added = TRUE;
				}
				else {
					crlf_added = FALSE;
				}

				break;
			case seen_cr:
				/* \r\n */
				if (!crlf_added) {
					if (IS_PART_HTML (part) || !url_open_bracket) {
						g_byte_array_append (part->utf_stripped_content,
								(const guint8 *) " ", 1);
						crlf_added = TRUE;
					}

					g_ptr_array_add (part->newlines,
							(((gpointer) (goffset) (part->utf_stripped_content->len))));
				}

				c = p + 1;
				state = seen_lf;

				break;
			case seen_lf:
				/* Double \n\n */
				if (!crlf_added) {
					g_byte_array_append (part->utf_stripped_content,
							(const guint8 *)" ", 1);
					crlf_added = TRUE;
					g_ptr_array_add (part->newlines,
							(((gpointer) (goffset) (part->utf_stripped_content->len))));
				}

				part->nlines++;
				part->empty_lines ++;

				c = p + 1;
				break;
			}
			url_open_bracket = FALSE;

			p ++;
		}
		else {
			if ((*p) == '<') {
				url_open_bracket = TRUE;
			}
			else if ((*p) == '>') {
				url_open_bracket = FALSE;
			}

			switch (state) {
			case normal_char:
				if (G_UNLIKELY (*p) == ' ') {
					part->spaces ++;

					if (p > begin && *(p - 1) == ' ') {
						part->double_spaces ++;
					}
				}
				else {
					part->non_spaces ++;

					if (G_UNLIKELY (*p & 0x80)) {
						part->non_ascii_chars ++;
					}
					else {
						if (g_ascii_isupper (*p)) {
							part->capital_letters ++;
						}
						else if (g_ascii_isdigit (*p)) {
							part->numeric_characters ++;
						}

						part->ascii_chars ++;
					}
				}
				break;
			case seen_cr:
			case seen_lf:
				part->nlines ++;

				if (!crlf_added) {
					g_ptr_array_add (part->newlines,
							(((gpointer) (goffset) (part->utf_stripped_content->len))));
				}

				/* Skip initial spaces */
				if (G_UNLIKELY (*p == ' ')) {
					if (!crlf_added) {
						g_byte_array_append (part->utf_stripped_content,
								(const guint8 *)" ", 1);
					}

					while (p < pe && *p == ' ') {
						p ++;
						c ++;
						part->spaces ++;
					}

					if (p < pe && (*p == '\r' || *p == '\n')) {
						part->empty_lines ++;
					}
				}

				state = normal_char;
				break;
			}

			p ++;
		}
	}

	/* Leftover */
	if (p > c) {
		if (p > pe) {
			p = pe;
		}

		switch (state) {
		case normal_char:
			g_byte_array_append (part->utf_stripped_content,
					(const guint8 *)c, p - c);

			while (c < p) {
				if (G_UNLIKELY (*c) == ' ') {
					part->spaces ++;

					if (*(c - 1) == ' ') {
						part->double_spaces ++;
					}
				}
				else {
					part->non_spaces ++;

					if (G_UNLIKELY (*c & 0x80)) {
						part->non_ascii_chars ++;
					}
					else {
						part->ascii_chars ++;
					}
				}

				c ++;
			}
			break;
		default:

			if (!crlf_added) {
				g_byte_array_append (part->utf_stripped_content,
						(const guint8 *)" ", 1);
				g_ptr_array_add (part->newlines,
						(((gpointer) (goffset) (part->utf_stripped_content->len))));
			}

			part->nlines++;
			break;
		}
	}
}

static void
rspamd_normalize_text_part (struct rspamd_task *task,
		struct rspamd_mime_text_part *part)
{
	const gchar *p, *end;
	guint i;
	goffset off;
	struct rspamd_process_exception *ex;
	UErrorCode uc_err = U_ZERO_ERROR;

	part->newlines = g_ptr_array_sized_new (128);

	if (IS_PART_EMPTY (part)) {
		part->utf_stripped_content = g_byte_array_new ();
	}
	else {
		part->utf_stripped_content = g_byte_array_sized_new (part->utf_content->len);

		p = (const gchar *)part->utf_content->data;
		end = p + part->utf_content->len;

		rspamd_strip_newlines_parse (p, end, part);

		for (i = 0; i < part->newlines->len; i ++) {
			ex = rspamd_mempool_alloc (task->task_pool, sizeof (*ex));
			off = (goffset)g_ptr_array_index (part->newlines, i);
			g_ptr_array_index (part->newlines, i) = (gpointer)(goffset)
					(part->utf_stripped_content->data + off);
			ex->pos = off;
			ex->len = 0;
			ex->type = RSPAMD_EXCEPTION_NEWLINE;
			part->exceptions = g_list_prepend (part->exceptions, ex);
		}
	}

	if (IS_PART_UTF (part)) {
		utext_openUTF8 (&part->utf_stripped_text,
				part->utf_stripped_content->data,
				part->utf_stripped_content->len,
				&uc_err);

		if (!U_SUCCESS (uc_err)) {
			msg_warn_task ("cannot open text from utf content");
			/* Probably, should be an assertion */
		}
		else {
			rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t)utext_close,
					&part->utf_stripped_text);
		}
	}

	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) free_byte_array_callback,
			part->utf_stripped_content);
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) rspamd_ptr_array_free_hard,
			part->newlines);
}

#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))

static guint
rspamd_words_levenshtein_distance (struct rspamd_task *task,
		GArray *w1, GArray *w2)
{
	guint s1len, s2len, x, y, lastdiag, olddiag;
	guint *column, ret;
	guint64 h1, h2;
	gint eq;
	static const guint max_words = 8192;

	s1len = w1->len;
	s2len = w2->len;

	if (s1len + s2len > max_words) {
		msg_err_task ("cannot compare parts with more than %ud words: %ud",
				max_words, s1len);
		return 0;
	}

	column = g_malloc0 ((s1len + 1) * sizeof (guint));

	for (y = 1; y <= s1len; y++) {
		column[y] = y;
	}

	for (x = 1; x <= s2len; x++) {
		column[0] = x;

		for (y = 1, lastdiag = x - 1; y <= s1len; y++) {
			olddiag = column[y];
			h1 = g_array_index (w1, guint64, y - 1);
			h2 = g_array_index (w2, guint64, x - 1);
			eq = (h1 == h2) ? 1 : 0;
			/*
			 * Cost of replacement is twice higher than cost of add/delete
			 * to calculate percentage properly
			 */
			column[y] = MIN3 (column[y] + 1, column[y - 1] + 1,
					lastdiag + (eq * 2));
			lastdiag = olddiag;
		}
	}

	ret = column[s1len];
	g_free (column);

	return ret;
}

static gint
rspamd_multipattern_gtube_cb (struct rspamd_multipattern *mp,
		guint strnum,
		gint match_start,
		gint match_pos,
		const gchar *text,
		gsize len,
		void *context)
{
	return strnum + 1; /* To distinguish from zero */
}

static enum rspamd_action_type
rspamd_check_gtube (struct rspamd_task *task, struct rspamd_mime_text_part *part)
{
	static const gsize max_check_size = 8 * 1024;
	gint ret;
	enum rspamd_action_type act = METRIC_ACTION_NOACTION;
	g_assert (part != NULL);

	if (gtube_matcher == NULL) {
		gtube_matcher = rspamd_multipattern_create (RSPAMD_MULTIPATTERN_DEFAULT);

		rspamd_multipattern_add_pattern (gtube_matcher,
				gtube_pattern_reject,
				RSPAMD_MULTIPATTERN_DEFAULT);
		rspamd_multipattern_add_pattern (gtube_matcher,
				gtube_pattern_add_header,
				RSPAMD_MULTIPATTERN_DEFAULT);
		rspamd_multipattern_add_pattern (gtube_matcher,
				gtube_pattern_rewrite_subject,
				RSPAMD_MULTIPATTERN_DEFAULT);

		g_assert (rspamd_multipattern_compile (gtube_matcher, NULL));
	}

	if (part->utf_content && part->utf_content->len >= sizeof (gtube_pattern_reject) &&
			part->utf_content->len <= max_check_size) {
		if ((ret = rspamd_multipattern_lookup (gtube_matcher, part->utf_content->data,
				part->utf_content->len,
				rspamd_multipattern_gtube_cb, NULL, NULL)) > 0) {

			switch (ret) {
			case 1:
				act = METRIC_ACTION_REJECT;
				break;
			case 2:
				act = METRIC_ACTION_ADD_HEADER;
				break;
			case 3:
				act = METRIC_ACTION_REWRITE_SUBJECT;
				break;
			}

			if (act != METRIC_ACTION_NOACTION) {
				task->flags |= RSPAMD_TASK_FLAG_SKIP;
				task->flags |= RSPAMD_TASK_FLAG_GTUBE;
				msg_info_task (
						"<%s>: gtube %s pattern has been found in part of length %ud",
						task->message_id, rspamd_action_to_str (act),
						part->utf_content->len);
			}
		}
	}

	return act;
}

static gint
exceptions_compare_func (gconstpointer a, gconstpointer b)
{
	const struct rspamd_process_exception *ea = a, *eb = b;

	return ea->pos - eb->pos;
}

static gboolean
rspamd_message_process_plain_text_part (struct rspamd_task *task,
										struct rspamd_mime_text_part *text_part)
{
	if (text_part->parsed.len == 0) {
		text_part->flags |= RSPAMD_MIME_TEXT_PART_FLAG_EMPTY;

		return TRUE;
	}

	rspamd_mime_text_part_maybe_convert (task, text_part);

	if (text_part->utf_raw_content != NULL) {
		/* Different from HTML, where we also parse HTML and strip tags */
		text_part->utf_content = text_part->utf_raw_content;
	}
	else {
		/*
		 * We ignore unconverted parts from now as it is dangerous
		 * to treat them as text parts
		 */

		return FALSE;
	}

	return TRUE;
}

static gboolean
rspamd_message_process_html_text_part (struct rspamd_task *task,
										struct rspamd_mime_text_part *text_part)
{
	text_part->flags |= RSPAMD_MIME_TEXT_PART_FLAG_HTML;

	if (text_part->parsed.len == 0) {
		text_part->flags |= RSPAMD_MIME_TEXT_PART_FLAG_EMPTY;

		return TRUE;
	}

	rspamd_mime_text_part_maybe_convert (task, text_part);

	if (text_part->utf_raw_content == NULL) {
		return FALSE;
	}

	text_part->html = rspamd_mempool_alloc0 (task->task_pool,
			sizeof (*text_part->html));
	text_part->flags |= RSPAMD_MIME_TEXT_PART_FLAG_BALANCED;
	text_part->utf_content = rspamd_html_process_part_full (
			task->task_pool,
			text_part->html,
			text_part->utf_raw_content,
			&text_part->exceptions,
			task->urls,
			task->emails);

	if (text_part->utf_content->len == 0) {
		text_part->flags |= RSPAMD_MIME_TEXT_PART_FLAG_EMPTY;
	}

	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) free_byte_array_callback,
			text_part->utf_content);

	return TRUE;
}

static void
rspamd_message_process_text_part_maybe (struct rspamd_task *task,
										struct rspamd_mime_part *mime_part)
{
	struct rspamd_mime_text_part *text_part;
	rspamd_ftok_t html_tok, xhtml_tok;
	gboolean found_html = FALSE, found_txt = FALSE;
	enum rspamd_action_type act;

	if (IS_CT_TEXT (mime_part->ct)) {
		html_tok.begin = "html";
		html_tok.len = 4;
		xhtml_tok.begin = "xhtml";
		xhtml_tok.len = 5;

		if (rspamd_ftok_cmp (&mime_part->ct->subtype, &html_tok) == 0 ||
				rspamd_ftok_cmp (&mime_part->ct->subtype, &xhtml_tok) == 0) {
			found_html = TRUE;
		}
		else {
			/*
			 * We also need to apply heuristic for text parts that are actually
			 * HTML.
			 */
			RSPAMD_FTOK_ASSIGN (&html_tok, "<!DOCTYPE html");
			RSPAMD_FTOK_ASSIGN (&xhtml_tok, "<html");

			if (mime_part->parsed_data.len >= xhtml_tok.len &&
					rspamd_lc_cmp (mime_part->parsed_data.begin,
							xhtml_tok.begin, xhtml_tok.len) == 0) {
				found_html = TRUE;
			}
			else if (mime_part->parsed_data.len >= html_tok.len &&
					rspamd_lc_cmp (mime_part->parsed_data.begin,
							html_tok.begin, html_tok.len) == 0) {
				found_html = TRUE;
			}
			else {
				/* We need to be extra careful with some stupid things here */

				html_tok.begin = "plain";
				html_tok.len = 5;

				if (rspamd_ftok_cmp (&mime_part->ct->subtype, &html_tok) == 0) {
					found_txt = TRUE;
				}
				else {
					if (mime_part->cd && mime_part->cd->filename.len > 4) {
						const gchar *pos = mime_part->cd->filename.begin +
										   mime_part->cd->filename.len -
										   sizeof (".txt") + 1;
						if (rspamd_lc_cmp (pos, ".txt", sizeof ("txt") - 1) == 0) {
							found_txt = TRUE;
						}
						else {
							msg_debug_task ("found mime part with incorrect content-type: %T/%T, "
										   "filename: %T",
									&mime_part->ct->type,
									&mime_part->ct->subtype,
									&mime_part->cd->filename);
						}
					}
					else {
						/* For something like Content-Type: text */
						found_txt = TRUE;
					}
				}
			}

			if (found_html) {
				msg_info_task ("found html part pretending to be text/plain part");
			}
		}
	}
	else {
		/* Apply heuristic */

		if (mime_part->cd && mime_part->cd->filename.len > 4) {
			const gchar *pos = mime_part->cd->filename.begin +
					mime_part->cd->filename.len - sizeof (".htm") + 1;

			if (rspamd_lc_cmp (pos, ".htm", sizeof (".htm") - 1) == 0) {
				found_html = TRUE;
			}
			else if (rspamd_lc_cmp (pos, ".txt", sizeof ("txt") - 1) == 0) {
				found_txt = TRUE;
			}
			else if ( mime_part->cd->filename.len > 5) {
				pos = mime_part->cd->filename.begin +
						mime_part->cd->filename.len - sizeof (".html") + 1;
				if (rspamd_lc_cmp (pos, ".html", sizeof (".html") - 1) == 0) {
					found_html = TRUE;
				}
			}
		}

		if (found_txt || found_html) {
			msg_info_task ("found %s part with incorrect content-type: %T/%T",
					found_html ? "html" : "text",
					&mime_part->ct->type, &mime_part->ct->subtype);
			mime_part->ct->flags |= RSPAMD_CONTENT_TYPE_BROKEN;
		}
	}

	/* Skip attachments */
	if ((found_txt || found_html) &&
			mime_part->cd && mime_part->cd->type == RSPAMD_CT_ATTACHMENT &&
			(task->cfg && !task->cfg->check_text_attachements)) {
		debug_task ("skip attachments for checking as text parts");
		return;
	}
	else if (!(found_txt || found_html)) {
		/* Not a text part */
		return;
	}

	text_part = rspamd_mempool_alloc0 (task->task_pool,
			sizeof (struct rspamd_mime_text_part));
	text_part->mime_part = mime_part;
	text_part->raw.begin = mime_part->raw_data.begin;
	text_part->raw.len = mime_part->raw_data.len;
	text_part->parsed.begin = mime_part->parsed_data.begin;
	text_part->parsed.len = mime_part->parsed_data.len;
	text_part->utf_stripped_text = (UText)UTEXT_INITIALIZER;

	if (found_html) {
		if (!rspamd_message_process_html_text_part (task, text_part)) {
			return;
		}
	}
	else {
		if (!rspamd_message_process_plain_text_part (task, text_part)) {
			return;
		}
	}

	g_ptr_array_add (task->text_parts, text_part);
	mime_part->flags |= RSPAMD_MIME_PART_TEXT;
	mime_part->specific.txt = text_part;

	act = rspamd_check_gtube (task, text_part);
	if (act != METRIC_ACTION_NOACTION) {
		struct rspamd_metric_result *mres = task->result;
		gdouble score = NAN;

		if (act == METRIC_ACTION_REJECT) {
			score = rspamd_task_get_required_score (task, mres);
		}
		else {
			score = mres->actions_limits[act];
		}

		rspamd_add_passthrough_result (task, act, RSPAMD_PASSTHROUGH_CRITICAL,
				score, "Gtube pattern", "GTUBE");

		if (ucl_object_lookup (task->messages, "smtp_message") == NULL) {
			ucl_object_replace_key (task->messages,
					ucl_object_fromstring ("Gtube pattern"), "smtp_message", 0,
					false);
		}

		rspamd_task_insert_result (task, GTUBE_SYMBOL, 0, NULL);

		return;
	}

	/* Post process part */
	rspamd_normalize_text_part (task, text_part);

	if (!IS_PART_HTML (text_part)) {
		rspamd_url_text_extract (task->task_pool, task, text_part, FALSE);
	}

	if (text_part->exceptions) {
		text_part->exceptions = g_list_sort (text_part->exceptions,
				exceptions_compare_func);
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t)g_list_free,
				text_part->exceptions);
	}

	rspamd_mime_part_create_words (task, text_part);
}

/* Creates message from various data using libmagic to detect type */
static void
rspamd_message_from_data (struct rspamd_task *task, const guchar *start,
		gsize len)
{
	struct rspamd_content_type *ct = NULL;
	struct rspamd_mime_part *part;
	const char *mb = NULL;
	gchar *mid;
	rspamd_ftok_t srch, *tok;

	g_assert (start != NULL);

	tok = rspamd_task_get_request_header (task, "Content-Type");

	if (tok) {
		/* We have Content-Type defined */
		ct = rspamd_content_type_parse (tok->begin, tok->len,
				task->task_pool);
	}
	else if (task->cfg && task->cfg->libs_ctx) {
		/* Try to predict it by content (slow) */
		mb = magic_buffer (task->cfg->libs_ctx->libmagic,
				start,
				len);

		if (mb) {
			srch.begin = mb;
			srch.len = strlen (mb);
			ct = rspamd_content_type_parse (srch.begin, srch.len,
					task->task_pool);
		}
	}

	msg_warn_task ("construct fake mime of type: %s", mb);
	part = rspamd_mempool_alloc0 (task->task_pool, sizeof (*part));
	part->ct = ct;
	part->raw_data.begin = start;
	part->raw_data.len = len;
	part->parsed_data.begin = start;
	part->parsed_data.len = len;

	/* Generate message ID */
	mid = rspamd_mime_message_id_generate ("localhost.localdomain");
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_free, mid);
	task->message_id = mid;
	task->queue_id = mid;
}

gboolean
rspamd_message_parse (struct rspamd_task *task)
{
	struct received_header *recv, *trecv;
	const gchar *p;
	gsize len;
	guint i;
	GError *err = NULL;
	rspamd_cryptobox_hash_state_t st;
	guchar digest_out[rspamd_cryptobox_HASHBYTES];

	if (RSPAMD_TASK_IS_EMPTY (task)) {
		/* Don't do anything with empty task */
		return TRUE;
	}

	p = task->msg.begin;
	len = task->msg.len;

	/* Skip any space characters to avoid some bad messages to be unparsed */
	while (len > 0 && g_ascii_isspace (*p)) {
		p ++;
		len --;
	}

	/*
	 * Exim somehow uses mailbox format for messages being scanned:
	 * From xxx@xxx.com Fri May 13 19:08:48 2016
	 *
	 * So we check if a task has non-http format then we check for such a line
	 * at the beginning to avoid errors
	 */
	if (!(task->flags & RSPAMD_TASK_FLAG_JSON) || (task->flags &
			RSPAMD_TASK_FLAG_LOCAL_CLIENT)) {
		if (len > sizeof ("From ") - 1) {
			if (memcmp (p, "From ", sizeof ("From ") - 1) == 0) {
				/* Skip to CRLF */
				msg_info_task ("mailbox input detected, enable workaround");
				p += sizeof ("From ") - 1;
				len -= sizeof ("From ") - 1;

				while (len > 0 && *p != '\n') {
					p ++;
					len --;
				}
				while (len > 0 && g_ascii_isspace (*p)) {
					p ++;
					len --;
				}
			}
		}
	}

	task->msg.begin = p;
	task->msg.len = len;
	rspamd_cryptobox_hash_init (&st, NULL, 0);

	if (task->flags & RSPAMD_TASK_FLAG_MIME) {
		enum rspamd_mime_parse_error ret;

		debug_task ("construct mime parser from string length %d",
				(gint) task->msg.len);
		ret = rspamd_mime_parse_task (task, &err);

		switch (ret) {
		case RSPAMD_MIME_PARSE_FATAL:
			msg_err_task ("cannot construct mime from stream: %e", err);

			if (task->cfg && (!task->cfg->allow_raw_input)) {
				msg_err_task ("cannot construct mime from stream");
				if (err) {
					task->err = err;
				}

				return FALSE;
			}
			else {
				task->flags &= ~RSPAMD_TASK_FLAG_MIME;
				rspamd_message_from_data (task, p, len);
			}
			break;
		case RSPAMD_MIME_PARSE_NESTING:
			msg_warn_task ("cannot construct full mime from stream: %e", err);
			task->flags |= RSPAMD_TASK_FLAG_BROKEN_HEADERS;
			break;
		case RSPAMD_MIME_PARSE_OK:
		default:
			break;
		}

		if (err) {
			g_error_free (err);
		}
	}
	else {
		task->flags &= ~RSPAMD_TASK_FLAG_MIME;
		rspamd_message_from_data (task, p, len);
	}


	if (task->message_id == NULL) {
		task->message_id = "undef";
	}

	debug_task ("found %ud parts in message", task->parts->len);
	if (task->queue_id == NULL) {
		task->queue_id = "undef";
	}

	if (task->received->len > 0) {
		gboolean need_recv_correction = FALSE;
		rspamd_inet_addr_t *raddr;

		recv = g_ptr_array_index (task->received, 0);
		/*
		 * For the first header we must ensure that
		 * received is consistent with the IP that we obtain through
		 * client.
		 */

		raddr = recv->addr;
		if (recv->real_ip == NULL || (task->cfg && task->cfg->ignore_received)) {
			need_recv_correction = TRUE;
		}
		else if (!(task->flags & RSPAMD_TASK_FLAG_NO_IP) && task->from_addr) {
			if (!raddr) {
				need_recv_correction = TRUE;
			}
			else {
				if (rspamd_inet_address_compare (raddr, task->from_addr) != 0) {
					need_recv_correction = TRUE;
				}
			}
		}

		if (need_recv_correction && !(task->flags & RSPAMD_TASK_FLAG_NO_IP)
				&& task->from_addr) {
			msg_debug_task ("the first received seems to be"
					" not ours, prepend it with fake one");

			trecv = rspamd_mempool_alloc0 (task->task_pool,
					sizeof (struct received_header));
			trecv->flags |= RSPAMD_RECEIVED_FLAG_ARTIFICIAL;

			if (task->flags & RSPAMD_TASK_FLAG_SSL) {
				trecv->flags |= RSPAMD_RECEIVED_FLAG_SSL;
			}

			if (task->user) {
				trecv->flags |= RSPAMD_RECEIVED_FLAG_AUTHENTICATED;
			}

			trecv->real_ip = rspamd_mempool_strdup (task->task_pool,
					rspamd_inet_address_to_string (task->from_addr));
			trecv->from_ip = trecv->real_ip;
			trecv->by_hostname = rspamd_mempool_get_variable (task->task_pool,
					RSPAMD_MEMPOOL_MTA_NAME);
			trecv->addr = rspamd_inet_address_copy (task->from_addr);
			rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t)rspamd_inet_address_free,
					trecv->addr);

			if (task->hostname) {
				trecv->real_hostname = task->hostname;
				trecv->from_hostname = trecv->real_hostname;
			}

#ifdef GLIB_VERSION_2_40
			g_ptr_array_insert (task->received, 0, trecv);
#else
			/*
			 * Unfortunately, before glib 2.40 we cannot insert element into a
			 * ptr array
			 */
			GPtrArray *nar = g_ptr_array_sized_new (task->received->len + 1);

			g_ptr_array_add (nar, trecv);
			PTR_ARRAY_FOREACH (task->received, i, recv) {
				g_ptr_array_add (nar, recv);
			}
			rspamd_mempool_add_destructor (task->task_pool,
						rspamd_ptr_array_free_hard, nar);
			task->received = nar;
#endif
		}
	}

	/* Extract data from received header if we were not given IP */
	if (task->received->len > 0 && (task->flags & RSPAMD_TASK_FLAG_NO_IP) &&
			(task->cfg && !task->cfg->ignore_received)) {
		recv = g_ptr_array_index (task->received, 0);
		if (recv->real_ip) {
			if (!rspamd_parse_inet_address (&task->from_addr,
					recv->real_ip,
					0)) {
				msg_warn_task ("cannot get IP from received header: '%s'",
						recv->real_ip);
				task->from_addr = NULL;
			}
		}
		if (recv->real_hostname) {
			task->hostname = recv->real_hostname;
		}
	}

	/* Parse urls inside Subject header */
	if (task->subject) {
		p = task->subject;
		len = strlen (p);
		rspamd_cryptobox_hash_update (&st, p, len);
		rspamd_url_find_multiple (task->task_pool, p, len, FALSE, NULL,
				rspamd_url_task_subject_callback, task);
	}

	for (i = 0; i < task->parts->len; i ++) {
		struct rspamd_mime_part *part;

		part = g_ptr_array_index (task->parts, i);
		rspamd_cryptobox_hash_update (&st, part->digest, sizeof (part->digest));
	}

	rspamd_cryptobox_hash_final (&st, digest_out);
	memcpy (task->digest, digest_out, sizeof (task->digest));

	if (task->queue_id) {
		msg_info_task ("loaded message; id: <%s>; queue-id: <%s>; size: %z; "
				"checksum: <%*xs>",
				task->message_id, task->queue_id, task->msg.len,
				(gint)sizeof (task->digest), task->digest);
	}
	else {
		msg_info_task ("loaded message; id: <%s>; size: %z; "
				"checksum: <%*xs>",
				task->message_id, task->msg.len,
				(gint)sizeof (task->digest), task->digest);
	}

	return TRUE;
}

void
rspamd_message_process (struct rspamd_task *task)
{
	guint i;
	struct rspamd_mime_text_part *p1, *p2;
	gdouble diff, *pdiff;
	guint tw, *ptw, dw;

	for (i = 0; i < task->parts->len; i ++) {
		struct rspamd_mime_part *part;

		part = g_ptr_array_index (task->parts, i);
		rspamd_message_process_text_part_maybe (task, part);
	}

	rspamd_images_process (task);
	rspamd_archives_process (task);

	/* Calculate distance for 2-parts messages */
	if (task->text_parts->len == 2) {
		p1 = g_ptr_array_index (task->text_parts, 0);
		p2 = g_ptr_array_index (task->text_parts, 1);

		/* First of all check parent object */
		if (p1->mime_part->parent_part) {
			rspamd_ftok_t srch;

			srch.begin = "alternative";
			srch.len = 11;

			if (rspamd_ftok_cmp (&p1->mime_part->parent_part->ct->subtype, &srch) == 0) {
				if (!IS_PART_EMPTY (p1) && !IS_PART_EMPTY (p2) &&
					p1->normalized_hashes && p2->normalized_hashes) {
					/*
					 * We also detect language on one part and propagate it to
					 * another one
					 */
					struct rspamd_mime_text_part *sel;

					/* Prefer HTML as text part is not displayed normally */
					if (IS_PART_HTML (p1)) {
						sel = p1;
					}
					else if (IS_PART_HTML (p2)) {
						sel = p2;
					}
					else {
						if (p1->utf_content->len > p2->utf_content->len) {
							sel = p1;
						}
						else {
							sel = p2;
						}
					}

					rspamd_mime_part_detect_language (task, sel);

					if (sel->language && sel->language[0]) {
						/* Propagate language */
						if (sel == p1) {
							p2->language = sel->language;
							p2->languages = g_ptr_array_ref (sel->languages);
						}
						else {
							p1->language = sel->language;
							p1->languages = g_ptr_array_ref (sel->languages);
						}
					}

					tw = p1->normalized_hashes->len + p2->normalized_hashes->len;

					if (tw > 0) {
						dw = rspamd_words_levenshtein_distance (task,
								p1->normalized_hashes,
								p2->normalized_hashes);
						diff = dw / (gdouble)tw;

						msg_debug_task (
								"different words: %d, total words: %d, "
								"got diff between parts of %.2f",
								dw, tw,
								diff);

						pdiff = rspamd_mempool_alloc (task->task_pool,
								sizeof (gdouble));
						*pdiff = diff;
						rspamd_mempool_set_variable (task->task_pool,
								"parts_distance",
								pdiff,
								NULL);
						ptw = rspamd_mempool_alloc (task->task_pool,
								sizeof (gint));
						*ptw = tw;
						rspamd_mempool_set_variable (task->task_pool,
								"total_words",
								ptw,
								NULL);
					}
				}
			}
		}
		else {
			debug_task (
					"message contains two parts but they are in different multi-parts");
		}
	}

	/* Calculate average words length and number of short words */
	struct rspamd_mime_text_part *text_part;
	gdouble *var;
	guint total_words = 0;

	PTR_ARRAY_FOREACH (task->text_parts, i, text_part) {
		if (!text_part->language) {
			rspamd_mime_part_detect_language (task, text_part);
		}

		rspamd_mime_part_extract_words (task, text_part);

		if (text_part->utf_words) {
			total_words += text_part->nwords;
		}
	}

	if (total_words > 0) {
		var = rspamd_mempool_get_variable (task->task_pool,
				RSPAMD_MEMPOOL_AVG_WORDS_LEN);

		if (var) {
			*var /= (double)total_words;
		}

		var = rspamd_mempool_get_variable (task->task_pool,
				RSPAMD_MEMPOOL_SHORT_WORDS_CNT);

		if (var) {
			*var /= (double)total_words;
		}
	}

	rspamd_tokenize_meta_words (task);
}


GPtrArray *
rspamd_message_get_header_from_hash (GHashTable *htb,
		rspamd_mempool_t *pool,
		const gchar *field,
		gboolean strong)
{
	GPtrArray *ret, *ar;
	struct rspamd_mime_header *cur;
	guint i;

	ar = g_hash_table_lookup (htb, field);

	if (ar == NULL) {
		return NULL;
	}

	if (strong && pool != NULL) {
		/* Need to filter what we have */
		ret = g_ptr_array_sized_new (ar->len);

		PTR_ARRAY_FOREACH (ar, i, cur) {
			if (strcmp (cur->name, field) != 0) {
				continue;
			}

			g_ptr_array_add (ret, cur);
		}

		rspamd_mempool_add_destructor (pool,
				(rspamd_mempool_destruct_t)rspamd_ptr_array_free_hard, ret);
	}
	else {
		ret = ar;
	}

	return ret;
}

GPtrArray *
rspamd_message_get_header_array (struct rspamd_task *task,
		const gchar *field,
		gboolean strong)
{
	return rspamd_message_get_header_from_hash (task->raw_headers,
			task->task_pool, field, strong);
}

GPtrArray *
rspamd_message_get_mime_header_array (struct rspamd_task *task,
		const gchar *field,
		gboolean strong)
{
	GPtrArray *ret, *ar;
	struct rspamd_mime_header *cur;
	guint nelems = 0, i, j;
	struct rspamd_mime_part *mp;

	for (i = 0; i < task->parts->len; i ++) {
		mp = g_ptr_array_index (task->parts, i);
		ar = g_hash_table_lookup (mp->raw_headers, field);

		if (ar == NULL) {
			continue;
		}

		nelems += ar->len;
	}

	if (nelems == 0) {
		return NULL;
	}

	ret = g_ptr_array_sized_new (nelems);

	for (i = 0; i < task->parts->len; i ++) {
		mp = g_ptr_array_index (task->parts, i);
		ar = g_hash_table_lookup (mp->raw_headers, field);

		PTR_ARRAY_FOREACH (ar, j, cur) {
			if (strong) {
				if (strcmp (cur->name, field) != 0) {
					continue;
				}
			}

			g_ptr_array_add (ret, cur);
		}
	}

	rspamd_mempool_add_destructor (task->task_pool,
		(rspamd_mempool_destruct_t)rspamd_ptr_array_free_hard, ret);

	return ret;
}
