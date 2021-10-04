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
#include "libserver/html/html.h"
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
#include "sodium.h"
#include "libserver/cfg_file_private.h"
#include "lua/lua_common.h"
#include "contrib/uthash/utlist.h"
#include "contrib/t1ha/t1ha.h"
#include "received.h"

#define GTUBE_SYMBOL "GTUBE"

#define SET_PART_RAW(part) ((part)->flags &= ~RSPAMD_MIME_TEXT_PART_FLAG_UTF)
#define SET_PART_UTF(part) ((part)->flags |= RSPAMD_MIME_TEXT_PART_FLAG_UTF)

static const gchar gtube_pattern_reject[] = "XJS*C4JDBQADN1.NSBN3*2IDNEN*"
				"GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
static const gchar gtube_pattern_add_header[] = "YJS*C4JDBQADN1.NSBN3*2IDNEN*"
				"GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
static const gchar gtube_pattern_rewrite_subject[] = "ZJS*C4JDBQADN1.NSBN3*2IDNEN*"
				"GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
static const gchar gtube_pattern_no_action[] = "AJS*C4JDBQADN1.NSBN3*2IDNEN*"
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

				if (w->flags & RSPAMD_STAT_TOKEN_FLAG_TEXT &&
					!(w->flags & RSPAMD_STAT_TOKEN_FLAG_SKIPPED)) {
					part->nwords ++;
				}
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

	if (IS_TEXT_PART_UTF (part)) {

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
			NULL,
			NULL,
			task->task_pool);


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

	if (!IS_TEXT_PART_EMPTY (part) && part->utf_words && part->utf_words->len > 0 &&
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
rspamd_strip_newlines_parse (struct rspamd_task *task,
		const gchar *begin, const gchar *pe,
		struct rspamd_mime_text_part *part)
{
	const gchar *p = begin, *c = begin;
	gboolean crlf_added = FALSE, is_utf = IS_TEXT_PART_UTF (part);
	gboolean url_open_bracket = FALSE;
	UChar32 uc;

	enum {
		normal_char,
		seen_cr,
		seen_lf,
	} state = normal_char;

	while (p < pe) {
		if (U8_IS_LEAD(*p) && is_utf) {
			gint32 off = p - begin;
			U8_NEXT (begin, off, pe - begin, uc);

			if (uc != -1) {
				while (p < pe && off < (pe - begin)) {
					if (IS_ZERO_WIDTH_SPACE (uc)) {
						/* Invisible space ! */
						task->flags |= RSPAMD_TASK_FLAG_BAD_UNICODE;
						part->spaces ++;

						if (p > c) {
							g_byte_array_append (part->utf_stripped_content,
									(const guint8 *) c, p - c);
							c = begin + off;
							p = c;
						}

						U8_NEXT (begin, off, pe - begin, uc);

						if (!IS_ZERO_WIDTH_SPACE (uc)) {
							break;
						}

						part->double_spaces ++;
						p = begin + off;
						c = p;
					}
					else {
						break;
					}
				}
			}
		}

		if (G_UNLIKELY (p >= pe)) {
			/*
			 * This is reached when there is a utf8 part and we
			 * have zero width spaces at the end of the text
			 * So we just check overflow and refuse to access *p if it is
			 * after our real content.
			 */
			break;
		}
		else if (*p == '\r') {
			switch (state) {
			case normal_char:
				state = seen_cr;
				if (p > c) {
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
		else if (*p == '\n') {
			switch (state) {
			case normal_char:
				state = seen_lf;

				if (p > c) {
					g_byte_array_append (part->utf_stripped_content,
							(const guint8 *)c, p - c);
				}

				c = p + 1;

				if (IS_TEXT_PART_HTML (part) || !url_open_bracket) {
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
					if (IS_TEXT_PART_HTML (part) || !url_open_bracket) {
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
				if (*p == ' ') {
					part->spaces ++;

					if (p > begin && *(p - 1) == ' ') {
						part->double_spaces ++;
					}
				}
				else {
					part->non_spaces ++;

					if ((*p) & 0x80) {
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
				if (*p == ' ') {
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
				continue;
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
				if (*c == ' ') {
					part->spaces ++;

					if (c > begin && *(c - 1) == ' ') {
						part->double_spaces ++;
					}
				}
				else {
					part->non_spaces ++;

					if ((*c) & 0x80) {
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
rspamd_u_text_dtor (void *p)
{
	utext_close ((UText *)p);
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

	if (IS_TEXT_PART_EMPTY (part)) {
		part->utf_stripped_content = g_byte_array_new ();
	}
	else {
		part->utf_stripped_content = g_byte_array_sized_new (part->utf_content.len);

		p = (const gchar *)part->utf_content.begin;
		end = p + part->utf_content.len;

		rspamd_strip_newlines_parse (task, p, end, part);

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

	if (IS_TEXT_PART_UTF (part)) {
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
					rspamd_u_text_dtor,
					&part->utf_stripped_text);
		}
	}

	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) free_byte_array_callback,
			part->utf_stripped_content);
	rspamd_mempool_notify_alloc (task->task_pool,
			part->utf_stripped_content->len);
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
		msg_err_task ("cannot compare parts with more than %ud words: (%ud + %ud)",
				max_words, s1len, s2len);
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
	struct rspamd_task *task = (struct rspamd_task *)context;

	if (strnum > 0) {
		if (task->cfg->enable_test_patterns) {
			return strnum + 1;
		}

		return 0;
	}

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
		rspamd_multipattern_add_pattern (gtube_matcher,
				gtube_pattern_no_action,
				RSPAMD_MULTIPATTERN_DEFAULT);

		g_assert (rspamd_multipattern_compile (gtube_matcher, NULL));
	}

	if (part->utf_content.len >= sizeof (gtube_pattern_reject) &&
			part->utf_content.len <= max_check_size) {
		if ((ret = rspamd_multipattern_lookup (gtube_matcher, part->utf_content.begin,
				part->utf_content.len,
				rspamd_multipattern_gtube_cb, task, NULL)) > 0) {

			switch (ret) {
			case 1:
				act = METRIC_ACTION_REJECT;
				break;
			case 2:
				g_assert (task->cfg->enable_test_patterns);
				act = METRIC_ACTION_ADD_HEADER;
				break;
			case 3:
				g_assert (task->cfg->enable_test_patterns);
				act = METRIC_ACTION_REWRITE_SUBJECT;
				break;
			case 4:
				g_assert (task->cfg->enable_test_patterns);
				act = METRIC_ACTION_NOACTION;
				break;
			}

			if (ret != 0) {
				task->flags |= RSPAMD_TASK_FLAG_SKIP;
				task->flags |= RSPAMD_TASK_FLAG_GTUBE;
				msg_info_task (
						"gtube %s pattern has been found in part of length %uz",
						rspamd_action_to_str (act),
						part->utf_content.len);
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
		/* Just have the same content */
		text_part->utf_content.begin = (const gchar *)text_part->utf_raw_content->data;
		text_part->utf_content.len = text_part->utf_raw_content->len;
	}
	else {
		/*
		 * We ignore unconverted parts from now as it is dangerous
		 * to treat them as text parts
		 */
		text_part->utf_content.begin = NULL;
		text_part->utf_content.len = 0;

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


	text_part->html = rspamd_html_process_part_full (
			task->task_pool,
			text_part->utf_raw_content,
			&text_part->exceptions,
			MESSAGE_FIELD (task, urls),
			text_part->mime_part->urls,
			task->cfg ? task->cfg->enable_css_parser : true);
	rspamd_html_get_parsed_content(text_part->html, &text_part->utf_content);

	if (text_part->utf_content.len == 0) {
		text_part->flags |= RSPAMD_MIME_TEXT_PART_FLAG_EMPTY;
	}

	return TRUE;
}

static gboolean
rspamd_message_process_text_part_maybe (struct rspamd_task *task,
										struct rspamd_mime_part *mime_part)
{
	struct rspamd_mime_text_part *text_part;
	rspamd_ftok_t html_tok, xhtml_tok;
	gboolean found_html = FALSE, found_txt = FALSE;
	guint flags = 0;
	enum rspamd_action_type act;

	if ((mime_part->ct && (mime_part->ct->flags & RSPAMD_CONTENT_TYPE_TEXT)) ||
		(mime_part->detected_type && strcmp (mime_part->detected_type, "text") == 0)) {

		found_txt = TRUE;

		html_tok.begin = "html";
		html_tok.len = 4;
		xhtml_tok.begin = "xhtml";
		xhtml_tok.len = 5;

		if (rspamd_ftok_casecmp (&mime_part->ct->subtype, &html_tok) == 0 ||
			rspamd_ftok_casecmp (&mime_part->ct->subtype, &xhtml_tok) == 0 ||
			(mime_part->detected_ext &&
				strcmp (mime_part->detected_ext, "html") == 0)) {
			found_html = TRUE;
		}
	}

	/* Skip attachments */
	if ((found_txt || found_html) &&
			(mime_part->cd && mime_part->cd->type == RSPAMD_CT_ATTACHMENT)) {
		if (!task->cfg->check_text_attachements) {
			debug_task ("skip attachments for checking as text parts");
			return FALSE;
		}
		else {
			flags |= RSPAMD_MIME_TEXT_PART_ATTACHMENT;
		}
	}
	else if (!(found_txt || found_html)) {
		/* Not a text part */
		return FALSE;
	}

	text_part = rspamd_mempool_alloc0 (task->task_pool,
			sizeof (struct rspamd_mime_text_part));
	text_part->mime_part = mime_part;
	text_part->raw.begin = mime_part->raw_data.begin;
	text_part->raw.len = mime_part->raw_data.len;
	text_part->parsed.begin = mime_part->parsed_data.begin;
	text_part->parsed.len = mime_part->parsed_data.len;
	text_part->utf_stripped_text = (UText)UTEXT_INITIALIZER;
	text_part->flags |= flags;

	if (found_html) {
		if (!rspamd_message_process_html_text_part (task, text_part)) {
			return FALSE;
		}
	}
	else {
		if (!rspamd_message_process_plain_text_part (task, text_part)) {
			return FALSE;
		}
	}

	g_ptr_array_add (MESSAGE_FIELD (task, text_parts), text_part);
	mime_part->part_type = RSPAMD_MIME_PART_TEXT;
	mime_part->specific.txt = text_part;

	act = rspamd_check_gtube (task, text_part);
	if (act != METRIC_ACTION_NOACTION) {
		struct rspamd_action *action;
		gdouble score = NAN;

		action = rspamd_config_get_action_by_type (task->cfg, act);

		if (action) {
			score = action->threshold;

			rspamd_add_passthrough_result (task, action,
					RSPAMD_PASSTHROUGH_CRITICAL,
					score, "Gtube pattern", "GTUBE", 0, NULL);
		}

		rspamd_task_insert_result (task, GTUBE_SYMBOL, 0, NULL);

		return TRUE;
	}

	/* Post process part */
	rspamd_normalize_text_part (task, text_part);

	if (!IS_TEXT_PART_HTML (text_part)) {
		if (mime_part->parent_part) {
			struct rspamd_mime_part *parent = mime_part->parent_part;

			if (IS_PART_MULTIPART (parent) && parent->specific.mp->children->len == 2) {
				/*
				 * Use strict extraction mode: we will extract missing urls from
				 * an html part if needed
				 */
				rspamd_url_text_extract (task->task_pool, task, text_part,
						RSPAMD_URL_FIND_STRICT);
			}
			else {
				/*
				 * Fall back to full text extraction using TLD patterns
				 */
				rspamd_url_text_extract (task->task_pool, task, text_part,
						RSPAMD_URL_FIND_ALL);
			}
		}
		else {
			/*
			 * Fall back to full text extraction using TLD patterns
			*/
			rspamd_url_text_extract (task->task_pool, task, text_part,
					RSPAMD_URL_FIND_ALL);
		}
	}
	else {
		rspamd_url_text_extract (task->task_pool, task, text_part,
				RSPAMD_URL_FIND_STRICT);
	}

	if (text_part->exceptions) {
		text_part->exceptions = g_list_sort (text_part->exceptions,
				exceptions_compare_func);
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t)g_list_free,
				text_part->exceptions);
	}

	rspamd_mime_part_create_words (task, text_part);

	return TRUE;
}

/* Creates message from various data using libmagic to detect type */
static void
rspamd_message_from_data (struct rspamd_task *task, const guchar *start,
		gsize len)
{
	struct rspamd_content_type *ct = NULL;
	struct rspamd_mime_part *part;
	const char *mb = "application/octet-stream";
	gchar *mid;
	rspamd_ftok_t srch, *tok;
	gchar cdbuf[1024];

	g_assert (start != NULL);

	part = rspamd_mempool_alloc0 (task->task_pool, sizeof (*part));

	part->raw_data.begin = start;
	part->raw_data.len = len;
	part->parsed_data.begin = start;
	part->parsed_data.len = len;
	part->part_number = MESSAGE_FIELD (task, parts)->len;
	part->urls = g_ptr_array_new ();
	part->raw_headers = rspamd_message_headers_new ();
	part->headers_order = NULL;

	tok = rspamd_task_get_request_header (task, "Content-Type");

	if (tok) {
		/* We have Content-Type defined */
		ct = rspamd_content_type_parse (tok->begin, tok->len,
				task->task_pool);
		part->ct = ct;
	}
	else if (task->cfg && task->cfg->libs_ctx) {
		lua_State *L = task->cfg->lua_state;

		if (rspamd_lua_require_function (L,
				"lua_magic", "detect_mime_part")) {

			struct rspamd_mime_part **pmime;
			struct rspamd_task **ptask;

			pmime = lua_newuserdata (L, sizeof (struct rspamd_mime_part *));
			rspamd_lua_setclass (L, "rspamd{mimepart}", -1);
			*pmime = part;
			ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
			rspamd_lua_setclass (L, "rspamd{task}", -1);
			*ptask = task;

			if (lua_pcall (L, 2, 2, 0) != 0) {
				msg_err_task ("cannot detect type: %s", lua_tostring (L, -1));
			}
			else {
				if (lua_istable (L, -1)) {
					lua_pushstring (L, "ct");
					lua_gettable (L, -2);

					if (lua_isstring (L, -1)) {
						mb = rspamd_mempool_strdup (task->task_pool,
								lua_tostring (L, -1));
					}
				}
			}

			lua_settop (L, 0);
		}
		else {
			msg_err_task ("cannot require lua_magic.detect_mime_part");
		}

		if (mb) {
			srch.begin = mb;
			srch.len = strlen (mb);
			ct = rspamd_content_type_parse (srch.begin, srch.len,
					task->task_pool);

			if (!part->ct) {
				msg_info_task ("construct fake mime of type: %s", mb);
				part->ct = ct;
			}
			else {
				/* Check sanity */
				if (part->ct && (part->ct->flags & RSPAMD_CONTENT_TYPE_TEXT)) {
					RSPAMD_FTOK_FROM_STR (&srch, "application");

					if (rspamd_ftok_cmp (&ct->type, &srch) == 0) {
						msg_info_task ("construct fake mime of type: %s", mb);
						part->ct = ct;
					}
				}
				else {
					msg_info_task ("construct fake mime of type: %T/%T, detected %s",
							&part->ct->type, &part->ct->subtype, mb);
				}
			}

			part->detected_ct = ct;
		}
	}


	tok = rspamd_task_get_request_header (task, "Filename");

	if (tok) {
		rspamd_snprintf (cdbuf, sizeof (cdbuf), "inline; filename=\"%T\"", tok);
	}
	else {
		rspamd_snprintf (cdbuf, sizeof (cdbuf), "inline");
	}

	part->cd = rspamd_content_disposition_parse (cdbuf, strlen (cdbuf),
			task->task_pool);

	g_ptr_array_add (MESSAGE_FIELD (task, parts), part);
	rspamd_mime_parser_calc_digest (part);

	/* Generate message ID */
	mid = rspamd_mime_message_id_generate ("localhost.localdomain");
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_free, mid);
	MESSAGE_FIELD (task, message_id) = mid;
	task->queue_id = mid;
}

static void
rspamd_message_dtor (struct rspamd_message *msg)
{
	guint i;
	struct rspamd_mime_part *p;
	struct rspamd_mime_text_part *tp;


	PTR_ARRAY_FOREACH (msg->parts, i, p) {
		if (p->raw_headers) {
			rspamd_message_headers_unref (p->raw_headers);
		}

		if (IS_PART_MULTIPART (p)) {
			if (p->specific.mp->children) {
				g_ptr_array_free (p->specific.mp->children, TRUE);
			}
		}

		if (p->part_type == RSPAMD_MIME_PART_CUSTOM_LUA &&
				p->specific.lua_specific.cbref != -1) {
			luaL_unref (msg->task->cfg->lua_state,
					LUA_REGISTRYINDEX,
					p->specific.lua_specific.cbref);
		}

		if (p->urls) {
			g_ptr_array_unref (p->urls);
		}
	}

	PTR_ARRAY_FOREACH (msg->text_parts, i, tp) {
		if (tp->utf_words) {
			g_array_free (tp->utf_words, TRUE);
		}
		if (tp->normalized_hashes) {
			g_array_free (tp->normalized_hashes, TRUE);
		}
		if (tp->languages) {
			g_ptr_array_unref (tp->languages);
		}
	}

	rspamd_message_headers_unref (msg->raw_headers);

	g_ptr_array_unref (msg->text_parts);
	g_ptr_array_unref (msg->parts);

	kh_destroy (rspamd_url_hash, msg->urls);
}

struct rspamd_message*
rspamd_message_new (struct rspamd_task *task)
{
	struct rspamd_message *msg;

	msg = rspamd_mempool_alloc0 (task->task_pool, sizeof (*msg));

	msg->raw_headers = rspamd_message_headers_new ();
	msg->urls = kh_init (rspamd_url_hash);
	msg->parts = g_ptr_array_sized_new (4);
	msg->text_parts = g_ptr_array_sized_new (2);
	msg->task = task;

	REF_INIT_RETAIN (msg, rspamd_message_dtor);

	return msg;
}

gboolean
rspamd_message_parse (struct rspamd_task *task)
{
	const gchar *p;
	gsize len;
	guint i;
	GError *err = NULL;
	guint64 n[2], seed;

	if (RSPAMD_TASK_IS_EMPTY (task)) {
		/* Don't do anything with empty task */
		task->flags |= RSPAMD_TASK_FLAG_SKIP_PROCESS;
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
	 * So we check if a task has this line to avoid possible issues
	 */
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

	task->msg.begin = p;
	task->msg.len = len;

	/* Cleanup old message */
	if (task->message) {
		rspamd_message_unref (task->message);
	}

	task->message = rspamd_message_new (task);

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
		rspamd_message_from_data (task, p, len);
	}


	if (MESSAGE_FIELD (task, message_id) == NULL) {
		MESSAGE_FIELD (task, message_id) = "undef";
	}

	debug_task ("found %ud parts in message", MESSAGE_FIELD (task, parts)->len);
	if (task->queue_id == NULL) {
		task->queue_id = "undef";
	}

	rspamd_received_maybe_fix_task(task);

	struct rspamd_mime_part *part;

	/* Blake2b applied to string 'rspamd' */
	static const guchar RSPAMD_ALIGNED(32) hash_key[] = {
			0xef,0x43,0xae,0x80,0xcc,0x8d,0xc3,0x4c,
			0x6f,0x1b,0xd6,0x18,0x1b,0xae,0x87,0x74,
			0x0c,0xca,0xf7,0x8e,0x5f,0x2e,0x54,0x32,
			0xf6,0x79,0xb9,0x27,0x26,0x96,0x20,0x92,
			0x70,0x07,0x85,0xeb,0x83,0xf7,0x89,0xe0,
			0xd7,0x32,0x2a,0xd2,0x1a,0x64,0x41,0xef,
			0x49,0xff,0xc3,0x8c,0x54,0xf9,0x67,0x74,
			0x30,0x1e,0x70,0x2e,0xb7,0x12,0x09,0xfe,
	};

	memcpy (&seed, hash_key, sizeof (seed));

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
		n[0] = t1ha2_atonce128 (&n[1],
				part->digest, sizeof (part->digest),
				seed);

		seed = n[0] ^ n[1];
	}

	memcpy (MESSAGE_FIELD (task, digest), n, sizeof (n));

	if (MESSAGE_FIELD (task, subject)) {
		p = MESSAGE_FIELD (task, subject);
		len = strlen (p);
		n[0] = t1ha2_atonce128 (&n[1],
				p, len,
				seed);
		memcpy (MESSAGE_FIELD (task, digest), n, sizeof (n));
	}

	if (task->queue_id) {
		msg_info_task ("loaded message; id: <%s>; queue-id: <%s>; size: %z; "
				"checksum: <%*xs>",
				MESSAGE_FIELD (task, message_id), task->queue_id, task->msg.len,
				(gint)sizeof (MESSAGE_FIELD (task, digest)), MESSAGE_FIELD (task, digest));
	}
	else {
		msg_info_task ("loaded message; id: <%s>; size: %z; "
				"checksum: <%*xs>",
				MESSAGE_FIELD (task, message_id), task->msg.len,
				(gint)sizeof (MESSAGE_FIELD (task, digest)), MESSAGE_FIELD (task, digest));
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
	struct rspamd_mime_part *part;
	lua_State *L = NULL;
	gint magic_func_pos = -1, content_func_pos = -1, old_top = -1, funcs_top = -1;

	if (task->cfg) {
		L = task->cfg->lua_state;
	}

	rspamd_archives_process (task);

	if (L) {
		old_top = lua_gettop (L);
	}

	if (L && rspamd_lua_require_function (L,
			"lua_magic", "detect_mime_part")) {
		magic_func_pos = lua_gettop (L);
	}
	else {
		msg_err_task ("cannot require lua_magic.detect_mime_part");
	}

	if (L && rspamd_lua_require_function (L,
			"lua_content", "maybe_process_mime_part")) {
		content_func_pos = lua_gettop (L);
	}
	else {
		msg_err_task ("cannot require lua_content.maybe_process_mime_part");
	}

	if (L) {
		funcs_top = lua_gettop (L);
	}

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, parts), i, part) {
		if (magic_func_pos != -1 && part->parsed_data.len > 0) {
			struct rspamd_mime_part **pmime;
			struct rspamd_task **ptask;

			lua_pushcfunction (L, &rspamd_lua_traceback);
			gint err_idx = lua_gettop (L);
			lua_pushvalue (L, magic_func_pos);
			pmime = lua_newuserdata (L, sizeof (struct rspamd_mime_part *));
			rspamd_lua_setclass (L, "rspamd{mimepart}", -1);
			*pmime = part;
			ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
			rspamd_lua_setclass (L, "rspamd{task}", -1);
			*ptask = task;

			if (lua_pcall (L, 2, 2, err_idx) != 0) {
				msg_err_task ("cannot detect type: %s", lua_tostring (L, -1));
			}
			else {
				if (lua_istable (L, -1)) {
					const gchar *mb;

					/* First returned value */
					part->detected_ext = rspamd_mempool_strdup (task->task_pool,
							lua_tostring (L, -2));

					lua_pushstring (L, "ct");
					lua_gettable (L, -2);

					if (lua_isstring (L, -1)) {
						mb = lua_tostring (L, -1);

						if (mb) {
							rspamd_ftok_t srch;

							srch.begin = mb;
							srch.len = strlen (mb);
							part->detected_ct = rspamd_content_type_parse (srch.begin,
									srch.len,
									task->task_pool);
						}
					}

					lua_pop (L, 1);

					lua_pushstring (L, "type");
					lua_gettable (L, -2);

					if (lua_isstring (L, -1)) {
						part->detected_type = rspamd_mempool_strdup (task->task_pool,
								lua_tostring (L, -1));
					}

					lua_pop (L, 1);

					lua_pushstring (L, "no_text");
					lua_gettable (L, -2);

					if (lua_isboolean (L, -1)) {
						if (!!lua_toboolean (L, -1)) {
							part->flags |= RSPAMD_MIME_PART_NO_TEXT_EXTRACTION;
						}
					}

					lua_pop (L, 1);
				}
			}

			lua_settop (L, funcs_top);
		}

		/* Now detect content */
		if (content_func_pos != -1 && part->parsed_data.len > 0 &&
			part->part_type == RSPAMD_MIME_PART_UNDEFINED) {
			struct rspamd_mime_part **pmime;
			struct rspamd_task **ptask;

			lua_pushcfunction (L, &rspamd_lua_traceback);
			gint err_idx = lua_gettop (L);
			lua_pushvalue (L, content_func_pos);
			pmime = lua_newuserdata (L, sizeof (struct rspamd_mime_part *));
			rspamd_lua_setclass (L, "rspamd{mimepart}", -1);
			*pmime = part;
			ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
			rspamd_lua_setclass (L, "rspamd{task}", -1);
			*ptask = task;

			if (lua_pcall (L, 2, 0, err_idx) != 0) {
				msg_err_task ("cannot detect content: %s", lua_tostring (L, -1));
			}

			lua_settop (L, funcs_top);
		}

		/* Try to detect image before checking for text */
		rspamd_images_process_mime_part_maybe (task, part);

		/* Still no content detected, try text heuristic */
		if (part->part_type == RSPAMD_MIME_PART_UNDEFINED &&
				!(part->flags & RSPAMD_MIME_PART_NO_TEXT_EXTRACTION)) {
			rspamd_message_process_text_part_maybe (task, part);
		}
	}

	if (old_top != -1) {
		lua_settop (L, old_top);
	}

	/* Parse urls inside Subject header */
	if (MESSAGE_FIELD (task, subject)) {
		rspamd_url_find_multiple (task->task_pool, MESSAGE_FIELD (task, subject),
				strlen (MESSAGE_FIELD (task, subject)),
				RSPAMD_URL_FIND_STRICT, NULL,
				rspamd_url_task_subject_callback,
				task);
	}

	/* Calculate average words length and number of short words */
	struct rspamd_mime_text_part *text_part;
	gdouble *var;
	guint total_words = 0;

	PTR_ARRAY_FOREACH (MESSAGE_FIELD (task, text_parts), i, text_part) {
		if (!text_part->language) {
			rspamd_mime_part_detect_language (task, text_part);
		}

		rspamd_mime_part_extract_words (task, text_part);

		if (text_part->utf_words) {
			total_words += text_part->nwords;
		}
	}

	/* Calculate distance for 2-parts messages */
	if (i == 2) {
		p1 = g_ptr_array_index (MESSAGE_FIELD (task, text_parts), 0);
		p2 = g_ptr_array_index (MESSAGE_FIELD (task, text_parts), 1);

		/* First of all check parent object */
		if (p1->mime_part->parent_part) {
			rspamd_ftok_t srch;

			srch.begin = "alternative";
			srch.len = 11;

			if (rspamd_ftok_cmp (&p1->mime_part->parent_part->ct->subtype, &srch) == 0) {
				if (!IS_TEXT_PART_EMPTY (p1) && !IS_TEXT_PART_EMPTY (p2) &&
					p1->normalized_hashes && p2->normalized_hashes) {
					/*
					 * We also detect language on one part and propagate it to
					 * another one
					 */
					struct rspamd_mime_text_part *sel;

					/* Prefer HTML as text part is not displayed normally */
					if (IS_TEXT_PART_HTML (p1)) {
						sel = p1;
					}
					else if (IS_TEXT_PART_HTML (p2)) {
						sel = p2;
					}
					else {
						if (p1->utf_content.len > p2->utf_content.len) {
							sel = p1;
						}
						else {
							sel = p2;
						}
					}

					if (sel->language && sel->language[0]) {
						/* Propagate language */
						if (sel == p1) {
							if (p2->languages) {
								g_ptr_array_unref (p2->languages);
							}

							p2->language = sel->language;
							p2->languages = g_ptr_array_ref (sel->languages);
						}
						else {
							if (p1->languages) {
								g_ptr_array_unref (p1->languages);
							}

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

	rspamd_images_link (task);

	rspamd_tokenize_meta_words (task);
}


struct rspamd_message *
rspamd_message_ref (struct rspamd_message *msg)
{
	REF_RETAIN (msg);

	return msg;
}

void rspamd_message_unref (struct rspamd_message *msg)
{
	if (msg) {
		REF_RELEASE (msg);
	}
}

void rspamd_message_update_digest (struct rspamd_message *msg,
								   const void *input, gsize len)
{
	guint64 n[2];
	/* Sanity */
	G_STATIC_ASSERT (sizeof (n) == sizeof (msg->digest));

	memcpy (n, msg->digest, sizeof (msg->digest));
	n[0] = t1ha2_atonce128 (&n[1], input, len, n[0]);
	memcpy (msg->digest, n, sizeof (msg->digest));
}
