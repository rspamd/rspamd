/*-
 * Copyright 2017 Vsevolod Stakhov
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

#include "lang_detection.h"
#include "libutil/logger.h"
#include "libcryptobox/cryptobox.h"
#include "ucl.h"
#include <glob.h>
#include <unicode/utf8.h>
#include <unicode/ucnv.h>
#include <unicode/uchar.h>
#include <math.h>

static const gsize default_short_text_limit = 200;
static const gsize default_words = 30;
static const gdouble update_prob = 0.6;
static const gchar *default_languages_path = RSPAMD_PLUGINSDIR "/languages";

enum rspamd_language_elt_flags {
	RS_LANGUAGE_DEFAULT = 0,
	RS_LANGUAGE_LATIN = (1 <<0),
};

struct rspamd_language_elt {
	const gchar *name; /* e.g. "en" or "ru" */
	enum rspamd_language_elt_flags flags;
	guint unigramms_total; /* total frequencies for unigramms */
	guint bigramms_total; /* total frequencies for bigramms */
	guint trigramms_total; /* total frequencies for trigramms */
};

struct rspamd_ngramm_elt {
	struct rspamd_language_elt *elt;
	gdouble prob;
};

struct rspamd_lang_detector {
	GPtrArray *languages;
	GHashTable *unigramms; /* unigramms frequencies */
	GHashTable *bigramms; /* bigramms frequencies */
	GHashTable *trigramms; /* trigramms frequencies */
	UConverter *uchar_converter;
	gsize short_text_limit;
};

#define msg_debug_lang_det(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "langdet", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

static guint
rspamd_unigram_hash (gconstpointer key)
{
	return rspamd_cryptobox_fast_hash (key, sizeof (UChar), rspamd_hash_seed ());
}

static gboolean
rspamd_unigram_equal (gconstpointer v, gconstpointer v2)
{
	return memcmp (v, v2, sizeof (UChar)) == 0;
}

static guint
rspamd_bigram_hash (gconstpointer key)
{
	return rspamd_cryptobox_fast_hash (key, 2 * sizeof (UChar), rspamd_hash_seed ());
}

static gboolean
rspamd_bigram_equal (gconstpointer v, gconstpointer v2)
{
	return memcmp (v, v2, 2 * sizeof (UChar)) == 0;
}

static guint
rspamd_trigram_hash (gconstpointer key)
{
	return rspamd_cryptobox_fast_hash (key, 3 * sizeof (UChar), rspamd_hash_seed ());
}

static gboolean
rspamd_trigram_equal (gconstpointer v, gconstpointer v2)
{
	return memcmp (v, v2, 3 * sizeof (UChar)) == 0;
}

static void
rspamd_language_detector_ucs_lowercase (UChar *s, gsize len)
{
	gsize i;

	for (i = 0; i < len; i ++) {
		s[i] = u_tolower (s[i]);
	}
}

static gboolean
rspamd_language_detector_ucs_is_latin (UChar *s, gsize len)
{
	gsize i;
	gboolean ret = TRUE;

	for (i = 0; i < len; i ++) {
		if (!u_hasBinaryProperty (s[i], UCHAR_POSIX_ALNUM)) {
			ret = FALSE;
			break;
		}
	}

	return ret;
}

static void
rspamd_language_detector_init_ngramm (struct rspamd_config *cfg,
		struct rspamd_lang_detector *d,
		struct rspamd_language_elt *lelt,
		UChar *s, guint len, guint freq, guint total)
{
	GHashTable *target;
	GPtrArray *ar;
	struct rspamd_ngramm_elt *elt;
	guint i;
	gboolean found;

	switch (len) {
	case 1:
		target = d->unigramms;
		break;
	case 2:
		target = d->bigramms;
		break;
	case 3:
		target = d->trigramms;
		break;
	default:
		g_assert_not_reached ();
		break;
	}

	ar = g_hash_table_lookup (target, s);

	if (ar == NULL) {
		/* New element */
		ar = g_ptr_array_sized_new (32);
		elt = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (*elt));
		elt->elt = lelt;
		elt->prob = ((gdouble)freq) / ((gdouble)total);
		g_ptr_array_add (ar, elt);

		g_hash_table_insert (target, s, ar);
	}
	else {
		/* Check sanity */
		found = FALSE;

		PTR_ARRAY_FOREACH (ar, i, elt) {
			if (strcmp (elt->elt->name, lelt->name) == 0) {
				found = TRUE;
				elt->prob += ((gdouble)freq) / ((gdouble)total);
				break;
			}
		}

		if (!found) {
			elt = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (*elt));
			elt->elt = lelt;
			elt->prob = ((gdouble)freq) / ((gdouble)total);
			g_ptr_array_add (ar, elt);
		}
	}
}

static void
rspamd_language_detector_read_file (struct rspamd_config *cfg,
		struct rspamd_lang_detector *d,
		const gchar *path)
{
	struct ucl_parser *parser;
	ucl_object_t *top;
	const ucl_object_t *freqs, *n_words, *cur;
	ucl_object_iter_t it = NULL;
	UErrorCode uc_err = U_ZERO_ERROR;
	struct rspamd_language_elt *nelt;
	gchar *pos;
	guint total = 0, total_latin = 0, total_ngramms = 0;

	parser = ucl_parser_new (UCL_PARSER_NO_FILEVARS);
	if (!ucl_parser_add_file (parser, path)) {
		msg_warn_config ("cannot parse file %s: %s", path,
				ucl_parser_get_error (parser));
		ucl_parser_free (parser);

		return;
	}

	top = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	freqs = ucl_object_lookup (top, "freq");

	if (freqs == NULL) {
		msg_warn_config ("file %s has no 'freq' key", path);
		ucl_object_unref (top);

		return;
	}

	pos = strrchr (path, '/');
	g_assert (pos != NULL);
	nelt = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*nelt));
	nelt->name = rspamd_mempool_strdup (cfg->cfg_pool, pos + 1);
	/* Remove extension */
	pos = strchr (nelt->name, '.');
	g_assert (pos != NULL);
	*pos = '\0';

	n_words = ucl_object_lookup (top, "n_words");

	if (n_words == NULL || ucl_object_type (n_words) != UCL_ARRAY ||
			n_words->len != 3) {
		msg_warn_config ("cannot find n_words in language %s", nelt->name);
		ucl_object_unref (top);

		return;
	}
	else {
		nelt->unigramms_total = ucl_object_toint (ucl_array_find_index (n_words,
				0));
		nelt->bigramms_total = ucl_object_toint (ucl_array_find_index (n_words,
				1));
		nelt->trigramms_total = ucl_object_toint (ucl_array_find_index (n_words,
				2));
	}

	while ((cur = ucl_object_iterate (freqs, &it, true)) != NULL) {
		const gchar *key;
		gsize keylen;
		guint freq, nsym;
		UChar *ucs_key;

		key = ucl_object_keyl (cur, &keylen);
		freq = ucl_object_toint (cur);

		if (key != NULL) {
			ucs_key = rspamd_mempool_alloc (cfg->cfg_pool,
					(keylen + 1) * sizeof (UChar));

			nsym = ucnv_toUChars (d->uchar_converter, ucs_key, keylen + 1, key,
					keylen, &uc_err);

			if (uc_err != U_ZERO_ERROR) {
				msg_warn_config ("cannot convert key to unicode: %s",
						u_errorName (uc_err));

				continue;
			}

			rspamd_language_detector_ucs_lowercase (ucs_key, nsym);
			if (nsym == 2) {
				/* We have a digraph */
				total = nelt->bigramms_total;
			}
			else if (nsym == 3) {
				total = nelt->trigramms_total;
			}
			else if (nsym == 1) {
				total = nelt->unigramms_total;
			}
			else if (nsym > 3) {
				msg_warn_config ("have more than 3 characters in key: %d", nsym);
				continue;
			}

			rspamd_language_detector_init_ngramm (cfg, d, nelt, ucs_key, nsym,
					freq, total);

			if (rspamd_language_detector_ucs_is_latin (ucs_key, nsym)) {
				total_latin ++;
			}

			total_ngramms ++;
		}
	}

	if (total_latin >= total_ngramms * 2 / 3) {
		nelt->flags |= RS_LANGUAGE_LATIN;
	}

	msg_info_config ("loaded %s language, %d unigramms, %d digramms, %d trigramms",
			nelt->name,
			(gint)nelt->unigramms_total,
			(gint)nelt->bigramms_total,
			(gint)nelt->trigramms_total);

	g_ptr_array_add (d->languages, nelt);
	ucl_object_unref (top);
}

struct rspamd_lang_detector*
rspamd_language_detector_init (struct rspamd_config *cfg)
{
	const ucl_object_t *section, *elt;
	const gchar *languages_path = default_languages_path;
	glob_t gl;
	size_t i, short_text_limit = default_short_text_limit;
	UErrorCode uc_err = U_ZERO_ERROR;
	GString *languages_pattern;
	struct rspamd_lang_detector *ret = NULL;

	section = ucl_object_lookup (cfg->rcl_obj, "lang_detection");

	if (section != NULL) {
		elt = ucl_object_lookup (section, "languages");

		if (elt) {
			languages_path = ucl_object_tostring (elt);
		}

		elt = ucl_object_lookup (section, "short_text_limit");

		if (elt) {
			short_text_limit = ucl_object_toint (elt);
		}
	}

	languages_pattern = g_string_sized_new (PATH_MAX);
	rspamd_printf_gstring (languages_pattern, "%s/*.json", languages_path);
	memset (&gl, 0, sizeof (gl));

	if (glob (languages_pattern->str, 0, NULL, &gl) != 0) {
		msg_err_config ("cannot read any files matching %v", languages_pattern);
		goto end;
	}

	ret = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (*ret));
	ret->languages = g_ptr_array_sized_new (gl.gl_pathc);
	ret->uchar_converter = ucnv_open ("UTF-8", &uc_err);
	ret->short_text_limit = short_text_limit;
	/* Map from ngramm in ucs32 to GPtrArray of rspamd_language_elt */
	ret->unigramms = g_hash_table_new_full (rspamd_unigram_hash,
			rspamd_unigram_equal, NULL, rspamd_ptr_array_free_hard);
	ret->bigramms = g_hash_table_new_full (rspamd_bigram_hash,
			rspamd_bigram_equal, NULL, rspamd_ptr_array_free_hard);
	ret->trigramms = g_hash_table_new_full (rspamd_trigram_hash,
			rspamd_trigram_equal, NULL, rspamd_ptr_array_free_hard);

	g_assert (uc_err == U_ZERO_ERROR);

	for (i = 0; i < gl.gl_pathc; i ++) {
		rspamd_language_detector_read_file (cfg, ret, gl.gl_pathv[i]);
	}

	msg_info_config ("loaded %d languages", (gint)ret->languages->len);
end:
	if (gl.gl_pathc > 0) {
		globfree (&gl);
	}

	g_string_free (languages_pattern, TRUE);

	return ret;
}


void
rspamd_language_detector_to_ucs (struct rspamd_lang_detector *d,
		rspamd_mempool_t *pool,
		rspamd_stat_token_t *utf_token, rspamd_stat_token_t *ucs_token)
{
	UChar *out;
	int32_t nsym;
	UErrorCode uc_err = U_ZERO_ERROR;

	ucs_token->flags = utf_token->flags;
	out = rspamd_mempool_alloc (pool, sizeof (*out) * (utf_token->len + 1));
	nsym = ucnv_toUChars (d->uchar_converter, out, (utf_token->len + 1),
			utf_token->begin, utf_token->len, &uc_err);

	if (nsym >= 0) {
		rspamd_language_detector_ucs_lowercase (out, nsym);
		ucs_token->begin = (const gchar *) out;
		ucs_token->len = nsym;
	}
	else {
		ucs_token->len = 0;
	}
}

static void
rspamd_language_detector_random_select (GArray *ucs_tokens, guint nwords,
		goffset *offsets_out)
{
	guint step_len, remainder, i, out_idx;
	guint64 coin, sel;
	goffset tmp;

	g_assert (nwords != 0);
	g_assert (offsets_out != NULL);
	g_assert (ucs_tokens->len >= nwords);
	/*
	 * We split input array into `nwords` parts. For each part we randomly select
	 * an element from this particular split. Here is an example:
	 *
	 * nwords=2, input_len=5
	 *
	 * w1 w2 w3   w4 w5
	 * ^          ^
	 * part1      part2
	 *  vv         vv
	 *  w2         w5
	 *
	 * So we have 2 output words from 5 input words selected randomly within
	 * their splits. It is not uniform distribution but it seems to be better
	 * to include words from different text parts
	 */
	step_len = ucs_tokens->len / nwords;
	remainder = ucs_tokens->len % nwords;

	out_idx = 0;
	coin = rspamd_random_uint64_fast ();
	sel = coin % (step_len + remainder);
	offsets_out[out_idx] = sel;

	for (i = step_len + remainder; i < ucs_tokens->len;
			i += step_len, out_idx ++) {
		coin = rspamd_random_uint64_fast ();
		sel = (coin % step_len) + i;
		offsets_out[out_idx] = sel;
	}

	/*
	 * Fisher-Yates algorithm:
	 * for i from 0 to n−2 do
     *   j ← random integer such that i ≤ j < n
     *   exchange a[i] and a[j]
     */
	if (out_idx > 2) {
		for (i = 0; i < out_idx - 2; i++) {
			coin = rspamd_random_uint64_fast ();
			sel = (coin % (out_idx - i)) + i;
			/* swap */
			tmp = offsets_out[i];
			offsets_out[i] = offsets_out[sel];
			offsets_out[sel] = tmp;
		}
	}
}

enum rspamd_language_gramm_type {
	rs_unigramm = 0,
	rs_bigramm,
	rs_trigramm
};

static goffset
rspamd_language_detector_next_ngramm (rspamd_stat_token_t *tok, UChar *window,
		guint wlen, goffset cur_off)
{
	guint i;

	if (wlen > 1) {
		/* Deal with spaces at the beginning and ending */

		if (cur_off == 0) {
			window[0] = (UChar)' ';

			for (i = 0; i < wlen - 1; i ++) {
				window[i + 1] = *(((UChar *)tok->begin) + i);
			}
		}
		else if (cur_off + wlen == tok->len + 1) {
			/* Add trailing space */
			for (i = 0; i < wlen - 1; i ++) {
				window[i] = *(((UChar *)tok->begin) + cur_off + i);
			}
			window[wlen - 1] = (UChar)' ';
		}
		else if (cur_off + wlen > tok->len + 1) {
			/* No more fun */
			return -1;
		}

		/* Normal case */
		for (i = 0; i < wlen; i ++) {
			window[i] = *(((UChar *)tok->begin) + cur_off + i);
		}
	}
	else {
		if (tok->len <= cur_off) {
			return -1;
		}

		window[0] = *(((UChar *)tok->begin) + cur_off);
	}

	return cur_off + 1;
}

/*
 * Do full guess for a specific ngramm, checking all languages defined
 */
static void
rspamd_language_detector_process_ngramm_full (struct rspamd_task *task,
		struct rspamd_lang_detector *d,
		UChar *window, enum rspamd_language_gramm_type type,
		GHashTable *candidates)
{
	guint i;
	GPtrArray *ar;
	struct rspamd_ngramm_elt *elt;
	struct rspamd_lang_detector_res *cand;
	GHashTable *ngramms;

	switch (type) {
	case rs_unigramm:
		ngramms = d->unigramms;
		break;
	case rs_bigramm:
		ngramms = d->bigramms;
		break;
	case rs_trigramm:
		ngramms = d->trigramms;
		break;
	}


	ar = g_hash_table_lookup (ngramms, window);

	if (ar) {
		PTR_ARRAY_FOREACH (ar, i, elt) {
			cand = g_hash_table_lookup (candidates, elt->elt->name);

			if (cand == NULL) {
				cand = g_malloc (sizeof (*cand));
				cand->elt = elt->elt;
				cand->lang = elt->elt->name;
				cand->prob = elt->prob;

				g_hash_table_insert (candidates, (gpointer)cand->lang, cand);
			} else {
				/* Update guess */
				cand->prob += elt->prob;
			}
		}
	}
}

static void
rspamd_language_detector_detect_word (struct rspamd_task *task,
		struct rspamd_lang_detector *d,
		rspamd_stat_token_t *tok, GHashTable *candidates,
		enum rspamd_language_gramm_type type)
{
	guint wlen;
	UChar window[3];
	goffset cur = 0;

	switch (type) {
	case rs_unigramm:
		wlen = 1;
		break;
	case rs_bigramm:
		wlen = 2;
		break;
	case rs_trigramm:
		wlen = 3;
		break;
	}

	/* Split words */
	while ((cur = rspamd_language_detector_next_ngramm (tok, window, wlen, cur))
			!= -1) {
		rspamd_language_detector_process_ngramm_full (task,
				d, window, type, candidates);
	}
}

/*
 * Converts frequencies to log probabilities, filter those candidates who
 * has the lowest probabilities
 */
static void
rspamd_language_detector_filter_negligible (struct rspamd_task *task,
		GHashTable *candidates)
{
	GHashTableIter it;
	gpointer k, v;
	struct rspamd_lang_detector_res *cand;
	guint filtered = 0;
	gdouble max_prob = -(G_MAXDOUBLE);

	/* Normalize step */
	g_hash_table_iter_init (&it, candidates);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		cand = (struct rspamd_lang_detector_res *)v;

		if (cand->prob == 0) {
			g_hash_table_iter_remove (&it);
		}
		else {
			cand->prob = log2 (cand->prob);

			if (cand->prob > max_prob) {
				max_prob = cand->prob;
			}
		}
	}

	g_hash_table_iter_init (&it, candidates);
	/* Filter step */
	while (g_hash_table_iter_next (&it, &k, &v)) {
		cand = (struct rspamd_lang_detector_res *) v;

		/*
		 * Probabilities are logarithmic, so if prob1 - prob2 > 4, it means that
		 * prob2 is 2^4 less than prob1
		 */
		if (max_prob - cand->prob > 1.5) {
			msg_debug_lang_det ("exclude language %s: %.3f (%.3f max)",
					cand->lang, cand->prob, max_prob);
			g_hash_table_iter_remove (&it);
			filtered ++;
		}
	}

	msg_debug_lang_det ("removed %d languages", filtered);
}

static void
rspamd_language_detector_detect_type (struct rspamd_task *task,
		guint nwords,
		struct rspamd_lang_detector *d,
		GArray *ucs_tokens,
		GHashTable *candidates,
		enum rspamd_language_gramm_type type)
{
	guint nparts = MIN (ucs_tokens->len, nwords);
	goffset *selected_words;
	rspamd_stat_token_t *tok;
	guint i;

	selected_words = g_new0 (goffset, nparts);
	rspamd_language_detector_random_select (ucs_tokens, nparts, selected_words);
	msg_debug_lang_det ("randomly selected %d words", nparts);

	/* Deal with the first word in a special case */
	tok = &g_array_index (ucs_tokens, rspamd_stat_token_t, selected_words[0]);

	rspamd_language_detector_detect_word (task, d, tok, candidates, type);

	for (i = 1; i < nparts; i ++) {
		tok = &g_array_index (ucs_tokens, rspamd_stat_token_t, selected_words[i]);
		rspamd_language_detector_detect_word (task, d, tok, candidates, type);
	}

	/* Filter negligible candidates */
	rspamd_language_detector_filter_negligible (task, candidates);
	g_free (selected_words);
}

static gint
rspamd_language_detector_cmp (gconstpointer a, gconstpointer b)
{
	const struct rspamd_lang_detector_res
			*canda = *(const struct rspamd_lang_detector_res **)a,
			*candb = *(const struct rspamd_lang_detector_res **)b;

	if (canda->prob > candb->prob) {
		return -1;
	}
	else if (candb->prob > canda->prob) {
		return 1;
	}

	return 0;
}

enum rspamd_language_detected_type {
	rs_detect_none = 0,
	rs_detect_single,
	rs_detect_multiple,
};

static enum rspamd_language_detected_type
rspamd_language_detector_try_ngramm (struct rspamd_task *task,
		guint nwords,
		struct rspamd_lang_detector *d,
		GArray *ucs_tokens,
		enum rspamd_language_gramm_type type,
		GHashTable *candidates)
{
	guint cand_len;

	rspamd_language_detector_detect_type (task,
			nwords,
			d,
			ucs_tokens,
			candidates,
			type);

	cand_len = g_hash_table_size (candidates);

	if (cand_len == 0) {
		return rs_detect_none;
	}
	else if (cand_len == 1) {
		return rs_detect_single;
	}

	return rs_detect_multiple;
}

GPtrArray *
rspamd_language_detector_detect (struct rspamd_task *task,
		struct rspamd_lang_detector *d,
		GArray *ucs_tokens, gsize words_len)
{
	GHashTable *candidates, *tcandidates;
	GPtrArray *result;
	GHashTableIter it;
	gpointer k, v;
	gdouble mean, std;
	struct rspamd_lang_detector_res *cand;
	enum rspamd_language_detected_type r;

	if (ucs_tokens->len == 0) {
		return g_ptr_array_new ();
	}

	candidates = g_hash_table_new_full (rspamd_str_hash, rspamd_str_equal,
			NULL, g_free);

	if (words_len < d->short_text_limit) {
		/* For short text, start directly from trigramms */
		msg_debug_lang_det ("text is less than %z words: %z, start with trigramms",
				d->short_text_limit, words_len);
		r = rspamd_language_detector_try_ngramm (task, default_words, d,
				ucs_tokens, rs_trigramm,
				candidates);

		if (r == rs_detect_none) {
			msg_debug_lang_det ("short mode; no trigramms found, switch to bigramms");
			r = rspamd_language_detector_try_ngramm (task, default_words, d,
					ucs_tokens, rs_bigramm,
					candidates);

			if (r == rs_detect_none) {
				msg_debug_lang_det ("short mode; no trigramms found, "
						"switch to unigramms");
				r = rspamd_language_detector_try_ngramm (task, default_words,
						d, ucs_tokens, rs_unigramm,
						candidates);
			}
		}
	}
	else {
		/* Start with unigramms */
		r = rspamd_language_detector_try_ngramm (task, default_words,
				d, ucs_tokens, rs_unigramm,
				candidates);

		switch (r) {
		case rs_detect_none:
		case rs_detect_single:
			msg_debug_lang_det ("no unigramms found, try bigramms");
			break;
		case rs_detect_multiple:
			/* Try to improve guess */
			msg_debug_lang_det ("unigramms pass finished, found %d candidates",
					(gint)g_hash_table_size (candidates));
			tcandidates = g_hash_table_new_full (rspamd_str_hash, rspamd_str_equal,
					NULL, g_free);
			r = rspamd_language_detector_try_ngramm (task, default_words,
					d, ucs_tokens, rs_trigramm,
					tcandidates);

			switch (r) {
			case rs_detect_none:
				/* Revert to unigramms result */
				g_hash_table_unref (tcandidates);
				break;
			case rs_detect_single:
				/* We have good enough result, return it */
				g_hash_table_unref (candidates);
				candidates = tcandidates;
				break;
			case rs_detect_multiple:
				mean = 0.0;
				std = 0.0;
				g_hash_table_iter_init (&it, tcandidates);

				/* Check distirbution */
				while (g_hash_table_iter_next (&it, &k, &v)) {
					cand = (struct rspamd_lang_detector_res *) v;
					mean += cand->prob;
				}

				mean /= g_hash_table_size (tcandidates);

				g_hash_table_iter_init (&it, tcandidates);
				while (g_hash_table_iter_next (&it, &k, &v)) {
					gdouble err;
					cand = (struct rspamd_lang_detector_res *) v;
					err = cand->prob - mean;
					std += fabs (err);
				}

				std /= g_hash_table_size (tcandidates);
				g_hash_table_unref (candidates);
				candidates = tcandidates;

				msg_debug_lang_det ("trigramms checked, %.3f mean, %.4f stddev",
						mean, std);

				if (std / fabs (mean) < 0.01) {
					/* Try trigramms */
					tcandidates = g_hash_table_new_full (rspamd_str_hash,
							rspamd_str_equal,
							NULL, g_free);

					r = rspamd_language_detector_try_ngramm (task,
							default_words * 2,
							d,
							ucs_tokens,
							rs_trigramm,
							tcandidates);

					if (r != rs_detect_none) {
						/* TODO: check if we have better distribution here */
						g_hash_table_unref (candidates);
						candidates = tcandidates;
					}
				}
				break;
			}
			break;
		}
	}

	/* Now, convert hash to array and sort it */
	result = g_ptr_array_new_full (g_hash_table_size (candidates), g_free);
	g_hash_table_iter_init (&it, candidates);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		cand = (struct rspamd_lang_detector_res *) v;
		msg_debug_lang_det ("final probability %s -> %.2f", cand->lang, cand->prob);
		g_ptr_array_add (result, cand);
		g_hash_table_iter_steal (&it);
	}

	g_ptr_array_sort (result, rspamd_language_detector_cmp);
	g_hash_table_unref (candidates);

	return result;
}