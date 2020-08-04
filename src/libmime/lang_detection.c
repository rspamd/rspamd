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
#include "libserver/logger.h"
#include "libcryptobox/cryptobox.h"
#include "libutil/multipattern.h"
#include "ucl.h"
#include "khash.h"
#include "libstemmer.h"

#include <glob.h>
#include <unicode/utf8.h>
#include <unicode/utf16.h>
#include <unicode/ucnv.h>
#include <unicode/uchar.h>
#include <unicode/ustring.h>
#include <math.h>

static const gsize default_short_text_limit = 10;
static const gsize default_words = 80;
static const gdouble update_prob = 0.6;
static const gchar *default_languages_path = RSPAMD_SHAREDIR "/languages";

#undef EXTRA_LANGDET_DEBUG

struct rspamd_language_unicode_match {
	const gchar *lang;
	gint unicode_code;
};

/*
 * List of languages detected by unicode scripts
 */
static const struct rspamd_language_unicode_match unicode_langs[] = {
		{"el", RSPAMD_UNICODE_GREEK},
		{"ml", RSPAMD_UNICODE_MALAYALAM},
		{"te", RSPAMD_UNICODE_TELUGU},
		{"ta", RSPAMD_UNICODE_TAMIL},
		{"gu", RSPAMD_UNICODE_GUJARATI},
		{"th", RSPAMD_UNICODE_THAI},
		{"ka", RSPAMD_UNICODE_GEORGIAN},
		{"si", RSPAMD_UNICODE_SINHALA},
		{"hy", RSPAMD_UNICODE_ARMENIAN},
		{"ja", RSPAMD_UNICODE_JP},
		{"ko", RSPAMD_UNICODE_HANGUL},
};

/*
 * Top languages
 */
static const gchar *tier0_langs[] = {
		"en",
};
static const gchar *tier1_langs[] = {
		"fr", "it", "de", "es", "nl",
		"pt", "ru", "pl", "tk", "th", "ar"
};

enum rspamd_language_category {
	RSPAMD_LANGUAGE_LATIN = 0,
	RSPAMD_LANGUAGE_CYRILLIC,
	RSPAMD_LANGUAGE_DEVANAGARI,
	RSPAMD_LANGUAGE_ARAB,
	RSPAMD_LANGUAGE_MAX,
};

struct rspamd_language_elt {
	const gchar *name; /* e.g. "en" or "ru" */
	gint flags; /* enum rspamd_language_elt_flags */
	enum rspamd_language_category category;
	guint trigramms_words;
	guint stop_words;
	gdouble mean;
	gdouble std;
	guint occurencies; /* total number of parts with this language */
};

struct rspamd_ngramm_elt {
	struct rspamd_language_elt *elt;
	gdouble prob;
};

struct rspamd_ngramm_chain {
	GPtrArray *languages;
	gdouble mean;
	gdouble std;
	gchar *utf;
};

struct rspamd_stop_word_range {
	guint start;
	guint stop;
	struct rspamd_language_elt *elt;
};

struct rspamd_stop_word_elt {
	struct rspamd_multipattern *mp;
	GArray *ranges; /* of rspamd_stop_word_range */
};

#define msg_debug_lang_det(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_langdet_log_id, "langdet", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_lang_det_cfg(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_langdet_log_id, "langdet", cfg->cfg_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE(langdet)

static const struct rspamd_language_unicode_match *
rspamd_language_search_unicode_match (const gchar *key,
		const struct rspamd_language_unicode_match *elts, size_t nelts)
{
	size_t i;

	for (i = 0; i < nelts; i++) {
		if (strcmp (elts[i].lang, key) == 0) {
			return &elts[i];
		}
	}

	return NULL;
}

static gboolean
rspamd_language_search_str (const gchar *key, const gchar *elts[], size_t nelts)
{
	size_t i;

	for (i = 0; i < nelts; i++) {
		if (strcmp (elts[i], key) == 0) {
			return TRUE;
		}
	}
	return FALSE;
}

static guint
rspamd_trigram_hash_func (gconstpointer key)
{
	return rspamd_cryptobox_fast_hash (key, 3 * sizeof (UChar32),
			rspamd_hash_seed ());
}

static gboolean
rspamd_trigram_equal_func (gconstpointer v, gconstpointer v2)
{
	return memcmp (v, v2, 3 * sizeof (UChar32)) == 0;
}

KHASH_INIT (rspamd_trigram_hash, const UChar32 *, struct rspamd_ngramm_chain, true,
		rspamd_trigram_hash_func, rspamd_trigram_equal_func);
KHASH_INIT (rspamd_candidates_hash, const gchar *,
		struct rspamd_lang_detector_res *, true,
		rspamd_str_hash, rspamd_str_equal);
KHASH_INIT (rspamd_stopwords_hash, rspamd_ftok_t *,
		char, false,
		rspamd_ftok_hash, rspamd_ftok_equal);

struct rspamd_lang_detector {
	GPtrArray *languages;
	khash_t(rspamd_trigram_hash) *trigramms[RSPAMD_LANGUAGE_MAX]; /* trigramms frequencies */
	struct rspamd_stop_word_elt stop_words[RSPAMD_LANGUAGE_MAX];
	khash_t(rspamd_stopwords_hash) *stop_words_norm;
	UConverter *uchar_converter;
	gsize short_text_limit;
	gsize total_occurencies; /* number of all languages found */
	ref_entry_t ref;
};

static void
rspamd_language_detector_ucs_lowercase (UChar32 *s, gsize len)
{
	gsize i;

	for (i = 0; i < len; i ++) {
		s[i] = u_tolower (s[i]);
	}
}

static gboolean
rspamd_language_detector_ucs_is_latin (const UChar32 *s, gsize len)
{
	gsize i;
	gboolean ret = TRUE;

	for (i = 0; i < len; i ++) {
		if (s[i] >= 128 || !(g_ascii_isalnum (s[i]) || s[i] == ' ')) {
			ret = FALSE;
			break;
		}
	}

	return ret;
}

struct rspamd_language_ucs_elt {
	guint freq;
	const gchar *utf;
	UChar32 s[0];
};

static void
rspamd_language_detector_init_ngramm (struct rspamd_config *cfg,
									  struct rspamd_lang_detector *d,
									  struct rspamd_language_elt *lelt,
									  struct rspamd_language_ucs_elt *ucs,
									  guint len,
									  guint freq,
									  guint total,
									  khash_t (rspamd_trigram_hash) *htb)
{
	struct rspamd_ngramm_chain *chain = NULL, st_chain;
	struct rspamd_ngramm_elt *elt;
	khiter_t k;
	guint i;
	gboolean found;

	switch (len) {
	case 1:
	case 2:
		g_assert_not_reached ();
		break;
	case 3:
		k = kh_get (rspamd_trigram_hash, htb, ucs->s);
		if (k != kh_end (htb)) {
			chain = &kh_value (htb, k);
		}
		break;
	default:
		g_assert_not_reached ();
		break;
	}

	if (chain == NULL) {
		/* New element */
		chain = &st_chain;
		memset (chain, 0, sizeof (st_chain));
		chain->languages = g_ptr_array_sized_new (32);
		rspamd_mempool_add_destructor (cfg->cfg_pool, rspamd_ptr_array_free_hard,
				chain->languages);
		chain->utf = rspamd_mempool_strdup (cfg->cfg_pool, ucs->utf);
		elt = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (*elt));
		elt->elt = lelt;
		elt->prob = ((gdouble)freq) / ((gdouble)total);
		g_ptr_array_add (chain->languages, elt);

		k = kh_put (rspamd_trigram_hash, htb, ucs->s, &i);
		kh_value (htb, k) = *chain;
	}
	else {
		/* Check sanity */
		found = FALSE;

		PTR_ARRAY_FOREACH (chain->languages, i, elt) {
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
			g_ptr_array_add (chain->languages, elt);
		}
	}
}

static inline enum rspamd_language_category
rspamd_language_detector_get_category (guint uflags)
{
	enum rspamd_language_category cat = RSPAMD_LANGUAGE_LATIN;

	if (uflags & RSPAMD_UNICODE_CYRILLIC) {
		cat = RSPAMD_LANGUAGE_CYRILLIC;
	}
	else if (uflags & RSPAMD_UNICODE_DEVANAGARI) {
		cat = RSPAMD_LANGUAGE_DEVANAGARI;
	}
	else if (uflags & RSPAMD_UNICODE_ARABIC) {
		cat = RSPAMD_LANGUAGE_ARAB;
	}

	return cat;
}

static const gchar *
rspamd_language_detector_print_flags (struct rspamd_language_elt *elt)
{
	static gchar flags_buf[256];
	goffset r = 0;

	if (elt->flags & RS_LANGUAGE_TIER1) {
		r += rspamd_snprintf (flags_buf + r, sizeof (flags_buf) - r, "tier1,");
	}
	if (elt->flags & RS_LANGUAGE_TIER0) {
		r += rspamd_snprintf (flags_buf + r, sizeof (flags_buf) - r, "tier0,");
	}
	if (elt->flags & RS_LANGUAGE_LATIN) {
		r += rspamd_snprintf (flags_buf + r, sizeof (flags_buf) - r, "latin,");
	}

	if (r > 0) {
		flags_buf[r - 1] = '\0';
	}
	else {
		flags_buf[r] = '\0';
	}

	return flags_buf;
}

static gint
rspamd_language_detector_cmp_ngramm (gconstpointer a, gconstpointer b)
{
	struct rspamd_language_ucs_elt *e1 = *(struct rspamd_language_ucs_elt **)a;
	struct rspamd_language_ucs_elt *e2 = *(struct rspamd_language_ucs_elt **)b;

	return (gint)e2->freq - (gint)e1->freq;
}

static void
rspamd_language_detector_read_file (struct rspamd_config *cfg,
		struct rspamd_lang_detector *d,
		const gchar *path,
		const ucl_object_t *stop_words)
{
	struct ucl_parser *parser;
	ucl_object_t *top;
	const ucl_object_t *freqs, *n_words, *cur, *type, *flags;
	ucl_object_iter_t it = NULL;
	UErrorCode uc_err = U_ZERO_ERROR;
	struct rspamd_language_elt *nelt;
	struct rspamd_language_ucs_elt *ucs_elt;
	khash_t (rspamd_trigram_hash) *htb = NULL;
	gchar *pos;
	guint total = 0, total_latin = 0, total_ngramms = 0, i, skipped,
			loaded, nstop = 0;
	gdouble mean = 0, std = 0, delta = 0, delta2 = 0, m2 = 0;
	enum rspamd_language_category cat = RSPAMD_LANGUAGE_MAX;

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
		nelt->trigramms_words = ucl_object_toint (ucl_array_find_index (n_words,
				2));
	}

	type = ucl_object_lookup (top, "type");

	if (type == NULL || ucl_object_type (type) != UCL_STRING) {
		msg_debug_config ("cannot find type in language %s", nelt->name);
		ucl_object_unref (top);

		return;
	}
	else {
		const gchar *stype = ucl_object_tostring (type);

		if (strcmp (stype, "latin") == 0) {
			cat = RSPAMD_LANGUAGE_LATIN;
		}
		else if (strcmp (stype, "cyrillic") == 0) {
			cat = RSPAMD_LANGUAGE_CYRILLIC;
		}
		else if (strcmp (stype, "arab") == 0) {
			cat = RSPAMD_LANGUAGE_ARAB;
		}
		else if (strcmp (stype, "devanagari") == 0) {
			cat = RSPAMD_LANGUAGE_DEVANAGARI;
		}
		else {
			msg_debug_config ("unknown type %s of language %s", stype, nelt->name);
			ucl_object_unref (top);

			return;
		}
	}

	flags = ucl_object_lookup (top, "flags");

	if (flags != NULL && ucl_object_type (flags) == UCL_ARRAY) {
		ucl_object_iter_t it = NULL;
		const ucl_object_t *cur;

		while ((cur = ucl_object_iterate (flags, &it, true)) != NULL) {
			const gchar *fl = ucl_object_tostring (cur);

			if (cur) {
				if (strcmp (fl, "diacritics") == 0) {
					nelt->flags |= RS_LANGUAGE_DIACRITICS;
				}
				else if (strcmp (fl, "ascii") == 0) {
					nelt->flags |= RS_LANGUAGE_ASCII;
				}
				else {
					msg_debug_config ("unknown flag %s of language %s", fl, nelt->name);
				}
			}
			else {
				msg_debug_config ("unknown flags type of language %s", nelt->name);
			}
		}
	}

	if (stop_words) {
		const ucl_object_t *specific_stop_words;

		specific_stop_words = ucl_object_lookup (stop_words, nelt->name);

		if (specific_stop_words) {
			struct sb_stemmer *stem = NULL;
			it = NULL;
			const ucl_object_t *w;
			guint start, stop;

			stem = sb_stemmer_new (nelt->name, "UTF_8");
			start = rspamd_multipattern_get_npatterns (d->stop_words[cat].mp);

			while ((w = ucl_object_iterate (specific_stop_words, &it, true)) != NULL) {
				gsize wlen;
				const char *word = ucl_object_tolstring (w, &wlen);
				const char *saved;
				guint mp_flags = RSPAMD_MULTIPATTERN_ICASE|RSPAMD_MULTIPATTERN_UTF8;

				if (rspamd_multipattern_has_hyperscan ()) {
					mp_flags |= RSPAMD_MULTIPATTERN_RE;
				}

				rspamd_multipattern_add_pattern_len (d->stop_words[cat].mp,
						word, wlen,
						mp_flags);
				nelt->stop_words ++;
				nstop ++;

				/* Also lemmatise and store normalised */
				if (stem) {
					const char *nw = sb_stemmer_stem (stem, word, wlen);


					if (nw) {
						saved = nw;
						wlen = strlen (nw);
					}
					else {
						saved = word;
					}
				}
				else {
					saved = word;
				}

				if (saved) {
					gint rc;
					rspamd_ftok_t *tok;
					gchar *dst;

					tok = rspamd_mempool_alloc (cfg->cfg_pool,
							sizeof (*tok) + wlen + 1);
					dst = ((gchar *)tok) + sizeof (*tok);
					rspamd_strlcpy (dst, saved, wlen + 1);
					tok->begin = dst;
					tok->len = wlen;

					kh_put (rspamd_stopwords_hash, d->stop_words_norm,
							tok, &rc);
				}
			}

			if (stem) {
				sb_stemmer_delete (stem);
			}

			stop = rspamd_multipattern_get_npatterns (d->stop_words[cat].mp);

			struct rspamd_stop_word_range r;

			r.start = start;
			r.stop = stop;
			r.elt = nelt;

			g_array_append_val (d->stop_words[cat].ranges, r);
			it = NULL;
		}
	}

	nelt->category = cat;
	htb = d->trigramms[cat];

	GPtrArray *ngramms;
	guint nsym;

	if (rspamd_language_search_str (nelt->name, tier1_langs,
			G_N_ELEMENTS (tier1_langs))) {
		nelt->flags |= RS_LANGUAGE_TIER1;
	}

	if (rspamd_language_search_str (nelt->name, tier0_langs,
			G_N_ELEMENTS (tier0_langs))) {
		nelt->flags |= RS_LANGUAGE_TIER0;
	}

	it = NULL;
	ngramms = g_ptr_array_sized_new (freqs->len);
	i = 0;
	skipped = 0;
	loaded = 0;

	while ((cur = ucl_object_iterate (freqs, &it, true)) != NULL) {
		const gchar *key;
		gsize keylen;
		guint freq;

		key = ucl_object_keyl (cur, &keylen);
		freq = ucl_object_toint (cur);

		i ++;
		delta = freq - mean;
		mean += delta / i;
		delta2 = freq - mean;
		m2 += delta * delta2;

		if (key != NULL) {
			UChar32 *cur_ucs;
			const char *end = key + keylen, *cur_utf = key;

			ucs_elt = rspamd_mempool_alloc (cfg->cfg_pool,
					sizeof (*ucs_elt) + (keylen + 1) * sizeof (UChar32));

			cur_ucs = ucs_elt->s;
			nsym = 0;
			uc_err = U_ZERO_ERROR;

			while (cur_utf < end) {
				*cur_ucs++ = ucnv_getNextUChar (d->uchar_converter, &cur_utf,
						end, &uc_err);
				if (!U_SUCCESS (uc_err)) {
					break;
				}

				nsym ++;
			}

			if (!U_SUCCESS (uc_err)) {
				msg_warn_config ("cannot convert key %*s to unicode: %s",
						(gint)keylen, key, u_errorName (uc_err));

				continue;
			}

			ucs_elt->utf = key;
			rspamd_language_detector_ucs_lowercase (ucs_elt->s, nsym);

			if (nsym == 3) {
				g_ptr_array_add (ngramms, ucs_elt);
			}
			else {
				continue;
			}

			if (rspamd_language_detector_ucs_is_latin (ucs_elt->s, nsym)) {
				total_latin++;
			}

			ucs_elt->freq = freq;

			total_ngramms++;
		}
	}

	std = sqrt (m2 / (i - 1));

	if (total_latin >= total_ngramms / 3) {
		nelt->flags |= RS_LANGUAGE_LATIN;
	}

	nsym = 3;

	total = 0;
	PTR_ARRAY_FOREACH (ngramms, i, ucs_elt) {

		if (!(nelt->flags & RS_LANGUAGE_LATIN) &&
			rspamd_language_detector_ucs_is_latin (ucs_elt->s, nsym)) {
			ucs_elt->freq = 0;
			/* Skip latin ngramm for non-latin language to avoid garbadge */
			skipped ++;
			continue;
		}

		/* Now, discriminate low frequency ngramms */

		total += ucs_elt->freq;
		loaded ++;
	}

	g_ptr_array_sort (ngramms, rspamd_language_detector_cmp_ngramm);

	PTR_ARRAY_FOREACH (ngramms, i, ucs_elt) {
		if (ucs_elt->freq > 0) {
			rspamd_language_detector_init_ngramm (cfg, d,
					nelt, ucs_elt, nsym,
					ucs_elt->freq, total, htb);
		}
	}

#ifdef EXTRA_LANGDET_DEBUG
	/* Useful for debug */
		for (i = 0; i < 10; i ++) {
			ucs_elt = g_ptr_array_index (ngramms, i);

			msg_debug_lang_det_cfg ("%s -> %s: %d", nelt->name,
					ucs_elt->utf, ucs_elt->freq);
		}
#endif

	g_ptr_array_free (ngramms, TRUE);
	nelt->mean = mean;
	nelt->std = std;

	msg_debug_lang_det_cfg ("loaded %s language, %d trigramms, "
					 "%d ngramms loaded; "
					 "std=%.2f, mean=%.2f, skipped=%d, loaded=%d, stop_words=%d; "
					 "(%s)",
			nelt->name,
			(gint)nelt->trigramms_words,
			total,
			std, mean,
			skipped, loaded, nelt->stop_words,
			rspamd_language_detector_print_flags (nelt));

	g_ptr_array_add (d->languages, nelt);
	ucl_object_unref (top);
}

static gboolean
rspamd_ucl_array_find_str (const gchar *str, const ucl_object_t *ar)
{
	ucl_object_iter_t it = NULL;
	const ucl_object_t *cur;

	if (ar == NULL || ar->len == 0) {
		return FALSE;
	}

	while ((cur = ucl_object_iterate (ar, &it, true)) != NULL) {
		if (ucl_object_type (cur) == UCL_STRING && rspamd_strcase_equal (
				ucl_object_tostring (cur), str)) {
			return TRUE;
		}
	}

	return FALSE;
}

static void
rspamd_language_detector_process_chain (struct rspamd_config *cfg,
		struct rspamd_ngramm_chain *chain)
{
	struct rspamd_ngramm_elt *elt;
	guint i;
	gdouble delta, mean = 0, delta2, m2 = 0, std;

	if (chain->languages->len > 3) {
		PTR_ARRAY_FOREACH (chain->languages, i, elt) {
			delta = elt->prob - mean;
			mean += delta / (i + 1);
			delta2 = elt->prob - mean;
			m2 += delta * delta2;
		}

		std = sqrt (m2 / (i - 1));
		chain->mean = mean;
		chain->std = std;

		/* Now, filter elements that are lower than mean */
		PTR_ARRAY_FOREACH (chain->languages, i, elt) {
			if (elt->prob < mean) {
				g_ptr_array_remove_index_fast (chain->languages, i);
#ifdef EXTRA_LANGDET_DEBUG
				msg_debug_lang_det_cfg ("remove %s from %s; prob: %.4f; mean: %.4f, std: %.4f",
						elt->elt->name, chain->utf, elt->prob, mean, std);
#endif
			}
		}
	}
	else {
		/* We have a unique ngramm, increase its weight */
		PTR_ARRAY_FOREACH (chain->languages, i, elt) {
			elt->prob *= 4.0;
#ifdef EXTRA_LANGDET_DEBUG
			msg_debug_lang_det_cfg ("increase weight of %s in %s; prob: %.4f",
					elt->elt->name, chain->utf, elt->prob);
#endif
		}
	}
}

static void
rspamd_language_detector_dtor (struct rspamd_lang_detector *d)
{
	if (d) {
		for (guint i = 0; i < RSPAMD_LANGUAGE_MAX; i ++) {
			kh_destroy (rspamd_trigram_hash, d->trigramms[i]);
			rspamd_multipattern_destroy (d->stop_words[i].mp);
			g_array_free (d->stop_words[i].ranges, TRUE);
		}

		if (d->languages) {
			g_ptr_array_free (d->languages, TRUE);
		}

		kh_destroy (rspamd_stopwords_hash, d->stop_words_norm);
	}
}

struct rspamd_lang_detector*
rspamd_language_detector_init (struct rspamd_config *cfg)
{
	const ucl_object_t *section, *elt, *languages_enable = NULL,
			*languages_disable = NULL;
	const gchar *languages_path = default_languages_path;
	glob_t gl;
	size_t i, short_text_limit = default_short_text_limit, total = 0;
	UErrorCode uc_err = U_ZERO_ERROR;
	GString *languages_pattern;
	struct rspamd_ngramm_chain *chain, schain;
	gchar *fname;
	struct rspamd_lang_detector *ret = NULL;
	struct ucl_parser *parser;
	ucl_object_t *stop_words;

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

		languages_enable = ucl_object_lookup (section, "languages_enable");
		languages_disable = ucl_object_lookup (section, "languages_disable");
	}

	languages_pattern = g_string_sized_new (PATH_MAX);
	rspamd_printf_gstring (languages_pattern, "%s/stop_words", languages_path);
	parser = ucl_parser_new (UCL_PARSER_DEFAULT);

	if (ucl_parser_add_file (parser, languages_pattern->str)) {
		stop_words = ucl_parser_get_object (parser);
	}
	else {
		msg_err_config ("cannot read stop words from %s: %s",
				languages_pattern->str,
				ucl_parser_get_error (parser));
		stop_words = NULL;
	}

	ucl_parser_free (parser);
	languages_pattern->len = 0;

	rspamd_printf_gstring (languages_pattern, "%s/*.json", languages_path);
	memset (&gl, 0, sizeof (gl));

	if (glob (languages_pattern->str, 0, NULL, &gl) != 0) {
		msg_err_config ("cannot read any files matching %v", languages_pattern);
		goto end;
	}

	ret = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*ret));
	ret->languages = g_ptr_array_sized_new (gl.gl_pathc);
	ret->uchar_converter = rspamd_get_utf8_converter ();
	ret->short_text_limit = short_text_limit;
	ret->stop_words_norm = kh_init (rspamd_stopwords_hash);

	/* Map from ngramm in ucs32 to GPtrArray of rspamd_language_elt */
	for (i = 0; i < RSPAMD_LANGUAGE_MAX; i ++) {
		ret->trigramms[i] = kh_init (rspamd_trigram_hash);
#ifdef WITH_HYPERSCAN
		ret->stop_words[i].mp = rspamd_multipattern_create (
				RSPAMD_MULTIPATTERN_ICASE|RSPAMD_MULTIPATTERN_UTF8|
				RSPAMD_MULTIPATTERN_RE);
#else
		ret->stop_words[i].mp = rspamd_multipattern_create (
				RSPAMD_MULTIPATTERN_ICASE|RSPAMD_MULTIPATTERN_UTF8);
#endif

		ret->stop_words[i].ranges = g_array_new (FALSE, FALSE,
				sizeof (struct rspamd_stop_word_range));
	}

	g_assert (uc_err == U_ZERO_ERROR);

	for (i = 0; i < gl.gl_pathc; i ++) {
		fname = g_path_get_basename (gl.gl_pathv[i]);

		if (!rspamd_ucl_array_find_str (fname, languages_disable) ||
				(languages_enable == NULL ||
						rspamd_ucl_array_find_str (fname, languages_enable))) {
			rspamd_language_detector_read_file (cfg, ret, gl.gl_pathv[i],
					stop_words);
		}
		else {
			msg_info_config ("skip language file %s: disabled", fname);
		}

		g_free (fname);
	}

	for (i = 0; i < RSPAMD_LANGUAGE_MAX; i ++) {
		GError *err = NULL;

		kh_foreach_value (ret->trigramms[i], schain, {
			chain = &schain;
			rspamd_language_detector_process_chain (cfg, chain);
		});

		if (!rspamd_multipattern_compile (ret->stop_words[i].mp, &err)) {
			msg_err_config ("cannot compile stop words for %z language group: %e",
					i, err);
			g_error_free (err);
		}

		total += kh_size (ret->trigramms[i]);
	}

	msg_info_config ("loaded %d languages, "
			"%d trigramms",
			(gint)ret->languages->len,
			(gint)total);

	if (stop_words) {
		ucl_object_unref (stop_words);
	}

	REF_INIT_RETAIN (ret, rspamd_language_detector_dtor);
	rspamd_mempool_add_destructor (cfg->cfg_pool,
			(rspamd_mempool_destruct_t)rspamd_language_detector_unref,
			ret);

end:
	if (gl.gl_pathc > 0) {
		globfree (&gl);
	}

	g_string_free (languages_pattern, TRUE);

	return ret;
}

static void
rspamd_language_detector_random_select (GArray *ucs_tokens, guint nwords,
		goffset *offsets_out)
{
	guint step_len, remainder, i, out_idx;
	guint64 coin, sel;
	rspamd_stat_token_t *tok;

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
		guint ntries = 0;
		coin = rspamd_random_uint64_fast ();
		sel = (coin % step_len) + i;

		for (;;) {
			tok = &g_array_index (ucs_tokens, rspamd_stat_token_t, sel);
			/* Filter bad tokens */

			if (tok->unicode.len >= 2 &&
					!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_EXCEPTION) &&
					u_isalpha (tok->unicode.begin[0]) &&
					u_isalpha (tok->unicode.begin[tok->unicode.len - 1])) {
				offsets_out[out_idx] = sel;
				break;
			}
			else {
				ntries ++;
				coin = rspamd_random_uint64_fast ();

				if (ntries < step_len) {
					sel = (coin % step_len) + i;
				}
				else if (ntries < ucs_tokens->len) {
					sel = coin % ucs_tokens->len;
				}
				else {
					offsets_out[out_idx] = sel;
					break;
				}
			}
		}
	}

	/*
	 * Fisher-Yates algorithm:
	 * for i from 0 to n−2 do
	 *   j ← random integer such that i ≤ j < n
	 *   exchange a[i] and a[j]
	 */
#if 0
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
#endif
}

static goffset
rspamd_language_detector_next_ngramm (rspamd_stat_token_t *tok, UChar32 *window,
		guint wlen, goffset cur_off)
{
	guint i;

	if (wlen > 1) {
		/* Deal with spaces at the beginning and ending */

		if (cur_off == 0) {
			window[0] = (UChar32)' ';

			for (i = 0; i < wlen - 1; i ++) {
				window[i + 1] = tok->unicode.begin[i];
			}
		}
		else if (cur_off + wlen == tok->unicode.len + 1) {
			/* Add trailing space */
			for (i = 0; i < wlen - 1; i ++) {
				window[i] = tok->unicode.begin[cur_off + i];
			}
			window[wlen - 1] = (UChar32)' ';
		}
		else if (cur_off + wlen > tok->unicode.len + 1) {
			/* No more fun */
			return -1;
		}
		else {
			/* Normal case */
			for (i = 0; i < wlen; i++) {
				window[i] = tok->unicode.begin[cur_off + i];
			}
		}
	}
	else {
		if (tok->normalized.len <= cur_off) {
			return -1;
		}

		window[0] = tok->unicode.begin[cur_off];
	}

	return cur_off + 1;
}

/*
 * Do full guess for a specific ngramm, checking all languages defined
 */
static void
rspamd_language_detector_process_ngramm_full (struct rspamd_task *task,
											  struct rspamd_lang_detector *d,
											  UChar32 *window,
											  khash_t(rspamd_candidates_hash) *candidates,
											  khash_t(rspamd_trigram_hash) *trigramms)
{
	guint i;
	gint ret;
	struct rspamd_ngramm_chain *chain = NULL;
	struct rspamd_ngramm_elt *elt;
	struct rspamd_lang_detector_res *cand;
	khiter_t k;
	gdouble prob;

	k = kh_get (rspamd_trigram_hash, trigramms, window);
	if (k != kh_end (trigramms)) {
		chain = &kh_value (trigramms, k);
	}

	if (chain) {
		PTR_ARRAY_FOREACH (chain->languages, i, elt) {
			prob = elt->prob;

			if (prob < chain->mean) {
				continue;
			}

			k = kh_get (rspamd_candidates_hash, candidates, elt->elt->name);
			if (k != kh_end (candidates)) {
				cand = kh_value (candidates, k);
			}
			else {
				cand = NULL;
			}

#ifdef NGRAMMS_DEBUG
			msg_err ("gramm: %s, lang: %s, prob: %.3f", chain->utf,
					elt->elt->name, log2 (elt->prob));
#endif
			if (cand == NULL) {
				cand = rspamd_mempool_alloc (task->task_pool, sizeof (*cand));
				cand->elt = elt->elt;
				cand->lang = elt->elt->name;
				cand->prob = prob;

				k = kh_put (rspamd_candidates_hash, candidates, elt->elt->name,
						&ret);
				kh_value (candidates, k) = cand;
			} else {
				/* Update guess */
				cand->prob += prob;
			}
		}
	}
}

static void
rspamd_language_detector_detect_word (struct rspamd_task *task,
									  struct rspamd_lang_detector *d,
									  rspamd_stat_token_t *tok,
									  khash_t(rspamd_candidates_hash) *candidates,
									  khash_t(rspamd_trigram_hash) *trigramms)
{
	const guint wlen = 3;
	UChar32 window[3];
	goffset cur = 0;

	/* Split words */
	while ((cur = rspamd_language_detector_next_ngramm (tok, window, wlen, cur))
			!= -1) {
		rspamd_language_detector_process_ngramm_full (task,
				d, window, candidates, trigramms);
	}
}

static const gdouble cutoff_limit = -8.0;
/*
 * Converts frequencies to log probabilities, filter those candidates who
 * has the lowest probabilities
 */

static inline void
rspamd_language_detector_filter_step1 (struct rspamd_task *task,
		struct rspamd_lang_detector_res *cand,
		gdouble *max_prob, guint *filtered)
{
	if (!isnan (cand->prob)) {
		if (cand->prob == 0) {
			cand->prob = NAN;
			msg_debug_lang_det (
					"exclude language %s",
					cand->lang);
			(*filtered)++;
		}
		else {
			cand->prob = log2 (cand->prob);
			if (cand->prob < cutoff_limit) {
				msg_debug_lang_det (
						"exclude language %s: %.3f, cutoff limit: %.3f",
						cand->lang, cand->prob, cutoff_limit);
				cand->prob = NAN;
				(*filtered)++;
			}
			else if (cand->prob > *max_prob) {
				*max_prob = cand->prob;
			}
		}
	}
}

static inline void
rspamd_language_detector_filter_step2 (struct rspamd_task *task,
		struct rspamd_lang_detector_res *cand,
		gdouble max_prob, guint *filtered)
{
	/*
		 * Probabilities are logarithmic, so if prob1 - prob2 > 4, it means that
		 * prob2 is 2^4 less than prob1
		 */
	if (!isnan (cand->prob) && max_prob - cand->prob > 1) {
		msg_debug_lang_det ("exclude language %s: %.3f (%.3f max)",
				cand->lang, cand->prob, max_prob);
		cand->prob = NAN;
		(*filtered) ++;
	}
}

static void
rspamd_language_detector_filter_negligible (struct rspamd_task *task,
		khash_t(rspamd_candidates_hash) *candidates)
{
	struct rspamd_lang_detector_res *cand;
	guint filtered = 0;
	gdouble max_prob = -(G_MAXDOUBLE);

	kh_foreach_value (candidates, cand,
			rspamd_language_detector_filter_step1 (task, cand, &max_prob, &filtered));
	kh_foreach_value (candidates, cand,
			rspamd_language_detector_filter_step2 (task, cand, max_prob, &filtered));

	msg_debug_lang_det ("removed %d languages", filtered);
}

static void
rspamd_language_detector_detect_type (struct rspamd_task *task,
									  guint nwords,
									  struct rspamd_lang_detector *d,
									  GArray *words,
									  enum rspamd_language_category cat,
									  khash_t(rspamd_candidates_hash) *candidates)
{
	guint nparts = MIN (words->len, nwords);
	goffset *selected_words;
	rspamd_stat_token_t *tok;
	guint i;

	selected_words = g_new0 (goffset, nparts);
	rspamd_language_detector_random_select (words, nparts, selected_words);
	msg_debug_lang_det ("randomly selected %d words", nparts);

	for (i = 0; i < nparts; i++) {
		tok = &g_array_index (words, rspamd_stat_token_t,
				selected_words[i]);

		if (tok->unicode.len >= 3) {
			rspamd_language_detector_detect_word (task, d, tok, candidates,
					d->trigramms[cat]);
		}
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
									 enum rspamd_language_category cat,
									 khash_t(rspamd_candidates_hash) *candidates)
{
	guint cand_len = 0;
	struct rspamd_lang_detector_res *cand;

	rspamd_language_detector_detect_type (task,
			nwords,
			d,
			ucs_tokens,
			cat,
			candidates);

	kh_foreach_value (candidates, cand, {
		if (!isnan (cand->prob)) {
			cand_len ++;
		}
	});

	if (cand_len == 0) {
		return rs_detect_none;
	}
	else if (cand_len == 1) {
		return rs_detect_single;
	}

	return rs_detect_multiple;
}

enum rspamd_language_sort_flags {
	RSPAMD_LANG_FLAG_DEFAULT = 0,
	RSPAMD_LANG_FLAG_SHORT = 1 << 0,
};

struct rspamd_frequency_sort_cbdata {
	struct rspamd_lang_detector *d;
	enum rspamd_language_sort_flags flags;
	gdouble std;
	gdouble mean;
};

static const gdouble tier0_adjustment = 1.2;
static const gdouble tier1_adjustment = 0.8;
static const gdouble frequency_adjustment = 0.8;

static gint
rspamd_language_detector_cmp_heuristic (gconstpointer a, gconstpointer b,
		gpointer ud)
{
	struct rspamd_frequency_sort_cbdata *cbd = ud;
	const struct rspamd_lang_detector_res
			*canda = *(const struct rspamd_lang_detector_res **)a,
			*candb = *(const struct rspamd_lang_detector_res **)b;
	gdouble adj;
	gdouble proba_adjusted, probb_adjusted, freqa, freqb;

	freqa = ((gdouble)canda->elt->occurencies) /
			(gdouble)cbd->d->total_occurencies;
	freqb = ((gdouble)candb->elt->occurencies) /
			(gdouble)cbd->d->total_occurencies;

	proba_adjusted = canda->prob;
	probb_adjusted = candb->prob;

	if (isnormal (freqa) && isnormal (freqb)) {
		proba_adjusted += cbd->std * (frequency_adjustment * freqa);
		probb_adjusted += cbd->std * (frequency_adjustment * freqb);
	}

	if (cbd->flags & RSPAMD_LANG_FLAG_SHORT) {
		adj = tier1_adjustment * 2.0;
	}
	else {
		adj = tier1_adjustment;
	}
	if (canda->elt->flags & RS_LANGUAGE_TIER1) {
		proba_adjusted += cbd->std * adj;
	}

	if (candb->elt->flags & RS_LANGUAGE_TIER1) {
		probb_adjusted += cbd->std * adj;
	}

	if (cbd->flags & RSPAMD_LANG_FLAG_SHORT) {
		adj = tier0_adjustment * 16.0;
	}
	else {
		adj = tier0_adjustment;
	}

	if (canda->elt->flags & RS_LANGUAGE_TIER0) {
		proba_adjusted += cbd->std * adj;
	}

	if (candb->elt->flags & RS_LANGUAGE_TIER0) {
		probb_adjusted += cbd->std * adj;
	}

	if (proba_adjusted > probb_adjusted) {
		return -1;
	}
	else if (probb_adjusted > proba_adjusted) {
		return 1;
	}

	return 0;
}

static void
rspamd_language_detector_unicode_scripts (struct rspamd_task *task,
										  struct rspamd_mime_text_part *part,
										  guint *pchinese,
										  guint *pspecial)
{
	const gchar *p = part->utf_stripped_content->data, *end;
	guint i = 0, cnt = 0;
	end = p + part->utf_stripped_content->len;
	gint32 uc, sc;
	guint nlatin = 0, nchinese = 0, nspecial = 0;
	const guint cutoff_limit = 32;

	while (p + i < end) {
		U8_NEXT (p, i, part->utf_stripped_content->len, uc);

		if (((gint32) uc) < 0) {
			break;
		}

		if (u_isalpha (uc)) {
			sc = ublock_getCode (uc);
			cnt ++;

			switch (sc) {
			case UBLOCK_BASIC_LATIN:
			case UBLOCK_LATIN_1_SUPPLEMENT:
				part->unicode_scripts |= RSPAMD_UNICODE_LATIN;
				nlatin ++;
				break;
			case UBLOCK_HEBREW:
				part->unicode_scripts |= RSPAMD_UNICODE_HEBREW;
				nspecial ++;
				break;
			case UBLOCK_GREEK:
				part->unicode_scripts |= RSPAMD_UNICODE_GREEK;
				nspecial ++;
				break;
			case UBLOCK_CYRILLIC:
				part->unicode_scripts |= RSPAMD_UNICODE_CYRILLIC;
				nspecial ++;
				break;
			case UBLOCK_CJK_UNIFIED_IDEOGRAPHS:
			case UBLOCK_CJK_COMPATIBILITY:
			case UBLOCK_CJK_RADICALS_SUPPLEMENT:
			case UBLOCK_CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A:
			case UBLOCK_CJK_UNIFIED_IDEOGRAPHS_EXTENSION_B:
				part->unicode_scripts |= RSPAMD_UNICODE_CJK;
				nchinese ++;
				break;
			case UBLOCK_HIRAGANA:
			case UBLOCK_KATAKANA:
				part->unicode_scripts |= RSPAMD_UNICODE_JP;
				nspecial ++;
				break;
			case UBLOCK_HANGUL_JAMO:
			case UBLOCK_HANGUL_COMPATIBILITY_JAMO:
				part->unicode_scripts |= RSPAMD_UNICODE_HANGUL;
				nspecial ++;
				break;
			case UBLOCK_ARABIC:
				part->unicode_scripts |= RSPAMD_UNICODE_ARABIC;
				nspecial ++;
				break;
			case UBLOCK_DEVANAGARI:
				part->unicode_scripts |= RSPAMD_UNICODE_DEVANAGARI;
				nspecial ++;
				break;
			case UBLOCK_ARMENIAN:
				part->unicode_scripts |= RSPAMD_UNICODE_ARMENIAN;
				nspecial ++;
				break;
			case UBLOCK_GEORGIAN:
				part->unicode_scripts |= RSPAMD_UNICODE_GEORGIAN;
				nspecial ++;
				break;
			case UBLOCK_GUJARATI:
				part->unicode_scripts |= RSPAMD_UNICODE_GUJARATI;
				nspecial ++;
				break;
			case UBLOCK_TELUGU:
				part->unicode_scripts |= RSPAMD_UNICODE_TELUGU;
				nspecial ++;
				break;
			case UBLOCK_TAMIL:
				part->unicode_scripts |= RSPAMD_UNICODE_TAMIL;
				nspecial ++;
				break;
			case UBLOCK_THAI:
				part->unicode_scripts |= RSPAMD_UNICODE_THAI;
				nspecial ++;
				break;
			case RSPAMD_UNICODE_MALAYALAM:
				part->unicode_scripts |= RSPAMD_UNICODE_MALAYALAM;
				nspecial ++;
				break;
			case RSPAMD_UNICODE_SINHALA:
				part->unicode_scripts |= RSPAMD_UNICODE_SINHALA;
				nspecial ++;
				break;
			}
		}

		if (nspecial > cutoff_limit && nspecial > nlatin) {
			break;
		}
		else if (nchinese > cutoff_limit && nchinese > nlatin) {
			if (nspecial > 0) {
				/* Likely japanese */
				break;
			}
		}
	}

	msg_debug_lang_det ("stop after checking %d characters, "
						"%d latin, %d special, %d chinese",
			cnt, nlatin, nspecial, nchinese);

	*pchinese = nchinese;
	*pspecial = nspecial;
}

static inline void
rspamd_language_detector_set_language (struct rspamd_task *task,
									   struct rspamd_mime_text_part *part,
									   const gchar *code,
									   struct rspamd_language_elt *elt)
{
	struct rspamd_lang_detector_res *r;

	r = rspamd_mempool_alloc0 (task->task_pool, sizeof (*r));
	r->prob = 1.0;
	r->lang = code;
	r->elt = elt;

	if (part->languages == NULL) {
		part->languages = g_ptr_array_sized_new (1);
	}

	g_ptr_array_add (part->languages, r);
	part->language = code;
}

static gboolean
rspamd_language_detector_try_uniscript (struct rspamd_task *task,
										struct rspamd_mime_text_part *part,
										guint nchinese,
										guint nspecial)
{
	guint i;

	for (i = 0; i < G_N_ELEMENTS (unicode_langs); i ++) {
		if (unicode_langs[i].unicode_code & part->unicode_scripts) {

			if (unicode_langs[i].unicode_code != RSPAMD_UNICODE_JP) {
				msg_debug_lang_det ("set language based on unicode script %s",
						unicode_langs[i].lang);
				rspamd_language_detector_set_language (task, part,
						unicode_langs[i].lang, NULL);

				return TRUE;
			}
			else {
				/* Japanese <-> Chinese guess */

				/*
				 * Typically there might be around 0-70% of kanji glyphs
				 * and the rest are Haragana/Katakana
				 *
				 * If we discover that Kanji is more than 80% then we consider
				 * it Chinese
				 */
				if (nchinese <= 5 || nchinese < nspecial * 5) {
					msg_debug_lang_det ("set language based on unicode script %s",
							unicode_langs[i].lang);
					rspamd_language_detector_set_language (task, part,
							unicode_langs[i].lang, NULL);

					return TRUE;
				}
			}
		}
	}

	if (part->unicode_scripts & RSPAMD_UNICODE_CJK) {
		msg_debug_lang_det ("guess chinese based on CJK characters: %d chinese, %d special",
				nchinese, nspecial);
		rspamd_language_detector_set_language (task, part,
				"zh-CN", NULL);

		return TRUE;
	}

	return FALSE;
}

static guint
rspamd_langelt_hash_func (gconstpointer key)
{
	const struct rspamd_language_elt *elt = (const struct rspamd_language_elt *)key;
	return rspamd_cryptobox_fast_hash (elt->name, strlen (elt->name),
			rspamd_hash_seed ());
}

static gboolean
rspamd_langelt_equal_func (gconstpointer v, gconstpointer v2)
{
	const struct rspamd_language_elt *elt1 = (const struct rspamd_language_elt *)v,
			*elt2 = (const struct rspamd_language_elt *)v2;
	return strcmp (elt1->name, elt2->name) == 0;
}

KHASH_INIT (rspamd_sw_hash, struct rspamd_language_elt *, int, 1,
		rspamd_langelt_hash_func, rspamd_langelt_equal_func);

struct rspamd_sw_cbdata {
	struct rspamd_task *task;
	khash_t (rspamd_sw_hash) *res;
	GArray *ranges;
};

static gint
rspamd_ranges_cmp (const void *k, const void *memb)
{
	gint pos = GPOINTER_TO_INT (k);
	const struct rspamd_stop_word_range *r = (struct rspamd_stop_word_range *)memb;

	if (pos >= r->start && pos < r->stop) {
		return 0;
	}
	else if (pos < r->start) {
		return -1;
	}

	return 1;
}

static gint
rspamd_language_detector_sw_cb (struct rspamd_multipattern *mp,
								  guint strnum,
								  gint match_start,
								  gint match_pos,
								  const gchar *text,
								  gsize len,
								  void *context)
{
	/* Check if boundary */
	const gchar *prev = text, *next = text + len;
	struct rspamd_stop_word_range *r;
	struct rspamd_sw_cbdata *cbdata = (struct rspamd_sw_cbdata *)context;
	khiter_t k;
	static const gsize max_stop_words = 80;
	struct rspamd_task *task;

	if (match_start > 0) {
		prev = text + match_start - 1;

		if (!(g_ascii_isspace (*prev) || g_ascii_ispunct (*prev))) {
			return 0;
		}
	}

	if (match_pos < len) {
		next = text + match_pos;

		if (!(g_ascii_isspace (*next) || g_ascii_ispunct (*next))) {
			return 0;
		}
	}

	/* We have a word on the boundary, check range */
	task = cbdata->task;
	r = bsearch (GINT_TO_POINTER (strnum), cbdata->ranges->data,
			cbdata->ranges->len, sizeof (*r), rspamd_ranges_cmp);

	g_assert (r != NULL);

	k = kh_get (rspamd_sw_hash, cbdata->res, r->elt);
	gint nwords = 1;

	if (k != kh_end (cbdata->res)) {
		nwords = ++ kh_value (cbdata->res, k);

		if (kh_value (cbdata->res, k) > max_stop_words) {
			return 1;
		}
	}
	else {
		gint tt;

		k = kh_put (rspamd_sw_hash, cbdata->res, r->elt, &tt);
		kh_value (cbdata->res, k) = 1;
	}

	msg_debug_lang_det ("found word %*s from %s language (%d stop words found so far)",
			(int)(next - prev - 1), prev + 1, r->elt->name, nwords);

	return 0;
}

static gboolean
rspamd_language_detector_try_stop_words (struct rspamd_task *task,
										 struct rspamd_lang_detector *d,
										 struct rspamd_mime_text_part *part,
										 enum rspamd_language_category cat)
{
	struct rspamd_stop_word_elt *elt;
	struct rspamd_sw_cbdata cbdata;
	gboolean ret = FALSE;
	static const int stop_words_threshold = 4, /* minimum stop words count */
			strong_confidence_threshold = 10 /* we are sure that this is enough */;

	elt = &d->stop_words[cat];
	cbdata.res = kh_init (rspamd_sw_hash);
	cbdata.ranges = elt->ranges;
	cbdata.task = task;

	rspamd_multipattern_lookup (elt->mp, part->utf_stripped_content->data,
			part->utf_stripped_content->len, rspamd_language_detector_sw_cb,
			&cbdata, NULL);

	if (kh_size (cbdata.res) > 0) {
		gint cur_matches;
		double max_rate = G_MINDOUBLE;
		struct rspamd_language_elt *cur_lang, *sel = NULL;
		gboolean ignore_ascii = FALSE, ignore_latin = FALSE;

		again:
		kh_foreach (cbdata.res, cur_lang, cur_matches, {
			if (!ignore_ascii && (cur_lang->flags & RS_LANGUAGE_DIACRITICS)) {
				/* Restart matches */
				ignore_ascii = TRUE;
				sel = NULL;
				max_rate = G_MINDOUBLE;
				msg_debug_lang_det ("ignore ascii after finding %d stop words from %s",
						cur_matches, cur_lang->name);
				goto again;
			}

			if (!ignore_latin && cur_lang->category != RSPAMD_LANGUAGE_LATIN) {
				/* Restart matches */
				ignore_latin = TRUE;
				sel = NULL;
				max_rate = G_MINDOUBLE;
				msg_debug_lang_det ("ignore latin after finding stop %d words from %s",
						cur_matches, cur_lang->name);
				goto again;
			}

			if (cur_matches < stop_words_threshold) {
				continue;
			}

			if (cur_matches < strong_confidence_threshold) {
				/* Ignore mixed languages when not enough confidence */
				if (ignore_ascii && (cur_lang->flags & RS_LANGUAGE_ASCII)) {
					continue;
				}

				if (ignore_latin && cur_lang->category == RSPAMD_LANGUAGE_LATIN) {
					continue;
				}
			}

			double rate = (double)cur_matches / (double)cur_lang->stop_words;

			if (rate > max_rate) {
				max_rate = rate;
				sel = cur_lang;
			}

			msg_debug_lang_det ("found %d stop words from %s: %3f rate",
					cur_matches, cur_lang->name, rate);
		});

		if (max_rate > 0 && sel) {
			msg_debug_lang_det ("set language based on stop words script %s, %.3f found",
					sel->name, max_rate);
			rspamd_language_detector_set_language (task, part,
					sel->name, sel);

			ret = TRUE;
		}
	}
	else {
		msg_debug_lang_det ("found no stop words in a text");
	}

	kh_destroy (rspamd_sw_hash, cbdata.res);

	return ret;
}

gboolean
rspamd_language_detector_detect (struct rspamd_task *task,
								 struct rspamd_lang_detector *d,
								 struct rspamd_mime_text_part *part)
{
	khash_t(rspamd_candidates_hash) *candidates;
	GPtrArray *result;
	gdouble mean, std, start_ticks, end_ticks;
	guint cand_len;
	enum rspamd_language_category cat;
	struct rspamd_lang_detector_res *cand;
	enum rspamd_language_detected_type r;
	struct rspamd_frequency_sort_cbdata cbd;
	/* Check if we have sorted candidates based on frequency */
	gboolean frequency_heuristic_applied = FALSE, ret = FALSE;

	if (!part->utf_stripped_content) {
		return FALSE;
	}

	start_ticks = rspamd_get_ticks (TRUE);

	guint nchinese = 0, nspecial = 0;
	rspamd_language_detector_unicode_scripts (task, part, &nchinese, &nspecial);
	/* Apply unicode scripts heuristic */

	if (rspamd_language_detector_try_uniscript (task, part, nchinese, nspecial)) {
		ret = TRUE;
	}

	cat = rspamd_language_detector_get_category (part->unicode_scripts);

	if (!ret && rspamd_language_detector_try_stop_words (task, d, part, cat)) {
		ret = TRUE;
	}

	if (!ret) {
		if (part->utf_words->len < default_short_text_limit) {
			r = rs_detect_none;
			msg_debug_lang_det ("text is too short for trigramms detection: "
					   "%d words; at least %d words required",
					(int)part->utf_words->len,
					(int)default_short_text_limit);
			switch (cat) {
			case RSPAMD_LANGUAGE_CYRILLIC:
				rspamd_language_detector_set_language (task, part, "ru", NULL);
				break;
			case RSPAMD_LANGUAGE_DEVANAGARI:
				rspamd_language_detector_set_language (task, part, "hi", NULL);
				break;
			case RSPAMD_LANGUAGE_ARAB:
				rspamd_language_detector_set_language (task, part, "ar", NULL);
				break;
			default:
			case RSPAMD_LANGUAGE_LATIN:
				rspamd_language_detector_set_language (task, part, "en", NULL);
				break;
			}
			msg_debug_lang_det ("set %s language based on symbols category",
					part->language);

			candidates = kh_init (rspamd_candidates_hash);
		}
		else {
			candidates = kh_init (rspamd_candidates_hash);
			kh_resize (rspamd_candidates_hash, candidates, 32);

			r = rspamd_language_detector_try_ngramm (task,
					default_words,
					d,
					part->utf_words,
					cat,
					candidates);

			if (r == rs_detect_none) {
				msg_debug_lang_det ("no trigramms found, fallback to english");
				rspamd_language_detector_set_language (task, part, "en", NULL);
			} else if (r == rs_detect_multiple) {
				/* Check our guess */

				mean = 0.0;
				std = 0.0;
				cand_len = 0;

				/* Check distirbution */
				kh_foreach_value (candidates, cand, {
					if (!isnan (cand->prob)) {
						mean += cand->prob;
						cand_len++;
					}
				});

				if (cand_len > 0) {
					mean /= cand_len;

					kh_foreach_value (candidates, cand, {
						gdouble err;
						if (!isnan (cand->prob)) {
							err = cand->prob - mean;
							std += fabs (err);
						}
					});

					std /= cand_len;
				}

				msg_debug_lang_det ("trigramms checked, %d candidates, %.3f mean, %.4f stddev",
						cand_len, mean, std);

				if (cand_len > 0 && std / fabs (mean) < 0.25) {
					msg_debug_lang_det ("apply frequency heuristic sorting");
					frequency_heuristic_applied = TRUE;
					cbd.d = d;
					cbd.mean = mean;
					cbd.std = std;
					cbd.flags = RSPAMD_LANG_FLAG_DEFAULT;

					if (part->nwords < default_words / 2) {
						cbd.flags |= RSPAMD_LANG_FLAG_SHORT;
					}
				}
			}
		}

		/* Now, convert hash to array and sort it */
		if (r != rs_detect_none && kh_size (candidates) > 0) {
			result = g_ptr_array_sized_new (kh_size (candidates));

			kh_foreach_value (candidates, cand, {
				if (!isnan (cand->prob)) {
					msg_debug_lang_det ("final probability %s -> %.2f", cand->lang,
							cand->prob);
					g_ptr_array_add (result, cand);
				}
			});

			if (frequency_heuristic_applied) {
				g_ptr_array_sort_with_data (result,
						rspamd_language_detector_cmp_heuristic, (gpointer) &cbd);
			} else {
				g_ptr_array_sort (result, rspamd_language_detector_cmp);
			}

			if (result->len > 0 && !frequency_heuristic_applied) {
				cand = g_ptr_array_index (result, 0);
				cand->elt->occurencies++;
				d->total_occurencies++;
			}

			if (part->languages != NULL) {
				g_ptr_array_unref (part->languages);
			}

			part->languages = result;
			ret = TRUE;
		}
		else if (part->languages == NULL) {
			rspamd_language_detector_set_language (task, part, "en", NULL);
		}

		kh_destroy (rspamd_candidates_hash, candidates);
	}

	end_ticks = rspamd_get_ticks (TRUE);
	msg_debug_lang_det ("detected languages in %.0f ticks",
			(end_ticks - start_ticks));

	return ret;
}


struct rspamd_lang_detector*
rspamd_language_detector_ref (struct rspamd_lang_detector* d)
{
	REF_RETAIN (d);

	return d;
}

void
rspamd_language_detector_unref (struct rspamd_lang_detector* d)
{
	REF_RELEASE (d);
}

gboolean
rspamd_language_detector_is_stop_word (struct rspamd_lang_detector *d,
									   const gchar *word, gsize wlen)
{
	khiter_t k;
	rspamd_ftok_t search;

	search.begin = word;
	search.len = wlen;

	k = kh_get (rspamd_stopwords_hash, d->stop_words_norm, &search);

	if (k != kh_end (d->stop_words_norm)) {
		return TRUE;
	}

	return FALSE;
}

gint
rspamd_language_detector_elt_flags (const struct rspamd_language_elt *elt)
{
	if (elt) {
		return elt->flags;
	}

	return 0;
}