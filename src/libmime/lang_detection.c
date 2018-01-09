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

struct rspamd_language_elt {
	const gchar *name; /* e.g. "en" or "ru" */
	guint unigramms_total; /* total frequencies for unigramms */
	GHashTable *unigramms; /* unigramms frequencies */
	guint bigramms_total; /* total frequencies for bigramms */
	GHashTable *bigramms; /* bigramms frequencies */
	guint trigramms_total; /* total frequencies for trigramms */
	GHashTable *trigramms; /* trigramms frequencies */
};

struct rspamd_lang_detector {
	GPtrArray *languages;
	UConverter *uchar_converter;
};

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
rspamd_language_detector_read_file (struct rspamd_config *cfg,
		struct rspamd_lang_detector *d,
		const gchar *path)
{
	struct ucl_parser *parser;
	ucl_object_t *top;
	const ucl_object_t *freqs, *cur;
	ucl_object_iter_t it = NULL;
	UErrorCode uc_err = U_ZERO_ERROR;
	struct rspamd_language_elt *nelt;
	gchar *pos;

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
	nelt->unigramms = g_hash_table_new (rspamd_unigram_hash, rspamd_unigram_equal);
	nelt->bigramms = g_hash_table_new (rspamd_bigram_hash, rspamd_bigram_equal);
	nelt->trigramms = g_hash_table_new (rspamd_trigram_hash, rspamd_trigram_equal);

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

			if (nsym == 2) {
				/* We have a digraph */
				g_hash_table_insert (nelt->bigramms, ucs_key,
						GUINT_TO_POINTER (freq));
				nelt->bigramms_total += freq;
			}
			else if (nsym == 3) {
				g_hash_table_insert (nelt->trigramms, ucs_key,
						GUINT_TO_POINTER (freq));
				nelt->trigramms_total += freq;
			}
			else if (nsym == 1) {
				g_hash_table_insert (nelt->unigramms, ucs_key,
						GUINT_TO_POINTER (freq));
				nelt->unigramms_total += freq;
			}
			else if (nsym > 3) {
				msg_warn_config ("have more than 3 characters in key: %d", nsym);
			}
		}
	}

	msg_info_config ("loaded %s language, %d unigramms, %d digramms, %d trigramms",
			nelt->name,
			(gint)g_hash_table_size (nelt->unigramms),
			(gint)g_hash_table_size (nelt->bigramms),
			(gint)g_hash_table_size (nelt->trigramms));

	g_ptr_array_add (d->languages, nelt);
	ucl_object_unref (top);
}

struct rspamd_lang_detector*
rspamd_language_detector_init (struct rspamd_config *cfg)
{
	const ucl_object_t *section, *elt;
	const gchar *languages_path = RSPAMD_PLUGINSDIR "/languages";
	glob_t gl;
	size_t i;
	UErrorCode uc_err = U_ZERO_ERROR;
	GString *languages_pattern;
	struct rspamd_lang_detector *ret = NULL;

	section = ucl_object_lookup (cfg->rcl_obj, "lang_detection");

	if (section != NULL) {
		elt = ucl_object_lookup (section, "languages");

		if (elt) {
			languages_path = ucl_object_tostring (elt);
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


void rspamd_language_detector_to_ucs (struct rspamd_lang_detector *d,
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
		ucs_token->begin = (const gchar *) out;
		ucs_token->len = nsym;
	}
	else {
		ucs_token->len = 0;
	}
}