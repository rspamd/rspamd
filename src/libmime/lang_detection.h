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

#ifndef RSPAMD_LANG_DETECTION_H
#define RSPAMD_LANG_DETECTION_H

#include "config.h"
#include "libserver/cfg_file.h"
#include "libstat/stat_api.h"
#include "libmime/message.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_lang_detector;
struct rspamd_language_elt;
struct rspamd_task;

enum rspamd_unicode_scripts {
	RSPAMD_UNICODE_LATIN = (1 << 0),
	RSPAMD_UNICODE_GREEK = (1 << 1),
	RSPAMD_UNICODE_CYRILLIC = (1 << 2),
	RSPAMD_UNICODE_HEBREW = (1 << 3),
	RSPAMD_UNICODE_CJK = (1 << 4),
	RSPAMD_UNICODE_JP = (1 << 5),
	RSPAMD_UNICODE_ARABIC = (1 << 6),
	RSPAMD_UNICODE_DEVANAGARI = (1 << 7),
	RSPAMD_UNICODE_THAI = (1 << 8),
	RSPAMD_UNICODE_ARMENIAN = (1 << 9),
	RSPAMD_UNICODE_GEORGIAN = (1 << 10),
	RSPAMD_UNICODE_GUJARATI = (1 << 11),
	RSPAMD_UNICODE_TAMIL = (1 << 12),
	RSPAMD_UNICODE_TELUGU = (1 << 13),
	RSPAMD_UNICODE_MALAYALAM = (1 << 14),
	RSPAMD_UNICODE_SINHALA = (1 << 15),
	RSPAMD_UNICODE_HANGUL = (1 << 16),
};

enum rspamd_language_elt_flags {
	RS_LANGUAGE_DEFAULT = 0,
	RS_LANGUAGE_LATIN = (1 << 0),
	RS_LANGUAGE_TIER1 = (1 << 3),
	RS_LANGUAGE_TIER0 = (1 << 4),
	RS_LANGUAGE_DIACRITICS = (1 << 5),
	RS_LANGUAGE_ASCII = (1 << 6),
};

struct rspamd_lang_detector_res {
	gdouble prob;
	const gchar *lang;
	struct rspamd_language_elt *elt;
};

/**
 * Create new language detector object using configuration object
 * @param cfg
 * @return
 */
struct rspamd_lang_detector *rspamd_language_detector_init (struct rspamd_config *cfg);

struct rspamd_lang_detector *rspamd_language_detector_ref (struct rspamd_lang_detector *d);

void rspamd_language_detector_unref (struct rspamd_lang_detector *d);

/**
 * Try to detect language of words
 * @param d
 * @param ucs_tokens
 * @param words_len
 * @return array of struct rspamd_lang_detector_res sorted by freq descending
 */
gboolean rspamd_language_detector_detect (struct rspamd_task *task,
										  struct rspamd_lang_detector *d,
										  struct rspamd_mime_text_part *part);

/**
 * Returns TRUE if the specified word is known to be a stop word
 * @param d
 * @param word
 * @param wlen
 * @return
 */
gboolean rspamd_language_detector_is_stop_word (struct rspamd_lang_detector *d,
												const gchar *word, gsize wlen);

/**
 * Return language flags for a specific language elt
 * @param elt
 * @return
 */
gint rspamd_language_detector_elt_flags (const struct rspamd_language_elt *elt);
#ifdef  __cplusplus
}
#endif

#endif
