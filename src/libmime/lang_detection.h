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

struct rspamd_lang_detector;
struct rspamd_language_elt;
struct rspamd_task;

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
struct rspamd_lang_detector* rspamd_language_detector_init (struct rspamd_config *cfg);
/**
 * Convert string from utf8 to ucs32
 * @param d
 * @param utf_token
 * @param ucs_token
 */
void rspamd_language_detector_to_ucs (struct rspamd_lang_detector *d,
		rspamd_mempool_t *pool,
		rspamd_stat_token_t *utf_token,
		rspamd_stat_token_t *ucs_token);

/**
 * Try to detect language of words
 * @param d
 * @param ucs_tokens
 * @param words_len
 * @return array of struct rspamd_lang_detector_res sorted by freq descending
 */
GPtrArray * rspamd_language_detector_detect (struct rspamd_task *task,
		struct rspamd_lang_detector *d,
		GArray *ucs_tokens, gsize words_len);

#endif
