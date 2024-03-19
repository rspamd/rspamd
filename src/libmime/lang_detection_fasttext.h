/*-
 * Copyright 2023 Vsevolod Stakhov
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
#ifndef RSPAMD_LANG_DETECTION_FASTTEXT_H
#define RSPAMD_LANG_DETECTION_FASTTEXT_H

#include "config.h"

G_BEGIN_DECLS
struct rspamd_config;
struct rspamd_task; /* for logging */
/**
 * Initialize fasttext language detector
 * @param cfg
 * @return opaque pointer
 */
void *rspamd_lang_detection_fasttext_init(struct rspamd_config *cfg);

/**
 * Check if fasttext language detector is enabled
 * @param ud
 * @return
 */
bool rspamd_lang_detection_fasttext_is_enabled(void *ud);

/**
 * Show info about fasttext language detector
 * @param ud
 * @return
 */
char *rspamd_lang_detection_fasttext_show_info(void *ud);


typedef void *rspamd_fasttext_predict_result_t;
/**
 * Detect language using fasttext
 * @param ud opaque pointer
 * @param in input text
 * @param len length of input text
 * @param k number of results to return
 * @return TRUE if language is detected
 */
rspamd_fasttext_predict_result_t rspamd_lang_detection_fasttext_detect(void *ud,
																	   struct rspamd_task *task, GArray *utf_words, int k);

/**
 * Get number of languages detected
 * @param ud
 * @return
 */
unsigned int rspamd_lang_detection_fasttext_get_nlangs(rspamd_fasttext_predict_result_t ud);
/**
 * Get language from fasttext result
 * @param res
 * @return
 */
const char *rspamd_lang_detection_fasttext_get_lang(rspamd_fasttext_predict_result_t res, unsigned int idx);

/**
 * Get probability from fasttext result
 * @param res
 * @return
 */
float rspamd_lang_detection_fasttext_get_prob(rspamd_fasttext_predict_result_t res, unsigned int idx);

/**
 * Destroy fasttext result
 * @param res
 */
void rspamd_fasttext_predict_result_destroy(rspamd_fasttext_predict_result_t res);

/**
 * Destroy fasttext language detector
 */
void rspamd_lang_detection_fasttext_destroy(void *ud);


G_END_DECLS
#endif /* RSPAMD_LANG_DETECTION_FASTTEXT_H */
