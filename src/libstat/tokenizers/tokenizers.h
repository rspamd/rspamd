/*
 * Copyright 2023 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TOKENIZERS_H
#define TOKENIZERS_H

#include "config.h"
#include "mem_pool.h"
#include "fstring.h"
#include "rspamd.h"
#include "stat_api.h"

#include <unicode/utext.h>

#define RSPAMD_DEFAULT_TOKENIZER "osb"

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_tokenizer_runtime;
struct rspamd_stat_ctx;

/* Common tokenizer structure */
struct rspamd_stat_tokenizer {
	char *name;

	gpointer (*get_config)(rspamd_mempool_t *pool,
						   struct rspamd_tokenizer_config *cf, gsize *len);

	int (*tokenize_func)(struct rspamd_stat_ctx *ctx,
						 struct rspamd_task *task,
						 GArray *words,
						 gboolean is_utf,
						 const char *prefix,
						 GPtrArray *result);
};

enum rspamd_tokenize_type {
	RSPAMD_TOKENIZE_UTF = 0,
	RSPAMD_TOKENIZE_RAW,
	RSPAMD_TOKENIZE_UNICODE
};

/* Compare two token nodes */
int token_node_compare_func(gconstpointer a, gconstpointer b);


/* Tokenize text into array of words (rspamd_stat_token_t type) */
GArray *rspamd_tokenize_text(const char *text, gsize len,
							 const UText *utxt,
							 enum rspamd_tokenize_type how,
							 struct rspamd_config *cfg,
							 GList *exceptions,
							 uint64_t *hash,
							 GArray *cur_words,
							 rspamd_mempool_t *pool);

/* OSB tokenize function */
int rspamd_tokenizer_osb(struct rspamd_stat_ctx *ctx,
						 struct rspamd_task *task,
						 GArray *words,
						 gboolean is_utf,
						 const char *prefix,
						 GPtrArray *result);

gpointer rspamd_tokenizer_osb_get_config(rspamd_mempool_t *pool,
										 struct rspamd_tokenizer_config *cf,
										 gsize *len);

struct rspamd_lang_detector;

void rspamd_normalize_single_word(rspamd_stat_token_t *tok, rspamd_mempool_t *pool);

void rspamd_normalize_words(GArray *words, rspamd_mempool_t *pool);

void rspamd_stem_words(GArray *words, rspamd_mempool_t *pool,
					   const char *language,
					   struct rspamd_lang_detector *lang_detector);

void rspamd_tokenize_meta_words(struct rspamd_task *task);

#ifdef __cplusplus
}
#endif

#endif
