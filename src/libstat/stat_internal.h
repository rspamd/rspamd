/* Copyright (c) 2015, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef STAT_INTERNAL_H_
#define STAT_INTERNAL_H_

#include "config.h"
#include "task.h"
#include "classifiers/classifiers.h"
#include "tokenizers/tokenizers.h"
#include "backends/backends.h"
#include "learn_cache/learn_cache.h"

enum stat_process_stage {
	RSPAMD_STAT_STAGE_PRE = 0,
	RSPAMD_STAT_STAGE_POST
};

struct rspamd_tokenizer_runtime {
	GTree *tokens;
	const gchar *name;
	struct rspamd_stat_tokenizer *tokenizer;
	struct rspamd_tokenizer_runtime *next;
};

struct rspamd_statfile_runtime {
	struct rspamd_statfile_config *st;
	struct rspamd_stat_backend *backend;
	gpointer backend_runtime;
	guint64 hits;
	guint64 total_hits;
};

struct rspamd_classifier_runtime {
	struct rspamd_classifier_config *clcf;
	struct rspamd_stat_classifier *cl;
	struct rspamd_tokenizer_runtime *tok;
	double ham_prob;
	double spam_prob;
	enum stat_process_stage stage;
	guint64 total_spam;
	guint64 total_ham;
	guint64 processed_tokens;
	GList *st_runtime;
	guint start_pos;
	guint end_pos;
};

struct rspamd_token_result {
	double value;
	struct rspamd_statfile_runtime *st_runtime;

	struct rspamd_classifier_runtime *cl_runtime;
};

#define RSPAMD_MAX_TOKEN_LEN 64
typedef struct token_node_s {
	guchar data[RSPAMD_MAX_TOKEN_LEN];
	guint datalen;
	GArray *results;
} rspamd_token_t;

struct rspamd_stat_ctx {
	struct rspamd_stat_classifier *classifiers;
	guint classifiers_count;
	struct rspamd_stat_tokenizer *tokenizers;
	guint tokenizers_count;
	struct rspamd_stat_backend *backends;
	guint backends_count;
	struct rspamd_stat_cache *caches;
	guint caches_count;

	guint statfiles;
};

typedef enum rspamd_learn_cache_result {
	RSPAMD_LEARN_OK = 0,
	RSPAMD_LEARN_UNLEARN,
	RSPAMD_LEARN_INGORE
} rspamd_learn_t;

struct rspamd_stat_ctx * rspamd_stat_get_ctx (void);
struct rspamd_stat_classifier * rspamd_stat_get_classifier (const gchar *name);
struct rspamd_stat_backend * rspamd_stat_get_backend (const gchar *name);
struct rspamd_stat_tokenizer * rspamd_stat_get_tokenizer (const gchar *name);

static GQuark rspamd_stat_quark (void)
{
	return g_quark_from_static_string ("rspamd-statistics");
}

#endif /* STAT_INTERNAL_H_ */
