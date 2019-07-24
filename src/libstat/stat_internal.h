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
#ifndef STAT_INTERNAL_H_
#define STAT_INTERNAL_H_

#include "config.h"
#include "task.h"
#include "ref.h"
#include "classifiers/classifiers.h"
#include "tokenizers/tokenizers.h"
#include "backends/backends.h"
#include "learn_cache/learn_cache.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct rspamd_statfile_runtime {
	struct rspamd_statfile_config *st;
	gpointer backend_runtime;
	guint64 hits;
	guint64 total_hits;
};

/* Common classifier structure */
struct rspamd_classifier {
	struct rspamd_stat_ctx *ctx;
	GArray *statfiles_ids; /* int */
	struct rspamd_stat_cache *cache;
	gpointer cachecf;
	gulong spam_learns;
	gulong ham_learns;
	gint autolearn_cbref;
	struct rspamd_classifier_config *cfg;
	struct rspamd_stat_classifier *subrs;
	gpointer specific;
};

struct rspamd_statfile {
	gint id;
	struct rspamd_statfile_config *stcf;
	struct rspamd_classifier *classifier;
	struct rspamd_stat_backend *backend;
	gpointer bkcf;
};

struct rspamd_stat_async_elt;

typedef void (*rspamd_stat_async_handler) (struct rspamd_stat_async_elt *elt,
										   gpointer ud);

typedef void (*rspamd_stat_async_cleanup) (struct rspamd_stat_async_elt *elt,
										   gpointer ud);

struct rspamd_stat_async_elt {
	rspamd_stat_async_handler handler;
	rspamd_stat_async_cleanup cleanup;
	struct ev_loop *event_loop;
	ev_timer timer_ev;
	gdouble timeout;
	gboolean enabled;
	gpointer ud;
	ref_entry_t ref;
};

struct rspamd_stat_ctx {
	/* Subroutines for all objects */
	struct rspamd_stat_classifier *classifiers_subrs;
	guint classifiers_count;
	struct rspamd_stat_tokenizer *tokenizers_subrs;
	guint tokenizers_count;
	struct rspamd_stat_backend *backends_subrs;
	guint backends_count;
	struct rspamd_stat_cache *caches_subrs;
	guint caches_count;

	/* Runtime configuration */
	GPtrArray *statfiles; /* struct rspamd_statfile */
	GPtrArray *classifiers; /* struct rspamd_classifier */
	GQueue *async_elts; /* struct rspamd_stat_async_elt */
	struct rspamd_config *cfg;

	gint lua_stat_tokens_ref;

	/* Global tokenizer */
	struct rspamd_stat_tokenizer *tokenizer;
	gpointer tkcf;

	struct ev_loop *event_loop;
};

typedef enum rspamd_learn_cache_result {
	RSPAMD_LEARN_OK = 0,
	RSPAMD_LEARN_UNLEARN,
	RSPAMD_LEARN_INGORE
} rspamd_learn_t;

struct rspamd_stat_ctx *rspamd_stat_get_ctx (void);

struct rspamd_stat_classifier *rspamd_stat_get_classifier (const gchar *name);

struct rspamd_stat_backend *rspamd_stat_get_backend (const gchar *name);

struct rspamd_stat_tokenizer *rspamd_stat_get_tokenizer (const gchar *name);

struct rspamd_stat_cache *rspamd_stat_get_cache (const gchar *name);

struct rspamd_stat_async_elt *rspamd_stat_ctx_register_async (
		rspamd_stat_async_handler handler, rspamd_stat_async_cleanup cleanup,
		gpointer d, gdouble timeout);

static GQuark rspamd_stat_quark (void) {
	return g_quark_from_static_string ("rspamd-statistics");
}

#ifdef  __cplusplus
}
#endif

#endif /* STAT_INTERNAL_H_ */
