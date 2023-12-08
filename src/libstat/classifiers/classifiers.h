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

#ifndef CLASSIFIERS_H
#define CLASSIFIERS_H

#include "config.h"
#include "mem_pool.h"
#include "contrib/libev/ev.h"

#define RSPAMD_DEFAULT_CLASSIFIER "bayes"
/* Consider this value as 0 */
#define ALPHA 0.0001

#ifdef __cplusplus
extern "C" {
#endif

struct rspamd_classifier_config;
struct rspamd_task;
struct rspamd_config;
struct rspamd_classifier;

struct token_node_s;

struct rspamd_stat_classifier {
	char *name;

	gboolean (*init_func)(struct rspamd_config *cfg,
						  struct ev_loop *ev_base,
						  struct rspamd_classifier *cl);

	gboolean (*classify_func)(struct rspamd_classifier *ctx,
							  GPtrArray *tokens,
							  struct rspamd_task *task);

	gboolean (*learn_spam_func)(struct rspamd_classifier *ctx,
								GPtrArray *input,
								struct rspamd_task *task,
								gboolean is_spam,
								gboolean unlearn,
								GError **err);

	void (*fin_func)(struct rspamd_classifier *cl);
};

/* Bayes algorithm */
gboolean bayes_init(struct rspamd_config *cfg,
					struct ev_loop *ev_base,
					struct rspamd_classifier *);

gboolean bayes_classify(struct rspamd_classifier *ctx,
						GPtrArray *tokens,
						struct rspamd_task *task);

gboolean bayes_learn_spam(struct rspamd_classifier *ctx,
						  GPtrArray *tokens,
						  struct rspamd_task *task,
						  gboolean is_spam,
						  gboolean unlearn,
						  GError **err);

void bayes_fin(struct rspamd_classifier *);

/* Generic lua classifier */
gboolean lua_classifier_init(struct rspamd_config *cfg,
							 struct ev_loop *ev_base,
							 struct rspamd_classifier *);

gboolean lua_classifier_classify(struct rspamd_classifier *ctx,
								 GPtrArray *tokens,
								 struct rspamd_task *task);

gboolean lua_classifier_learn_spam(struct rspamd_classifier *ctx,
								   GPtrArray *tokens,
								   struct rspamd_task *task,
								   gboolean is_spam,
								   gboolean unlearn,
								   GError **err);

extern gint rspamd_bayes_log_id;
#define msg_debug_bayes(...) rspamd_conditional_debug_fast(NULL, task->from_addr,                                  \
														   rspamd_bayes_log_id, "bayes", task->task_pool->tag.uid, \
														   G_STRFUNC,                                              \
														   __VA_ARGS__)
#define msg_debug_bayes_cfg(...) rspamd_conditional_debug_fast(NULL, NULL,                                           \
															   rspamd_bayes_log_id, "bayes", cfg->cfg_pool->tag.uid, \
															   G_STRFUNC,                                            \
															   __VA_ARGS__)


#ifdef __cplusplus
}
#endif

#endif
