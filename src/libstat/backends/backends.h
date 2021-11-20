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
#ifndef BACKENDS_H_
#define BACKENDS_H_

#include "config.h"
#include "ucl.h"

#define RSPAMD_DEFAULT_BACKEND "mmap"

#ifdef  __cplusplus
extern "C" {
#endif

/* Forwarded declarations */
struct rspamd_classifier_config;
struct rspamd_statfile_config;
struct rspamd_config;
struct rspamd_stat_ctx;
struct rspamd_token_result;
struct rspamd_statfile;
struct rspamd_task;

struct rspamd_stat_backend {
	const char *name;
	bool read_only;

	gpointer (*init) (struct rspamd_stat_ctx *ctx, struct rspamd_config *cfg,
					  struct rspamd_statfile *st);

	gpointer (*runtime) (struct rspamd_task *task,
						 struct rspamd_statfile_config *stcf, gboolean learn, gpointer ctx);

	gboolean (*process_tokens) (struct rspamd_task *task, GPtrArray *tokens,
								gint id,
								gpointer ctx);

	gboolean (*finalize_process) (struct rspamd_task *task,
								  gpointer runtime, gpointer ctx);

	gboolean (*learn_tokens) (struct rspamd_task *task, GPtrArray *tokens,
							  gint id,
							  gpointer ctx);

	gulong (*total_learns) (struct rspamd_task *task,
							gpointer runtime, gpointer ctx);

	gboolean (*finalize_learn) (struct rspamd_task *task,
								gpointer runtime, gpointer ctx, GError **err);

	gulong (*inc_learns) (struct rspamd_task *task,
						  gpointer runtime, gpointer ctx);

	gulong (*dec_learns) (struct rspamd_task *task,
						  gpointer runtime, gpointer ctx);

	ucl_object_t *(*get_stat) (gpointer runtime, gpointer ctx);

	void (*close) (gpointer ctx);

	gpointer (*load_tokenizer_config) (gpointer runtime, gsize *sz);

	gpointer ctx;
};

#define RSPAMD_STAT_BACKEND_DEF(name) \
        gpointer rspamd_##name##_init (struct rspamd_stat_ctx *ctx, \
            struct rspamd_config *cfg, struct rspamd_statfile *st); \
        gpointer rspamd_##name##_runtime (struct rspamd_task *task, \
                struct rspamd_statfile_config *stcf, \
                gboolean learn, gpointer ctx); \
        gboolean rspamd_##name##_process_tokens (struct rspamd_task *task, \
                GPtrArray *tokens, gint id, \
                gpointer ctx); \
        gboolean rspamd_##name##_finalize_process (struct rspamd_task *task, \
                gpointer runtime, \
                gpointer ctx); \
        gboolean rspamd_##name##_learn_tokens (struct rspamd_task *task, \
                GPtrArray *tokens, gint id, \
                gpointer ctx); \
        gboolean rspamd_##name##_finalize_learn (struct rspamd_task *task, \
                gpointer runtime, \
                gpointer ctx, GError **err); \
        gulong rspamd_##name##_total_learns (struct rspamd_task *task, \
                gpointer runtime, \
                gpointer ctx); \
        gulong rspamd_##name##_inc_learns (struct rspamd_task *task, \
                gpointer runtime, \
                gpointer ctx); \
        gulong rspamd_##name##_dec_learns (struct rspamd_task *task, \
                gpointer runtime, \
                gpointer ctx); \
        gulong rspamd_##name##_learns (struct rspamd_task *task, \
                gpointer runtime, \
                gpointer ctx); \
        ucl_object_t * rspamd_##name##_get_stat (gpointer runtime, \
                gpointer ctx); \
        gpointer rspamd_##name##_load_tokenizer_config (gpointer runtime, \
                gsize *len); \
        void rspamd_##name##_close (gpointer ctx)

RSPAMD_STAT_BACKEND_DEF(mmaped_file);
RSPAMD_STAT_BACKEND_DEF(sqlite3);
RSPAMD_STAT_BACKEND_DEF(cdb);
RSPAMD_STAT_BACKEND_DEF(redis);

#ifdef  __cplusplus
}
#endif

#endif /* BACKENDS_H_ */
