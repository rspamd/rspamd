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
#ifndef LEARN_CACHE_H_
#define LEARN_CACHE_H_

#include "config.h"
#include "ucl.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define RSPAMD_DEFAULT_CACHE "sqlite3"

struct rspamd_task;
struct rspamd_stat_ctx;
struct rspamd_config;
struct rspamd_statfile;

struct rspamd_stat_cache {
	const char *name;

	gpointer (*init) (struct rspamd_stat_ctx *ctx,
					  struct rspamd_config *cfg,
					  struct rspamd_statfile *st,
					  const ucl_object_t *cf);

	gpointer (*runtime) (struct rspamd_task *task,
						 gpointer ctx, gboolean learn);

	gint (*check) (struct rspamd_task *task,
				   gboolean is_spam,
				   gpointer runtime);

	gint (*learn) (struct rspamd_task *task,
				   gboolean is_spam,
				   gpointer runtime);

	void (*close) (gpointer ctx);

	gpointer ctx;
};

#define RSPAMD_STAT_CACHE_DEF(name) \
        gpointer rspamd_stat_cache_##name##_init (struct rspamd_stat_ctx *ctx, \
                struct rspamd_config *cfg, \
                struct rspamd_statfile *st, \
                const ucl_object_t *cf); \
        gpointer rspamd_stat_cache_##name##_runtime (struct rspamd_task *task, \
                gpointer ctx, gboolean learn); \
        gint rspamd_stat_cache_##name##_check (struct rspamd_task *task, \
                gboolean is_spam, \
                gpointer runtime); \
        gint rspamd_stat_cache_##name##_learn (struct rspamd_task *task, \
                gboolean is_spam, \
                gpointer runtime); \
        void rspamd_stat_cache_##name##_close (gpointer ctx)

RSPAMD_STAT_CACHE_DEF(sqlite3);
RSPAMD_STAT_CACHE_DEF(redis);

#ifdef  __cplusplus
}
#endif

#endif /* LEARN_CACHE_H_ */
