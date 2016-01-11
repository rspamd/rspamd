/*
 * Copyright (c) 2015, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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
#ifndef LEARN_CACHE_H_
#define LEARN_CACHE_H_

#include "config.h"
#include "ucl.h"

#define RSPAMD_DEFAULT_CACHE "sqlite3"

struct rspamd_task;
struct rspamd_stat_ctx;
struct rspamd_config;
struct rspamd_statfile;

struct rspamd_stat_cache {
	const char *name;
	gpointer (*init)(struct rspamd_stat_ctx *ctx,
			struct rspamd_config *cfg,
			struct rspamd_statfile *st,
			const ucl_object_t *cf);
	gpointer (*runtime)(struct rspamd_task *task,
			gpointer ctx, gboolean learn);
	gint (*check)(struct rspamd_task *task,
			gboolean is_spam,
			gpointer runtime);
	gint (*learn)(struct rspamd_task *task,
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
#ifdef WITH_HIREDIS
RSPAMD_STAT_CACHE_DEF(redis);
#endif

#endif /* LEARN_CACHE_H_ */
