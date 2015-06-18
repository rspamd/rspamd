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
#ifndef BACKENDS_H_
#define BACKENDS_H_

#include "config.h"
#include "ucl.h"

#define RSPAMD_DEFAULT_BACKEND "mmap"

/* Forwarded declarations */
struct rspamd_classifier_config;
struct rspamd_statfile_config;
struct rspamd_config;
struct rspamd_stat_ctx;
struct rspamd_token_result;
struct rspamd_statfile_runtime;
struct token_node_s;
struct rspamd_task;

struct rspamd_stat_backend {
	const char *name;
	gpointer (*init)(struct rspamd_stat_ctx *ctx, struct rspamd_config *cfg);
	gpointer (*runtime)(struct rspamd_task *task,
			struct rspamd_statfile_config *stcf, gboolean learn, gpointer ctx);
	gboolean (*process_token)(struct token_node_s *tok,
			struct rspamd_token_result *res, gpointer ctx);
	gboolean (*learn_token)(struct token_node_s *tok,
			struct rspamd_token_result *res, gpointer ctx);
	gulong (*total_learns)(struct rspamd_statfile_runtime *runtime, gpointer ctx);
	void (*finalize_learn)(struct rspamd_statfile_runtime *runtime, gpointer ctx);
	gulong (*inc_learns)(struct rspamd_statfile_runtime *runtime, gpointer ctx);
	gulong (*dec_learns)(struct rspamd_statfile_runtime *runtime, gpointer ctx);
	ucl_object_t* (*get_stat)(struct rspamd_statfile_runtime *runtime, gpointer ctx);
	gpointer ctx;
};

#define RSPAMD_STAT_BACKEND_DEF(name) \
		gpointer rspamd_##name##_init (struct rspamd_stat_ctx *ctx, struct rspamd_config *cfg); \
		gpointer rspamd_##name##_runtime (struct rspamd_task *task, \
				struct rspamd_statfile_config *stcf, \
				gboolean learn, gpointer ctx); \
		gboolean rspamd_##name##_process_token (struct token_node_s *tok, \
				struct rspamd_token_result *res, \
				gpointer ctx); \
		gboolean rspamd_##name##_learn_token (struct token_node_s *tok, \
				struct rspamd_token_result *res, \
				gpointer ctx); \
		void rspamd_##name##_finalize_learn (struct rspamd_statfile_runtime *runtime, \
				gpointer ctx); \
		gulong rspamd_##name##_total_learns (struct rspamd_statfile_runtime *runtime, \
				gpointer ctx); \
		gulong rspamd_##name##_inc_learns (struct rspamd_statfile_runtime *runtime, \
				gpointer ctx); \
		gulong rspamd_##name##_dec_learns (struct rspamd_statfile_runtime *runtime, \
						gpointer ctx); \
		gulong rspamd_##name##_learns (struct rspamd_statfile_runtime *runtime, \
				gpointer ctx); \
		ucl_object_t * rspamd_##name##_get_stat (struct rspamd_statfile_runtime *runtime, \
				gpointer ctx)

RSPAMD_STAT_BACKEND_DEF(mmaped_file);
RSPAMD_STAT_BACKEND_DEF(redis);

#endif /* BACKENDS_H_ */
