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
#ifndef STAT_API_H_
#define STAT_API_H_

#include "config.h"
#include "task.h"
#include <lua.h>

/**
 * @file stat_api.h
 * High level statistics API
 */

/**
 * Initialise statistics modules
 * @param cfg
 */
void rspamd_stat_init (struct rspamd_config *cfg);

/**
 * Classify the task specified and insert symbols if needed
 * @param task
 * @return TRUE if task has been classified
 */
gboolean rspamd_stat_classify (struct rspamd_task *task, lua_State *L, GError **err);


/**
 * Learn task as spam or ham, task must be processed prior to this call
 * @param task task to learn
 * @param spam if TRUE learn spam, otherwise learn ham
 * @return TRUE if task has been learned
 */
gboolean rspamd_stat_learn (struct rspamd_task *task, gboolean spam, lua_State *L,
		GError **err);

/**
 * Get the overall statistics for all statfile backends
 * @param cfg configuration
 * @param total_learns the total number of learns is stored here
 * @return array of statistical information
 */
ucl_object_t * rspamd_stat_statistics (struct rspamd_config *cfg,
		guint64 *total_learns);

void rspamd_stat_unload (void);

#endif /* STAT_API_H_ */
