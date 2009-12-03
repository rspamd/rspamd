/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Winnow classifier
 */

#include "classifiers.h"
#include "../main.h"
#include "../filter.h"
#include "../cfg_file.h"

#define WINNOW_PROMOTION 1.23
#define WINNOW_DEMOTION 0.83

struct winnow_callback_data {
	statfile_pool_t                *pool;
	struct classifier_ctx          *ctx;
	stat_file_t                    *file;
	double                          sum;
	int                             count;
	int                             in_class;
	time_t                          now;
};

static                          gboolean
classify_callback (gpointer key, gpointer value, gpointer data)
{
	token_node_t                   *node = key;
	struct winnow_callback_data    *cd = data;
	double                           v;

	/* Consider that not found blocks have value 1 */
	v = statfile_pool_get_block (cd->pool, cd->file, node->h1, node->h2, cd->now);
	if (fabs (v) > 0.00001) {
		cd->sum += v;
		cd->in_class++;
	}

	cd->count++;

	return FALSE;
}

static                          gboolean
learn_callback (gpointer key, gpointer value, gpointer data)
{
	token_node_t                   *node = key;
	struct winnow_callback_data    *cd = data;
	double                           v, c;

	c = (cd->in_class) ? WINNOW_PROMOTION : WINNOW_DEMOTION;

	/* Consider that not found blocks have value 1 */
	v = statfile_pool_get_block (cd->pool, cd->file, node->h1, node->h2, cd->now);
	if (fabs (v) < 0.00001) {
		statfile_pool_set_block (cd->pool, cd->file, node->h1, node->h2, cd->now, c);
		node->value = c;
	}
	else {
		statfile_pool_set_block (cd->pool, cd->file, node->h1, node->h2, cd->now, v * c);
		node->value = v * c;
	}

	cd->sum += node->value;
	cd->count++;

	return FALSE;
}

struct classifier_ctx          *
winnow_init (memory_pool_t * pool, struct classifier_config *cfg)
{
	struct classifier_ctx          *ctx = memory_pool_alloc (pool, sizeof (struct classifier_ctx));

	ctx->pool = pool;
	ctx->cfg = cfg;

	return ctx;
}

void
winnow_classify (struct classifier_ctx *ctx, statfile_pool_t * pool, GTree * input, struct worker_task *task)
{
	struct winnow_callback_data     data;
	char                           *sumbuf;
	double                          res = 0., max = 0.;
	GList                          *cur;
	struct statfile                *st, *sel = NULL;

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	data.pool = pool;
	data.sum = 0;
	data.count = 0;
	data.now = time (NULL);
	data.ctx = ctx;

	cur = ctx->cfg->statfiles;
	while (cur) {
		st = cur->data;
		if ((data.file = statfile_pool_is_open (pool, st->path)) == NULL) {
			if ((data.file = statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
				msg_warn ("winnow_classify: cannot open %s, skip it", st->path);
				cur = g_list_next (cur);
				continue;
			}
		}

		if (data.file != NULL) {
			statfile_pool_lock_file (pool, data.file);
			g_tree_foreach (input, classify_callback, &data);
			statfile_pool_unlock_file (pool, data.file);
		}

		if (data.count != 0) {
			res = data.sum / data.count;
		}
		else {
			res = 0;
		}
		if (res > max) {
			max = res;
			sel = st;
		}
		cur = g_list_next (cur);
	}

	if (sel != NULL) {
		sumbuf = memory_pool_alloc (task->task_pool, 32);
		snprintf (sumbuf, 32, "%.2f", max);
		cur = g_list_prepend (NULL, sumbuf);
		insert_result (task, ctx->cfg->metric, sel->symbol, 1, cur);
	}
}

void
winnow_learn (struct classifier_ctx *ctx, statfile_pool_t *pool, stat_file_t *file, GTree * input, int in_class, double *sum)
{
	struct winnow_callback_data     data = {
		.file = NULL,
		.sum = 0,
		.count = 0,
	};

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	data.pool = pool;
	data.in_class = in_class;
	data.now = time (NULL);
	data.ctx = ctx;

	data.file = file;


	if (data.file != NULL) {
		statfile_pool_lock_file (pool, data.file);
		g_tree_foreach (input, learn_callback, &data);
		statfile_pool_unlock_file (pool, data.file);
	}
	
	if (sum) {
		if (data.count != 0) {
			*sum = data.sum / data.count;
		}
		else {
			*sum = 0;
		}
	}
}
