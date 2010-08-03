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
#include "../tokenizers/tokenizers.h"
#include "../main.h"
#include "../filter.h"
#include "../cfg_file.h"
#ifdef WITH_LUA
#include "../lua/lua_common.h"
#endif

#define WINNOW_PROMOTION 1.23
#define WINNOW_DEMOTION 0.83

#define MEDIAN_WINDOW_SIZE 5

#define MAX_WEIGHT G_MAXDOUBLE / 2.

#define ALPHA 0.01

#define MAX_LEARN_ITERATIONS 100

struct winnow_callback_data {
	statfile_pool_t                *pool;
	struct classifier_ctx          *ctx;
	stat_file_t                    *file;
	stat_file_t                    *learn_file;
	long double                     sum;
	double                          multiplier;
	int                             count;
	gboolean                        in_class;
	gboolean                        do_demote;
	gboolean                        fresh_run;
	time_t                          now;
};

static const double max_common_weight = MAX_WEIGHT * WINNOW_DEMOTION;

static                          gboolean
classify_callback (gpointer key, gpointer value, gpointer data)
{
	token_node_t                   *node = key;
	struct winnow_callback_data    *cd = data;
	double                           v;

	/* Consider that not found blocks have value 1 */
	v = statfile_pool_get_block (cd->pool, cd->file, node->h1, node->h2, cd->now);
	if (fabs (v) > ALPHA) {
		cd->sum += v;
		cd->in_class++;
	}
	else {
		cd->sum += 1.0;
	}

	cd->count++;

	return FALSE;
}

static                          gboolean
learn_callback (gpointer key, gpointer value, gpointer data)
{
	token_node_t                   *node = key;
	struct winnow_callback_data    *cd = data;
	double                          v, c;
	
	c = (cd->in_class) ? WINNOW_PROMOTION * cd->multiplier : WINNOW_DEMOTION / cd->multiplier;

	/* Consider that not found blocks have value 1 */
	v = statfile_pool_get_block (cd->pool, cd->file, node->h1, node->h2, cd->now);
	if (fabs (v) < ALPHA) {
		/* Block not found, insert new */
		if (cd->file == cd->learn_file) {
			statfile_pool_set_block (cd->pool, cd->file, node->h1, node->h2, cd->now, c);
			node->value = c;
		}
	}
	else {
		/* Here we just increase the extra value of block */
		if (cd->fresh_run) {
			node->extra = 0;
		}
		else {
			node->extra ++;
		}
		node->value = v;
		
		if (node->extra > 1) {
			/* 
			 * Assume that this node is common for several statfiles, so
			 * decrease its weight proportianally
			 */
			if (node->value > max_common_weight) {
				/* Static fluctuation */
				statfile_pool_set_block (cd->pool, cd->file, node->h1, node->h2, cd->now, 0.);
				node->value = 0.;
			}
			else if (node->value > WINNOW_PROMOTION * cd->multiplier) {
				/* Try to decrease its value */
				/* XXX: it is more intelligent to add some adaptive filter here */
				if (cd->file == cd->learn_file) {
					if (node->value > max_common_weight / 2.) {
						node->value *= c;
					}
					else {
						/* 
						 * Too high token value that exists also in other
						 * statfiles, may be statistic error, so decrease it
						 * slightly
						 */
						node->value *= WINNOW_DEMOTION;
					}
				}
				else {
					node->value = WINNOW_DEMOTION / cd->multiplier;
				}
				statfile_pool_set_block (cd->pool, cd->file, node->h1, node->h2, cd->now, node->value);
			} 
		}
		else if (cd->file == cd->learn_file) {
			/* New block or block that is in only one statfile */
			/* Set some limit on growing */
			if (v > MAX_WEIGHT) {
				node->value = v;
			}
			else {
				node->value *= c;
			}
			statfile_pool_set_block (cd->pool, cd->file, node->h1, node->h2, cd->now, node->value);
		}
		else if (cd->do_demote) {
			/* Demote blocks in file */
			node->value *= WINNOW_DEMOTION / cd->multiplier;
			statfile_pool_set_block (cd->pool, cd->file, node->h1, node->h2, cd->now, node->value);
		}
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
	char                           *sumbuf, *value;
	long double                     res = 0., max = 0.;
	GList                          *cur;
	struct statfile                *st, *sel = NULL;
	int                             nodes, minnodes;

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	data.pool = pool;
	data.now = time (NULL);
	data.ctx = ctx;
    
	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "min_tokens")) != NULL) {
		minnodes = strtol (value, NULL, 10);
		nodes = g_tree_nnodes (input) / FEATURE_WINDOW_SIZE;
		if (nodes < minnodes) {
			msg_info ("do not classify message as it has too few tokens: %d, while %d min", nodes, minnodes);
			return;
		}
	}

    if (ctx->cfg->pre_callbacks) {
#ifdef WITH_LUA
        cur = call_classifier_pre_callbacks (ctx->cfg, task);
        if (cur) {
            memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, cur);
        }
#else
	    cur = ctx->cfg->statfiles;
#endif
    }
    else {
	    cur = ctx->cfg->statfiles;
    }
	while (cur) {
		st = cur->data;
		data.sum = 0;
		data.count = 0;
		if ((data.file = statfile_pool_is_open (pool, st->path)) == NULL) {
			if ((data.file = statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
				msg_warn ("cannot open %s, skip it", st->path);
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
			res = data.sum / (double)data.count;
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
#ifdef WITH_LUA
        max = call_classifier_post_callbacks (ctx->cfg, task, max);
#endif
		if (st->normalizer != NULL) {
			max = st->normalizer (task->cfg, max, st->normalizer_data);
		}
		sumbuf = memory_pool_alloc (task->task_pool, 32);
		rspamd_snprintf (sumbuf, 32, "%.2F", max);
		cur = g_list_prepend (NULL, sumbuf);
		insert_result (task, sel->symbol, max, cur);
	}
}

GList *
winnow_weights (struct classifier_ctx *ctx, statfile_pool_t * pool, GTree * input, struct worker_task *task)
{
	struct winnow_callback_data     data;
	long double                     res = 0.;
	GList                          *cur, *resl = NULL;
	struct statfile                *st;
	struct classify_weight         *w;
	char                           *value;
	int                             nodes, minnodes;

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	data.pool = pool;
	data.now = time (NULL);
	data.ctx = ctx;

	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "min_tokens")) != NULL) {
		minnodes = strtol (value, NULL, 10);
		nodes = g_tree_nnodes (input) / FEATURE_WINDOW_SIZE;
		if (nodes < minnodes) {
			msg_info ("do not classify message as it has too few tokens: %d, while %d min", nodes, minnodes);
			return NULL;
		}
	}
    
	cur = ctx->cfg->statfiles;
	while (cur) {
		st = cur->data;
		data.sum = 0;
		data.count = 0;
		if ((data.file = statfile_pool_is_open (pool, st->path)) == NULL) {
			if ((data.file = statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
				msg_warn ("cannot open %s, skip it", st->path);
				cur = g_list_next (cur);
				continue;
			}
		}

		if (data.file != NULL) {
			statfile_pool_lock_file (pool, data.file);
			g_tree_foreach (input, classify_callback, &data);
			statfile_pool_unlock_file (pool, data.file);
		}

		w = memory_pool_alloc0 (task->task_pool, sizeof (struct classify_weight));
		if (data.count != 0) {
			res = data.sum / (double)data.count;
		}
		else {
			res = 0;
		}
		w->name = st->symbol;
		w->weight = res;
		resl = g_list_prepend (resl, w);
		cur = g_list_next (cur);
	}
	
	if (resl != NULL) {
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, resl);
	}

	return resl;

}


void
winnow_learn (struct classifier_ctx *ctx, statfile_pool_t *pool, stat_file_t *file, GTree * input, int in_class, double *sum, double multiplier)
{
	struct winnow_callback_data     data = {
		.file = NULL,
		.multiplier = multiplier
	};
	char                           *value;
	int                             nodes, minnodes, iterations = 0;
	struct statfile                *st, *sel_st;
	stat_file_t                    *sel = NULL;
	long double                     res = 0., max = 0.;
	double                          learn_threshold = 1.0;
	GList                          *cur, *to_demote = NULL;

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	data.pool = pool;
	data.in_class = in_class;
	data.now = time (NULL);
	data.ctx = ctx;
	data.learn_file = file;

	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "min_tokens")) != NULL) {
		minnodes = strtol (value, NULL, 10);
		nodes = g_tree_nnodes (input) / FEATURE_WINDOW_SIZE;
		if (nodes < minnodes) {
			msg_info ("do not learn message as it has too few tokens: %d, while %d min", nodes, minnodes);
			*sum = 0;
			return;
		}
	}
	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "learn_threshold")) != NULL) {
		learn_threshold = strtod (value, NULL);
	}
	
	if (learn_threshold >= 1.0) {
		/* Classify message and check target statfile score */
		cur = ctx->cfg->statfiles;
		/* Check target statfile */
		data.file = file;
		data.sum = 0;
		data.count = 0;
		data.file = file;
		statfile_pool_lock_file (pool, data.file);
		g_tree_foreach (input, classify_callback, &data);
		statfile_pool_unlock_file (pool, data.file);
		if (data.count > 0) {
			max = data.sum / (double)data.count;
		}
		else {
			max = 0;
		}
		while (cur) {
			st = cur->data;
			data.sum = 0;
			data.count = 0;
			if ((data.file = statfile_pool_is_open (pool, st->path)) == NULL) {
				if ((data.file = statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
					msg_warn ("cannot open %s, skip it", st->path);
					cur = g_list_next (cur);
					continue;
				}
			}
			statfile_pool_lock_file (pool, data.file);
			g_tree_foreach (input, classify_callback, &data);
			statfile_pool_unlock_file (pool, data.file);
			if (data.count != 0) {
				res = data.sum / data.count;
			}
			else {
				res = 0;
			}
			if (file != data.file && res / max > learn_threshold) {
				/* Demote tokens in this statfile */
				to_demote = g_list_prepend (to_demote, data.file);
			}
			else if (file == data.file) {
				sel_st = st;
			}
			cur = g_list_next (cur);
		}
	}
	else {
		msg_err ("learn threshold is less than 1, so cannot do learn, please check your configuration");
		return;
	}
	/* If to_demote list is empty this message is already classified correctly */
	if (max > ALPHA && to_demote == NULL) {
		msg_info ("this message is already of class %s with threshold %.2f and weight %.2F",
				sel_st->symbol, learn_threshold, max);
		goto end;
	}
	do {
		cur = ctx->cfg->statfiles;
		data.fresh_run = TRUE;
		while (cur) {
			st = cur->data;
			data.sum = 0;
			data.count = 0;
			if ((data.file = statfile_pool_is_open (pool, st->path)) == NULL) {
				if ((data.file = statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
					msg_warn ("cannot open %s, skip it", st->path);
					cur = g_list_next (cur);
					continue;
				}
			}
			if (to_demote != NULL && g_list_find (to_demote, data.file) != NULL) {
				data.do_demote = TRUE;
			}
			else {
				data.do_demote = FALSE;
			}
			statfile_pool_lock_file (pool, data.file);
			g_tree_foreach (input, learn_callback, &data);
			statfile_pool_unlock_file (pool, data.file);
			if (data.count != 0) {
				res = data.sum / data.count;
			}
			else {
				res = 0;
			}
			if (res > max) {
				max = res;
				sel = data.file;
			}
			cur = g_list_next (cur);
			data.fresh_run = FALSE;
		}
		
		if (data.multiplier > 1) {
			data.multiplier *= data.multiplier;
		}
		else {
			data.multiplier *= WINNOW_PROMOTION;
		}
	} while ((in_class ? sel != file : sel == file)  && iterations ++ < MAX_LEARN_ITERATIONS);
	
	if (iterations >= MAX_LEARN_ITERATIONS) {
		msg_warn ("learning statfile %s  was not fully successfull: iterations count is limited to %d, final sum is %G", 
				file->filename, MAX_LEARN_ITERATIONS, max);
	}
	else {
		msg_info ("learned statfile %s successfully with %d iterations and sum %G", file->filename, iterations + 1, max);
	}


end:
	if (sum) {
		*sum = (double)max;
	}
}
