/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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

/*
 * Bayesian classifier
 */
#include "classifiers.h"
#include "tokenizers/tokenizers.h"
#include "main.h"
#include "filter.h"
#include "cfg_file.h"
#include "binlog.h"
#include "lua/lua_common.h"

#define LOCAL_PROB_DENOM 16.0

static inline GQuark
bayes_error_quark (void)
{
	return g_quark_from_static_string ("bayes-error");
}

struct bayes_statfile_data {
	guint64                         hits;
	guint64                         total_hits;
	double                          local_probability;
	double                          post_probability;
	double                          corr;
	double                          value;
	struct statfile                *st;
	stat_file_t                    *file;
};

struct bayes_callback_data {
	statfile_pool_t                *pool;
	struct classifier_ctx          *ctx;
	gboolean                        in_class;
	time_t                          now;
	stat_file_t                    *file;
	struct bayes_statfile_data     *statfiles;
	guint32                         statfiles_num;
	guint64                         learned_tokens;
	gsize                           max_tokens;
};

static                          gboolean
bayes_learn_callback (gpointer key, gpointer value, gpointer data)
{
	token_node_t                   *node = key;
	struct bayes_callback_data     *cd = data;
	gint                            c;
	guint64                         v;

	c = (cd->in_class) ? 1 : -1;

	/* Consider that not found blocks have value 1 */
	v = statfile_pool_get_block (cd->pool, cd->file, node->h1, node->h2, cd->now);
	if (v == 0 && c > 0) {
		statfile_pool_set_block (cd->pool, cd->file, node->h1, node->h2, cd->now, c);
		cd->learned_tokens ++;
	}
	else if (v != 0) {
		if (G_LIKELY (c > 0)) {
			v ++;
		}
		else if (c < 0){
			if (v != 0) {
				v --;
			}
		}
		statfile_pool_set_block (cd->pool, cd->file, node->h1, node->h2, cd->now, v);
		cd->learned_tokens ++;
	}

	if (cd->max_tokens != 0 && cd->learned_tokens > cd->max_tokens) {
		/* Stop learning on max tokens */
		return TRUE;
	}
	return FALSE;
}

/*
 * In this callback we calculate local probabilities for tokens
 */
static gboolean
bayes_classify_callback (gpointer key, gpointer value, gpointer data)
{

	token_node_t                   *node = key;
	struct bayes_callback_data     *cd = data;
	double                          renorm = 0;
	guint                            i;
	double                          local_hits = 0;
	struct bayes_statfile_data     *cur;

	for (i = 0; i < cd->statfiles_num; i ++) {
		cur = &cd->statfiles[i];
		cur->value = statfile_pool_get_block (cd->pool, cur->file, node->h1, node->h2, cd->now);
		if (cur->value > 0) {
			cur->total_hits ++;
			cur->hits = cur->value;
			local_hits += cur->value;
		}
	}
	for (i = 0; i < cd->statfiles_num; i ++) {
		cur = &cd->statfiles[i];
		cur->local_probability = 0.5 + (cur->value - (local_hits - cur->value)) /
				(LOCAL_PROB_DENOM * (1.0 + local_hits));
		renorm += cur->post_probability * cur->local_probability;
	}

	for (i = 0; i < cd->statfiles_num; i ++) {
		cur = &cd->statfiles[i];
		cur->post_probability = (cur->post_probability * cur->local_probability) / renorm;
		if (cur->post_probability < G_MINDOUBLE * 100) {
			cur->post_probability = G_MINDOUBLE * 100;
		}

	}
	renorm = 0;
	for (i = 0; i < cd->statfiles_num; i ++) {
		cur = &cd->statfiles[i];
		renorm += cur->post_probability;
	}
	/* Renormalize to form sum of probabilities equal to 1 */
	for (i = 0; i < cd->statfiles_num; i ++) {
		cur = &cd->statfiles[i];
		cur->post_probability /= renorm;
		if (cur->post_probability < G_MINDOUBLE * 10) {
			cur->post_probability = G_MINDOUBLE * 100;
		}
		if (cd->ctx->debug) {
			msg_info ("token: %s, statfile: %s, probability: %.4f, post_probability: %.4f",
					node->extra, cur->st->symbol, cur->value, cur->post_probability);
		}
	}

	cd->learned_tokens ++;
	if (cd->max_tokens != 0 && cd->learned_tokens > cd->max_tokens) {
		/* Stop classifying on max tokens */
		return TRUE;
	}

	return FALSE;
}

struct classifier_ctx*
bayes_init (memory_pool_t *pool, struct classifier_config *cfg)
{
	struct classifier_ctx          *ctx = memory_pool_alloc (pool, sizeof (struct classifier_ctx));

	ctx->pool = pool;
	ctx->cfg = cfg;
	ctx->debug = FALSE;

	return ctx;
}

gboolean
bayes_classify (struct classifier_ctx* ctx, statfile_pool_t *pool, GTree *input, struct worker_task *task, lua_State *L)
{
	struct bayes_callback_data      data;
	gchar                          *value;
	gint                            nodes, i = 0, cnt, best_num = 0;
	gint                            minnodes;
	guint64                         rev, total_learns = 0;
	double                          best = 0;
	struct statfile                *st;
	stat_file_t                    *file;
	GList                          *cur;
	char                           *sumbuf;

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "min_tokens")) != NULL) {
		minnodes = strtol (value, NULL, 10);
		nodes = g_tree_nnodes (input);
		if (nodes > FEATURE_WINDOW_SIZE) {
			nodes = nodes / FEATURE_WINDOW_SIZE + FEATURE_WINDOW_SIZE;
		}
		if (nodes < minnodes) {
			return FALSE;
		}
	}

	cur = call_classifier_pre_callbacks (ctx->cfg, task, FALSE, FALSE, L);
	if (cur) {
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, cur);
	}
	else {
		cur = ctx->cfg->statfiles;
	}

	data.statfiles_num = g_list_length (cur);
	data.statfiles = g_new0 (struct bayes_statfile_data, data.statfiles_num);
	data.pool = pool;
	data.now = time (NULL);
	data.ctx = ctx;

	data.learned_tokens = 0;
	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "max_tokens")) != NULL) {
		minnodes = parse_limit (value, -1);
		data.max_tokens = minnodes;
	}
	else {
		data.max_tokens = 0;
	}

	while (cur) {
		/* Select statfile to classify */
		st = cur->data;
		if ((file = statfile_pool_is_open (pool, st->path)) == NULL) {
			if ((file = statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
				msg_warn ("cannot open %s", st->path);
				cur = g_list_next (cur);
				data.statfiles_num --;
				continue;
			}
		}
		data.statfiles[i].file = file;
		data.statfiles[i].st = st;
		data.statfiles[i].post_probability = 0.5;
		data.statfiles[i].local_probability = 0.5;
		statfile_get_revision (file, &rev, NULL);
		total_learns += rev;

		cur = g_list_next (cur);
		i ++;
	}

	cnt = i;

	/* Calculate correction factor */
	for (i = 0; i < cnt; i ++) {
		statfile_get_revision (data.statfiles[i].file, &rev, NULL);
		data.statfiles[i].corr = ((double)rev / cnt) / (double)total_learns;
	}

	g_tree_foreach (input, bayes_classify_callback, &data);

	for (i = 0; i < cnt; i ++) {
		debug_task ("got probability for symbol %s: %.2f", data.statfiles[i].st->symbol, data.statfiles[i].post_probability);
		if (data.statfiles[i].post_probability > best) {
			best = data.statfiles[i].post_probability;
			best_num = i;
		}
	}

	if (best > 0.5) {
		sumbuf = memory_pool_alloc (task->task_pool, 32);
		rspamd_snprintf (sumbuf, 32, "%.2f", best);
		cur = g_list_prepend (NULL, sumbuf);
		insert_result (task, data.statfiles[best_num].st->symbol, best, cur);
	}

	g_free (data.statfiles);

	return TRUE;
}

gboolean
bayes_learn (struct classifier_ctx* ctx, statfile_pool_t *pool, const char *symbol, GTree *input,
				gboolean in_class, double *sum, double multiplier, GError **err)
{
	struct bayes_callback_data      data;
	gchar                          *value;
	gint                            nodes;
	gint                            minnodes;
	struct statfile                *st, *sel_st = NULL;
	stat_file_t                    *to_learn;
	GList                          *cur;

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "min_tokens")) != NULL) {
		minnodes = strtol (value, NULL, 10);
		nodes = g_tree_nnodes (input);
		if (nodes > FEATURE_WINDOW_SIZE) {
			nodes = nodes / FEATURE_WINDOW_SIZE + FEATURE_WINDOW_SIZE;
		}
		if (nodes < minnodes) {
			msg_info ("do not learn message as it has too few tokens: %d, while %d min", nodes, minnodes);
			*sum = 0;
			g_set_error (err,
	                   bayes_error_quark(),		/* error domain */
	                   1,            				/* error code */
	                   "message contains too few tokens: %d, while min is %d",
	                   nodes, (int)minnodes);
			return FALSE;
		}
	}

	data.pool = pool;
	data.in_class = in_class;
	data.now = time (NULL);
	data.ctx = ctx;
	data.learned_tokens = 0;
	data.learned_tokens = 0;
	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "max_tokens")) != NULL) {
		minnodes = parse_limit (value, -1);
		data.max_tokens = minnodes;
	}
	else {
		data.max_tokens = 0;
	}
	cur = ctx->cfg->statfiles;
	while (cur) {
		/* Select statfile to learn */
		st = cur->data;
		if (strcmp (st->symbol, symbol) == 0) {
			sel_st = st;
			break;
		}
		cur = g_list_next (cur);
	}
	if (sel_st == NULL) {
		g_set_error (err,
				bayes_error_quark(),		/* error domain */
				1,            				/* error code */
				"cannot find statfile for symbol: %s",
				symbol);
		return FALSE;
	}
	if ((to_learn = statfile_pool_is_open (pool, sel_st->path)) == NULL) {
		if ((to_learn = statfile_pool_open (pool, sel_st->path, sel_st->size, FALSE)) == NULL) {
			msg_warn ("cannot open %s", sel_st->path);
			if (statfile_pool_create (pool, sel_st->path, sel_st->size) == -1) {
				msg_err ("cannot create statfile %s", sel_st->path);
				g_set_error (err,
						bayes_error_quark(),		/* error domain */
						1,            				/* error code */
						"cannot create statfile: %s",
						sel_st->path);
				return FALSE;
			}
			if ((to_learn = statfile_pool_open (pool, sel_st->path, sel_st->size, FALSE)) == NULL) {
				g_set_error (err,
						bayes_error_quark(),		/* error domain */
						1,            				/* error code */
						"cannot open statfile %s after creation",
						sel_st->path);
				msg_err ("cannot open statfile %s after creation", sel_st->path);
				return FALSE;
			}
		}
	}
	data.file = to_learn;
	statfile_pool_lock_file (pool, data.file);
	g_tree_foreach (input, bayes_learn_callback, &data);
	statfile_inc_revision (to_learn);
	statfile_pool_unlock_file (pool, data.file);

	if (sum != NULL) {
		*sum = data.learned_tokens;
	}

	return TRUE;
}

gboolean
bayes_learn_spam (struct classifier_ctx* ctx, statfile_pool_t *pool,
		GTree *input, struct worker_task *task, gboolean is_spam, lua_State *L, GError **err)
{
	struct bayes_callback_data      data;
	gchar                          *value;
	gint                            nodes;
	gint                            minnodes;
	struct statfile                *st;
	stat_file_t                    *file;
	GList                          *cur;
	gboolean						skip_labels;

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "min_tokens")) != NULL) {
		minnodes = strtol (value, NULL, 10);
		nodes = g_tree_nnodes (input);
		if (nodes > FEATURE_WINDOW_SIZE) {
			nodes = nodes / FEATURE_WINDOW_SIZE + FEATURE_WINDOW_SIZE;
		}
		if (nodes < minnodes) {
			g_set_error (err,
					bayes_error_quark(),		/* error domain */
					1,            				/* error code */
					"message contains too few tokens: %d, while min is %d",
					nodes, (int)minnodes);
			return FALSE;
		}
	}

	cur = call_classifier_pre_callbacks (ctx->cfg, task, TRUE, is_spam, L);
	if (cur) {
		skip_labels = FALSE;
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, cur);
	}
	else {
		/* Do not try to learn specific statfiles if pre callback returned nil */
		skip_labels = TRUE;
		cur = ctx->cfg->statfiles;
	}

	data.pool = pool;
	data.now = time (NULL);
	data.ctx = ctx;

	data.learned_tokens = 0;
	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "max_tokens")) != NULL) {
		minnodes = parse_limit (value, -1);
		data.max_tokens = minnodes;
	}
	else {
		data.max_tokens = 0;
	}

	while (cur) {
		/* Select statfiles to learn */
		st = cur->data;
		if (st->is_spam != is_spam || (skip_labels && st->label)) {
			cur = g_list_next (cur);
			continue;
		}
		if ((file = statfile_pool_is_open (pool, st->path)) == NULL) {
			if ((file = statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
				msg_warn ("cannot open %s", st->path);
				if (statfile_pool_create (pool, st->path, st->size) == -1) {
					msg_err ("cannot create statfile %s", st->path);
					g_set_error (err,
							bayes_error_quark(),		/* error domain */
							1,            				/* error code */
							"cannot create statfile: %s",
							st->path);
					return FALSE;
				}
				if ((file = statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
					g_set_error (err,
							bayes_error_quark(),		/* error domain */
							1,            				/* error code */
							"cannot open statfile %s after creation",
							st->path);
					msg_err ("cannot open statfile %s after creation", st->path);
					return FALSE;
				}
			}
		}
		data.file = file;
		statfile_pool_lock_file (pool, data.file);
		g_tree_foreach (input, bayes_learn_callback, &data);
		statfile_inc_revision (file);
		statfile_pool_unlock_file (pool, data.file);
		maybe_write_binlog (ctx->cfg, st, file, input);
		msg_info ("increase revision for %s", st->path);

		cur = g_list_next (cur);
	}

	return TRUE;
}

GList *
bayes_weights (struct classifier_ctx* ctx, statfile_pool_t *pool, GTree *input, struct worker_task *task)
{
	struct bayes_callback_data      data;
	char                           *value;
	int                             nodes, minnodes, i, cnt;
	struct classify_weight         *w;
	struct statfile                *st;
	stat_file_t                    *file;
	GList                          *cur, *resl = NULL;

	g_assert (pool != NULL);
	g_assert (ctx != NULL);

	if (ctx->cfg->opts && (value = g_hash_table_lookup (ctx->cfg->opts, "min_tokens")) != NULL) {
		minnodes = strtol (value, NULL, 10);
		nodes = g_tree_nnodes (input);
		if (nodes > FEATURE_WINDOW_SIZE) {
			nodes = nodes / FEATURE_WINDOW_SIZE + FEATURE_WINDOW_SIZE;
		}
		if (nodes < minnodes) {
			return NULL;
		}
	}

	data.statfiles_num = g_list_length (ctx->cfg->statfiles);
	data.statfiles = g_new0 (struct bayes_statfile_data, data.statfiles_num);
	data.pool = pool;
	data.now = time (NULL);
	data.ctx = ctx;

	cur = ctx->cfg->statfiles;
	i = 0;
	while (cur) {
		/* Select statfile to learn */
		st = cur->data;
		if ((file = statfile_pool_is_open (pool, st->path)) == NULL) {
			if ((file = statfile_pool_open (pool, st->path, st->size, FALSE)) == NULL) {
				msg_warn ("cannot open %s", st->path);
				cur = g_list_next (cur);
				data.statfiles_num --;
				continue;
			}
		}
		data.statfiles[i].file = file;
		data.statfiles[i].st = st;
		data.statfiles[i].post_probability = 0.5;
		data.statfiles[i].local_probability = 0.5;
		i ++;
		cur = g_list_next (cur);
	}
	cnt = i;

	g_tree_foreach (input, bayes_classify_callback, &data);

	for (i = 0; i < cnt; i ++) {
		w = memory_pool_alloc0 (task->task_pool, sizeof (struct classify_weight));
		w->name = data.statfiles[i].st->symbol;
		w->weight = data.statfiles[i].post_probability;
		resl = g_list_prepend (resl, w);
	}

	g_free (data.statfiles);

	if (resl != NULL) {
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, resl);
	}

	return resl;
}
