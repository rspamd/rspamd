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
#include "main.h"
#include "filter.h"
#include "cfg_file.h"
#include "stat_internal.h"

#define LOCAL_PROB_DENOM 16.0

static inline GQuark
bayes_error_quark (void)
{
	return g_quark_from_static_string ("bayes-error");
}

struct bayes_statfile_data {
	guint64 hits;
	guint64 total_hits;
	double value;
	struct rspamd_statfile_config *st;
};

struct bayes_callback_data {
	struct classifier_ctx *ctx;
	gboolean in_class;
	time_t now;
	struct bayes_statfile_data *statfiles;
	guint32 statfiles_num;
	guint64 total_spam;
	guint64 total_ham;
	guint64 processed_tokens;
	gsize max_tokens;
	double spam_probability;
	double ham_probability;
};

static gboolean
bayes_learn_callback (gpointer key, gpointer value, gpointer data)
{
	rspamd_token_t *node = key;
	struct bayes_callback_data *cd = data;
	gint c;
	guint64 v;

	c = (cd->in_class) ? 1 : -1;

	/* Consider that not found blocks have value 1 */
	/* XXX implement getting */
	if (v == 0 && c > 0) {
		/* XXX: add token to the backend */
		cd->processed_tokens++;
	}
	else if (v != 0) {
		if (G_LIKELY (c > 0)) {
			v++;
		}
		else if (c < 0) {
			if (v != 0) {
				v--;
			}
		}
		/* XXX: Implement setting */
		cd->processed_tokens++;
	}

	if (cd->max_tokens != 0 && cd->processed_tokens > cd->max_tokens) {
		/* Stop learning on max tokens */
		return TRUE;
	}
	return FALSE;
}

/**
 * Returns probability of chisquare > value with specified number of freedom
 * degrees
 * @param value value to test
 * @param freedom_deg number of degrees of freedom
 * @return
 */
static gdouble
inv_chi_square (gdouble value, gint freedom_deg)
{
	long double prob, sum;
	gint i;

	if ((freedom_deg & 1) != 0) {
		msg_err ("non-odd freedom degrees count: %d", freedom_deg);
		return 0;
	}

	value /= 2.;
	errno = 0;
#ifdef HAVE_EXPL
	prob = expl (-value);
#elif defined(HAVE_EXP2L)
	prob = exp2l (-value * log2 (M_E));
#else
	prob = exp (-value);
#endif
	if (errno == ERANGE) {
		msg_err ("exp overflow");
		return 0;
	}
	sum = prob;
	for (i = 1; i < freedom_deg / 2; i++) {
		prob *= value / (gdouble)i;
		sum += prob;
	}

	return MIN (1.0, sum);
}

/*
 * In this callback we calculate local probabilities for tokens
 */
static gboolean
bayes_classify_callback (gpointer key, gpointer value, gpointer data)
{

	rspamd_token_t *node = key;
	struct bayes_callback_data *cd = data;
	guint i;
	struct bayes_statfile_data *cur;
	guint64 spam_count = 0, ham_count = 0, total_count = 0;
	double spam_prob, spam_freq, ham_freq, bayes_spam_prob;

	for (i = 0; i < cd->statfiles_num; i++) {
		cur = &cd->statfiles[i];
		/*
		 * XXX: Implement getting
		 */
		if (cur->value > 0) {
			cur->total_hits += cur->value;
			if (cur->st->is_spam) {
				spam_count += cur->value;
			}
			else {
				ham_count += cur->value;
			}
			total_count += cur->value;
		}
	}

	/* Probability for this token */
	if (total_count > 0) {
		spam_freq = ((double)spam_count / MAX (1., (double)cd->total_spam));
		ham_freq = ((double)ham_count / MAX (1., (double)cd->total_ham));
		spam_prob = spam_freq / (spam_freq + ham_freq);
		bayes_spam_prob = (0.5 + spam_prob * total_count) / (1. + total_count);
		cd->spam_probability += log (bayes_spam_prob);
		cd->ham_probability += log (1. - bayes_spam_prob);
		cd->processed_tokens++;
	}

	if (cd->max_tokens != 0 && cd->processed_tokens > cd->max_tokens) {
		/* Stop classifying on max tokens */
		return TRUE;
	}

	return FALSE;
}

struct classifier_ctx *
bayes_init (rspamd_mempool_t *pool, struct rspamd_classifier_config *cfg)
{
	struct classifier_ctx *ctx =
		rspamd_mempool_alloc (pool, sizeof (struct classifier_ctx));

	ctx->pool = pool;
	ctx->cfg = cfg;
	ctx->debug = FALSE;

	return ctx;
}

gboolean
bayes_classify (struct classifier_ctx * ctx,
	GTree *input,
	struct rspamd_task *task)
{
	struct bayes_callback_data data;
	gchar *value;
	gint nodes, i = 0, selected_st = -1, cnt;
	gint minnodes;
	guint64 maxhits = 0, rev;
	double final_prob, h, s;
	struct rspamd_statfile_config *st;
	GList *cur;
	char *sumbuf;

	g_assert (ctx != NULL);

	if (ctx->cfg->opts &&
		(value = g_hash_table_lookup (ctx->cfg->opts, "min_tokens")) != NULL) {
		minnodes = strtol (value, NULL, 10);
		nodes = g_tree_nnodes (input);

		if (nodes < minnodes) {
			return FALSE;
		}
	}

	cur = ctx->cfg->statfiles;
#if 0
	cur = rspamd_lua_call_cls_pre_callbacks (ctx->cfg, task, FALSE, FALSE, L);
	if (cur) {
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)g_list_free, cur);
	}
	else {
		cur = ctx->cfg->statfiles;
	}
#endif


	data.statfiles_num = g_list_length (cur);
	data.statfiles = g_new0 (struct bayes_statfile_data, data.statfiles_num);
	data.now = time (NULL);
	data.ctx = ctx;

	data.processed_tokens = 0;
	data.spam_probability = 0;
	data.ham_probability = 0;
	data.total_ham = 0;
	data.total_spam = 0;
	if (ctx->cfg->opts &&
		(value = g_hash_table_lookup (ctx->cfg->opts, "max_tokens")) != NULL) {
		minnodes = rspamd_config_parse_limit (value, -1);
		data.max_tokens = minnodes;
	}
	else {
		data.max_tokens = 0;
	}

	cnt = i;

	g_tree_foreach (input, bayes_classify_callback, &data);

	if (data.processed_tokens == 0 || data.spam_probability == 0) {
		final_prob = 0;
	}
	else {
		h = 1 - inv_chi_square (-2. * data.spam_probability,
				2 * data.processed_tokens);
		s = 1 - inv_chi_square (-2. * data.ham_probability,
				2 * data.processed_tokens);
		final_prob = (s + 1 - h) / 2.;
	}

	if (data.processed_tokens > 0 && fabs (final_prob - 0.5) > 0.05) {

		sumbuf = rspamd_mempool_alloc (task->task_pool, 32);
		for (i = 0; i < cnt; i++) {
			if ((final_prob > 0.5 && !data.statfiles[i].st->is_spam) ||
				(final_prob < 0.5 && data.statfiles[i].st->is_spam)) {
				continue;
			}
			if (data.statfiles[i].total_hits > maxhits) {
				maxhits = data.statfiles[i].total_hits;
				selected_st = i;
			}
		}
		if (selected_st == -1) {
			msg_err (
				"unexpected classifier error: cannot select desired statfile");
		}
		else {
			/* Calculate ham probability correctly */
			if (final_prob < 0.5) {
				final_prob = 1. - final_prob;
			}
			rspamd_snprintf (sumbuf, 32, "%.2f%%", final_prob * 100.);
			cur = g_list_prepend (NULL, sumbuf);
			rspamd_task_insert_result (task,
				data.statfiles[selected_st].st->symbol,
				final_prob,
				cur);
		}
	}

	g_free (data.statfiles);

	return TRUE;
}

gboolean
bayes_learn_spam (struct classifier_ctx * ctx,
	GTree *input,
	struct rspamd_task *task,
	gboolean is_spam,
	GError **err)
{
	struct bayes_callback_data data;
	gchar *value;
	gint nodes;
	gint minnodes;
	struct rspamd_statfile_config *st;
	GList *cur;
	gboolean skip_labels;

	g_assert (ctx != NULL);

	if (ctx->cfg->opts &&
		(value = g_hash_table_lookup (ctx->cfg->opts, "min_tokens")) != NULL) {
		minnodes = strtol (value, NULL, 10);
		nodes = g_tree_nnodes (input);

		if (nodes < minnodes) {
			g_set_error (err,
				bayes_error_quark (),           /* error domain */
				1,                              /* error code */
				"message contains too few tokens: %d, while min is %d",
				nodes, (int)minnodes);
			return FALSE;
		}
	}

	data.now = time (NULL);
	data.ctx = ctx;
	data.in_class = TRUE;

	data.processed_tokens = 0;
	if (ctx->cfg->opts &&
		(value = g_hash_table_lookup (ctx->cfg->opts, "max_tokens")) != NULL) {
		minnodes = rspamd_config_parse_limit (value, -1);
		data.max_tokens = minnodes;
	}
	else {
		data.max_tokens = 0;
	}

	g_tree_foreach (input, bayes_learn_callback, &data);


	return TRUE;
}
