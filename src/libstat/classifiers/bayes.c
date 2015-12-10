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
#include "rspamd.h"
#include "filter.h"
#include "cfg_file.h"
#include "stat_internal.h"
#include "math.h"

#define msg_err_bayes(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "bayes", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_warn_bayes(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "bayes", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_info_bayes(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "bayes", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)
#define msg_debug_bayes(...)  rspamd_default_log_function (G_LOG_LEVEL_DEBUG, \
        "bayes", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)


static inline GQuark
bayes_error_quark (void)
{
	return g_quark_from_static_string ("bayes-error");
}

/**
 * Returns probability of chisquare > value with specified number of freedom
 * degrees
 * @param value value to test
 * @param freedom_deg number of degrees of freedom
 * @return
 */
static gdouble
inv_chi_square (struct rspamd_task *task, gdouble value, gint freedom_deg)
{
	double prob, sum, m;
	gint i;

	errno = 0;
	m = -value;
	prob = exp (value);

	if (errno == ERANGE) {
		msg_err_bayes ("exp overflow");
		return 0;
	}

	sum = prob;

	for (i = 1; i < freedom_deg; i++) {
		prob *= m / (gdouble)i;
		msg_debug_bayes ("prob: %.6f", prob);
		sum += prob;
	}

	return MIN (1.0, sum);
}

struct bayes_task_closure {
	struct rspamd_classifier_runtime *rt;
	struct rspamd_task *task;
};

/*
 * Mathematically we use pow(complexity, complexity), where complexity is the
 * window index
 */
static const double feature_weight[] = { 0, 1, 4, 27, 256, 3125, 46656, 823543 };

#define PROB_COMBINE(prob, cnt, weight, assumed) (((weight) * (assumed) + (cnt) * (prob)) / ((weight) + (cnt)))
/*
 * In this callback we calculate local probabilities for tokens
 */
static gboolean
bayes_classify_callback (gpointer key, gpointer value, gpointer data)
{
	rspamd_token_t *node = value;
	struct bayes_task_closure *cl = data;
	struct rspamd_classifier_runtime *rt;
	guint i;
	struct rspamd_token_result *res;
	guint64 spam_count = 0, ham_count = 0, total_count = 0;
	struct rspamd_task *task;
	double spam_prob, spam_freq, ham_freq, bayes_spam_prob, bayes_ham_prob,
		ham_prob, fw, w, norm_sum, norm_sub;

	rt = cl->rt;
	task = cl->task;

	for (i = rt->start_pos; i < rt->end_pos; i++) {
		res = &g_array_index (node->results, struct rspamd_token_result, i);

		if (res->value > 0) {
			if (res->st_runtime->st->is_spam) {
				spam_count += res->value;
			}
			else {
				ham_count += res->value;
			}
			total_count += res->value;
			res->st_runtime->total_hits += res->value;
		}
	}

	/* Probability for this token */
	if (total_count > 0) {
		spam_freq = ((double)spam_count / MAX (1., (double)rt->total_spam));
		ham_freq = ((double)ham_count / MAX (1., (double)rt->total_ham));
		spam_prob = spam_freq / (spam_freq + ham_freq);
		ham_prob = ham_freq / (spam_freq + ham_freq);
		fw = feature_weight[node->window_idx % G_N_ELEMENTS (feature_weight)];
		norm_sum = (spam_freq + ham_freq) * (spam_freq + ham_freq);
		norm_sub = (spam_freq - ham_freq) * (spam_freq - ham_freq);
		w = (norm_sub) / (norm_sum) *
				(fw * total_count) / (4.0 * (1.0 + fw * total_count));
		bayes_spam_prob = PROB_COMBINE (spam_prob, total_count, w, 0.5);
		norm_sub = (ham_freq - spam_freq) * (ham_freq - spam_freq);
		w = (norm_sub) / (norm_sum) *
				(fw * total_count) / (4.0 * (1.0 + fw * total_count));
		bayes_ham_prob = PROB_COMBINE (ham_prob, total_count, w, 0.5);
		rt->spam_prob += log (bayes_spam_prob);
		rt->ham_prob += log (bayes_ham_prob);
		res->cl_runtime->processed_tokens ++;

		msg_debug_bayes ("token: weight: %f, total_count: %L, "
				"spam_count: %L, ham_count: %L,"
				"spam_prob: %.3f, ham_prob: %.3f, "
				"bayes_spam_prob: %.3f, bayes_ham_prob: %.3f, "
				"current spam prob: %.3f, current ham prob: %.3f",
				fw, total_count, spam_count, ham_count,
				spam_prob, ham_prob,
				bayes_spam_prob, bayes_ham_prob,
				rt->spam_prob, rt->ham_prob);
	}

	return FALSE;
}

/*
 * A(x - 0.5)^4 + B(x - 0.5)^3 + C(x - 0.5)^2 + D(x - 0.5)
 * A = 32,
 * B = -6
 * C = -7
 * D = 3
 * y = 32(x - 0.5)^4 - 6(x - 0.5)^3 - 7(x - 0.5)^2 + 3(x - 0.5)
 */
static gdouble
bayes_normalize_prob (gdouble x)
{
	const gdouble a = 32, b = -6, c = -7, d = 3;
	gdouble xx, x2, x3, x4;

	xx = x - 0.5;
	x2 = xx * xx;
	x3 = x2 * xx;
	x4 = x3 * xx;

	return a*x4 + b*x3 + c*x2 + d*xx;
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
	struct rspamd_classifier_runtime *rt,
	struct rspamd_task *task)
{
	double final_prob, h, s;
	guint maxhits = 0;
	struct rspamd_statfile_runtime *st, *selected_st = NULL;
	GList *cur;
	char *sumbuf;
	struct bayes_task_closure cl;

	g_assert (ctx != NULL);
	g_assert (input != NULL);
	g_assert (rt != NULL);
	g_assert (rt->end_pos > rt->start_pos);

	if (rt->stage == RSPAMD_STAT_STAGE_PRE) {
		cl.rt = rt;
		cl.task = task;
		g_tree_foreach (input, bayes_classify_callback, &cl);
	}
	else {
		h = 1 - inv_chi_square (task, rt->spam_prob, rt->processed_tokens);
		s = 1 - inv_chi_square (task, rt->ham_prob, rt->processed_tokens);

		if (isfinite (s) && isfinite (h)) {
			final_prob = (s + 1.0 - h) / 2.;
			msg_debug_bayes ("<%s> got ham prob %.2f -> %.2f and spam prob %.2f -> %.2f,"
					" %L tokens processed of %ud total tokens",
					task->message_id, rt->ham_prob, h, rt->spam_prob, s,
					rt->processed_tokens, g_tree_nnodes (input));
		}
		else {
			/*
			 * We have some overflow, hence we need to check which class
			 * is NaN
			 */
			if (isfinite (h)) {
				final_prob = 1.0;
				msg_debug_bayes ("<%s> spam class is overflowed, as we have no"
						" ham samples", task->message_id);
			}
			else if (isfinite (s)){
				final_prob = 0.0;
				msg_debug_bayes ("<%s> ham class is overflowed, as we have no"
						" spam samples", task->message_id);
			}
			else {
				final_prob = 0.5;
				msg_warn_bayes ("<%s> spam and ham classes are both overflowed",
						task->message_id);
			}
		}

		if (rt->processed_tokens > 0 && fabs (final_prob - 0.5) > 0.05) {

			sumbuf = rspamd_mempool_alloc (task->task_pool, 32);
			cur = g_list_first (rt->st_runtime);

			while (cur) {
				st = (struct rspamd_statfile_runtime *)cur->data;

				if ((final_prob < 0.5 && !st->st->is_spam) ||
						(final_prob > 0.5 && st->st->is_spam)) {
					if (st->total_hits > maxhits) {
						maxhits = st->total_hits;
						selected_st = st;
					}
				}

				cur = g_list_next (cur);
			}

			if (selected_st == NULL) {
				msg_err_bayes (
					"unexpected classifier error: cannot select desired statfile, "
					"prob: %.4f", final_prob);
			}
			else {
				/* Correctly scale HAM */
				if (final_prob < 0.5) {
					final_prob = 1.0 - final_prob;
				}

				rspamd_snprintf (sumbuf, 32, "%.2f%%", final_prob * 100.);
				final_prob = bayes_normalize_prob (final_prob);

				cur = g_list_prepend (NULL, sumbuf);
				rspamd_task_insert_result (task,
						selected_st->st->symbol,
						final_prob,
						cur);
			}
		}
	}

	return TRUE;
}

static gboolean
bayes_learn_spam_callback (gpointer key, gpointer value, gpointer data)
{
	rspamd_token_t *node = value;
	struct rspamd_token_result *res;
	struct rspamd_classifier_runtime *rt = (struct rspamd_classifier_runtime *)data;
	guint i;


	for (i = rt->start_pos; i < rt->end_pos; i++) {
		res = &g_array_index (node->results, struct rspamd_token_result, i);

		if (res->st_runtime) {
			if (res->st_runtime->st->is_spam) {
				res->value ++;
			}
			else if (res->value > 0) {
				/* Unlearning */
				res->value --;
			}
		}
	}

	return FALSE;
}

static gboolean
bayes_learn_ham_callback (gpointer key, gpointer value, gpointer data)
{
	rspamd_token_t *node = value;
	struct rspamd_token_result *res;
	struct rspamd_classifier_runtime *rt = (struct rspamd_classifier_runtime *)data;
	guint i;


	for (i = rt->start_pos; i < rt->end_pos; i++) {
		res = &g_array_index (node->results, struct rspamd_token_result, i);

		if (res->st_runtime) {
			if (!res->st_runtime->st->is_spam) {
				res->value ++;
			}
			else if (res->value > 0) {
				res->value --;
			}
		}
	}

	return FALSE;
}

gboolean
bayes_learn_spam (struct classifier_ctx * ctx,
	GTree *input,
	struct rspamd_classifier_runtime *rt,
	struct rspamd_task *task,
	gboolean is_spam,
	GError **err)
{
	g_assert (ctx != NULL);
	g_assert (input != NULL);
	g_assert (rt != NULL);
	g_assert (rt->end_pos > rt->start_pos);

	if (is_spam) {
		g_tree_foreach (input, bayes_learn_spam_callback, rt);
	}
	else {
		g_tree_foreach (input, bayes_learn_ham_callback, rt);
	}


	return TRUE;
}
