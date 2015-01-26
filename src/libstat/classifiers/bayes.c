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
	rspamd_token_t *node = value;
	struct rspamd_classifier_runtime *rt = (struct rspamd_classifier_runtime *)data;
	guint i;
	struct rspamd_token_result *res;
	guint64 spam_count = 0, ham_count = 0, total_count = 0;
	double spam_prob, spam_freq, ham_freq, bayes_spam_prob;

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
		}
	}

	/* Probability for this token */
	if (total_count > 0) {
		spam_freq = ((double)spam_count / MAX (1., (double)rt->total_spam));
		ham_freq = ((double)ham_count / MAX (1., (double)rt->total_ham));
		spam_prob = spam_freq / (spam_freq + ham_freq);
		bayes_spam_prob = (0.5 + spam_prob * total_count) / (1. + total_count);
		rt->spam_prob += log (bayes_spam_prob);
		rt->ham_prob += log (1. - bayes_spam_prob);
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
	struct rspamd_classifier_runtime *rt,
	struct rspamd_task *task)
{
	double final_prob, h, s;
	guint maxhits = 0;
	struct rspamd_statfile_runtime *st, *selected_st = NULL;
	GList *cur;
	char *sumbuf;

	g_assert (ctx != NULL);
	g_assert (input != NULL);
	g_assert (rt != NULL);
	g_assert (rt->end_pos > rt->start_pos);

	g_tree_foreach (input, bayes_classify_callback, &rt);

	if (rt->spam_prob == 0) {
		final_prob = 0;
	}
	else {
		h = 1 - inv_chi_square (-2. * rt->spam_prob,
				2 * rt->processed_tokens);
		s = 1 - inv_chi_square (-2. * rt->ham_prob,
				2 * rt->processed_tokens);
		final_prob = (s + 1 - h) / 2.;
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
				selected_st->st->symbol,
				final_prob,
				cur);
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

		if (res->st_runtime->st->is_spam) {
			res->value ++;
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

		if (!res->st_runtime->st->is_spam) {
			res->value ++;
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
