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
	double ham_prob;
	double spam_prob;
	guint64 processed_tokens;
	guint64 total_hits;
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
static void
bayes_classify_token (struct rspamd_classifier *ctx,
		rspamd_token_t *tok, struct bayes_task_closure *cl)
{
	guint i;
	gint id;
	guint64 spam_count = 0, ham_count = 0, total_count = 0;
	struct rspamd_statfile *st;
	struct rspamd_task *task;
	double spam_prob, spam_freq, ham_freq, bayes_spam_prob, bayes_ham_prob,
		ham_prob, fw, w, norm_sum, norm_sub, val;

	task = cl->task;

	for (i = 0; i < ctx->statfiles_ids->len; i++) {
		id = g_array_index (ctx->statfiles_ids, gint, i);
		st = g_ptr_array_index (ctx->ctx->statfiles, id);
		g_assert (st != NULL);
		val = tok->values[id];

		if (val > 0) {
			if (st->stcf->is_spam) {
				spam_count += val;
			}
			else {
				ham_count += val;
			}

			total_count += val;
			cl->total_hits += val;
		}
	}

	/* Probability for this token */
	if (total_count > 0) {
		spam_freq = ((double)spam_count / MAX (1., (double) ctx->spam_learns));
		ham_freq = ((double)ham_count / MAX (1., (double)ctx->ham_learns));
		spam_prob = spam_freq / (spam_freq + ham_freq);
		ham_prob = ham_freq / (spam_freq + ham_freq);
		fw = feature_weight[tok->window_idx % G_N_ELEMENTS (feature_weight)];
		norm_sum = (spam_freq + ham_freq) * (spam_freq + ham_freq);
		norm_sub = (spam_freq - ham_freq) * (spam_freq - ham_freq);
		w = (norm_sub) / (norm_sum) *
				(fw * total_count) / (4.0 * (1.0 + fw * total_count));
		bayes_spam_prob = PROB_COMBINE (spam_prob, total_count, w, 0.5);
		norm_sub = (ham_freq - spam_freq) * (ham_freq - spam_freq);
		w = (norm_sub) / (norm_sum) *
				(fw * total_count) / (4.0 * (1.0 + fw * total_count));
		bayes_ham_prob = PROB_COMBINE (ham_prob, total_count, w, 0.5);
		cl->spam_prob += log (bayes_spam_prob);
		cl->ham_prob += log (bayes_ham_prob);
		cl->processed_tokens ++;

		msg_debug_bayes ("token: weight: %f, total_count: %L, "
				"spam_count: %L, ham_count: %L,"
				"spam_prob: %.3f, ham_prob: %.3f, "
				"bayes_spam_prob: %.3f, bayes_ham_prob: %.3f, "
				"current spam prob: %.3f, current ham prob: %.3f",
				fw, total_count, spam_count, ham_count,
				spam_prob, ham_prob,
				bayes_spam_prob, bayes_ham_prob,
				cl->spam_prob, cl->ham_prob);
	}
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

void
bayes_init (rspamd_mempool_t *pool, struct rspamd_classifier *cl)
{
}

gboolean
bayes_classify (struct rspamd_classifier * ctx,
		GPtrArray *tokens,
		struct rspamd_task *task)
{
	double final_prob, h, s;
	char *sumbuf;
	struct rspamd_statfile *st = NULL;
	struct bayes_task_closure cl;
	rspamd_token_t *tok;
	guint i;
	gint id;
	GList *cur;

	g_assert (ctx != NULL);
	g_assert (tokens != NULL);

	memset (&cl, 0, sizeof (cl));
	cl.task = task;

	for (i = 0; i < tokens->len; i ++) {
		tok = g_ptr_array_index (tokens, i);

		bayes_classify_token (ctx, tok, &cl);
	}

	h = 1 - inv_chi_square (task, cl.spam_prob, cl.processed_tokens);
	s = 1 - inv_chi_square (task, cl.ham_prob, cl.processed_tokens);

	if (isfinite (s) && isfinite (h)) {
		final_prob = (s + 1.0 - h) / 2.;
		msg_debug_bayes (
				"<%s> got ham prob %.2f -> %.2f and spam prob %.2f -> %.2f,"
						" %L tokens processed of %ud total tokens",
				task->message_id,
				cl.ham_prob,
				h,
				cl.spam_prob,
				s,
				cl.processed_tokens,
				tokens->len);
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
		else if (isfinite (s)) {
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

	if (cl.processed_tokens > 0 && fabs (final_prob - 0.5) > 0.05) {

		sumbuf = rspamd_mempool_alloc (task->task_pool, 32);

		/* Now we can have exactly one HAM and exactly one SPAM statfiles per classifier */
		for (i = 0; i < ctx->statfiles_ids->len; i++) {
			id = g_array_index (ctx->statfiles_ids, gint, i);
			st = g_ptr_array_index (ctx->ctx->statfiles, id);

			if (final_prob > 0.5 && st->stcf->is_spam) {
				break;
			}
			else if (final_prob < 0.5 && !st->stcf->is_spam) {
				break;
			}
		}

		/* Correctly scale HAM */
		if (final_prob < 0.5) {
			final_prob = 1.0 - final_prob;
		}

		rspamd_snprintf (sumbuf, 32, "%.2f%%", final_prob * 100.);
		final_prob = bayes_normalize_prob (final_prob);
		g_assert (st != NULL);
		cur = g_list_prepend (NULL, sumbuf);
		rspamd_task_insert_result (task,
				st->stcf->symbol,
				final_prob,
				cur);
	}

	return TRUE;
}

gboolean
bayes_learn_spam (struct rspamd_classifier * ctx,
		GPtrArray *tokens,
		struct rspamd_task *task,
		gboolean is_spam,
		GError **err)
{
	guint i, j;
	gint id;
	struct rspamd_statfile *st;
	rspamd_token_t *tok;

	g_assert (ctx != NULL);
	g_assert (tokens != NULL);

	for (i = 0; i < tokens->len; i++) {
		tok = g_ptr_array_index (tokens, i);

		for (j = 0; j < ctx->statfiles_ids->len; j++) {
			id = g_array_index (ctx->statfiles_ids, gint, j);
			st = g_ptr_array_index (ctx->ctx->statfiles, id);
			g_assert (st != NULL);

			if (is_spam) {
				if (st->stcf->is_spam) {
					tok->values[id]++;
				}
				else if (tok->values[id] > 0) {
					/* Unlearning */
					tok->values[id]--;
				}
			}
			else {
				if (!st->stcf->is_spam) {
					tok->values[id]++;
				}
				else if (tok->values[id] > 0) {
					/* Unlearning */
					tok->values[id]--;
				}
			}
		}
	}

	return TRUE;
}
