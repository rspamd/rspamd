/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Bayesian classifier
 */
#include "classifiers.h"
#include "rspamd.h"
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
#define msg_debug_bayes(...)  rspamd_conditional_debug_fast (NULL, task->from_addr, \
        rspamd_bayes_log_id, "bayes", task->task_pool->tag.uid, \
        G_STRFUNC, \
        __VA_ARGS__)

INIT_LOG_MODULE_PUBLIC(bayes)

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
		/*
		 * e^x where x is large *NEGATIVE* number is OK, so we have a very strong
		 * confidence that inv-chi-square is close to zero
		 */
		msg_debug_bayes ("exp overflow");

		if (value < 0) {
			return 0;
		}
		else {
			return 1.0;
		}
	}

	sum = prob;

	msg_debug_bayes ("m: %f, probability: %g", m, prob);

	/*
	 * m is our confidence in class
	 * prob is e ^ x (small value since x is normally less than zero
	 * So we integrate over degrees of freedom and produce the total result
	 * from 1.0 (no confidence) to 0.0 (full confidence)
	 */
	for (i = 1; i < freedom_deg; i++) {
		prob *= m / (gdouble)i;
		sum += prob;
		msg_debug_bayes ("i=%d, probability: %g, sum: %g", i, prob, sum);
	}

	return MIN (1.0, sum);
}

struct bayes_task_closure {
	double ham_prob;
	double spam_prob;
	gdouble meta_skip_prob;
	guint64 processed_tokens;
	guint64 total_hits;
	guint64 text_tokens;
	struct rspamd_task *task;
};

/*
 * Mathematically we use pow(complexity, complexity), where complexity is the
 * window index
 */
static const double feature_weight[] = { 0, 3125, 256, 27, 1, 0, 0, 0 };

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
	guint spam_count = 0, ham_count = 0, total_count = 0;
	struct rspamd_statfile *st;
	struct rspamd_task *task;
	const gchar *token_type = "txt";
	double spam_prob, spam_freq, ham_freq, bayes_spam_prob, bayes_ham_prob,
		ham_prob, fw, w, val;

	task = cl->task;

#if 0
	if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_LUA_META) {
		/* Ignore lua metatokens for now */
		return;
	}
#endif

	if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_META && cl->meta_skip_prob > 0) {
		val = rspamd_random_double_fast ();

		if (val <= cl->meta_skip_prob) {
			if (tok->t1 && tok->t2) {
				msg_debug_bayes (
						"token(meta) %uL <%*s:%*s> probabilistically skipped",
						tok->data,
						(int) tok->t1->original.len, tok->t1->original.begin,
						(int) tok->t2->original.len, tok->t2->original.begin);
			}

			return;
		}
	}

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
	if (total_count >= ctx->cfg->min_token_hits) {
		spam_freq = ((double)spam_count / MAX (1., (double) ctx->spam_learns));
		ham_freq = ((double)ham_count / MAX (1., (double)ctx->ham_learns));
		spam_prob = spam_freq / (spam_freq + ham_freq);
		ham_prob = ham_freq / (spam_freq + ham_freq);

		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_UNIGRAM) {
			fw = 1.0;
		}
		else {
			fw = feature_weight[tok->window_idx %
					G_N_ELEMENTS (feature_weight)];
		}


		w = (fw * total_count) / (1.0 + fw * total_count);

		bayes_spam_prob = PROB_COMBINE (spam_prob, total_count, w, 0.5);

		if ((bayes_spam_prob > 0.5 && bayes_spam_prob < 0.5 + ctx->cfg->min_prob_strength) ||
			(bayes_spam_prob < 0.5 && bayes_spam_prob > 0.5 - ctx->cfg->min_prob_strength)) {
			msg_debug_bayes (
					"token %uL <%*s:%*s> skipped, probability not in range: %f",
					tok->data,
					(int) tok->t1->stemmed.len, tok->t1->stemmed.begin,
					(int) tok->t2->stemmed.len, tok->t2->stemmed.begin,
					bayes_spam_prob);

			return;
		}

		bayes_ham_prob = PROB_COMBINE (ham_prob, total_count, w, 0.5);

		cl->spam_prob += log (bayes_spam_prob);
		cl->ham_prob += log (bayes_ham_prob);
		cl->processed_tokens ++;

		if (!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_META)) {
			cl->text_tokens ++;
		}
		else {
			token_type = "meta";
		}

		if (tok->t1 && tok->t2) {
			msg_debug_bayes ("token(%s) %uL <%*s:%*s>: weight: %f, cf: %f, "
					"total_count: %ud, "
					"spam_count: %ud, ham_count: %ud,"
					"spam_prob: %.3f, ham_prob: %.3f, "
					"bayes_spam_prob: %.3f, bayes_ham_prob: %.3f, "
					"current spam probability: %.3f, current ham probability: %.3f",
					token_type,
					tok->data,
					(int) tok->t1->stemmed.len, tok->t1->stemmed.begin,
					(int) tok->t2->stemmed.len, tok->t2->stemmed.begin,
					fw, w, total_count, spam_count, ham_count,
					spam_prob, ham_prob,
					bayes_spam_prob, bayes_ham_prob,
					cl->spam_prob, cl->ham_prob);
		}
		else {
			msg_debug_bayes ("token(%s) %uL <?:?>: weight: %f, cf: %f, "
					"total_count: %ud, "
					"spam_count: %ud, ham_count: %ud,"
					"spam_prob: %.3f, ham_prob: %.3f, "
					"bayes_spam_prob: %.3f, bayes_ham_prob: %.3f, "
					"current spam probability: %.3f, current ham probability: %.3f",
					token_type,
					tok->data,
					fw, w, total_count, spam_count, ham_count,
					spam_prob, ham_prob,
					bayes_spam_prob, bayes_ham_prob,
					cl->spam_prob, cl->ham_prob);
		}
	}
}



gboolean
bayes_init (struct rspamd_config *cfg,
			struct ev_loop *ev_base,
			struct rspamd_classifier *cl)
{
	cl->cfg->flags |= RSPAMD_FLAG_CLASSIFIER_INTEGER;

	return TRUE;
}

void
bayes_fin (struct rspamd_classifier *cl)
{
}

gboolean
bayes_classify (struct rspamd_classifier * ctx,
		GPtrArray *tokens,
		struct rspamd_task *task)
{
	double final_prob, h, s, *pprob;
	gchar sumbuf[32];
	struct rspamd_statfile *st = NULL;
	struct bayes_task_closure cl;
	rspamd_token_t *tok;
	guint i, text_tokens = 0;
	gint id;

	g_assert (ctx != NULL);
	g_assert (tokens != NULL);

	memset (&cl, 0, sizeof (cl));
	cl.task = task;

	/* Check min learns */
	if (ctx->cfg->min_learns > 0) {
		if (ctx->ham_learns < ctx->cfg->min_learns) {
			msg_info_task ("not classified as ham. The ham class needs more "
					"training samples. Currently: %ul; minimum %ud required",
					ctx->ham_learns, ctx->cfg->min_learns);

			return TRUE;
		}
		if (ctx->spam_learns < ctx->cfg->min_learns) {
			msg_info_task ("not classified as spam. The spam class needs more "
					"training samples. Currently: %ul; minimum %ud required",
					ctx->spam_learns, ctx->cfg->min_learns);

			return TRUE;
		}
	}

	for (i = 0; i < tokens->len; i ++) {
		tok = g_ptr_array_index (tokens, i);
		if (!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_META)) {
			text_tokens ++;
		}
	}

	if (text_tokens == 0) {
		msg_info_task ("skipped classification as there are no text tokens. "
				"Total tokens: %ud",
				tokens->len);

		return TRUE;
	}

	/*
	 * Skip some metatokens if we don't have enough text tokens
	 */
	if (text_tokens > tokens->len - text_tokens) {
		cl.meta_skip_prob = 0.0;
	}
	else {
		cl.meta_skip_prob = 1.0 - text_tokens / tokens->len;
	}

	for (i = 0; i < tokens->len; i ++) {
		tok = g_ptr_array_index (tokens, i);

		bayes_classify_token (ctx, tok, &cl);
	}

	if (cl.processed_tokens == 0) {
		msg_info_bayes ("no tokens found in bayes database "
				  "(%ud total tokens, %ud text tokens), ignore stats",
				tokens->len, text_tokens);

		return TRUE;
	}

	if (ctx->cfg->min_tokens > 0 &&
		cl.text_tokens < (gint)(ctx->cfg->min_tokens * 0.1)) {
		msg_info_bayes ("ignore bayes probability since we have "
						"found too few text tokens: %uL (of %ud checked), "
						"at least %d required",
						cl.text_tokens,
						text_tokens,
						(gint)(ctx->cfg->min_tokens * 0.1));

		return TRUE;
	}

	if (cl.spam_prob > -300 && cl.ham_prob > -300) {
		/* Fisher value is low enough to apply inv_chi_square */
		h = 1 - inv_chi_square (task, cl.spam_prob, cl.processed_tokens);
		s = 1 - inv_chi_square (task, cl.ham_prob, cl.processed_tokens);
	}
	else {
		/* Use naive method */
		if (cl.spam_prob < cl.ham_prob) {
			h = (1.0 - exp(cl.spam_prob - cl.ham_prob)) /
					(1.0 + exp(cl.spam_prob - cl.ham_prob));
			s = 1.0 - h;
		}
		else {
			s = (1.0 - exp(cl.ham_prob - cl.spam_prob)) /
				(1.0 + exp(cl.ham_prob - cl.spam_prob));
			h = 1.0 - s;
		}
	}

	if (isfinite (s) && isfinite (h)) {
		final_prob = (s + 1.0 - h) / 2.;
		msg_debug_bayes (
				"got ham probability %.2f -> %.2f and spam probability %.2f -> %.2f,"
				" %L tokens processed of %ud total tokens;"
				" %uL text tokens found of %ud text tokens)",
				cl.ham_prob,
				h,
				cl.spam_prob,
				s,
				cl.processed_tokens,
				tokens->len,
				cl.text_tokens,
				text_tokens);
	}
	else {
		/*
		 * We have some overflow, hence we need to check which class
		 * is NaN
		 */
		if (isfinite (h)) {
			final_prob = 1.0;
			msg_debug_bayes ("spam class is full: no"
					" ham samples");
		}
		else if (isfinite (s)) {
			final_prob = 0.0;
			msg_debug_bayes ("ham class is full: no"
					" spam samples");
		}
		else {
			final_prob = 0.5;
			msg_warn_bayes ("spam and ham classes are both full");
		}
	}

	pprob = rspamd_mempool_alloc (task->task_pool, sizeof (*pprob));
	*pprob = final_prob;
	rspamd_mempool_set_variable (task->task_pool, "bayes_prob", pprob, NULL);

	if (cl.processed_tokens > 0 && fabs (final_prob - 0.5) > 0.05) {
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

		/*
		 * Bayes p is from 0.5 to 1.0, but confidence is from 0 to 1, so
		 * we need to rescale it to display correctly
		 */
		rspamd_snprintf (sumbuf, sizeof (sumbuf), "%.2f%%",
				(final_prob - 0.5) * 200.);
		final_prob = rspamd_normalize_probability (final_prob, 0.5);
		g_assert (st != NULL);

		if (final_prob > 1 || final_prob < 0) {
			msg_err_bayes ("internal error: probability %f is outside of the "
				  "allowed range [0..1]", final_prob);

			if (final_prob > 1) {
				final_prob = 1.0;
			}
			else {
				final_prob = 0.0;
			}
		}

		rspamd_task_insert_result (task,
				st->stcf->symbol,
				final_prob,
				sumbuf);
	}

	return TRUE;
}

gboolean
bayes_learn_spam (struct rspamd_classifier * ctx,
		GPtrArray *tokens,
		struct rspamd_task *task,
		gboolean is_spam,
		gboolean unlearn,
		GError **err)
{
	guint i, j, total_cnt, spam_cnt, ham_cnt;
	gint id;
	struct rspamd_statfile *st;
	rspamd_token_t *tok;
	gboolean incrementing;

	g_assert (ctx != NULL);
	g_assert (tokens != NULL);

	incrementing = ctx->cfg->flags & RSPAMD_FLAG_CLASSIFIER_INCREMENTING_BACKEND;

	for (i = 0; i < tokens->len; i++) {
		total_cnt = 0;
		spam_cnt = 0;
		ham_cnt = 0;
		tok = g_ptr_array_index (tokens, i);

		for (j = 0; j < ctx->statfiles_ids->len; j++) {
			id = g_array_index (ctx->statfiles_ids, gint, j);
			st = g_ptr_array_index (ctx->ctx->statfiles, id);
			g_assert (st != NULL);

			if (!!st->stcf->is_spam == !!is_spam) {
				if (incrementing) {
					tok->values[id] = 1;
				}
				else {
					tok->values[id]++;
				}

				total_cnt += tok->values[id];

				if (st->stcf->is_spam) {
					spam_cnt += tok->values[id];
				}
				else {
					ham_cnt += tok->values[id];
				}
			}
			else {
				if (tok->values[id] > 0 && unlearn) {
					/* Unlearning */
					if (incrementing) {
						tok->values[id] = -1;
					}
					else {
						tok->values[id]--;
					}

					if (st->stcf->is_spam) {
						spam_cnt += tok->values[id];
					}
					else {
						ham_cnt += tok->values[id];
					}
					total_cnt += tok->values[id];
				}
				else if (incrementing) {
					tok->values[id] = 0;
				}
			}
		}

		if (tok->t1 && tok->t2) {
			msg_debug_bayes ("token %uL <%*s:%*s>: window: %d, total_count: %d, "
					"spam_count: %d, ham_count: %d",
					tok->data,
					(int) tok->t1->stemmed.len, tok->t1->stemmed.begin,
					(int) tok->t2->stemmed.len, tok->t2->stemmed.begin,
					tok->window_idx, total_cnt, spam_cnt, ham_cnt);
		}
		else {
			msg_debug_bayes ("token %uL <?:?>: window: %d, total_count: %d, "
					"spam_count: %d, ham_count: %d",
					tok->data,
					tok->window_idx, total_cnt, spam_cnt, ham_cnt);
		}
	}

	return TRUE;
}
