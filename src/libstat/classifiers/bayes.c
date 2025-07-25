/*
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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

#define msg_err_bayes(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,              \
													   "bayes", task->task_pool->tag.uid, \
													   RSPAMD_LOG_FUNC,                   \
													   __VA_ARGS__)
#define msg_warn_bayes(...) rspamd_default_log_function(G_LOG_LEVEL_WARNING,               \
														"bayes", task->task_pool->tag.uid, \
														RSPAMD_LOG_FUNC,                   \
														__VA_ARGS__)
#define msg_info_bayes(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,                  \
														"bayes", task->task_pool->tag.uid, \
														RSPAMD_LOG_FUNC,                   \
														__VA_ARGS__)

INIT_LOG_MODULE_PUBLIC(bayes)

static inline GQuark
bayes_error_quark(void)
{
	return g_quark_from_static_string("bayes-error");
}

/**
 * Returns probability of chisquare > value with specified number of freedom
 * degrees
 * @param value value to test
 * @param freedom_deg number of degrees of freedom
 * @return
 */
static double
inv_chi_square(struct rspamd_task *task, double value, int freedom_deg)
{
	double prob, sum, m;
	int i;

	errno = 0;
	m = -value;
	prob = exp(value);

	if (errno == ERANGE) {
		/*
		 * e^x where x is large *NEGATIVE* number is OK, so we have a very strong
		 * confidence that inv-chi-square is close to zero
		 */
		msg_debug_bayes("exp overflow");

		if (value < 0) {
			return 0;
		}
		else {
			return 1.0;
		}
	}

	sum = prob;

	msg_debug_bayes("m: %f, probability: %g", m, prob);

	/*
	 * m is our confidence in class
	 * prob is e ^ x (small value since x is normally less than zero
	 * So we integrate over degrees of freedom and produce the total result
	 * from 1.0 (no confidence) to 0.0 (full confidence)
	 */
	for (i = 1; i < freedom_deg; i++) {
		prob *= m / (double) i;
		sum += prob;
		msg_debug_bayes("i=%d, probability: %g, sum: %g", i, prob, sum);
	}

	return MIN(1.0, sum);
}

struct bayes_task_closure {
	double ham_prob;  /* Kept for binary compatibility */
	double spam_prob; /* Kept for binary compatibility */
	double meta_skip_prob;
	uint64_t processed_tokens;
	uint64_t total_hits;
	uint64_t text_tokens;
	struct rspamd_task *task;
};

/* Multi-class classification closure */
struct bayes_multiclass_closure {
	double *class_log_probs;  /* Array of log probabilities for each class */
	uint64_t *class_learns;   /* Learning counts for each class */
	char **class_names;       /* Array of class names */
	unsigned int num_classes; /* Number of classes */
	double meta_skip_prob;
	uint64_t processed_tokens;
	uint64_t total_hits;
	uint64_t text_tokens;
	struct rspamd_task *task;
	struct rspamd_classifier_config *cfg;
};

/*
 * Mathematically we use pow(complexity, complexity), where complexity is the
 * window index
 */
static const double feature_weight[] = {0, 3125, 256, 27, 1, 0, 0, 0};

#define PROB_COMBINE(prob, cnt, weight, assumed) (((weight) * (assumed) + (cnt) * (prob)) / ((weight) + (cnt)))
/*
 * In this callback we calculate local probabilities for tokens
 */
static void
bayes_classify_token(struct rspamd_classifier *ctx,
					 rspamd_token_t *tok, struct bayes_task_closure *cl)
{
	unsigned int i;
	int id;
	unsigned int spam_count = 0, ham_count = 0, total_count = 0;
	struct rspamd_statfile *st;
	struct rspamd_task *task;
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
		val = rspamd_random_double_fast();

		if (val <= cl->meta_skip_prob) {
			if (tok->t1 && tok->t2) {
				msg_debug_bayes(
					"token(meta) %uL <%*s:%*s> probabilistically skipped",
					tok->data,
					(int) tok->t1->original.len, tok->t1->original.begin,
					(int) tok->t2->original.len, tok->t2->original.begin);
			}

			return;
		}
	}

	for (i = 0; i < ctx->statfiles_ids->len; i++) {
		id = g_array_index(ctx->statfiles_ids, int, i);
		st = g_ptr_array_index(ctx->ctx->statfiles, id);
		g_assert(st != NULL);
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
		spam_freq = ((double) spam_count / MAX(1., (double) ctx->spam_learns));
		ham_freq = ((double) ham_count / MAX(1., (double) ctx->ham_learns));
		spam_prob = spam_freq / (spam_freq + ham_freq);
		ham_prob = ham_freq / (spam_freq + ham_freq);

		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_UNIGRAM) {
			fw = 1.0;
		}
		else {
			fw = feature_weight[tok->window_idx %
								G_N_ELEMENTS(feature_weight)];
		}


		w = (fw * total_count) / (1.0 + fw * total_count);

		bayes_spam_prob = PROB_COMBINE(spam_prob, total_count, w, 0.5);

		if ((bayes_spam_prob > 0.5 && bayes_spam_prob < 0.5 + ctx->cfg->min_prob_strength) ||
			(bayes_spam_prob < 0.5 && bayes_spam_prob > 0.5 - ctx->cfg->min_prob_strength)) {
			msg_debug_bayes(
				"token %uL <%*s:%*s> skipped, probability not in range: %f",
				tok->data,
				(int) tok->t1->stemmed.len, tok->t1->stemmed.begin,
				(int) tok->t2->stemmed.len, tok->t2->stemmed.begin,
				bayes_spam_prob);

			return;
		}

		bayes_ham_prob = PROB_COMBINE(ham_prob, total_count, w, 0.5);

		cl->spam_prob += log(bayes_spam_prob);
		cl->ham_prob += log(bayes_ham_prob);
		cl->processed_tokens++;

		if (!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_META)) {
			cl->text_tokens++;
		}
	}
}

/*
 * Multinomial token classification for multi-class Bayes
 */
static void
bayes_classify_token_multiclass(struct rspamd_classifier *ctx,
								rspamd_token_t *tok,
								struct bayes_multiclass_closure *cl)
{
	unsigned int i, j;
	int id;
	struct rspamd_statfile *st;
	struct rspamd_task *task;
	double val, fw, w;
	guint64 *class_counts;
	guint64 total_count = 0;

	task = cl->task;

	/* Skip meta tokens probabilistically if configured */
	if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_META && cl->meta_skip_prob > 0) {
		val = rspamd_random_double_fast();
		if (val <= cl->meta_skip_prob) {
			return;
		}
	}

	/* Allocate array for class counts */
	class_counts = g_alloca(cl->num_classes * sizeof(guint64));
	memset(class_counts, 0, cl->num_classes * sizeof(guint64));

	/* Collect counts for each class */
	for (i = 0; i < ctx->statfiles_ids->len; i++) {
		id = g_array_index(ctx->statfiles_ids, int, i);
		st = g_ptr_array_index(ctx->ctx->statfiles, id);
		g_assert(st != NULL);
		val = tok->values[id];

		if (val > 0) {
			/* Direct O(1) class index lookup instead of O(N) string comparison */
			if (st->stcf->class_name && st->stcf->class_index < cl->num_classes) {
				unsigned int class_idx = st->stcf->class_index;
				class_counts[class_idx] += val;
				total_count += val;
				cl->total_hits += val;
			}
			else {
				msg_debug_bayes("invalid class_index %ud >= %ud for statfile %s",
								st->stcf->class_index, cl->num_classes, st->stcf->symbol);
			}
		}
	}

	/* Calculate multinomial probability for this token */
	if (total_count >= ctx->cfg->min_token_hits) {
		/* Feature weight calculation */
		if (tok->flags & RSPAMD_STAT_TOKEN_FLAG_UNIGRAM) {
			fw = 1.0;
		}
		else {
			fw = feature_weight[tok->window_idx % G_N_ELEMENTS(feature_weight)];
		}

		w = (fw * total_count) / (1.0 + fw * total_count);

		/* Apply multinomial model for each class */
		for (j = 0; j < cl->num_classes; j++) {
			double class_freq = (double) class_counts[j] / MAX(1.0, (double) cl->class_learns[j]);
			double class_prob = PROB_COMBINE(class_freq, total_count, w, 1.0 / cl->num_classes);

			/* Skip probabilities too close to uniform (1/num_classes) */
			double uniform_prior = 1.0 / cl->num_classes;
			if (fabs(class_prob - uniform_prior) < ctx->cfg->min_prob_strength) {
				continue;
			}

			cl->class_log_probs[j] += log(class_prob);
		}

		cl->processed_tokens++;
		if (!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_META)) {
			cl->text_tokens++;
		}

		/* Per-token debug logging removed to reduce verbosity */
	}
}

/*
 * Multinomial Bayes classification with Fisher confidence
 */
static gboolean
bayes_classify_multiclass(struct rspamd_classifier *ctx,
						  GPtrArray *tokens,
						  struct rspamd_task *task)
{
	struct bayes_multiclass_closure cl;
	rspamd_token_t *tok;
	unsigned int i, j, text_tokens = 0;
	int id;
	struct rspamd_statfile *st;
	rspamd_multiclass_result_t *result;
	double *normalized_probs;
	double max_log_prob = -INFINITY;
	unsigned int winning_class_idx = 0;
	double confidence;

	g_assert(ctx != NULL);
	g_assert(tokens != NULL);

	/* Initialize multi-class closure */
	memset(&cl, 0, sizeof(cl));
	cl.task = task;
	cl.cfg = ctx->cfg;

	/* Get class information from classifier config */
	if (!ctx->cfg->class_names) {
		msg_debug_bayes("no class_names array in classifier config");
		return TRUE; /* Fall back to binary mode */
	}
	if (ctx->cfg->class_names->len < 2) {
		msg_debug_bayes("insufficient classes: %ud < 2", (unsigned int) ctx->cfg->class_names->len);
		return TRUE; /* Fall back to binary mode */
	}
	if (!ctx->cfg->class_names->pdata) {
		msg_debug_bayes("class_names->pdata is NULL");
		return TRUE; /* Fall back to binary mode */
	}

	cl.num_classes = ctx->cfg->class_names->len;
	cl.class_names = (char **) ctx->cfg->class_names->pdata;

	/* Debug: verify class names are accessible */
	msg_debug_bayes("multiclass setup: ctx->cfg->class_names=%p, len=%ud, pdata=%p",
					ctx->cfg->class_names, (unsigned int) ctx->cfg->class_names->len, ctx->cfg->class_names->pdata);
	msg_debug_bayes("multiclass setup: cl.num_classes=%ud, cl.class_names=%p",
					cl.num_classes, cl.class_names);
	cl.class_log_probs = g_alloca(cl.num_classes * sizeof(double));
	cl.class_learns = g_alloca(cl.num_classes * sizeof(uint64_t));

	/* Initialize probabilities and get learning counts */
	for (i = 0; i < cl.num_classes; i++) {
		cl.class_log_probs[i] = 0.0;
		cl.class_learns[i] = 0;
	}

	/* Collect learning counts for each class */
	for (i = 0; i < ctx->statfiles_ids->len; i++) {
		id = g_array_index(ctx->statfiles_ids, int, i);
		st = g_ptr_array_index(ctx->ctx->statfiles, id);
		g_assert(st != NULL);

		for (j = 0; j < cl.num_classes; j++) {
			if (st->stcf->class_name &&
				strcmp(st->stcf->class_name, cl.class_names[j]) == 0) {
				cl.class_learns[j] += st->backend->total_learns(task,
																g_ptr_array_index(task->stat_runtimes, id), ctx->ctx);
				break;
			}
		}
	}

	/* Check minimum learns requirement */
	if (ctx->cfg->min_learns > 0) {
		for (i = 0; i < cl.num_classes; i++) {
			if (cl.class_learns[i] < ctx->cfg->min_learns) {
				msg_info_task("not classified as %s. The class needs more "
							  "training samples. Currently: %uL; minimum %ud required",
							  cl.class_names[i], cl.class_learns[i], ctx->cfg->min_learns);
				return TRUE;
			}
		}
	}

	/* Count text tokens */
	for (i = 0; i < tokens->len; i++) {
		tok = g_ptr_array_index(tokens, i);
		if (!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_META)) {
			text_tokens++;
		}
	}

	if (text_tokens == 0) {
		msg_info_task("skipped classification as there are no text tokens. "
					  "Total tokens: %ud",
					  tokens->len);
		return TRUE;
	}

	/* Set meta token skip probability */
	if (text_tokens > tokens->len - text_tokens) {
		cl.meta_skip_prob = 0.0;
	}
	else {
		cl.meta_skip_prob = 1.0 - (double) text_tokens / tokens->len;
	}

	/* Process all tokens */
	for (i = 0; i < tokens->len; i++) {
		tok = g_ptr_array_index(tokens, i);
		bayes_classify_token_multiclass(ctx, tok, &cl);
	}

	if (cl.processed_tokens == 0) {
		/* Debug: check why no tokens were processed */
		msg_debug_bayes("examining token values for debugging:");
		for (i = 0; i < MIN(tokens->len, 10); i++) { /* Check first 10 tokens */
			tok = g_ptr_array_index(tokens, i);
			for (j = 0; j < ctx->statfiles_ids->len; j++) {
				id = g_array_index(ctx->statfiles_ids, int, j);
				if (tok->values[id] > 0) {
					struct rspamd_statfile *st = g_ptr_array_index(ctx->ctx->statfiles, id);
					msg_debug_bayes("token %ud: values[%d] = %.2f (class=%s, symbol=%s)",
									i, id, tok->values[id],
									st->stcf->class_name ? st->stcf->class_name : "unknown",
									st->stcf->symbol);
				}
			}
		}

		msg_info_bayes("no tokens found in bayes database "
					   "(%ud total tokens, %ud text tokens), ignore stats",
					   tokens->len, text_tokens);
		return TRUE;
	}

	if (ctx->cfg->min_tokens > 0 &&
		cl.text_tokens < (int) (ctx->cfg->min_tokens * 0.1)) {
		msg_info_bayes("ignore bayes probability since we have "
					   "found too few text tokens: %uL (of %ud checked), "
					   "at least %d required",
					   cl.text_tokens, text_tokens,
					   (int) (ctx->cfg->min_tokens * 0.1));
		return TRUE;
	}

	/* Normalize probabilities using softmax */
	normalized_probs = g_alloca(cl.num_classes * sizeof(double));

	/* Find maximum for numerical stability */
	for (i = 0; i < cl.num_classes; i++) {
		if (cl.class_log_probs[i] > max_log_prob) {
			max_log_prob = cl.class_log_probs[i];
			winning_class_idx = i;
		}
	}

	/* Apply softmax normalization */
	double sum_exp = 0.0;
	for (i = 0; i < cl.num_classes; i++) {
		normalized_probs[i] = exp(cl.class_log_probs[i] - max_log_prob);
		sum_exp += normalized_probs[i];
	}

	if (sum_exp > 0) {
		for (i = 0; i < cl.num_classes; i++) {
			normalized_probs[i] /= sum_exp;
		}
	}
	else {
		/* Fallback to uniform distribution */
		for (i = 0; i < cl.num_classes; i++) {
			normalized_probs[i] = 1.0 / cl.num_classes;
		}
	}

	/* Calculate confidence using Fisher method for the winning class */
	if (max_log_prob > -300) {
		confidence = 1.0 - inv_chi_square(task, max_log_prob, cl.processed_tokens);
	}
	else {
		confidence = normalized_probs[winning_class_idx];
	}

	/* Create and store multiclass result */
	result = g_new0(rspamd_multiclass_result_t, 1);
	result->class_names = g_new(char *, cl.num_classes);
	result->probabilities = g_new(double, cl.num_classes);
	result->num_classes = cl.num_classes;
	result->winning_class = cl.class_names[winning_class_idx]; /* Reference, not copy */
	result->confidence = confidence;

	for (i = 0; i < cl.num_classes; i++) {
		result->class_names[i] = g_strdup(cl.class_names[i]);
		result->probabilities[i] = normalized_probs[i];
	}

	rspamd_task_set_multiclass_result(task, result);

	/* Insert symbol for winning class if confidence is significant */
	if (confidence > 0.05) {
		char sumbuf[32];
		double final_prob = rspamd_normalize_probability(confidence, 0.5);

		rspamd_snprintf(sumbuf, sizeof(sumbuf), "%.2f%%", confidence * 100.0);

		/* Find the statfile for the winning class to get the symbol */
		for (i = 0; i < ctx->statfiles_ids->len; i++) {
			id = g_array_index(ctx->statfiles_ids, int, i);
			st = g_ptr_array_index(ctx->ctx->statfiles, id);

			if (st->stcf->class_name &&
				strcmp(st->stcf->class_name, cl.class_names[winning_class_idx]) == 0) {
				rspamd_task_insert_result(task, st->stcf->symbol, final_prob, sumbuf);
				break;
			}
		}

		msg_debug_bayes("multiclass classification: winning class '%s' with "
						"probability %.3f, confidence %.3f, %uL tokens processed",
						cl.class_names[winning_class_idx],
						normalized_probs[winning_class_idx],
						confidence, cl.processed_tokens);
	}

	return TRUE;
}


gboolean
bayes_init(struct rspamd_config *cfg,
		   struct ev_loop *ev_base,
		   struct rspamd_classifier *cl)
{
	cl->cfg->flags |= RSPAMD_FLAG_CLASSIFIER_INTEGER;

	return TRUE;
}

void bayes_fin(struct rspamd_classifier *cl)
{
}

gboolean
bayes_classify(struct rspamd_classifier *ctx,
			   GPtrArray *tokens,
			   struct rspamd_task *task)
{
	double final_prob, h, s, *pprob;
	char sumbuf[32];
	struct rspamd_statfile *st = NULL;
	struct bayes_task_closure cl;
	rspamd_token_t *tok;
	unsigned int i, text_tokens = 0;
	int id;

	g_assert(ctx != NULL);
	g_assert(tokens != NULL);

	/* Check if this is a multi-class classifier */
	msg_debug_bayes("classification check: class_names=%p, len=%uz",
					ctx->cfg->class_names,
					ctx->cfg->class_names ? ctx->cfg->class_names->len : 0);

	if (ctx->cfg->class_names && ctx->cfg->class_names->len >= 2) {
		/* Verify that at least one statfile has class_name set (indicating new multi-class config) */
		gboolean has_class_names = FALSE;
		for (i = 0; i < ctx->statfiles_ids->len; i++) {
			int id = g_array_index(ctx->statfiles_ids, int, i);
			struct rspamd_statfile *st = g_ptr_array_index(ctx->ctx->statfiles, id);
			msg_debug_bayes("checking statfile %s: class_name=%s, is_spam_converted=%s",
							st->stcf->symbol,
							st->stcf->class_name ? st->stcf->class_name : "NULL",
							st->stcf->is_spam_converted ? "true" : "false");
			if (st->stcf->class_name) {
				has_class_names = TRUE;
			}
		}

		msg_debug_bayes("has_class_names=%s", has_class_names ? "true" : "false");

		if (has_class_names) {
			msg_debug_bayes("using multiclass classification with %ud classes",
							(unsigned int) ctx->cfg->class_names->len);
			return bayes_classify_multiclass(ctx, tokens, task);
		}
	}

	/* Fall back to binary classification */
	msg_debug_bayes("using binary classification");
	memset(&cl, 0, sizeof(cl));
	cl.task = task;

	/* Check min learns */
	if (ctx->cfg->min_learns > 0) {
		if (ctx->ham_learns < ctx->cfg->min_learns) {
			msg_info_task("not classified as ham. The ham class needs more "
						  "training samples. Currently: %uL; minimum %ud required",
						  ctx->ham_learns, ctx->cfg->min_learns);

			return TRUE;
		}
		if (ctx->spam_learns < ctx->cfg->min_learns) {
			msg_info_task("not classified as spam. The spam class needs more "
						  "training samples. Currently: %uL; minimum %ud required",
						  ctx->spam_learns, ctx->cfg->min_learns);

			return TRUE;
		}
	}

	for (i = 0; i < tokens->len; i++) {
		tok = g_ptr_array_index(tokens, i);
		if (!(tok->flags & RSPAMD_STAT_TOKEN_FLAG_META)) {
			text_tokens++;
		}
	}

	if (text_tokens == 0) {
		msg_info_task("skipped classification as there are no text tokens. "
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

	for (i = 0; i < tokens->len; i++) {
		tok = g_ptr_array_index(tokens, i);

		bayes_classify_token(ctx, tok, &cl);
	}

	if (cl.processed_tokens == 0) {
		msg_info_bayes("no tokens found in bayes database "
					   "(%ud total tokens, %ud text tokens), ignore stats",
					   tokens->len, text_tokens);

		return TRUE;
	}

	if (ctx->cfg->min_tokens > 0 &&
		cl.text_tokens < (int) (ctx->cfg->min_tokens * 0.1)) {
		msg_info_bayes("ignore bayes probability since we have "
					   "found too few text tokens: %uL (of %ud checked), "
					   "at least %d required",
					   cl.text_tokens,
					   text_tokens,
					   (int) (ctx->cfg->min_tokens * 0.1));

		return TRUE;
	}

	if (cl.spam_prob > -300 && cl.ham_prob > -300) {
		/* Fisher value is low enough to apply inv_chi_square */
		h = 1 - inv_chi_square(task, cl.spam_prob, cl.processed_tokens);
		s = 1 - inv_chi_square(task, cl.ham_prob, cl.processed_tokens);
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

	if (isfinite(s) && isfinite(h)) {
		final_prob = (s + 1.0 - h) / 2.;
		msg_debug_bayes(
			"got ham probability %.2f -> %.2f and spam probability %.2f -> %.2f,"
			" %uL tokens processed of %ud total tokens;"
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
		if (isfinite(h)) {
			final_prob = 1.0;
			msg_debug_bayes("spam class is full: no"
							" ham samples");
		}
		else if (isfinite(s)) {
			final_prob = 0.0;
			msg_debug_bayes("ham class is full: no"
							" spam samples");
		}
		else {
			final_prob = 0.5;
			msg_warn_bayes("spam and ham classes are both full");
		}
	}

	pprob = rspamd_mempool_alloc(task->task_pool, sizeof(*pprob));
	*pprob = final_prob;
	rspamd_mempool_set_variable(task->task_pool, "bayes_prob", pprob, NULL);

	if (cl.processed_tokens > 0 && fabs(final_prob - 0.5) > 0.05) {
		/* Now we can have exactly one HAM and exactly one SPAM statfiles per classifier */
		for (i = 0; i < ctx->statfiles_ids->len; i++) {
			id = g_array_index(ctx->statfiles_ids, int, i);
			st = g_ptr_array_index(ctx->ctx->statfiles, id);

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
		rspamd_snprintf(sumbuf, sizeof(sumbuf), "%.2f%%",
						(final_prob - 0.5) * 200.);
		final_prob = rspamd_normalize_probability(final_prob, 0.5);
		g_assert(st != NULL);

		if (final_prob > 1 || final_prob < 0) {
			msg_err_bayes("internal error: probability %f is outside of the "
						  "allowed range [0..1]",
						  final_prob);

			if (final_prob > 1) {
				final_prob = 1.0;
			}
			else {
				final_prob = 0.0;
			}
		}

		rspamd_task_insert_result(task,
								  st->stcf->symbol,
								  final_prob,
								  sumbuf);
	}

	return TRUE;
}

gboolean
bayes_learn_spam(struct rspamd_classifier *ctx,
				 GPtrArray *tokens,
				 struct rspamd_task *task,
				 gboolean is_spam,
				 gboolean unlearn,
				 GError **err)
{
	unsigned int i, j, total_cnt, spam_cnt, ham_cnt;
	int id;
	struct rspamd_statfile *st;
	rspamd_token_t *tok;
	gboolean incrementing;

	g_assert(ctx != NULL);
	g_assert(tokens != NULL);

	incrementing = ctx->cfg->flags & RSPAMD_FLAG_CLASSIFIER_INCREMENTING_BACKEND;

	for (i = 0; i < tokens->len; i++) {
		total_cnt = 0;
		spam_cnt = 0;
		ham_cnt = 0;
		tok = g_ptr_array_index(tokens, i);

		for (j = 0; j < ctx->statfiles_ids->len; j++) {
			id = g_array_index(ctx->statfiles_ids, int, j);
			st = g_ptr_array_index(ctx->ctx->statfiles, id);
			g_assert(st != NULL);

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
			msg_debug_bayes("token %uL <%*s:%*s>: window: %d, total_count: %d, "
							"spam_count: %d, ham_count: %d",
							tok->data,
							(int) tok->t1->stemmed.len, tok->t1->stemmed.begin,
							(int) tok->t2->stemmed.len, tok->t2->stemmed.begin,
							tok->window_idx, total_cnt, spam_cnt, ham_cnt);
		}
		else {
			msg_debug_bayes("token %uL <?:?>: window: %d, total_count: %d, "
							"spam_count: %d, ham_count: %d",
							tok->data,
							tok->window_idx, total_cnt, spam_cnt, ham_cnt);
		}
	}

	return TRUE;
}

gboolean
bayes_learn_class(struct rspamd_classifier *ctx,
				  GPtrArray *tokens,
				  struct rspamd_task *task,
				  const char *class_name,
				  gboolean unlearn,
				  GError **err)
{
	unsigned int i, j, total_cnt;
	int id;
	struct rspamd_statfile *st;
	rspamd_token_t *tok;
	gboolean incrementing;
	unsigned int *class_counts = NULL;
	struct rspamd_statfile **class_statfiles = NULL;
	unsigned int num_classes = 0;

	g_assert(ctx != NULL);
	g_assert(tokens != NULL);
	g_assert(class_name != NULL);

	incrementing = ctx->cfg->flags & RSPAMD_FLAG_CLASSIFIER_INCREMENTING_BACKEND;

	/* Count classes and prepare arrays for multi-class learning */
	if (ctx->cfg->class_names && ctx->cfg->class_names->len > 0) {
		num_classes = ctx->cfg->class_names->len;
		class_counts = g_alloca(num_classes * sizeof(unsigned int));
		class_statfiles = g_alloca(num_classes * sizeof(struct rspamd_statfile *));
		memset(class_counts, 0, num_classes * sizeof(unsigned int));
		memset(class_statfiles, 0, num_classes * sizeof(struct rspamd_statfile *));
	}

	for (i = 0; i < tokens->len; i++) {
		total_cnt = 0;
		tok = g_ptr_array_index(tokens, i);

		/* Reset class counts for this token */
		if (num_classes > 0) {
			memset(class_counts, 0, num_classes * sizeof(unsigned int));
		}

		for (j = 0; j < ctx->statfiles_ids->len; j++) {
			id = g_array_index(ctx->statfiles_ids, int, j);
			st = g_ptr_array_index(ctx->ctx->statfiles, id);
			g_assert(st != NULL);

			/* Determine if this statfile matches our target class */
			gboolean is_target_class = FALSE;
			if (st->stcf->class_name) {
				/* Multi-class: exact class name match */
				is_target_class = (strcmp(st->stcf->class_name, class_name) == 0);
			}
			else {
				/* Legacy binary: map class_name to spam/ham */
				if (strcmp(class_name, "spam") == 0 || strcmp(class_name, "S") == 0) {
					is_target_class = st->stcf->is_spam;
				}
				else if (strcmp(class_name, "ham") == 0 || strcmp(class_name, "H") == 0) {
					is_target_class = !st->stcf->is_spam;
				}
			}

			if (is_target_class) {
				/* Learning: increment the target class */
				if (incrementing) {
					tok->values[id] = 1;
				}
				else {
					tok->values[id]++;
				}
				total_cnt += tok->values[id];

				/* Track class counts for debugging */
				if (num_classes > 0) {
					for (unsigned int k = 0; k < num_classes; k++) {
						const char *check_class = (const char *) g_ptr_array_index(ctx->cfg->class_names, k);
						if (st->stcf->class_name && strcmp(st->stcf->class_name, check_class) == 0) {
							class_counts[k] += tok->values[id];
							class_statfiles[k] = st;
							break;
						}
					}
				}
			}
			else {
				/* Unlearning: decrement other classes if unlearn flag is set */
				if (tok->values[id] > 0 && unlearn) {
					if (incrementing) {
						tok->values[id] = -1;
					}
					else {
						tok->values[id]--;
					}
					total_cnt += tok->values[id];

					/* Track class counts for debugging */
					if (num_classes > 0) {
						for (unsigned int k = 0; k < num_classes; k++) {
							const char *check_class = (const char *) g_ptr_array_index(ctx->cfg->class_names, k);
							if (st->stcf->class_name && strcmp(st->stcf->class_name, check_class) == 0) {
								class_counts[k] += tok->values[id];
								class_statfiles[k] = st;
								break;
							}
						}
					}
				}
				else if (incrementing) {
					tok->values[id] = 0;
				}
			}
		}

		/* Debug logging */
		if (tok->t1 && tok->t2) {
			if (num_classes > 0) {
				GString *debug_str = g_string_new("");
				for (unsigned int k = 0; k < num_classes; k++) {
					const char *check_class = (const char *) g_ptr_array_index(ctx->cfg->class_names, k);
					g_string_append_printf(debug_str, "%s:%d ", check_class, class_counts[k]);
				}
				msg_debug_bayes("token %uL <%*s:%*s>: window: %d, total_count: %d, "
								"class_counts: %s",
								tok->data,
								(int) tok->t1->stemmed.len, tok->t1->stemmed.begin,
								(int) tok->t2->stemmed.len, tok->t2->stemmed.begin,
								tok->window_idx, total_cnt, debug_str->str);
				g_string_free(debug_str, TRUE);
			}
			else {
				msg_debug_bayes("token %uL <%*s:%*s>: window: %d, total_count: %d, "
								"class: %s",
								tok->data,
								(int) tok->t1->stemmed.len, tok->t1->stemmed.begin,
								(int) tok->t2->stemmed.len, tok->t2->stemmed.begin,
								tok->window_idx, total_cnt, class_name);
			}
		}
		else {
			msg_debug_bayes("token %uL <?:?>: window: %d, total_count: %d, "
							"class: %s",
							tok->data,
							tok->window_idx, total_cnt, class_name);
		}
	}

	return TRUE;
}
