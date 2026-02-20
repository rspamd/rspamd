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
#include "config.h"
#include "stat_api.h"
#include "rspamd.h"
#include "stat_internal.h"
#include "libmime/message.h"
#include "libmime/images.h"
#include "libserver/html/html.h"
#include "lua/lua_common.h"
#include "lua/lua_classnames.h"
#include "libserver/mempool_vars_internal.h"
#include "utlist.h"
#include <math.h>

#define RSPAMD_CLASSIFY_OP 0
#define RSPAMD_LEARN_OP 1
#define RSPAMD_UNLEARN_OP 2

static const double similarity_threshold = 80.0;

void rspamd_task_set_multiclass_result(struct rspamd_task *task,
									   rspamd_multiclass_result_t *result,
									   const char *classifier_name)
{
	g_assert(task != NULL);
	g_assert(result != NULL);

	/* Unified key: "multiclass_result:<name>", empty string for unnamed classifiers */
	const char *cl_name = (classifier_name && *classifier_name) ? classifier_name : "";
	gsize key_len = strlen("multiclass_result:") + strlen(cl_name) + 1;
	char *key = rspamd_mempool_alloc(task->task_pool, key_len);
	rspamd_snprintf(key, key_len, "multiclass_result:%s", cl_name);

	/* NULL destructor — result is pool-allocated */
	rspamd_mempool_set_variable(task->task_pool, key, result, NULL);
}

rspamd_multiclass_result_t *
rspamd_task_get_multiclass_result(struct rspamd_task *task, const char *classifier_name)
{
	g_assert(task != NULL);

	const char *cl_name = (classifier_name && *classifier_name) ? classifier_name : "";
	gsize key_len = strlen("multiclass_result:") + strlen(cl_name) + 1;
	char *key = rspamd_mempool_alloc(task->task_pool, key_len);
	rspamd_snprintf(key, key_len, "multiclass_result:%s", cl_name);

	return (rspamd_multiclass_result_t *) rspamd_mempool_get_variable(task->task_pool, key);
}

void rspamd_task_set_autolearn_class(struct rspamd_task *task, const char *class_name)
{
	g_assert(task != NULL);
	g_assert(class_name != NULL);

	/* Store the class name in the mempool */
	const char *class_name_copy = rspamd_mempool_strdup(task->task_pool, class_name);
	rspamd_mempool_set_variable(task->task_pool, "autolearn_class",
								(gpointer) class_name_copy, NULL);

	/* Set the appropriate flags */
	task->flags |= RSPAMD_TASK_FLAG_LEARN_CLASS;

	/* For backward compatibility, also set binary flags */
	if (strcmp(class_name, "spam") == 0 || strcmp(class_name, "S") == 0) {
		task->flags |= RSPAMD_TASK_FLAG_LEARN_SPAM;
	}
	else if (strcmp(class_name, "ham") == 0 || strcmp(class_name, "H") == 0) {
		task->flags |= RSPAMD_TASK_FLAG_LEARN_HAM;
	}
}

const char *
rspamd_task_get_autolearn_class(struct rspamd_task *task)
{
	g_assert(task != NULL);

	if (task->flags & RSPAMD_TASK_FLAG_LEARN_CLASS) {
		return (const char *) rspamd_mempool_get_variable(task->task_pool, "autolearn_class");
	}

	/* Fallback to binary flags for backward compatibility */
	if (task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM) {
		return "spam";
	}
	else if (task->flags & RSPAMD_TASK_FLAG_LEARN_HAM) {
		return "ham";
	}

	return NULL;
}

static void
rspamd_words_kvec_dtor(gpointer p)
{
	rspamd_words_t *words = (rspamd_words_t *) p;
	kv_destroy(*words);
}

static void
rspamd_stat_tokenize_parts_metadata(struct rspamd_stat_ctx *st_ctx,
									struct rspamd_task *task)
{
	rspamd_words_t *words;
	rspamd_word_t elt;
	unsigned int i;
	lua_State *L = task->cfg->lua_state;

	words = rspamd_mempool_alloc(task->task_pool, sizeof(*words));
	kv_init(*words);
	rspamd_mempool_add_destructor(task->task_pool, rspamd_words_kvec_dtor, words);
	memset(&elt, 0, sizeof(elt));
	elt.flags = RSPAMD_STAT_TOKEN_FLAG_META;

	if (st_ctx->lua_stat_tokens_ref != -1) {
		int err_idx, ret;
		struct rspamd_task **ptask;

		lua_pushcfunction(L, &rspamd_lua_traceback);
		err_idx = lua_gettop(L);
		lua_rawgeti(L, LUA_REGISTRYINDEX, st_ctx->lua_stat_tokens_ref);

		ptask = lua_newuserdata(L, sizeof(*ptask));
		*ptask = task;
		rspamd_lua_setclass(L, rspamd_task_classname, -1);

		if ((ret = lua_pcall(L, 1, 1, err_idx)) != 0) {
			msg_err_task("call to stat_tokens lua "
						 "script failed (%d): %s",
						 ret, lua_tostring(L, -1));
		}
		else {
			if (lua_type(L, -1) != LUA_TTABLE) {
				msg_err_task("stat_tokens invocation must return "
							 "table and not %s",
							 lua_typename(L, lua_type(L, -1)));
			}
			else {
				unsigned int vlen;
				rspamd_ftok_t tok;

				vlen = rspamd_lua_table_size(L, -1);

				for (i = 0; i < vlen; i++) {
					lua_rawgeti(L, -1, i + 1);
					tok.begin = lua_tolstring(L, -1, &tok.len);

					if (tok.begin && tok.len > 0) {
						elt.original.begin =
							rspamd_mempool_ftokdup(task->task_pool, &tok);
						elt.original.len = tok.len;
						elt.stemmed.begin = elt.original.begin;
						elt.stemmed.len = elt.original.len;
						elt.normalized.begin = elt.original.begin;
						elt.normalized.len = elt.original.len;

						kv_push_safe(rspamd_word_t, *words, elt, meta_words_error);
					}

					lua_pop(L, 1);
				}
			}
		}

		lua_settop(L, 0);
	}


	if (kv_size(*words) > 0) {
		st_ctx->tokenizer->tokenize_func(st_ctx,
										 task,
										 words,
										 TRUE,
										 "M",
										 task->tokens);
	}

	return;
meta_words_error:

	msg_err("cannot process meta words for task"
			"memory allocation error, skipping the remaining");
}

/*
 * Tokenize task using the tokenizer specified
 */
void rspamd_stat_process_tokenize(struct rspamd_stat_ctx *st_ctx,
								  struct rspamd_task *task)
{
	struct rspamd_mime_text_part *part;
	rspamd_cryptobox_hash_state_t hst;
	rspamd_token_t *st_tok;
	unsigned int i, reserved_len = 0;
	double *pdiff;
	unsigned char hout[rspamd_cryptobox_HASHBYTES];
	char *b32_hout;

	if (st_ctx == NULL) {
		st_ctx = rspamd_stat_get_ctx();
	}

	g_assert(st_ctx != NULL);

	PTR_ARRAY_FOREACH(MESSAGE_FIELD(task, text_parts), i, part)
	{
		if (!IS_TEXT_PART_EMPTY(part) && part->utf_words.a) {
			reserved_len += kv_size(part->utf_words);
		}
		/* XXX: normal window size */
		reserved_len += 5;
	}

	task->tokens = g_ptr_array_sized_new(reserved_len);
	rspamd_mempool_add_destructor(task->task_pool,
								  rspamd_ptr_array_free_hard, task->tokens);
	rspamd_mempool_notify_alloc(task->task_pool, reserved_len * sizeof(gpointer));
	pdiff = rspamd_mempool_get_variable(task->task_pool, "parts_distance");

	PTR_ARRAY_FOREACH(MESSAGE_FIELD(task, text_parts), i, part)
	{
		if (!IS_TEXT_PART_EMPTY(part) && part->utf_words.a) {
			st_ctx->tokenizer->tokenize_func(st_ctx, task,
											 &part->utf_words, IS_TEXT_PART_UTF(part),
											 NULL, task->tokens);
		}


		if (pdiff != NULL && (1.0 - *pdiff) * 100.0 > similarity_threshold) {
			msg_debug_bayes("message has two common parts (%.2f), so skip the last one",
							*pdiff);
			break;
		}
	}

	if (task->meta_words.a) {
		st_ctx->tokenizer->tokenize_func(st_ctx,
										 task,
										 &task->meta_words,
										 TRUE,
										 "SUBJECT",
										 task->tokens);
	}

	rspamd_stat_tokenize_parts_metadata(st_ctx, task);

	/* Produce signature */
	rspamd_cryptobox_hash_init(&hst, NULL, 0);

	PTR_ARRAY_FOREACH(task->tokens, i, st_tok)
	{
		rspamd_cryptobox_hash_update(&hst, (unsigned char *) &st_tok->data,
									 sizeof(st_tok->data));
	}

	rspamd_cryptobox_hash_final(&hst, hout);
	b32_hout = rspamd_encode_base32(hout, sizeof(hout), RSPAMD_BASE32_DEFAULT);
	/*
	 * We need to strip it to 32 characters providing ~160 bits of
	 * hash distribution
	 */
	b32_hout[32] = '\0';
	rspamd_mempool_set_variable(task->task_pool, RSPAMD_MEMPOOL_STAT_SIGNATURE,
								b32_hout, g_free);
}

static gboolean
rspamd_stat_classifier_is_skipped(struct rspamd_task *task,
								  struct rspamd_classifier *cl, gboolean is_learn, gboolean is_spam,
								  const char *learn_class_name)
{
	GList *cur = is_learn ? cl->cfg->learn_conditions : cl->cfg->classify_conditions;
	lua_State *L = task->cfg->lua_state;
	gboolean ret = FALSE;

	/*
	 * Before calling the Lua learn condition, populate "can_learn_prob" in the
	 * mempool with the probability from THIS specific classifier's result.
	 *
	 * Binary classifiers:   read "bayes_prob:<name>" (set by bayes_classify())
	 * Multiclass classifiers: read "multiclass_result:<name>", find target class
	 *
	 * Per-classifier keys prevent cross-contamination when multiple classifiers
	 * of the same type are configured. Falls back to NULL (= skip probability
	 * check) if this classifier has no result yet (e.g. zero learns).
	 */
	if (is_learn && learn_class_name != NULL) {
		double *can_learn_prob_ptr = NULL;
		/* Use "" for unnamed classifiers — matches what bayes_classify() stores */
		const char *cl_name = (cl->cfg->name && *cl->cfg->name) ? cl->cfg->name : "";

		if (cl->cfg->flags & RSPAMD_FLAG_CLASSIFIER_MULTICLASS) {
			/* Look up THIS classifier's multiclass result via the unified API */
			rspamd_multiclass_result_t *mc_result =
				rspamd_task_get_multiclass_result(task, cl_name);
			if (mc_result != NULL) {
				for (unsigned int mci = 0; mci < mc_result->num_classes; mci++) {
					if (mc_result->class_names[mci] != NULL &&
						strcmp(mc_result->class_names[mci], learn_class_name) == 0) {
						can_learn_prob_ptr = rspamd_mempool_alloc(task->task_pool,
																  sizeof(double));
						*can_learn_prob_ptr = mc_result->probabilities[mci];
						break;
					}
				}
			}
			/* NULL means classifier has no result (zero learns) → skip prob check → allow */
		}
		else {
			/* Look up THIS classifier's binary bayes_prob by name.
			 * bayes_prob is the spam probability (0=ham, 1=spam).
			 * Convert to "probability of the class being learned" so the
			 * unified >= threshold check works correctly for both directions:
			 * learning spam: use raw prob (high = already spam = skip)
			 * learning ham:  use 1-prob  (high = already ham = skip) */
			gsize key_len = strlen("bayes_prob:") + strlen(cl_name) + 1;
			char *per_cl_key = rspamd_mempool_alloc(task->task_pool, key_len);
			rspamd_snprintf(per_cl_key, key_len, "bayes_prob:%s", cl_name);
			double *raw_prob = (double *) rspamd_mempool_get_variable(task->task_pool,
																	  per_cl_key);
			if (raw_prob != NULL) {
				can_learn_prob_ptr = rspamd_mempool_alloc(task->task_pool, sizeof(double));
				gboolean learning_ham = (strcmp(learn_class_name, "ham") == 0 ||
										 strcmp(learn_class_name, "H") == 0);
				*can_learn_prob_ptr = learning_ham ? (1.0 - *raw_prob) : *raw_prob;
			}
		}

		rspamd_mempool_set_variable(task->task_pool, "can_learn_prob",
									can_learn_prob_ptr, NULL);
		/* Also store the class name so can_learn() can include it in log messages */
		rspamd_mempool_set_variable(task->task_pool, "can_learn_class",
									(gpointer) learn_class_name, NULL);
	}

	while (cur) {
		int cb_ref = GPOINTER_TO_INT(cur->data);
		int old_top = lua_gettop(L);
		int nargs;

		lua_rawgeti(L, LUA_REGISTRYINDEX, cb_ref);
		/* Push task and two booleans: is_spam and is_unlearn */
		struct rspamd_task **ptask = lua_newuserdata(L, sizeof(*ptask));
		*ptask = task;
		rspamd_lua_setclass(L, rspamd_task_classname, -1);

		if (is_learn) {
			lua_pushboolean(L, is_spam);
			lua_pushboolean(L,
							task->flags & RSPAMD_TASK_FLAG_UNLEARN ? true : false);
			nargs = 3;
		}
		else {
			nargs = 1;
		}

		if (lua_pcall(L, nargs, LUA_MULTRET, 0) != 0) {
			msg_err_task("call to %s failed: %s",
						 "condition callback",
						 lua_tostring(L, -1));
		}
		else {
			if (lua_isboolean(L, 1)) {
				if (!lua_toboolean(L, 1)) {
					ret = TRUE;
				}
			}

			if (lua_isstring(L, 2)) {
				if (ret) {
					msg_notice_task("%s condition for classifier %s returned: %s; skip classifier",
									is_learn ? "learn" : "classify", cl->cfg->name,
									lua_tostring(L, 2));
				}
				else {
					msg_info_task("%s condition for classifier %s returned: %s",
								  is_learn ? "learn" : "classify", cl->cfg->name,
								  lua_tostring(L, 2));
				}
			}
			else if (ret) {
				msg_notice_task("%s condition for classifier %s returned false; skip classifier",
								is_learn ? "learn" : "classify", cl->cfg->name);
			}

			if (ret) {
				lua_settop(L, old_top);
				break;
			}
		}

		lua_settop(L, old_top);
		cur = g_list_next(cur);
	}

	return ret;
}

static void
rspamd_stat_preprocess(struct rspamd_stat_ctx *st_ctx,
					   struct rspamd_task *task, gboolean is_learn, gboolean is_spam)
{
	unsigned int i;
	struct rspamd_statfile *st;
	gpointer bk_run;

	if (task->tokens == NULL) {
		rspamd_stat_process_tokenize(st_ctx, task);
	}

	task->stat_runtimes = g_ptr_array_sized_new(st_ctx->statfiles->len);
	g_ptr_array_set_size(task->stat_runtimes, st_ctx->statfiles->len);
	rspamd_mempool_add_destructor(task->task_pool,
								  rspamd_ptr_array_free_hard, task->stat_runtimes);

	/* Temporary set all stat_runtimes to some max size to distinguish from NULL */
	for (i = 0; i < st_ctx->statfiles->len; i++) {
		g_ptr_array_index(task->stat_runtimes, i) = GSIZE_TO_POINTER(G_MAXSIZE);
	}

	/* When learning a specific class, retrieve it once for use in the loop below */
	const char *learn_class_name = is_learn ? rspamd_task_get_autolearn_class(task) : NULL;

	for (i = 0; i < st_ctx->classifiers->len; i++) {
		struct rspamd_classifier *cl = g_ptr_array_index(st_ctx->classifiers, i);
		gboolean skip_classifier = FALSE;

		if (cl->cfg->flags & RSPAMD_FLAG_CLASSIFIER_NO_BACKEND) {
			skip_classifier = TRUE;
		}
		else {
			/* Respect task->classifier filter: if a specific classifier was
			 * requested, skip all others without running can_learn on them */
			if (is_learn && task->classifier != NULL &&
					(cl->cfg->name == NULL ||
					 g_ascii_strcasecmp(task->classifier, cl->cfg->name) != 0)) {
				skip_classifier = TRUE;
			}

			/* For class-based learning: skip classifiers that don't have the
			 * target class at all — no need to run can_learn on them. */
			if (!skip_classifier && is_learn && learn_class_name != NULL) {
				gboolean cl_has_class = FALSE;
				for (int j = 0; j < cl->statfiles_ids->len; j++) {
					int id = g_array_index(cl->statfiles_ids, int, j);
					struct rspamd_statfile *cst = g_ptr_array_index(st_ctx->statfiles, id);
					if (cst->stcf->class_name &&
							strcmp(cst->stcf->class_name, learn_class_name) == 0) {
						cl_has_class = TRUE;
						break;
					}
				}
				if (!cl_has_class) {
					skip_classifier = TRUE;
				}
			}

			if (!skip_classifier) {
				if (rspamd_stat_classifier_is_skipped(task, cl, is_learn, is_spam,
													  learn_class_name)) {
					skip_classifier = TRUE;
				}
			}
		}

		if (skip_classifier) {
			/* Set NULL for all statfiles indexed by id */
			for (int j = 0; j < cl->statfiles_ids->len; j++) {
				int id = g_array_index(cl->statfiles_ids, int, j);
				g_ptr_array_index(task->stat_runtimes, id) = NULL;
			}
		}
	}

	for (i = 0; i < st_ctx->statfiles->len; i++) {
		st = g_ptr_array_index(st_ctx->statfiles, i);
		g_assert(st != NULL);

		if (g_ptr_array_index(task->stat_runtimes, i) == NULL) {
			/* The whole classifier is skipped */
			continue;
		}

		if (is_learn && st->backend->read_only) {
			/* Read only backend, skip it */
			g_ptr_array_index(task->stat_runtimes, i) = NULL;
			continue;
		}

		if (!is_learn && !rspamd_symcache_is_symbol_enabled(task, task->cfg->cache,
															st->stcf->symbol)) {
			g_ptr_array_index(task->stat_runtimes, i) = NULL;
			msg_debug_bayes("symbol %s is disabled, skip classification",
							st->stcf->symbol);
			/* We need to disable the whole classifier for this! */
			struct rspamd_classifier *cl = st->classifier;
			for (int j = 0; j < st_ctx->statfiles->len; j++) {
				struct rspamd_statfile *nst = g_ptr_array_index(st_ctx->statfiles, j);

				if (st != nst && nst->classifier == cl) {
					g_ptr_array_index(task->stat_runtimes, j) = NULL;
					msg_debug_bayes("symbol %s is disabled, skip classification for %s as well",
									st->stcf->symbol, nst->stcf->symbol);
				}
			}

			continue;
		}

		bk_run = st->backend->runtime(task, st->stcf, is_learn, st->bkcf, i);

		if (bk_run == NULL) {
			msg_err_task("cannot init backend %s for statfile %s",
						 st->backend->name, st->stcf->symbol);
		}

		g_ptr_array_index(task->stat_runtimes, i) = bk_run;
	}
}

static void
rspamd_stat_backends_process(struct rspamd_stat_ctx *st_ctx,
							 struct rspamd_task *task)
{
	unsigned int i;
	struct rspamd_statfile *st;
	gpointer bk_run;

	g_assert(task->stat_runtimes != NULL);

	for (i = 0; i < st_ctx->statfiles->len; i++) {
		st = g_ptr_array_index(st_ctx->statfiles, i);
		bk_run = g_ptr_array_index(task->stat_runtimes, i);

		if (bk_run != NULL) {
			st->backend->process_tokens(task, task->tokens, i, bk_run);
		}
	}
}

static void
rspamd_stat_classifiers_process(struct rspamd_stat_ctx *st_ctx,
								struct rspamd_task *task)
{
	unsigned int i, j, id;
	struct rspamd_classifier *cl;
	struct rspamd_statfile *st;
	gpointer bk_run;
	gboolean skip;

	if (st_ctx->classifiers->len == 0) {
		return;
	}

	/*
	 * Multi-class approach: don't check for missing classes
	 * Missing tokens naturally result in 0 probability
	 */

	for (i = 0; i < st_ctx->classifiers->len; i++) {
		cl = g_ptr_array_index(st_ctx->classifiers, i);
		cl->spam_learns = 0;
		cl->ham_learns = 0;
	}

	g_assert(task->stat_runtimes != NULL);

	for (i = 0; i < st_ctx->statfiles->len; i++) {
		st = g_ptr_array_index(st_ctx->statfiles, i);
		cl = st->classifier;

		bk_run = g_ptr_array_index(task->stat_runtimes, i);
		g_assert(st != NULL);

		if (bk_run != NULL) {
			if (st->stcf->is_spam) {
				cl->spam_learns += st->backend->total_learns(task,
															 bk_run,
															 st_ctx);
			}
			else {
				cl->ham_learns += st->backend->total_learns(task,
															bk_run,
															st_ctx);
			}
		}
	}

	for (i = 0; i < st_ctx->classifiers->len; i++) {
		cl = g_ptr_array_index(st_ctx->classifiers, i);

		g_assert(cl != NULL);

		skip = FALSE;

		/* Do not process classifiers on backend failures */
		for (j = 0; j < cl->statfiles_ids->len; j++) {
			id = g_array_index(cl->statfiles_ids, int, j);
			bk_run = g_ptr_array_index(task->stat_runtimes, id);
			st = g_ptr_array_index(st_ctx->statfiles, id);

			if (bk_run != NULL) {
				if (!st->backend->finalize_process(task, bk_run, st_ctx)) {
					skip = TRUE;
					break;
				}
			}
		}

		/* Ensure that all symbols enabled */
		if (!skip && !(cl->cfg->flags & RSPAMD_FLAG_CLASSIFIER_NO_BACKEND)) {
			for (j = 0; j < cl->statfiles_ids->len; j++) {
				id = g_array_index(cl->statfiles_ids, int, j);
				bk_run = g_ptr_array_index(task->stat_runtimes, id);
				st = g_ptr_array_index(st_ctx->statfiles, id);

				if (bk_run == NULL) {
					skip = TRUE;
					msg_debug_bayes("disable classifier %s as statfile symbol %s is disabled",
									cl->cfg->name, st->stcf->symbol);
					break;
				}
			}
		}

		if (!skip) {
			if (cl->cfg->min_tokens > 0 && task->tokens->len < cl->cfg->min_tokens) {
				msg_debug_bayes(
					"contains less tokens than required for %s classifier: "
					"%ud < %ud",
					cl->cfg->name,
					task->tokens->len,
					cl->cfg->min_tokens);
				continue;
			}
			else if (cl->cfg->max_tokens > 0 && task->tokens->len > cl->cfg->max_tokens) {
				msg_debug_bayes(
					"contains more tokens than allowed for %s classifier: "
					"%ud > %ud",
					cl->cfg->name,
					task->tokens->len,
					cl->cfg->max_tokens);
				continue;
			}

			cl->subrs->classify_func(cl, task->tokens, task);
		}
	}
}

rspamd_stat_result_t
rspamd_stat_classify(struct rspamd_task *task, lua_State *L, unsigned int stage,
					 GError **err)
{
	struct rspamd_stat_ctx *st_ctx;
	rspamd_stat_result_t ret = RSPAMD_STAT_PROCESS_OK;

	st_ctx = rspamd_stat_get_ctx();
	g_assert(st_ctx != NULL);

	if (st_ctx->classifiers->len == 0) {
		task->processed_stages |= stage;
		return ret;
	}

	if (task->message == NULL) {
		ret = RSPAMD_STAT_PROCESS_ERROR;
		msg_err_task("trying to classify empty message");

		task->processed_stages |= stage;
		return ret;
	}

	if (stage == RSPAMD_TASK_STAGE_CLASSIFIERS_PRE) {
		/* Preprocess tokens */
		rspamd_stat_preprocess(st_ctx, task, FALSE, FALSE);
	}
	else if (stage == RSPAMD_TASK_STAGE_CLASSIFIERS) {
		/* Process backends */
		rspamd_stat_backends_process(st_ctx, task);
	}
	else if (stage == RSPAMD_TASK_STAGE_CLASSIFIERS_POST) {
		/* Process classifiers */
		rspamd_stat_classifiers_process(st_ctx, task);
	}

	task->processed_stages |= stage;

	return ret;
}

static gboolean
rspamd_stat_cache_check(struct rspamd_stat_ctx *st_ctx,
						struct rspamd_task *task,
						const char *classifier,
						gboolean spam,
						GError **err)
{
	rspamd_learn_t learn_res = RSPAMD_LEARN_OK;
	struct rspamd_classifier *cl, *sel = NULL;
	gpointer rt;
	unsigned int i;

	/* Check whether we have learned that file */
	for (i = 0; i < st_ctx->classifiers->len; i++) {
		cl = g_ptr_array_index(st_ctx->classifiers, i);

		/* Skip other classifiers if they are not needed */
		if (classifier != NULL && (cl->cfg->name == NULL ||
								   g_ascii_strcasecmp(classifier, cl->cfg->name) != 0)) {
			continue;
		}

		sel = cl;

		if (sel->cache && sel->cachecf) {
			rt = cl->cache->runtime(task, sel->cachecf, FALSE);

			/* For multi-class learning, determine spam boolean from class name if available */
			gboolean cache_spam = spam; /* Default to original spam parameter */
			const char *autolearn_class = rspamd_task_get_autolearn_class(task);
			if (autolearn_class) {
				if (strcmp(autolearn_class, "spam") == 0 || strcmp(autolearn_class, "S") == 0) {
					cache_spam = TRUE;
				}
				else if (strcmp(autolearn_class, "ham") == 0 || strcmp(autolearn_class, "H") == 0) {
					cache_spam = FALSE;
				}
				else {
					/* For other classes, use a heuristic or default to spam for cache purposes */
					cache_spam = TRUE; /* Non-ham classes are treated as spam for cache */
				}
			}

			learn_res = cl->cache->check(task, cache_spam, rt);

			/* Honor flags set by cache check callback (e.g. Redis) */
			if (task->flags & RSPAMD_TASK_FLAG_ALREADY_LEARNED) {
				const char *already_class = rspamd_task_get_autolearn_class(task);
				if (!already_class) {
					already_class = cache_spam ? "spam" : "ham";
				}

				g_set_error(err, rspamd_stat_quark(), 404, "<%s> has been already "
														   "learned as %s, ignore it",
							MESSAGE_FIELD(task, message_id),
							already_class);

				return FALSE;
			}
			else if (task->flags & RSPAMD_TASK_FLAG_UNLEARN) {
				/* Will be handled on learn stage */
				break;
			}
		}

		if (learn_res == RSPAMD_LEARN_IGNORE) {
			/* Do not learn twice */
			g_set_error(err, rspamd_stat_quark(), 404, "<%s> has been already "
													   "learned as %s, ignore it",
						MESSAGE_FIELD(task, message_id),
						spam ? "spam" : "ham");
			task->flags |= RSPAMD_TASK_FLAG_ALREADY_LEARNED;

			return FALSE;
		}
		else if (learn_res == RSPAMD_LEARN_UNLEARN) {
			task->flags |= RSPAMD_TASK_FLAG_UNLEARN;
			break;
		}
	}

	if (sel == NULL) {
		if (classifier) {
			g_set_error(err, rspamd_stat_quark(), 404, "cannot find classifier "
													   "with name %s",
						classifier);
		}
		else {
			g_set_error(err, rspamd_stat_quark(), 404, "no classifiers defined");
		}

		return FALSE;
	}

	return TRUE;
}

static gboolean
rspamd_stat_classifiers_learn(struct rspamd_stat_ctx *st_ctx,
							  struct rspamd_task *task,
							  const char *classifier,
							  gboolean spam,
							  GError **err)
{
	struct rspamd_classifier *cl, *sel = NULL;
	unsigned int i;
	gboolean learned = FALSE, too_small = FALSE, too_large = FALSE;

	if (task->flags & RSPAMD_TASK_FLAG_ALREADY_LEARNED) {
		/* Do not learn twice */
		if (err && *err == NULL) {
			g_set_error(err, rspamd_stat_quark(), 208, "<%s> has been already "
													   "learned as %s, ignore it",
						MESSAGE_FIELD(task, message_id),
						spam ? "spam" : "ham");
		}

		return FALSE;
	}

	/* Check whether we have learned that file */
	for (i = 0; i < st_ctx->classifiers->len; i++) {
		cl = g_ptr_array_index(st_ctx->classifiers, i);

		/* Skip other classifiers if they are not needed */
		if (classifier != NULL && (cl->cfg->name == NULL ||
								   g_ascii_strcasecmp(classifier, cl->cfg->name) != 0)) {
			continue;
		}

		sel = cl;

		/* Now check max and min tokens */
		if (cl->cfg->min_tokens > 0 && task->tokens->len < cl->cfg->min_tokens) {
			msg_info_task(
				"<%s> contains less tokens than required for %s classifier: "
				"%ud < %ud",
				MESSAGE_FIELD(task, message_id),
				cl->cfg->name,
				task->tokens->len,
				cl->cfg->min_tokens);
			too_small = TRUE;
			continue;
		}
		else if (cl->cfg->max_tokens > 0 && task->tokens->len > cl->cfg->max_tokens) {
			msg_info_task(
				"<%s> contains more tokens than allowed for %s classifier: "
				"%ud > %ud",
				MESSAGE_FIELD(task, message_id),
				cl->cfg->name,
				task->tokens->len,
				cl->cfg->max_tokens);
			too_large = TRUE;
			continue;
		}

		/* Check if classifier supports multi-class learning and if we should use it */
		if (cl->subrs->learn_class_func && cl->cfg->class_names && cl->cfg->class_names->len > 2) {
			/* Multi-class learning: determine class name from task flags or autolearn result */
			const char *class_name = NULL;

			if (task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM) {
				/* Find spam class name */
				for (unsigned int k = 0; k < cl->cfg->class_names->len; k++) {
					const char *check_class = (const char *) g_ptr_array_index(cl->cfg->class_names, k);
					/* Look for statfile with this class that is spam */
					GList *cur = cl->cfg->statfiles;
					while (cur) {
						struct rspamd_statfile_config *stcf = (struct rspamd_statfile_config *) cur->data;
						if (stcf->class_name && strcmp(stcf->class_name, check_class) == 0 && stcf->is_spam) {
							class_name = check_class;
							break;
						}
						cur = g_list_next(cur);
					}
					if (class_name) break;
				}
				if (!class_name) class_name = "spam"; /* fallback */
			}
			else if (task->flags & RSPAMD_TASK_FLAG_LEARN_HAM) {
				/* Find ham class name */
				for (unsigned int k = 0; k < cl->cfg->class_names->len; k++) {
					const char *check_class = (const char *) g_ptr_array_index(cl->cfg->class_names, k);
					/* Look for statfile with this class that is ham */
					GList *cur = cl->cfg->statfiles;
					while (cur) {
						struct rspamd_statfile_config *stcf = (struct rspamd_statfile_config *) cur->data;
						if (stcf->class_name && strcmp(stcf->class_name, check_class) == 0 && !stcf->is_spam) {
							class_name = check_class;
							break;
						}
						cur = g_list_next(cur);
					}
					if (class_name) break;
				}
				if (!class_name) class_name = "ham"; /* fallback */
			}
			else {
				/* Fallback to spam/ham based on the spam parameter */
				class_name = spam ? "spam" : "ham";
			}

			if (cl->subrs->learn_class_func(cl, task->tokens, task, class_name,
											task->flags & RSPAMD_TASK_FLAG_UNLEARN, err)) {
				learned = TRUE;
			}
		}
		else {
			/* Binary learning: use existing function */
			if (cl->subrs->learn_spam_func(cl, task->tokens, task, spam,
										   task->flags & RSPAMD_TASK_FLAG_UNLEARN, err)) {
				learned = TRUE;
			}
		}
	}

	if (sel == NULL) {
		if (classifier) {
			g_set_error(err, rspamd_stat_quark(), 404, "cannot find classifier "
													   "with name %s",
						classifier);
		}
		else {
			g_set_error(err, rspamd_stat_quark(), 404, "no classifiers defined");
		}

		return FALSE;
	}

	if (!learned && err && *err == NULL) {
		if (too_large) {
			g_set_error(err, rspamd_stat_quark(), 204,
						"<%s> contains more tokens than allowed for %s classifier: "
						"%d > %d",
						MESSAGE_FIELD(task, message_id),
						sel->cfg->name,
						task->tokens->len,
						sel->cfg->max_tokens);
		}
		else if (too_small) {
			g_set_error(err, rspamd_stat_quark(), 204,
						"<%s> contains less tokens than required for %s classifier: "
						"%d < %d",
						MESSAGE_FIELD(task, message_id),
						sel->cfg->name,
						task->tokens->len,
						sel->cfg->min_tokens);
		}
	}

	return learned;
}

static gboolean
rspamd_stat_backends_learn(struct rspamd_stat_ctx *st_ctx,
						   struct rspamd_task *task,
						   const char *classifier,
						   gboolean spam,
						   GError **err)
{
	struct rspamd_classifier *cl, *sel = NULL;
	struct rspamd_statfile *st;
	gpointer bk_run;
	unsigned int i, j;
	int id;
	gboolean res = FALSE, backend_found = FALSE;

	for (i = 0; i < st_ctx->classifiers->len; i++) {
		cl = g_ptr_array_index(st_ctx->classifiers, i);

		/* Skip other classifiers if they are not needed */
		if (classifier != NULL && (cl->cfg->name == NULL ||
								   g_ascii_strcasecmp(classifier, cl->cfg->name) != 0)) {
			continue;
		}

		if (cl->cfg->flags & RSPAMD_FLAG_CLASSIFIER_NO_BACKEND) {
			res = TRUE;
			continue;
		}

		sel = cl;

		for (j = 0; j < cl->statfiles_ids->len; j++) {
			id = g_array_index(cl->statfiles_ids, int, j);
			st = g_ptr_array_index(st_ctx->statfiles, id);
			bk_run = g_ptr_array_index(task->stat_runtimes, id);

			g_assert(st != NULL);

			if (bk_run == NULL) {
				/* XXX: must be error */
				if (task->result->passthrough_result) {
					/* Passthrough email, cannot learn */
					g_set_error(err, rspamd_stat_quark(), 204,
								"Cannot learn statistics when passthrough "
								"result has been set; not classified");

					res = FALSE;
					goto end;
				}

				msg_debug_task("no runtime for backend %s; classifier %s; symbol %s",
							   st->backend->name, cl->cfg->name, st->stcf->symbol);
				continue;
			}

			/* We set sel merely when we have runtime */
			backend_found = TRUE;

			if (!(task->flags & RSPAMD_TASK_FLAG_UNLEARN)) {
				/* For multiclass learning, check if this statfile has any tokens to learn */
				if (task->flags & RSPAMD_TASK_FLAG_LEARN_CLASS) {
					/* Multiclass learning: only process statfiles that have tokens set up by the classifier */
					gboolean has_tokens = FALSE;
					for (unsigned int k = 0; k < task->tokens->len && !has_tokens; k++) {
						rspamd_token_t *tok = (rspamd_token_t *) g_ptr_array_index(task->tokens, k);
						if (tok->values[id] != 0) {
							has_tokens = TRUE;
						}
					}
					if (!has_tokens) {
						continue;
					}
				}
				else {
					/* Binary learning: use traditional spam/ham check */
					if (!!spam != !!st->stcf->is_spam) {
						/* If we are not unlearning, then do not touch another class */
						continue;
					}
				}
			}

			if (!st->backend->learn_tokens(task, task->tokens, id, bk_run)) {
				g_set_error(err, rspamd_stat_quark(), 500,
							"Cannot push "
							"learned results to the backend");

				res = FALSE;
				goto end;
			}
			else {
				if (!!spam == !!st->stcf->is_spam) {
					st->backend->inc_learns(task, bk_run, st_ctx);
				}
				else if (task->flags & RSPAMD_TASK_FLAG_UNLEARN) {
					st->backend->dec_learns(task, bk_run, st_ctx);
				}

				res = TRUE;
				/* Mark that at least one backend has actually learned */
				rspamd_mempool_set_variable(task->task_pool, "stat_learn_performed",
											GINT_TO_POINTER(1), NULL);
			}
		}
	}

end:

	if (!res) {
		if (err && *err) {
			/* Error has been set already */
			return res;
		}

		if (sel == NULL) {
			if (classifier) {
				g_set_error(err, rspamd_stat_quark(), 404, "cannot find classifier "
														   "with name %s",
							classifier);
			}
			else {
				g_set_error(err, rspamd_stat_quark(), 404, "no classifiers defined");
			}

			return FALSE;
		}
		else if (!backend_found) {
			g_set_error(err, rspamd_stat_quark(), 204, "all learn conditions "
													   "denied learning %s in %s",
						spam ? "spam" : "ham",
						classifier ? classifier : "default classifier");
		}
		else {
			g_set_error(err, rspamd_stat_quark(), 404, "cannot find statfile "
													   "backend to learn %s in %s",
						spam ? "spam" : "ham",
						classifier ? classifier : "default classifier");
		}
	}

	return res;
}

static gboolean
rspamd_stat_backends_post_learn(struct rspamd_stat_ctx *st_ctx,
								struct rspamd_task *task,
								const char *classifier,
								gboolean spam,
								GError **err)
{
	struct rspamd_classifier *cl;
	struct rspamd_statfile *st;
	gpointer bk_run, cache_run;
	unsigned int i, j;
	int id;
	gboolean res = TRUE;

	for (i = 0; i < st_ctx->classifiers->len; i++) {
		cl = g_ptr_array_index(st_ctx->classifiers, i);

		/* Skip other classifiers if they are not needed */
		if (classifier != NULL && (cl->cfg->name == NULL ||
								   g_ascii_strcasecmp(classifier, cl->cfg->name) != 0)) {
			continue;
		}

		if (cl->cfg->flags & RSPAMD_FLAG_CLASSIFIER_NO_BACKEND) {
			res = TRUE;
			continue;
		}

		for (j = 0; j < cl->statfiles_ids->len; j++) {
			id = g_array_index(cl->statfiles_ids, int, j);
			st = g_ptr_array_index(st_ctx->statfiles, id);
			bk_run = g_ptr_array_index(task->stat_runtimes, id);

			g_assert(st != NULL);

			if (bk_run == NULL) {
				/* XXX: must be error */
				continue;
			}

			if (!st->backend->finalize_learn(task, bk_run, st_ctx, err)) {
				return RSPAMD_STAT_PROCESS_ERROR;
			}
		}

		if (cl->cache) {
			cache_run = cl->cache->runtime(task, cl->cachecf, TRUE);

			/* Update cache only if some backend actually learned */
			if (rspamd_mempool_get_variable(task->task_pool, "stat_learn_performed")) {
				/* For multi-class learning, determine spam boolean from class name if available */
				gboolean cache_spam = spam; /* Default to original spam parameter */
				const char *autolearn_class = rspamd_task_get_autolearn_class(task);
				if (autolearn_class) {
					if (strcmp(autolearn_class, "spam") == 0 || strcmp(autolearn_class, "S") == 0) {
						cache_spam = TRUE;
					}
					else if (strcmp(autolearn_class, "ham") == 0 || strcmp(autolearn_class, "H") == 0) {
						cache_spam = FALSE;
					}
					else {
						/* For other classes, use a heuristic or default to spam for cache purposes */
						cache_spam = TRUE; /* Non-ham classes are treated as spam for cache */
					}
				}

				cl->cache->learn(task, cache_spam, cache_run);
			}
		}
	}

	/* Increment learned counter only if any backend actually learned */
	if (rspamd_mempool_get_variable(task->task_pool, "stat_learn_performed")) {
		g_atomic_int_add(&task->worker->srv->stat->messages_learned, 1);
	}

	return res;
}

static gboolean
rspamd_stat_classifiers_learn_class(struct rspamd_stat_ctx *st_ctx,
									struct rspamd_task *task,
									const char *classifier,
									const char *class_name,
									GError **err)
{
	struct rspamd_classifier *cl, *sel = NULL;
	unsigned int i;
	gboolean learned = FALSE, too_small = FALSE, too_large = FALSE;

	if (task->flags & RSPAMD_TASK_FLAG_ALREADY_LEARNED) {
		/* Do not learn twice */
		if (err && *err == NULL) {
			g_set_error(err, rspamd_stat_quark(), 208, "<%s> has been already "
													   "learned as %s, ignore it",
						MESSAGE_FIELD(task, message_id),
						class_name);
		}

		return FALSE;
	}

	/* Check whether we have learned that file */
	for (i = 0; i < st_ctx->classifiers->len; i++) {
		cl = g_ptr_array_index(st_ctx->classifiers, i);

		/* Skip other classifiers if they are not needed */
		if (classifier != NULL && (cl->cfg->name == NULL ||
								   g_ascii_strcasecmp(classifier, cl->cfg->name) != 0)) {
			continue;
		}

		sel = cl;

		/* Now check max and min tokens */
		if (cl->cfg->min_tokens > 0 && task->tokens->len < cl->cfg->min_tokens) {
			msg_info_task(
				"<%s> contains less tokens than required for %s classifier: "
				"%ud < %ud",
				MESSAGE_FIELD(task, message_id),
				cl->cfg->name,
				task->tokens->len,
				cl->cfg->min_tokens);
			too_small = TRUE;
			continue;
		}
		else if (cl->cfg->max_tokens > 0 && task->tokens->len > cl->cfg->max_tokens) {
			msg_info_task(
				"<%s> contains more tokens than allowed for %s classifier: "
				"%ud > %ud",
				MESSAGE_FIELD(task, message_id),
				cl->cfg->name,
				task->tokens->len,
				cl->cfg->max_tokens);
			too_large = TRUE;
			continue;
		}

		/* Use the new multi-class learning function if available */
		if (cl->subrs->learn_class_func) {
			if (cl->subrs->learn_class_func(cl, task->tokens, task, class_name,
											task->flags & RSPAMD_TASK_FLAG_UNLEARN, err)) {
				learned = TRUE;
			}
		}
		else {
			/* Fallback to binary learning with class name mapping */
			gboolean is_spam;
			if (strcmp(class_name, "spam") == 0 || strcmp(class_name, "S") == 0) {
				is_spam = TRUE;
			}
			else if (strcmp(class_name, "ham") == 0 || strcmp(class_name, "H") == 0) {
				is_spam = FALSE;
			}
			else {
				/* For unknown classes with binary classifier, skip */
				msg_info_task("skipping class '%s' for binary classifier %s",
							  class_name, cl->cfg->name);
				continue;
			}

			if (cl->subrs->learn_spam_func(cl, task->tokens, task, is_spam,
										   task->flags & RSPAMD_TASK_FLAG_UNLEARN, err)) {
				learned = TRUE;
			}
		}
	}

	if (sel == NULL) {
		if (classifier) {
			g_set_error(err, rspamd_stat_quark(), 404, "cannot find classifier "
													   "with name %s",
						classifier);
		}
		else {
			g_set_error(err, rspamd_stat_quark(), 404, "no classifiers defined");
		}

		return FALSE;
	}

	if (!learned && err && *err == NULL) {
		if (too_large) {
			g_set_error(err, rspamd_stat_quark(), 204,
						"<%s> contains more tokens than allowed for %s classifier: "
						"%d > %d",
						MESSAGE_FIELD(task, message_id),
						sel->cfg->name,
						task->tokens->len,
						sel->cfg->max_tokens);
		}
		else if (too_small) {
			g_set_error(err, rspamd_stat_quark(), 204,
						"<%s> contains less tokens than required for %s classifier: "
						"%d < %d",
						MESSAGE_FIELD(task, message_id),
						sel->cfg->name,
						task->tokens->len,
						sel->cfg->min_tokens);
		}
	}

	return learned;
}

rspamd_stat_result_t
rspamd_stat_learn_class(struct rspamd_task *task,
						const char *class_name,
						lua_State *L,
						const char *classifier,
						unsigned int stage,
						GError **err)
{
	struct rspamd_stat_ctx *st_ctx;
	rspamd_stat_result_t ret = RSPAMD_STAT_PROCESS_OK;

	/*
	 * We assume now that a task has been already classified before
	 * coming to learn
	 */
	g_assert(RSPAMD_TASK_IS_CLASSIFIED(task));

	st_ctx = rspamd_stat_get_ctx();
	g_assert(st_ctx != NULL);

	msg_debug_bayes("learn class stage %d has been called for class '%s'", stage, class_name);

	if (st_ctx->classifiers->len == 0) {
		msg_debug_bayes("no classifiers defined");
		task->processed_stages |= stage;
		return ret;
	}

	if (task->message == NULL) {
		ret = RSPAMD_STAT_PROCESS_ERROR;
		if (err && *err == NULL) {
			g_set_error(err, rspamd_stat_quark(), 500,
						"Trying to learn an empty message");
		}

		task->processed_stages |= stage;
		return ret;
	}

	if (stage == RSPAMD_TASK_STAGE_LEARN_PRE) {
		/* Validate that the requested class exists in (at least one statfile of) the
		 * target classifier(s) before doing any further work such as tokenisation,
		 * running learn-conditions, or hitting the cache.  Failing early avoids the
		 * confusing situation where /learnham returns success on a multiclass
		 * classifier that has no "ham" statfile. */
		gboolean class_valid = FALSE;
		for (unsigned int ci = 0; ci < st_ctx->classifiers->len; ci++) {
			struct rspamd_classifier *cl = g_ptr_array_index(st_ctx->classifiers, ci);
			if (classifier != NULL && (cl->cfg->name == NULL ||
					g_ascii_strcasecmp(classifier, cl->cfg->name) != 0)) {
				continue;
			}
			for (unsigned int si = 0; si < cl->statfiles_ids->len; si++) {
				int sid = g_array_index(cl->statfiles_ids, int, si);
				struct rspamd_statfile *st = g_ptr_array_index(st_ctx->statfiles, sid);
				if (st->stcf->class_name &&
						strcmp(st->stcf->class_name, class_name) == 0) {
					class_valid = TRUE;
					break;
				}
			}
			if (class_valid) break;
		}
		if (!class_valid) {
			if (err && *err == NULL) {
				g_set_error(err, rspamd_stat_quark(), 404,
							"class '%s' is not defined in classifier %s",
							class_name,
							classifier ? classifier : "(any)");
			}
			task->processed_stages |= stage;
			return RSPAMD_STAT_PROCESS_ERROR;
		}

		/* Ensure cache comparison uses the exact class we are about to learn */
		rspamd_task_set_autolearn_class(task, class_name);
		/* Process classifiers - determine spam boolean for compatibility */
		gboolean spam = (strcmp(class_name, "spam") == 0 || strcmp(class_name, "S") == 0);
		rspamd_stat_preprocess(st_ctx, task, TRUE, spam);

		if (!rspamd_stat_cache_check(st_ctx, task, classifier, spam, err)) {
			msg_debug_bayes("pre-learn checks failed, skip learning");
			return RSPAMD_STAT_PROCESS_ERROR;
		}
	}
	else if (stage == RSPAMD_TASK_STAGE_LEARN) {
		/* Process classifiers */
		if (!rspamd_stat_classifiers_learn_class(st_ctx, task, classifier,
												 class_name, err)) {
			if (err && *err == NULL) {
				g_set_error(err, rspamd_stat_quark(), 500,
							"Unknown statistics error, found when learning classifiers;"
							" classifier: %s",
							task->classifier);
			}
			return RSPAMD_STAT_PROCESS_ERROR;
		}

		/* Process backends - determine spam boolean for compatibility */
		gboolean spam = (strcmp(class_name, "spam") == 0 || strcmp(class_name, "S") == 0);
		if (!rspamd_stat_backends_learn(st_ctx, task, classifier, spam, err)) {
			if (err && *err == NULL) {
				g_set_error(err, rspamd_stat_quark(), 500,
							"Unknown statistics error, found when storing data on backend;"
							" classifier: %s",
							task->classifier);
			}
			return RSPAMD_STAT_PROCESS_ERROR;
		}
	}
	else if (stage == RSPAMD_TASK_STAGE_LEARN_POST) {
		/* Process backends - determine spam boolean for compatibility */
		gboolean spam = (strcmp(class_name, "spam") == 0 || strcmp(class_name, "S") == 0);
		if (!rspamd_stat_backends_post_learn(st_ctx, task, classifier, spam, err)) {
			return RSPAMD_STAT_PROCESS_ERROR;
		}
	}

	task->processed_stages |= stage;

	return ret;
}

rspamd_stat_result_t
rspamd_stat_learn(struct rspamd_task *task,
				  gboolean spam, lua_State *L, const char *classifier, unsigned int stage,
				  GError **err)
{
	struct rspamd_stat_ctx *st_ctx;
	rspamd_stat_result_t ret = RSPAMD_STAT_PROCESS_OK;

	/*
	 * We assume now that a task has been already classified before
	 * coming to learn
	 */
	g_assert(RSPAMD_TASK_IS_CLASSIFIED(task));

	st_ctx = rspamd_stat_get_ctx();
	g_assert(st_ctx != NULL);

	msg_debug_bayes("learn stage %d has been called", stage);

	if (st_ctx->classifiers->len == 0) {
		msg_debug_bayes("no classifiers defined");
		task->processed_stages |= stage;
		return ret;
	}


	if (task->message == NULL) {
		ret = RSPAMD_STAT_PROCESS_ERROR;
		if (err && *err == NULL) {
			g_set_error(err, rspamd_stat_quark(), 500,
						"Trying to learn an empty message");
		}

		task->processed_stages |= stage;
		return ret;
	}

	if (stage == RSPAMD_TASK_STAGE_LEARN_PRE) {
		/* Ensure cache comparison uses the exact class we are about to learn */
		rspamd_task_set_autolearn_class(task, spam ? "spam" : "ham");
		/* Process classifiers */
		rspamd_stat_preprocess(st_ctx, task, TRUE, spam);

		if (!rspamd_stat_cache_check(st_ctx, task, classifier, spam, err)) {
			msg_debug_bayes("pre-learn checks failed, skip learning");
			return RSPAMD_STAT_PROCESS_ERROR;
		}
	}
	else if (stage == RSPAMD_TASK_STAGE_LEARN) {
		/* Process classifiers */
		if (!rspamd_stat_classifiers_learn(st_ctx, task, classifier,
										   spam, err)) {
			if (err && *err == NULL) {
				g_set_error(err, rspamd_stat_quark(), 500,
							"Unknown statistics error, found when learning classifiers;"
							" classifier: %s",
							task->classifier);
			}
			return RSPAMD_STAT_PROCESS_ERROR;
		}

		/* Process backends */
		if (!rspamd_stat_backends_learn(st_ctx, task, classifier, spam, err)) {
			if (err && *err == NULL) {
				g_set_error(err, rspamd_stat_quark(), 500,
							"Unknown statistics error, found when storing data on backend;"
							" classifier: %s",
							task->classifier);
			}
			return RSPAMD_STAT_PROCESS_ERROR;
		}
	}
	else if (stage == RSPAMD_TASK_STAGE_LEARN_POST) {
		if (!rspamd_stat_backends_post_learn(st_ctx, task, classifier, spam, err)) {
			return RSPAMD_STAT_PROCESS_ERROR;
		}
	}

	task->processed_stages |= stage;

	return ret;
}

static gboolean
rspamd_stat_has_classifier_symbols(struct rspamd_task *task,
								   struct rspamd_scan_result *mres,
								   struct rspamd_classifier *cl)
{
	unsigned int i;
	int id;
	struct rspamd_statfile *st;
	struct rspamd_stat_ctx *st_ctx;
	gboolean is_spam;

	if (mres == NULL) {
		return FALSE;
	}

	st_ctx = rspamd_stat_get_ctx();
	is_spam = !!(task->flags & RSPAMD_TASK_FLAG_LEARN_SPAM);

	for (i = 0; i < cl->statfiles_ids->len; i++) {
		id = g_array_index(cl->statfiles_ids, int, i);
		st = g_ptr_array_index(st_ctx->statfiles, id);

		if (rspamd_task_find_symbol_result(task, st->stcf->symbol, NULL)) {
			if (is_spam == !!st->stcf->is_spam) {
				msg_debug_bayes("do not autolearn %s as symbol %s is already "
								"added",
								is_spam ? "spam" : "ham", st->stcf->symbol);

				return TRUE;
			}
		}
	}

	return FALSE;
}

gboolean
rspamd_stat_check_autolearn(struct rspamd_task *task)
{
	struct rspamd_stat_ctx *st_ctx;
	struct rspamd_classifier *cl;
	const ucl_object_t *obj, *elt1, *elt2;
	struct rspamd_scan_result *mres = task->result;
	struct rspamd_task **ptask;
	lua_State *L;
	unsigned int i;
	int err_idx;
	gboolean ret = FALSE;
	double ham_score, spam_score;
	const char *lua_script, *lua_ret;

	g_assert(RSPAMD_TASK_IS_CLASSIFIED(task));
	st_ctx = rspamd_stat_get_ctx();
	g_assert(st_ctx != NULL);

	L = task->cfg->lua_state;

	for (i = 0; i < st_ctx->classifiers->len; i++) {
		cl = g_ptr_array_index(st_ctx->classifiers, i);
		ret = FALSE;

		rspamd_mempool_set_variable(task->task_pool, RSPAMD_MEMPOOL_HAM_LEARNS, (void *) &cl->ham_learns, NULL);
		rspamd_mempool_set_variable(task->task_pool, RSPAMD_MEMPOOL_SPAM_LEARNS, (void *) &cl->spam_learns, NULL);

		if (cl->cfg->opts) {
			obj = ucl_object_lookup(cl->cfg->opts, "autolearn");

			if (ucl_object_type(obj) == UCL_BOOLEAN) {
				/* Legacy true/false */
				if (ucl_object_toboolean(obj)) {
					/*
					 * Default learning algorithm:
					 *
					 * - We learn spam if action is ACTION_REJECT
					 * - We learn ham if score is less than zero
					 */

					if (mres) {
						if (mres->score > rspamd_task_get_required_score(task, mres)) {
							rspamd_task_set_autolearn_class(task, "spam");
							ret = TRUE;
						}
						else if (mres->score < 0) {
							rspamd_task_set_autolearn_class(task, "ham");
							ret = TRUE;
						}
					}
				}
			}
			else if (ucl_object_type(obj) == UCL_ARRAY && obj->len == 2) {
				/* Legacy thresholds */
				/*
				 * We have an array of 2 elements, treat it as a
				 * ham_score, spam_score
				 */
				elt1 = ucl_array_find_index(obj, 0);
				elt2 = ucl_array_find_index(obj, 1);

				if ((ucl_object_type(elt1) == UCL_FLOAT ||
					 ucl_object_type(elt1) == UCL_INT) &&
					(ucl_object_type(elt2) == UCL_FLOAT ||
					 ucl_object_type(elt2) == UCL_INT)) {
					ham_score = ucl_object_todouble(elt1);
					spam_score = ucl_object_todouble(elt2);

					if (ham_score > spam_score) {
						double t;

						t = ham_score;
						ham_score = spam_score;
						spam_score = t;
					}

					if (mres) {
						if (mres->score >= spam_score) {
							rspamd_task_set_autolearn_class(task, "spam");
							ret = TRUE;
						}
						else if (mres->score <= ham_score) {
							rspamd_task_set_autolearn_class(task, "ham");
							ret = TRUE;
						}
					}
				}
			}
			else if (ucl_object_type(obj) == UCL_STRING) {
				/* Legacy script */
				lua_script = ucl_object_tostring(obj);

				if (luaL_dostring(L, lua_script) != 0) {
					msg_err_task("cannot execute lua script for autolearn "
								 "extraction: %s",
								 lua_tostring(L, -1));
				}
				else {
					if (lua_type(L, -1) == LUA_TFUNCTION) {
						lua_pushcfunction(L, &rspamd_lua_traceback);
						err_idx = lua_gettop(L);
						lua_pushvalue(L, -2); /* Function itself */

						ptask = lua_newuserdata(L, sizeof(struct rspamd_task *));
						*ptask = task;
						rspamd_lua_setclass(L, rspamd_task_classname, -1);

						if (lua_pcall(L, 1, 1, err_idx) != 0) {
							msg_err_task("call to autolearn script failed: "
										 "%s",
										 lua_tostring(L, -1));
						}
						else {
							lua_ret = lua_tostring(L, -1);

							/* We can have immediate results */
							if (lua_ret) {
								if (strcmp(lua_ret, "ham") == 0) {
									rspamd_task_set_autolearn_class(task, "ham");
									ret = TRUE;
								}
								else if (strcmp(lua_ret, "spam") == 0) {
									rspamd_task_set_autolearn_class(task, "spam");
									ret = TRUE;
								}
								else {
									/* Multi-class: any other class name */
									rspamd_task_set_autolearn_class(task, lua_ret);
									ret = TRUE;
								}
							}
						}

						/* Result + error function + original function */
						lua_pop(L, 3);
					}
					else {
						msg_err_task("lua script must return "
									 "function(task) and not %s",
									 lua_typename(L, lua_type(
														 L, -1)));
					}
				}
			}
			else if (ucl_object_type(obj) == UCL_OBJECT) {
				/* Check if this is a multi-class autolearn configuration */
				const ucl_object_t *multiclass_obj = ucl_object_lookup(obj, "multiclass");

				if (multiclass_obj && ucl_object_type(multiclass_obj) == UCL_OBJECT) {
					/* Multi-class threshold-based autolearn */
					const ucl_object_t *thresholds_obj = ucl_object_lookup(multiclass_obj, "thresholds");

					if (thresholds_obj && ucl_object_type(thresholds_obj) == UCL_OBJECT) {
						/* Iterate through class thresholds */
						ucl_object_iter_t it = NULL;
						const ucl_object_t *class_obj;
						const char *class_name;

						while ((class_obj = ucl_object_iterate(thresholds_obj, &it, true))) {
							class_name = ucl_object_key(class_obj);

							if (class_name && ucl_object_type(class_obj) == UCL_ARRAY && class_obj->len == 2) {
								/* [min_score, max_score] for this class */
								const ucl_object_t *min_elt = ucl_array_find_index(class_obj, 0);
								const ucl_object_t *max_elt = ucl_array_find_index(class_obj, 1);

								if ((ucl_object_type(min_elt) == UCL_FLOAT || ucl_object_type(min_elt) == UCL_INT) &&
									(ucl_object_type(max_elt) == UCL_FLOAT || ucl_object_type(max_elt) == UCL_INT)) {

									double min_score = ucl_object_todouble(min_elt);
									double max_score = ucl_object_todouble(max_elt);

									if (mres && mres->score >= min_score && mres->score <= max_score) {
										rspamd_task_set_autolearn_class(task, class_name);
										ret = TRUE;
										msg_debug_bayes("multiclass autolearn: score %.2f matches class '%s' [%.2f, %.2f]",
														mres->score, class_name, min_score, max_score);
										break; /* Stop at first matching class */
									}
								}
							}
						}
					}
				}
				else {
					/* Try to find autolearn callback */
					if (cl->autolearn_cbref == 0) {
						/* We don't have preprocessed cb id, so try to get it */
						if (!rspamd_lua_require_function(L, "lua_bayes_learn",
														 "autolearn")) {
							msg_err_task("cannot get autolearn library from "
										 "`lua_bayes_learn`");
						}
						else {
							cl->autolearn_cbref = luaL_ref(L, LUA_REGISTRYINDEX);
						}
					}

					if (cl->autolearn_cbref != -1) {
						lua_pushcfunction(L, &rspamd_lua_traceback);
						err_idx = lua_gettop(L);
						lua_rawgeti(L, LUA_REGISTRYINDEX, cl->autolearn_cbref);

						ptask = lua_newuserdata(L, sizeof(struct rspamd_task *));
						*ptask = task;
						rspamd_lua_setclass(L, rspamd_task_classname, -1);
						/* Push the whole object as well */
						ucl_object_push_lua(L, obj, true);

						if (lua_pcall(L, 2, 1, err_idx) != 0) {
							msg_err_task("call to autolearn script failed: "
										 "%s",
										 lua_tostring(L, -1));
						}
						else {
							lua_ret = lua_tostring(L, -1);

							if (lua_ret) {
								if (strcmp(lua_ret, "ham") == 0) {
									rspamd_task_set_autolearn_class(task, "ham");
									ret = TRUE;
								}
								else if (strcmp(lua_ret, "spam") == 0) {
									rspamd_task_set_autolearn_class(task, "spam");
									ret = TRUE;
								}
								else {
									/* Multi-class: any other class name */
									rspamd_task_set_autolearn_class(task, lua_ret);
									ret = TRUE;
								}
							}
						}

						lua_settop(L, err_idx - 1);
					}
				}

				if (ret) {
					/* Do not autolearn if we have this symbol already */
					if (rspamd_stat_has_classifier_symbols(task, mres, cl)) {
						ret = FALSE;
						task->flags &= ~(RSPAMD_TASK_FLAG_LEARN_HAM |
										 RSPAMD_TASK_FLAG_LEARN_SPAM |
										 RSPAMD_TASK_FLAG_LEARN_CLASS);
						/* Clear the autolearn class from mempool */
						rspamd_mempool_set_variable(task->task_pool, "autolearn_class", NULL, NULL);
					}
					else if (mres != NULL) {
						const char *autolearn_class = rspamd_task_get_autolearn_class(task);

						if (autolearn_class) {
							if (strcmp(autolearn_class, "ham") == 0) {
								msg_info_task("<%s>: autolearn ham for classifier "
											  "'%s' as message's "
											  "score is negative: %.2f",
											  MESSAGE_FIELD(task, message_id), cl->cfg->name,
											  mres->score);
							}
							else if (strcmp(autolearn_class, "spam") == 0) {
								msg_info_task("<%s>: autolearn spam for classifier "
											  "'%s' as message's "
											  "action is reject, score: %.2f",
											  MESSAGE_FIELD(task, message_id), cl->cfg->name,
											  mres->score);
							}
							else {
								msg_info_task("<%s>: autolearn class '%s' for classifier "
											  "'%s', score: %.2f",
											  MESSAGE_FIELD(task, message_id), autolearn_class,
											  cl->cfg->name, mres->score);
							}
						}

						task->classifier = cl->cfg->name;
						break;
					}
				}
			}
		}
	}

	return ret;
}

static gboolean
rspamd_classifier_is_per_user(const struct rspamd_classifier_config *cfg)
{
	const ucl_object_t *users_enabled;

	if (cfg == NULL || cfg->opts == NULL) {
		return FALSE;
	}

	users_enabled = ucl_object_lookup_any(cfg->opts, "per_user",
			"users_enabled", NULL);
	if (users_enabled == NULL) {
		return FALSE;
	}

	if (ucl_object_type(users_enabled) == UCL_BOOLEAN) {
		return ucl_object_toboolean(users_enabled);
	}

	return TRUE;
}

static const char *
rspamd_classifier_type(const struct rspamd_classifier_config *cfg)
{
	gboolean has_spam = FALSE;
	gboolean has_ham = FALSE;
	gboolean has_other = FALSE;
	gboolean has_explicit_classes = FALSE;
	GList *cur;

	if (cfg == NULL) {
		return "binary";
	}

	for (cur = cfg->statfiles; cur != NULL; cur = g_list_next(cur)) {
		struct rspamd_statfile_config *stcf = cur->data;

		if (stcf == NULL || stcf->class_name == NULL) {
			has_other = TRUE;
			continue;
		}

		if (!stcf->is_spam_converted) {
			has_explicit_classes = TRUE;
		}

		if (g_ascii_strcasecmp(stcf->class_name, "spam") == 0) {
			has_spam = TRUE;
		}
		else if (g_ascii_strcasecmp(stcf->class_name, "ham") == 0) {
			has_ham = TRUE;
		}
		else {
			has_other = TRUE;
		}
	}

	/* If any statfile has explicit class (not converted from is_spam) */
	if (has_explicit_classes) {
		return "multi-class";
	}

	/* Legacy binary: spam=true/false converted to class names */
	if (has_spam && has_ham && !has_other) {
		return "binary";
	}

	/* Empty classifier (no statfiles) defaults to binary */
	if (!has_spam && !has_ham && !has_other) {
		return "binary";
	}

	return "multi-class";
}

/**
 * Get the overall statistics for all statfile backends
 * @param cfg configuration
 * @param total_learns the total number of learns is stored here
 * @return array of statistical information
 */
rspamd_stat_result_t
rspamd_stat_statistics(struct rspamd_task *task,
					   struct rspamd_config *cfg,
					   uint64_t *total_learns,
					   ucl_object_t **target)
{
	struct rspamd_stat_ctx *st_ctx;
	struct rspamd_classifier *cl;
	struct rspamd_statfile *st;
	gpointer backend_runtime;
	ucl_object_t *res = NULL, *elt;
	uint64_t learns = 0;
	const char *classifier_name;
	const char *classifier_type;
	gboolean classifier_per_user;
	unsigned int i, j;
	int id;

	st_ctx = rspamd_stat_get_ctx();
	g_assert(st_ctx != NULL);

	res = ucl_object_typed_new(UCL_ARRAY);

	for (i = 0; i < st_ctx->classifiers->len; i++) {
		cl = g_ptr_array_index(st_ctx->classifiers, i);

		if (cl->cfg->flags & RSPAMD_FLAG_CLASSIFIER_NO_BACKEND) {
			continue;
		}

		classifier_name = cl->cfg->name;
		classifier_type = rspamd_classifier_type(cl->cfg);
		classifier_per_user = rspamd_classifier_is_per_user(cl->cfg);

		for (j = 0; j < cl->statfiles_ids->len; j++) {
			id = g_array_index(cl->statfiles_ids, int, j);
			st = g_ptr_array_index(st_ctx->statfiles, id);
			backend_runtime = st->backend->runtime(task, st->stcf, FALSE,
												   st->bkcf, id);
			elt = st->backend->get_stat(backend_runtime, st->bkcf);

			if (elt && ucl_object_type(elt) == UCL_OBJECT) {
				const ucl_object_t *rev = ucl_object_lookup(elt, "revision");
				ucl_object_t *elt_copy, *classifier_obj;

				/* Create new object and copy fields from original (avoiding cached object modification) */
				elt_copy = ucl_object_typed_new(UCL_OBJECT);
				{
					ucl_object_iter_t it = NULL;
					const ucl_object_t *cur;
					const char *key;

					while ((cur = ucl_object_iterate(elt, &it, true))) {
						key = ucl_object_key(cur);
						/* Skip classifier and class keys if they exist */
						if (key && strcmp(key, "classifier") != 0 && strcmp(key, "class") != 0) {
							ucl_object_insert_key(elt_copy, ucl_object_ref(cur), key, 0, true);
						}
					}
				}
				ucl_object_unref(elt);
				elt = elt_copy;

				/* Add classifier metadata */
				classifier_obj = ucl_object_typed_new(UCL_OBJECT);
				ucl_object_insert_key(classifier_obj,
						ucl_object_fromstring(classifier_name),
						"name", 0, false);
				ucl_object_insert_key(classifier_obj,
						ucl_object_fromstring(classifier_type),
						"type", 0, false);
				ucl_object_insert_key(classifier_obj,
						ucl_object_frombool(classifier_per_user),
						"per_user", 0, false);

				ucl_object_insert_key(elt, classifier_obj, "classifier", 0, false);

				if (st->stcf->class_name) {
					ucl_object_insert_key(elt,
							ucl_object_fromstring(st->stcf->class_name),
							"class", 0, false);
				}

				learns += ucl_object_toint(rev);
			}
			else {
				learns += st->backend->total_learns(task, backend_runtime,
													st->bkcf);
			}

			if (elt != NULL) {
				ucl_array_append(res, elt);
			}
		}
	}

	if (total_learns != NULL) {
		*total_learns = learns;
	}

	if (target) {
		*target = res;
	}
	else {
		ucl_object_unref(res);
	}

	return RSPAMD_STAT_PROCESS_OK;
}
