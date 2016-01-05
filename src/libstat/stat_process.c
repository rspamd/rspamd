/* Copyright (c) 2015-2016, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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

#include "config.h"
#include "stat_api.h"
#include "rspamd.h"
#include "stat_internal.h"
#include "libmime/message.h"
#include "libmime/images.h"
#include "libserver/html.h"
#include "lua/lua_common.h"
#include <utlist.h>

#define RSPAMD_CLASSIFY_OP 0
#define RSPAMD_LEARN_OP 1
#define RSPAMD_UNLEARN_OP 2

static const gint similarity_treshold = 80;

static void
rspamd_stat_tokenize_header (struct rspamd_task *task,
		const gchar *name, const gchar *prefix, GArray *ar)
{
	struct raw_header *rh, *cur;
	rspamd_ftok_t str;

	rh = g_hash_table_lookup (task->raw_headers, name);

	if (rh != NULL) {

		LL_FOREACH (rh, cur) {
			if (cur->name != NULL) {
				str.begin = cur->name;
				str.len = strlen (cur->name);
				g_array_append_val (ar, str);
			}
			if (cur->decoded != NULL) {
				str.begin = cur->decoded;
				str.len = strlen (cur->decoded);
				g_array_append_val (ar, str);
			}
			else if (cur->value != NULL) {
				str.begin = cur->value;
				str.len = strlen (cur->value);
				g_array_append_val (ar, str);
			}
		}

		msg_debug_task ("added stat tokens for header '%s'", name);
	}
}

static void
rspamd_stat_tokenize_parts_metadata (struct rspamd_stat_ctx *st_ctx,
		struct rspamd_task *task)
{
	struct rspamd_image *img;
	struct mime_part *part;
	struct mime_text_part *tp;
	GList *cur;
	GArray *ar;
	rspamd_ftok_t elt;
	guint i;

	ar = g_array_sized_new (FALSE, FALSE, sizeof (elt), 4);

	/* Insert images */
	cur = g_list_first (task->images);

	while (cur) {
		img = cur->data;

		/* If an image has a linked HTML part, then we push its details to the stat */
		if (img->html_image) {
			elt.begin = (gchar *)"image";
			elt.len = 5;
			g_array_append_val (ar, elt);
			elt.begin = (gchar *)&img->html_image->height;
			elt.len = sizeof (img->html_image->height);
			g_array_append_val (ar, elt);
			elt.begin = (gchar *)&img->html_image->width;
			elt.len = sizeof (img->html_image->width);
			g_array_append_val (ar, elt);
			elt.begin = (gchar *)&img->type;
			elt.len = sizeof (img->type);
			g_array_append_val (ar, elt);

			if (img->filename) {
				elt.begin = (gchar *)img->filename;
				elt.len = strlen (elt.begin);
				g_array_append_val (ar, elt);
			}

			msg_debug_task ("added stat tokens for image '%s'", img->html_image->src);
		}

		cur = g_list_next (cur);
	}

	/* Process mime parts */
	for (i = 0; i < task->parts->len; i ++) {
		part = g_ptr_array_index (task->parts, i);

		if (GMIME_IS_MULTIPART (part->mime)) {
			elt.begin = (gchar *)g_mime_multipart_get_boundary (
					GMIME_MULTIPART (part->mime));

			if (elt.begin) {
				elt.len = strlen (elt.begin);
				msg_debug_task ("added stat tokens for mime boundary '%s'", elt.begin);
				g_array_append_val (ar, elt);
			}
		}
	}

	/* Process text parts metadata */
	for (i = 0; i < task->text_parts->len; i ++) {
		tp = g_ptr_array_index (task->text_parts, i);

		if (tp->language != NULL && tp->language[0] != '\0') {
			elt.begin = (gchar *)tp->language;
			elt.len = strlen (elt.begin);
			msg_debug_task ("added stat tokens for part language '%s'", elt.begin);
			g_array_append_val (ar, elt);
		}
		if (tp->real_charset != NULL) {
			elt.begin = (gchar *)tp->real_charset;
			elt.len = strlen (elt.begin);
			msg_debug_task ("added stat tokens for part charset '%s'", elt.begin);
			g_array_append_val (ar, elt);
		}
	}

	cur = g_list_first (task->cfg->classify_headers);

	while (cur) {
		rspamd_stat_tokenize_header (task, cur->data, "UA:", ar);

		cur = g_list_next (cur);
	}

	st_ctx->tokenizer->tokenize_func (st_ctx,
			task->task_pool,
			ar,
			TRUE,
			"META:",
			task->tokens);

	g_array_free (ar, TRUE);
}

/*
 * Tokenize task using the tokenizer specified
 */
static void
rspamd_stat_process_tokenize (struct rspamd_stat_ctx *st_ctx,
		struct rspamd_task *task)
{
	struct mime_text_part *part;
	GArray *words;
	gchar *sub;
	guint i, reserved_len = 0;
	gint *pdiff;

	for (i = 0; i < task->text_parts->len; i++) {
		part = g_ptr_array_index (task->text_parts, i);

		if (!IS_PART_EMPTY (part) && part->normalized_words != NULL) {
			reserved_len += part->normalized_words->len;
		}
		/* XXX: normal window size */
		reserved_len += 5;
	}

	task->tokens = g_ptr_array_sized_new (reserved_len);
	rspamd_mempool_add_destructor (task->task_pool,
			rspamd_ptr_array_free_hard, task->tokens);
	pdiff = rspamd_mempool_get_variable (task->task_pool, "parts_distance");

	for (i = 0; i < task->text_parts->len; i ++) {
		part = g_ptr_array_index (task->text_parts, i);

		if (!IS_PART_EMPTY (part) && part->normalized_words != NULL) {
			st_ctx->tokenizer->tokenize_func (st_ctx, task->task_pool,
					part->normalized_words, IS_PART_UTF (part),
					NULL, task->tokens);
		}


		if (pdiff != NULL && *pdiff > similarity_treshold) {
			msg_debug_task ("message has two common parts (%d%%), so skip the last one",
					*pdiff);
			break;
		}
	}

	if (task->subject != NULL) {
		sub = task->subject;
	}
	else {
		sub = (gchar *)g_mime_message_get_subject (task->message);
	}

	if (sub != NULL) {
		words = rspamd_tokenize_text (sub, strlen (sub), TRUE, NULL, NULL, FALSE,
				NULL);
		if (words != NULL) {
			st_ctx->tokenizer->tokenize_func (st_ctx,
					task->task_pool,
					words,
					TRUE,
					"SUBJECT",
					task->tokens);
			g_array_free (words, TRUE);
		}
	}

	rspamd_stat_tokenize_parts_metadata (st_ctx, task);
}

static void
rspamd_stat_preprocess (struct rspamd_stat_ctx *st_ctx,
		struct rspamd_task *task, gboolean learn)
{
	guint i;
	struct rspamd_statfile *st;
	gpointer bk_run;

	rspamd_stat_process_tokenize (st_ctx, task);
	task->stat_runtimes = g_ptr_array_sized_new (st_ctx->statfiles->len);
	rspamd_mempool_add_destructor (task->task_pool,
			rspamd_ptr_array_free_hard, task->stat_runtimes);

	for (i = 0; i < st_ctx->statfiles->len; i ++) {
		st = g_ptr_array_index (st_ctx->statfiles, i);
		g_assert (st != NULL);

		bk_run = st->backend->runtime (task, st->stcf, learn, st->bkcf);

		if (bk_run == NULL) {
			msg_err_task ("cannot init backend %s for statfile %s",
					st->backend->name, st->stcf->symbol);
		}

		g_ptr_array_add (task->stat_runtimes, bk_run);
	}
}

static void
rspamd_stat_backends_process (struct rspamd_stat_ctx *st_ctx,
		struct rspamd_task *task)
{
	guint i;
	struct rspamd_statfile *st;
	struct rspamd_classifier *cl;
	gpointer bk_run;

	g_assert (task->stat_runtimes != NULL);

	for (i = 0; i < st_ctx->statfiles->len; i++) {
		st = g_ptr_array_index (st_ctx->statfiles, i);
		bk_run = g_ptr_array_index (task->stat_runtimes, i);
		cl = st->classifier;
		g_assert (st != NULL);

		if (bk_run != NULL) {
			st->backend->process_tokens (task, task->tokens, i, bk_run);

			if (st->stcf->is_spam) {
				cl->spam_learns = st->backend->total_learns (task,
						bk_run,
						st_ctx);
			}
			else {
				cl->ham_learns = st->backend->total_learns (task,
						bk_run,
						st_ctx);
			}
		}
	}
}

static void
rspamd_stat_backends_post_process (struct rspamd_stat_ctx *st_ctx,
		struct rspamd_task *task)
{
	guint i;
	struct rspamd_statfile *st;
	gpointer bk_run;

	g_assert (task->stat_runtimes != NULL);

	for (i = 0; i < st_ctx->statfiles->len; i++) {
		st = g_ptr_array_index (st_ctx->statfiles, i);
		bk_run = g_ptr_array_index (task->stat_runtimes, i);
		g_assert (st != NULL);

		if (bk_run != NULL) {
			st->backend->finalize_process (task, bk_run, st_ctx);
		}
	}
}

static void
rspamd_stat_classifiers_process (struct rspamd_stat_ctx *st_ctx,
		struct rspamd_task *task)
{
	guint i;
	struct rspamd_classifier *cl;

	for (i = 0; i < st_ctx->classifiers->len; i++) {
		cl = g_ptr_array_index (st_ctx->classifiers, i);
		g_assert (cl != NULL);

		cl->subrs->classify_func (cl, task->tokens, task);
	}
}

rspamd_stat_result_t
rspamd_stat_classify (struct rspamd_task *task, lua_State *L, guint stage,
		GError **err)
{
	struct rspamd_stat_ctx *st_ctx;
	rspamd_stat_result_t ret = RSPAMD_STAT_PROCESS_OK;

	st_ctx = rspamd_stat_get_ctx ();
	g_assert (st_ctx != NULL);


	if (stage == RSPAMD_TASK_STAGE_CLASSIFIERS_PRE) {
		/* Preprocess tokens */
		rspamd_stat_preprocess (st_ctx, task, FALSE);
	}
	else if (stage == RSPAMD_TASK_STAGE_CLASSIFIERS) {
		/* Process backends */
		rspamd_stat_backends_process (st_ctx, task);
	}
	else if (stage == RSPAMD_TASK_STAGE_CLASSIFIERS_POST) {
		/* Process classifiers */
		rspamd_stat_backends_post_process (st_ctx, task);
		rspamd_stat_classifiers_process (st_ctx, task);
	}

	return ret;
}

#if 0
static gboolean
rspamd_stat_learn_token (gpointer k, gpointer v, gpointer d)
{
	rspamd_token_t *t = (rspamd_token_t *)v;
	struct preprocess_cb_data *cbdata = (struct preprocess_cb_data *)d;
	struct rspamd_statfile_runtime *st_runtime;
	struct rspamd_classifier_runtime *cl_runtime;
	struct rspamd_token_result *res;
	struct rspamd_task *task;
	GList *cur, *curst;
	gint i = 0;

	task = cbdata->task;
	cur = g_list_first (cbdata->classifier_runtimes);

	while (cur) {
		cl_runtime = (struct rspamd_classifier_runtime *)cur->data;

		if (cl_runtime->clcf->min_tokens > 0 &&
				(guint32)g_tree_nnodes (cbdata->tok->tokens) < cl_runtime->clcf->min_tokens) {
			/* Skip this classifier */
			msg_debug_task ("<%s> contains less tokens than required for %s classifier: "
					"%ud < %ud", cbdata->task->message_id, cl_runtime->clcf->name,
					g_tree_nnodes (cbdata->tok->tokens),
					cl_runtime->clcf->min_tokens);
			cur = g_list_next (cur);
			continue;
		}

		curst = cl_runtime->st_runtime;

		while (curst) {
			res = &g_array_index (t->results, struct rspamd_token_result, i);
			st_runtime = (struct rspamd_statfile_runtime *)curst->data;

			if (cl_runtime->backend->learn_token (cbdata->task, t, res,
					cl_runtime->backend->ctx)) {
				cl_runtime->processed_tokens ++;

				if (cl_runtime->clcf->max_tokens > 0 &&
						cl_runtime->processed_tokens > cl_runtime->clcf->max_tokens) {
					msg_debug_task ("message contains more tokens than allowed for %s classifier: "
							"%uL > %ud", cl_runtime->clcf->name,
							cl_runtime->processed_tokens,
							cl_runtime->clcf->max_tokens);

					return TRUE;
				}
			}

			i ++;
			curst = g_list_next (curst);
		}

		cur = g_list_next (cur);
	}


	return FALSE;
}

rspamd_stat_result_t
rspamd_stat_learn (struct rspamd_task *task,
		gboolean spam,
		lua_State *L,
		const gchar *classifier,
		GError **err)
{
	struct rspamd_stat_ctx *st_ctx;
	struct rspamd_classifier_runtime *cl_run;
	struct rspamd_statfile_runtime *st_run;
	struct classifier_ctx *cl_ctx;
	struct preprocess_cb_data cbdata;
	GList *cl_runtimes;
	GList *cur, *curst;
	gboolean unlearn = FALSE;
	rspamd_stat_result_t ret = RSPAMD_STAT_PROCESS_ERROR;
	gulong nrev;
	rspamd_learn_t learn_res = RSPAMD_LEARN_OK;
	guint i;
	gboolean learned = FALSE;

	st_ctx = rspamd_stat_get_ctx ();
	g_assert (st_ctx != NULL);

	cur = g_list_first (task->cfg->classifiers);

	/* Check whether we have learned that file */
	for (i = 0; i < st_ctx->caches_count; i ++) {
		learn_res = st_ctx->caches[i].process (task, spam,
				st_ctx->caches[i].ctx);

		if (learn_res == RSPAMD_LEARN_INGORE) {
			/* Do not learn twice */
			g_set_error (err, rspamd_stat_quark (), 404, "<%s> has been already "
					"learned as %s, ignore it", task->message_id,
					spam ? "spam" : "ham");
			return RSPAMD_STAT_PROCESS_ERROR;
		}
		else if (learn_res == RSPAMD_LEARN_UNLEARN) {
			unlearn = TRUE;
		}
	}

	/* Initialize classifiers and statfiles runtime */
	if ((cl_runtimes = rspamd_stat_preprocess (st_ctx,
			task,
			L,
			unlearn ? RSPAMD_UNLEARN_OP : RSPAMD_LEARN_OP,
			spam,
			classifier,
			err)) == NULL) {
		return RSPAMD_STAT_PROCESS_ERROR;
	}

	cur = cl_runtimes;

	while (cur) {
		cl_run = (struct rspamd_classifier_runtime *)cur->data;

		curst = cl_run->st_runtime;

		/* Needed to finalize pre-process stage */
		while (curst) {
			st_run = curst->data;
			cl_run->backend->finalize_process (task,
					st_run->backend_runtime,
					cl_run->backend->ctx);
			curst = g_list_next (curst);
		}

		if (cl_run->skipped) {
			msg_info_task (
					"<%s> contains less tokens than required for %s classifier: "
							"%ud < %ud",
					task->message_id,
					cl_run->clcf->name,
					g_tree_nnodes (cl_run->tok->tokens),
					cl_run->clcf->min_tokens);
		}

		if (cl_run->cl && !cl_run->skipped) {
			cl_ctx = cl_run->cl->init_func (task->task_pool, cl_run->clcf);

			if (cl_ctx != NULL) {
				if (cl_run->cl->learn_spam_func (cl_ctx, cl_run->tok->tokens,
						cl_run, task, spam, err)) {
					msg_debug_task ("learned %s classifier %s", spam ? "spam" : "ham",
							cl_run->clcf->name);
					ret = RSPAMD_STAT_PROCESS_OK;
					learned = TRUE;

					cbdata.classifier_runtimes = cur;
					cbdata.task = task;
					cbdata.tok = cl_run->tok;
					cbdata.unlearn = unlearn;
					cbdata.spam = spam;
					g_tree_foreach (cl_run->tok->tokens, rspamd_stat_learn_token,
							&cbdata);

					curst = g_list_first (cl_run->st_runtime);

					while (curst) {
						st_run = (struct rspamd_statfile_runtime *)curst->data;

						if (unlearn && spam != st_run->st->is_spam) {
							nrev = cl_run->backend->dec_learns (task,
									st_run->backend_runtime,
									cl_run->backend->ctx);
							msg_debug_task ("unlearned %s, new revision: %ul",
									st_run->st->symbol, nrev);
						}
						else {
							nrev = cl_run->backend->inc_learns (task,
								st_run->backend_runtime,
								cl_run->backend->ctx);
							msg_debug_task ("learned %s, new revision: %ul",
								st_run->st->symbol, nrev);
						}

						cl_run->backend->finalize_learn (task,
								st_run->backend_runtime,
								cl_run->backend->ctx);

						curst = g_list_next (curst);
					}
				}
				else {
					return RSPAMD_STAT_PROCESS_ERROR;
				}

			}
		}

		cur = g_list_next (cur);
	}

	if (!learned) {
		g_set_error (err, rspamd_stat_quark (), 500, "message cannot be learned as "
				"it has too few tokens for any classifier defined");
	}
	else {
		g_atomic_int_inc (&task->worker->srv->stat->messages_learned);
	}

	return ret;
}

rspamd_stat_result_t rspamd_stat_statistics (struct rspamd_task *task,
		struct rspamd_config *cfg,
		guint64 *total_learns,
		ucl_object_t **target)
{
	struct rspamd_classifier_config *clcf;
	struct rspamd_statfile_config *stcf;
	struct rspamd_stat_backend *bk;
	gpointer backend_runtime;
	GList *cur, *st_list = NULL, *curst;
	ucl_object_t *res = NULL, *elt;
	guint64 learns = 0;

	if (cfg != NULL && cfg->classifiers != NULL) {
		res = ucl_object_typed_new (UCL_ARRAY);

		cur = g_list_first (cfg->classifiers);

		while (cur) {
			clcf = (struct rspamd_classifier_config *)cur->data;

			st_list = clcf->statfiles;
			curst = st_list;

			while (curst != NULL) {
				stcf = (struct rspamd_statfile_config *)curst->data;

				bk = rspamd_stat_get_backend (clcf->backend);

				if (bk == NULL) {
					msg_warn ("backend of type %s is not defined", clcf->backend);
					curst = g_list_next (curst);
					continue;
				}

				backend_runtime = bk->runtime (task, stcf, FALSE, bk->ctx);

				learns += bk->total_learns (task, backend_runtime, bk->ctx);
				elt = bk->get_stat (backend_runtime, bk->ctx);

				if (elt != NULL) {
					ucl_array_append (res, elt);
				}

				curst = g_list_next (curst);
			}

			/* Next classifier */
			cur = g_list_next (cur);
		}

		if (total_learns != NULL) {
			*total_learns = learns;
		}
	}

	if (target) {
		*target = res;
	}

	return RSPAMD_STAT_PROCESS_OK;
}
#else
/* TODO: finish learning */
rspamd_stat_result_t rspamd_stat_learn (struct rspamd_task *task,
		gboolean spam, lua_State *L, const gchar *classifier,
		GError **err)
{
	return RSPAMD_STAT_PROCESS_ERROR;
}

/**
 * Get the overall statistics for all statfile backends
 * @param cfg configuration
 * @param total_learns the total number of learns is stored here
 * @return array of statistical information
 */
rspamd_stat_result_t rspamd_stat_statistics (struct rspamd_task *task,
		struct rspamd_config *cfg,
		guint64 *total_learns,
		ucl_object_t **res)
{
	return RSPAMD_STAT_PROCESS_ERROR;
}
#endif
