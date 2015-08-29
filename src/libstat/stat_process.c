/* Copyright (c) 2015, Vsevolod Stakhov
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
#include "main.h"
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

struct preprocess_cb_data {
	struct rspamd_task *task;
	GList *classifier_runtimes;
	struct rspamd_tokenizer_runtime *tok;
	guint results_count;
	gboolean unlearn;
	gboolean spam;
};

static void
rspamd_stat_tokenize_header (struct rspamd_task *task,
		struct rspamd_tokenizer_runtime *tok,
		const gchar *name, const gchar *prefix, GArray *ar)
{
	struct raw_header *rh, *cur;
	rspamd_fstring_t str;

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
rspamd_stat_tokenize_parts_metadata (struct rspamd_task *task,
		struct rspamd_tokenizer_runtime *tok)
{
	struct rspamd_image *img;
	struct mime_part *part;
	struct mime_text_part *tp;
	GList *cur;
	GArray *ar;
	rspamd_fstring_t elt;
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
		rspamd_stat_tokenize_header (task, tok, cur->data, "UA:", ar);

		cur = g_list_next (cur);
	}

	tok->tokenizer->tokenize_func (tok,
			task->task_pool,
			ar,
			TRUE,
			"META:");

	g_array_free (ar, TRUE);
}

/*
 * Tokenize task using the tokenizer specified
 */
static void
rspamd_stat_process_tokenize (struct rspamd_stat_ctx *st_ctx,
		struct rspamd_task *task, struct rspamd_tokenizer_runtime *tok)
{
	struct mime_text_part *part;
	GArray *words;
	gchar *sub;
	guint i;
	gint *pdiff;
	gboolean compat;

	compat = tok->tokenizer->is_compat (tok);
	pdiff = rspamd_mempool_get_variable (task->task_pool, "parts_distance");

	for (i = 0; i < task->text_parts->len; i ++) {
		part = g_ptr_array_index (task->text_parts, i);

		if (!IS_PART_EMPTY (part) && part->words != NULL) {
			if (compat) {
				tok->tokenizer->tokenize_func (tok, task->task_pool,
					part->words, IS_PART_UTF (part), NULL);
			}
			else {
				tok->tokenizer->tokenize_func (tok, task->task_pool,
					part->normalized_words, IS_PART_UTF (part), NULL);
			}
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
		words = rspamd_tokenize_text (sub, strlen (sub), TRUE, 0, NULL, compat,
				FALSE);
		if (words != NULL) {
			tok->tokenizer->tokenize_func (tok,
					task->task_pool,
					words,
					TRUE,
					"SUBJECT");
			g_array_free (words, TRUE);
		}
	}

	rspamd_stat_tokenize_parts_metadata (task, tok);
}

static struct rspamd_tokenizer_runtime *
rspamd_stat_get_tokenizer_runtime (struct rspamd_tokenizer_config *cf,
		struct rspamd_stat_ctx *st_ctx,
		struct rspamd_task *task,
		struct rspamd_classifier_runtime *cl_runtime,
		gpointer conf, gsize conf_len)
{
	struct rspamd_tokenizer_runtime *tok = NULL;
	const gchar *name;

	if (cf == NULL || cf->name == NULL) {
		name = RSPAMD_DEFAULT_TOKENIZER;
		cf->name = name;
	}
	else {
		name = cf->name;
	}

	tok = rspamd_mempool_alloc (task->task_pool, sizeof (*tok));
	tok->tokenizer = rspamd_stat_get_tokenizer (name);
	tok->tkcf = cf;

	if (tok->tokenizer == NULL) {
		return NULL;
	}

	if (!tok->tokenizer->load_config (task->task_pool, tok, conf, conf_len)) {
		return NULL;
	}

	tok->tokens = g_tree_new (token_node_compare_func);
	rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)g_tree_destroy, tok->tokens);
	tok->name = name;
	rspamd_stat_process_tokenize (st_ctx, task, tok);
	cl_runtime->tok = tok;

	return tok;
}

static gboolean
preprocess_init_stat_token (gpointer k, gpointer v, gpointer d)
{
	rspamd_token_t *t = (rspamd_token_t *)v;
	struct preprocess_cb_data *cbdata = (struct preprocess_cb_data *)d;
	struct rspamd_statfile_runtime *st_runtime;
	struct rspamd_classifier_runtime *cl_runtime;
	struct rspamd_token_result *res;
	GList *cur, *curst;
	struct rspamd_task *task;
	gint i = 0;

	task = cbdata->task;
	t->results = g_array_sized_new (FALSE, TRUE,
			sizeof (struct rspamd_token_result), cbdata->results_count);
	g_array_set_size (t->results, cbdata->results_count);
	rspamd_mempool_add_destructor (cbdata->task->task_pool,
			rspamd_array_free_hard, t->results);

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
			cl_runtime->skipped = TRUE;

			continue;
		}

		curst = cl_runtime->st_runtime;

		while (curst) {

			st_runtime = (struct rspamd_statfile_runtime *)curst->data;
			res = &g_array_index (t->results, struct rspamd_token_result, i);
			res->cl_runtime = cl_runtime;
			res->st_runtime = st_runtime;

			if (cl_runtime->backend->process_token (cbdata->task, t, res,
					cl_runtime->backend->ctx)) {

				if (cl_runtime->clcf->max_tokens > 0 &&
						cl_runtime->processed_tokens > cl_runtime->clcf->max_tokens) {
					msg_debug_task ("<%s> contains more tokens than allowed for %s classifier: "
							"%ud > %ud", cbdata->task, cl_runtime->clcf->name,
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

static GList*
rspamd_stat_preprocess (struct rspamd_stat_ctx *st_ctx,
		struct rspamd_task *task,
		lua_State *L, gint op, gboolean spam, GError **err)
{
	struct rspamd_classifier_config *clcf;
	struct rspamd_statfile_config *stcf;
	struct rspamd_classifier_runtime *cl_runtime;
	struct rspamd_statfile_runtime *st_runtime;
	struct rspamd_stat_backend *bk;
	gpointer backend_runtime, tok_config;
	GList *cur, *st_list = NULL, *curst;
	GList *cl_runtimes = NULL;
	guint result_size = 0, start_pos = 0, end_pos = 0;
	gsize conf_len;
	struct preprocess_cb_data cbdata;

	cur = g_list_first (task->cfg->classifiers);

	while (cur) {
		clcf = (struct rspamd_classifier_config *)cur->data;
		st_list = NULL;

		if (clcf->pre_callbacks != NULL) {
			st_list = rspamd_lua_call_cls_pre_callbacks (clcf, task, FALSE,
					FALSE, L);
		}
		if (st_list != NULL) {
			rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t)g_list_free, st_list);
		}
		else {
			st_list = clcf->statfiles;
		}

		/* Now init runtime values */
		cl_runtime = rspamd_mempool_alloc0 (task->task_pool, sizeof (*cl_runtime));
		cl_runtime->cl = rspamd_stat_get_classifier (clcf->classifier);

		if (cl_runtime->cl == NULL) {
			g_set_error (err, rspamd_stat_quark(), 500,
					"classifier %s is not defined", clcf->classifier);
			g_list_free (cl_runtimes);
			return NULL;
		}

		cl_runtime->clcf = clcf;

		bk = rspamd_stat_get_backend (clcf->backend);
		if (bk == NULL) {
			g_set_error (err, rspamd_stat_quark(), 500,
					"backend %s is not defined", clcf->backend);
			g_list_free (cl_runtimes);
			return NULL;
		}

		cl_runtime->backend = bk;

		curst = st_list;
		while (curst != NULL) {
			stcf = (struct rspamd_statfile_config *)curst->data;

			/* On learning skip statfiles that do not belong to class */
			if (op == RSPAMD_LEARN_OP && (spam != stcf->is_spam)) {
				curst = g_list_next (curst);
				continue;
			}

			backend_runtime = bk->runtime (task, stcf, op != RSPAMD_CLASSIFY_OP,
					bk->ctx);

			if (backend_runtime == NULL) {
				if (op != RSPAMD_CLASSIFY_OP) {
					/* Assume backend absence as fatal error */
					g_set_error (err, rspamd_stat_quark(), 500,
							"cannot open backend for statfile %s", stcf->symbol);
					g_list_free (cl_runtimes);

					return NULL;
				}
				else {
					/* Just skip this element */
					msg_warn ("backend of type %s does not exist: %s",
							clcf->backend, stcf->symbol);
					curst = g_list_next (curst);
					continue;
				}
			}

			tok_config = bk->load_tokenizer_config (backend_runtime,
					&conf_len);

			if (cl_runtime->tok == NULL) {
				cl_runtime->tok = rspamd_stat_get_tokenizer_runtime (clcf->tokenizer,
						st_ctx, task, cl_runtime, tok_config, conf_len);

				if (cl_runtime->tok == NULL) {
					g_set_error (err, rspamd_stat_quark(), 500,
							"cannot initialize tokenizer for statfile %s", stcf->symbol);
					g_list_free (cl_runtimes);

					return NULL;
				}
			}

			if (!cl_runtime->tok->tokenizer->compatible_config (
					cl_runtime->tok, tok_config, conf_len)) {
				g_set_error (err, rspamd_stat_quark(), 500,
						"incompatible tokenizer for statfile %s", stcf->symbol);
				g_list_free (cl_runtimes);

				return NULL;
			}

			st_runtime = rspamd_mempool_alloc0 (task->task_pool,
					sizeof (*st_runtime));
			st_runtime->st = stcf;
			st_runtime->backend_runtime = backend_runtime;

			if (stcf->is_spam) {
				cl_runtime->total_spam += bk->total_learns (task, backend_runtime,
						bk->ctx);
			}
			else {
				cl_runtime->total_ham += bk->total_learns (task, backend_runtime,
						bk->ctx);
			}

			cl_runtime->st_runtime = g_list_prepend (cl_runtime->st_runtime,
					st_runtime);
			result_size ++;

			curst = g_list_next (curst);
			end_pos ++;
		}

		if (cl_runtime->st_runtime != NULL) {
			rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t)g_list_free,
					cl_runtime->st_runtime);
			cl_runtimes = g_list_prepend (cl_runtimes, cl_runtime);
		}

		/* Set positions in the results array */
		cl_runtime->start_pos = start_pos;
		cl_runtime->end_pos = end_pos;

		msg_debug_task ("added runtime for %s classifier from %ud to %ud",
				clcf->name, start_pos, end_pos);

		start_pos = end_pos;

		/* Next classifier */
		cur = g_list_next (cur);
	}

	if (cl_runtimes != NULL) {
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t)g_list_free,
				cl_runtimes);

		cbdata.results_count = result_size;
		cbdata.classifier_runtimes = cl_runtimes;
		cbdata.task = task;
		cbdata.tok = cl_runtime->tok;
		g_tree_foreach (cbdata.tok->tokens, preprocess_init_stat_token,
				&cbdata);
	}

	return cl_runtimes;
}

rspamd_stat_result_t
rspamd_stat_classify (struct rspamd_task *task, lua_State *L, GError **err)
{
	struct rspamd_stat_ctx *st_ctx;
	struct rspamd_statfile_runtime *st_run;
	struct rspamd_classifier_runtime *cl_run;
	struct classifier_ctx *cl_ctx;
	GList *cl_runtimes;
	GList *cur, *curst;
	gboolean ret = RSPAMD_STAT_PROCESS_OK;

	st_ctx = rspamd_stat_get_ctx ();
	g_assert (st_ctx != NULL);

	/* Initialize classifiers and statfiles runtime */
	if ((cl_runtimes = rspamd_stat_preprocess (st_ctx, task, L,
			RSPAMD_CLASSIFY_OP, FALSE, err)) == NULL) {
		return RSPAMD_STAT_PROCESS_OK;
	}

	cur = cl_runtimes;

	while (cur) {
		cl_run = (struct rspamd_classifier_runtime *)cur->data;
		cl_run->stage = RSPAMD_STAT_STAGE_PRE;

		if (cl_run->cl) {
			cl_ctx = cl_run->cl->init_func (task->task_pool, cl_run->clcf);

			if (cl_ctx != NULL) {
				cl_run->cl->classify_func (cl_ctx, cl_run->tok->tokens,
						cl_run, task);
			}
		}

		cur = g_list_next (cur);
	}

	/* XXX: backend runtime post-processing */
	/* Post-processing */
	cur = cl_runtimes;
	while (cur) {
		cl_run = (struct rspamd_classifier_runtime *)cur->data;
		cl_run->stage = RSPAMD_STAT_STAGE_POST;

		if (cl_run->skipped) {
			cur = g_list_next (cur);
			continue;
		}

		if (cl_run->cl) {
			if (cl_ctx != NULL) {
				if (cl_run->cl->classify_func (cl_ctx, cl_run->tok->tokens,
						cl_run, task)) {
					ret = RSPAMD_STAT_PROCESS_OK;
				}
			}
		}

		curst = cl_run->st_runtime;

		while (curst) {
			st_run = curst->data;
			cl_run->backend->finalize_process (task,
					st_run->backend_runtime,
					cl_run->backend->ctx);
			curst = g_list_next (curst);
		}

		cur = g_list_next (cur);
	}

	return ret;
}

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
					msg_debug_task ("<%s> contains more tokens than allowed for %s classifier: "
							"%ud > %ud", cbdata->task, cl_runtime->clcf->name,
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
rspamd_stat_learn (struct rspamd_task *task, gboolean spam, lua_State *L,
		GError **err)
{
	struct rspamd_stat_ctx *st_ctx;
	struct rspamd_classifier_runtime *cl_run;
	struct rspamd_statfile_runtime *st_run;
	struct classifier_ctx *cl_ctx;
	struct preprocess_cb_data cbdata;
	GList *cl_runtimes;
	GList *cur, *curst;
	gboolean ret = RSPAMD_STAT_PROCESS_ERROR, unlearn = FALSE;
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
	if ((cl_runtimes = rspamd_stat_preprocess (st_ctx, task, L,
			unlearn ? RSPAMD_UNLEARN_OP : RSPAMD_LEARN_OP, spam, err)) == NULL) {
		return RSPAMD_STAT_PROCESS_ERROR;
	}

	cur = cl_runtimes;

	while (cur) {
		cl_run = (struct rspamd_classifier_runtime *)cur->data;

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
		g_set_error (err, rspamd_stat_quark (), 500, "message cannot be learned"
				" for any classifier defined");
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
