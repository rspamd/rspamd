/*
 * Copyright (c) 2009, Rambler media
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
 * THIS SOFTWARE IS PROVIDED BY Rambler media ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Rambler BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "mem_pool.h"
#include "filter.h"
#include "main.h"
#include "message.h"
#include "cfg_file.h"
#include "util.h"
#include "expressions.h"
#include "settings.h"
#include "view.h"
#include "binlog.h"
#include "classifiers/classifiers.h"
#include "tokenizers/tokenizers.h"

#ifndef WITHOUT_PERL
#   include "perl.h"
#endif
#ifdef WITH_LUA
#   include "lua/lua_common.h"
#endif

static void
insert_metric_result (struct worker_task *task, struct metric *metric, const char *symbol, double flag, GList * opts)
{
	struct metric_result           *metric_res;
	struct symbol                  *s;
	gdouble                        *weight, w;

	metric_res = g_hash_table_lookup (task->results, metric->name);

	if (metric_res == NULL) {
		/* Create new metric chain */
		metric_res = memory_pool_alloc (task->task_pool, sizeof (struct metric_result));
		metric_res->symbols = g_hash_table_new (g_str_hash, g_str_equal);
		metric_res->checked = FALSE;
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_hash_table_destroy, metric_res->symbols);
		metric_res->metric = metric;
		metric_res->grow_factor = 0;
		metric_res->score = 0;
		g_hash_table_insert (task->results, (gpointer) metric->name, metric_res);
	}
	
	weight = g_hash_table_lookup (metric->symbols, symbol);
	if (weight == NULL) {
		w = 1.0 * flag;
	}
	else {
		w = (*weight) * flag;
	}
	/* Handle grow factor */
	if (metric_res->grow_factor && w > 0) {
		w *= metric_res->grow_factor;
		metric_res->grow_factor *= metric->grow_factor;
	}
	else if (w > 0) {
		metric_res->grow_factor = metric->grow_factor;
	}

	/* Add metric score */
	metric_res->score += w;

	if ((s = g_hash_table_lookup (metric_res->symbols, symbol)) != NULL) {
		if (s->options && opts) {
			/* Append new options */
			s->options = g_list_concat (s->options, opts);
			/* 
			* Note that there is no need to add new destructor of GList as elements of appended
			* GList are used directly, so just free initial GList
			*/
		}
		else if (opts) {
			s->options = opts;
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_list_free, s->options);
		}

		s->score = w;
	}
	else {
		s = memory_pool_alloc (task->task_pool, sizeof (struct symbol));
		s->score = w;
		s->options = opts;

		if (opts) {
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_list_free, s->options);
		}

		g_hash_table_insert (metric_res->symbols, (gpointer) symbol, s);
	}
	debug_task ("symbol %s, score %.2f, metric %s, factor: %f", symbol, s->score, metric->name, w);
	
}

void
insert_result (struct worker_task *task, const char *symbol, double flag, GList * opts)
{
	struct metric                  *metric;
	struct cache_item              *item;
	GList                          *cur, *metric_list;

	metric_list = g_hash_table_lookup (task->cfg->metrics_symbols, symbol);
	if (metric_list) {
		cur = metric_list;
		
		while (cur) {
			metric = cur->data;
			insert_metric_result (task, metric, symbol, flag, opts);
			cur = g_list_next (cur);
		}
	}
	else {
		/* Insert symbol to default metric */
		insert_metric_result (task, task->cfg->default_metric, symbol, flag, opts);
	}

	/* Process cache item */
	if (task->cfg->cache) {
		cur = task->cfg->cache->static_items;
		while (cur)
		{
			item = cur->data;

			if (strcmp (item->s->symbol, symbol) == 0) {
				item->s->frequency++;
			}
			cur = g_list_next (cur);
		}
		cur = task->cfg->cache->negative_items;
		while (cur)
		{
			item = cur->data;

			if (strcmp (item->s->symbol, symbol) == 0) {
				item->s->frequency++;
			}
			cur = g_list_next (cur);
		}
	}
}

/* 
 * Call perl or C module function for specified part of message 
 */
static void
call_filter_by_name (struct worker_task *task, const char *name, enum filter_type filt_type)
{
	struct module_ctx              *c_module;
	int                             res = 0;

	switch (filt_type) {
	case C_FILTER:
		c_module = g_hash_table_lookup (task->cfg->c_modules, name);
		if (c_module) {
			res = 1;
			c_module->filter (task);
		}
		else {
			debug_task ("%s is not a C module", name);
		}
		break;
	case PERL_FILTER:
		res = 1;
#ifndef WITHOUT_PERL
		perl_call_filter (name, task);
#elif defined(WITH_LUA)
		lua_call_filter (name, task);
#else
		msg_err ("trying to call perl function while perl support is disabled %s", name);
#endif
		break;
	}

	debug_task ("filter name: %s, result: %d", name, (int)res);
}

/* Return true if metric has score that is more than spam score for it */
static                          gboolean
check_metric_is_spam (struct worker_task *task, struct metric *metric)
{
	struct metric_result           *res;
	double                          ms, rs;

	res = g_hash_table_lookup (task->results, metric->name);
	if (res) {
		if (!check_metric_settings (task, metric, &ms, &rs)) {
			ms = metric->required_score;
		}
		return res->score >= ms;
	}

	return FALSE;
}

static int
continue_process_filters (struct worker_task *task)
{
	GList                          *cur;
	gpointer                        item = task->save.item;
	struct metric                  *metric;

	while (call_symbol_callback (task, task->cfg->cache, &item)) {
		cur = task->cfg->metrics_list;
		while (cur) {
			metric = cur->data;
			/* call_filter_by_name (task, filt->func_name, filt->type, SCRIPT_HEADER); */
			if (task->save.saved) {
				task->save.entry = cur;
				task->save.item = item;
				return 0;
			}
			else if (!task->pass_all_filters && 
						metric->action == METRIC_ACTION_REJECT && 
						check_metric_is_spam (task, metric)) {
				goto end;
			}
			cur = g_list_next (cur);
		}
	}

end:
	/* Process all statfiles */
	process_statfiles (task);
	/* XXX: ugly direct call */
	if (task->fin_callback) {
		task->fin_callback (task->fin_arg);
	}
	else {
		task->dispatcher->write_callback (task);
	}
	return 1;
}

int
process_filters (struct worker_task *task)
{
	GList                          *cur;
	struct metric                  *metric;
	gpointer                        item = NULL;

	if (task->save.saved) {
		task->save.saved = 0;
		return continue_process_filters (task);
	}
	/* Check skip */
	if (check_skip (task->cfg->views, task)) {
		task->is_skipped = TRUE;
		task->state = WRITE_REPLY;
		msg_info ("disable check for message id <%s>, view wants spam", task->message_id);
		return 1;
	}
	/* Check want spam setting */
	if (check_want_spam (task)) {
		task->is_skipped = TRUE;
		task->state = WRITE_REPLY;
		msg_info ("disable check for message id <%s>, user wants spam", task->message_id);
		return 1;
	}

	/* Process metrics symbols */
	while (call_symbol_callback (task, task->cfg->cache, &item)) {
		/* Check reject actions */
		cur = task->cfg->metrics_list;
		while (cur) {
			metric = cur->data;
			if (task->save.saved) {
				task->save.entry = cur;
				task->save.item = item;
				return 0;
			}
			else if (!task->pass_all_filters && 
						metric->action == METRIC_ACTION_REJECT && 
						check_metric_is_spam (task, metric)) {
				return 1;
			}
			cur = g_list_next (cur);
		}
	}

	return 1;
}

struct composites_data {
	struct worker_task             *task;
	struct metric_result           *metric_res;
};

static void
composites_foreach_callback (gpointer key, gpointer value, void *data)
{
	struct composites_data         *cd = (struct composites_data *)data;
	struct expression              *expr = (struct expression *)value;
	GQueue                         *stack;
	GList                          *symbols = NULL, *s;
	gsize                           cur, op1, op2;

	stack = g_queue_new ();

	while (expr) {
		if (expr->type == EXPR_STR) {
			/* Find corresponding symbol */
			if (g_hash_table_lookup (cd->metric_res->symbols, expr->content.operand) == NULL) {
				cur = 0;
			}
			else {
				cur = 1;
				symbols = g_list_append (symbols, expr->content.operand);
			}
			g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
		}
		else {
			if (g_queue_is_empty (stack)) {
				/* Queue has no operands for operation, exiting */
				g_list_free (symbols);
				g_queue_free (stack);
				return;
			}
			switch (expr->content.operation) {
			case '!':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op1 = !op1;
				g_queue_push_head (stack, GSIZE_TO_POINTER (op1));
				break;
			case '&':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				g_queue_push_head (stack, GSIZE_TO_POINTER (op1 && op2));
			case '|':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				g_queue_push_head (stack, GSIZE_TO_POINTER (op1 || op2));
			default:
				expr = expr->next;
				continue;
			}
		}
		expr = expr->next;
	}
	if (!g_queue_is_empty (stack)) {
		op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
		if (op1) {
			/* Remove all symbols that are in composite symbol */
			s = g_list_first (symbols);
			while (s) {
				g_hash_table_remove (cd->metric_res->symbols, s->data);
				s = g_list_next (s);
			}
			/* Add new symbol */
			insert_result (cd->task, key, 1.0, NULL);
		}
	}

	g_queue_free (stack);
	g_list_free (symbols);

	return;
}

static                          gboolean
check_autolearn (struct statfile_autolearn_params *params, struct worker_task *task)
{
	char                           *metric_name = DEFAULT_METRIC;
	struct metric_result           *metric_res;
	GList                          *cur;

	if (params->metric != NULL) {
		metric_name = (char *)params->metric;
	}

	/* First check threshold */
	metric_res = g_hash_table_lookup (task->results, metric_name);
	if (metric_res == NULL) {
		if (params->symbols == NULL && params->threshold_max > 0) {
			/* For ham messages */
			return TRUE;
		}
		debug_task ("metric %s has no results", metric_name);
		return FALSE;
	}
	else {
		/* Process score of metric */
		if ((params->threshold_min != 0 && metric_res->score > params->threshold_min) || (params->threshold_max != 0 && metric_res->score < params->threshold_max)) {
			/* Now check for specific symbols */
			if (params->symbols) {
				cur = params->symbols;
				while (cur) {
					if (g_hash_table_lookup (metric_res->symbols, cur->data) == NULL) {
						return FALSE;
					}
					cur = g_list_next (cur);
				}
			}
			/* Now allow processing of actual autolearn */
			return TRUE;
		}
	}

	return FALSE;
}

void
process_autolearn (struct statfile *st, struct worker_task *task, GTree * tokens, struct classifier *classifier, char *filename, struct classifier_ctx *ctx)
{
	stat_file_t                    *statfile;
	struct statfile                *unused;

	if (check_autolearn (st->autolearn, task)) {
		if (tokens) {
			msg_info ("message with id <%s> autolearned statfile '%s'", task->message_id, filename);
			
			/* Get or create statfile */
			statfile = get_statfile_by_symbol (task->worker->srv->statfile_pool, ctx->cfg,
						st->symbol, &unused, TRUE);
			
			if (statfile == NULL) {
				return;
			}

			classifier->learn_func (ctx, task->worker->srv->statfile_pool, statfile, tokens, TRUE, NULL, 1.);
			maybe_write_binlog (ctx->cfg, st, statfile, tokens);
		}
	}
}

static void
composites_metric_callback (gpointer key, gpointer value, void *data)
{
	struct worker_task             *task = (struct worker_task *)data;
	struct composites_data         *cd = memory_pool_alloc (task->task_pool, sizeof (struct composites_data));
	struct metric_result           *metric_res = (struct metric_result *)value;

	cd->task = task;
	cd->metric_res = (struct metric_result *)metric_res;

	g_hash_table_foreach (task->cfg->composite_symbols, composites_foreach_callback, cd);
}

void
make_composites (struct worker_task *task)
{
	g_hash_table_foreach (task->results, composites_metric_callback, task);
}


struct statfile_callback_data {
	GHashTable                     *tokens;
	struct worker_task             *task;
};

static void
classifiers_callback (gpointer value, void *arg)
{
	struct statfile_callback_data  *data = (struct statfile_callback_data *)arg;
	struct worker_task             *task = data->task;
	struct classifier_config       *cl = value;
	struct classifier_ctx          *ctx;
	struct mime_text_part          *text_part;
	struct statfile                *st;
	GTree                          *tokens = NULL;
	GList                          *cur;
	f_str_t                         c;
	char                           *header = NULL;
	
	if ((header = g_hash_table_lookup (cl->opts, "header")) != NULL) {
		cur = message_get_header (task->task_pool, task->message, header);
		if (cur) {
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, cur);
		}
	}
	else {
		cur = g_list_first (task->text_parts);
	}
	ctx = cl->classifier->init_func (task->task_pool, cl);

	if ((tokens = g_hash_table_lookup (data->tokens, cl->tokenizer)) == NULL) {
		while (cur != NULL) {
			if (header) {
				c.len = strlen (cur->data);
				if (c.len > 0) {
					c.begin = cur->data;
					if (!cl->tokenizer->tokenize_func (cl->tokenizer, task->task_pool, &c, &tokens)) {
						msg_info ("cannot tokenize input");
						return;
					}
				}
			}
			else {
				text_part = (struct mime_text_part *)cur->data;
				if (text_part->is_empty) {
					cur = g_list_next (cur);
					continue;
				}
				c.begin = text_part->content->data;
				c.len = text_part->content->len;
				/* Tree would be freed at task pool freeing */
				if (!cl->tokenizer->tokenize_func (cl->tokenizer, task->task_pool, &c, &tokens)) {
					msg_info ("cannot tokenize input");
					return;
				}
			}
			cur = g_list_next (cur);
		}
		g_hash_table_insert (data->tokens, cl->tokenizer, tokens);
	}

	if (tokens == NULL) {
		return;
	}

	cl->classifier->classify_func (ctx, task->worker->srv->statfile_pool, tokens, task);

	/* Autolearning */
	cur = g_list_first (cl->statfiles);
	while (cur) {
		st = cur->data;
		if (st->autolearn) {
			if (check_autolearn (st->autolearn, task)) {
				/* Process autolearn */
				process_autolearn (st, task, tokens, cl->classifier, st->path, ctx);
			}
		}
		cur = g_list_next (cur);
	}
}


void
process_statfiles (struct worker_task *task)
{
	struct statfile_callback_data   cd;
	
	if (task->is_skipped) {
		return;
	}
	cd.task = task;
	cd.tokens = g_hash_table_new (g_direct_hash, g_direct_equal);

	g_list_foreach (task->cfg->classifiers, classifiers_callback, &cd);
	g_hash_table_destroy (cd.tokens);

	/* Process results */
	make_composites (task);
	task->state = WRITE_REPLY;
}

static void
insert_metric_header (gpointer metric_name, gpointer metric_value, gpointer data)
{
	struct worker_task             *task = (struct worker_task *)data;
	int                             r = 0;
	/* Try to be rfc2822 compatible and avoid long headers with folding */
	char                            header_name[128], outbuf[1000];
	GList                          *symbols = NULL, *cur;
	struct metric_result           *metric_res = (struct metric_result *)metric_value;
	double                          ms, rs;

	rspamd_snprintf (header_name, sizeof (header_name), "X-Spam-%s", metric_res->metric->name);

	if (!check_metric_settings (task, metric_res->metric, &ms, &rs)) {
		ms = metric_res->metric->required_score;
	}
	if (metric_res->score >= ms) {
		r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "yes; %.2f/%.2f/%.2f; ", metric_res->score, ms, rs);
	}
	else {
		r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "no; %.2f/%.2f/%.2f; ", metric_res->score, ms, rs);
	}

	symbols = g_hash_table_get_keys (metric_res->symbols);
	cur = symbols;
	while (cur) {
		if (g_list_next (cur) != NULL) {
			r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "%s,", (char *)cur->data);
		}
		else {
			r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "%s", (char *)cur->data);
		}
		cur = g_list_next (cur);
	}
	g_list_free (symbols);
#ifdef GMIME24
	g_mime_object_append_header (GMIME_OBJECT (task->message), header_name, outbuf);
#else
	g_mime_message_add_header (task->message, header_name, outbuf);
#endif

}

void
insert_headers (struct worker_task *task)
{
	g_hash_table_foreach (task->results, insert_metric_header, task);
}

/* 
 * vi:ts=4 
 */
