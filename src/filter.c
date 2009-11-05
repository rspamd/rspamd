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
#include "classifiers/classifiers.h"
#include "tokenizers/tokenizers.h"

#ifndef WITHOUT_PERL
#   include "perl.h"
#endif
#ifdef WITH_LUA
#   include "lua/lua_common.h"
#endif

void
insert_result (struct worker_task *task, const char *metric_name, const char *symbol, double flag, GList * opts)
{
	struct metric                  *metric;
	struct metric_result           *metric_res;
	struct symbol                  *s;
	struct cache_item              *item;
	int                             i;

	metric = g_hash_table_lookup (task->worker->srv->cfg->metrics, metric_name);
	if (metric == NULL) {
		return;
	}

	metric_res = g_hash_table_lookup (task->results, metric_name);

	if (metric_res == NULL) {
		/* Create new metric chain */
		metric_res = memory_pool_alloc (task->task_pool, sizeof (struct metric_result));
		metric_res->symbols = g_hash_table_new (g_str_hash, g_str_equal);
		metric_res->checked = FALSE;
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_hash_table_destroy, metric_res->symbols);
		metric_res->metric = metric;
		g_hash_table_insert (task->results, (gpointer) metric_name, metric_res);
	}

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

		s->score = flag;
	}
	else {
		s = memory_pool_alloc (task->task_pool, sizeof (struct symbol));
		s->score = flag;
		s->options = opts;

		if (opts) {
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_list_free, s->options);
		}

		g_hash_table_insert (metric_res->symbols, (gpointer) symbol, s);
	}

	/* Process cache item */
	if (metric->cache) {
		for (i = 0; i < metric->cache->used_items; i++) {
			item = &metric->cache->items[i];

			if (flag > 0 && strcmp (item->s->symbol, symbol) == 0) {
				item->s->frequency++;
			}
		}
	}
}

/*
 * Default consolidation function based on factors in config file
 */
struct consolidation_callback_data {
	struct worker_task             *task;
	double                          score;
	int                             count;
};

static void
consolidation_callback (gpointer key, gpointer value, gpointer arg)
{
	double                         *factor, fs, grow = 1;
	struct symbol                  *s = (struct symbol *)value;
	struct consolidation_callback_data *data = (struct consolidation_callback_data *)arg;
	
	if (data->count > 0) {
		grow = 1. + (data->task->cfg->grow_factor - 1.) * data->count;
	}

	if (check_factor_settings (data->task, key, &fs)) {
		if (s->score > 0) {
			data->score += fs * s->score * grow;
			data->count ++;
		}
		else {
			data->score += fs * s->score;
		}
	}
	else {
		factor = g_hash_table_lookup (data->task->worker->srv->cfg->factors, key);
		if (factor == NULL) {
			msg_debug ("consolidation_callback: got %.2f score for metric %s, factor: 1", s->score, (char *)key);
			data->score += s->score;
		}
		else {
			if (s->score > 0) {
				data->score += *factor * s->score * grow;
				data->count ++;
			}
			else {
				data->score += *factor * s->score;
			}
			msg_debug ("consolidation_callback: got %.2f score for metric %s, factor: %.2f", s->score, (char *)key, *factor);
		}
	}
}

double
factor_consolidation_func (struct worker_task *task, const char *metric_name, const char *unused)
{
	struct metric_result           *metric_res;
	double                          res = 0.;
	struct consolidation_callback_data data = { 
		.task = task, 
		.score = 0,
		.count = 0
	};

	metric_res = g_hash_table_lookup (task->results, metric_name);
	if (metric_res == NULL) {
		return res;
	}

	g_hash_table_foreach (metric_res->symbols, consolidation_callback, &data);

	return data.score;
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
		c_module = g_hash_table_lookup (task->worker->srv->cfg->c_modules, name);
		if (c_module) {
			res = 1;
			c_module->filter (task);
		}
		else {
			msg_debug ("call_filter_by_name: %s is not a C module", name);
		}
		break;
	case PERL_FILTER:
		res = 1;
#ifndef WITHOUT_PERL
		perl_call_filter (name, task);
#elif defined(WITH_LUA)
		lua_call_filter (name, task);
#else
		msg_err ("call_filter_by_name: trying to call perl function while perl support is disabled %s", name);
#endif
		break;
	}

	msg_debug ("call_filter_by_name: filter name: %s, result: %d", name, (int)res);
}

static void
metric_process_callback_common (gpointer key, gpointer value, void *data, gboolean is_forced)
{
	struct worker_task             *task = (struct worker_task *)data;
	struct metric_result           *metric_res = (struct metric_result *)value;

	if (metric_res->checked && !is_forced) {
		/* Already checked */
		return;
	}

	/* Set flag */
	metric_res->checked = TRUE;

	if (metric_res->metric->func != NULL) {
		metric_res->score = metric_res->metric->func (task, metric_res->metric->name, metric_res->metric->func_name);
	}
	else {
		metric_res->score = factor_consolidation_func (task, metric_res->metric->name, NULL);
	}
	msg_debug ("process_metric_callback: got result %.2f from consolidation function for metric %s", metric_res->score, metric_res->metric->name);
}

static void
metric_process_callback_normal (gpointer key, gpointer value, void *data)
{
	metric_process_callback_common (key, value, data, FALSE);
}

static void
metric_process_callback_forced (gpointer key, gpointer value, void *data)
{
	metric_process_callback_common (key, value, data, TRUE);
}

/* Return true if metric has score that is more than spam score for it */
static                          gboolean
check_metric_is_spam (struct worker_task *task, struct metric *metric)
{
	struct metric_result           *res;
	double                          ms, rs;

	res = g_hash_table_lookup (task->results, metric->name);
	if (res) {
		metric_process_callback_forced (metric->name, res, task);
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
	GList                          *cur = task->save.entry;
	struct cache_item              *item = task->save.item;

	struct metric                  *metric = cur->data;

	while (cur) {
		metric = cur->data;
		while (call_symbol_callback (task, metric->cache, &item)) {
			/* call_filter_by_name (task, filt->func_name, filt->type, SCRIPT_HEADER); */
			if (task->save.saved) {
				task->save.entry = cur;
				task->save.item = item;
				return 0;
			}
			else if (check_metric_is_spam (task, metric)) {
				break;
			}
		}
		cur = g_list_next (cur);
	}

	/* Process all statfiles */
	process_statfiles (task);
	/* XXX: ugly direct call */
	task->dispatcher->write_callback (task);
	return 1;
}

int
process_filters (struct worker_task *task)
{
	GList                          *cur;
	struct metric                  *metric;
	struct cache_item              *item = NULL;

	if (task->save.saved) {
		task->save.saved = 0;
		return continue_process_filters (task);
	}
	/* Check skip */
	if (check_skip (task->cfg->views, task)) {
		task->is_skipped = TRUE;
		task->state = WRITE_REPLY;
		msg_info ("process_filters: disable check for message id <%s>, view wants spam", task->message_id);
		return 1;
	}
	/* Check want spam setting */
	if (check_want_spam (task)) {
		task->is_skipped = TRUE;
		task->state = WRITE_REPLY;
		msg_info ("process_filters: disable check for message id <%s>, user wants spam", task->message_id);
		return 1;
	}

	/* Process metrics symbols */
	cur = task->worker->srv->cfg->metrics_list;
	while (cur) {
		metric = cur->data;
		while (call_symbol_callback (task, metric->cache, &item)) {
			/* call_filter_by_name (task, filt->func_name, filt->type, SCRIPT_HEADER); */
			if (task->save.saved) {
				task->save.entry = cur;
				task->save.item = item;
				return 0;
			}
			else if (check_metric_is_spam (task, metric)) {
				break;
			}
		}
		cur = g_list_next (cur);
	}

	/* Process all metrics */
	g_hash_table_foreach (task->results, metric_process_callback_forced, task);
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
	struct symbol                  *res;

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
			res = memory_pool_alloc (cd->task->task_pool, sizeof (struct symbol));
			res->score = 1.;
			res->options = NULL;
			g_hash_table_insert (cd->metric_res->symbols, key, res);
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
		msg_debug ("check_autolearn: metric %s has no results", metric_name);
		return FALSE;
	}
	else {
		/* Process score of metric */
		metric_process_callback_normal ((void *)metric_name, metric_res, task);
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
	if (check_autolearn (st->autolearn, task)) {
		if (tokens) {
			msg_info ("process_autolearn: message with id <%s> autolearned statfile '%s'", task->message_id, filename);
			/* Check opened */
			if (!statfile_pool_is_open (task->worker->srv->statfile_pool, filename)) {
				/* Try open */
				if (statfile_pool_open (task->worker->srv->statfile_pool, filename, st->size, FALSE) == NULL) {
					/* Try create */
					if (statfile_pool_create (task->worker->srv->statfile_pool, filename, st->size) == -1) {
						msg_info ("process_autolearn: error while creating statfile %s", filename);
						return;
					}
				}
			}

			classifier->learn_func (ctx, task->worker->srv->statfile_pool, st->symbol, tokens, TRUE);
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
	/* Process all metrics */
	g_hash_table_foreach (task->results, metric_process_callback_forced, task);
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

	cur = g_list_first (task->text_parts);
	ctx = cl->classifier->init_func (task->task_pool, cl);

	if ((tokens = g_hash_table_lookup (data->tokens, cl->tokenizer)) == NULL) {
		while (cur != NULL) {
			text_part = (struct mime_text_part *)cur->data;
			if (text_part->is_empty) {
				cur = g_list_next (cur);
				continue;
			}
			c.begin = text_part->content->data;
			c.len = text_part->content->len;
			/* Tree would be freed at task pool freeing */
			if (!cl->tokenizer->tokenize_func (cl->tokenizer, task->task_pool, &c, &tokens)) {
				msg_info ("statfiles_callback: cannot tokenize input");
				return;
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

	snprintf (header_name, sizeof (header_name), "X-Spam-%s", metric_res->metric->name);

	if (!check_metric_settings (task, metric_res->metric, &ms, &rs)) {
		ms = metric_res->metric->required_score;
	}
	if (metric_res->score >= ms) {
		r += snprintf (outbuf + r, sizeof (outbuf) - r, "yes; %.2f/%.2f/%.2f; ", metric_res->score, ms, rs);
	}
	else {
		r += snprintf (outbuf + r, sizeof (outbuf) - r, "no; %.2f/%.2f/%.2f; ", metric_res->score, ms, rs);
	}

	symbols = g_hash_table_get_keys (metric_res->symbols);
	cur = symbols;
	while (cur) {
		if (g_list_next (cur) != NULL) {
			r += snprintf (outbuf + r, sizeof (outbuf) - r, "%s,", (char *)cur->data);
		}
		else {
			r += snprintf (outbuf + r, sizeof (outbuf) - r, "%s", (char *)cur->data);
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
