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

#ifdef WITH_LUA
#   include "lua/lua_common.h"
#endif

#define COMMON_PART_FACTOR 80

static inline                   GQuark
filter_error_quark (void)
{
	return g_quark_from_static_string ("g-filter-error-quark");
}

static void
insert_metric_result (struct worker_task *task, struct metric *metric, const gchar *symbol,
		double flag, GList * opts, gboolean single)
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
		metric_res->domain_settings = NULL;
		metric_res->user_settings = NULL;
		apply_metric_settings (task, metric, metric_res);
		g_hash_table_insert (task->results, (gpointer) metric->name, metric_res);
	}
	
	weight = g_hash_table_lookup (metric->symbols, symbol);
	if (weight == NULL) {
		w = 1.0 * flag;
	}
	else {
		w = (*weight) * flag;
	}


	/* Add metric score */
	if ((s = g_hash_table_lookup (metric_res->symbols, symbol)) != NULL) {
		if (s->options && opts && opts != s->options) {
			/* Append new options */
			s->options = g_list_concat (s->options, g_list_copy(opts));
			/*
			 * Note that there is no need to add new destructor of GList as elements of appended
			 * GList are used directly, so just free initial GList
			 */
		}
		else if (opts) {
			s->options = g_list_copy (opts);
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_list_free, s->options);
		}
		if (!single) {
			/* Handle grow factor */
			if (metric_res->grow_factor && w > 0) {
				w *= metric_res->grow_factor;
				metric_res->grow_factor *= metric->grow_factor;
			}
			else if (w > 0) {
				metric_res->grow_factor = metric->grow_factor;
			}
			s->score += w;
			metric_res->score += w;
		}
	}
	else {
		s = memory_pool_alloc (task->task_pool, sizeof (struct symbol));
		s->score = w;

		/* Handle grow factor */
		if (metric_res->grow_factor && w > 0) {
			w *= metric_res->grow_factor;
			metric_res->grow_factor *= metric->grow_factor;
		}
		else if (w > 0) {
			metric_res->grow_factor = metric->grow_factor;
		}
		s->name = symbol;
		metric_res->score += w;

		if (opts) {
			s->options = g_list_copy (opts);
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_list_free, s->options);
		}
		else {
			s->options = NULL;
		}

		g_hash_table_insert (metric_res->symbols, (gpointer) symbol, s);
	}
	debug_task ("symbol %s, score %.2f, metric %s, factor: %f", symbol, s->score, metric->name, w);
	
}

static void
insert_result_common (struct worker_task *task, const gchar *symbol, double flag, GList * opts, gboolean single)
{
	struct metric                  *metric;
	struct cache_item              *item;
	GList                          *cur, *metric_list;

	metric_list = g_hash_table_lookup (task->cfg->metrics_symbols, symbol);
	if (metric_list) {
		cur = metric_list;
		
		while (cur) {
			metric = cur->data;
			insert_metric_result (task, metric, symbol, flag, opts, single);
			cur = g_list_next (cur);
		}
	}
	else {
		/* Insert symbol to default metric */
		insert_metric_result (task, task->cfg->default_metric, symbol, flag, opts, single);
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

	if (opts != NULL) {
		/* XXX: it is not wise to destroy them here */
		g_list_free (opts);
	}
}

/* Insert result that may be increased on next insertions */
void
insert_result (struct worker_task *task, const gchar *symbol, double flag, GList * opts)
{
	insert_result_common (task, symbol, flag, opts, task->cfg->one_shot_mode);
}

/* Insert result as a single option */
void
insert_result_single (struct worker_task *task, const gchar *symbol, double flag, GList * opts)
{
	insert_result_common (task, symbol, flag, opts, TRUE);
}

/* 
 * Call perl or C module function for specified part of message 
 */
static void
call_filter_by_name (struct worker_task *task, const gchar *name, enum filter_type filt_type)
{
	struct module_ctx              *c_module;
	gint                            res = 0;

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

	debug_task ("filter name: %s, result: %d", name, (gint)res);
}

/* Return true if metric has score that is more than spam score for it */
static                          gboolean
check_metric_is_spam (struct worker_task *task, struct metric *metric)
{
	struct metric_result           *res;
	double                          ms, rs;

	res = g_hash_table_lookup (task->results, metric->name);
	if (res) {
		if (!check_metric_settings (res, &ms, &rs)) {
			ms = metric->required_score;
		}
		return res->score >= ms;
	}

	return FALSE;
}

static gint
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
	/* Call post filters */
	lua_call_post_filters (task);
	task->state = WRITE_REPLY;
	/* XXX: ugly direct call */
	if (task->fin_callback) {
		task->fin_callback (task->fin_arg);
	}
	else {
		task->dispatcher->write_callback (task);
	}
	return 1;
}

gint
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
				task->state = WRITE_REPLY;
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
	GTree                          *symbols_to_remove;
};

struct symbol_remove_data {
	struct symbol                  *ms;
	gboolean                        remove_weight;
	gboolean                        remove_symbol;
};

static gint
remove_compare_data (gconstpointer a, gconstpointer b)
{
	const gchar                    *ca = a, *cb = b;

	return strcmp (ca, cb);
}

static void
composites_foreach_callback (gpointer key, gpointer value, void *data)
{
	struct composites_data         *cd = (struct composites_data *)data;
	struct expression              *expr = (struct expression *)value;
	GQueue                         *stack;
	GList                          *symbols = NULL, *s;
	gsize                           cur, op1, op2;
	gchar                           logbuf[256], *sym;
	gint                            r;
	struct symbol                  *ms;
	struct symbol_remove_data      *rd;

	stack = g_queue_new ();

	while (expr) {
		if (expr->type == EXPR_STR) {
			/* Find corresponding symbol */
			sym = expr->content.operand;
			if (*sym == '~' || *sym == '-') {
				sym ++;
			}
			if (g_hash_table_lookup (cd->metric_res->symbols, sym) == NULL) {
				cur = 0;
			}
			else {
				cur = 1;
				symbols = g_list_prepend (symbols, expr->content.operand);
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
			r = rspamd_snprintf (logbuf, sizeof (logbuf), "<%s>, insert symbol %s instead of symbols: ", cd->task->message_id, key);
			while (s) {
				sym = s->data;
				if (*sym == '~' || *sym == '-') {
					ms = g_hash_table_lookup (cd->metric_res->symbols, sym + 1);
				}
				else {
					ms = g_hash_table_lookup (cd->metric_res->symbols, sym);
				}

				if (ms != NULL) {
					rd = memory_pool_alloc (cd->task->task_pool, sizeof (struct symbol_remove_data));
					rd->ms = ms;
					if (G_UNLIKELY (*sym == '~')) {
						rd->remove_weight = FALSE;
						rd->remove_symbol = TRUE;
					}
					else if (G_UNLIKELY (*sym == '-')) {
						rd->remove_symbol = FALSE;
						rd->remove_weight = FALSE;
					}
					else {
						rd->remove_symbol = TRUE;
						rd->remove_weight = TRUE;
					}
					if (!g_tree_lookup (cd->symbols_to_remove, rd)) {
						g_tree_insert (cd->symbols_to_remove, (gpointer)ms->name, rd);
					}
				}

				if (s->next) {
					r += rspamd_snprintf (logbuf + r, sizeof (logbuf) -r, "%s, ", s->data);
				}
				else {
					r += rspamd_snprintf (logbuf + r, sizeof (logbuf) -r, "%s", s->data);
				}
				s = g_list_next (s);
			}
			/* Add new symbol */
			insert_result_single (cd->task, key, 1.0, NULL);
			msg_info ("%s", logbuf);
		}
	}

	g_queue_free (stack);
	g_list_free (symbols);

	return;
}

static                          gboolean
check_autolearn (struct statfile_autolearn_params *params, struct worker_task *task)
{
	gchar                          *metric_name = DEFAULT_METRIC;
	struct metric_result           *metric_res;
	GList                          *cur;

	if (params->metric != NULL) {
		metric_name = (gchar *)params->metric;
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
process_autolearn (struct statfile *st, struct worker_task *task, GTree * tokens, struct classifier *classifier, gchar *filename, struct classifier_ctx *ctx)
{
	stat_file_t                    *statfile;
	struct statfile                *unused;

	if (check_autolearn (st->autolearn, task)) {
		if (tokens) {
			/* Take care of subject */
			tokenize_subject (task, &tokens);
			msg_info ("message with id <%s> autolearned statfile '%s'", task->message_id, filename);
			
			/* Get or create statfile */
			statfile = get_statfile_by_symbol (task->worker->srv->statfile_pool, ctx->cfg,
						st->symbol, &unused, TRUE);
			
			if (statfile == NULL) {
				return;
			}

			classifier->learn_func (ctx, task->worker->srv->statfile_pool, st->symbol, tokens, TRUE, NULL, 1., NULL);
			maybe_write_binlog (ctx->cfg, st, statfile, tokens);
			statfile_pool_plan_invalidate (task->worker->srv->statfile_pool, DEFAULT_STATFILE_INVALIDATE_TIME, DEFAULT_STATFILE_INVALIDATE_JITTER);
		}
	}
}

static gboolean
composites_remove_symbols (gpointer key, gpointer value, gpointer data)
{
	struct composites_data         *cd = data;
	struct symbol_remove_data      *rd = value;

	if (rd->remove_symbol) {
		g_hash_table_remove (cd->metric_res->symbols, key);
	}
	if (rd->remove_weight) {
		cd->metric_res->score -= rd->ms->score;
	}

	return FALSE;
}

static void
composites_metric_callback (gpointer key, gpointer value, gpointer data)
{
	struct worker_task             *task = (struct worker_task *)data;
	struct composites_data         *cd = memory_pool_alloc (task->task_pool, sizeof (struct composites_data));
	struct metric_result           *metric_res = (struct metric_result *)value;

	cd->task = task;
	cd->metric_res = (struct metric_result *)metric_res;
	cd->symbols_to_remove = g_tree_new (remove_compare_data);

	/* Process hash table */
	g_hash_table_foreach (task->cfg->composite_symbols, composites_foreach_callback, cd);

	/* Remove symbols that are in composites */
	g_tree_foreach (cd->symbols_to_remove, composites_remove_symbols, cd);
	/* Free list */
	g_tree_destroy (cd->symbols_to_remove);
}

void
make_composites (struct worker_task *task)
{
	g_hash_table_foreach (task->results, composites_metric_callback, task);
}

static void
classifiers_callback (gpointer value, void *arg)
{
	struct worker_task             *task = arg;
	struct classifier_config       *cl = value;
	struct classifier_ctx          *ctx;
	struct mime_text_part          *text_part;
	struct statfile                *st;
	GTree                          *tokens = NULL;
	GList                          *cur;
	f_str_t                         c;
	gchar                          *header = NULL;
	gboolean                        is_twopart = FALSE;
	
	if ((header = g_hash_table_lookup (cl->opts, "header")) != NULL) {
		cur = message_get_header (task->task_pool, task->message, header, FALSE);
		if (cur) {
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, cur);
		}
	}
	else {
		cur = g_list_first (task->text_parts);
		if (cur != NULL && cur->next != NULL && cur->next->next == NULL) {
			is_twopart = TRUE;
		}
	}
	ctx = cl->classifier->init_func (task->task_pool, cl);

	if ((tokens = g_hash_table_lookup (task->tokens, cl->tokenizer)) == NULL) {
		while (cur != NULL) {
			if (header) {
				c.len = strlen (cur->data);
				if (c.len > 0) {
					c.begin = cur->data;
					if (!cl->tokenizer->tokenize_func (cl->tokenizer, task->task_pool, &c, &tokens, FALSE, FALSE, NULL)) {
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
				if (is_twopart && cur->next == NULL) {
					/* Compare part's content */
					if (fuzzy_compare_parts (cur->data, cur->prev->data) >= COMMON_PART_FACTOR) {
						msg_info ("message <%s> has two common text parts, ignore the last one", task->message_id);
						break;
					}
				}
				c.begin = text_part->content->data;
				c.len = text_part->content->len;
				/* Tree would be freed at task pool freeing */
				if (!cl->tokenizer->tokenize_func (cl->tokenizer, task->task_pool, &c, &tokens,
						FALSE, text_part->is_utf, text_part->urls_offset)) {
					msg_info ("cannot tokenize input");
					return;
				}
			}
			cur = g_list_next (cur);
		}
		g_hash_table_insert (task->tokens, cl->tokenizer, tokens);
	}

	if (tokens == NULL) {
		return;
	}

	/* Take care of subject */
	tokenize_subject (task, &tokens);
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

	if (task->is_skipped) {
		return;
	}

	if (task->tokens == NULL) {
		task->tokens = g_hash_table_new (g_direct_hash, g_direct_equal);
		memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_hash_table_destroy, task->tokens);
	}

	g_list_foreach (task->cfg->classifiers, classifiers_callback, task);

	/* Process results */
	make_composites (task);
}

static void
insert_metric_header (gpointer metric_name, gpointer metric_value, gpointer data)
{
	struct worker_task             *task = (struct worker_task *)data;
	gint                            r = 0;
	/* Try to be rfc2822 compatible and avoid long headers with folding */
	gchar                           header_name[128], outbuf[1000];
	GList                          *symbols = NULL, *cur;
	struct metric_result           *metric_res = (struct metric_result *)metric_value;
	double                          ms, rs;

	rspamd_snprintf (header_name, sizeof (header_name), "X-Spam-%s", metric_res->metric->name);

	if (!check_metric_settings (metric_res, &ms, &rs)) {
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
			r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "%s,", (gchar *)cur->data);
		}
		else {
			r += rspamd_snprintf (outbuf + r, sizeof (outbuf) - r, "%s", (gchar *)cur->data);
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

gboolean
check_action_str (const gchar *data, gint *result)
{
	if (g_ascii_strncasecmp (data, "reject", sizeof ("reject") - 1) == 0) {
		*result = METRIC_ACTION_REJECT;
	}
	else if (g_ascii_strncasecmp (data, "greylist", sizeof ("greylist") - 1) == 0) {
		*result = METRIC_ACTION_GREYLIST;
	}
	else if (g_ascii_strncasecmp (data, "add_header", sizeof ("add_header") - 1) == 0) {
		*result = METRIC_ACTION_ADD_HEADER;
	}
	else if (g_ascii_strncasecmp (data, "rewrite_subject", sizeof ("rewrite_subject") - 1) == 0) {
		*result = METRIC_ACTION_REWRITE_SUBJECT;
	}
	else {
		return FALSE;
	}
	return TRUE;
}

const gchar *
str_action_metric (enum rspamd_metric_action action)
{
	switch (action) {
	case METRIC_ACTION_REJECT:
		return "reject";
	case METRIC_ACTION_SOFT_REJECT:
		return "soft reject";
	case METRIC_ACTION_REWRITE_SUBJECT:
		return "rewrite subject";
	case METRIC_ACTION_ADD_HEADER:
		return "add header";
	case METRIC_ACTION_GREYLIST:
		return "greylist";
	case METRIC_ACTION_NOACTION:
		return "no action";
	}

	return "unknown action";
}

gint
check_metric_action (double score, double required_score, struct metric *metric)
{
	GList                          *cur;
	struct metric_action           *action, *selected_action = NULL;
	double                          max_score = 0;

	if (score >= required_score) {
		return metric->action;
	}
	else if (metric->actions == NULL) {
		return METRIC_ACTION_NOACTION;
	}
	else {
		cur = metric->actions;
		while (cur) {
			action = cur->data;
			if (score >= action->score && action->score > max_score) {
				selected_action = action;
				max_score = action->score;
			}
			cur = g_list_next (cur);
		}
		if (selected_action) {
			return selected_action->action;
		}
		else {
			return METRIC_ACTION_NOACTION;
		}
	}
}

gboolean
learn_task (const gchar *statfile, struct worker_task *task, GError **err)
{
	GList                          *cur, *ex;
	struct classifier_config       *cl;
	struct classifier_ctx          *cls_ctx;
	gchar                          *s;
	f_str_t                         c;
	GTree                          *tokens = NULL;
	struct statfile                *st;
	stat_file_t                    *stf;
	gdouble                         sum;
	struct mime_text_part          *part;
	gboolean                        is_utf = FALSE, is_twopart = FALSE;

	/* Load classifier by symbol */
	cl = g_hash_table_lookup (task->cfg->classifiers_symbols, statfile);
	if (cl == NULL) {
		g_set_error (err, filter_error_quark(), 1, "Statfile %s is not configured in any classifier", statfile);
		return FALSE;
	}

	/* If classifier has 'header' option just classify header of this type */
	if ((s = g_hash_table_lookup (cl->opts, "header")) != NULL) {
		cur = message_get_header (task->task_pool, task->message, s, FALSE);
		if (cur) {
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func)g_list_free, cur);
		}
	}
	else {
		/* Classify message otherwise */
		cur = g_list_first (task->text_parts);
		if (cur != NULL && cur->next != NULL && cur->next->next == NULL) {
			is_twopart = TRUE;
		}
	}

	/* Get tokens from each element */
	while (cur) {
		if (s != NULL) {
			c.len = strlen (cur->data);
			c.begin = cur->data;
			ex = NULL;
		}
		else {
			part = cur->data;
			/* Skip empty parts */
			if (part->is_empty) {
				cur = g_list_next (cur);
				continue;
			}
			c.begin = part->content->data;
			c.len = part->content->len;
			is_utf = part->is_utf;
			ex = part->urls_offset;
			if (is_twopart && cur->next == NULL) {
				/* Compare part's content */
				if (fuzzy_compare_parts (cur->data, cur->prev->data) >= COMMON_PART_FACTOR) {
					msg_info ("message <%s> has two common text parts, ignore the last one", task->message_id);
					break;
				}
			}
		}
		/* Get tokens */
		if (!cl->tokenizer->tokenize_func (
				cl->tokenizer, task->task_pool,
				&c, &tokens, FALSE, is_utf, ex)) {
			g_set_error (err, filter_error_quark(), 2, "Cannot tokenize message");
			return FALSE;
		}
		cur = g_list_next (cur);
	}

	/* Handle messages without text */
	if (tokens == NULL) {
		g_set_error (err, filter_error_quark(), 3, "Cannot tokenize message, no text data");
		msg_info ("learn failed for message <%s>, no tokens to extract", task->message_id);
		return FALSE;
	}

	/* Take care of subject */
	tokenize_subject (task, &tokens);

	/* Init classifier */
	cls_ctx = cl->classifier->init_func (
			task->task_pool, cl);
	/* Get or create statfile */
	stf = get_statfile_by_symbol (task->worker->srv->statfile_pool,
			cl, statfile, &st, TRUE);

	/* Learn */
	if (stf== NULL || !cl->classifier->learn_func (
			cls_ctx, task->worker->srv->statfile_pool,
			statfile, tokens, TRUE, &sum,
			1.0, err)) {
		if (*err) {
			msg_info ("learn failed for message <%s>, learn error: %s", task->message_id, (*err)->message);
			return FALSE;
		}
		else {
			g_set_error (err, filter_error_quark(), 4, "Learn failed, unknown learn classifier error");
			msg_info ("learn failed for message <%s>, unknown learn error", task->message_id);
			return FALSE;
		}
	}
	/* Increase statistics */
	task->worker->srv->stat->messages_learned++;

	maybe_write_binlog (cl, st, stf, tokens);
	msg_info ("learn success for message <%s>, for statfile: %s, sum weight: %.2f",
			task->message_id, statfile, sum);
	statfile_pool_plan_invalidate (task->worker->srv->statfile_pool,
			DEFAULT_STATFILE_INVALIDATE_TIME,
			DEFAULT_STATFILE_INVALIDATE_JITTER);

	return TRUE;
}

gboolean
learn_task_spam (struct classifier_config *cl, struct worker_task *task, gboolean is_spam, GError **err)
{
	GList                          *cur, *ex;
	struct classifier_ctx          *cls_ctx;
	f_str_t                         c;
	GTree                          *tokens = NULL;
	struct mime_text_part          *part;
	gboolean                        is_utf = FALSE, is_twopart = FALSE;

	cur = g_list_first (task->text_parts);
	if (cur != NULL && cur->next != NULL && cur->next->next == NULL) {
		is_twopart = TRUE;
	}

	/* Get tokens from each element */
	while (cur) {
		part = cur->data;
		/* Skip empty parts */
		if (part->is_empty) {
			cur = g_list_next (cur);
			continue;
		}
		c.begin = part->content->data;
		c.len = part->content->len;
		is_utf = part->is_utf;
		ex = part->urls_offset;
		if (is_twopart && cur->next == NULL) {
			/* Compare part's content */
			if (fuzzy_compare_parts (cur->data, cur->prev->data) >= COMMON_PART_FACTOR) {
				msg_info ("message <%s> has two common text parts, ignore the last one", task->message_id);
				break;
			}
		}
		/* Get tokens */
		if (!cl->tokenizer->tokenize_func (
				cl->tokenizer, task->task_pool,
				&c, &tokens, FALSE, is_utf, ex)) {
			g_set_error (err, filter_error_quark(), 2, "Cannot tokenize message");
			return FALSE;
		}
		cur = g_list_next (cur);
	}

	/* Handle messages without text */
	if (tokens == NULL) {
		g_set_error (err, filter_error_quark(), 3, "Cannot tokenize message, no text data");
		msg_info ("learn failed for message <%s>, no tokens to extract", task->message_id);
		return FALSE;
	}

	/* Take care of subject */
	tokenize_subject (task, &tokens);

	/* Init classifier */
	cls_ctx = cl->classifier->init_func (
			task->task_pool, cl);
	/* Learn */
	if (!cl->classifier->learn_spam_func (
			cls_ctx, task->worker->srv->statfile_pool,
			tokens, task, is_spam, err)) {
		if (*err) {
			msg_info ("learn failed for message <%s>, learn error: %s", task->message_id, (*err)->message);
			return FALSE;
		}
		else {
			g_set_error (err, filter_error_quark(), 4, "Learn failed, unknown learn classifier error");
			msg_info ("learn failed for message <%s>, unknown learn error", task->message_id);
			return FALSE;
		}
	}
	/* Increase statistics */
	task->worker->srv->stat->messages_learned++;

	msg_info ("learn success for message <%s>",
			task->message_id);
	statfile_pool_plan_invalidate (task->worker->srv->statfile_pool,
			DEFAULT_STATFILE_INVALIDATE_TIME,
			DEFAULT_STATFILE_INVALIDATE_JITTER);

	return TRUE;
}

/* 
 * vi:ts=4 
 */
