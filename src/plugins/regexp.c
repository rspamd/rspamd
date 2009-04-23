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

/***MODULE:regexp
 * rspamd module that implements different regexp rules
 */


#include <evdns.h>

#include "../config.h"
#include "../main.h"
#include "../message.h"
#include "../modules.h"
#include "../cfg_file.h"
#include "../expressions.h"

struct regexp_module_item {
	struct expression *expr;
	char *symbol;
};

struct regexp_ctx {
	int (*header_filter)(struct worker_task *task);
	int (*mime_filter)(struct worker_task *task);
	int (*message_filter)(struct worker_task *task);
	int (*url_filter)(struct worker_task *task);
	GList *items;
	char *metric;

	memory_pool_t *regexp_pool;
};

static struct regexp_ctx *regexp_module_ctx = NULL;

static int regexp_common_filter (struct worker_task *task);
static gboolean rspamd_regexp_match_number (struct worker_task *task, GList *args);

int
regexp_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	regexp_module_ctx = g_malloc (sizeof (struct regexp_ctx));

	regexp_module_ctx->header_filter = regexp_common_filter;
	regexp_module_ctx->mime_filter = NULL;
	regexp_module_ctx->message_filter = NULL;
	regexp_module_ctx->url_filter = NULL;
	regexp_module_ctx->regexp_pool = memory_pool_new (1024);
	regexp_module_ctx->items = NULL;

	*ctx = (struct module_ctx *)regexp_module_ctx;
	register_expression_function ("regexp_match_number", rspamd_regexp_match_number);
	
	return 0;
}

static gboolean
read_regexp_expression (memory_pool_t *pool, struct regexp_module_item *chain, char *symbol, char *line, struct config_file *cfg)
{	
	struct expression *e, *cur;

	e = parse_expression (regexp_module_ctx->regexp_pool, line);
	if (e == NULL) {
		msg_warn ("read_regexp_expression: %s = \"%s\" is invalid regexp expression", symbol, line);
		return FALSE;
	}
	chain->expr = e;
	cur = e;
	while (cur) {
		if (cur->type == EXPR_REGEXP) {
			cur->content.operand = parse_regexp (pool, cur->content.operand, cfg->raw_mode);
			if (cur->content.operand == NULL) {
				msg_warn ("read_regexp_expression: cannot parse regexp, skip expression %s = \"%s\"", symbol, line);
				return FALSE;
			}
			cur->type = EXPR_REGEXP_PARSED;
		}
		cur = cur->next;
	}

	return TRUE;
}

int
regexp_module_config (struct config_file *cfg)
{
	LIST_HEAD (moduleoptq, module_opt) *cur_module_opt = NULL;
	struct module_opt *cur;
	struct regexp_module_item *cur_item;
	char *value;
	int res = TRUE;

	if ((value = get_module_opt (cfg, "regexp", "metric")) != NULL) {
		regexp_module_ctx->metric = memory_pool_strdup (regexp_module_ctx->regexp_pool, value);
		g_free (value);
	}
	else {
		regexp_module_ctx->metric = DEFAULT_METRIC;
	}

	cur_module_opt = g_hash_table_lookup (cfg->modules_opts, "regexp");
	if (cur_module_opt != NULL) {
		LIST_FOREACH (cur, cur_module_opt, next) {
			if (strcmp (cur->param, "metric") == 0) {
				continue;
			}
			cur_item = memory_pool_alloc0 (regexp_module_ctx->regexp_pool, sizeof (struct regexp_module_item));
			cur_item->symbol = cur->param;
			if (!read_regexp_expression (regexp_module_ctx->regexp_pool, cur_item, cur->param, cur->value, cfg)) {
				res = FALSE;
			}
			regexp_module_ctx->items = g_list_prepend (regexp_module_ctx->items, cur_item);
		}
	}
	
	return res;
}

int
regexp_module_reconfig (struct config_file *cfg)
{
	memory_pool_delete (regexp_module_ctx->regexp_pool);
	regexp_module_ctx->regexp_pool = memory_pool_new (1024);

	return regexp_module_config (cfg);
}

static gsize
process_regexp (struct rspamd_regexp *re, struct worker_task *task)
{
	char *headerv, *c, t;
	struct mime_text_part *part;
	GList *cur, *headerlist;
	GRegex *regexp;
	struct uri *url;
	int r;

	if (re == NULL) {
		msg_info ("process_regexp: invalid regexp passed");
		return 0;
	}
	
	if ((r = task_cache_check (task, re)) != -1) {
		return r == 1;
	}

	switch (re->type) {
		case REGEXP_NONE:
			return 0;
		case REGEXP_HEADER:
			if (re->header == NULL) {
				msg_info ("process_regexp: header regexp without header name: '%s'", re->regexp_text);
				task_cache_add (task, re, 0);
				return 0;
			}
			msg_debug ("process_regexp: checking header regexp: %s = /%s/", re->header, re->regexp_text);
			headerlist = message_get_header (task->task_pool, task->message, re->header);
			if (headerlist == NULL) {
				task_cache_add (task, re, 0);
				return 0;
			}
			else {
				if (re->regexp == NULL) {
					msg_debug ("process_regexp: regexp contains only header and it is found %s", re->header);
					task_cache_add (task, re, 1);
					g_list_free (headerlist);
					return 1;
				}
				cur = headerlist;
				while (cur) {
					if (cur->data && g_regex_match (re->regexp, cur->data, 0, NULL) == TRUE) {
						task_cache_add (task, re, 1);
						return 1;
					}
					cur = g_list_next (cur);
				}
				g_list_free (headerlist);
				task_cache_add (task, re, 0);
				return 0;
			}
			break;
		case REGEXP_MIME:
			msg_debug ("process_regexp: checking mime regexp: /%s/", re->regexp_text);
			cur = g_list_first (task->text_parts);
			while (cur) {
				part = (struct mime_text_part *)cur->data;
				if (part->is_raw) {
					regexp = re->raw_regexp;
				}
				else {
					regexp = re->regexp;
				}
				if (g_regex_match_full (regexp, part->orig->data, part->orig->len, 0, 0, NULL, NULL) == TRUE) {
					task_cache_add (task, re, 1);
					return 1;
				}
				cur = g_list_next (cur);
			}
			task_cache_add (task, re, 0);
			return 0;
		case REGEXP_MESSAGE:
			msg_debug ("process_regexp: checking message regexp: /%s/", re->regexp_text);
			if (g_regex_match_full (re->regexp, task->msg->begin, task->msg->len, 0, 0, NULL, NULL) == TRUE) {
				task_cache_add (task, re, 1);
				return 1;
			}
			task_cache_add (task, re, 0);
			return 0;
		case REGEXP_URL:
			msg_debug ("process_regexp: checking url regexp: /%s/", re->regexp_text);
			TAILQ_FOREACH (url, &task->urls, next) {
				if (g_regex_match (re->regexp, struri (url), 0, NULL) == TRUE) {
					task_cache_add (task, re, 1);
					return 1;
				}
			}
			task_cache_add (task, re, 0);
			return 0;
		case REGEXP_RAW_HEADER:
			msg_debug ("process_regexp: checking for raw header: %s with regexp: /%s/", re->header, re->regexp_text);
			if (task->raw_headers == NULL) {
				msg_debug ("process_regexp: cannot check for raw header in message, no headers found");
				task_cache_add (task, re, 0);
				return 0;
			}
			if ((headerv = strstr (task->raw_headers, re->header)) == NULL) {
				/* No header was found */
				task_cache_add (task, re, 0);
				return 0;
			}
			/* Skip header name and start matching after regexp */
			headerv += strlen (re->header) + 1;
			/* Now the main problem is to find position of end of raw header */
			c = headerv;
			while (*c) {
				/* We need to handle all types of line end */
				if ((*c == '\r' && *(c + 1) == '\n')) {
					c ++;
					/* Check for folding */
					if (!g_ascii_isspace (*(c + 1))) {
						c ++;
						break;
					}
				} 
				else if (*c == '\r' || *c == '\n') {
					if (!g_ascii_isspace (*(c + 1))) {
						c ++;
						break;
					}
				}
				c ++;
			}
			/* Temporary null terminate this part of string */
			t = *c;
			*c = '\0';
			if (g_regex_match (re->raw_regexp, headerv, 0, NULL) == TRUE) {
				*c = t;
				task_cache_add (task, re, 1);
				return 1;
			}
			*c = t;
			task_cache_add (task, re, 0);
			return 0;
	}

	/* Not reached */
	return 0;
}

static gboolean 
optimize_regexp_expression (struct expression **e, GQueue *stack, gboolean res)
{
	struct expression *it = *e;
	gboolean ret = FALSE, is_nearest = TRUE;
	
	while (it) {
		/* Find first operation for this iterator */
		if (it->type == EXPR_OPERATION) {
			/* If this operation is just ! just inverse res and check for further operators */
			if (it->content.operation == '!' && is_nearest) {
				msg_debug ("optimize_regexp_expression: found '!' operator, inversing result");
				res = !res;
				it = it->next;
				*e = it;
				continue;
			}
			else if (it->content.operation == '&' && res == FALSE) {
				msg_debug ("optimize_regexp_expression: found '&' and previous expression is false");
				*e = it;
				ret = TRUE;
			}
			else if (it->content.operation == '|' && res == TRUE) {
				msg_debug ("optimize_regexp_expression: found '|' and previous expression is true");
				*e = it;
				ret = TRUE;
			}
			break;
		}
		is_nearest = FALSE;
		it = it->next;
	}

	g_queue_push_head (stack, GSIZE_TO_POINTER (res));

	return ret;
}

static gboolean
process_regexp_expression (struct expression *expr, struct worker_task *task)
{
	GQueue *stack;
	gsize cur, op1, op2;
	struct expression *it = expr;
	gboolean try_optimize = TRUE;
	
	stack = g_queue_new ();

	while (it) {
		if (it->type == EXPR_REGEXP_PARSED) {
			/* Find corresponding symbol */
			cur = process_regexp ((struct rspamd_regexp *)it->content.operand, task);
			msg_debug ("process_regexp_expression: regexp %s found", cur ? "is" : "is not");
			if (try_optimize) {
				try_optimize = optimize_regexp_expression (&it, stack, cur);
			} else {
				g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
			}

		} else if (it->type == EXPR_FUNCTION) {
			cur = (gsize)call_expression_function ((struct expression_function *)it->content.operand, task);
			msg_debug ("process_regexp_expression: function %s returned %s", ((struct expression_function *)it->content.operand)->name,
															cur ? "true" : "false");
			if (try_optimize) {
				try_optimize = optimize_regexp_expression (&it, stack, cur);
			} else {
				g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
			}
		} else if (it->type == EXPR_REGEXP) {
			/* Compile regexp if it is not parsed */
			it->content.operand = parse_regexp (task->task_pool, it->content.operand, task->cfg->raw_mode);
			if (it->content.operand == NULL) {
				msg_warn ("process_regexp_expression: cannot parse regexp, skip expression");
				return FALSE;
			}
			it->type = EXPR_REGEXP_PARSED;
			/* Continue with this regexp once again */
			continue;
		} else if (it->type == EXPR_OPERATION) {
			if (g_queue_is_empty (stack)) {
				/* Queue has no operands for operation, exiting */
				g_queue_free (stack);
				return FALSE;
			}
			try_optimize = TRUE;
			switch (it->content.operation) {
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
					it = it->next;
					continue;
			}
		}
		if (it) {
			it = it->next;
		}
	}
	if (!g_queue_is_empty (stack)) {
		op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
		if (op1) {
			return TRUE;
		}
	}

	g_queue_free (stack);

	return FALSE;
}

static void
process_regexp_item (struct regexp_module_item *item, struct worker_task *task)
{
	if (process_regexp_expression (item->expr, task)) {
		insert_result (task, regexp_module_ctx->metric, item->symbol, 1, NULL);
	}
}

static int
regexp_common_filter (struct worker_task *task)
{
	GList *cur_expr = g_list_first (regexp_module_ctx->items);

	while (cur_expr) {
		process_regexp_item ((struct regexp_module_item *)cur_expr->data, task);
		cur_expr = g_list_next (cur_expr);
	}

	return 0;
}

static gboolean 
rspamd_regexp_match_number (struct worker_task *task, GList *args)
{
	int param_count, res = 0;
	struct expression_argument *arg;
	GList *cur;
	
	if (args == NULL) {
		msg_warn ("rspamd_regexp_match_number: no parameters to function");
		return FALSE;
	}
	
	arg = get_function_arg (args->data, task, TRUE);
	param_count = strtoul (arg->data, NULL, 10);
	
	cur = args->next;
	while (cur) {
		arg = get_function_arg (cur->data, task, FALSE);
		if (arg && arg->type == EXPRESSION_ARGUMENT_BOOL) {
			if ((gboolean)GPOINTER_TO_SIZE (arg->data)) {
				res ++;
			}
		}
		else {
			if (process_regexp_expression (cur->data, task)) {
				res ++;
			}
			if (res >= param_count) {
				return TRUE;
			}
		}
		cur = g_list_next (cur);
	}

	return res >= param_count;
}
