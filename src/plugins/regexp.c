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
#include "../util.h"
#include "../expressions.h"
#include "../view.h"

#define DEFAULT_STATFILE_PREFIX "./"

struct regexp_module_item {
	struct expression              *expr;
	char                           *symbol;
	long int                        avg_time;
};

struct autolearn_data {
	char                           *statfile_name;
	char                           *symbol;
	float                           weight;
};

struct regexp_ctx {
	int                             (*filter) (struct worker_task * task);
	GHashTable                     *autolearn_symbols;
	char                           *metric;
	char                           *statfile_prefix;

	memory_pool_t                  *regexp_pool;
};

static struct regexp_ctx       *regexp_module_ctx = NULL;

static int                      regexp_common_filter (struct worker_task *task);
static gboolean                 rspamd_regexp_match_number (struct worker_task *task, GList * args, void *unused);
static gboolean                 rspamd_raw_header_exists (struct worker_task *task, GList * args, void *unused);
static gboolean                 rspamd_check_smtp_data (struct worker_task *task, GList * args, void *unused);
static void                     process_regexp_item (struct worker_task *task, void *user_data);


int
regexp_module_init (struct config_file *cfg, struct module_ctx **ctx)
{
	regexp_module_ctx = g_malloc (sizeof (struct regexp_ctx));

	regexp_module_ctx->filter = regexp_common_filter;
	regexp_module_ctx->regexp_pool = memory_pool_new (1024);
	regexp_module_ctx->autolearn_symbols = g_hash_table_new (g_str_hash, g_str_equal);

	*ctx = (struct module_ctx *)regexp_module_ctx;
	register_expression_function ("regexp_match_number", rspamd_regexp_match_number, NULL);
	register_expression_function ("raw_header_exists", rspamd_raw_header_exists, NULL);
	register_expression_function ("check_smtp_data", rspamd_check_smtp_data, NULL);

	return 0;
}

static                          gboolean
read_regexp_expression (memory_pool_t * pool, struct regexp_module_item *chain, char *symbol, char *line, struct config_file *cfg)
{
	struct expression              *e, *cur;

	e = parse_expression (regexp_module_ctx->regexp_pool, line);
	if (e == NULL) {
		msg_warn ("%s = \"%s\" is invalid regexp expression", symbol, line);
		return FALSE;
	}
	chain->expr = e;
	cur = e;
	while (cur) {
		if (cur->type == EXPR_REGEXP) {
			cur->content.operand = parse_regexp (pool, cur->content.operand, cfg->raw_mode);
			if (cur->content.operand == NULL) {
				msg_warn ("cannot parse regexp, skip expression %s = \"%s\"", symbol, line);
				return FALSE;
			}
			cur->type = EXPR_REGEXP_PARSED;
		}
		cur = cur->next;
	}

	return TRUE;
}

/* 
 * Parse string in format:
 * SYMBOL:statfile:weight
 */
void
parse_autolearn_param (const char *param, const char *value, struct config_file *cfg)
{
	struct autolearn_data          *d;
	char                           *p;

	p = memory_pool_strdup (regexp_module_ctx->regexp_pool, value);
	d = memory_pool_alloc (regexp_module_ctx->regexp_pool, sizeof (struct autolearn_data));

	d->symbol = strsep (&p, ":");
	if (d->symbol) {
		d->statfile_name = strsep (&p, ":");
		if (d->statfile_name) {
			if (p != NULL && *p != '\0') {
				d->weight = strtod (p, NULL);
				g_hash_table_insert (regexp_module_ctx->autolearn_symbols, d->symbol, d);
			}
		}
		else {
			msg_warn ("cannot extract statfile name from %s", p);
		}
	}
	else {
		msg_warn ("cannot extract symbol name from %s", p);
	}
}

int
regexp_module_config (struct config_file *cfg)
{
	GList                          *cur_opt = NULL;
	struct module_opt              *cur;
	struct regexp_module_item      *cur_item;
	struct metric                  *metric;
	char                           *value;
	int                             res = TRUE;
	double                         *w;

	if ((value = get_module_opt (cfg, "regexp", "metric")) != NULL) {
		regexp_module_ctx->metric = memory_pool_strdup (regexp_module_ctx->regexp_pool, value);
		g_free (value);
	}
	else {
		regexp_module_ctx->metric = DEFAULT_METRIC;
	}
	if ((value = get_module_opt (cfg, "regexp", "statfile_prefix")) != NULL) {
		regexp_module_ctx->statfile_prefix = memory_pool_strdup (regexp_module_ctx->regexp_pool, value);
		g_free (value);
	}
	else {
		regexp_module_ctx->statfile_prefix = DEFAULT_STATFILE_PREFIX;
	}

	metric = g_hash_table_lookup (cfg->metrics, regexp_module_ctx->metric);
	if (metric == NULL) {
		msg_err ("cannot find metric definition %s", regexp_module_ctx->metric);
		return FALSE;
	}

	cur_opt = g_hash_table_lookup (cfg->modules_opts, "regexp");
	while (cur_opt) {
		cur = cur_opt->data;
		if (strcmp (cur->param, "metric") == 0 || strcmp (cur->param, "statfile_prefix") == 0) {
			continue;
		}
		else if (g_ascii_strncasecmp (cur->param, "autolearn", sizeof ("autolearn") - 1) == 0) {
			parse_autolearn_param (cur->param, cur->value, cfg);
			continue;
		}
		cur_item = memory_pool_alloc0 (regexp_module_ctx->regexp_pool, sizeof (struct regexp_module_item));
		cur_item->symbol = cur->param;
		if (!read_regexp_expression (regexp_module_ctx->regexp_pool, cur_item, cur->param, cur->value, cfg)) {
			res = FALSE;
		}

		/* Search in factors hash table */
		w = g_hash_table_lookup (cfg->factors, cur->param);
		if (w == NULL) {
			register_symbol (&metric->cache, cur->param, 1, process_regexp_item, cur_item);
		}
		else {
			register_symbol (&metric->cache, cur->param, *w, process_regexp_item, cur_item);
		}

		cur_opt = g_list_next (cur_opt);
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

static const char              *
find_raw_header_pos (const char *headers, const char *headerv)
{
	const char                     *p = headers;
	gsize                           headerlen = strlen (headerv);

	if (headers == NULL) {
		return NULL;
	}

	while (*p) {
		/* Try to find headers only at the begin of line */
		if (*p == '\r' || *p == '\n') {
			if (*(p + 1) == '\n' && *p == '\r') {
				p++;
			}
			if (g_ascii_isspace (*(++p))) {
				/* Folding */
				continue;
			}
			if (g_ascii_strncasecmp (p, headerv, headerlen) == 0) {
				/* Find semicolon */
				p += headerlen;
				if (*p == ':') {
					while (*p && g_ascii_isspace (*(++p)));
					return p;
				}
			}
		}
		if (*p != '\0') {
			p++;
		}
	}

	return NULL;
}

struct url_regexp_param {
	struct worker_task             *task;
	GRegex                         *regexp;
	struct rspamd_regexp           *re;
	gboolean                        found;
};

static                          gboolean
tree_url_callback (gpointer key, gpointer value, void *data)
{
	struct url_regexp_param        *param = data;
	struct uri                     *url = value;

	if (g_regex_match (param->regexp, struri (url), 0, NULL) == TRUE) {
		task_cache_add (param->task, param->re, 1);
		param->found = TRUE;
		return TRUE;
	}

	return FALSE;
}

static                          gsize
process_regexp (struct rspamd_regexp *re, struct worker_task *task, const char *additional)
{
	char                           *headerv, *c, t;
	struct mime_text_part          *part;
	GList                          *cur, *headerlist;
	GRegex                         *regexp;
	struct url_regexp_param         callback_param;
	int                             r;


	if (re == NULL) {
		msg_info ("invalid regexp passed");
		return 0;
	}

	if ((r = task_cache_check (task, re)) != -1) {
		debug_task ("regexp /%s/ is found in cache, result: %d", re->regexp_text, r);
		return r == 1;
	}
	
	if (additional != NULL) {
		/* We have additional parameter defined, so ignore type of regexp expression and use it for parsing */
		if (g_regex_match_full (regexp, additional, strlen (additional), 0, 0, NULL, NULL) == TRUE) {
			task_cache_add (task, re, 1);
			return 1;
		}
		else {
			task_cache_add (task, re, 0);
			return 0;
		}
	}

	switch (re->type) {
	case REGEXP_NONE:
		msg_warn ("bad error detected: /%s/ has invalid regexp type", re->regexp_text);
		return 0;
	case REGEXP_HEADER:
		if (re->header == NULL) {
			msg_info ("header regexp without header name: '%s'", re->regexp_text);
			task_cache_add (task, re, 0);
			return 0;
		}
		debug_task ("checking header regexp: %s = /%s/", re->header, re->regexp_text);
		headerlist = message_get_header (task->task_pool, task->message, re->header);
		if (headerlist == NULL) {
			task_cache_add (task, re, 0);
			return 0;
		}
		else {
			memory_pool_add_destructor (task->task_pool, (pool_destruct_func) g_list_free, headerlist);
			if (re->regexp == NULL) {
				debug_task ("regexp contains only header and it is found %s", re->header);
				task_cache_add (task, re, 1);
				return 1;
			}
			cur = headerlist;
			while (cur) {
				debug_task ("found header \"%s\" with value \"%s\"", re->header, (char *)cur->data);
				if (cur->data && g_regex_match (re->regexp, cur->data, 0, NULL) == TRUE) {
					task_cache_add (task, re, 1);
					return 1;
				}
				cur = g_list_next (cur);
			}
			task_cache_add (task, re, 0);
			return 0;
		}
		break;
	case REGEXP_MIME:
		debug_task ("checking mime regexp: /%s/", re->regexp_text);
		cur = g_list_first (task->text_parts);
		while (cur) {
			part = (struct mime_text_part *)cur->data;
			/* Skip empty parts */
			if (part->is_empty) {
				cur = g_list_next (cur);
				continue;
			}
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
		debug_task ("checking message regexp: /%s/", re->regexp_text);
		if (g_regex_match_full (re->raw_regexp, task->msg->begin, task->msg->len, 0, 0, NULL, NULL) == TRUE) {
			task_cache_add (task, re, 1);
			return 1;
		}
		task_cache_add (task, re, 0);
		return 0;
	case REGEXP_URL:
		debug_task ("checking url regexp: /%s/", re->regexp_text);
		cur = g_list_first (task->text_parts);
		while (cur) {
			part = (struct mime_text_part *)cur->data;
			/* Skip empty parts */
			if (part->is_empty) {
				cur = g_list_next (cur);
				continue;
			}
			if (part->is_raw) {
				regexp = re->raw_regexp;
			}
			else {
				regexp = re->regexp;
			}
			callback_param.task = task;
			callback_param.regexp = regexp;
			callback_param.re = re;
			callback_param.found = FALSE;
			if (part->urls) {
				g_tree_foreach (part->urls, tree_url_callback, &callback_param);
			}
			if (part->html_urls && callback_param.found == FALSE) {
				g_tree_foreach (part->html_urls, tree_url_callback, &callback_param);
			}
			cur = g_list_next (cur);
		}
		if (callback_param.found == FALSE) {
			task_cache_add (task, re, 0);
		}
		return 0;
	case REGEXP_RAW_HEADER:
		debug_task ("checking for raw header: %s with regexp: /%s/", re->header, re->regexp_text);
		if (task->raw_headers == NULL) {
			debug_task ("cannot check for raw header in message, no headers found");
			task_cache_add (task, re, 0);
			return 0;
		}
		if ((headerv = (char *)find_raw_header_pos (task->raw_headers, re->header)) == NULL) {
			/* No header was found */
			task_cache_add (task, re, 0);
			return 0;
		}
		/* Now the main problem is to find position of end of raw header */
		c = headerv;
		while (*c) {
			/* We need to handle all types of line end */
			if ((*c == '\r' && *(c + 1) == '\n')) {
				c++;
				/* Check for folding */
				if (!g_ascii_isspace (*(c + 1))) {
					c++;
					break;
				}
			}
			else if (*c == '\r' || *c == '\n') {
				if (!g_ascii_isspace (*(c + 1))) {
					c++;
					break;
				}
			}
			c++;
		}
		/* Temporary null terminate this part of string */
		t = *c;
		*c = '\0';
		debug_task ("found raw header \"%s\" with value \"%s\"", re->header, headerv);
		if (g_regex_match (re->raw_regexp, headerv, 0, NULL) == TRUE) {
			*c = t;
			task_cache_add (task, re, 1);
			return 1;
		}
		*c = t;
		task_cache_add (task, re, 0);
		return 0;
	default:
		msg_warn ("bad error detected: %p is not a valid regexp object", re);
	}

	/* Not reached */
	return 0;
}

static                          gboolean
optimize_regexp_expression (struct expression **e, GQueue * stack, gboolean res)
{
	struct expression              *it = (*e)->next;
	gboolean                        ret = FALSE, is_nearest = TRUE;
	int                             skip_level = 0;

	/* Skip nearest logical operators from optimization */
	if (!it || (it->type == EXPR_OPERATION && it->content.operation != '!')) {
		g_queue_push_head (stack, GSIZE_TO_POINTER (res));
		return ret;
	}

	while (it) {
		/* Find first operation for this iterator */
		if (it->type == EXPR_OPERATION) {
			/* If this operation is just ! just inverse res and check for further operators */
			if (it->content.operation == '!') {
				if (is_nearest) {
					msg_debug ("found '!' operator, inversing result");
					res = !res;
					*e = it;
				}
				it = it->next;
				continue;
			}
			else {
				skip_level--;
			}
			/* Check whether we found corresponding operator for this operand */
			if (skip_level <= 0) {
				if (it->content.operation == '|' && res == TRUE) {
					msg_debug ("found '|' and previous expression is true");
					*e = it;
					ret = TRUE;
				}
				else if (it->content.operation == '&' && res == FALSE) {
					msg_debug ("found '&' and previous expression is false");
					*e = it;
					ret = TRUE;
				}
				break;
			}
		}
		else {
			is_nearest = FALSE;
			skip_level++;
		}
		it = it->next;
	}

	g_queue_push_head (stack, GSIZE_TO_POINTER (res));

	return ret;
}

static                          gboolean
process_regexp_expression (struct expression *expr, char *symbol, struct worker_task *task, const char *additional)
{
	GQueue                         *stack;
	gsize                           cur, op1, op2;
	struct expression              *it = expr;
	struct rspamd_regexp           *re;
	gboolean                        try_optimize = TRUE;

	stack = g_queue_new ();

	while (it) {
		if (it->type == EXPR_REGEXP_PARSED) {
			/* Find corresponding symbol */
			cur = process_regexp ((struct rspamd_regexp *)it->content.operand, task, additional);
			debug_task ("regexp %s found", cur ? "is" : "is not");
			if (try_optimize) {
				try_optimize = optimize_regexp_expression (&it, stack, cur);
			}
			else {
				g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
			}
		}
		else if (it->type == EXPR_FUNCTION) {
			cur = (gsize) call_expression_function ((struct expression_function *)it->content.operand, task);
			debug_task ("function %s returned %s", ((struct expression_function *)it->content.operand)->name, cur ? "true" : "false");
			if (try_optimize) {
				try_optimize = optimize_regexp_expression (&it, stack, cur);
			}
			else {
				g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
			}
		}
		else if (it->type == EXPR_REGEXP) {
			/* Compile regexp if it is not parsed */
			if (it->content.operand == NULL) {
				it = it->next;
				continue;
			}
			re = parse_regexp (task->cfg->cfg_pool, it->content.operand, task->cfg->raw_mode);
			if (re == NULL) {
				msg_warn ("cannot parse regexp, skip expression");
				g_queue_free (stack);
				return FALSE;
			}
			it->content.operand = re;
			it->type = EXPR_REGEXP_PARSED;
			/* Continue with this regexp once again */
			continue;
		}
		else if (it->type == EXPR_OPERATION) {
			if (g_queue_is_empty (stack)) {
				/* Queue has no operands for operation, exiting */
				msg_warn ("regexp expression seems to be invalid: empty stack while reading operation");
				g_queue_free (stack);
				return FALSE;
			}
			debug_task ("got operation %c", it->content.operation);
			switch (it->content.operation) {
			case '!':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op1 = !op1;
				try_optimize = optimize_regexp_expression (&it, stack, op1);
				break;
			case '&':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				try_optimize = optimize_regexp_expression (&it, stack, op1 && op2);
				break;
			case '|':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				try_optimize = optimize_regexp_expression (&it, stack, op1 || op2);
				break;
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
			g_queue_free (stack);
			return TRUE;
		}
	}
	else {
		msg_warn ("regexp expression seems to be invalid: empty stack at the end of expression, symbol %s", symbol);
	}

	g_queue_free (stack);

	return FALSE;
}

static void
process_regexp_item (struct worker_task *task, void *user_data)
{
	struct regexp_module_item      *item = user_data;

	if (process_regexp_expression (item->expr, item->symbol, task, NULL)) {
		insert_result (task, regexp_module_ctx->metric, item->symbol, 1, NULL);
	}
}

static int
regexp_common_filter (struct worker_task *task)
{
	/* XXX: remove this shit too */
	return 0;
}

static                          gboolean
rspamd_regexp_match_number (struct worker_task *task, GList * args, void *unused)
{
	int                             param_count, res = 0;
	struct expression_argument     *arg;
	GList                          *cur;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	param_count = strtoul (arg->data, NULL, 10);

	cur = args->next;
	while (cur) {
		arg = get_function_arg (cur->data, task, FALSE);
		if (arg && arg->type == EXPRESSION_ARGUMENT_BOOL) {
			if ((gboolean) GPOINTER_TO_SIZE (arg->data)) {
				res++;
			}
		}
		else {
			if (process_regexp_expression (cur->data, "regexp_match_number", task, NULL)) {
				res++;
			}
			if (res >= param_count) {
				return TRUE;
			}
		}
		cur = g_list_next (cur);
	}

	return res >= param_count;
}

static                          gboolean
rspamd_raw_header_exists (struct worker_task *task, GList * args, void *unused)
{
	struct expression_argument     *arg;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	if (!arg || arg->type == EXPRESSION_ARGUMENT_BOOL) {
		msg_warn ("invalid argument to function is passed");
		return FALSE;
	}
	if (find_raw_header_pos (task->raw_headers, (char *)arg->data) == NULL) {
		return FALSE;
	}

	return TRUE;
}

static                          gboolean
rspamd_check_smtp_data (struct worker_task *task, GList * args, void *unused)
{
	struct expression_argument     *arg;
	GList                          *cur, *rcpt_list = NULL;
	char                           *type, *what = NULL;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);

	if (!arg || !arg->data) {
		msg_warn ("no parameters to function");
		return FALSE;
	}
	else {
		type = arg->data;
		switch (*type) {
			case 'f':
			case 'F':
				if (g_ascii_strcasecmp (type, "from") == 0) {
					what = task->from;
				}
				else {
					msg_warn ("bad argument to function: %s", type);
					return FALSE;
				}
				break;
			case 'h':
			case 'H':
				if (g_ascii_strcasecmp (type, "helo") == 0) {
					what = task->helo;
				}
				else {
					msg_warn ("bad argument to function: %s", type);
					return FALSE;
				}
				break;
			case 'u':
			case 'U':
				if (g_ascii_strcasecmp (type, "user") == 0) {
					what = task->user;
				}
				else {
					msg_warn ("bad argument to function: %s", type);
					return FALSE;
				}
				break;
			case 's':
			case 'S':
				if (g_ascii_strcasecmp (type, "subject") == 0) {
					what = task->subject;
				}
				else {
					msg_warn ("bad argument to function: %s", type);
					return FALSE;
				}
				break;
			case 'r':
			case 'R':
				if (g_ascii_strcasecmp (type, "rcpt") == 0) {
					rcpt_list = task->rcpt;
				}
				else {
					msg_warn ("bad argument to function: %s", type);
					return FALSE;
				}
				break;
			default:
				msg_warn ("bad argument to function: %s", type);
				return FALSE;
		}
	}

	if (what == NULL && rcpt_list == NULL) {
		/* Not enough data so regexp would NOT be found anyway */
		return FALSE;
	}
	
	/* We would process only one more argument, others are ignored */
	cur = args->next;
	if (cur) {
		arg = get_function_arg (cur->data, task, FALSE);
		if (arg && arg->type == EXPRESSION_ARGUMENT_NORMAL) {
			if (what != NULL) {
				if (g_ascii_strcasecmp (cur->data, what) == 0) {
					return TRUE;
				}
			}
			else {
				while (rcpt_list) {
					if (g_ascii_strcasecmp (cur->data, rcpt_list->data) == 0) {
						return TRUE;
					}
					rcpt_list = g_list_next (rcpt_list);
				}
			}
		}
		else {
			if (what != NULL) {
				if (process_regexp_expression (cur->data, "regexp_check_smtp_data", task, what)) {
					return TRUE;
				}
			}
			else {
				while (rcpt_list) {
					if (process_regexp_expression (cur->data, "regexp_check_smtp_data", task, rcpt_list->data)) {
						return TRUE;
					}
					rcpt_list = g_list_next (rcpt_list);
				}
			}
		}
	}

	return FALSE;
}
