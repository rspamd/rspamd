/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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

/***MODULE:regexp
 * rspamd module that implements different regexp rules
 */


#include "config.h"
#include "libmime/message.h"
#include "libmime/expressions.h"
#include "libutil/map.h"
#include "lua/lua_common.h"
#include "main.h"

#define DEFAULT_STATFILE_PREFIX "./"

struct regexp_module_item {
	struct expression *expr;
	const gchar *symbol;
	guint32 avg_time;
	struct ucl_lua_funcdata *lua_function;
};

struct regexp_ctx {
	gchar *statfile_prefix;

	rspamd_mempool_t *regexp_pool;
	gsize max_size;
	gsize max_threads;
	GThreadPool *workers;
};

/* Lua regexp module for checking rspamd regexps */
LUA_FUNCTION_DEF (regexp, match);

static const struct luaL_reg regexplib_m[] = {
	LUA_INTERFACE_DEF (regexp, match),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static struct regexp_ctx *regexp_module_ctx = NULL;
static GMutex *workers_mtx = NULL;

static void process_regexp_item_threaded (gpointer data, gpointer user_data);
static gboolean rspamd_regexp_match_number (struct rspamd_task *task,
	GList * args,
	void *unused);
static gboolean rspamd_raw_header_exists (struct rspamd_task *task,
	GList * args,
	void *unused);
static gboolean rspamd_check_smtp_data (struct rspamd_task *task,
	GList * args,
	void *unused);
static gboolean rspamd_regexp_occurs_number (struct rspamd_task *task,
	GList * args,
	void *unused);
static gboolean rspamd_content_type_is_type (struct rspamd_task * task,
	GList * args,
	void *unused);
static gboolean rspamd_content_type_is_subtype (struct rspamd_task *task,
	GList * args,
	void *unused);
static gboolean rspamd_content_type_has_param (struct rspamd_task * task,
	GList * args,
	void *unused);
static gboolean rspamd_content_type_compare_param (struct rspamd_task * task,
	GList * args,
	void *unused);
static gboolean rspamd_has_content_part (struct rspamd_task *task,
	GList * args,
	void *unused);
static gboolean rspamd_has_content_part_len (struct rspamd_task *task,
	GList * args,
	void *unused);
static void process_regexp_item (struct rspamd_task *task, void *user_data);


/* Initialization */
gint regexp_module_init (struct rspamd_config *cfg, struct module_ctx **ctx);
gint regexp_module_config (struct rspamd_config *cfg);
gint regexp_module_reconfig (struct rspamd_config *cfg);

module_t regexp_module = {
	"regexp",
	regexp_module_init,
	regexp_module_config,
	regexp_module_reconfig,
	NULL
};

/* Task cache functions */
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
static GStaticMutex task_cache_mtx = G_STATIC_MUTEX_INIT;
#else
G_LOCK_DEFINE (task_cache_mtx);
#endif

/*
 * Utility functions for matching exact number of regexps
 */
typedef gboolean (*int_compare_func) (gint a, gint b);
static gboolean
op_equal (gint a, gint b)
{
	return a == b;
}
static gboolean
op_more (gint a, gint b)
{
	return a > b;
}
static gboolean
op_less (gint a, gint b)
{
	return a < b;
}
static gboolean
op_more_equal (gint a, gint b)
{
	return a >= b;
}
static gboolean
op_less_equal (gint a, gint b)
{
	return a <= b;
}

/* Process regexp expression */
static gboolean
read_regexp_expression (rspamd_mempool_t * pool,
	struct regexp_module_item *chain,
	const gchar *symbol,
	const gchar *line,
	gboolean raw_mode)
{
	struct expression *e, *cur;

	e = parse_expression (pool, (gchar *)line);
	if (e == NULL) {
		msg_warn ("%s = \"%s\" is invalid regexp expression", symbol, line);
		return FALSE;
	}
	chain->expr = e;
	cur = e;
	while (cur) {
		if (cur->type == EXPR_REGEXP) {
			cur->content.operand = parse_regexp (pool,
					cur->content.operand,
					raw_mode);
			if (cur->content.operand == NULL) {
				msg_warn ("cannot parse regexp, skip expression %s = \"%s\"",
					symbol,
					line);
				return FALSE;
			}
			cur->type = EXPR_REGEXP_PARSED;
		}
		cur = cur->next;
	}

	return TRUE;
}


/* Init function */
gint
regexp_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	regexp_module_ctx = g_malloc (sizeof (struct regexp_ctx));

	regexp_module_ctx->regexp_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());
	regexp_module_ctx->workers = NULL;

	*ctx = (struct module_ctx *)regexp_module_ctx;
	register_expression_function ("regexp_match_number",
		rspamd_regexp_match_number,
		NULL);
	register_expression_function ("regexp_occurs_number",
		rspamd_regexp_occurs_number,
		NULL);
	register_expression_function ("raw_header_exists",
		rspamd_raw_header_exists,
		NULL);
	register_expression_function ("check_smtp_data",
		rspamd_check_smtp_data,
		NULL);
	register_expression_function ("content_type_is_type",
		rspamd_content_type_is_type,
		NULL);
	register_expression_function ("content_type_is_subtype",
		rspamd_content_type_is_subtype,
		NULL);
	register_expression_function ("content_type_has_param",
		rspamd_content_type_has_param,
		NULL);
	register_expression_function ("content_type_compare_param",
		rspamd_content_type_compare_param,
		NULL);
	register_expression_function ("has_content_part",
		rspamd_has_content_part,
		NULL);
	register_expression_function ("has_content_part_len",
		rspamd_has_content_part_len,
		NULL);

	(void)luaopen_regexp (cfg->lua_state);

	return 0;
}

gint
regexp_module_config (struct rspamd_config *cfg)
{
	struct regexp_module_item *cur_item;
	const ucl_object_t *sec, *value;
	ucl_object_iter_t it = NULL;
	gint res = TRUE;

	sec = ucl_object_find_key (cfg->rcl_obj, "regexp");
	if (sec == NULL) {
		msg_err ("regexp module enabled, but no rules are defined");
		return TRUE;
	}

	regexp_module_ctx->max_size = 0;
	regexp_module_ctx->max_threads = 0;
	regexp_module_ctx->workers = NULL;

	while ((value = ucl_iterate_object (sec, &it, true)) != NULL) {
		if (g_ascii_strncasecmp (ucl_object_key (value), "max_size",
			sizeof ("max_size") - 1) == 0) {
			regexp_module_ctx->max_size = ucl_obj_toint (value);
		}
		else if (g_ascii_strncasecmp (ucl_object_key (value), "max_threads",
			sizeof ("max_threads") - 1) == 0) {
			regexp_module_ctx->max_threads = ucl_obj_toint (value);
		}
		else if (value->type == UCL_STRING) {
			cur_item = rspamd_mempool_alloc0 (regexp_module_ctx->regexp_pool,
					sizeof (struct regexp_module_item));
			cur_item->symbol = ucl_object_key (value);
			if (!read_regexp_expression (regexp_module_ctx->regexp_pool,
				cur_item, ucl_object_key (value),
				ucl_obj_tostring (value), cfg->raw_mode)) {
				res = FALSE;
			}
			register_symbol (&cfg->cache,
				cur_item->symbol,
				1,
				process_regexp_item,
				cur_item);
		}
		else if (value->type == UCL_USERDATA) {
			cur_item = rspamd_mempool_alloc0 (regexp_module_ctx->regexp_pool,
					sizeof (struct regexp_module_item));
			cur_item->symbol = ucl_object_key (value);
			cur_item->lua_function = ucl_object_toclosure (value);
			register_symbol (&cfg->cache,
				cur_item->symbol,
				1,
				process_regexp_item,
				cur_item);
		}
		else {
			msg_warn ("unknown type of attribute %s for regexp module",
				ucl_object_key (value));
		}
	}

	return res;
}

gint
regexp_module_reconfig (struct rspamd_config *cfg)
{
	rspamd_mempool_delete (regexp_module_ctx->regexp_pool);
	regexp_module_ctx->regexp_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());

	return regexp_module_config (cfg);
}


static gboolean
maybe_call_lua_function (const gchar *name,
	struct rspamd_task *task,
	lua_State *L)
{
	struct rspamd_task **ptask;
	gboolean res;

	lua_getglobal (L, name);
	if (lua_isfunction (L, -1)) {
		ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
		rspamd_lua_setclass (L, "rspamd{task}", -1);
		*ptask = task;
		/* Call function */
		if (lua_pcall (L, 1, 1, 0) != 0) {
			msg_info ("call to %s failed: %s", (gchar *)name,
				lua_tostring (L, -1));
			return FALSE;
		}
		res = lua_toboolean (L, -1);
		lua_pop (L, 1);
		return res;
	}
	else {
		lua_pop (L, 1);
	}
	return FALSE;
}

static gboolean
optimize_regexp_expression (struct expression **e, GQueue * stack, gboolean res)
{
	struct expression *it = (*e)->next;
	gboolean ret = FALSE, is_nearest = TRUE;
	gint skip_level = 0;

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

static gboolean
process_regexp_expression (struct expression *expr,
	const gchar *symbol,
	struct rspamd_task *task,
	const gchar *additional,
	struct lua_locked_state *nL)
{
	GQueue *stack;
	gsize cur, op1, op2;
	struct expression *it = expr;
	struct rspamd_regexp_element *re;
	gboolean try_optimize = TRUE;

	stack = g_queue_new ();

	while (it) {
		if (it->type == EXPR_REGEXP_PARSED) {
			/* Find corresponding symbol */
			cur = process_regexp ((struct rspamd_regexp_element *)it->content.operand,
					task,
					additional,
					0,
					NULL);
			debug_task ("regexp %s found", cur ? "is" : "is not");
			if (try_optimize) {
				try_optimize = optimize_regexp_expression (&it, stack, cur);
			}
			else {
				g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
			}
		}
		else if (it->type == EXPR_FUNCTION) {
			if (nL) {
				rspamd_mutex_lock (nL->m);
				cur =
					(gsize) call_expression_function ((struct
						expression_function
						*)it->content.operand, task, nL->L);
				rspamd_mutex_unlock (nL->m);
			}
			else {
				cur =
					(gsize) call_expression_function ((struct
						expression_function
						*)it->content.operand, task, task->cfg->lua_state);
			}
			debug_task ("function %s returned %s",
				((struct expression_function *)it->content.operand)->name,
				cur ? "true" : "false");
			if (try_optimize) {
				try_optimize = optimize_regexp_expression (&it, stack, cur);
			}
			else {
				g_queue_push_head (stack, GSIZE_TO_POINTER (cur));
			}
		}
		else if (it->type == EXPR_STR) {
			/* This may be lua function, try to call it */
			if (nL) {
				rspamd_mutex_lock (nL->m);
				cur = maybe_call_lua_function (
					(const gchar *)it->content.operand,
					task,
					nL->L);
				rspamd_mutex_unlock (nL->m);
			}
			else {
				cur = maybe_call_lua_function (
					(const gchar *)it->content.operand,
					task,
					task->cfg->lua_state);
			}
			debug_task ("function %s returned %s",
				(const gchar *)it->content.operand,
				cur ? "true" : "false");
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
			re = parse_regexp (task->cfg->cfg_pool,
					it->content.operand,
					task->cfg->raw_mode);
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
				msg_warn (
					"regexp expression seems to be invalid: empty stack while reading operation");
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
				try_optimize = optimize_regexp_expression (&it,
						stack,
						op1 && op2);
				break;
			case '|':
				op1 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				op2 = GPOINTER_TO_SIZE (g_queue_pop_head (stack));
				try_optimize = optimize_regexp_expression (&it,
						stack,
						op1 || op2);
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
		msg_warn (
			"regexp expression seems to be invalid: empty stack at the end of expression, symbol %s",
			symbol);
	}

	g_queue_free (stack);

	return FALSE;
}

/* Call custom lua function in rspamd expression */
static gboolean
rspamd_lua_call_expression_func (struct ucl_lua_funcdata *lua_data,
	struct rspamd_task *task, GList *args, gboolean *res)
{
	lua_State *L = lua_data->L;
	struct rspamd_task **ptask;
	GList *cur;
	struct expression_argument *arg;
	int nargs = 1, pop = 0;

	lua_rawgeti (L, LUA_REGISTRYINDEX, lua_data->idx);
	/* Now we got function in top of stack */
	ptask = lua_newuserdata (L, sizeof (struct rspamd_task *));
	rspamd_lua_setclass (L, "rspamd{task}", -1);
	*ptask = task;

	/* Now push all arguments */
	cur = args;
	while (cur) {
		arg = get_function_arg (cur->data, task, FALSE);
		if (arg) {
			switch (arg->type) {
			case EXPRESSION_ARGUMENT_NORMAL:
				lua_pushstring (L, (const gchar *)arg->data);
				break;
			case EXPRESSION_ARGUMENT_BOOL:
				lua_pushboolean (L, (gboolean) GPOINTER_TO_SIZE (arg->data));
				break;
			default:
				msg_err ("cannot pass custom params to lua function");
				return FALSE;
			}
		}
		nargs++;
		cur = g_list_next (cur);
	}

	if (lua_pcall (L, nargs, 1, 0) != 0) {
		msg_info ("call to lua function failed: %s", lua_tostring (L, -1));
		return FALSE;
	}
	pop++;

	if (!lua_isboolean (L, -1)) {
		lua_pop (L, pop);
		msg_info ("lua function must return a boolean");
		return FALSE;
	}
	*res = lua_toboolean (L, -1);
	lua_pop (L, pop);

	return TRUE;
}

struct regexp_threaded_ud {
	struct regexp_module_item *item;
	struct rspamd_task *task;
};

static void
process_regexp_item_threaded (gpointer data, gpointer user_data)
{
	struct regexp_threaded_ud *ud = data;
	struct lua_locked_state *nL = user_data;

	/* Process expression */
	if (process_regexp_expression (ud->item->expr, ud->item->symbol, ud->task,
		NULL, nL)) {
		g_mutex_lock (workers_mtx);
		rspamd_task_insert_result (ud->task, ud->item->symbol, 1, NULL);
		g_mutex_unlock (workers_mtx);
	}
	remove_async_thread (ud->task->s);
}

static void
process_regexp_item (struct rspamd_task *task, void *user_data)
{
	struct regexp_module_item *item = user_data;
	gboolean res = FALSE;
	struct regexp_threaded_ud *thr_ud;
	GError *err = NULL;
	struct lua_locked_state *nL;


	if (!item->lua_function && regexp_module_ctx->max_threads > 1) {
		if (regexp_module_ctx->workers == NULL) {
#if ((GLIB_MAJOR_VERSION == 2) && (GLIB_MINOR_VERSION <= 30))
# if GLIB_MINOR_VERSION > 20
			if (!g_thread_get_initialized ()) {
				g_thread_init (NULL);
			}
# else
			g_thread_init (NULL);
# endif
			workers_mtx = g_mutex_new ();
#else
			workers_mtx = rspamd_mempool_alloc (regexp_module_ctx->regexp_pool,
					sizeof (GMutex));
			g_mutex_init (workers_mtx);
#endif
			nL = rspamd_init_lua_locked (task->cfg);
			luaopen_regexp (nL->L);
			regexp_module_ctx->workers = g_thread_pool_new (
				process_regexp_item_threaded,
				nL,
				regexp_module_ctx->max_threads,
				TRUE,
				&err);
			if (err != NULL) {
				msg_err ("thread pool creation failed: %s", err->message);
				regexp_module_ctx->max_threads = 0;
				return;
			}
		}
		thr_ud =
			rspamd_mempool_alloc (task->task_pool,
				sizeof (struct regexp_threaded_ud));
		thr_ud->item = item;
		thr_ud->task = task;


		register_async_thread (task->s);
		g_thread_pool_push (regexp_module_ctx->workers, thr_ud, &err);
		if (err != NULL) {
			msg_err ("error pushing task to the regexp thread pool: %s",
				err->message);
			remove_async_thread (task->s);
		}
	}
	else {
		/* Non-threaded version */
		if (item->lua_function) {
			/* Just call function */
			res = FALSE;
			if (!rspamd_lua_call_expression_func (item->lua_function, task, NULL,
				&res)) {
				msg_err ("error occurred when checking symbol %s", item->symbol);
			}
			if (res) {
				rspamd_task_insert_result (task, item->symbol, 1, NULL);
			}
		}
		else {
			/* Process expression */
			if (process_regexp_expression (item->expr, item->symbol, task, NULL,
				NULL)) {
				rspamd_task_insert_result (task, item->symbol, 1, NULL);
			}
		}
	}
}

static gboolean
rspamd_regexp_match_number (struct rspamd_task *task, GList * args,
	void *unused)
{
	gint param_count, res = 0;
	struct expression_argument *arg;
	GList *cur;

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
			if (process_regexp_expression (cur->data, "regexp_match_number",
				task, NULL, NULL)) {
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

static gboolean
rspamd_regexp_occurs_number (struct rspamd_task *task,
	GList * args,
	void *unused)
{
	gint limit;
	struct expression_argument *arg;
	struct rspamd_regexp_element *re;
	gchar *param, *err_str, op;
	int_compare_func f = NULL;

	if (args == NULL || args->next == NULL) {
		msg_warn ("wrong number of parameters to function, must be 2");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	if ((re = re_cache_check (arg->data, task->cfg->cfg_pool)) == NULL) {
		re = parse_regexp (task->cfg->cfg_pool, arg->data, task->cfg->raw_mode);
		if (!re) {
			msg_err ("cannot parse given regexp: %s", (gchar *)arg->data);
			return FALSE;
		}
	}

	arg = get_function_arg (args->next->data, task, TRUE);
	param = arg->data;
	op = *param;
	if (g_ascii_isdigit (op)) {
		op = '=';
	}
	else {
		param++;
	}
	switch (op) {
	case '>':
		if (*param == '=') {
			f = op_more_equal;
			param++;
		}
		else {
			f = op_more;
		}
		break;
	case '<':
		if (*param == '=') {
			f = op_less_equal;
			param++;
		}
		else {
			f = op_less;
		}
		break;
	case '=':
		f = op_equal;
		break;
	default:
		msg_err (
			"wrong operation character: %c, assumed '=', '>', '<', '>=', '<=' or empty op",
			op);
		return FALSE;
	}

	limit = strtoul (param, &err_str, 10);
	if (*err_str != 0) {
		msg_err ("wrong numeric: %s at position: %s", param, err_str);
		return FALSE;
	}

	return process_regexp (re, task, NULL, limit, f);
}
static gboolean
rspamd_raw_header_exists (struct rspamd_task *task, GList * args, void *unused)
{
	struct expression_argument *arg;

	if (args == NULL || task == NULL) {
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	if (!arg || arg->type == EXPRESSION_ARGUMENT_BOOL) {
		msg_warn ("invalid argument to function is passed");
		return FALSE;
	}

	return g_hash_table_lookup (task->raw_headers, arg->data) != NULL;
}

static gboolean
match_smtp_data (struct rspamd_task *task,
	const gchar *re_text,
	const gchar *what)
{
	struct rspamd_regexp_element *re;
	gint r;

	if (*re_text == '/') {
		/* This is a regexp */
		re = parse_regexp (task->cfg->cfg_pool,
				(gchar *)re_text,
				task->cfg->raw_mode);
		if (re == NULL) {
			msg_warn ("cannot compile regexp for function");
			return FALSE;
		}

		if ((r = task_cache_check (task, re)) == -1) {
			if (rspamd_regexp_search (re->regexp, what, 0, NULL, NULL, FALSE)) {
				task_cache_add (task, re, 1);
				return TRUE;
			}
			task_cache_add (task, re, 0);
		}
		else {
			return r == 1;
		}
	}
	else if (g_ascii_strcasecmp (re_text, what) == 0) {
		return TRUE;
	}

	return FALSE;
}

static gboolean
rspamd_check_smtp_data (struct rspamd_task *task, GList * args, void *unused)
{
	struct expression_argument *arg;
	InternetAddressList *ia = NULL;
	const gchar *type, *what = NULL;
	GList *cur;
	gint i, ialen;

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
				what = rspamd_task_get_sender (task);
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
				ia = task->rcpt_mime;
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

	if (what == NULL && ia == NULL) {
		/* Not enough data so regexp would NOT be found anyway */
		return FALSE;
	}

	/* We would process only one more argument, others are ignored */
	cur = args->next;
	if (cur) {
		arg = get_function_arg (cur->data, task, FALSE);
		if (arg && arg->type == EXPRESSION_ARGUMENT_NORMAL) {
			if (what != NULL) {
				return match_smtp_data (task, arg->data, what);
			}
			else {
				if (ia != NULL) {
					ialen = internet_address_list_length(ia);
					for (i = 0; i < ialen; i ++) {
						InternetAddress *iaelt =
								internet_address_list_get_address(ia, i);
						InternetAddressMailbox *iamb =
							INTERNET_ADDRESS_IS_MAILBOX(iaelt) ?
							INTERNET_ADDRESS_MAILBOX (iaelt) : NULL;
						if (iamb &&
							match_smtp_data (task, arg->data,
								internet_address_mailbox_get_addr(iamb))) {
							return TRUE;
						}
					}
				}
			}
		}
		else if (arg != NULL) {
			if (what != NULL) {
				if (process_regexp_expression (arg->data,
					"regexp_check_smtp_data", task, what, NULL)) {
					return TRUE;
				}
			}
			else {
				if (ia != NULL) {
					ialen = internet_address_list_length(ia);
					for (i = 0; i < ialen; i ++) {
						InternetAddress *iaelt =
								internet_address_list_get_address(ia, i);
						InternetAddressMailbox *iamb =
								INTERNET_ADDRESS_IS_MAILBOX(iaelt) ?
								INTERNET_ADDRESS_MAILBOX (iaelt) : NULL;
						if (iamb &&
								process_regexp_expression (arg->data,
									"regexp_check_smtp_data", task,
									internet_address_mailbox_get_addr(iamb),
									NULL)) {
							return TRUE;
						}
					}
				}
			}
		}
	}

	return FALSE;
}

/* Lua part */
static gint
lua_regexp_match (lua_State *L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{task}");
	struct rspamd_task *task;
	const gchar *re_text;
	struct rspamd_regexp_element *re;
	gint r = 0;

	luaL_argcheck (L, ud != NULL, 1, "'task' expected");
	task = ud ? *((struct rspamd_task **)ud) : NULL;
	re_text = luaL_checkstring (L, 2);

	/* This is a regexp */
	if (task != NULL) {
		re = parse_regexp (task->cfg->cfg_pool,
				(gchar *)re_text,
				task->cfg->raw_mode);
		if (re == NULL) {
			msg_warn ("cannot compile regexp for function");
			return FALSE;
		}
		r = process_regexp (re, task, NULL, 0, NULL);
	}
	lua_pushboolean (L, r == 1);

	return 1;
}

static gboolean
rspamd_content_type_compare_param (struct rspamd_task * task,
	GList * args,
	void *unused)
{
	gchar *param_name, *param_pattern;
	const gchar *param_data;
	struct rspamd_regexp_element *re;
	struct expression_argument *arg, *arg1;
	GMimeObject *part;
	GMimeContentType *ct;
	gint r;
	gboolean recursive = FALSE, result = FALSE;
	GList *cur = NULL;
	struct mime_part *cur_part;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}
	arg = get_function_arg (args->data, task, TRUE);
	param_name = arg->data;
	args = g_list_next (args);
	if (args == NULL) {
		msg_warn ("too few params to function");
		return FALSE;
	}
	arg = get_function_arg (args->data, task, TRUE);
	param_pattern = arg->data;


	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);
		if (args->next) {
			args = g_list_next (args);
			arg1 = get_function_arg (args->data, task, TRUE);
			if (g_ascii_strncasecmp (arg1->data, "true",
				sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}

		if (recursive) {
			cur = task->parts;
		}

#ifndef GMIME24
		g_object_unref (part);
#endif
		for (;; ) {
			if ((param_data =
				g_mime_content_type_get_parameter ((GMimeContentType *)ct,
				param_name)) == NULL) {
				result = FALSE;
			}
			else {
				if (*param_pattern == '/') {
					re = parse_regexp (task->cfg->cfg_pool,
							param_pattern,
							task->cfg->raw_mode);
					if (re == NULL) {
						msg_warn ("cannot compile regexp for function");
						return FALSE;
					}
					if ((r = task_cache_check (task, re)) == -1) {
						if (rspamd_regexp_search (re->regexp, param_data, 0,
							NULL, NULL, FALSE) == TRUE) {
							task_cache_add (task, re, 1);
							return TRUE;
						}
						task_cache_add (task, re, 0);
					}
					else {

					}
				}
				else {
					/* Just do strcasecmp */
					if (g_ascii_strcasecmp (param_data, param_pattern) == 0) {
						return TRUE;
					}
				}
			}
			/* Get next part */
			if (!recursive) {
				return result;
			}
			else if (cur != NULL) {
				cur_part = cur->data;
				if (cur_part->type != NULL) {
					ct = cur_part->type;
				}
				cur = g_list_next (cur);
			}
			else {
				/* All is done */
				return result;
			}
		}

	}

	return FALSE;
}

static gboolean
rspamd_content_type_has_param (struct rspamd_task * task,
	GList * args,
	void *unused)
{
	gchar *param_name;
	const gchar *param_data;
	struct expression_argument *arg, *arg1;
	GMimeObject *part;
	GMimeContentType *ct;
	gboolean recursive = FALSE, result = FALSE;
	GList *cur = NULL;
	struct mime_part *cur_part;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}
	arg = get_function_arg (args->data, task, TRUE);
	param_name = arg->data;

	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);
		if (args->next) {
			args = g_list_next (args);
			arg1 = get_function_arg (args->data, task, TRUE);
			if (g_ascii_strncasecmp (arg1->data, "true",
				sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}

		if (recursive) {
			cur = task->parts;
		}

#ifndef GMIME24
		g_object_unref (part);
#endif
		for (;; ) {
			if ((param_data =
				g_mime_content_type_get_parameter ((GMimeContentType *)ct,
				param_name)) != NULL) {
				return TRUE;
			}
			/* Get next part */
			if (!recursive) {
				return result;
			}
			else if (cur != NULL) {
				cur_part = cur->data;
				if (cur_part->type != NULL) {
					ct = cur_part->type;
				}
				cur = g_list_next (cur);
			}
			else {
				/* All is done */
				return result;
			}
		}

	}

	return TRUE;
}

static gboolean
rspamd_content_type_is_subtype (struct rspamd_task *task,
	GList * args,
	void *unused)
{
	gchar *param_pattern;
	struct rspamd_regexp_element *re;
	struct expression_argument *arg, *arg1;
	GMimeObject *part;
	GMimeContentType *ct;
	gint r;
	gboolean recursive = FALSE, result = FALSE;
	GList *cur = NULL;
	struct mime_part *cur_part;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}
	arg = get_function_arg (args->data, task, TRUE);
	param_pattern = arg->data;

	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);
		if (args->next) {
			args = g_list_next (args);
			arg1 = get_function_arg (args->data, task, TRUE);
			if (g_ascii_strncasecmp (arg1->data, "true",
				sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}

		if (recursive) {
			cur = task->parts;
		}

#ifndef GMIME24
		g_object_unref (part);
#endif
		for (;; ) {
			if (*param_pattern == '/') {
				re = parse_regexp (task->cfg->cfg_pool,
						param_pattern,
						task->cfg->raw_mode);
				if (re == NULL) {
					msg_warn ("cannot compile regexp for function");
					return FALSE;
				}
				if ((r = task_cache_check (task, re)) == -1) {
					if (rspamd_regexp_search (re->regexp, ct->subtype, 0,
						NULL, NULL, FALSE)) {
						task_cache_add (task, re, 1);
						return TRUE;
					}
					task_cache_add (task, re, 0);
				}
				else {

				}
			}
			else {
				/* Just do strcasecmp */
				if (g_ascii_strcasecmp (ct->subtype, param_pattern) == 0) {
					return TRUE;
				}
			}
			/* Get next part */
			if (!recursive) {
				return result;
			}
			else if (cur != NULL) {
				cur_part = cur->data;
				if (cur_part->type != NULL) {
					ct = cur_part->type;
				}
				cur = g_list_next (cur);
			}
			else {
				/* All is done */
				return result;
			}
		}

	}

	return FALSE;
}

static gboolean
rspamd_content_type_is_type (struct rspamd_task * task,
	GList * args,
	void *unused)
{
	gchar *param_pattern;
	struct rspamd_regexp_element *re;
	struct expression_argument *arg, *arg1;
	GMimeObject *part;
	GMimeContentType *ct;
	gint r;
	gboolean recursive = FALSE, result = FALSE;
	GList *cur = NULL;
	struct mime_part *cur_part;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}
	arg = get_function_arg (args->data, task, TRUE);
	param_pattern = arg->data;


	part = g_mime_message_get_mime_part (task->message);
	if (part) {
		ct = (GMimeContentType *)g_mime_object_get_content_type (part);
		if (args->next) {
			args = g_list_next (args);
			arg1 = get_function_arg (args->data, task, TRUE);
			if (g_ascii_strncasecmp (arg1->data, "true",
				sizeof ("true") - 1) == 0) {
				recursive = TRUE;
			}
		}
		else {
			/*
			 * If user did not specify argument, let's assume that he wants
			 * recursive search if mime part is multipart/mixed
			 */
			if (g_mime_content_type_is_type (ct, "multipart", "*")) {
				recursive = TRUE;
			}
		}

		if (recursive) {
			cur = task->parts;
		}

#ifndef GMIME24
		g_object_unref (part);
#endif
		for (;; ) {
			if (*param_pattern == '/') {
				re = parse_regexp (task->cfg->cfg_pool,
						param_pattern,
						task->cfg->raw_mode);
				if (re == NULL) {
					msg_warn ("cannot compile regexp for function");
					return FALSE;
				}
				if ((r = task_cache_check (task, re)) == -1) {
					if (rspamd_regexp_search (re->regexp, ct->type, 0,
							NULL, NULL, FALSE) == TRUE) {
						task_cache_add (task, re, 1);
						return TRUE;
					}
					task_cache_add (task, re, 0);
				}
				else {

				}
			}
			else {
				/* Just do strcasecmp */
				if (g_ascii_strcasecmp (ct->type, param_pattern) == 0) {
					return TRUE;
				}
			}
			/* Get next part */
			if (!recursive) {
				return result;
			}
			else if (cur != NULL) {
				cur_part = cur->data;
				if (cur_part->type != NULL) {
					ct = cur_part->type;
				}
				cur = g_list_next (cur);
			}
			else {
				/* All is done */
				return result;
			}
		}

	}

	return FALSE;
}

static gboolean
compare_subtype (struct rspamd_task *task, GMimeContentType * ct,
	gchar *subtype)
{
	struct rspamd_regexp_element *re;
	gint r;

	if (subtype == NULL || ct == NULL) {
		msg_warn ("invalid parameters passed");
		return FALSE;
	}
	if (*subtype == '/') {
		re = parse_regexp (task->cfg->cfg_pool, subtype,
				task->cfg->raw_mode);
		if (re == NULL) {
			msg_warn ("cannot compile regexp for function");
			return FALSE;
		}
		if ((r = task_cache_check (task, re)) == -1) {
			if (rspamd_regexp_search (re->regexp, subtype, 0,
					NULL, NULL, FALSE) == TRUE) {
				task_cache_add (task, re, 1);
				return TRUE;
			}
			task_cache_add (task, re, 0);
		}
		else {
			return r == 1;
		}
	}
	else {
		/* Just do strcasecmp */
		if (ct->subtype && g_ascii_strcasecmp (ct->subtype, subtype) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean
compare_len (struct mime_part *part, guint min, guint max)
{
	if (min == 0 && max == 0) {
		return TRUE;
	}

	if (min == 0) {
		return part->content->len <= max;
	}
	else if (max == 0) {
		return part->content->len >= min;
	}
	else {
		return part->content->len >= min && part->content->len <= max;
	}
}

static gboolean
common_has_content_part (struct rspamd_task * task,
	gchar *param_type,
	gchar *param_subtype,
	gint min_len,
	gint max_len)
{
	struct rspamd_regexp_element *re;
	struct mime_part *part;
	GList *cur;
	GMimeContentType *ct;
	gint r;

	cur = g_list_first (task->parts);
	while (cur) {
		part = cur->data;
		ct = part->type;
		if (ct == NULL) {
			cur = g_list_next (cur);
			continue;
		}

		if (*param_type == '/') {
			re = parse_regexp (task->cfg->cfg_pool,
					param_type,
					task->cfg->raw_mode);
			if (re == NULL) {
				msg_warn ("cannot compile regexp for function");
				cur = g_list_next (cur);
				continue;
			}
			if ((r = task_cache_check (task, re)) == -1) {
				if (ct->type &&
					rspamd_regexp_search (re->regexp, ct->type, 0,
							NULL, NULL, TRUE)) {
					if (param_subtype) {
						if (compare_subtype (task, ct, param_subtype)) {
							if (compare_len (part, min_len, max_len)) {
								return TRUE;
							}
						}
					}
					else {
						if (compare_len (part, min_len, max_len)) {
							return TRUE;
						}
					}
					task_cache_add (task, re, 1);
				}
				else {
					task_cache_add (task, re, 0);
				}
			}
			else {
				if (r == 1) {
					if (compare_subtype (task, ct, param_subtype)) {
						if (compare_len (part, min_len, max_len)) {
							return TRUE;
						}
					}
				}
			}
		}
		else {
			/* Just do strcasecmp */
			if (ct->type && g_ascii_strcasecmp (ct->type, param_type) == 0) {
				if (param_subtype) {
					if (compare_subtype (task, ct, param_subtype)) {
						if (compare_len (part, min_len, max_len)) {
							return TRUE;
						}
					}
				}
				else {
					if (compare_len (part, min_len, max_len)) {
						return TRUE;
					}
				}
			}
		}
		cur = g_list_next (cur);
	}

	return FALSE;
}

static gboolean
rspamd_has_content_part (struct rspamd_task * task, GList * args, void *unused)
{
	gchar *param_type = NULL, *param_subtype = NULL;
	struct expression_argument *arg;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	param_type = arg->data;
	args = args->next;
	if (args) {
		arg = args->data;
		param_subtype = arg->data;
	}

	return common_has_content_part (task, param_type, param_subtype, 0, 0);
}

static gboolean
rspamd_has_content_part_len (struct rspamd_task * task,
	GList * args,
	void *unused)
{
	gchar *param_type = NULL, *param_subtype = NULL;
	gint min = 0, max = 0;
	struct expression_argument *arg;

	if (args == NULL) {
		msg_warn ("no parameters to function");
		return FALSE;
	}

	arg = get_function_arg (args->data, task, TRUE);
	param_type = arg->data;
	args = args->next;
	if (args) {
		arg = get_function_arg (args->data, task, TRUE);
		param_subtype = arg->data;
		args = args->next;
		if (args) {
			arg = get_function_arg (args->data, task, TRUE);
			errno = 0;
			min = strtoul (arg->data, NULL, 10);
			if (errno != 0) {
				msg_warn ("invalid numeric value '%s': %s",
					(gchar *)arg->data,
					strerror (errno));
				return FALSE;
			}
			args = args->next;
			if (args) {
				arg = get_function_arg (args->data, task, TRUE);
				max = strtoul (arg->data, NULL, 10);
				if (errno != 0) {
					msg_warn ("invalid numeric value '%s': %s",
						(gchar *)arg->data,
						strerror (errno));
					return FALSE;
				}
			}
		}
	}

	return common_has_content_part (task, param_type, param_subtype, min, max);
}
