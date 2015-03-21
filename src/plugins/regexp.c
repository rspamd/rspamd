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
#include "expression.h"
#include "mime_expressions.h"
#include "libutil/map.h"
#include "lua/lua_common.h"
#include "main.h"

struct regexp_module_item {
	struct rspamd_expression *expr;
	const gchar *symbol;
	struct ucl_lua_funcdata *lua_function;
};

struct regexp_ctx {
	gchar *statfile_prefix;

	rspamd_mempool_t *regexp_pool;
	gsize max_size;
	gsize max_threads;
	GThreadPool *workers;
};

static struct regexp_ctx *regexp_module_ctx = NULL;

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
