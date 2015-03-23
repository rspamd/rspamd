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
	rspamd_mempool_t *regexp_pool;
	gsize max_size;
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

/* Process regexp expression */
static gboolean
read_regexp_expression (rspamd_mempool_t * pool,
	struct regexp_module_item *chain,
	const gchar *symbol,
	const gchar *line,
	gboolean raw_mode)
{
	struct rspamd_expression *e = NULL;
	GError *err = NULL;

	if (!rspamd_parse_expression (line, 0, &mime_expr_subr, NULL, pool, &err,
			&e)) {
		msg_warn ("%s = \"%s\" is invalid regexp expression: %e", symbol, line,
				err);
		g_error_free (err);

		return FALSE;
	}

	g_assert (e != NULL);
	chain->expr = e;

	return TRUE;
}


/* Init function */
gint
regexp_module_init (struct rspamd_config *cfg, struct module_ctx **ctx)
{
	regexp_module_ctx = g_malloc (sizeof (struct regexp_ctx));

	regexp_module_ctx->regexp_pool = rspamd_mempool_new (
		rspamd_mempool_suggest_size ());

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

	while ((value = ucl_iterate_object (sec, &it, true)) != NULL) {
		if (g_ascii_strncasecmp (ucl_object_key (value), "max_size",
			sizeof ("max_size") - 1) == 0) {
			regexp_module_ctx->max_size = ucl_obj_toint (value);
		}
		else if (g_ascii_strncasecmp (ucl_object_key (value), "max_threads",
			sizeof ("max_threads") - 1) == 0) {
			msg_warn ("regexp module is now single threaded, max_threads is ignored");
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
			else {
				register_symbol (&cfg->cache,
						cur_item->symbol,
						1,
						process_regexp_item,
						cur_item);
			}
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

static gboolean rspamd_lua_call_expression_func(
		struct ucl_lua_funcdata *lua_data, struct rspamd_task *task,
		GArray *args, gint *res)
{
	lua_State *L = lua_data->L;
	struct rspamd_task **ptask;
	struct expression_argument *arg;
	gint pop = 0, i;

	lua_rawgeti (L, LUA_REGISTRYINDEX, lua_data->idx);
	/* Now we got function in top of stack */
	ptask = lua_newuserdata (L, sizeof(struct rspamd_task *));
	rspamd_lua_setclass (L, "rspamd{task}", -1);
	*ptask = task;

	/* Now push all arguments */
	for (i = 0; i < (gint)args->len; i ++) {
		arg = &g_array_index (args, struct expression_argument, i);
		if (arg) {
			switch (arg->type) {
			case EXPRESSION_ARGUMENT_NORMAL:
				lua_pushstring (L, (const gchar *) arg->data);
				break;
			case EXPRESSION_ARGUMENT_BOOL:
				lua_pushboolean (L, (gboolean) GPOINTER_TO_SIZE(arg->data));
				break;
			default:
				msg_err("cannot pass custom params to lua function");
				return FALSE;
			}
		}
	}

	if (lua_pcall (L, args->len, 1, 0) != 0) {
		msg_info("call to lua function failed: %s", lua_tostring (L, -1));
		return FALSE;
	}
	pop++;

	if (lua_type (L, -1) == LUA_TNUMBER) {
		*res = lua_tonumber (L, -1);
	}
	else if (lua_type (L, -1) == LUA_TBOOLEAN) {
		*res = lua_toboolean (L, -1);
	}
	else {
		msg_info("lua function must return a boolean");
	}

	lua_pop (L, pop);

	return TRUE;
}


static void
process_regexp_item (struct rspamd_task *task, void *user_data)
{
	struct regexp_module_item *item = user_data;
	gint res = FALSE;

	/* Non-threaded version */
	if (item->lua_function) {
		/* Just call function */
		res = FALSE;
		if (!rspamd_lua_call_expression_func (item->lua_function, task, NULL,
				&res)) {
			msg_err ("error occurred when checking symbol %s", item->symbol);
		}
	}
	else {
		/* Process expression */
		if (item->expr) {
			res = rspamd_process_expression (item->expr, task);
		}
		else {
			msg_warn ("FIXME: %s symbol is broken with new expressions",
					item->symbol);
		}
	}

	if (res) {
		rspamd_task_insert_result (task, item->symbol, res, NULL);
	}
}
