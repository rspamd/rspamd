/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/***MODULE:regexp
 * rspamd module that implements different regexp rules
 */


#include "config.h"
#include "libmime/message.h"
#include "expression.h"
#include "mime_expressions.h"
#include "libserver/maps/map.h"
#include "lua/lua_common.h"

static const guint64 rspamd_regexp_cb_magic = 0xca9d9649fc3e2659ULL;

struct regexp_module_item {
	guint64 magic;
	struct rspamd_expression *expr;
	const gchar *symbol;
	struct ucl_lua_funcdata *lua_function;
};

struct regexp_ctx {
	struct module_ctx ctx;
	gsize max_size;
};

static void process_regexp_item (struct rspamd_task *task,
								 struct rspamd_symcache_item *item,
								 void *user_data);


/* Initialization */
gint regexp_module_init (struct rspamd_config *cfg, struct module_ctx **ctx);
gint regexp_module_config (struct rspamd_config *cfg, bool validate);
gint regexp_module_reconfig (struct rspamd_config *cfg);

module_t regexp_module = {
		"regexp",
		regexp_module_init,
		regexp_module_config,
		regexp_module_reconfig,
		NULL,
		RSPAMD_MODULE_VER,
		(guint)-1,
};


static inline struct regexp_ctx *
regexp_get_context (struct rspamd_config *cfg)
{
	return (struct regexp_ctx *)g_ptr_array_index (cfg->c_modules,
			regexp_module.ctx_offset);
}

/* Process regexp expression */
static gboolean
read_regexp_expression (rspamd_mempool_t * pool,
	struct regexp_module_item *chain,
	const gchar *symbol,
	const gchar *line,
	struct rspamd_mime_expr_ud *ud)
{
	struct rspamd_expression *e = NULL;
	GError *err = NULL;

	if (!rspamd_parse_expression (line, 0, &mime_expr_subr, ud, pool, &err,
			&e)) {
		msg_warn_pool ("%s = \"%s\" is invalid regexp expression: %e", symbol,
				line,
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
	struct regexp_ctx *regexp_module_ctx;

	regexp_module_ctx = rspamd_mempool_alloc0 (cfg->cfg_pool,
			sizeof (*regexp_module_ctx));

	*ctx = (struct module_ctx *)regexp_module_ctx;

	rspamd_rcl_add_doc_by_path (cfg,
			NULL,
			"Regular expressions rules plugin",
			"regexp",
			UCL_OBJECT,
			NULL,
			0,
			NULL,
			0);

	rspamd_rcl_add_doc_by_path (cfg,
			"regexp",
			"Maximum size of data chunk scanned with any regexp (further data is truncated)",
			"max_size",
			UCL_INT,
			NULL,
			0,
			NULL,
			0);

	return 0;
}

gint
regexp_module_config (struct rspamd_config *cfg, bool validate)
{
	struct regexp_ctx *regexp_module_ctx = regexp_get_context (cfg);
	struct regexp_module_item *cur_item = NULL;
	const ucl_object_t *sec, *value, *elt;
	ucl_object_iter_t it = NULL;
	gint res = TRUE, nre = 0, nlua = 0, nshots = cfg->default_max_shots;

	if (!rspamd_config_is_module_enabled (cfg, "regexp")) {
		return TRUE;
	}

	sec = ucl_object_lookup (cfg->rcl_obj, "regexp");
	if (sec == NULL) {
		msg_err_config ("regexp module enabled, but no rules are defined");
		return TRUE;
	}

	regexp_module_ctx->max_size = 0;

	while ((value = ucl_object_iterate (sec, &it, true)) != NULL) {
		if (g_ascii_strncasecmp (ucl_object_key (value), "max_size",
			sizeof ("max_size") - 1) == 0) {
			regexp_module_ctx->max_size = ucl_obj_toint (value);
			rspamd_re_cache_set_limit (cfg->re_cache, regexp_module_ctx->max_size);
		}
		else if (g_ascii_strncasecmp (ucl_object_key (value), "max_threads",
			sizeof ("max_threads") - 1) == 0) {
			msg_warn_config ("regexp module is now single threaded, max_threads is ignored");
		}
		else if (value->type == UCL_STRING) {
			struct rspamd_mime_expr_ud ud;

			cur_item = rspamd_mempool_alloc0 (cfg->cfg_pool,
					sizeof (struct regexp_module_item));
			cur_item->symbol = ucl_object_key (value);
			cur_item->magic = rspamd_regexp_cb_magic;

			ud.conf_obj = NULL;
			ud.cfg = cfg;

			if (!read_regexp_expression (cfg->cfg_pool,
					cur_item, ucl_object_key (value),
					ucl_obj_tostring (value), &ud)) {
				if (validate) {
					return FALSE;
				}
			}
			else {
				rspamd_symcache_add_symbol (cfg->cache,
						cur_item->symbol,
						0,
						process_regexp_item,
						cur_item,
						SYMBOL_TYPE_NORMAL, -1);
				nre ++;
			}
		}
		else if (value->type == UCL_USERDATA) {
			/* Just a lua function */
			cur_item = rspamd_mempool_alloc0 (cfg->cfg_pool,
					sizeof (struct regexp_module_item));
			cur_item->magic = rspamd_regexp_cb_magic;
			cur_item->symbol = ucl_object_key (value);
			cur_item->lua_function = ucl_object_toclosure (value);

			rspamd_symcache_add_symbol (cfg->cache,
					cur_item->symbol,
					0,
					process_regexp_item,
					cur_item,
					SYMBOL_TYPE_NORMAL, -1);
			nlua ++;
		}
		else if (value->type == UCL_OBJECT) {
			const gchar *description = NULL, *group = NULL;
			gdouble score = 0.0;
			guint flags = 0, priority = 0;
			gboolean is_lua = FALSE, valid_expression = TRUE;
			struct rspamd_mime_expr_ud ud;

			/* We have some lua table, extract its arguments */
			elt = ucl_object_lookup (value, "callback");

			if (elt == NULL || elt->type != UCL_USERDATA) {

				/* Try plain regexp expression */
				elt = ucl_object_lookup_any (value, "regexp", "re", NULL);

				if (elt != NULL && ucl_object_type (elt) == UCL_STRING) {
					cur_item = rspamd_mempool_alloc0 (cfg->cfg_pool,
							sizeof (struct regexp_module_item));
					cur_item->symbol = ucl_object_key (value);
					cur_item->magic = rspamd_regexp_cb_magic;
					ud.cfg = cfg;
					ud.conf_obj = value;

					if (!read_regexp_expression (cfg->cfg_pool,
							cur_item, ucl_object_key (value),
							ucl_obj_tostring (elt), &ud)) {
						if (validate) {
							return FALSE;
						}
					}
					else {
						valid_expression = TRUE;
						nre ++;
					}
				}
				else {
					msg_err_config (
							"no callback/expression defined for regexp symbol: "
									"%s", ucl_object_key (value));
				}
			}
			else {
				is_lua = TRUE;
				nlua ++;
				cur_item = rspamd_mempool_alloc0 (
						cfg->cfg_pool,
						sizeof (struct regexp_module_item));
				cur_item->magic = rspamd_regexp_cb_magic;
				cur_item->symbol = ucl_object_key (value);
				cur_item->lua_function = ucl_object_toclosure (value);
			}

			if (cur_item && (is_lua || valid_expression)) {

				flags = SYMBOL_TYPE_NORMAL;
				elt = ucl_object_lookup (value, "mime_only");

				if (elt) {
					if (ucl_object_type (elt) != UCL_BOOLEAN) {
						msg_err_config (
								"mime_only attribute is not boolean for symbol: '%s'",
								cur_item->symbol);

						if (validate) {
							return FALSE;
						}
					}
					else {
						if (ucl_object_toboolean (elt)) {
							flags |= SYMBOL_TYPE_MIME_ONLY;
						}
					}
				}

				rspamd_symcache_add_symbol (cfg->cache,
						cur_item->symbol,
						0,
						process_regexp_item,
						cur_item,
						flags, -1);

				/* Reset flags */
				flags = 0;

				elt = ucl_object_lookup (value, "condition");

				if (elt != NULL && ucl_object_type (elt) == UCL_USERDATA) {
					struct ucl_lua_funcdata *conddata;

					g_assert (cur_item->symbol != NULL);
					conddata = ucl_object_toclosure (elt);
					rspamd_symcache_add_condition_delayed (cfg->cache,
							cur_item->symbol,
							conddata->L, conddata->idx);
				}

				elt = ucl_object_lookup (value, "description");

				if (elt) {
					description = ucl_object_tostring (elt);
				}

				elt = ucl_object_lookup (value, "group");

				if (elt) {
					group = ucl_object_tostring (elt);
				}

				elt = ucl_object_lookup (value, "score");

				if (elt) {
					if (ucl_object_type (elt) != UCL_FLOAT && ucl_object_type (elt) != UCL_INT) {
						msg_err_config (
								"score attribute is not numeric for symbol: '%s'",
								cur_item->symbol);

						if (validate) {
							return FALSE;
						}
					}
					else {
						score = ucl_object_todouble (elt);
					}
				}

				elt = ucl_object_lookup (value, "one_shot");

				if (elt) {
					if (ucl_object_type (elt) != UCL_BOOLEAN) {
						msg_err_config (
								"one_shot attribute is not boolean for symbol: '%s'",
								cur_item->symbol);

						if (validate) {
							return FALSE;
						}
					}
					else {
						if (ucl_object_toboolean (elt)) {
							nshots = 1;
						}
					}
				}

				if ((elt = ucl_object_lookup (value, "any_shot")) != NULL) {
					if (ucl_object_type (elt) != UCL_BOOLEAN) {
						msg_err_config (
								"any_shot attribute is not boolean for symbol: '%s'",
								cur_item->symbol);

						if (validate) {
							return FALSE;
						}
					}
					else {
						if (ucl_object_toboolean (elt)) {
							nshots = -1;
						}
					}
				}

				if ((elt = ucl_object_lookup (value, "nshots")) != NULL) {
					if (ucl_object_type (elt) != UCL_FLOAT && ucl_object_type (elt) != UCL_INT) {
						msg_err_config (
								"nshots attribute is not numeric for symbol: '%s'",
								cur_item->symbol);

						if (validate) {
							return FALSE;
						}
					}
					else {
						nshots = ucl_object_toint (elt);
					}
				}

				elt = ucl_object_lookup (value, "one_param");

				if (elt) {
					if (ucl_object_type (elt) != UCL_BOOLEAN) {
						msg_err_config (
								"one_param attribute is not boolean for symbol: '%s'",
								cur_item->symbol);

						if (validate) {
							return FALSE;
						}
					}
					else {
						if (ucl_object_toboolean (elt)) {
							flags |= RSPAMD_SYMBOL_FLAG_ONEPARAM;
						}
					}
				}

				elt = ucl_object_lookup (value, "priority");

				if (elt) {
					if (ucl_object_type (elt) != UCL_FLOAT && ucl_object_type (elt) != UCL_INT) {
						msg_err_config (
								"priority attribute is not numeric for symbol: '%s'",
								cur_item->symbol);

						if (validate) {
							return FALSE;
						}
					}
					else {
						priority = ucl_object_toint (elt);
					}
				}
				else {
					priority = 0;
				}

				rspamd_config_add_symbol (cfg, cur_item->symbol,
						score, description, group, flags, priority, nshots);

				elt = ucl_object_lookup (value, "groups");

				if (elt) {
					ucl_object_iter_t gr_it;
					const ucl_object_t *cur_gr;

					gr_it = ucl_object_iterate_new (elt);

					while ((cur_gr = ucl_object_iterate_safe (gr_it, true)) != NULL) {
						rspamd_config_add_symbol_group (cfg, cur_item->symbol,
								ucl_object_tostring (cur_gr));
					}

					ucl_object_iterate_free (gr_it);
				}
			}
		}
		else {
			msg_warn_config ("unknown type of attribute %s for regexp module",
				ucl_object_key (value));
		}
	}

	if (res) {
		msg_info_config ("init internal regexp module, %d regexp rules and %d "
						 "lua rules are loaded", nre, nlua);
	}
	else {
		msg_err_config ("fatal regexp module error");
	}

	return res;
}

gint
regexp_module_reconfig (struct rspamd_config *cfg)
{
	return regexp_module_config (cfg, false);
}

static gboolean
rspamd_lua_call_expression_func (struct ucl_lua_funcdata *lua_data,
		struct rspamd_task *task,
		GArray *args, gdouble *res,
		const gchar *symbol)
{
	lua_State *L = lua_data->L;
	struct rspamd_task **ptask;
	struct expression_argument *arg;
	gint pop = 0, i, nargs = 0;

	lua_rawgeti (L, LUA_REGISTRYINDEX, lua_data->idx);
	/* Now we got function in top of stack */
	ptask = lua_newuserdata (L, sizeof(struct rspamd_task *));
	rspamd_lua_setclass (L, "rspamd{task}", -1);
	*ptask = task;

	/* Now push all arguments */
	if (args) {
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
					msg_err_task ("%s: cannot pass custom params to lua function",
							symbol);
					return FALSE;
				}
			}
		}
		nargs = args->len;
	}

	if (lua_pcall (L, nargs + 1, 1, 0) != 0) {
		msg_info_task ("%s: call to lua function failed: %s", symbol,
				lua_tostring (L, -1));
		lua_pop (L, 1);

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
		msg_info_task ("%s: lua function must return a boolean", symbol);
		*res = FALSE;
	}

	lua_pop (L, pop);

	return TRUE;
}


static void
process_regexp_item (struct rspamd_task *task,
		struct rspamd_symcache_item *symcache_item,
		void *user_data)
{
	struct regexp_module_item *item = user_data;
	gdouble res = FALSE;

	/* Non-threaded version */
	if (item->lua_function) {
		/* Just call function */
		res = FALSE;
		if (!rspamd_lua_call_expression_func (item->lua_function, task, NULL,
				&res, item->symbol)) {
			msg_err_task ("error occurred when checking symbol %s",
					item->symbol);
		}
	}
	else {
		/* Process expression */
		if (item->expr) {
			res = rspamd_process_expression (item->expr, 0, task);
		}
		else {
			msg_warn_task ("FIXME: %s symbol is broken with new expressions",
					item->symbol);
		}
	}

	if (res != 0) {
		rspamd_task_insert_result (task, item->symbol, res, NULL);
	}

	rspamd_symcache_finalize_item (task, symcache_item);
}
