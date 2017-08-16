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
#include "lua_common.h"
#include "expression.h"
#include "composites.h"

#ifdef HAVE_SYS_UTSNAME_H
#endif

/*
 * This is implementation of lua routines to handle config file params
 */

/* Process a single item in 'metrics' table */
static void
lua_process_metric (lua_State *L, const gchar *name, struct rspamd_config *cfg)
{
	GList *metric_list;
	gchar *symbol;
	const gchar *desc = NULL;
	struct rspamd_metric *metric;
	gdouble *score;
	struct rspamd_symbol *s;

	/* Get module opt structure */
	if ((metric = g_hash_table_lookup (cfg->metrics, name)) == NULL) {
		metric = rspamd_config_new_metric (cfg, metric, name);
	}

	/* Now iterate through module table */
	for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
		/* key - -2, value - -1 */
		symbol =
			rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, -2));
		if (symbol != NULL) {
			if (lua_istable (L, -1)) {
				/* We got a table, so extract individual attributes */
				lua_pushstring (L, "weight");
				lua_gettable (L, -2);
				if (lua_isnumber (L, -1)) {
					score =
						rspamd_mempool_alloc (cfg->cfg_pool, sizeof (double));
					*score = lua_tonumber (L, -1);
				}
				else {
					msg_warn_config("cannot get weight of symbol: %s", symbol);
					continue;
				}
				lua_pop (L, 1);
				lua_pushstring (L, "description");
				lua_gettable (L, -2);
				if (lua_isstring (L, -1)) {
					desc = lua_tostring (L, -1);
				}
				lua_pop (L, 1);
			}
			else if (lua_isnumber (L, -1)) {
				/* Just got weight */
				score = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (double));
				*score = lua_tonumber (L, -1);
			}
			else {
				msg_warn_config("cannot get weight of symbol: %s", symbol);
				continue;
			}
			/* Insert symbol */
			if ((s =
				g_hash_table_lookup (metric->symbols, symbol)) != NULL) {
				msg_info_config("replacing weight for symbol %s: %.2f -> %.2f",
					symbol,
					*s->weight_ptr,
					*score);
				s->weight_ptr = score;
			}
			else {
				s = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (*s));
				s->name = symbol;
				s->weight_ptr = score;
				g_hash_table_insert (metric->symbols, symbol, s);
			}

			if (desc) {
				s->description = rspamd_mempool_strdup (cfg->cfg_pool, desc);
			}

			if ((metric_list =
				g_hash_table_lookup (cfg->metrics_symbols, symbol)) == NULL) {
				metric_list = g_list_prepend (NULL, metric);
				rspamd_mempool_add_destructor (cfg->cfg_pool,
					(rspamd_mempool_destruct_t)g_list_free, metric_list);
				g_hash_table_insert (cfg->metrics_symbols, symbol, metric_list);
			}
			else {
				/* Slow but keep start element of list in safe */
				if (!g_list_find (metric_list, metric)) {
					metric_list = g_list_append (metric_list, metric);
				}
			}
		}
	}
}

/* Do post load initialization based on lua */
void
rspamd_lua_post_load_config (struct rspamd_config *cfg)
{
	lua_State *L = cfg->lua_state;
	const gchar *name, *val;
	gchar *sym;
	struct rspamd_expression *expr, *old_expr;
	ucl_object_t *obj;
	gsize keylen;
	GError *err = NULL;

	/* First check all module options that may be overridden in 'config' global */
	lua_getglobal (L, "config");

	if (lua_istable (L, -1)) {
		/* Iterate */
		for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
			/* 'key' is at index -2 and 'value' is at index -1 */
			/* Key must be a string and value must be a table */
			name = luaL_checklstring (L, -2, &keylen);
			if (name != NULL && lua_istable (L, -1)) {
				obj = ucl_object_lua_import (L, lua_gettop (L));
				if (obj != NULL) {
					ucl_object_insert_key_merged (cfg->rcl_obj,
						obj,
						name,
						keylen,
						true);
				}
			}
		}
	}

	/* Check metrics settings */
	lua_getglobal (L, "metrics");

	if (lua_istable (L, -1)) {
		/* Iterate */
		for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
			/* 'key' is at index -2 and 'value' is at index -1 */
			/* Key must be a string and value must be a table */
			name = luaL_checkstring (L, -2);
			if (name != NULL && lua_istable (L, -1)) {
				lua_process_metric (L, name, cfg);
			}
		}
	}

	/* Check composites */
	lua_getglobal (L, "composites");

	if (lua_istable (L, -1)) {
		/* Iterate */
		for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
			/* 'key' is at index -2 and 'value' is at index -1 */
			/* Key must be a string and value must be a table */
			name = luaL_checkstring (L, -2);
			if (name != NULL && lua_isstring (L, -1)) {
				val = lua_tostring (L, -1);
				sym = rspamd_mempool_strdup (cfg->cfg_pool, name);
				if (!rspamd_parse_expression (val, 0, &composite_expr_subr, NULL,
							cfg->cfg_pool, &err, &expr)) {
					msg_err_config("cannot parse composite expression '%s': %s", val,
							err->message);
					g_error_free (err);
					err = NULL;
					continue;
				}
				/* Now check hash table for this composite */
				if ((old_expr =
					g_hash_table_lookup (cfg->composite_symbols,
					name)) != NULL) {
					msg_info_config("replacing composite symbol %s", name);
					g_hash_table_replace (cfg->composite_symbols, sym, expr);
				}
				else {
					g_hash_table_insert (cfg->composite_symbols, sym, expr);
					rspamd_symbols_cache_add_symbol (cfg->cache, sym,
							0, NULL, NULL, SYMBOL_TYPE_COMPOSITE, -1);
				}
			}
		}
	}

	lua_settop (L, 0);
}
