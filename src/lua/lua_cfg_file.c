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
#include "src/libserver/composites/composites.h"

/*
 * This is implementation of lua routines to handle config file params
 */

/* Process a single item in 'metrics' table */
static void
lua_process_metric (lua_State *L, const gchar *name, struct rspamd_config *cfg)
{
	gchar *symbol;
	const gchar *desc = NULL;
	gdouble *score;
	struct rspamd_symbol *s;

	/* Now iterate through module table */
	for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
		/* key - -2, value - -1 */
		symbol = rspamd_mempool_strdup (cfg->cfg_pool, luaL_checkstring (L, -2));
		if (symbol != NULL) {
			if (lua_istable (L, -1)) {
				/* We got a table, so extract individual attributes */
				lua_pushstring (L, "weight");
				lua_gettable (L, -2);
				if (lua_isnumber (L, -1)) {
					score = rspamd_mempool_alloc (cfg->cfg_pool, sizeof (double));
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
					g_hash_table_lookup (cfg->symbols, symbol)) != NULL) {
				msg_info_config("replacing weight for symbol %s: %.2f -> %.2f",
						symbol,
						*s->weight_ptr,
						*score);
				s->weight_ptr = score;
			}
			else {
				s = rspamd_mempool_alloc0 (cfg->cfg_pool, sizeof (*s));
				s->name = symbol;
				s->weight_ptr = score;
				g_hash_table_insert (cfg->symbols, symbol, s);
			}

			if (desc) {
				s->description = rspamd_mempool_strdup (cfg->cfg_pool, desc);
			}
		}
	}
}

/* Do post load initialization based on lua */
void
rspamd_lua_post_load_config (struct rspamd_config *cfg)
{
	lua_State *L = cfg->lua_state;
	const gchar *name;
	ucl_object_t *obj;
	gsize keylen, i;

	/* First check all module options that may be overridden in 'config' global */
	lua_getglobal (L, "config");

	if (lua_istable (L, -1)) {
		/* Iterate to get all keys */
		GPtrArray *names = g_ptr_array_new_full (rspamd_lua_table_size (L, -1),
				g_free);

		for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 2)) {
			gchar *tmp;
			lua_pushvalue (L, -2);
			name = luaL_checklstring (L, -1, &keylen);

			if (name && lua_istable (L, -2)) {
				tmp = g_malloc (keylen + 1);
				rspamd_strlcpy (tmp, name, keylen + 1);
				g_ptr_array_add (names, tmp);
			}
		}

		PTR_ARRAY_FOREACH (names, i, name) {
			lua_getfield (L, -1, name);

			if (lua_istable (L, -1)) {
				obj = ucl_object_lua_import (L, lua_gettop (L));

				if (obj != NULL) {
					ucl_object_sort_keys (obj, UCL_SORT_KEYS_DEFAULT);
					ucl_object_insert_key_merged (cfg->rcl_obj,
							obj,
							name,
							strlen (name),
							true);
				}
			}
		}

		g_ptr_array_free (names, TRUE);
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

	lua_settop (L, 0);

	rspamd_lua_start_gc (cfg);
}
