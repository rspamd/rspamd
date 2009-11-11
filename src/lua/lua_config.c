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


#include "lua_common.h"
#include "../expressions.h"
#include "../map.h"
#include "../radix.h"

/* Config file methods */
LUA_FUNCTION_DEF (config, get_module_opt);
LUA_FUNCTION_DEF (config, get_metric);
LUA_FUNCTION_DEF (config, get_all_opt);
LUA_FUNCTION_DEF (config, register_function);
LUA_FUNCTION_DEF (config, add_radix_map);
LUA_FUNCTION_DEF (config, add_hash_map);

static const struct luaL_reg    configlib_m[] = {
	LUA_INTERFACE_DEF (config, get_module_opt),
	LUA_INTERFACE_DEF (config, get_metric),
	LUA_INTERFACE_DEF (config, get_all_opt),
	LUA_INTERFACE_DEF (config, register_function),
	LUA_INTERFACE_DEF (config, add_radix_map),
	LUA_INTERFACE_DEF (config, add_hash_map),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* Metric methods */
LUA_FUNCTION_DEF (metric, register_symbol);

static const struct luaL_reg    metriclib_m[] = {
	LUA_INTERFACE_DEF (metric, register_symbol),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* Radix tree */
LUA_FUNCTION_DEF (radix, get_key);

static const struct luaL_reg    radixlib_m[] = {
	LUA_INTERFACE_DEF (radix, get_key),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

/* Hash table */
LUA_FUNCTION_DEF (hash_table, get_key);

static const struct luaL_reg    hashlib_m[] = {
	LUA_INTERFACE_DEF (hash_table, get_key),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

static struct config_file      *
lua_check_config (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{config}");
	luaL_argcheck (L, ud != NULL, 1, "'config' expected");
	return *((struct config_file **)ud);
}

static struct metric           *
lua_check_metric (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{metric}");
	luaL_argcheck (L, ud != NULL, 1, "'metric' expected");
	return *((struct metric **)ud);
}

static radix_tree_t           *
lua_check_radix (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{radix}");
	luaL_argcheck (L, ud != NULL, 1, "'radix' expected");
	return **((radix_tree_t ***)ud);
}

static GHashTable           *
lua_check_hash_table (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{hash_table}");
	luaL_argcheck (L, ud != NULL, 1, "'hash_table' expected");
	return **((GHashTable ***)ud);
}

/*** Config functions ***/
static int
lua_config_get_module_opt (lua_State * L)
{
	struct config_file             *cfg = lua_check_config (L);
	const char                     *mname, *optname, *val;

	if (cfg) {
		mname = luaL_checkstring (L, 2);
		optname = luaL_checkstring (L, 3);

		if (mname && optname) {
			val = get_module_opt (cfg, (char *)mname, (char *)optname);
			if (val) {
				lua_pushstring (L, val);
				return 1;
			}
		}
	}
	lua_pushnil (L);
	return 1;
}

static int
opt_compare (gconstpointer a, gconstpointer b)
{
	const struct module_opt        *o1 = a,
								   *o2 = b;
	
	return g_ascii_strcasecmp (o1->param, o2->param);
}

static int
lua_config_get_all_opt (lua_State * L)
{
	struct config_file             *cfg = lua_check_config (L);
	const char                     *mname;
	GList                          *cur_opt, *next_opt;
	struct module_opt              *opt, *tmp;
	int                             i;

	if (cfg) {
		mname = luaL_checkstring (L, 2);

		if (mname) {
			cur_opt = g_hash_table_lookup (cfg->modules_opts, mname);
			if (cur_opt == NULL) {
				lua_pushnil (L);
				return 1;
			}
			/* Sort options in alphabet order by param name */
			cur_opt = g_list_sort (cur_opt, opt_compare);
			g_hash_table_insert (cfg->modules_opts, (gpointer)mname, cur_opt);

			lua_newtable (L);
			while (cur_opt) {
				opt = cur_opt->data;
				next_opt = g_list_next (cur_opt);
				if (next_opt) {
					tmp = next_opt->data;
					if (g_ascii_strcasecmp (tmp->param, opt->param) == 0) {
						/* We have some common values */
						lua_pushstring (L, opt->param);
						lua_newtable (L);
						/* Now stack looks like:
						 * table - parent associated table of options
						 * key - string key of this option
						 * table - array of values, beginig from 1
						 */
						
						for (i = 1; ; i++) {
							lua_pushinteger (L, i);
							lua_pushstring (L, opt->value);
							lua_settable (L, -3);

							cur_opt = g_list_next (cur_opt);
							if (!cur_opt) {
								break;
							}
							tmp = cur_opt->data;
							if (g_ascii_strcasecmp (tmp->param, opt->param) != 0) {
								break;
							}
							opt = tmp;
						}
						/* Now set index in parent table */
						lua_settable (L, -3);
						/* Now continue in outter cycle */
						continue;
					}
					else {
						lua_set_table_index (L, opt->param, opt->value);
					}
				}
				else {
					lua_set_table_index (L, opt->param, opt->value);
				}
				cur_opt = next_opt;
			}
			return 1;
		}
	}
	lua_pushnil (L);
	return 1;
}


static int
lua_config_get_metric (lua_State * L)
{
	struct config_file             *cfg = lua_check_config (L);
	struct metric                  *metric, **pmetric;
	const char                     *name;

	if (cfg) {
		name = luaL_checkstring (L, 2);
		metric = g_hash_table_lookup (cfg->metrics, name);
		if (metric) {
			pmetric = lua_newuserdata (L, sizeof (struct metric *));
			lua_setclass (L, "rspamd{metric}", -1);
			*pmetric = metric;
			return 1;
		}
	}

	lua_pushnil (L);
	return 1;

}

struct lua_callback_data {
	const char                     *name;
	lua_State                      *L;
};

static gboolean
lua_config_function_callback (struct worker_task *task, GList *args, void *user_data)
{
	struct lua_callback_data       *cd = user_data;
	struct worker_task            **ptask;
	int                             i = 1;
	struct expression_argument     *arg;
	GList                          *cur;
	gboolean                        res = FALSE;

	lua_getglobal (cd->L, cd->name);
	ptask = lua_newuserdata (cd->L, sizeof (struct worker_task *));
	lua_setclass (cd->L, "rspamd{task}", -1);
	*ptask = task;
	/* Now push all arguments */
	cur = args;
	while (cur) {
		arg = get_function_arg (cur->data, task, TRUE);
		lua_pushstring (cd->L, (const char *)arg->data);
		cur = g_list_next (cur);
		i ++;
	}

	if (lua_pcall (cd->L, i, 1, 0) != 0) {
		msg_warn ("lua_metric_symbol_callback: error running function %s: %s", cd->name, lua_tostring (cd->L, -1));
	}
	else {
		if (lua_isboolean (cd->L, 1)) {
			res = lua_toboolean (cd->L, 1);
		}
	}

	return res;
}

static int
lua_config_register_function (lua_State *L)
{
	struct config_file             *cfg = lua_check_config (L);
	const char                     *name, *callback;
	struct lua_callback_data       *cd;
	
	if (cfg) {
		name = g_strdup (luaL_checkstring (L, 2));
	
		callback = luaL_checkstring (L, 3);
		if (name) {
			cd = g_malloc (sizeof (struct lua_callback_data));
			cd->name = g_strdup (callback);
			cd->L = L;
			register_expression_function (name, lua_config_function_callback, cd);
		}
	}
	return 0;
}

static int
lua_config_add_radix_map (lua_State *L)
{
	struct config_file             *cfg = lua_check_config (L);
	const char                     *map_line;
	radix_tree_t                   **r, ***ud;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		r = g_malloc (sizeof (radix_tree_t *));
		*r = radix_tree_create ();
		if (!add_map (map_line, read_radix_list, fin_radix_list, (void **)r)) {
			msg_warn ("add_radix_map: invalid radix map %s", map_line);
			radix_tree_free (*r);
			g_free (r);
			lua_pushnil (L);
			return 1;
		}
		ud = lua_newuserdata (L, sizeof (radix_tree_t *));
		*ud = r;
		lua_setclass (L, "rspamd{radix}", -1);

		return 1;
	}

	lua_pushnil (L);
	return 1;

}

static int
lua_config_add_hash_map (lua_State *L)
{
	struct config_file             *cfg = lua_check_config (L);
	const char                     *map_line;
	GHashTable                    **r, ***ud;

	if (cfg) {
		map_line = luaL_checkstring (L, 2);
		r = g_malloc (sizeof (GHashTable *));
		*r = g_hash_table_new (rspamd_strcase_hash, rspamd_strcase_equal);
		if (!add_map (map_line, read_host_list, fin_host_list, (void **)r)) {
			msg_warn ("add_radix_map: invalid hash map %s", map_line);
			g_hash_table_destroy (*r);
			g_free (r);
			lua_pushnil (L);
			return 1;
		}
		ud = lua_newuserdata (L, sizeof (GHashTable *));
		*ud = r;
		lua_setclass (L, "rspamd{hash_table}", -1);

		return 1;
	}

	lua_pushnil (L);
	return 1;

}

/*** Metric functions ***/


static void
lua_metric_symbol_callback (struct worker_task *task, gpointer ud)
{
	struct lua_callback_data       *cd = ud;
	struct worker_task            **ptask;

	lua_getglobal (cd->L, cd->name);
	ptask = lua_newuserdata (cd->L, sizeof (struct worker_task *));
	lua_setclass (cd->L, "rspamd{task}", -1);
	*ptask = task;

	if (lua_pcall (cd->L, 1, 1, 0) != 0) {
		msg_warn ("lua_metric_symbol_callback: error running function %s: %s", cd->name, lua_tostring (cd->L, -1));
	}
}

static int
lua_metric_register_symbol (lua_State * L)
{
	struct metric                  *metric = lua_check_metric (L);
	const char                     *name, *callback;
	double                          weight;
	struct lua_callback_data       *cd;

	if (metric) {
		name = g_strdup (luaL_checkstring (L, 2));
		weight = luaL_checknumber (L, 3);
		callback = luaL_checkstring (L, 4);
		if (name) {
			cd = g_malloc (sizeof (struct lua_callback_data));
			cd->name = g_strdup (callback);
			cd->L = L;
			register_symbol (&metric->cache, name, weight, lua_metric_symbol_callback, cd);
		}
	}
	return 1;
}

/* Radix and hash table functions */
static int
lua_radix_get_key (lua_State * L)
{
	radix_tree_t                  *radix = lua_check_radix (L);
	uint32_t                       key;

	if (radix) {
		key = luaL_checkint (L, 2);

		if (radix32tree_find (radix, key) != RADIX_NO_VALUE) {
			lua_pushboolean (L, 1);
			return 1;
		}
	}

	lua_pushboolean (L, 0);
	return 1;
}

static int
lua_hash_table_get_key (lua_State * L)
{
	GHashTable                    *tbl = lua_check_hash_table (L);
	const char                    *key;

	if (tbl) {
		key = luaL_checkstring (L, 2);

		if (g_hash_table_lookup (tbl, key) != NULL) {
			lua_pushboolean (L, 1);
			return 1;
		}
	}

	lua_pushboolean (L, 0);
	return 1;
}

int
luaopen_config (lua_State * L)
{
	lua_newclass (L, "rspamd{config}", configlib_m);
	luaL_openlib (L, "rspamd_config", null_reg, 0);

	return 1;
}

int
luaopen_metric (lua_State * L)
{
	lua_newclass (L, "rspamd{metric}", metriclib_m);
	luaL_openlib (L, "rspamd_metric", null_reg, 0);

	return 1;
}

int
luaopen_radix (lua_State * L)
{
	lua_newclass (L, "rspamd{radix}", radixlib_m);
	luaL_openlib (L, "rspamd_radix", null_reg, 0);

	return 1;
}

int
luaopen_hash_table (lua_State * L)
{
	lua_newclass (L, "rspamd{hash_table}", hashlib_m);
	luaL_openlib (L, "rspamd_hash_table", null_reg, 0);

	return 1;
}
