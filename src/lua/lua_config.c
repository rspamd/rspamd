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

/* Config file methods */
LUA_FUNCTION_DEF(config, get_module_opt);
LUA_FUNCTION_DEF(config, get_metric);
LUA_FUNCTION_DEF(config, get_all_opt);

static const struct luaL_reg configlib_m[] = {
    LUA_INTERFACE_DEF(config, get_module_opt),
    LUA_INTERFACE_DEF(config, get_metric),
    LUA_INTERFACE_DEF(config, get_all_opt),
	{"__tostring", lua_class_tostring},
    {NULL, NULL}
};

/* Metric methods */
LUA_FUNCTION_DEF(metric, register_symbol);

static const struct luaL_reg metriclib_m[] = {
	LUA_INTERFACE_DEF(metric, register_symbol),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

static struct config_file *
lua_check_config (lua_State *L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{config}");
	luaL_argcheck (L, ud != NULL, 1, "'config' expected");
	return *((struct config_file **)ud);
}

static struct metric *
lua_check_metric (lua_State *L)
{
	void *ud = luaL_checkudata (L, 1, "rspamd{metric}");
	luaL_argcheck (L, ud != NULL, 1, "'metric' expected");
	return *((struct metric **)ud);
}

/*** Config functions ***/
static int
lua_config_get_module_opt (lua_State *L)
{
    struct config_file *cfg = lua_check_config (L);
    const char *mname, *optname, *val;

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
lua_config_get_all_opt (lua_State *L)
{
    struct config_file *cfg = lua_check_config (L);
    const char *mname;
	GList *cur_opt;
	struct module_opt *cur;

    if (cfg) {
        mname = luaL_checkstring (L, 2);

        if (mname) {	
			cur_opt = g_hash_table_lookup (cfg->modules_opts, mname);
			if (cur_opt == NULL) {
				lua_pushnil (L);
				return 1;
			}
	
			lua_newtable (L);
			while (cur_opt) {
				cur = cur_opt->data;
				lua_set_table_index (L, cur->param, cur->value);
				cur_opt = g_list_next (cur_opt);
			}
			return 1;
        }
    }
    lua_pushnil (L);
    return 1;
}


static int
lua_config_get_metric (lua_State *L)
{
    struct config_file *cfg = lua_check_config (L);
    struct metric *metric, **pmetric;
    const char *name;

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

/*** Metric functions ***/

struct lua_callback_data {
	const char *name;
	lua_State *L;
};

static void
lua_metric_symbol_callback (struct worker_task *task, gpointer ud)
{
	struct lua_callback_data *cd = ud;
	struct worker_task **ptask;

	lua_getglobal (cd->L, cd->name);
	ptask = lua_newuserdata (cd->L, sizeof (struct worker_task *));
	lua_setclass (cd->L, "rspamd{task}", -1);
	*ptask = task;

	if (lua_pcall(cd->L, 1, 1, 0) != 0) {
        msg_warn ("lua_metric_symbol_callback: error running function %s: %s",
					cd->name, lua_tostring(cd->L, -1));
	}
}

static int
lua_metric_register_symbol (lua_State *L)
{
	struct metric *metric = lua_check_metric (L);
	const char *name, *callback;
	double weight;
	struct lua_callback_data *cd;

	if (metric) {
		name = luaL_checkstring (L, 2);
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

int
luaopen_config (lua_State *L)
{
    lua_newclass (L, "rspamd{config}", configlib_m);
	luaL_openlib (L, "rspamd_config", null_reg, 0);

    return 1;
}

int
luaopen_metric (lua_State *L)
{
    lua_newclass (L, "rspamd{metric}", metriclib_m);
	luaL_openlib (L, "rspamd_metric", null_reg, 0);

    return 1;
}
