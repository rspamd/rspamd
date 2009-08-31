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
    {NULL, NULL}
};

static struct config_file *
lua_check_config (lua_State *L)
{
	void *ud = luaL_checkudata (L, 1, "Rspamd.config");
	luaL_argcheck (L, ud != NULL, 1, "'config' expected");
	return (struct config_file *)ud;
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
		    lua_setclass (L, "Rspamd.metric", -1);
		    *pmetric = metric;
        }
    }
    lua_pushnil (L);
    return 1;
    
}

int
luaopen_config (lua_State *L)
{
    lua_newclass (L, "Rspamd.config", configlib_m);
	luaL_openlib (L, "config", configlib_m, 0);

    return 1;
}

