/*
 * Copyright (c) 2009, Rambler media
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
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

/* 
 * This is implementation of lua routines to handle config file params 
 */


/* Check element with specified name in list, and append it to list if no element with such name was found */
static void
lua_check_element (memory_pool_t *pool, const gchar *name, GList *options, struct module_opt **opt) 
{
	struct module_opt                   *cur;
	GList                               *cur_opt;
	gboolean                             found = FALSE;

	cur_opt = options;

	while (cur_opt) {
		cur = cur_opt->data;

		if (g_ascii_strcasecmp (cur->param, name) == 0) {
			found = TRUE;
			break;
		}
		cur_opt = g_list_next (cur_opt);
	}
	
	if (found) {
		*opt = cur;
		cur->is_lua = TRUE;
	}
	else {
		/* New option */
		*opt = memory_pool_alloc0 (pool, sizeof (struct module_opt));
		(*opt)->is_lua = TRUE;
		(void)g_list_append (options, *opt);
	}
}

/* Process a single item in 'config' table */
static void
lua_process_module (lua_State *L, const gchar *param, struct config_file *cfg)
{
	GList                               *cur_opt;
	struct module_opt                   *cur;
	const char                          *name;
	gboolean                             new_module = FALSE;

	/* Get module opt structure */
	if ((cur_opt = g_hash_table_lookup (cfg->modules_opts, param)) == NULL) {
		new_module = TRUE;
	}

	/* Now iterate throught module table */
	lua_gettable (L, -1);
	for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
		/* key - -2, value - -1 */
		name = luaL_checkstring (L, -2);
		if (name != NULL) {
			lua_check_element (cfg->cfg_pool, name, cur_opt, &cur);
			lua_process_element (cfg, name, cur, -1);
		}
	}
	
	if (new_module && cur_opt != NULL) {
		/* Insert new list into a hash */
		g_hash_table_insert (cfg->modules_opts, memory_pool_strdup (cfg->cfg_pool, param), cur_opt);
	}
}

/* Process single element */
void
lua_process_element (struct config_file *cfg, const char *name, struct module_opt *opt, int idx) 
{
	lua_State                            *L = cfg->lua_state;
	int                                   t;
	double                               *num;
	gboolean                             *flag;
	
	t = lua_type (L, idx);
	/* Handle type */
	switch (t) {
		case LUA_TNUMBER:
			opt->actual_data = memory_pool_alloc (cfg->cfg_pool, sizeof (double));
			num = (double *)opt->actual_data;
			*num = lua_tonumber (L, idx);
			opt->lua_type = LUA_VAR_NUM;
			break;
		case LUA_TBOOLEAN: 
			opt->actual_data = memory_pool_alloc (cfg->cfg_pool, sizeof (gboolean));
			flag = (gboolean *)opt->actual_data;
			*flag = lua_toboolean (L, idx);
			opt->lua_type = LUA_VAR_BOOLEAN;
			break;
		case LUA_TSTRING: 
			opt->actual_data = memory_pool_strdup (cfg->cfg_pool, lua_tostring (L, idx));
			opt->lua_type = LUA_VAR_STRING;
			break;
		case LUA_TFUNCTION:
			opt->actual_data = (gpointer)lua_topointer (L, idx);
			opt->lua_type = LUA_VAR_FUNCTION;
			break;
		case LUA_TNIL:
		case LUA_TTABLE: 
		case LUA_TUSERDATA:
		case LUA_TTHREAD:
		case LUA_TLIGHTUSERDATA:
			msg_warn ("cannot handle variables of type %s as there is nothing to do with them", lua_typename (L, t));
			opt->lua_type = LUA_VAR_UNKNOWN;
			break;
	}
}


static void
lua_module_callback (gpointer key, gpointer value, gpointer ud)
{
	struct config_file                  *cfg = ud;
	lua_State                           *L = cfg->lua_state;
	GList                               *cur;
	struct module_opt                   *opt;

	cur = value;
	while (cur) {
		opt = cur->data;
		if (opt->is_lua && opt->actual_data == NULL) {
			/* Try to extract variable name from config table first */
			lua_getglobal (L, "config");
			if (lua_istable (L, -1)) {
				lua_pushstring (L, opt->param);
      			lua_gettable (L, -2);
				if (lua_isnil (L, -1)) {
					/* Try to get global variable */
					lua_getglobal (L, opt->param);
				}
			}
			else {
				/* Try to get global variable */
				lua_getglobal (L, opt->param);
			}
			lua_process_element (cfg, opt->param, opt, -1);
		}
		cur = g_list_next (cur);
	}

}

/* Do post load initialization based on lua */
void
lua_post_load_config (struct config_file *cfg)
{
	lua_State                            *L = cfg->lua_state;
	const gchar                          *name;

	/* First check all module options that may be overriden in 'config' global */
	lua_getglobal (L, "config");

	if (lua_istable (L, -1)) {
		/* Iterate */
		for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
			/* 'key' is at index -2 and 'value' is at index -1 */
			/* Key must be a string and value must be a table */
			name = luaL_checkstring (L, -2);
			if (name != NULL && lua_istable (L, -1)) {
				lua_process_module (L, name, cfg);
			}
		}
	}

	/* Now parse all lua params */
	g_hash_table_foreach (cfg->modules_opts, lua_module_callback, cfg);
}
