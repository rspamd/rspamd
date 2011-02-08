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
#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

/* 
 * This is implementation of lua routines to handle config file params 
 */


/* Check element with specified name in list, and append it to list if no element with such name was found */
static void
lua_check_element (memory_pool_t *pool, const gchar *name, GList **options, struct module_opt **opt) 
{
	struct module_opt                   *cur;
	GList                               *cur_opt;
	gboolean                             found = FALSE;

	cur_opt = *options;

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
		(*opt)->param = memory_pool_strdup (pool, name);
		*options = g_list_prepend (*options, *opt);
	}
}

/* Process a single item in 'config' table */
static void
lua_process_module (lua_State *L, const gchar *param, struct config_file *cfg)
{
	GList                               *cur_opt;
	struct module_opt                   *cur;
	const gchar                          *name;
	gboolean                             new_module = FALSE;

	/* Get module opt structure */
	if ((cur_opt = g_hash_table_lookup (cfg->modules_opts, param)) == NULL) {
		new_module = TRUE;
	}

	/* Now iterate throught module table */
	for (lua_pushnil(L); lua_next(L, -2); lua_pop(L, 1)) {
		/* key - -2, value - -1 */
		name = luaL_checkstring (L, -2);
		if (name != NULL) {
			lua_check_element (cfg->cfg_pool, name, &cur_opt, &cur);
			lua_process_element (cfg, name, cur, -1);
			g_hash_table_insert (cfg->modules_opts, (gpointer)param, cur_opt);
		}
	}
	
	if (new_module && cur_opt != NULL) {
		/* Insert new list into a hash */
		g_hash_table_insert (cfg->modules_opts, memory_pool_strdup (cfg->cfg_pool, param), cur_opt);
	}
}

/* Process single element */
void
lua_process_element (struct config_file *cfg, const gchar *name, struct module_opt *opt, gint idx) 
{
	lua_State                            *L = cfg->lua_state;
	gint                            t;
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
			opt->actual_data = memory_pool_strdup (cfg->cfg_pool, name);
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

/* Handle lua dynamic config param */
gboolean
lua_handle_param (struct worker_task *task, gchar *mname, gchar *optname, enum lua_var_type expected_type, gpointer *res)
{
	lua_State                            *L = task->cfg->lua_state;
	GList                                *cur;
	struct module_opt                    *opt;
	struct worker_task                  **ptask;
	double                                num_res;
	gboolean                              bool_res;
	gchar                                *str_res;

	if ((cur = g_hash_table_lookup (task->cfg->modules_opts, mname)) == NULL) {
		*res = NULL;
		return FALSE;
	}
	
	/* Search for specified option */
	while (cur) {
		opt = cur->data;
		if (opt->is_lua && g_ascii_strcasecmp (opt->param, optname) == 0) {
			if (opt->lua_type == expected_type) {
				/* Just push pointer to res */
				*res = opt->actual_data;
				return TRUE;
			}
			else if (opt->lua_type == LUA_VAR_FUNCTION) {
				/* Call specified function and expect result of given expected_type */
				/* First check function in config table */
				lua_getglobal (L, "config");
				if (lua_istable (L, -1)) {
					lua_pushstring (L, mname);
					lua_gettable (L, -2);
					if (lua_isnil (L, -1)) {
						/* Try to get global variable */
						lua_getglobal (L, opt->actual_data);
					}
					else {
						/* Call local function in table */
						lua_pushstring (L, opt->actual_data);
						lua_gettable (L, -2);
					}
				}
				else {
					/* Try to get global variable */
					lua_getglobal (L, opt->actual_data);
				}
				if (lua_isnil (L, -1)) {
					msg_err ("function with name %s is not defined", (gchar *)opt->actual_data);
					return FALSE;
				}
				/* Now we got function in top of stack */
				ptask = lua_newuserdata (L, sizeof (struct worker_task *));
				lua_setclass (L, "rspamd{task}", -1);
				*ptask = task;
				/* Call function */
				if (lua_pcall (L, 1, 1, 0) != 0) {
					msg_info ("call to %s failed: %s", (gchar *)opt->actual_data, lua_tostring (L, -1));
					*res = NULL;
					return FALSE;
				}
				/* Get result of specified type */
				switch (expected_type) {
					case LUA_VAR_NUM:
						if (!lua_isnumber (L, -1)) {
							*res = NULL;
							return FALSE;
						}
						num_res = lua_tonumber (L, -1);
						*res = memory_pool_alloc (task->task_pool, sizeof (double));
						**(double **)res = num_res;
						return TRUE;
					case LUA_VAR_BOOLEAN:
						if (!lua_isboolean (L, -1)) {
							*res = NULL;
							return FALSE;
						}
						bool_res = lua_toboolean (L, -1);
						*res = memory_pool_alloc (task->task_pool, sizeof (gboolean));
						**(gboolean **)res = bool_res;
						return TRUE;
					case LUA_VAR_STRING:
						if (!lua_isstring (L, -1)) {
							*res = NULL;
							return FALSE;
						}
						str_res = memory_pool_strdup (task->task_pool, lua_tostring (L, -1));
						*res = str_res;
						return TRUE;
					case LUA_VAR_FUNCTION:
					case LUA_VAR_UNKNOWN:
						msg_err ("cannot expect function or unknown types");
						*res = NULL;
						return FALSE;
				}
			}
		}
		cur = g_list_next (cur);
	}

	/* Option not found */
	*res = NULL;
	return FALSE;
}

#define FAKE_RES_VAR "rspamd_res"
gboolean
lua_check_condition (struct config_file *cfg, const gchar *condition)
{
	lua_State                            *L = cfg->lua_state;
	gchar                                *hostbuf, *condbuf;
	gsize                                 hostlen;
	gboolean                              res;
#ifdef HAVE_SYS_UTSNAME_H
	struct utsname                        uts;
#endif

	/* Set some globals for condition */
	/* XXX: think what other variables can be useful */
	hostlen = sysconf (_SC_HOST_NAME_MAX) + 1;
	hostbuf = alloca (hostlen);
	gethostname (hostbuf, hostlen);
	hostbuf[hostlen - 1] = '\0';

	/* Hostname */
	lua_pushstring (L, hostbuf);
	lua_setglobal (L, "hostname");
	/* Config file name */
	lua_pushstring (L, cfg->cfg_name);
	lua_setglobal (L, "cfg_name");
	/* Check for uname */
#ifdef HAVE_SYS_UTSNAME_H
	uname (&uts);
	lua_pushstring (L, uts.sysname);
	lua_setglobal (L, "osname");
	lua_pushstring (L, uts.release);
	lua_setglobal (L, "osrelease");
#else
	lua_pushstring (L, "unknown");
	lua_setglobal (L, "osname");
	lua_pushstring (L, "");
	lua_setglobal (L, "osrelease");
#endif
	/* Make fake string */
	hostlen = sizeof (FAKE_RES_VAR "=") + strlen (condition);
	condbuf = g_malloc (hostlen);
	rspamd_strlcpy (condbuf, FAKE_RES_VAR "=", sizeof (FAKE_RES_VAR "="));
	g_strlcat (condbuf, condition, hostlen);
	/* Evaluate condition */
	if (luaL_dostring (L, condbuf) != 0) {
		msg_err ("eval of '%s' failed: '%s'", condition, lua_tostring (L, -1));
		g_free (condbuf);
		return FALSE;
	}
	/* Get global variable res to get result */
	lua_getglobal (L, FAKE_RES_VAR);
	if (! lua_isboolean (L, -1)) {
		msg_err ("bad string evaluated: %s, type: %s", condbuf, lua_typename (L, lua_type (L, -1)));
		g_free (condbuf);
			return FALSE;
	}

	res = lua_toboolean (L, -1);
	g_free (condbuf);

	return res;
}
