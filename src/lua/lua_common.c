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
#include "lptree.h"
#include "utlist.h"
#include "unix-std.h"
#include "worker_util.h"
#include "ottery.h"
#include "rspamd_control.h"
#include "lua_thread_pool.h"
#include "libstat/stat_api.h"
#include "libserver/rspamd_control.h"

#include <math.h>
#include <sys/wait.h>


/* Lua module init function */
#define MODULE_INIT_FUNC "module_init"

#ifdef WITH_LUA_TRACE
ucl_object_t *lua_traces;
#endif

const luaL_reg null_reg[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};


LUA_FUNCTION_DEF (worker, get_name);
LUA_FUNCTION_DEF (worker, get_stat);
LUA_FUNCTION_DEF (worker, get_index);
LUA_FUNCTION_DEF (worker, get_pid);
LUA_FUNCTION_DEF (worker, is_scanner);
LUA_FUNCTION_DEF (worker, is_primary_controller);
LUA_FUNCTION_DEF (worker, spawn_process);

const luaL_reg worker_reg[] = {
	LUA_INTERFACE_DEF (worker, get_name),
	LUA_INTERFACE_DEF (worker, get_stat),
	LUA_INTERFACE_DEF (worker, get_index),
	LUA_INTERFACE_DEF (worker, get_pid),
	LUA_INTERFACE_DEF (worker, spawn_process),
	LUA_INTERFACE_DEF (worker, is_scanner),
	LUA_INTERFACE_DEF (worker, is_primary_controller),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static const char rspamd_modules_state_global[] = "rspamd_plugins_state";

static GQuark
lua_error_quark (void)
{
	return g_quark_from_static_string ("lua-routines");
}

/* Util functions */
/**
 * Create new class and store metatable on top of the stack
 * @param L
 * @param classname name of class
 * @param func table of class methods
 */
void
rspamd_lua_new_class (lua_State * L,
	const gchar *classname,
	const struct luaL_reg *methods)
{
	luaL_newmetatable (L, classname);   /* mt */
	lua_pushstring (L, "__index");
	lua_pushvalue (L, -2);      /* pushes the metatable */
	lua_settable (L, -3);       /* metatable.__index = metatable */

	lua_pushstring (L, "class");    /* mt,"__index",it,"class" */
	lua_pushstring (L, classname);  /* mt,"__index",it,"class",classname */
	lua_rawset (L, -3);         /* mt,"__index",it */
	luaL_register (L, NULL, methods);
}

/**
 * Create and register new class with static methods and store metatable on top of the stack
 */
void
rspamd_lua_new_class_full (lua_State *L,
	const gchar *classname,
	const gchar *static_name,
	const struct luaL_reg *methods,
	const struct luaL_reg *func)
{
	rspamd_lua_new_class (L, classname, methods);
	luaL_register (L, static_name, func);
}

static const gchar *
rspamd_lua_class_tostring_buf (lua_State *L, gboolean print_pointer, gint pos)
{
	static gchar buf[64];
	const gchar *ret = NULL;
	gint pop = 0;

	if (!lua_getmetatable (L, pos)) {
		goto err;
	}

	lua_pushstring (L, "__index");
	lua_gettable (L, -2);
	pop ++;

	if (!lua_istable (L, -1)) {
		goto err;
	}

	lua_pushstring (L, "class");
	lua_gettable (L, -2);
	pop ++;

	if (!lua_isstring (L, -1)) {
		goto err;
	}

	if (print_pointer) {
		rspamd_snprintf (buf, sizeof (buf), "%s(%p)", lua_tostring (L, -1),
				lua_touserdata (L, 1));
	}
	else {
		rspamd_snprintf (buf, sizeof (buf), "%s", lua_tostring (L, -1));
	}

	ret = buf;

err:
	lua_pop (L, pop);

	return ret;
}

gint
rspamd_lua_class_tostring (lua_State * L)
{
	const gchar *p;

	p = rspamd_lua_class_tostring_buf (L, TRUE, 1);

	if (!p) {
		lua_pushstring (L, "invalid object passed to 'lua_common.c:__tostring'");
		return lua_error (L);
	}

	lua_pushstring (L, p);

	return 1;
}


void
rspamd_lua_setclass (lua_State * L, const gchar *classname, gint objidx)
{
	luaL_getmetatable (L, classname);
	if (objidx < 0) {
		objidx--;
	}
	lua_setmetatable (L, objidx);
}

/* assume that table is at the top */
void
rspamd_lua_table_set (lua_State * L, const gchar *index, const gchar *value)
{

	lua_pushstring (L, index);
	if (value) {
		lua_pushstring (L, value);
	}
	else {
		lua_pushnil (L);
	}
	lua_settable (L, -3);
}

const gchar *
rspamd_lua_table_get (lua_State *L, const gchar *index)
{
	const gchar *result;

	lua_pushstring (L, index);
	lua_gettable (L, -2);
	if (!lua_isstring (L, -1)) {
		return NULL;
	}
	result = lua_tostring (L, -1);
	lua_pop (L, 1);
	return result;
}

static void
lua_add_actions_global (lua_State *L)
{
	gint i;

	lua_newtable (L);

	for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
		lua_pushstring (L, rspamd_action_to_str (i));
		lua_pushinteger (L, i);
		lua_settable (L, -3);
	}
	/* Set global table */
	lua_setglobal (L, "rspamd_actions");
}

#ifndef __APPLE__
#define OS_SO_SUFFIX ".so"
#else
#define OS_SO_SUFFIX ".dylib"
#endif

void
rspamd_lua_set_path (lua_State *L, const ucl_object_t *cfg_obj, GHashTable *vars)
{
	const gchar *old_path, *additional_path = NULL;
	const ucl_object_t *opts = NULL;
	const gchar *pluginsdir = RSPAMD_PLUGINSDIR,
			*rulesdir = RSPAMD_RULESDIR,
			*lualibdir = RSPAMD_LUALIBDIR,
			*libdir = RSPAMD_LIBDIR;
	const gchar *t;

	gchar path_buf[PATH_MAX];

	lua_getglobal (L, "package");
	lua_getfield (L, -1, "path");
	old_path = luaL_checkstring (L, -1);

	if (strstr (old_path, RSPAMD_PLUGINSDIR) != NULL) {
		/* Path has been already set, do not touch it */
		lua_pop (L, 2);
		return;
	}

	if (cfg_obj) {
		opts = ucl_object_lookup (cfg_obj, "options");
		if (opts != NULL) {
			opts = ucl_object_lookup (opts, "lua_path");
			if (opts != NULL && ucl_object_type (opts) == UCL_STRING) {
				additional_path = ucl_object_tostring (opts);
			}
		}
	}

	/* Try environment */
	t = getenv ("PLUGINSDIR");
	if (t) {
		pluginsdir = t;
	}

	t = getenv ("RULESDIR");
	if (t) {
		rulesdir = t;
	}

	t = getenv ("LUALIBDIR");
	if (t) {
		lualibdir = t;
	}

	t = getenv ("LIBDIR");
	if (t) {
		libdir = t;
	}

	t = getenv ("RSPAMD_LIBDIR");
	if (t) {
		libdir = t;
	}

	if (vars) {
		t = g_hash_table_lookup (vars, "PLUGINSDIR");
		if (t) {
			pluginsdir = t;
		}

		t = g_hash_table_lookup (vars, "RULESDIR");
		if (t) {
			rulesdir = t;
		}

		t = g_hash_table_lookup (vars, "LUALIBDIR");
		if (t) {
			lualibdir = t;
		}

		t = g_hash_table_lookup (vars, "LIBDIR");
		if (t) {
			libdir = t;
		}

		t = g_hash_table_lookup (vars, "RSPAMD_LIBDIR");
		if (t) {
			libdir = t;
		}
	}

	if (additional_path) {
		rspamd_snprintf (path_buf, sizeof (path_buf),
				"%s/lua/?.lua;"
						"%s/lua/?.lua;"
						"%s/?.lua;"
						"%s/?.lua;"
						"%s/?/init.lua;"
						"%s;"
						"%s",
				pluginsdir, RSPAMD_CONFDIR, rulesdir,
				lualibdir, lualibdir,
				additional_path, old_path);
	}
	else {
		rspamd_snprintf (path_buf, sizeof (path_buf),
				"%s/lua/?.lua;"
						"%s/lua/?.lua;"
						"%s/?.lua;"
						"%s/?.lua;"
						"%s/?/init.lua;"
						"%s",
				pluginsdir, RSPAMD_CONFDIR, rulesdir,
				lualibdir, lualibdir,
				old_path);
	}

	lua_pop (L, 1);
	lua_pushstring (L, path_buf);
	lua_setfield (L, -2, "path");

	lua_getglobal (L, "package");
	lua_getfield (L, -1, "cpath");
	old_path = luaL_checkstring (L, -1);

	additional_path = NULL;

	if (opts != NULL) {
		opts = ucl_object_lookup (opts, "lua_cpath");
		if (opts != NULL && ucl_object_type (opts) == UCL_STRING) {
			additional_path = ucl_object_tostring (opts);
		}
	}

	if (additional_path) {
		rspamd_snprintf (path_buf, sizeof (path_buf),
				"%s/?%s;"
				"%s;"
				"%s",
				libdir,
				OS_SO_SUFFIX,
				additional_path,
				old_path);
	}
	else {
		rspamd_snprintf (path_buf, sizeof (path_buf),
				"%s/?%s;"
				"%s",
				libdir,
				OS_SO_SUFFIX,
				old_path);
	}
	lua_pop (L, 1);
	lua_pushstring (L, path_buf);
	lua_setfield (L, -2, "cpath");

	lua_pop (L, 1);
}

static gint
rspamd_lua_cmp_version_components (const gchar *comp1, const gchar *comp2)
{
	guint v1, v2;

	v1 = strtoul (comp1, NULL, 10);
	v2 = strtoul (comp2, NULL, 10);

	return v1 - v2;
}

static int
rspamd_lua_rspamd_version_cmp (lua_State *L)
{
	const gchar *ver;
	gchar **components;
	gint ret = 0;

	if (lua_type (L, 2) == LUA_TSTRING) {
		ver = lua_tostring (L, 2);

		components = g_strsplit_set (ver, ".-_", -1);

		if (!components) {
			return luaL_error (L, "invalid arguments to 'cmp': %s", ver);
		}

		if (components[0]) {
			ret = rspamd_lua_cmp_version_components (components[0],
					RSPAMD_VERSION_MAJOR);
		}

		if (ret) {
			goto set;
		}

		if (components[1]) {
			ret = rspamd_lua_cmp_version_components (components[1],
					RSPAMD_VERSION_MINOR);
		}

		if (ret) {
			goto set;
		}

		if (components[2]) {
			ret = rspamd_lua_cmp_version_components (components[2],
					RSPAMD_VERSION_PATCH);
		}

		/*
		 * XXX: we don't compare git releases assuming that it is meaningless
		 */
	}
	else {
		return luaL_error (L, "invalid arguments to 'cmp'");
	}

set:
	g_strfreev (components);
	lua_pushinteger (L, ret);

	return 1;
}

static int
rspamd_lua_rspamd_version_numeric (lua_State *L)
{
	static gint64 version_num = RSPAMD_VERSION_NUM;
	const gchar *type;

	if (lua_gettop (L) >= 2 && lua_type (L, 1) == LUA_TSTRING) {
		type = lua_tostring (L, 1);
		if (g_ascii_strcasecmp (type, "short") == 0) {
			version_num = RSPAMD_VERSION_MAJOR_NUM * 1000 +
						  RSPAMD_VERSION_MINOR_NUM * 100 +
						  RSPAMD_VERSION_PATCH_NUM * 10;
		}
		else if (g_ascii_strcasecmp (type, "main") == 0) {
			version_num = RSPAMD_VERSION_MAJOR_NUM * 1000 +
						  RSPAMD_VERSION_MINOR_NUM * 100;
		}
		else if (g_ascii_strcasecmp (type, "major") == 0) {
			version_num = RSPAMD_VERSION_MAJOR_NUM;
		}
		else if (g_ascii_strcasecmp (type, "minor") == 0) {
			version_num = RSPAMD_VERSION_MINOR_NUM;
		}
		else if (g_ascii_strcasecmp (type, "patch") == 0) {
			version_num = RSPAMD_VERSION_PATCH_NUM;
		}
	}

	lua_pushinteger (L, version_num);

	return 1;
}

static int
rspamd_lua_rspamd_version (lua_State *L)
{
	const gchar *result = NULL, *type;

	if (lua_gettop (L) == 0) {
		result = RVERSION;
	}
	else if (lua_gettop (L) >= 1 && lua_type (L, 1) == LUA_TSTRING) {
		/* We got something like string */
		type = lua_tostring (L, 1);

		if (g_ascii_strcasecmp (type, "short") == 0) {
			result = RSPAMD_VERSION_MAJOR
					 "." RSPAMD_VERSION_MINOR
					 "." RSPAMD_VERSION_PATCH;
		}
		else if (g_ascii_strcasecmp (type, "main") == 0) {
			result = RSPAMD_VERSION_MAJOR "." RSPAMD_VERSION_MINOR;
		}
		else if (g_ascii_strcasecmp (type, "major") == 0) {
			result = RSPAMD_VERSION_MAJOR;
		}
		else if (g_ascii_strcasecmp (type, "minor") == 0) {
			result = RSPAMD_VERSION_MINOR;
		}
		else if (g_ascii_strcasecmp (type, "patch") == 0) {
			result = RSPAMD_VERSION_PATCH;
		}
		else if (g_ascii_strcasecmp (type, "id") == 0) {
			result = RID;
		}
		else if (g_ascii_strcasecmp (type, "num") == 0) {
			return rspamd_lua_rspamd_version_numeric (L);
		}
		else if (g_ascii_strcasecmp (type, "cmp") == 0) {
			return rspamd_lua_rspamd_version_cmp (L);
		}
	}

	lua_pushstring (L, result);

	return 1;
}

void
rspamd_lua_set_globals (struct rspamd_config *cfg, lua_State *L,
							GHashTable *vars)
{
	struct rspamd_config **pcfg;
	gint orig_top = lua_gettop (L);

	/* First check for global variable 'config' */
	lua_getglobal (L, "config");
	if (lua_isnil (L, -1)) {
		/* Assign global table to set up attributes */
		lua_newtable (L);
		lua_setglobal (L, "config");
	}

	lua_getglobal (L, "metrics");
	if (lua_isnil (L, -1)) {
		lua_newtable (L);
		lua_setglobal (L, "metrics");
	}

	lua_getglobal (L, "composites");
	if (lua_isnil (L, -1)) {
		lua_newtable (L);
		lua_setglobal (L, "composites");
	}

	lua_getglobal (L, "rspamd_classifiers");
	if (lua_isnil (L, -1)) {
		lua_newtable (L);
		lua_setglobal (L, "rspamd_classifiers");
	}

	lua_getglobal (L, "classifiers");
	if (lua_isnil (L, -1)) {
		lua_newtable (L);
		lua_setglobal (L, "classifiers");
	}

	lua_getglobal (L, "rspamd_version");
	if (lua_isnil (L, -1)) {
		lua_pushcfunction (L, rspamd_lua_rspamd_version);
		lua_setglobal (L, "rspamd_version");
	}

	if (cfg != NULL) {
		pcfg = lua_newuserdata (L, sizeof (struct rspamd_config *));
		rspamd_lua_setclass (L, "rspamd{config}", -1);
		*pcfg = cfg;
		lua_setglobal (L, "rspamd_config");
	}

	lua_settop (L, orig_top);

	/* Set known paths as rspamd_paths global */
	lua_getglobal (L, "rspamd_paths");
	if (lua_isnil (L, -1)) {
		const gchar *confdir = RSPAMD_CONFDIR,
				*local_confdir = RSPAMD_LOCAL_CONFDIR,
				*rundir = RSPAMD_RUNDIR,
				*dbdir = RSPAMD_DBDIR,
				*logdir = RSPAMD_LOGDIR,
				*wwwdir = RSPAMD_WWWDIR,
				*pluginsdir = RSPAMD_PLUGINSDIR,
				*rulesdir = RSPAMD_RULESDIR,
				*lualibdir = RSPAMD_LUALIBDIR,
				*prefix = RSPAMD_PREFIX;
		const gchar *t;

		/* Try environment */
		t = getenv ("PLUGINSDIR");
		if (t) {
			pluginsdir = t;
		}

		t = getenv ("RULESDIR");
		if (t) {
			rulesdir = t;
		}

		t = getenv ("DBDIR");
		if (t) {
			dbdir = t;
		}

		t = getenv ("RUNDIR");
		if (t) {
			rundir = t;
		}

		t = getenv ("LUALIBDIR");
		if (t) {
			lualibdir = t;
		}

		t = getenv ("LOGDIR");
		if (t) {
			logdir = t;
		}

		t = getenv ("WWWDIR");
		if (t) {
			wwwdir = t;
		}

		t = getenv ("CONFDIR");
		if (t) {
			confdir = t;
		}

		t = getenv ("LOCAL_CONFDIR");
		if (t) {
			local_confdir = t;
		}


		if (vars) {
			t = g_hash_table_lookup (vars, "PLUGINSDIR");
			if (t) {
				pluginsdir = t;
			}

			t = g_hash_table_lookup (vars, "RULESDIR");
			if (t) {
				rulesdir = t;
			}

			t = g_hash_table_lookup (vars, "LUALIBDIR");
			if (t) {
				lualibdir = t;
			}

			t = g_hash_table_lookup (vars, "RUNDIR");
			if (t) {
				rundir = t;
			}

			t = g_hash_table_lookup (vars, "WWWDIR");
			if (t) {
				wwwdir = t;
			}

			t = g_hash_table_lookup (vars, "CONFDIR");
			if (t) {
				confdir = t;
			}

			t = g_hash_table_lookup (vars, "LOCAL_CONFDIR");
			if (t) {
				local_confdir = t;
			}

			t = g_hash_table_lookup (vars, "DBDIR");
			if (t) {
				dbdir = t;
			}

			t = g_hash_table_lookup (vars, "LOGDIR");
			if (t) {
				logdir = t;
			}
		}

		lua_createtable (L, 0, 9);

		rspamd_lua_table_set (L, RSPAMD_CONFDIR_INDEX, confdir);
		rspamd_lua_table_set (L, RSPAMD_LOCAL_CONFDIR_INDEX, local_confdir);
		rspamd_lua_table_set (L, RSPAMD_RUNDIR_INDEX, rundir);
		rspamd_lua_table_set (L, RSPAMD_DBDIR_INDEX, dbdir);
		rspamd_lua_table_set (L, RSPAMD_LOGDIR_INDEX, logdir);
		rspamd_lua_table_set (L, RSPAMD_WWWDIR_INDEX, wwwdir);
		rspamd_lua_table_set (L, RSPAMD_PLUGINSDIR_INDEX, pluginsdir);
		rspamd_lua_table_set (L, RSPAMD_RULESDIR_INDEX, rulesdir);
		rspamd_lua_table_set (L, RSPAMD_LUALIBDIR_INDEX, lualibdir);
		rspamd_lua_table_set (L, RSPAMD_PREFIX_INDEX, prefix);

		lua_setglobal (L, "rspamd_paths");
	}

	lua_settop (L, orig_top);
}

#ifdef WITH_LUA_TRACE
static gint
lua_push_trace_data (lua_State *L)
{
	if (lua_traces) {
		ucl_object_push_lua (L, lua_traces, true);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}
#endif

lua_State *
rspamd_lua_init ()
{
	lua_State *L;

	L = luaL_newstate ();
	luaL_openlibs (L);
	luaopen_logger (L);
	luaopen_mempool (L);
	luaopen_config (L);
	luaopen_map (L);
	luaopen_trie (L);
	luaopen_task (L);
	luaopen_textpart (L);
	luaopen_mimepart (L);
	luaopen_image (L);
	luaopen_url (L);
	luaopen_classifier (L);
	luaopen_statfile (L);
	luaopen_regexp (L);
	luaopen_cdb (L);
	luaopen_xmlrpc (L);
	luaopen_http (L);
	luaopen_redis (L);
	luaopen_upstream (L);
	lua_add_actions_global (L);
	luaopen_dns_resolver (L);
	luaopen_rsa (L);
	luaopen_ip (L);
	luaopen_expression (L);
	luaopen_text (L);
	luaopen_util (L);
	luaopen_tcp (L);
	luaopen_html (L);
	luaopen_fann (L);
	luaopen_sqlite3 (L);
	luaopen_cryptobox (L);
	luaopen_dns (L);

	luaL_newmetatable (L, "rspamd{ev_base}");
	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{ev_base}");
	lua_rawset (L, -3);
	lua_pop (L, 1);

	luaL_newmetatable (L, "rspamd{session}");
	lua_pushstring (L, "class");
	lua_pushstring (L, "rspamd{session}");
	lua_rawset (L, -3);
	lua_pop (L, 1);

	rspamd_lua_new_class (L, "rspamd{worker}", worker_reg);
	rspamd_lua_add_preload (L, "lpeg", luaopen_lpeg);
	luaopen_ucl (L);
	rspamd_lua_add_preload (L, "ucl", luaopen_ucl);

	/* Add plugins global */
	lua_newtable (L);
	lua_setglobal (L, "rspamd_plugins");

	/* Set PRNG */
	lua_getglobal (L, "math");
	lua_pushstring (L, "randomseed");
	lua_gettable (L, -2);
	lua_pushinteger (L, ottery_rand_uint64 ());
	lua_pcall (L, 1, 0, 0);
	lua_pop (L, 1); /* math table */

	/* Modules state */
	lua_newtable (L);
	/*
	 * rspamd_plugins_state = {
	 *   enabled = {},
	 *   disabled_unconfigured = {},
	 *   disabled_redis = {},
	 *   disabled_explicitly = {},
	 *   disabled_failed = {},
	 *   disabled_experimental = {},
	 * }
	 */
#define ADD_TABLE(name) do { \
	lua_pushstring (L, #name); \
	lua_newtable (L); \
	lua_settable (L, -3); \
} while (0)

	ADD_TABLE (enabled);
	ADD_TABLE (disabled_unconfigured);
	ADD_TABLE (disabled_redis);
	ADD_TABLE (disabled_explicitly);
	ADD_TABLE (disabled_failed);
	ADD_TABLE (disabled_experimental);

#undef ADD_TABLE
	lua_setglobal (L, rspamd_modules_state_global);

#ifdef WITH_LUA_TRACE
	lua_pushcfunction (L, lua_push_trace_data);
	lua_setglobal (L, "get_traces");
#endif

	return L;
}

/**
 * Initialize new locked lua_State structure
 */
struct lua_locked_state *
rspamd_init_lua_locked (struct rspamd_config *cfg)
{
	struct lua_locked_state *new;

	new = g_malloc0 (sizeof (struct lua_locked_state));
	new->L = rspamd_lua_init ();
	new->m = rspamd_mutex_new ();

	return new;
}

/**
 * Free locked state structure
 */
void
rspamd_free_lua_locked (struct lua_locked_state *st)
{
	g_assert (st != NULL);

	lua_close (st->L);

	rspamd_mutex_free (st->m);

	g_free (st);
}


void
rspamd_plugins_table_push_elt (lua_State *L, const gchar *field_name,
		const gchar *new_elt)
{
	lua_getglobal (L, rspamd_modules_state_global);
	lua_pushstring (L, field_name);
	lua_gettable (L, -2);
	lua_pushstring (L, new_elt);
	lua_newtable (L);
	lua_settable (L, -3);
	lua_pop (L, 2); /* Global + element */
}

gboolean
rspamd_init_lua_filters (struct rspamd_config *cfg, gboolean force_load)
{
	struct rspamd_config **pcfg;
	GList *cur;
	struct script_module *module;
	lua_State *L = cfg->lua_state;
	GString *tb;
	gint err_idx;

	cur = g_list_first (cfg->script_modules);

	while (cur) {
		module = cur->data;

		if (module->path) {
			if (!force_load) {
				if (!rspamd_config_is_module_enabled (cfg, module->name)) {
					cur = g_list_next (cur);
					continue;
				}
			}

			lua_pushcfunction (L, &rspamd_lua_traceback);
			err_idx = lua_gettop (L);

			if (luaL_loadfile (L, module->path) != 0) {
				msg_err_config ("load of %s failed: %s", module->path,
					lua_tostring (L, -1));
				lua_pop (L, 1); /*  Error function */

				rspamd_plugins_table_push_elt (L, "disabled_failed",
						module->name);

				cur = g_list_next (cur);
				continue;
			}

			/* Initialize config structure */
			pcfg = lua_newuserdata (L, sizeof (struct rspamd_config *));
			rspamd_lua_setclass (L, "rspamd{config}", -1);
			*pcfg = cfg;
			lua_setglobal (L, "rspamd_config");

			if (lua_pcall (L, 0, 0, err_idx) != 0) {
				tb = lua_touserdata (L, -1);
				msg_err_config ("init of %s failed: %v",
						module->path,
						tb);

				g_string_free (tb, TRUE);
				lua_pop (L, 2); /* Result and error function */

				rspamd_plugins_table_push_elt (L, "disabled_failed",
						module->name);

				cur = g_list_next (cur);
				continue;
			}

			if (!force_load) {
				msg_info_config ("init lua module %s", module->name);
			}

			lua_pop (L, 1); /* Error function */
		}

		cur = g_list_next (cur);
	}

	return TRUE;
}

void
rspamd_lua_dumpstack (lua_State *L)
{
	gint i, t, r = 0;
	gint top = lua_gettop (L);
	gchar buf[BUFSIZ];

	r += rspamd_snprintf (buf + r, sizeof (buf) - r, "lua stack: ");
	for (i = 1; i <= top; i++) { /* repeat for each level */
		t = lua_type (L, i);
		switch (t)
		{
		case LUA_TSTRING: /* strings */
			r += rspamd_snprintf (buf + r,
					sizeof (buf) - r,
					"str: %s",
					lua_tostring (L, i));
			break;

		case LUA_TBOOLEAN: /* booleans */
			r += rspamd_snprintf (buf + r, sizeof (buf) - r,
					lua_toboolean (L, i) ? "bool: true" : "bool: false");
			break;

		case LUA_TNUMBER: /* numbers */
			r += rspamd_snprintf (buf + r,
					sizeof (buf) - r,
					"number: %.2f",
					lua_tonumber (L, i));
			break;

		default: /* other values */
			r += rspamd_snprintf (buf + r,
					sizeof (buf) - r,
					"type: %s",
					lua_typename (L, t));
			break;

		}
		if (i < top) {
			r += rspamd_snprintf (buf + r, sizeof (buf) - r, " -> "); /* put a separator */
		}
	}
	msg_info (buf);
}

gpointer
rspamd_lua_check_class (lua_State *L, gint index, const gchar *name)
{
	gpointer p;

	if (lua_type (L, index) == LUA_TUSERDATA) {
		p = lua_touserdata (L, index);
		if (p) {
			if (lua_getmetatable (L, index)) {
				lua_getfield (L, LUA_REGISTRYINDEX, name);  /* get correct metatable */
				if (lua_rawequal (L, -1, -2)) {  /* does it have the correct mt? */
					lua_pop (L, 2);  /* remove both metatables */
					return p;
				}
				lua_pop (L, 2);
			}
		}
	}
	return NULL;
}

int
rspamd_lua_typerror (lua_State *L, int narg, const char *tname)
{
	const char *msg = lua_pushfstring (L, "%s expected, got %s", tname,
			luaL_typename (L, narg));
	return luaL_argerror (L, narg, msg);
}


void
rspamd_lua_add_preload (lua_State *L, const gchar *name, lua_CFunction func)
{
	lua_getglobal (L, "package");
	lua_pushstring (L, "preload");
	lua_gettable (L, -2);
	lua_pushcfunction (L, func);
	lua_setfield (L, -2, name);
	lua_pop (L, 2); /* preload key + global package */
}


gboolean
rspamd_lua_parse_table_arguments (lua_State *L, gint pos,
		GError **err, const gchar *extraction_pattern, ...)
{
	const gchar *p, *key = NULL, *end, *cls;
	va_list ap;
	gboolean required = FALSE, failed = FALSE, is_table;
	gchar classbuf[128];
	enum {
		read_key = 0,
		read_arg,
		read_class_start,
		read_class,
		read_semicolon
	} state = read_key;
	gsize keylen = 0, *valuelen, clslen;
	gint idx = 0, t;

	g_assert (extraction_pattern != NULL);

	if (pos < 0) {
		/* Get absolute pos */
		pos = lua_gettop (L) + pos + 1;
	}

	if (lua_type (L, pos) == LUA_TTABLE) {
		is_table = TRUE;
	}
	else {
		is_table = FALSE;
		idx = pos;
	}

	p = extraction_pattern;
	end = p + strlen (extraction_pattern);

	va_start (ap, extraction_pattern);

	while (p <= end) {
		switch (state) {
		case read_key:
			if (*p == '=') {
				if (key == NULL) {
					g_set_error (err, lua_error_quark (), 1, "cannot read key");
					va_end (ap);

					return FALSE;
				}

				state = read_arg;
				keylen = p - key;
			}
			else if (*p == '*' && key == NULL) {
				required = TRUE;
			}
			else if (key == NULL) {
				key = p;
			}
			p ++;
			break;
		case read_arg:
			g_assert (keylen != 0);

			if (is_table) {
				lua_pushlstring (L, key, keylen);
				lua_gettable (L, pos);
				idx = -1;
			}

			t = lua_type (L, idx);

			switch (g_ascii_toupper (*p)) {
			case 'S':
				if (t == LUA_TSTRING) {
					*(va_arg (ap, const gchar **)) = lua_tostring (L, idx);
				}
				else if (t == LUA_TNIL || t == LUA_TNONE) {
					failed = TRUE;
					*(va_arg (ap, const gchar **)) = NULL;
				}
				else {
					g_set_error (err,
							lua_error_quark (),
							1,
							"bad type for key:"
									" %.*s: '%s', '%s' is expected",
							(gint) keylen,
							key,
							lua_typename (L, lua_type (L, idx)), "string");
					va_end (ap);

					return FALSE;
				}

				if (is_table) {
					lua_pop (L, 1);
				}
				break;

			case 'I':
				if (t == LUA_TNUMBER) {
					*(va_arg (ap, gint64 *)) = lua_tonumber (L, idx);
				}
				else if (t == LUA_TNIL || t == LUA_TNONE) {
					failed = TRUE;
					*(va_arg (ap,  gint64 *)) = 0;
				}
				else {
					g_set_error (err,
							lua_error_quark (),
							1,
							"bad type for key:"
									" %.*s: '%s', '%s' is expected",
							(gint) keylen,
							key,
							lua_typename (L, lua_type (L, idx)),
							"int64");
					va_end (ap);

					return FALSE;
				}
				if (is_table) {
					lua_pop (L, 1);
				}
				break;

			case 'F':
				if (t == LUA_TFUNCTION) {
					if (!is_table) {
						lua_pushvalue (L, idx);
					}

					*(va_arg (ap, gint *)) = luaL_ref (L, LUA_REGISTRYINDEX);
				}
				else if (t == LUA_TNIL || t == LUA_TNONE) {
					failed = TRUE;
					*(va_arg (ap,  gint *)) = -1;
					if (is_table) {
						lua_pop (L, 1);
					}
				}
				else {
					g_set_error (err,
							lua_error_quark (),
							1,
							"bad type for key:"
									" %.*s: '%s', '%s' is expected",
							(gint) keylen,
							key,
							lua_typename (L, lua_type (L, idx)),
							"function");
					va_end (ap);
					if (is_table) {
						lua_pop (L, 1);
					}

					return FALSE;
				}

				/* luaL_ref pops argument from the stack */
				break;

			case 'B':
				if (t == LUA_TBOOLEAN) {
					*(va_arg (ap, gboolean *)) = lua_toboolean (L, idx);
				}
				else if (t == LUA_TNIL || t == LUA_TNONE) {
					failed = TRUE;
					*(va_arg (ap,  gboolean *)) = 0;
				}
				else {
					g_set_error (err,
							lua_error_quark (),
							1,
							"bad type for key:"
									" %.*s: '%s', '%s' is expected",
							(gint) keylen,
							key,
							lua_typename (L, lua_type (L, idx)),
							"bool");
					va_end (ap);

					return FALSE;
				}

				if (is_table) {
					lua_pop (L, 1);
				}
				break;

			case 'N':
				if (t == LUA_TNUMBER) {
					*(va_arg (ap, gdouble *)) = lua_tonumber (L, idx);
				}
				else if (t == LUA_TNIL || t == LUA_TNONE) {
					failed = TRUE;
					*(va_arg (ap,  gdouble *)) = 0;
				}
				else {
					g_set_error (err,
							lua_error_quark (),
							1,
							"bad type for key:"
									" %.*s: '%s', '%s' is expected",
							(gint) keylen,
							key,
							lua_typename (L, lua_type (L, idx)),
							"double");
					va_end (ap);

					return FALSE;
				}

				if (is_table) {
					lua_pop (L, 1);
				}
				break;

			case 'D':
				if (t == LUA_TNUMBER) {
					*(va_arg (ap, gdouble *)) = lua_tonumber (L, idx);
				}
				else if (t == LUA_TNIL || t == LUA_TNONE) {
					failed = TRUE;
					*(va_arg (ap,  gdouble *)) = NAN;
				}
				else {
					g_set_error (err,
							lua_error_quark (),
							1,
							"bad type for key:"
							" %.*s: '%s', '%s' is expected",
							(gint) keylen,
							key,
							lua_typename (L, lua_type (L, idx)),
							"double");
					va_end (ap);

					return FALSE;
				}

				if (is_table) {
					lua_pop (L, 1);
				}
				break;

			case 'V':
				valuelen = va_arg (ap, gsize *);

				if (t == LUA_TSTRING) {
					*(va_arg (ap, const gchar **)) = lua_tolstring (L, idx,
							valuelen);
				}
				else if (t == LUA_TNIL || t == LUA_TNONE) {
					failed = TRUE;
					*(va_arg (ap, const char **)) = NULL;
					*valuelen = 0;
				}
				else {
					g_set_error (err,
							lua_error_quark (),
							1,
							"bad type for key:"
									" %.*s: '%s', '%s' is expected",
							(gint) keylen,
							key,
							lua_typename (L, lua_type (L, idx)),
							"string");
					va_end (ap);

					return FALSE;
				}

				if (is_table) {
					lua_pop (L, 1);
				}
				break;
			case 'O':
				if (t != LUA_TNONE) {
					*(va_arg (ap, ucl_object_t **)) = ucl_object_lua_import (L,
							idx);
				}
				else {
					failed = TRUE;
					*(va_arg (ap, ucl_object_t **)) = NULL;
				}

				if (is_table) {
					lua_pop (L, 1);
				}
				break;
			case 'U':
				if (t == LUA_TNIL || t == LUA_TNONE) {
					failed = TRUE;
					*(va_arg (ap, void **)) = NULL;
				}
				else if (t != LUA_TUSERDATA) {
					g_set_error (err,
							lua_error_quark (),
							1,
							"bad type for key:"
									" %.*s: '%s', '%s' is expected",
							(gint) keylen,
							key,
							lua_typename (L, lua_type (L, idx)),
							"int64");
					va_end (ap);

					return FALSE;
				}

				state = read_class_start;
				clslen = 0;
				cls = NULL;
				p ++;
				continue;
			default:
				g_assert (0);
				break;
			}

			if (failed && required) {
				g_set_error (err, lua_error_quark (), 2, "required parameter "
						"%.*s is missing", (gint)keylen, key);
				va_end (ap);

				return FALSE;
			}

			if (!is_table) {
				idx ++;
			}

			/* Reset read params */
			state = read_semicolon;
			failed = FALSE;
			required = FALSE;
			keylen = 0;
			key = NULL;
			p ++;
			break;

		case read_class_start:
			if (*p == '{') {
				cls = p + 1;
				state = read_class;
			}
			else {
				if (is_table) {
					lua_pop (L, 1);
				}

				g_set_error (err, lua_error_quark (), 2, "missing classname for "
						"%.*s", (gint)keylen, key);
				va_end (ap);

				return FALSE;
			}
			p ++;
			break;

		case read_class:
			if (*p == '}') {
				clslen = p - cls;
				if (clslen == 0) {
					if (is_table) {
						lua_pop (L, 1);
					}

					g_set_error (err,
							lua_error_quark (),
							2,
							"empty classname for "
									"%*.s",
							(gint) keylen,
							key);
					va_end (ap);

					return FALSE;
				}

				rspamd_snprintf (classbuf, sizeof (classbuf), "rspamd{%*s}",
						(gint) clslen, cls);


				/*
				 * We skip class check here for speed in non-table mode
				 */
				if (!failed && (!is_table ||
						rspamd_lua_check_class (L, idx, classbuf))) {
					*(va_arg (ap, void **)) = *(void **)lua_touserdata (L, idx);
				}
				else {
					if (!failed) {
						g_set_error (err,
								lua_error_quark (),
								2,
								"invalid class for key %.*s, expected %s, got %s",
								(gint) keylen,
								key,
								classbuf,
								rspamd_lua_class_tostring_buf (L, FALSE, idx));
						va_end (ap);

						return FALSE;
					}
				}

				if (is_table) {
					lua_pop (L, 1);
				}
				else {
					idx ++;
				}

				if (failed && required) {
					g_set_error (err,
							lua_error_quark (),
							2,
							"required parameter "
									"%.*s is missing",
							(gint) keylen,
							key);
					va_end (ap);

					return FALSE;
				}

				/* Reset read params */
				state = read_semicolon;
				failed = FALSE;
				required = FALSE;
				keylen = 0;
				key = NULL;
			}
			p ++;
			break;

		case read_semicolon:
			if (*p == ';' || p == end) {
				state = read_key;
				key = NULL;
				keylen = 0;
				failed = FALSE;
			}
			else {
				g_set_error (err, lua_error_quark (), 2, "bad format string: %s,"
								" at char %c, position %d",
						extraction_pattern, *p, (int)(p - extraction_pattern));
				va_end (ap);

				return FALSE;
			}

			p++;
			break;
		}
	}

	va_end (ap);

	return TRUE;
}

static void
rspamd_lua_traceback_string (lua_State *L, GString *s)
{
	gint i = 1;
	lua_Debug d;

	while (lua_getstack (L, i++, &d)) {
		lua_getinfo (L, "nSl", &d);
		g_string_append_printf (s, " [%d]:{%s:%d - %s [%s]};",
				i - 1, d.short_src, d.currentline,
				(d.name ? d.name : "<unknown>"), d.what);
	}
}

gint
rspamd_lua_traceback (lua_State *L)
{

	GString *tb;

	tb = rspamd_lua_get_traceback_string (L);

	lua_pushlightuserdata (L, tb);

	return 1;
}

GString *
rspamd_lua_get_traceback_string (lua_State *L)
{
	GString *tb;
	const gchar *msg = lua_tostring (L, -1);

	tb = g_string_sized_new (100);
	g_string_append_printf (tb, "%s; trace:", msg);

	rspamd_lua_traceback_string (L, tb);

	return tb;
}

guint
rspamd_lua_table_size (lua_State *L, gint tbl_pos)
{
	guint tbl_size = 0;

	if (!lua_istable (L, tbl_pos)) {
		return 0;
	}

#if LUA_VERSION_NUM >= 502
	tbl_size = lua_rawlen (L, tbl_pos);
#else
	tbl_size = lua_objlen (L, tbl_pos);
#endif

	return tbl_size;
}

static void *
rspamd_lua_check_udata_common (lua_State *L, gint pos, const gchar *classname,
		gboolean fatal)
{
	void *p = lua_touserdata (L, pos);
	GString *err_msg;
	guint i, top = lua_gettop (L);

	if (p == NULL) {
		goto err;
	}
	else {
		/* Match class */
		if (lua_getmetatable (L, pos)) {
			luaL_getmetatable (L, classname);

			if (!lua_rawequal (L, -1, -2)) {
				goto err;
			}
		}
		else {
			goto err;
		}
	}

	lua_settop (L, top);

	return p;

err:
	if (fatal) {
		const gchar *actual_classname = NULL;

		if (lua_type (L, pos) == LUA_TUSERDATA && lua_getmetatable (L, pos)) {
			lua_pushstring (L, "__index");
			lua_gettable (L, -2);
			lua_pushstring (L, "class");
			lua_gettable (L, -2);
			actual_classname = lua_tostring (L, -1);
		}
		else {
			actual_classname = lua_typename (L, lua_type (L, pos));
		}

		err_msg = g_string_sized_new (100);
		rspamd_printf_gstring (err_msg, "expected %s at position %d, but userdata has "
										"%s metatable; trace: ",
				classname, pos, actual_classname);
		rspamd_lua_traceback_string (L, err_msg);
		rspamd_printf_gstring (err_msg, " stack(%d): ", top);

		for (i = 1; i <= MIN (top, 10); i ++) {
			if (lua_type (L, i) == LUA_TUSERDATA) {
				const char *clsname;

				if (lua_getmetatable (L, i)) {
					lua_pushstring (L, "__index");
					lua_gettable (L, -2);
					lua_pushstring (L, "class");
					lua_gettable (L, -2);
					clsname = lua_tostring (L, -1);
				}
				else {
					clsname = lua_typename (L, lua_type (L, i));
				}

				rspamd_printf_gstring (err_msg, "[%d: ud=%s] ", i,
						clsname);
			}
			else {
				rspamd_printf_gstring (err_msg, "[%d: %s] ", i,
						lua_typename (L, lua_type (L, i)));
			}
		}

		msg_err ("lua type error: %v", err_msg);
		g_string_free (err_msg, TRUE);
	}

	lua_settop (L, top);

	return NULL;
}

void *
rspamd_lua_check_udata (lua_State *L, gint pos, const gchar *classname)
{
	return rspamd_lua_check_udata_common (L, pos, classname, TRUE);
}

void *
rspamd_lua_check_udata_maybe (lua_State *L, gint pos, const gchar *classname)
{
	return rspamd_lua_check_udata_common (L, pos, classname, FALSE);
}

struct rspamd_async_session*
lua_check_session (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{session}");
	luaL_argcheck (L, ud != NULL, pos, "'session' expected");
	return ud ? *((struct rspamd_async_session **)ud) : NULL;
}

struct event_base*
lua_check_ev_base (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{ev_base}");
	luaL_argcheck (L, ud != NULL, pos, "'event_base' expected");
	return ud ? *((struct event_base **)ud) : NULL;
}

static void rspamd_lua_run_postloads_error (struct thread_entry *thread, int ret, const char *msg);

void
rspamd_lua_run_postloads (lua_State *L, struct rspamd_config *cfg,
		struct event_base *ev_base, struct rspamd_worker *w)
{
	struct rspamd_config_post_load_script *sc;
	struct rspamd_config **pcfg;
	struct event_base **pev_base;
	struct rspamd_worker **pw;

	/* Execute post load scripts */
	LL_FOREACH (cfg->on_load, sc) {
		struct thread_entry *thread = lua_thread_pool_get_for_config (cfg);
		thread->error_callback = rspamd_lua_run_postloads_error;
		L = thread->lua_state;

		lua_rawgeti (L, LUA_REGISTRYINDEX, sc->cbref);
		pcfg = lua_newuserdata (L, sizeof (*pcfg));
		*pcfg = cfg;
		rspamd_lua_setclass (L, "rspamd{config}", -1);

		pev_base = lua_newuserdata (L, sizeof (*pev_base));
		*pev_base = ev_base;
		rspamd_lua_setclass (L, "rspamd{ev_base}", -1);

		pw = lua_newuserdata (L, sizeof (*pw));
		*pw = w;
		rspamd_lua_setclass (L, "rspamd{worker}", -1);

		lua_thread_call (thread, 3);
	}
}


static void
rspamd_lua_run_postloads_error (struct thread_entry *thread, int ret, const char *msg)
{
	struct rspamd_config *cfg = thread->cfg;

	msg_err_config ("error executing post load code: %s", msg);
}


static struct rspamd_worker *
lua_check_worker (lua_State *L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{worker}");
	luaL_argcheck (L, ud != NULL, pos, "'worker' expected");
	return ud ? *((struct rspamd_worker **)ud) : NULL;
}

static gint
lua_worker_get_stat (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		rspamd_mempool_stat_t mem_st;
		struct rspamd_stat *stat, stat_copy;
		ucl_object_t *top, *sub;
		gint i;
		guint64 spam = 0, ham = 0;

		memset (&mem_st, 0, sizeof (mem_st));
		rspamd_mempool_stat (&mem_st);
		memcpy (&stat_copy, w->srv->stat, sizeof (stat_copy));
		stat = &stat_copy;
		top = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_scanned), "scanned", 0, false);
		ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_learned), "learned", 0, false);
		if (stat->messages_scanned > 0) {
			sub = ucl_object_typed_new (UCL_OBJECT);
			for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
				ucl_object_insert_key (sub,
					ucl_object_fromint (stat->actions_stat[i]),
					rspamd_action_to_str (i), 0, false);
				if (i < METRIC_ACTION_GREYLIST) {
					spam += stat->actions_stat[i];
				}
				else {
					ham += stat->actions_stat[i];
				}
			}
			ucl_object_insert_key (top, sub, "actions", 0, false);
		}
		else {
			sub = ucl_object_typed_new (UCL_OBJECT);
			for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
				ucl_object_insert_key (sub,
					0,
					rspamd_action_to_str (i), 0, false);
			}
			ucl_object_insert_key (top, sub, "actions", 0, false);
		}
		ucl_object_insert_key (top, ucl_object_fromint (
			spam), "spam_count", 0, false);
		ucl_object_insert_key (top, ucl_object_fromint (
			ham),  "ham_count",      0, false);
		ucl_object_insert_key (top,
			ucl_object_fromint (stat->connections_count), "connections", 0, false);
		ucl_object_insert_key (top,
			ucl_object_fromint (stat->control_connections_count),
			"control_connections", 0, false);
		ucl_object_insert_key (top,
			ucl_object_fromint (mem_st.pools_allocated), "pools_allocated", 0,
			false);
		ucl_object_insert_key (top,
			ucl_object_fromint (mem_st.pools_freed), "pools_freed", 0, false);
		ucl_object_insert_key (top,
			ucl_object_fromint (mem_st.bytes_allocated), "bytes_allocated", 0,
			false);
		ucl_object_insert_key (top,
			ucl_object_fromint (
			mem_st.chunks_allocated), "chunks_allocated", 0, false);
		ucl_object_insert_key (top,
			ucl_object_fromint (mem_st.shared_chunks_allocated),
			"shared_chunks_allocated", 0, false);
		ucl_object_insert_key (top,
			ucl_object_fromint (mem_st.chunks_freed), "chunks_freed", 0, false);
		ucl_object_insert_key (top,
			ucl_object_fromint (
				mem_st.oversized_chunks), "chunks_oversized", 0, false);

		ucl_object_push_lua (L, top, true);
		ucl_object_unref (top);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_worker_get_name (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushstring (L, g_quark_to_string (w->type));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_worker_get_index (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushinteger (L, w->index);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_worker_get_pid (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushinteger (L, w->pid);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}


static gint
lua_worker_is_scanner (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushboolean (L, rspamd_worker_is_scanner (w));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_worker_is_primary_controller (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);

	if (w) {
		lua_pushboolean (L, rspamd_worker_is_primary_controller (w));
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

struct rspamd_lua_process_cbdata {
	gint sp[2];
	gint func_cbref;
	gint cb_cbref;
	gboolean replied;
	gboolean is_error;
	pid_t cpid;
	lua_State *L;
	guint64 sz;
	GString *io_buf;
	GString *out_buf;
	goffset out_pos;
	struct rspamd_worker *wrk;
	struct event_base *ev_base;
	struct event ev;
};

static void
rspamd_lua_execute_lua_subprocess (lua_State *L,
		struct rspamd_lua_process_cbdata *cbdata)
{
	gint err_idx, r;
	GString *tb;
	guint64 wlen = 0;
	const gchar *ret;
	gsize retlen;

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	lua_rawgeti (L, LUA_REGISTRYINDEX, cbdata->func_cbref);

	if (lua_pcall (L, 0, 1, err_idx) != 0) {
		tb = lua_touserdata (L, -1);
		msg_err ("call to subprocess failed: %v", tb);
		/* Indicate error */
		wlen = (1ULL << 63) + tb->len;
		g_string_free (tb, TRUE);

		r = write (cbdata->sp[1], &wlen, sizeof (wlen));
		if (r == -1) {
			msg_err ("write failed: %s", strerror (errno));
		}

		r = write (cbdata->sp[1], tb->str, tb->len);
		if (r == -1) {
			msg_err ("write failed: %s", strerror (errno));
		}

		lua_pop (L, 1);
	}
	else {
		ret = lua_tolstring (L, -1, &retlen);
		wlen = retlen;

		r = write (cbdata->sp[1], &wlen, sizeof (wlen));
		if (r == -1) {
			msg_err ("write failed: %s", strerror (errno));
		}

		r = write (cbdata->sp[1], ret, retlen);
		if (r == -1) {
			msg_err ("write failed: %s", strerror (errno));
		}
	}

	lua_pop (L, 1); /* Error function */
}

static void
rspamd_lua_call_on_complete (lua_State *L,
		struct rspamd_lua_process_cbdata *cbdata,
		const gchar *err_msg,
		const gchar *data, gsize datalen)
{
	gint err_idx;
	GString *tb;

	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	lua_rawgeti (L, LUA_REGISTRYINDEX, cbdata->cb_cbref);

	if (err_msg) {
		lua_pushstring (L, err_msg);
	}
	else {
		lua_pushnil (L);
	}

	if (data) {
		lua_pushlstring (L, data, datalen);
	}
	else {
		lua_pushnil (L);
	}

	if (lua_pcall (L, 2, 0, err_idx) != 0) {
		tb = lua_touserdata (L, -1);
		msg_err ("call to subprocess callback script failed: %v", tb);
		lua_pop (L, 1);
	}

	lua_pop (L, 1); /* Error function */
}

static gboolean
rspamd_lua_cld_handler (struct rspamd_worker_signal_handler *sigh, void *ud)
{
	struct rspamd_lua_process_cbdata *cbdata = ud;
	struct rspamd_srv_command srv_cmd;
	lua_State *L;
	pid_t died;
	gint res = 0;

	/* Are we called by a correct children ? */
	died = waitpid (cbdata->cpid, &res, WNOHANG);

	if (died <= 0) {
		/* Wait more */
		return TRUE;
	}

	L = cbdata->L;
	msg_info ("handled SIGCHLD from %p", cbdata->cpid);

	if (!cbdata->replied) {
		/* We still need to call on_complete callback */
		rspamd_lua_call_on_complete (cbdata->L, cbdata,
				"Worker has died without reply", NULL, 0);
		event_del (&cbdata->ev);
	}

	/* Free structures */
	close (cbdata->sp[0]);
	luaL_unref (L, LUA_REGISTRYINDEX, cbdata->func_cbref);
	luaL_unref (L, LUA_REGISTRYINDEX, cbdata->cb_cbref);
	g_string_free (cbdata->io_buf, TRUE);

	if (cbdata->out_buf) {
		g_string_free (cbdata->out_buf, TRUE);
	}

	/* Notify main */
	memset (&srv_cmd, 0, sizeof (srv_cmd));
	srv_cmd.type = RSPAMD_SRV_ON_FORK;
	srv_cmd.cmd.on_fork.state = child_dead;
	srv_cmd.cmd.on_fork.cpid = cbdata->cpid;
	srv_cmd.cmd.on_fork.ppid = getpid ();
	rspamd_srv_send_command (cbdata->wrk, cbdata->ev_base, &srv_cmd, -1,
			NULL, NULL);
	g_free (cbdata);

	/* We are done with this SIGCHLD */
	return FALSE;
}

static void
rspamd_lua_subprocess_io (gint fd, short what, gpointer ud)
{
	struct rspamd_lua_process_cbdata *cbdata = ud;
	gssize r;

	if (cbdata->sz == (guint64)-1) {
		guint64 sz;

		/* We read size of reply + flags first */
		r = read (cbdata->sp[0], cbdata->io_buf->str + cbdata->io_buf->len,
				sizeof (guint64) - cbdata->io_buf->len);

		if (r == 0) {
			rspamd_lua_call_on_complete (cbdata->L, cbdata,
					"Unexpected EOF", NULL, 0);
			event_del (&cbdata->ev);
			cbdata->replied = TRUE;
			kill (cbdata->cpid, SIGTERM);

			return;
		}
		else if (r == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				return;
			}
			else {
				rspamd_lua_call_on_complete (cbdata->L, cbdata,
						strerror (errno), NULL, 0);
				event_del (&cbdata->ev);
				cbdata->replied = TRUE;
				kill (cbdata->cpid, SIGTERM);

				return;
			}
		}

		cbdata->io_buf->len += r;

		if (cbdata->io_buf->len == sizeof (guint64)) {
			memcpy ((guchar *)&sz, cbdata->io_buf->str, sizeof (sz));

			if (sz & (1ULL << 63)) {
				cbdata->is_error = TRUE;
				sz &= ~(1ULL << 63);
			}

			cbdata->io_buf->len = 0;
			cbdata->sz = sz;
			g_string_set_size (cbdata->io_buf, sz + 1);
			cbdata->io_buf->len = 0;
		}
	}
	else {
		/* Read data */
		r = read (cbdata->sp[0], cbdata->io_buf->str + cbdata->io_buf->len,
				cbdata->sz - cbdata->io_buf->len);

		if (r == 0) {
			rspamd_lua_call_on_complete (cbdata->L, cbdata,
					"Unexpected EOF", NULL, 0);
			event_del (&cbdata->ev);
			cbdata->replied = TRUE;
			kill (cbdata->cpid, SIGTERM);

			return;
		}
		else if (r == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				return;
			}
			else {
				rspamd_lua_call_on_complete (cbdata->L, cbdata,
						strerror (errno), NULL, 0);
				event_del (&cbdata->ev);
				cbdata->replied = TRUE;
				kill (cbdata->cpid, SIGTERM);

				return;
			}
		}

		cbdata->io_buf->len += r;

		if (cbdata->io_buf->len == cbdata->sz) {
			gchar rep[4];

			/* Finished reading data */
			if (cbdata->is_error) {
				cbdata->io_buf->str[cbdata->io_buf->len] = '\0';
				rspamd_lua_call_on_complete (cbdata->L, cbdata,
						cbdata->io_buf->str, NULL, 0);
			}
			else {
				rspamd_lua_call_on_complete (cbdata->L, cbdata,
						NULL, cbdata->io_buf->str, cbdata->io_buf->len);
			}

			event_del (&cbdata->ev);
			cbdata->replied = TRUE;

			/* Write reply to the child */
			rspamd_socket_blocking (cbdata->sp[0]);
			memset (rep, 0, sizeof (rep));
			(void)write (cbdata->sp[0], rep, sizeof (rep));
		}
	}
}

static gint
lua_worker_spawn_process (lua_State *L)
{
	struct rspamd_worker *w = lua_check_worker (L, 1);
	struct rspamd_lua_process_cbdata *cbdata;
	struct rspamd_abstract_worker_ctx *actx;
	struct rspamd_srv_command srv_cmd;
	const gchar *cmdline = NULL, *input = NULL;
	gsize inputlen = 0;
	pid_t pid;
	GError *err = NULL;
	gint func_cbref, cb_cbref;

	if (!rspamd_lua_parse_table_arguments (L, 2, &err,
		"func=F;exec=S;stdin=V;*on_complete=F", &func_cbref,
			&cmdline, &inputlen, &input, &cb_cbref)) {
		msg_err ("cannot get parameters list: %e", err);

		if (err) {
			g_error_free (err);
		}

		return 0;
	}

	cbdata = g_malloc0 (sizeof (*cbdata));
	cbdata->cb_cbref = cb_cbref;
	cbdata->func_cbref = func_cbref;

	if (input) {
		cbdata->out_buf = g_string_new_len (input, inputlen);
		cbdata->out_pos = 0;
	}

	if (rspamd_socketpair (cbdata->sp, TRUE) == -1) {
		msg_err ("cannot spawn socketpair: %s", strerror (errno));
		g_free (cbdata);
		luaL_unref (L, LUA_REGISTRYINDEX, cbdata->func_cbref);
		luaL_unref (L, LUA_REGISTRYINDEX, cbdata->cb_cbref);

		return 0;
	}

	actx = w->ctx;
	cbdata->wrk = w;
	cbdata->L = L;
	cbdata->ev_base = actx->ev_base;
	cbdata->sz = (guint64)-1;

	pid = fork ();

	if (pid == -1) {
		msg_err ("cannot spawn process: %s", strerror (errno));
		close (cbdata->sp[0]);
		close (cbdata->sp[1]);
		luaL_unref (L, LUA_REGISTRYINDEX, cbdata->func_cbref);
		luaL_unref (L, LUA_REGISTRYINDEX, cbdata->cb_cbref);
		g_free (cbdata);

		return 0;
	}
	else if (pid == 0) {
		/* Child */
		gint rc;
		gchar inbuf[4];

		rspamd_log_update_pid (w->cf->type, w->srv->logger);
		rc = ottery_init (w->srv->cfg->libs_ctx->ottery_cfg);

		if (rc != OTTERY_ERR_NONE) {
			msg_err ("cannot initialize PRNG: %d", rc);
			abort ();
		}
		rspamd_random_seed_fast ();
#ifdef HAVE_EVUTIL_RNG_INIT
		evutil_secure_rng_init ();
#endif

		close (cbdata->sp[0]);
		/* Here we assume that we can block on writing results */
		rspamd_socket_blocking (cbdata->sp[1]);
		event_reinit (cbdata->ev_base);
		g_hash_table_remove_all (w->signal_events);
		rspamd_worker_unblock_signals ();
		rspamd_lua_execute_lua_subprocess (L, cbdata);

		/* Wait for parent to reply and exit */
		rc = read (cbdata->sp[1], inbuf, sizeof (inbuf));

		if (memcmp (inbuf, "\0\0\0\0", 4) == 0) {
			exit (EXIT_SUCCESS);
		}
		else {
			msg_err ("got invalid reply from parent");

			exit (EXIT_FAILURE);
		}

	}

	cbdata->cpid = pid;
	cbdata->io_buf = g_string_sized_new (8);
	/* Notify main */
	memset (&srv_cmd, 0, sizeof (srv_cmd));
	srv_cmd.type = RSPAMD_SRV_ON_FORK;
	srv_cmd.cmd.on_fork.state = child_create;
	srv_cmd.cmd.on_fork.cpid = pid;
	srv_cmd.cmd.on_fork.ppid = getpid ();
	rspamd_srv_send_command (w, cbdata->ev_base, &srv_cmd, -1, NULL, NULL);

	close (cbdata->sp[1]);
	rspamd_socket_nonblocking (cbdata->sp[0]);
	/* Parent */
	rspamd_worker_set_signal_handler (SIGCHLD, w, cbdata->ev_base,
			rspamd_lua_cld_handler,
			cbdata);

	/* Add result pipe waiting */
	event_set (&cbdata->ev, cbdata->sp[0], EV_READ | EV_PERSIST,
			rspamd_lua_subprocess_io, cbdata);
	event_base_set (cbdata->ev_base, &cbdata->ev);
	/* TODO: maybe add timeout? */
	event_add (&cbdata->ev, NULL);

	return 0;
}


struct rspamd_lua_ref_cbdata {
	lua_State *L;
	gint cbref;
};

static void
rspamd_lua_ref_dtor (gpointer p)
{
	struct rspamd_lua_ref_cbdata *cbdata = p;

	luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref);
}

void
rspamd_lua_add_ref_dtor (lua_State *L, rspamd_mempool_t *pool,
		gint ref)
{
	struct rspamd_lua_ref_cbdata *cbdata;

	if (ref != -1) {
		cbdata = rspamd_mempool_alloc (pool, sizeof (*cbdata));
		cbdata->cbref = ref;
		cbdata->L = L;

		rspamd_mempool_add_destructor (pool, rspamd_lua_ref_dtor, cbdata);
	}
}

gboolean
rspamd_lua_require_function (lua_State *L, const gchar *modname,
		const gchar *funcname)
{
	gint table_pos;

	lua_getglobal (L, "require");

	if (lua_isnil (L, -1)) {
		lua_pop (L, 1);

		return FALSE;
	}

	lua_pushstring (L, modname);

	/* Now try to call */
	if (lua_pcall (L, 1, 1, 0) != 0) {
		lua_pop (L, 1);

		return FALSE;
	}

	/* Now we should have a table with results */
	if (!lua_istable (L, -1)) {
		lua_pop (L, 1);

		return FALSE;
	}

	table_pos = lua_gettop (L);
	lua_pushstring (L, funcname);
	lua_gettable (L, -2);

	if (lua_type (L, -1) == LUA_TFUNCTION) {
		/* Remove table, preserve just a function */
		lua_remove (L, table_pos);

		return TRUE;
	}

	lua_pop (L, 2);

	return FALSE;
}


gboolean
rspamd_lua_try_load_redis (lua_State *L, const ucl_object_t *obj,
									struct rspamd_config *cfg, gint *ref_id)
{
	gint res_pos, err_idx;
	struct rspamd_config **pcfg;

	/* Create results table */
	lua_createtable (L, 0, 0);
	res_pos = lua_gettop (L);
	lua_pushcfunction (L, &rspamd_lua_traceback);
	err_idx = lua_gettop (L);

	/* Obtain function */
	if (!rspamd_lua_require_function (L, "lua_redis", "try_load_redis_servers")) {
		msg_err_config ("cannot require lua_redis");
		lua_pop (L, 2);

		return FALSE;
	}

	/* Function arguments */
	ucl_object_push_lua (L, obj, false);
	pcfg = lua_newuserdata (L, sizeof (*pcfg));
	rspamd_lua_setclass (L, "rspamd{config}", -1);
	*pcfg = cfg;
	lua_pushvalue (L, res_pos);

	if (lua_pcall (L, 3, 1, err_idx) != 0) {
		GString *tb;

		tb = lua_touserdata (L, -1);
		msg_err_config ("cannot call lua try_load_redis_servers script: %s", tb->str);
		g_string_free (tb, TRUE);
		lua_settop (L, 0);

		return FALSE;
	}

	if (lua_toboolean (L, -1)) {
		if (ref_id) {
			/* Ref table */
			lua_pushvalue (L, res_pos);
			*ref_id = luaL_ref (L, LUA_REGISTRYINDEX);
			lua_settop (L, 0);
		}
		else {
			/* Leave it on the stack */
			lua_settop (L, res_pos);
		}

		return TRUE;
	}
	else {
		lua_settop (L, 0);
	}

	return FALSE;
}

void
rspamd_lua_push_full_word (lua_State *L, rspamd_stat_token_t *w)
{
	gint fl_cnt;

	lua_createtable (L, 4, 0);

	if (w->stemmed.len > 0) {
		lua_pushlstring (L, w->stemmed.begin, w->stemmed.len);
		lua_rawseti (L, -2, 1);
	}
	else {
		lua_pushstring (L, "");
		lua_rawseti (L, -2, 1);
	}

	if (w->normalized.len > 0) {
		lua_pushlstring (L, w->normalized.begin, w->normalized.len);
		lua_rawseti (L, -2, 2);
	}
	else {
		lua_pushstring (L, "");
		lua_rawseti (L, -2, 2);
	}

	if (w->original.len > 0) {
		lua_pushlstring (L, w->original.begin, w->original.len);
		lua_rawseti (L, -2, 3);
	}
	else {
		lua_pushstring (L, "");
		lua_rawseti (L, -2, 3);
	}

	/* Flags part */
	fl_cnt = 1;
	lua_createtable (L, 4, 0);

	if (w->flags & RSPAMD_STAT_TOKEN_FLAG_NORMALISED) {
		lua_pushstring (L, "normalised");
		lua_rawseti (L, -2, fl_cnt ++);
	}
	if (w->flags & RSPAMD_STAT_TOKEN_FLAG_BROKEN_UNICODE) {
		lua_pushstring (L, "broken_unicode");
		lua_rawseti (L, -2, fl_cnt ++);
	}
	if (w->flags & RSPAMD_STAT_TOKEN_FLAG_UTF) {
		lua_pushstring (L, "utf");
		lua_rawseti (L, -2, fl_cnt ++);
	}
	if (w->flags & RSPAMD_STAT_TOKEN_FLAG_TEXT) {
		lua_pushstring (L, "text");
		lua_rawseti (L, -2, fl_cnt ++);
	}
	if (w->flags & RSPAMD_STAT_TOKEN_FLAG_HEADER) {
		lua_pushstring (L, "header");
		lua_rawseti (L, -2, fl_cnt ++);
	}
	if (w->flags & (RSPAMD_STAT_TOKEN_FLAG_META|RSPAMD_STAT_TOKEN_FLAG_LUA_META)) {
		lua_pushstring (L, "meta");
		lua_rawseti (L, -2, fl_cnt ++);
	}
	if (w->flags & RSPAMD_STAT_TOKEN_FLAG_STOP_WORD) {
		lua_pushstring (L, "stop_word");
		lua_rawseti (L, -2, fl_cnt ++);
	}
	if (w->flags & RSPAMD_STAT_TOKEN_FLAG_INVISIBLE_SPACES) {
		lua_pushstring (L, "invisible_spaces");
		lua_rawseti (L, -2, fl_cnt ++);
	}
	if (w->flags & RSPAMD_STAT_TOKEN_FLAG_STEMMED) {
		lua_pushstring (L, "stemmed");
		lua_rawseti (L, -2, fl_cnt ++);
	}

	lua_rawseti (L, -2, 4);
}

gint
rspamd_lua_push_words (lua_State *L, GArray *words,
							enum rspamd_lua_words_type how)
{
	rspamd_stat_token_t *w;
	guint i, cnt;

	lua_createtable (L, words->len, 0);

	for (i = 0, cnt = 1; i < words->len; i ++) {
		w = &g_array_index (words, rspamd_stat_token_t, i);

		switch (how) {
		case RSPAMD_LUA_WORDS_STEM:
			if (w->stemmed.len > 0) {
				lua_pushlstring (L, w->stemmed.begin, w->stemmed.len);
				lua_rawseti (L, -2, cnt ++);
			}
			break;
		case RSPAMD_LUA_WORDS_NORM:
			if (w->normalized.len > 0) {
				lua_pushlstring (L, w->normalized.begin, w->normalized.len);
				lua_rawseti (L, -2, cnt ++);
			}
			break;
		case RSPAMD_LUA_WORDS_RAW:
			if (w->original.len > 0) {
				lua_pushlstring (L, w->original.begin, w->original.len);
				lua_rawseti (L, -2, cnt ++);
			}
			break;
		case RSPAMD_LUA_WORDS_FULL:
			rspamd_lua_push_full_word (L, w);
			/* Push to the resulting vector */
			lua_rawseti (L, -2, cnt ++);
			break;
		}
	}

	return 1;
}