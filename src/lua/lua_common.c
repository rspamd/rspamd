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
#include <math.h>

/* Lua module init function */
#define MODULE_INIT_FUNC "module_init"

const luaL_reg null_reg[] = {
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};


LUA_FUNCTION_DEF (worker, get_name);
LUA_FUNCTION_DEF (worker, get_stat);
LUA_FUNCTION_DEF (worker, get_index);
LUA_FUNCTION_DEF (worker, get_pid);

const luaL_reg worker_reg[] = {
	LUA_INTERFACE_DEF (worker, get_name),
	LUA_INTERFACE_DEF (worker, get_stat),
	LUA_INTERFACE_DEF (worker, get_index),
	LUA_INTERFACE_DEF (worker, get_pid),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

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

void
rspamd_lua_set_path (lua_State *L, struct rspamd_config *cfg, GHashTable *vars)
{
	const gchar *old_path, *additional_path = NULL;
	const ucl_object_t *opts;
	const gchar *pluginsdir = RSPAMD_PLUGINSDIR,
			*rulesdir = RSPAMD_RULESDIR,
			*lualibdir = RSPAMD_LUALIBDIR;

	gchar path_buf[PATH_MAX];

	lua_getglobal (L, "package");
	lua_getfield (L, -1, "path");
	old_path = luaL_checkstring (L, -1);

	if (strstr (old_path, RSPAMD_PLUGINSDIR) != NULL) {
		/* Path has been already set, do not touch it */
		lua_pop (L, 2);
		return;
	}

	if (cfg) {
		opts = ucl_object_lookup (cfg->rcl_obj, "options");
		if (opts != NULL) {
			opts = ucl_object_lookup (opts, "lua_path");
			if (opts != NULL && ucl_object_type (opts) == UCL_STRING) {
				additional_path = ucl_object_tostring (opts);
			}
		}
	}

	if (vars) {
		gchar *t;

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
	}

	if (additional_path) {
		rspamd_snprintf (path_buf, sizeof (path_buf),
				"%s/lua/?.lua;%s/lua/?.lua;%s/?.lua;%s/?.lua;%s/?.so;%s;%s",
				pluginsdir, RSPAMD_CONFDIR, rulesdir,
				lualibdir, lualibdir,
				additional_path, old_path);
	}
	else {
		rspamd_snprintf (path_buf, sizeof (path_buf),
				"%s/lua/?.lua;%s/lua/?.lua;%s/?.lua;%s/?.lua;%s/?.so;%s",
				pluginsdir, RSPAMD_CONFDIR, rulesdir,
				lualibdir, lualibdir,
				old_path);
	}

	lua_pop (L, 1);
	lua_pushstring (L, path_buf);
	lua_setfield (L, -2, "path");
	lua_pop (L, 1);
}

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
	luaopen_lpeg (L);

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
	rspamd_lua_add_preload (L, "ucl", luaopen_ucl);

	/* Add plugins global */
	lua_newtable (L);
	lua_setglobal (L, "rspamd_plugins");

	return L;
}

/**
 * Initialize new locked lua_State structure
 */
struct lua_locked_state *
rspamd_init_lua_locked (struct rspamd_config *cfg)
{
	struct lua_locked_state *new;

	new = g_slice_alloc (sizeof (struct lua_locked_state));
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

	g_slice_free1 (sizeof (struct lua_locked_state), st);
}

gboolean
rspamd_init_lua_filters (struct rspamd_config *cfg, gboolean force_load,
		GHashTable *vars)
{
	struct rspamd_config **pcfg;
	GList *cur;
	struct script_module *module;
	lua_State *L = cfg->lua_state;
	GString *tb;
	gint err_idx;

	rspamd_lua_set_path (L, cfg, vars);
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
				cur = g_list_next (cur);
				lua_pop (L, 1); /*  Error function */
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
				cur = g_list_next (cur);
				g_string_free (tb, TRUE);
				lua_pop (L, 2); /* Result and error function */
				continue;
			}

			if (!force_load) {
				msg_info_config ("init lua module %s", module->name);
			}

			lua_pop (L, 1); /* Error function */
		}
		cur = g_list_next (cur);
	}

	/* Assign state */
	cfg->lua_state = L;

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
	const gchar *msg = lua_tostring (L, 1);

	tb = g_string_sized_new (100);
	g_string_append_printf (tb, "%s; trace:", msg);
	rspamd_lua_traceback_string (L, tb);
	lua_pushlightuserdata (L, tb);

	return 1;
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

	if (p == NULL) {
		if (fatal) {
			err_msg = g_string_sized_new (100);
			rspamd_printf_gstring (err_msg, "expected %s at %d, but got %s; trace: ",
					classname, pos, lua_typename (L, lua_type (L, pos)));
			rspamd_lua_traceback_string (L, err_msg);
			msg_err ("lua typecheck error: %v", err_msg);
			g_string_free (err_msg, TRUE);
		}

		return NULL;
	}
	else {
		/* Match class */
		if (lua_getmetatable (L, pos)) {
			luaL_getmetatable (L, classname);

			if (!lua_rawequal (L, -1, -2)) {
				p = NULL;
				lua_pushstring (L, "__index");
				lua_gettable (L, -3);
				lua_pushstring (L, "class");
				lua_gettable (L, -2);

				if (fatal) {
					err_msg = g_string_sized_new (100);
					rspamd_printf_gstring (err_msg, "expected %s at %d, but userdata has "
							"classname: %s; trace: ",
							classname, pos, lua_tostring (L, -1));
					rspamd_lua_traceback_string (L, err_msg);
					msg_err ("lua typecheck error: %v", err_msg);
					g_string_free (err_msg, TRUE);
				}

				lua_pop (L, 2); /* __index -> classname */
			}

			lua_pop (L, 2);
		}
		else {
			p = NULL;

			if (fatal) {
				err_msg = g_string_sized_new (100);
				rspamd_printf_gstring (err_msg, "expected %s at %d, but userdata has "
						"no metatable; trace: ",
						classname, pos);
				rspamd_lua_traceback_string (L, err_msg);
				msg_err ("lua typecheck error: %v", err_msg);
				g_string_free (err_msg, TRUE);
			}
		}
	}

	return p;
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

gboolean
rspamd_lua_run_postloads (lua_State *L, struct rspamd_config *cfg,
		struct event_base *ev_base, struct rspamd_worker *w)
{
	struct rspamd_config_post_load_script *sc;
	struct rspamd_config **pcfg;
	struct event_base **pev_base;
	struct rspamd_worker **pw;

	/* Execute post load scripts */
	LL_FOREACH (cfg->on_load, sc) {
		lua_rawgeti (cfg->lua_state, LUA_REGISTRYINDEX, sc->cbref);
		pcfg = lua_newuserdata (cfg->lua_state, sizeof (*pcfg));
		*pcfg = cfg;
		rspamd_lua_setclass (cfg->lua_state, "rspamd{config}", -1);

		pev_base = lua_newuserdata (cfg->lua_state, sizeof (*pev_base));
		*pev_base = ev_base;
		rspamd_lua_setclass (cfg->lua_state, "rspamd{ev_base}", -1);

		pw = lua_newuserdata (cfg->lua_state, sizeof (*pw));
		*pw = w;
		rspamd_lua_setclass (cfg->lua_state, "rspamd{worker}", -1);

		if (lua_pcall (cfg->lua_state, 3, 0, 0) != 0) {
			msg_err_config ("error executing post load code: %s",
					lua_tostring (cfg->lua_state, -1));
			lua_pop (cfg->lua_state, 1);

			return FALSE;
		}
	}

	return TRUE;
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
		lua_pushnumber (L, w->index);
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
		lua_pushnumber (L, w->pid);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
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
