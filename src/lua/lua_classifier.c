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
#include "../cfg_file.h"
#include "../classifiers/classifiers.h"

/* Classifier methods */
LUA_FUNCTION_DEF (classifier, register_pre_callback);
LUA_FUNCTION_DEF (classifier, register_post_callback);
LUA_FUNCTION_DEF (classifier, get_statfiles);

static const struct luaL_reg    classifierlib_m[] = {
	LUA_INTERFACE_DEF (classifier, register_pre_callback),
	LUA_INTERFACE_DEF (classifier, register_post_callback),
	LUA_INTERFACE_DEF (classifier, get_statfiles),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};


LUA_FUNCTION_DEF (statfile, get_symbol);
LUA_FUNCTION_DEF (statfile, get_path);
LUA_FUNCTION_DEF (statfile, get_size);
LUA_FUNCTION_DEF (statfile, is_spam);
LUA_FUNCTION_DEF (statfile, get_param);

static const struct luaL_reg    statfilelib_m[] = {
	LUA_INTERFACE_DEF (statfile, get_symbol),
	LUA_INTERFACE_DEF (statfile, get_path),
	LUA_INTERFACE_DEF (statfile, get_size),
	LUA_INTERFACE_DEF (statfile, is_spam),
	LUA_INTERFACE_DEF (statfile, get_param),
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

struct classifier_callback_data {
	lua_State *L;
	const gchar *name;
};

static struct statfile* lua_check_statfile (lua_State * L);

/* Classifier implementation */


static struct classifier_config      *
lua_check_classifier (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{classifier}");
	luaL_argcheck (L, ud != NULL, 1, "'classifier' expected");
	return ud ? *((struct classifier_config **)ud) : NULL;
}

static GList *
call_classifier_pre_callback (struct classifier_config *ccf, struct worker_task *task,
		lua_State *L, gboolean is_learn, gboolean is_spam)
{
	struct classifier_config      **pccf;
	struct worker_task            **ptask;
	struct statfile               **pst;
	GList                          *res = NULL;

	pccf = lua_newuserdata (L, sizeof (struct classifier_config *));
	lua_setclass (L, "rspamd{classifier}", -1);
	*pccf = ccf;

	ptask = lua_newuserdata (L, sizeof (struct worker_task *));
	lua_setclass (L, "rspamd{task}", -1);
	*ptask = task;

	lua_pushboolean (L, is_learn);
	lua_pushboolean (L, is_spam);

	if (lua_pcall (L, 4, 1, 0) != 0) {
		msg_warn ("error running pre classifier callback %s", lua_tostring (L, -1));
	}
	else {
		if (lua_istable (L, -1)) {
			lua_pushnil (L);
			while(lua_next (L, -2)) {
				pst = luaL_checkudata (L, -1, "rspamd{statfile}");
				if (pst) {
					res = g_list_prepend (res, *pst);
				}
				lua_pop (L, 1);
			}
			lua_pop (L, 1);
		}
	}

	return res;
}

/* Return list of statfiles that should be checked for this message */
GList *
call_classifier_pre_callbacks (struct classifier_config *ccf, struct worker_task *task,
		gboolean is_learn, gboolean is_spam)
{
	GList                           *res = NULL, *cur;
	struct classifier_callback_data *cd;
	lua_State                       *L;


	/* Go throught all callbacks and call them, appending results to list */
	cur = g_list_first (ccf->pre_callbacks);
	while (cur) {
		cd = cur->data;
		lua_getglobal (cd->L, cd->name);

		res = g_list_concat (res, call_classifier_pre_callback (ccf, task, cd->L, is_learn, is_spam));

		cur = g_list_next (cur);
	}
	
	if (res == NULL) {
		L = task->cfg->lua_state;
		/* Check function from global table 'classifiers' */
		lua_getglobal (L, "classifiers");
		if (lua_istable (L, -1)) {
			lua_pushstring (L, ccf->classifier->name);
			lua_gettable (L, -2);
			/* Function is now on top */
			if (lua_isfunction (L, -1)) {
				res = call_classifier_pre_callback (ccf, task, L, is_learn, is_spam);
			}
		}
	}

	return res;
}

/* Return result mark for statfile */
double
call_classifier_post_callbacks (struct classifier_config *ccf, struct worker_task *task, double in)
{
	struct classifier_callback_data *cd;
	struct classifier_config      **pccf;
	struct worker_task            **ptask;
	double                          out = in;
	GList                          *cur;

	/* Go throught all callbacks and call them, appending results to list */
	cur = g_list_first (ccf->pre_callbacks);
	while (cur) {
		cd = cur->data;
		lua_getglobal (cd->L, cd->name);

		pccf = lua_newuserdata (cd->L, sizeof (struct classifier_config *));
		lua_setclass (cd->L, "rspamd{classifier}", -1);
		*pccf = ccf;

		ptask = lua_newuserdata (cd->L, sizeof (struct worker_task *));
		lua_setclass (cd->L, "rspamd{task}", -1);
		*ptask = task;

		lua_pushnumber (cd->L, out);

		if (lua_pcall (cd->L, 3, 1, 0) != 0) {
			msg_warn ("error running function %s: %s", cd->name, lua_tostring (cd->L, -1));
		}
		else {
			if (lua_isnumber (cd->L, 1)) {
				out = lua_tonumber (cd->L, 1);
			}
		}

		cur = g_list_next (cur);
	}

	return out;

}

static gint
lua_classifier_register_pre_callback (lua_State *L)
{
	struct classifier_config       *ccf = lua_check_classifier (L);
	struct classifier_callback_data *cd;
	const gchar                     *name;

	if (ccf) {
		name = luaL_checkstring (L, 2);
		if (name) {
			cd = g_malloc (sizeof (struct classifier_callback_data));
			cd->name = g_strdup (name);
			cd->L = L;
			ccf->pre_callbacks = g_list_prepend (ccf->pre_callbacks, cd);
		}
	}

	return 0;

}

static gint
lua_classifier_register_post_callback (lua_State *L)
{
	struct classifier_config       *ccf = lua_check_classifier (L);
	struct classifier_callback_data *cd;
	const gchar                     *name;

	if (ccf) {
		name = luaL_checkstring (L, 2);
		if (name) {
			cd = g_malloc (sizeof (struct classifier_callback_data));
			cd->name = g_strdup (name);
			cd->L = L;
			ccf->pre_callbacks = g_list_prepend (ccf->pre_callbacks, cd);
		}
	}

	return 0;
}

/* Return table of statfiles indexed by theirs name */
static gint
lua_classifier_get_statfiles (lua_State *L)
{
	struct classifier_config       *ccf = lua_check_classifier (L);
	GList                          *cur;
	struct statfile                *st, **pst;

	if (ccf) {
		lua_newtable (L);
		cur = g_list_first (ccf->statfiles);
		while (cur) {
			st = cur->data;
			/* t['statfile_name'] = statfile */
			lua_pushstring (L, st->symbol);
			pst = lua_newuserdata (L, sizeof (struct statfile *));
			lua_setclass (L, "rspamd{statfile}", -1);
			*pst = st;

			lua_settable (L, -3);

			cur = g_list_next (cur);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

/* Statfile functions */
static gint
lua_statfile_get_symbol (lua_State *L)
{
	struct statfile                *st = lua_check_statfile (L);

	if (st != NULL) {
		lua_pushstring (L, st->symbol);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_statfile_get_path (lua_State *L)
{
	struct statfile                *st = lua_check_statfile (L);

	if (st != NULL) {
		lua_pushstring (L, st->path);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_statfile_get_size (lua_State *L)
{
	struct statfile                *st = lua_check_statfile (L);

	if (st != NULL) {
		lua_pushinteger (L, st->size);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_statfile_is_spam (lua_State *L)
{
	struct statfile                *st = lua_check_statfile (L);

	if (st != NULL) {
		lua_pushboolean (L, st->is_spam);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_statfile_get_param (lua_State *L)
{
	struct statfile                *st = lua_check_statfile (L);
	const gchar                    *param, *value;

	param = luaL_checkstring (L, 2);

	if (st != NULL && param != NULL) {
		value = g_hash_table_lookup (st->opts, param);
		if (param != NULL) {
			lua_pushstring (L, value);
			return 1;
		}
	}
	lua_pushnil (L);

	return 1;
}

static struct statfile      *
lua_check_statfile (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{statfile}");
	luaL_argcheck (L, ud != NULL, 1, "'statfile' expected");
	return ud ? *((struct statfile **)ud) : NULL;
}


/* Open functions */

gint
luaopen_classifier (lua_State * L)
{
	lua_newclass (L, "rspamd{classifier}", classifierlib_m);
	luaL_openlib (L, "rspamd_classifier", null_reg, 0);

	return 1;
}

gint
luaopen_statfile (lua_State * L)
{
	lua_newclass (L, "rspamd{statfile}", statfilelib_m);
	luaL_openlib (L, "rspamd_statfile", null_reg, 0);

	return 1;
}

