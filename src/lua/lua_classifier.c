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


static const struct luaL_reg    statfilelib_m[] = {
	{"__tostring", lua_class_tostring},
	{NULL, NULL}
};

struct classifier_callback_data {
	lua_State *L;
	const char *name;
};

static struct statfile* lua_check_statfile (lua_State * L);

/* Classifier implementation */


static struct classifier_config      *
lua_check_classifier (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{classifier}");
	luaL_argcheck (L, ud != NULL, 1, "'classifier' expected");
	return *((struct classifier_config **)ud);
}

/* Return list of statfiles that should be checked for this message */
GList *
call_classifier_pre_callbacks (struct classifier_config *ccf, struct worker_task *task)
{
	GList                          *res = NULL, *cur;
	struct classifier_callback_data *cd;
	struct classifier_config      **pccf;
	struct worker_task            **ptask;
	struct statfile                *st;
	int                             i, len;

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

		if (lua_pcall (cd->L, 2, 1, 0) != 0) {
			msg_warn ("call_classifier_pre_callbacks: error running function %s: %s", cd->name, lua_tostring (cd->L, -1));
		}
		else {
			if (lua_istable (cd->L, 1)) {
				len = lua_objlen (cd->L, 1);
				for (i = 1; i <= len; i ++) {
					lua_rawgeti (cd->L, 1, i);
					st = lua_check_statfile (cd->L);
					if (st) {
						res = g_list_prepend (res, st);
					}
				}
			}
		}

		cur = g_list_next (cur);
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
			msg_warn ("call_classifier_pre_callbacks: error running function %s: %s", cd->name, lua_tostring (cd->L, -1));
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

static int
lua_classifier_register_pre_callback (lua_State *L)
{
	struct classifier_config       *ccf = lua_check_classifier (L);
	struct classifier_callback_data *cd;
	const char                     *name;

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

static int
lua_classifier_register_post_callback (lua_State *L)
{
	struct classifier_config       *ccf = lua_check_classifier (L);
	struct classifier_callback_data *cd;
	const char                     *name;

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
static int
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
static struct statfile      *
lua_check_statfile (lua_State * L)
{
	void                           *ud = luaL_checkudata (L, 1, "rspamd{statfile}");
	luaL_argcheck (L, ud != NULL, 1, "'statfile' expected");
	return *((struct statfile **)ud);
}


/* Open functions */

int
luaopen_classifier (lua_State * L)
{
	lua_newclass (L, "rspamd{classifier}", classifierlib_m);
	luaL_openlib (L, "rspamd_classifier", null_reg, 0);

	return 1;
}

int
luaopen_statfile (lua_State * L)
{
	lua_newclass (L, "rspamd{statfile}", statfilelib_m);
	luaL_openlib (L, "rspamd_statfile", null_reg, 0);

	return 1;
}

