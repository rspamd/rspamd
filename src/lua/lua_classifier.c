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

/* Classifier methods */
LUA_FUNCTION_DEF (classifier, get_statfiles);
LUA_FUNCTION_DEF (classifier, get_statfile_by_label);
LUA_FUNCTION_DEF (classifier, get_param);

static const struct luaL_reg classifierlib_m[] = {
	LUA_INTERFACE_DEF (classifier, get_statfiles),
	LUA_INTERFACE_DEF (classifier, get_param),
	LUA_INTERFACE_DEF (classifier, get_statfile_by_label),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

LUA_FUNCTION_DEF (statfile, get_symbol);
LUA_FUNCTION_DEF (statfile, get_label);
LUA_FUNCTION_DEF (statfile, is_spam);
LUA_FUNCTION_DEF (statfile, get_param);

static const struct luaL_reg statfilelib_m[] = {
	LUA_INTERFACE_DEF (statfile, get_symbol),
	LUA_INTERFACE_DEF (statfile, get_label),
	LUA_INTERFACE_DEF (statfile, is_spam),
	LUA_INTERFACE_DEF (statfile, get_param),
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static struct rspamd_statfile_config * lua_check_statfile (lua_State * L);

/* Classifier implementation */


static struct rspamd_classifier_config *
lua_check_classifier (lua_State * L)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{classifier}");
	luaL_argcheck (L, ud != NULL, 1, "'classifier' expected");
	return ud ? *((struct rspamd_classifier_config **)ud) : NULL;
}

/* Return table of statfiles indexed by name */
static gint
lua_classifier_get_statfiles (lua_State *L)
{
	struct rspamd_classifier_config *ccf = lua_check_classifier (L);
	GList *cur;
	struct rspamd_statfile_config *st, **pst;
	gint i;

	if (ccf) {
		lua_newtable (L);
		cur = g_list_first (ccf->statfiles);
		i = 1;
		while (cur) {
			st = cur->data;
			pst = lua_newuserdata (L, sizeof (struct rspamd_statfile_config *));
			rspamd_lua_setclass (L, "rspamd{statfile}", -1);
			*pst = st;
			lua_rawseti (L, -2, i++);

			cur = g_list_next (cur);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_classifier_get_param (lua_State *L)
{
	struct rspamd_classifier_config *ccf = lua_check_classifier (L);
	const gchar *param;
	const ucl_object_t *value;

	param = luaL_checkstring (L, 2);

	if (ccf != NULL && param != NULL) {
		value = ucl_object_lookup (ccf->opts, param);

		if (value != NULL) {
			ucl_object_push_lua (L, value, true);
			return 1;
		}
	}

	lua_pushnil (L);

	return 1;
}

/* Get statfile with specified label */
static gint
lua_classifier_get_statfile_by_label (lua_State *L)
{
	struct rspamd_classifier_config *ccf = lua_check_classifier (L);
	struct rspamd_statfile_config *st, **pst;
	const gchar *label;
	GList *cur;
	gint i;

	label = luaL_checkstring (L, 2);
	if (ccf && label) {
		cur = g_hash_table_lookup (ccf->labels, label);
		if (cur) {
			lua_newtable (L);
			i = 1;
			while (cur) {
				st = cur->data;
				pst =
					lua_newuserdata (L,
						sizeof (struct rspamd_statfile_config *));
				rspamd_lua_setclass (L, "rspamd{statfile}", -1);
				*pst = st;
				lua_rawseti (L, -2, i++);
				cur = g_list_next (cur);
			}
			return 1;
		}
	}
	lua_pushnil (L);
	return 1;
}

/* Statfile functions */
static gint
lua_statfile_get_symbol (lua_State *L)
{
	struct rspamd_statfile_config *st = lua_check_statfile (L);

	if (st != NULL) {
		lua_pushstring (L, st->symbol);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_statfile_get_label (lua_State *L)
{
	struct rspamd_statfile_config *st = lua_check_statfile (L);

	if (st != NULL && st->label != NULL) {
		lua_pushstring (L, st->label);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_statfile_is_spam (lua_State *L)
{
	struct rspamd_statfile_config *st = lua_check_statfile (L);

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
	struct rspamd_statfile_config *st = lua_check_statfile (L);
	const gchar *param;
	const ucl_object_t *value;

	param = luaL_checkstring (L, 2);

	if (st != NULL && param != NULL) {
		value = ucl_object_lookup (st->opts, param);
		if (value != NULL) {
			lua_pushstring (L, ucl_object_tostring_forced (value));
			return 1;
		}
	}
	lua_pushnil (L);

	return 1;
}

static struct rspamd_statfile_config *
lua_check_statfile (lua_State * L)
{
	void *ud = rspamd_lua_check_udata (L, 1, "rspamd{statfile}");
	luaL_argcheck (L, ud != NULL, 1, "'statfile' expected");
	return ud ? *((struct rspamd_statfile_config **)ud) : NULL;
}


/* Open functions */

void
luaopen_classifier (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{classifier}", classifierlib_m);
	lua_pop (L, 1);                      /* remove metatable from stack */
}

void
luaopen_statfile (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{statfile}", statfilelib_m);
	lua_pop (L, 1);                      /* remove metatable from stack */
}

