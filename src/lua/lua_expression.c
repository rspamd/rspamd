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
#include "expression.h"

/***
 * @module rspamd_expression
 * This module can be used to implement different logic expressions in lua using
 * rspamd AST optimizer. There are some examples in individual methods definitions to help understanding of this module.
 */

/***
 * @function rspamd_expression.create(line, {parse_func, [process_func]}, pool)
 * Create expression from the line using atom parsing routines and the specified memory pool
 * @param {string} line expression line
 * @param {table} atom_functions parse_atom function and optional process_atom function
 * @param {rspamd_mempool} memory pool to use for this function
 * @return {expr, err} expression object and error message of `expr` is nil
 * @example
require "fun" ()
local rspamd_expression = require "rspamd_expression"
local rspamd_mempool = require "rspamd_mempool"

local function parse_func(str)
	-- extract token till the first space character
	local token = table.concat(totable(take_while(function(s) return s ~= ' ' end, iter(str))))
	-- Return token name
	return token
end

local function process_func(token)
	-- Do something using token and task
end

local pool = rspamd_mempool.create()
local expr,err = rspamd_expression.create('A & B | !C', {parse_func, process_func}, pool)
-- Expression is destroyed when the corresponding pool is destroyed
pool:destroy()
 */
LUA_FUNCTION_DEF (expr, create);

/***
 * @method rspamd_expression:to_string()
 * Converts rspamd expression to string
 * @return {string} string representation of rspamd expression
 */
LUA_FUNCTION_DEF (expr, to_string);

/***
 * @method rspamd_expression:process([callback, ]input[, flags])
 * Executes the expression and pass input to process atom callbacks
 * @param {function} callback if not specified on process, then callback must be here
 * @param {any} input input data for processing callbacks
 * @return {number} result of the expression evaluation
 */
LUA_FUNCTION_DEF (expr, process);

/***
 * @method rspamd_expression:process_traced([callback, ]input[, flags])
 * Executes the expression and pass input to process atom callbacks. This function also saves the full trace
 * @param {function} callback if not specified on process, then callback must be here
 * @param {any} input input data for processing callbacks
 * @return {number, table of matched atoms} result of the expression evaluation
 */
LUA_FUNCTION_DEF (expr, process_traced);

/***
 * @method rspamd_expression:atoms()
 * Extract all atoms from the expression as table of strings
 * @return {table/strings} list of all atoms in the expression
 */
LUA_FUNCTION_DEF (expr, atoms);

static const struct luaL_reg exprlib_m[] = {
	LUA_INTERFACE_DEF (expr, to_string),
	LUA_INTERFACE_DEF (expr, atoms),
	LUA_INTERFACE_DEF (expr, process),
	LUA_INTERFACE_DEF (expr, process_traced),
	{"__tostring", lua_expr_to_string},
	{NULL, NULL}
};

static const struct luaL_reg exprlib_f[] = {
	LUA_INTERFACE_DEF (expr, create),
	{NULL, NULL}
};

static rspamd_expression_atom_t * lua_atom_parse (const gchar *line, gsize len,
			rspamd_mempool_t *pool, gpointer ud, GError **err);
static gdouble lua_atom_process (gpointer runtime_ud, rspamd_expression_atom_t *atom);

static const struct rspamd_atom_subr lua_atom_subr = {
	.parse = lua_atom_parse,
	.process = lua_atom_process,
	.priority = NULL,
	.destroy = NULL
};

struct lua_expression {
	struct rspamd_expression *expr;
	gint parse_idx;
	gint process_idx;
	lua_State *L;
	rspamd_mempool_t *pool;
};

static GQuark
lua_expr_quark (void)
{
	return g_quark_from_static_string ("lua-expression");
}

struct lua_expression *
rspamd_lua_expression (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{expr}");
	luaL_argcheck (L, ud != NULL, pos, "'expr' expected");
	return ud ? *((struct lua_expression **)ud) : NULL;
}

static void
lua_expr_dtor (gpointer p)
{
	struct lua_expression *e = (struct lua_expression *)p;

	if (e->parse_idx != -1) {
		luaL_unref (e->L, LUA_REGISTRYINDEX, e->parse_idx);
	}

	if (e->process_idx != -1) {
		luaL_unref (e->L, LUA_REGISTRYINDEX, e->process_idx);
	}
}

static rspamd_expression_atom_t *
lua_atom_parse (const gchar *line, gsize len,
			rspamd_mempool_t *pool, gpointer ud, GError **err)
{
	struct lua_expression *e = (struct lua_expression *)ud;
	rspamd_expression_atom_t *atom;
	gsize rlen;
	const gchar *tok;

	lua_rawgeti (e->L, LUA_REGISTRYINDEX, e->parse_idx);
	lua_pushlstring (e->L, line, len);

	if (lua_pcall (e->L, 1, 1, 0) != 0) {
		msg_info ("callback call failed: %s", lua_tostring (e->L, -1));
		lua_pop (e->L, 1);
		return NULL;
	}

	if (lua_type (e->L, -1) != LUA_TSTRING) {
		g_set_error (err, lua_expr_quark(), 500, "cannot parse lua atom");
		lua_pop (e->L, 1);
		return NULL;
	}

	tok = lua_tolstring (e->L, -1, &rlen);
	atom = rspamd_mempool_alloc0 (e->pool, sizeof (*atom));
	atom->str = rspamd_mempool_strdup (e->pool, tok);
	atom->len = rlen;
	atom->data = ud;

	lua_pop (e->L, 1);

	return atom;
}

struct lua_atom_process_data {
	lua_State *L;
	struct lua_expression *e;
	gint process_cb_pos;
	gint stack_item;
};

static gdouble
lua_atom_process (gpointer runtime_ud, rspamd_expression_atom_t *atom)
{
	struct lua_atom_process_data *pd = (struct lua_atom_process_data *)runtime_ud;
	gdouble ret = 0;
	guint nargs;
	gint err_idx;

	if (pd->stack_item != -1) {
		nargs = 2;
	}
	else {
		nargs = 1;
	}

	lua_pushcfunction (pd->L, &rspamd_lua_traceback);
	err_idx = lua_gettop (pd->L);

	/* Function position */
	lua_pushvalue (pd->L, pd->process_cb_pos);
	/* Atom name */
	lua_pushlstring (pd->L, atom->str, atom->len);

	/* If we have data passed */
	if (pd->stack_item != -1) {
		lua_pushvalue (pd->L, pd->stack_item);
	}

	if (lua_pcall (pd->L, nargs, 1, err_idx) != 0) {
		msg_info ("expression process callback failed: %s", lua_tostring (pd->L, -1));
	}
	else {
		ret = lua_tonumber (pd->L, -1);
	}

	lua_settop (pd->L, err_idx - 1);

	return ret;
}

static gint
lua_expr_process (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_expression *e = rspamd_lua_expression (L, 1);
	struct lua_atom_process_data pd;
	gdouble res;
	gint flags = 0, old_top;

	pd.L = L;
	pd.e = e;
	old_top = lua_gettop (L);

	if (e->process_idx == -1) {
		if (!lua_isfunction (L, 2)) {
			return luaL_error (L, "expression process is called with no callback function");
		}

		pd.process_cb_pos = 2;

		if (lua_type (L, 3) != LUA_TNONE && lua_type (L, 3) != LUA_TNIL) {
			pd.stack_item = 3;
		}
		else {
			pd.stack_item = -1;
		}

		if (lua_isnumber (L, 4)) {
			flags = lua_tointeger (L, 4);
		}
	}
	else {
		lua_rawgeti (L, LUA_REGISTRYINDEX, e->process_idx);
		pd.process_cb_pos = lua_gettop (L);

		if (lua_type (L, 2) != LUA_TNONE && lua_type (L, 2) != LUA_TNIL) {
			pd.stack_item = 2;
		}
		else {
			pd.stack_item = -1;
		}

		if (lua_isnumber (L, 3)) {
			flags = lua_tointeger (L, 3);
		}
	}

	res = rspamd_process_expression (e->expr, flags, &pd);

	lua_settop (L, old_top);
	lua_pushnumber (L, res);

	return 1;
}

static gint
lua_expr_process_traced (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_expression *e = rspamd_lua_expression (L, 1);
	struct lua_atom_process_data pd;
	gdouble res;
	gint flags = 0, old_top;
	GPtrArray *trace;

	pd.L = L;
	pd.e = e;
	old_top = lua_gettop (L);

	if (e->process_idx == -1) {
		if (!lua_isfunction (L, 2)) {
			return luaL_error (L, "expression process is called with no callback function");
		}

		pd.process_cb_pos = 2;
		pd.stack_item = 3;

		if (lua_isnumber (L, 4)) {
			flags = lua_tointeger (L, 4);
		}
	}
	else {
		lua_rawgeti (L, LUA_REGISTRYINDEX, e->process_idx);
		pd.process_cb_pos = lua_gettop (L);
		pd.stack_item = 2;

		if (lua_isnumber (L, 3)) {
			flags = lua_tointeger (L, 3);
		}
	}

	res = rspamd_process_expression_track (e->expr, flags, &pd, &trace);

	lua_settop (L, old_top);
	lua_pushnumber (L, res);

	lua_createtable (L, trace->len, 0);

	for (guint i = 0; i < trace->len; i ++) {
		struct rspamd_expression_atom_s *atom = g_ptr_array_index (trace, i);

		lua_pushlstring (L, atom->str, atom->len);
		lua_rawseti (L, -2, i + 1);
	}

	g_ptr_array_free (trace, TRUE);

	return 2;
}

static gint
lua_expr_create (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_expression *e, **pe;
	const char *line;
	gsize len;
	gboolean no_process = FALSE;
	GError *err = NULL;
	rspamd_mempool_t *pool;

	/* Check sanity of the arguments */
	if (lua_type (L, 1) != LUA_TSTRING ||
			(lua_type (L, 2) != LUA_TTABLE && lua_type (L, 2) != LUA_TFUNCTION) ||
			rspamd_lua_check_mempool (L, 3) == NULL) {
		lua_pushnil (L);
		lua_pushstring (L, "bad arguments");
	}
	else {
		line = lua_tolstring (L, 1, &len);
		pool = rspamd_lua_check_mempool (L, 3);

		e = rspamd_mempool_alloc (pool, sizeof (*e));
		e->L = L;
		e->pool = pool;

		/* Check callbacks */
		if (lua_istable (L, 2)) {
			lua_pushvalue (L, 2);
			lua_pushnumber (L, 1);
			lua_gettable (L, -2);

			if (lua_type (L, -1) != LUA_TFUNCTION) {
				lua_pop (L, 1);
				lua_pushnil (L);
				lua_pushstring (L, "bad parse callback");

				return 2;
			}

			lua_pop (L, 1);

			lua_pushnumber (L, 2);
			lua_gettable (L, -2);

			if (lua_type (L, -1) != LUA_TFUNCTION) {
				if (lua_type (L, -1) != LUA_TNIL && lua_type (L, -1) != LUA_TNONE) {
					lua_pop (L, 1);
					lua_pushnil (L);
					lua_pushstring (L, "bad process callback");

					return 2;
				}
				else {
					no_process = TRUE;
				}
			}

			lua_pop (L, 1);
			/* Table is still on the top of stack */

			lua_pushnumber (L, 1);
			lua_gettable (L, -2);
			e->parse_idx = luaL_ref (L, LUA_REGISTRYINDEX);

			if (!no_process) {
				lua_pushnumber (L, 2);
				lua_gettable (L, -2);
				e->process_idx = luaL_ref (L, LUA_REGISTRYINDEX);
			}
			else {
				e->process_idx = -1;
			}

			lua_pop (L, 1); /* Table */
		}
		else {
			/* Process function is just a function, not a table */
			lua_pushvalue (L, 2);
			e->parse_idx = luaL_ref (L, LUA_REGISTRYINDEX);
			e->process_idx = -1;
		}

		if (!rspamd_parse_expression (line, len, &lua_atom_subr, e, pool, &err,
				&e->expr)) {
			lua_pushnil (L);
			lua_pushstring (L, err->message);
			g_error_free (err);
			lua_expr_dtor (e);

			return 2;
		}

		rspamd_mempool_add_destructor (pool, lua_expr_dtor, e);
		pe = lua_newuserdata (L, sizeof (struct lua_expression *));
		rspamd_lua_setclass (L, "rspamd{expr}", -1);
		*pe = e;
		lua_pushnil (L);
	}

	return 2;
}

static gint
lua_expr_to_string (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_expression *e = rspamd_lua_expression (L, 1);
	GString *str;

	if (e != NULL && e->expr != NULL) {
		str = rspamd_expression_tostring (e->expr);
		if (str) {
			lua_pushlstring (L, str->str, str->len);
			g_string_free (str, TRUE);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

struct lua_expr_atoms_cbdata {
	lua_State *L;
	gint idx;
};

static void
lua_exr_atom_cb (const rspamd_ftok_t *tok, gpointer ud)
{
	struct lua_expr_atoms_cbdata *cbdata = ud;

	lua_pushlstring (cbdata->L, tok->begin, tok->len);
	lua_rawseti (cbdata->L, -2, cbdata->idx ++);
}

static gint
lua_expr_atoms (lua_State *L)
{
	LUA_TRACE_POINT;
	struct lua_expression *e = rspamd_lua_expression (L, 1);
	struct lua_expr_atoms_cbdata cbdata;

	if (e != NULL && e->expr != NULL) {
		lua_newtable (L);
		cbdata.L = L;
		cbdata.idx = 1;
		rspamd_expression_atom_foreach (e->expr, lua_exr_atom_cb, &cbdata);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static gint
lua_load_expression (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, exprlib_f);

	return 1;
}

void
luaopen_expression (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{expr}", exprlib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_expression", lua_load_expression);
}
