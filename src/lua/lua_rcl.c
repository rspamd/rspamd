/* Copyright (c) 2013, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "lua_common.h"

/**
 * @file lua rcl bindings
 */

static gint lua_rcl_obj_push_array (lua_State *L, ucl_object_t *obj);
static gint lua_rcl_obj_push_simple (lua_State *L, ucl_object_t *obj);
static void lua_rcl_table_get (lua_State *L, ucl_object_t *top, gint idx);
static void lua_rcl_elt_get (lua_State *L, ucl_object_t *top, gint idx);

/**
 * Push a single element of an object to lua
 * @param L
 * @param key
 * @param obj
 */
static void
lua_rcl_obj_push_elt (lua_State *L, const char *key, ucl_object_t *obj)
{
	lua_pushstring (L, key);
	lua_rcl_obj_push (L, obj);
	lua_settable (L, -3);
}

/**
 * Push a single object to lua
 * @param L
 * @param obj
 * @return
 */
static gint
lua_rcl_obj_push_obj (lua_State *L, ucl_object_t *obj)
{
	ucl_object_t *cur, *tmp;

	if (obj->next != NULL) {
		/* Actually we need to push this as an array */
		return lua_rcl_obj_push_array (L, obj);
	}

	lua_newtable (L);
	HASH_ITER (hh, obj, cur, tmp) {
		lua_rcl_obj_push_elt (L, ucl_object_key (obj), obj);
	}

	return 1;
}

/**
 * Push an array to lua as table indexed by integers
 * @param L
 * @param obj
 * @return
 */
static gint
lua_rcl_obj_push_array (lua_State *L, ucl_object_t *obj)
{
	ucl_object_t *cur;
	gint i = 1;

	lua_newtable (L);

	LL_FOREACH (obj, cur) {
		lua_rcl_obj_push (L, cur);
		lua_rawseti (L, -2, i);
		i ++;
	}

	return 1;
}

/**
 * Push a simple object to lua depending on its actual type
 */
static gint
lua_rcl_obj_push_simple (lua_State *L, ucl_object_t *obj)
{
	if (obj->next != NULL) {
		/* Actually we need to push this as an array */
		return lua_rcl_obj_push_array (L, obj);
	}

	switch (obj->type) {
	case UCL_BOOLEAN:
		lua_pushboolean (L, ucl_obj_toboolean (obj));
		break;
	case UCL_STRING:
		lua_pushstring (L, ucl_obj_tostring (obj));
		break;
	case UCL_INT:
#if LUA_VERSION_NUM >= 501
		lua_pushinteger (L, ucl_obj_toint (obj));
#else
		lua_pushnumber (L, ucl_obj_toint (obj));
#endif
		break;
	case UCL_FLOAT:
	case UCL_TIME:
		lua_pushnumber (L, ucl_obj_todouble (obj));
		break;
	default:
		lua_pushnil (L);
		break;
	}

	return 1;
}

/**
 * Push an object to lua
 * @param L lua state
 * @param obj object to push
 */
gint
lua_rcl_obj_push (lua_State *L, ucl_object_t *obj)
{
	switch (obj->type) {
	case UCL_OBJECT:
		return lua_rcl_obj_push_obj (L, obj->value.ov);
	case UCL_ARRAY:
		return lua_rcl_obj_push_array (L, obj->value.ov);
	default:
		return lua_rcl_obj_push_simple (L, obj);
	}
}

/**
 * Parse lua table into object top
 * @param L
 * @param top
 * @param idx
 */
static void
lua_rcl_table_get (lua_State *L, ucl_object_t *top, gint idx)
{
	ucl_object_t *obj;
	gsize keylen;
	const gchar *k;

	/* Table iterate */
	lua_pushvalue (L, idx);
	lua_pushnil (L);
	while (lua_next (L, -2) != 0) {
		/* copy key to avoid modifications */
		lua_pushvalue (L, -2);
		obj = ucl_object_new ();
		if (obj != NULL) {
			k = lua_tolstring (L, -1, &keylen);
			ucl_object_insert_key (top, obj, k, keylen, true);
			lua_rcl_elt_get (L, obj, -2);
		}

		lua_pop (L, 2);
	}
	lua_pop (L, 1);
}

/**
 * Get a single element from lua to object obj
 * @param L
 * @param obj
 * @param idx
 */
static void
lua_rcl_elt_get (lua_State *L, ucl_object_t *obj, gint idx)
{
	gint type;

	type = lua_type (L, idx);

	switch (type) {
	case LUA_TFUNCTION:
		lua_pushvalue (L, idx);
		obj->type = UCL_USERDATA;
		obj->value.ud = GINT_TO_POINTER (luaL_ref (L, LUA_REGISTRYINDEX));
		break;
	case LUA_TSTRING:
		obj->type = UCL_STRING;
		obj->value.sv = g_strdup (lua_tostring (L, idx));
		break;
	case LUA_TNUMBER:
		obj->type = UCL_FLOAT;
		obj->value.dv = lua_tonumber (L, idx);
		break;
	case LUA_TBOOLEAN:
		obj->type = UCL_BOOLEAN;
		obj->value.iv = lua_toboolean (L, idx);
		break;
	case LUA_TTABLE:
		obj->type = UCL_OBJECT;
		lua_rcl_table_get (L, obj, idx);
		break;
	}
}

/**
 * Extract rcl object from lua object
 * @param L
 * @return
 */
ucl_object_t *
lua_rcl_obj_get (lua_State *L, gint idx)
{
	ucl_object_t *obj;
	gint t;

	obj = ucl_object_new ();

	if (obj != NULL) {
		t = lua_type (L, idx);
		switch (t) {
		case LUA_TTABLE:
			/* We assume all tables as objects, not arrays */
			lua_rcl_table_get (L, obj, idx);
			break;
		default:
			lua_rcl_elt_get (L, obj, idx);
			break;
		}
	}

	return obj;
}
