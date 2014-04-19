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

static gint lua_rcl_obj_push_array (lua_State *L, const ucl_object_t *obj);
static gint lua_rcl_obj_push_simple (lua_State *L, const ucl_object_t *obj, gboolean allow_array);
static ucl_object_t* lua_rcl_table_get (lua_State *L, gint idx);
static ucl_object_t* lua_rcl_elt_get (lua_State *L, gint idx);

/**
 * Push a single element of an object to lua
 * @param L
 * @param key
 * @param obj
 */
static void
lua_rcl_obj_push_elt (lua_State *L, const char *key, const ucl_object_t *obj)
{
	lua_pushstring (L, key);
	lua_rcl_obj_push (L, obj, TRUE);
	lua_settable (L, -3);
}

/**
 * Push a single object to lua
 * @param L
 * @param obj
 * @return
 */
static gint
lua_rcl_obj_push_obj (lua_State *L, const ucl_object_t *obj, gboolean allow_array)
{
	const ucl_object_t *cur;
	ucl_object_iter_t it = NULL;

	if (allow_array && obj->next != NULL) {
		/* Actually we need to push this as an array */
		return lua_rcl_obj_push_array (L, obj);
	}

	lua_newtable (L);
	while ((cur = ucl_iterate_object (obj, &it, true)) != NULL) {
		lua_rcl_obj_push_elt (L, ucl_object_key (cur), cur);
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
lua_rcl_obj_push_array (lua_State *L, const ucl_object_t *obj)
{
	const ucl_object_t *cur;
	gint i = 1;

	lua_newtable (L);

	LL_FOREACH (obj, cur) {
		lua_rcl_obj_push (L, cur, FALSE);
		lua_rawseti (L, -2, i);
		i ++;
	}

	return 1;
}

/**
 * Push a simple object to lua depending on its actual type
 */
static gint
lua_rcl_obj_push_simple (lua_State *L, const ucl_object_t *obj, gboolean allow_array)
{
	if (allow_array && obj->next != NULL) {
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
lua_rcl_obj_push (lua_State *L, const ucl_object_t *obj, gboolean allow_array)
{
	switch (obj->type) {
	case UCL_OBJECT:
		return lua_rcl_obj_push_obj (L, obj, allow_array);
	case UCL_ARRAY:
		return lua_rcl_obj_push_array (L, obj->value.av);
	default:
		return lua_rcl_obj_push_simple (L, obj, allow_array);
	}
}

/**
 * Parse lua table into object top
 * @param L
 * @param top
 * @param idx
 */
static ucl_object_t *
lua_rcl_table_get (lua_State *L, gint idx)
{
	ucl_object_t *obj, *top = NULL;
	gsize keylen;
	const gchar *k;

	/* Table iterate */
	lua_pushvalue (L, idx);
	lua_pushnil (L);
	top = ucl_object_typed_new (UCL_OBJECT);
	while (lua_next (L, -2) != 0) {
		/* copy key to avoid modifications */
		lua_pushvalue (L, -2);
		k = lua_tolstring (L, -1, &keylen);
		obj = lua_rcl_elt_get (L, -2);
		ucl_object_insert_key (top, obj, k, keylen, true);
		lua_pop (L, 2);
	}
	lua_pop (L, 1);

	return top;
}

/**
 * Get a single element from lua to object obj
 * @param L
 * @param obj
 * @param idx
 */
static ucl_object_t *
lua_rcl_elt_get (lua_State *L, gint idx)
{
	gint type;
	ucl_object_t *obj;

	type = lua_type (L, idx);

	switch (type) {
	case LUA_TFUNCTION:
		lua_pushvalue (L, idx);
		obj = ucl_object_new ();
		obj->type = UCL_USERDATA;
		obj->value.ud = GINT_TO_POINTER (luaL_ref (L, LUA_REGISTRYINDEX));
		break;
	case LUA_TSTRING:
		obj = ucl_object_fromstring_common (lua_tostring (L, idx), 0, 0);
		break;
	case LUA_TNUMBER:
		obj = ucl_object_fromdouble (lua_tonumber (L, idx));
		break;
	case LUA_TBOOLEAN:
		obj = ucl_object_frombool (lua_toboolean (L, idx));
		break;
	case LUA_TTABLE:
		obj = lua_rcl_table_get (L, idx);
		break;
	}

	return obj;
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

	t = lua_type (L, idx);
	switch (t) {
	case LUA_TTABLE:
		/* We assume all tables as objects, not arrays */
		obj = lua_rcl_table_get (L, idx);
		break;
	default:
		obj = lua_rcl_elt_get (L, idx);
		break;
	}

	return obj;
}
