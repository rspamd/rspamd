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

/***
 * @module rspamd_mempool
 * Rspamd memory pool is used to allocate memory attached to specific objects,
 * namely it was initially used for memory allocation for rspamd_task.
 *
 * All memory allocated by the pool is destroyed when the associated object is
 * destroyed. This allows a sort of controlled garbage collection for memory
 * allocated from the pool. Memory pools are extensively used by rspamd internal
 * components and provide some powerful features, such as destructors or
 * persistent variables.
 * @example
local mempool = require "rspamd_mempool"
local pool = mempool.create()

pool:set_variable('a', 'bcd', 1, 1.01, false)
local v1, v2, v3, v4 = pool:get_variable('a', 'string,double,double,bool')
pool:destroy()
 */

/* Lua bindings */
/***
 * @function mempool.create([size])
 * Creates a memory pool of a specified `size` or platform dependent optimal size (normally, a page size)
 * @param {number} size size of a page inside pool
 * @return {rspamd_mempool} new pool object (that should be removed by explicit call to `pool:destroy()`)
 */
LUA_FUNCTION_DEF (mempool, create);
/***
 * @method mempool:add_destructor(func)
 * Adds new destructor function to the pool
 * @param {function} func function to be called when the pool is destroyed
 */
LUA_FUNCTION_DEF (mempool, add_destructor);
/***
 * @method mempool:destroy()
 * Destroys memory pool cleaning all variables and calling all destructors registered (both C and Lua ones)
 */
LUA_FUNCTION_DEF (mempool, delete);
LUA_FUNCTION_DEF (mempool, stat);
LUA_FUNCTION_DEF (mempool, suggest_size);
/***
 * @method mempool:set_variable(name, [value1[, value2 ...]])
 * Sets a variable that's valid during memory pool lifetime. This function allows
 * to pack multiple values inside a single variable. Currently supported types are:
 *
 * - `string`: packed as null terminated C string (so no `\0` are allowed)
 * - `number`: packed as C double
 * - `boolean`: packed as bool
 * @param {string} name variable's name to set
 */
LUA_FUNCTION_DEF (mempool, set_variable);
/***
 * @method mempool:set_bucket(name, num_values, [value1...valuen]|[table])
 * Stores a variable bucket of numbers where the first number is number of elements to pack
 * and then there should be either n numeric values or a plain table of numeric values
 * @param {string} name variable's name to set
 * @param {number} num_values number of variables in the bucket
 * @param {table|list} values values
 */
LUA_FUNCTION_DEF (mempool, set_bucket);
/***
 * @method mempool:get_variable(name[, type])
 * Unpacks mempool variable to lua If `type` is not specified, then a variable is
 * assumed to be zero-terminated C string. Otherwise, `type` is a comma separated (spaces are ignored)
 * list of types that should be unpacked from a variable's content. The following types
 * are supported:
 *
 * - `string`: null terminated C string (so no `\0` are allowed)
 * - `double`: returned as lua number
 * - `int`: unpack a single integer
 * - `int64`: unpack 64-bits integer
 * - `boolean`: unpack boolean
 * - `bucket`: bucket of numbers represented as a Lua table
 * - `fstrings`: list of rspamd_fstring_t (GList) represented as a Lua table
 * @param {string} name variable's name to get
 * @param {string} type list of types to be extracted
 * @return {variable list} list of variables extracted (but **not** a table)
 */
LUA_FUNCTION_DEF (mempool, get_variable);
/***
 * @method mempool:has_variable(name)
 * Checks if the specified variable `name` exists in the memory pool
 * @param {string} name variable's name to get
 * @return {boolean} `true` if variable exists and `false` otherwise
 */
LUA_FUNCTION_DEF (mempool, has_variable);

/***
 * @method mempool:delete_variable(name)
 * Removes the specified variable `name` from the memory pool
 * @param {string} name variable's name to remove
 * @return {boolean} `true` if variable exists and has been removed
 */
LUA_FUNCTION_DEF (mempool, delete_variable);
/**
 * @method mempool:topointer()
 *
 * Returns raw C pointer (lightuserdata) associated with mempool. This might be
 * broken with luajit and GC64, use with caution.
 */
LUA_FUNCTION_DEF (mempool, topointer);

static const struct luaL_reg mempoollib_m[] = {
	LUA_INTERFACE_DEF (mempool, add_destructor),
	LUA_INTERFACE_DEF (mempool, stat),
	LUA_INTERFACE_DEF (mempool, suggest_size),
	LUA_INTERFACE_DEF (mempool, set_variable),
	LUA_INTERFACE_DEF (mempool, set_bucket),
	LUA_INTERFACE_DEF (mempool, get_variable),
	LUA_INTERFACE_DEF (mempool, has_variable),
	LUA_INTERFACE_DEF (mempool, delete_variable),
	LUA_INTERFACE_DEF (mempool, topointer),
	LUA_INTERFACE_DEF (mempool, delete),
	{"destroy", lua_mempool_delete},
	{"__tostring", rspamd_lua_class_tostring},
	{NULL, NULL}
};

static const struct luaL_reg mempoollib_f[] = {
	LUA_INTERFACE_DEF (mempool, create),
	{NULL, NULL}
};

/*
 * Struct for lua destructor
 */

struct lua_mempool_udata {
	lua_State *L;
	gint cbref;
	rspamd_mempool_t *mempool;
};

struct memory_pool_s *
rspamd_lua_check_mempool (lua_State * L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{mempool}");
	luaL_argcheck (L, ud != NULL, pos, "'mempool' expected");
	return ud ? *((struct memory_pool_s **)ud) : NULL;
}


static int
lua_mempool_create (lua_State *L)
{
	LUA_TRACE_POINT;
	struct memory_pool_s *mempool = rspamd_mempool_new (
			rspamd_mempool_suggest_size (), "lua", 0), **pmempool;

	if (mempool) {
		pmempool = lua_newuserdata (L, sizeof (struct memory_pool_s *));
		rspamd_lua_setclass (L, "rspamd{mempool}", -1);
		*pmempool = mempool;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static void
lua_mempool_destructor_func (gpointer p)
{
	struct lua_mempool_udata *ud = p;

	lua_rawgeti (ud->L, LUA_REGISTRYINDEX, ud->cbref);
	if (lua_pcall (ud->L, 0, 0, 0) != 0) {
		msg_info ("call to destructor failed: %s", lua_tostring (ud->L, -1));
		lua_pop (ud->L, 1);
	}
	luaL_unref (ud->L, LUA_REGISTRYINDEX, ud->cbref);
}

static int
lua_mempool_add_destructor (lua_State *L)
{
	LUA_TRACE_POINT;
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);
	struct lua_mempool_udata *ud;

	if (mempool) {
		if (lua_isfunction (L, 2)) {
			ud = rspamd_mempool_alloc (mempool,
					sizeof (struct lua_mempool_udata));
			lua_pushvalue (L, 2);
			/* Get a reference */
			ud->cbref = luaL_ref (L, LUA_REGISTRYINDEX);
			ud->L = L;
			ud->mempool = mempool;
			rspamd_mempool_add_destructor (mempool,
				lua_mempool_destructor_func,
				ud);
		}
		else {
			msg_err ("trying to add destructor without function");
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_mempool_delete (lua_State *L)
{
	LUA_TRACE_POINT;
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);

	if (mempool) {
		rspamd_mempool_delete (mempool);
		return 0;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_mempool_stat (lua_State *L)
{
	LUA_TRACE_POINT;
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);

	if (mempool) {

	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

static int
lua_mempool_suggest_size (lua_State *L)
{
	LUA_TRACE_POINT;
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);

	if (mempool) {
		lua_pushinteger (L, rspamd_mempool_suggest_size ());
		return 0;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}

struct lua_numbers_bucket {
	guint nelts;
	gdouble elts[0];
};

static int
lua_mempool_set_bucket (lua_State *L)
{
	LUA_TRACE_POINT;
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);
	const gchar *var = luaL_checkstring (L, 2);
	struct lua_numbers_bucket *bucket;
	gint nelts = luaL_checknumber (L, 3), i;

	if (var && nelts > 0) {
		bucket = rspamd_mempool_alloc (mempool,
				sizeof (*bucket) + sizeof (gdouble) * nelts);
		bucket->nelts = nelts;

		if (lua_type (L, 4) == LUA_TTABLE) {
			/* Table version */
			for (i = 1; i <= nelts; i ++) {
				lua_rawgeti (L, 4, i);
				bucket->elts[i - 1] = lua_tonumber (L, -1);
				lua_pop (L, 1);
			}
		}
		else {
			for (i = 0; i <= nelts; i ++) {
				bucket->elts[i] = lua_tonumber (L, 4 + i);
			}
		}

		rspamd_mempool_set_variable (mempool, var, bucket, NULL);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;
}

static int
lua_mempool_set_variable (lua_State *L)
{
	LUA_TRACE_POINT;
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);
	const gchar *var = luaL_checkstring (L, 2);
	gpointer value;
	struct lua_numbers_bucket *bucket;
	gchar *vp;
	union {
		gdouble d;
		const gchar *s;
		gboolean b;
	} val;
	gsize slen;
	gint i, j, len = 0, type;

	if (mempool && var) {

		for (i = 3; i <= lua_gettop (L); i ++) {
			type = lua_type (L, i);

			if (type == LUA_TNUMBER) {
				/* We have some ambiguity here between integer and double */
				len += sizeof (gdouble);
			}
			else if (type == LUA_TBOOLEAN) {
				len += sizeof (gboolean);
			}
			else if (type == LUA_TSTRING) {
				(void)lua_tolstring (L, i, &slen);
				len += slen + 1;
			}
			else if (type == LUA_TTABLE) {
				/* We assume it as a bucket of numbers so far */
				slen = rspamd_lua_table_size (L, i);
				len += sizeof (gdouble) * slen + sizeof (*bucket);
			}
			else {
				msg_err ("cannot handle lua type %s", lua_typename (L, type));
			}
		}

		if (len == 0) {
			msg_err ("no values specified");
		}
		else {
			value = rspamd_mempool_alloc (mempool, len);
			vp = value;

			for (i = 3; i <= lua_gettop (L); i ++) {
				type = lua_type (L, i);

				if (type == LUA_TNUMBER) {
					val.d = lua_tonumber (L, i);
					memcpy (vp, &val, sizeof (gdouble));
					vp += sizeof (gdouble);
				}
				else if (type == LUA_TBOOLEAN) {
					val.b = lua_toboolean (L, i);
					memcpy (vp, &val, sizeof (gboolean));
					vp += sizeof (gboolean);
				}
				else if (type == LUA_TSTRING) {
					val.s = lua_tolstring (L, i, &slen);
					memcpy (vp, val.s, slen + 1);
					vp += slen + 1;
				}
				else if (type == LUA_TTABLE) {
					slen = rspamd_lua_table_size (L, i);
					/* XXX: Ret, ret, ret: alignment issues */
					bucket = (struct lua_numbers_bucket *)vp;
					bucket->nelts = slen;

					for (j = 0; j < slen; j ++) {
						lua_rawgeti (L, i, j + 1);
						bucket->elts[j] = lua_tonumber (L, -1);
						lua_pop (L, 1);
					}

					vp += sizeof (gdouble) * slen + sizeof (*bucket);
				}
				else {
					msg_err ("cannot handle lua type %s", lua_typename (L, type));
				}
			}

			rspamd_mempool_set_variable (mempool, var, value, NULL);
		}

		return 0;
	}
	else {
		lua_pushnil (L);
	}

	return 1;
}


static int
lua_mempool_get_variable (lua_State *L)
{
	LUA_TRACE_POINT;
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);
	const gchar *var = luaL_checkstring (L, 2);
	const gchar *type = NULL, *pt;
	struct lua_numbers_bucket bucket;
	const gchar *value, *pv;
	guint len, nvar, slen, i;

	if (mempool && var) {
		value = rspamd_mempool_get_variable (mempool, var);

		if (lua_gettop (L) >= 3) {
			type = luaL_checkstring (L, 3);
		}

		if (value) {

			if (type) {
				pt = type;
				pv = value;
				nvar = 0;

				while ((len = strcspn (pt, ", ")) > 0) {
					if (len == sizeof ("double") - 1 &&
							g_ascii_strncasecmp (pt, "double", len) == 0) {
						gdouble num;
						memcpy (&num, pv, sizeof (gdouble));
						lua_pushnumber (L, num);
						pv += sizeof (gdouble);
					}
					else if (len == sizeof ("int") - 1 &&
							g_ascii_strncasecmp (pt, "int", len) == 0) {
						gint num;
						memcpy (&num, pv, sizeof (gint));
						lua_pushinteger (L, num);
						pv += sizeof (gint);
					}
					else if (len == sizeof ("int64") - 1 &&
							g_ascii_strncasecmp (pt, "int64", len) == 0) {
						gint64 num;
						memcpy (&num, pv, sizeof (gint64));
						lua_pushinteger (L, num);
						pv += sizeof (gint64);
					}
					else if (len == sizeof ("bool") - 1 &&
							g_ascii_strncasecmp (pt, "bool", len) == 0) {
						gboolean num;
						memcpy (&num, pv, sizeof (gboolean));
						lua_pushboolean (L, num);
						pv += sizeof (gboolean);
					}
					else if (len == sizeof ("string") - 1 &&
							g_ascii_strncasecmp (pt, "string", len) == 0) {
						slen = strlen ((const gchar *)pv);
						lua_pushlstring (L, (const gchar *)pv, slen);
						pv += slen + 1;
					}
					else if (len == sizeof ("gstring") - 1 &&
							g_ascii_strncasecmp (pt, "gstring", len) == 0) {
						GString *st = (GString *)pv;
						lua_pushlstring (L, st->str, st->len);
						pv += sizeof (GString *);
					}
					else if (len == sizeof ("bucket") - 1 &&
							g_ascii_strncasecmp (pt, "bucket", len) == 0) {
						memcpy (&bucket, pv, sizeof (bucket));
						lua_createtable (L, bucket.nelts, 0);
						pv += sizeof (struct lua_numbers_bucket);

						for (i = 0; i < bucket.nelts; i ++) {
							gdouble num;
							memcpy (&num, pv, sizeof (num));
							lua_pushnumber (L, num);
							lua_rawseti (L, -2, i + 1);
							pv += sizeof (num);
						}
					}
					else if (len == sizeof ("fstrings") - 1 &&
							 g_ascii_strncasecmp (pt, "fstrings", len) == 0) {
						GList *cur;
						rspamd_fstring_t *fstr;

						cur = (GList *)pv;
						lua_newtable (L);

						i = 1;
						while (cur != NULL) {
							fstr = cur->data;
							lua_pushlstring (L, fstr->str, fstr->len);
							lua_rawseti (L, -2, i);
							i ++;
							cur = g_list_next (cur);
						}

						pv += sizeof (GList *);
					}
					else {
						msg_err ("unknown type for get_variable: %s", pt);
						lua_pushnil (L);
					}

					pt += len;
					pt += strspn (pt, ", ");

					nvar ++;
				}

				return nvar;
			}
			else {
				/* No type specified, return string */
				lua_pushstring(L, value);
			}
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

static int
lua_mempool_has_variable (lua_State *L)
{
	LUA_TRACE_POINT;
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);
	const gchar *var = luaL_checkstring (L, 2);
	gboolean ret = FALSE;

	if (mempool && var) {
		if (rspamd_mempool_get_variable (mempool, var) != NULL) {
			ret = TRUE;
		}
	}

	lua_pushboolean (L, ret);

	return 1;
}

static int
lua_mempool_delete_variable (lua_State *L)
{
	LUA_TRACE_POINT;
	struct memory_pool_s *mempool = rspamd_lua_check_mempool (L, 1);
	const gchar *var = luaL_checkstring (L, 2);
	gboolean ret = FALSE;

	if (mempool && var) {
		if (rspamd_mempool_get_variable (mempool, var) != NULL) {
			ret = TRUE;

			rspamd_mempool_remove_variable (mempool, var);
		}
	}

	lua_pushboolean (L, ret);

	return 1;
}

static gint
lua_mempool_topointer (lua_State *L)
{
	LUA_TRACE_POINT;
	rspamd_mempool_t *pool = rspamd_lua_check_mempool (L, 1);

	if (pool) {
		/* XXX: this might cause issues on arm64 and LuaJIT */
		lua_pushlightuserdata (L, pool);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_load_mempool (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, mempoollib_f);

	return 1;
}

void
luaopen_mempool (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{mempool}", mempoollib_m);
	lua_pop (L, 1);
	rspamd_lua_add_preload (L, "rspamd_mempool", lua_load_mempool);
}
