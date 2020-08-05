/*-
 * Copyright 2020 Vsevolod Stakhov
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
#include "lua_tensor.h"
#include "contrib/kann/kautodiff.h"

/***
 * @module rspamd_tensor
 * `rspamd_tensor` is a simple Lua library to abstract matrices and vectors
 * Internally, they are represented as arrays of float variables
 * So far, merely 1D and 2D tensors are supported
 */

LUA_FUNCTION_DEF (tensor, load);
LUA_FUNCTION_DEF (tensor, save);
LUA_FUNCTION_DEF (tensor, new);
LUA_FUNCTION_DEF (tensor, fromtable);
LUA_FUNCTION_DEF (tensor, destroy);
LUA_FUNCTION_DEF (tensor, mul);

static luaL_reg rspamd_tensor_f[] = {
		LUA_INTERFACE_DEF (tensor, load),
		LUA_INTERFACE_DEF (tensor, new),
		LUA_INTERFACE_DEF (tensor, fromtable),
		{NULL, NULL},
};

static luaL_reg rspamd_tensor_m[] = {
		LUA_INTERFACE_DEF (tensor, save),
		{"__gc", lua_tensor_destroy},
		{"__mul", lua_tensor_mul},
		{"mul", lua_tensor_mul},
		{NULL, NULL},
};

static struct rspamd_lua_tensor *
lua_newtensor (lua_State *L, int ndims, const int *dim, bool zero_fill)
{
	struct rspamd_lua_tensor *res;

	res = lua_newuserdata (L, sizeof (struct rspamd_lua_tensor));

	res->ndims = ndims;
	res->size = 1;

	for (guint i = 0; i < ndims; i ++) {
		res->size *= dim[i];
		res->dim[i] = dim[i];
	}

	/* To avoid allocating large stuff in Lua */
	res->data = g_malloc (sizeof (rspamd_tensor_num_t) * res->size);

	if (zero_fill) {
		memset (res->data, 0, sizeof (rspamd_tensor_num_t) * res->size);
	}

	rspamd_lua_setclass (L, TENSOR_CLASS, -1);

	return res;
}

/***
 * @function tensor.new(ndims, [dim1, ... dimN])
 * Creates a new zero filled tensor with the specific number of dimensions
 * @return
 */
static gint
lua_tensor_new (lua_State *L)
{
	gint ndims = luaL_checkinteger (L, 1);

	if (ndims > 0 && ndims <= 2) {
		gint *dims = g_alloca (sizeof (gint) * ndims);

		for (guint i = 0; i < ndims; i ++) {
			dims[i] = lua_tointeger (L, i + 2);
		}

		(void)lua_newtensor (L, ndims, dims, true);
	}
	else {
		return luaL_error (L, "incorrect dimensions number: %d", ndims);
	}

	return 1;
}

/***
 * @function tensor.fromtable(tbl)
 * Creates a new zero filled tensor with the specific number of dimensions
 * @return
 */
static gint
lua_tensor_fromtable (lua_State *L)
{
	if (lua_istable (L, 1)) {
		lua_rawgeti (L, 1, 1);

		if (lua_isnumber (L, -1)) {
			lua_pop (L, 1);
			/* Input vector */
			gint dim = rspamd_lua_table_size (L, 1);

			struct rspamd_lua_tensor *res = lua_newtensor (L, 1,
					&dim, false);

			for (guint i = 0; i < dim; i ++) {
				lua_rawgeti (L, 1, i + 1);
				res->data[i] = lua_tonumber (L, -1);
				lua_pop (L, 1);
			}
		}
		else if (lua_istable (L, -1)) {
			/* Input matrix */
			lua_pop (L, 1);

			/* Calculate the overall size */
			gint nrows = rspamd_lua_table_size (L, 1), ncols = 0;
			gint err;

			for (gint i = 0; i < nrows; i ++) {
				lua_rawgeti (L, 1, i + 1);

				if (ncols == 0) {
					ncols = rspamd_lua_table_size (L, -1);

					if (ncols == 0) {
						lua_pop (L, 1);
						err = luaL_error (L, "invalid params at pos %d: "
										   "bad input dimension %d",
								i,
								(int)ncols);

						return err;
					}
				}
				else {
					if (ncols != rspamd_lua_table_size (L, -1)) {
						gint t = rspamd_lua_table_size (L, -1);

						lua_pop (L, 1);
						err = luaL_error (L, "invalid params at pos %d: "
											 "bad input dimension %d; %d expected",
								i,
								t,
								ncols);

						return err;
					}
				}

				lua_pop (L, 1);
			}

			gint dims[2];
			dims[0] = ncols;
			dims[1] = nrows;

			struct rspamd_lua_tensor *res = lua_newtensor (L, 2,
					dims, false);

			for (gint i = 0; i < nrows; i ++) {
				lua_rawgeti (L, 1, i + 1);

				for (gint j = 0; j < ncols; j++) {
					lua_rawgeti (L, -1, j + 1);

					res->data[i * ncols + j] = lua_tonumber (L, -1);

					lua_pop (L, 1);
				}

				lua_pop (L, 1);
			}
		}
		else {
			lua_pop (L, 1);
			return luaL_error (L, "incorrect table");
		}
	}
	else {
		return luaL_error (L, "incorrect input");
	}

	return 1;
}


/***
 * @method tensor:destroy()
 * Tensor destructor
 * @return
 */
static gint
lua_tensor_destroy (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1);

	if (t) {
		g_free (t->data);
	}

	return 0;
}

/***
 * @method tensor:save()
 * Tensor serialisation function
 * @return
 */
static gint
lua_tensor_save (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1);

	if (t) {

	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @method tensor:mul(other, [transA, [transB]])
 * Multiply two tensors (optionally transposed) and return a new tensor
 * @return
 */
static gint
lua_tensor_mul (lua_State *L)
{
	struct rspamd_lua_tensor *t1 = lua_check_tensor (L, 1),
			*t2 = lua_check_tensor (L, 2), *res;
	int transA = 0, transB = 0;

	if (lua_isboolean (L, 3)) {
		transA = lua_toboolean (L, 3);
	}

	if (lua_isboolean (L, 4)) {
		transB = lua_toboolean (L, 4);
	}

	if (t1 && t2) {
		gint dims[2];
		dims[0] = transA ? t1->dim[1] : t1->dim[0];
		dims[1] = transB ? t2->dim[0] : t2->dim[1];

		res = lua_newtensor (L, 2, dims, false);
		kad_sgemm_simple (transA, transB, t1->dim[1], t2->dim[0], t1->dim[0],
				t1->data, t2->data, res->data);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

/***
 * @function tensor.load(rspamd_text)
 * Deserialize tensor
 * @return
 */
static gint
lua_tensor_load (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1);

	if (t) {

	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_load_tensor (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, rspamd_tensor_f);

	return 1;
}


void luaopen_tensor (lua_State *L)
{
	/* Metatables */
	rspamd_lua_new_class (L, TENSOR_CLASS, rspamd_tensor_m);
	lua_pop (L, 1); /* No need in metatable... */
	rspamd_lua_add_preload (L, "rspamd_tensor", lua_load_tensor);
	lua_settop (L, 0);
}

struct rspamd_lua_tensor *
lua_check_tensor (lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, TENSOR_CLASS);
	luaL_argcheck (L, ud != NULL, pos, "'tensor' expected");
	return ud ? ((struct rspamd_lua_tensor *)ud) : NULL;
}

