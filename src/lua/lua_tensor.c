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
#include "blas-config.h"

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
LUA_FUNCTION_DEF (tensor, tostring);
LUA_FUNCTION_DEF (tensor, index);
LUA_FUNCTION_DEF (tensor, newindex);
LUA_FUNCTION_DEF (tensor, len);
LUA_FUNCTION_DEF (tensor, eigen);
LUA_FUNCTION_DEF (tensor, mean);
LUA_FUNCTION_DEF (tensor, transpose);
LUA_FUNCTION_DEF (tensor, has_blas);
LUA_FUNCTION_DEF (tensor, scatter_matrix);

static luaL_reg rspamd_tensor_f[] = {
		LUA_INTERFACE_DEF (tensor, load),
		LUA_INTERFACE_DEF (tensor, new),
		LUA_INTERFACE_DEF (tensor, fromtable),
		LUA_INTERFACE_DEF (tensor, has_blas),
		LUA_INTERFACE_DEF (tensor, scatter_matrix),
		{NULL, NULL},
};

static luaL_reg rspamd_tensor_m[] = {
		LUA_INTERFACE_DEF (tensor, save),
		{"__gc", lua_tensor_destroy},
		{"__mul", lua_tensor_mul},
		{"mul", lua_tensor_mul},
		{"tostring", lua_tensor_tostring},
		{"__tostring", lua_tensor_tostring},
		{"__index", lua_tensor_index},
		{"__newindex", lua_tensor_newindex},
		{"__len", lua_tensor_len},
		LUA_INTERFACE_DEF (tensor, eigen),
		LUA_INTERFACE_DEF (tensor, mean),
		LUA_INTERFACE_DEF (tensor, transpose),
		{NULL, NULL},
};

struct rspamd_lua_tensor *
lua_newtensor (lua_State *L, int ndims, const int *dim, bool zero_fill, bool own)
{
	struct rspamd_lua_tensor *res;

	res = lua_newuserdata (L, sizeof (struct rspamd_lua_tensor));
	memset (res, 0, sizeof (*res));

	res->ndims = ndims;
	res->size = 1;

	for (guint i = 0; i < ndims; i ++) {
		res->size *= dim[i];
		res->dim[i] = dim[i];
	}

	/* To avoid allocating large stuff in Lua */
	if (own) {
		res->data = g_malloc (sizeof (rspamd_tensor_num_t) * res->size);

		if (zero_fill) {
			memset (res->data, 0, sizeof (rspamd_tensor_num_t) * res->size);
		}
	}
	else {
		/* Mark size negative to distinguish */
		res->size = -(res->size);
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

		(void)lua_newtensor (L, ndims, dims, true, true);
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
			gint dims[2];
			dims[0] = 1;
			dims[1] = rspamd_lua_table_size (L, 1);

			struct rspamd_lua_tensor *res = lua_newtensor (L, 2,
					dims, false, true);

			for (guint i = 0; i < dims[1]; i ++) {
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
			dims[0] = nrows;
			dims[1] = ncols;

			struct rspamd_lua_tensor *res = lua_newtensor (L, 2,
					dims, false, true);

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
		if (t->size > 0) {
			g_free (t->data);
		}
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
	gint size;

	if (t) {
		if (t->size > 0) {
			size = t->size;
		}
		else {
			size = -(t->size);
		}

		gsize sz = sizeof (gint) * 4 + size * sizeof (rspamd_tensor_num_t);
		guchar *data;

		struct rspamd_lua_text *out = lua_new_text (L, NULL, 0, TRUE);

		data = g_malloc (sz);
		memcpy (data, &t->ndims, sizeof (int));
		memcpy (data + sizeof (int), &size, sizeof (int));
		memcpy (data + 2 * sizeof (int), t->dim, sizeof (int) * 2);
		memcpy (data + 4 * sizeof (int), t->data,
				size * sizeof (rspamd_tensor_num_t));

		out->start = (const gchar *)data;
		out->len = sz;
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_tensor_tostring (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1);

	if (t) {
		GString *out = g_string_sized_new (128);

		if (t->ndims == 1) {
			/* Print as a vector */
			for (gint i = 0; i < t->dim[0]; i ++) {
				rspamd_printf_gstring (out, "%.4f ", t->data[i]);
			}
			/* Trim last space */
			out->len --;
		}
		else {
			for (gint i = 0; i < t->dim[0]; i ++) {
				for (gint j = 0; j < t->dim[1]; j ++) {
					rspamd_printf_gstring (out, "%.4f ",
							t->data[i * t->dim[1] + j]);
				}
				/* Trim last space */
				out->len --;
				rspamd_printf_gstring (out, "\n");
			}
			/* Trim last ; */
			out->len --;
		}

		lua_pushlstring (L, out->str, out->len);

		g_string_free (out, TRUE);
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_tensor_index (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1);
	gint idx;

	if (t) {
		if (lua_isnumber (L, 2)) {
			idx = lua_tointeger (L, 2);

			if (t->ndims == 1) {
				/* Individual element */
				if (idx <= t->dim[0]) {
					lua_pushnumber (L, t->data[idx - 1]);
				}
				else {
					lua_pushnil (L);
				}
			}
			else {
				/* Push row */
				gint dim = t->dim[1];


				if (idx <= t->dim[0]) {
					/* Non-owning tensor */
					struct rspamd_lua_tensor *res =
							lua_newtensor (L, 1, &dim, false, false);
					res->data = &t->data[(idx - 1) * t->dim[1]];
				}
				else {
					lua_pushnil (L);
				}
			}
		}
		else if (lua_isstring (L, 2)) {
			/* Access to methods */
			lua_getmetatable (L, 1);
			lua_pushvalue (L, 2);
			lua_rawget (L, -2);
		}
	}

	return 1;
}
static gint
lua_tensor_newindex (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1);
	gint idx;

	if (t) {
		if (lua_isnumber (L, 2)) {
			idx = lua_tointeger (L, 2);

			if (t->ndims == 1) {
				/* Individual element */
				if (idx <= t->dim[0] && idx > 0) {
					rspamd_tensor_num_t value = lua_tonumber (L, 3), old;

					old = t->data[idx - 1];
					t->data[idx - 1] = value;
					lua_pushnumber (L, old);
				}
				else {
					return luaL_error (L, "invalid index: %d", idx);
				}
			}
			else {
				if (lua_isnumber (L, 3)) {
					return luaL_error (L, "cannot assign number to a row");
				}
				else if (lua_isuserdata (L, 3)) {
					/* Tensor assignment */
					struct rspamd_lua_tensor *row = lua_check_tensor (L, 3);

					if (row) {
						if (row->ndims == 1) {
							if (row->dim[0] == t->dim[1]) {
								if (idx > 0 && idx <= t->dim[0]) {
									idx --; /* Zero based index */
									memcpy (&t->data[idx * t->dim[1]],
											row->data,
											t->dim[1] * sizeof (rspamd_tensor_num_t));

									return 0;
								}
								else {
									return luaL_error (L, "invalid index: %d", idx);
								}
							}
						}
						else {
							return luaL_error (L, "cannot assign matrix to row");
						}
					}
					else {
						return luaL_error (L, "cannot assign row, invalid tensor");
					}
				}
				else {
					/* TODO: add table assignment */
					return luaL_error (L, "cannot assign row, not a tensor");
				}
			}
		}
		else {
			/* Access to methods? NYI */
			return luaL_error (L, "cannot assign method of a tensor");
		}
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
		gint dims[2], shadow_dims[2];
		dims[0] = abs (transA ? t1->dim[1] : t1->dim[0]);
		shadow_dims[0] = abs (transB ? t2->dim[1] : t2->dim[0]);
		dims[1] = abs (transB ? t2->dim[0] : t2->dim[1]);
		shadow_dims[1] = abs (transA ? t1->dim[0] : t1->dim[1]);

		if (shadow_dims[0] != shadow_dims[1]) {
			return luaL_error (L, "incompatible dimensions %d x %d * %d x %d",
					dims[0], shadow_dims[1], shadow_dims[0], dims[1]);
		}
		else if (shadow_dims[0] == 0) {
			/* Row * Column -> matrix */
			shadow_dims[0] = 1;
			shadow_dims[1] = 1;
		}

		if (dims[0] == 0) {
			/* Column */
			dims[0] = 1;

			if (dims[1] == 0) {
				/* Column * row -> number */
				dims[1] = 1;
			}
			res = lua_newtensor (L, 2, dims, true, true);
		}
		else if (dims[1] == 0) {
			/* Row */
			res = lua_newtensor (L, 1, dims, true, true);
			dims[1] = 1;
		}
		else {
			res = lua_newtensor (L, 2, dims, true, true);
		}

		kad_sgemm_simple (transA, transB, dims[0], dims[1], shadow_dims[0],
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
	const guchar *data;
	gsize sz;

	if (lua_type (L, 1) == LUA_TUSERDATA) {
		struct rspamd_lua_text *t = lua_check_text (L, 1);

		if (!t) {
			return luaL_error (L, "invalid argument");
		}

		data = (const guchar *)t->start;
		sz = t->len;
	}
	else {
		data = (const guchar *)lua_tolstring (L, 1, &sz);
	}

	if (sz >= sizeof (gint) * 4) {
		int ndims, nelts, dims[2];

		memcpy (&ndims, data, sizeof (int));
		memcpy (&nelts, data + sizeof (int), sizeof (int));
		memcpy (dims, data + sizeof (int) * 2, sizeof (int) * 2);

		if (sz == nelts * sizeof (rspamd_tensor_num_t) + sizeof (int) * 4) {
			if (ndims == 1) {
				if (nelts == dims[0]) {
					struct rspamd_lua_tensor *t = lua_newtensor (L, ndims, dims, false, true);
					memcpy (t->data, data + sizeof (int) * 4, nelts *
							sizeof (rspamd_tensor_num_t));
				}
				else {
					return luaL_error (L, "invalid argument: bad dims: %d x %d != %d",
							dims[0], 1, nelts);
				}
			}
			else if (ndims == 2) {
				if (nelts == dims[0] * dims[1]) {
					struct rspamd_lua_tensor *t = lua_newtensor (L, ndims, dims, false, true);
					memcpy (t->data, data + sizeof (int) * 4, nelts *
							sizeof (rspamd_tensor_num_t));
				}
				else {
					return luaL_error (L, "invalid argument: bad dims: %d x %d != %d",
							dims[0], dims[1], nelts);
				}
			}
			else {
				return luaL_error (L, "invalid argument: bad ndims: %d", ndims);
			}
		}
		else {
			return luaL_error (L, "invalid size: %d, %d required, %d elts", (int)sz,
					(int)(nelts * sizeof (rspamd_tensor_num_t) + sizeof (int) * 4),
					nelts);
		}
	}
	else {
		return luaL_error (L, "invalid arguments; sz = %d", (int)sz);
	}

	return 1;
}

static gint
lua_tensor_len (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1);
	gint nret = 1;

	if (t) {
		/* Return the main dimension first */
		if (t->ndims == 1) {
			lua_pushinteger (L, t->dim[0]);
		}
		else {
			lua_pushinteger (L, t->dim[0]);
			lua_pushinteger (L, t->dim[1]);
			nret = 2;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return nret;
}

static gint
lua_tensor_eigen (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1), *eigen;

	if (t) {
		if (t->ndims != 2 || t->dim[0] != t->dim[1]) {
			return luaL_error (L, "expected square matrix NxN but got %dx%d",
					t->dim[0], t->dim[1]);
		}

		eigen = lua_newtensor (L, 1, &t->dim[0], true, true);

		if (!kad_ssyev_simple (t->dim[0], t->data, eigen->data)) {
			lua_pop (L, 1);
			return luaL_error (L, "kad_ssyev_simple failed (no blas?)");
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static inline rspamd_tensor_num_t
mean_vec (rspamd_tensor_num_t *x, int n)
{
	rspamd_tensor_num_t s = 0;
	rspamd_tensor_num_t c = 0;

	/* https://en.wikipedia.org/wiki/Kahan_summation_algorithm */
	for (int i = 0; i < n; i ++) {
		rspamd_tensor_num_t v = x[i];
		rspamd_tensor_num_t y = v - c;
		rspamd_tensor_num_t t = s + y;
		c = (t - s) - y;
		s = t;
	}

	return s / (rspamd_tensor_num_t)n;
}

static gint
lua_tensor_mean (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1);

	if (t) {
		if (t->ndims == 1) {
			/* Mean of all elements in a vector */
			lua_pushnumber (L, mean_vec (t->data, t->dim[0]));
		}
		else {
			/* Row-wise mean vector output */
			struct rspamd_lua_tensor *res;

			res = lua_newtensor (L, 1, &t->dim[0], false, true);

			for (int i = 0; i < t->dim[0]; i ++) {
				res->data[i] = mean_vec (&t->data[i * t->dim[1]], t->dim[1]);
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_tensor_transpose (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1), *res;
	int dims[2];

	if (t) {
		if (t->ndims == 1) {
			/* Row to column */
			dims[0] = 1;
			dims[1] = t->dim[0];
			res = lua_newtensor (L, 2, dims, false, true);
			memcpy (res->data, t->data, t->dim[0] * sizeof (rspamd_tensor_num_t));
		}
		else {
			/* Cache friendly algorithm */
			struct rspamd_lua_tensor *res;

			dims[0] = t->dim[1];
			dims[1] = t->dim[0];
			res = lua_newtensor (L, 2, dims, false, true);

			static const int block = 32;

			for (int i = 0; i < t->dim[0]; i += block) {
				for(int j = 0; j < t->dim[1]; ++j) {
					for(int boff = 0; boff < block && i + boff < t->dim[0]; ++boff) {
						res->data[j * t->dim[0] + i + boff] =
								t->data[(i + boff) * t->dim[1] + j];
					}
				}
			}
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static gint
lua_tensor_has_blas (lua_State *L)
{
#ifdef HAVE_CBLAS
	lua_pushboolean (L, true);
#else
	lua_pushboolean (L, false);
#endif

	return 1;
}

static gint
lua_tensor_scatter_matrix (lua_State *L)
{
	struct rspamd_lua_tensor *t = lua_check_tensor (L, 1), *res;
	int dims[2];

	if (t) {
		if (t->ndims != 2) {
			return luaL_error (L, "matrix required");
		}

		/* X * X square matrix */
		dims[0] = t->dim[1];
		dims[1] = t->dim[1];
		res = lua_newtensor (L, 2, dims, true, true);

		/* Auxiliary vars */
		rspamd_tensor_num_t *means, /* means vector */
			*tmp_row, /* temp row for Kahan's algorithm */
			*tmp_square /* temp matrix for multiplications */;
		means = g_malloc0 (sizeof (rspamd_tensor_num_t) * t->dim[1]);
		tmp_row = g_malloc0 (sizeof (rspamd_tensor_num_t) * t->dim[1]);
		tmp_square = g_malloc (sizeof (rspamd_tensor_num_t) * t->dim[1] * t->dim[1]);

		/*
		 * Column based means
		 * means will have s, tmp_row will have c
		 */
		for (int i = 0; i < t->dim[0]; i ++) {
			/* Cycle by rows */
			for (int j = 0; j < t->dim[1]; j ++) {
				rspamd_tensor_num_t v = t->data[i * t->dim[1] + j];
				rspamd_tensor_num_t y = v - tmp_row[j];
				rspamd_tensor_num_t st = means[j] + y;
				tmp_row[j] = (st - means[j]) - y;
				means[j] = st;
			}
		}

		for (int j = 0; j < t->dim[1]; j ++) {
			means[j] /= t->dim[0];
		}

		for (int i = 0; i < t->dim[0]; i ++) {
			/* Update for each sample */
			for (int j = 0; j < t->dim[1]; j ++) {
				tmp_row[j] = t->data[i * t->dim[1] + j] - means[j];
			}

			memset (tmp_square, 0, t->dim[1] * t->dim[1] * sizeof (rspamd_tensor_num_t));
			kad_sgemm_simple (1, 0, t->dim[1], t->dim[1], 1,
					tmp_row, tmp_row, tmp_square);

			for (int j = 0; j < t->dim[1]; j ++) {
				kad_saxpy (t->dim[1], 1.0, &tmp_square[j * t->dim[1]],
						&res->data[j * t->dim[1]]);
			}
		}

		g_free (tmp_row);
		g_free (means);
		g_free (tmp_square);
	}
	else {
		return luaL_error (L, "tensor required");
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

