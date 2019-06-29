/*-
 * Copyright 2019 Vsevolod Stakhov
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
#include "contrib/kann/kann.h"

/***
 * @module rspamd_kann
 * `rspamd_kann` is a Lua interface to kann library
 */

#define KANN_NODE_CLASS "rspamd{kann_node}"
#define KANN_NETWORK_CLASS "rspamd{kann}"

/* Simple macros to define behaviour */
#define KANN_LAYER_DEF(name) static int lua_kann_layer_ ## name (lua_State *L)
#define KANN_LAYER_INTERFACE(name) {#name, lua_kann_layer_ ## name}

#define KANN_TRANSFORM_DEF(name) static int lua_kann_transform_ ## name (lua_State *L)
#define KANN_TRANSFORM_INTERFACE(name) {#name, lua_kann_transform_ ## name}

#define KANN_LOSS_DEF(name) static int lua_kann_loss_ ## name (lua_State *L)
#define KANN_LOSS_INTERFACE(name) {#name, lua_kann_loss_ ## name}

#define KANN_NEW_DEF(name) static int lua_kann_new_ ## name (lua_State *L)
#define KANN_NEW_INTERFACE(name) {#name, lua_kann_new_ ## name}


/*
 * Forwarded declarations
 */
static kad_node_t *lua_check_kann_node (lua_State *L, int pos);

/* Layers */
KANN_LAYER_DEF(input);
KANN_LAYER_DEF(dense);
KANN_LAYER_DEF(layernorm);
KANN_LAYER_DEF(rnn);
KANN_LAYER_DEF(lstm);
KANN_LAYER_DEF(gru);
KANN_LAYER_DEF(conv2d);
KANN_LAYER_DEF(conv1d);
KANN_LAYER_DEF(cost);

static luaL_reg rspamd_kann_layers_f[] = {
		KANN_LAYER_INTERFACE(input),
		KANN_LAYER_INTERFACE(dense),
		KANN_LAYER_INTERFACE(layernorm),
		KANN_LAYER_INTERFACE(rnn),
		KANN_LAYER_INTERFACE(lstm),
		KANN_LAYER_INTERFACE(gru),
		KANN_LAYER_INTERFACE(conv2d),
		KANN_LAYER_INTERFACE(conv1d),
		KANN_LAYER_INTERFACE(cost),
		{NULL, NULL},
};

/* Transition and composition functions */

/* General transform */
KANN_TRANSFORM_DEF (add);
KANN_TRANSFORM_DEF (sub);
KANN_TRANSFORM_DEF (mul);
KANN_TRANSFORM_DEF (cmul);
KANN_TRANSFORM_DEF (matmul);

KANN_TRANSFORM_DEF (square);
KANN_TRANSFORM_DEF (sigm);
KANN_TRANSFORM_DEF (tanh);
KANN_TRANSFORM_DEF (relu);
KANN_TRANSFORM_DEF (softmax);
KANN_TRANSFORM_DEF (1minus);
KANN_TRANSFORM_DEF (exp);
KANN_TRANSFORM_DEF (log);
KANN_TRANSFORM_DEF (sin);
static luaL_reg rspamd_kann_transform_f[] = {
		KANN_TRANSFORM_INTERFACE (add),
		KANN_TRANSFORM_INTERFACE (sub),
		KANN_TRANSFORM_INTERFACE (mul),
		KANN_TRANSFORM_INTERFACE (cmul),
		KANN_TRANSFORM_INTERFACE (matmul),

		KANN_TRANSFORM_INTERFACE (square),
		KANN_TRANSFORM_INTERFACE (sigm),
		KANN_TRANSFORM_INTERFACE (tanh),
		KANN_TRANSFORM_INTERFACE (relu),
		KANN_TRANSFORM_INTERFACE (softmax),
		KANN_TRANSFORM_INTERFACE (1minus),
		KANN_TRANSFORM_INTERFACE (exp),
		KANN_TRANSFORM_INTERFACE (log),
		KANN_TRANSFORM_INTERFACE (sin),
		{NULL, NULL},
};

/* Loss functions */
KANN_LOSS_DEF (mse);
KANN_LOSS_DEF (ce_multi);
KANN_LOSS_DEF (ce_bin);
KANN_LOSS_DEF (ce_bin_neg);
KANN_LOSS_DEF (ce_multi_weighted);
static luaL_reg rspamd_kann_loss_f[] = {
		KANN_LOSS_INTERFACE (mse),
		KANN_LOSS_INTERFACE (ce_multi),
		KANN_LOSS_INTERFACE (ce_bin),
		KANN_LOSS_INTERFACE (ce_bin_neg),
		KANN_LOSS_INTERFACE (ce_multi_weighted),
		{NULL, NULL},
};

/* Creation functions */
KANN_NEW_DEF (leaf);
KANN_NEW_DEF (scalar);
KANN_NEW_DEF (weight);
KANN_NEW_DEF (bias);
KANN_NEW_DEF (weight_conv2d);
KANN_NEW_DEF (weight_conv1d);
KANN_NEW_DEF (kann);

static luaL_reg rspamd_kann_new_f[] = {
		KANN_NEW_INTERFACE (leaf),
		KANN_NEW_INTERFACE (scalar),
		KANN_NEW_INTERFACE (weight),
		KANN_NEW_INTERFACE (bias),
		KANN_NEW_INTERFACE (weight_conv2d),
		KANN_NEW_INTERFACE (weight_conv1d),
		KANN_NEW_INTERFACE (kann),
		{NULL, NULL},
};

static int
rspamd_kann_table_to_flags (lua_State *L, int table_pos)
{
	int result = 0;

	lua_pushvalue (L, table_pos);

	for (lua_pushnil (L); lua_next (L, -2); lua_pop (L, 1)) {
		int fl = lua_tointeger (L, -1);

		result |= fl;
	}

	lua_pop (L, 1);

	return result;
}

static gint
lua_load_kann (lua_State * L)
{
	lua_newtable (L);

	/* Flags */
	lua_pushstring (L, "flag");
	lua_newtable (L);
	lua_pushinteger (L, KANN_F_IN);
	lua_setfield (L, -2, "in");
	lua_pushinteger (L, KANN_F_COST);
	lua_setfield (L, -2, "cost");
	lua_pushinteger (L, KANN_F_OUT);
	lua_setfield (L, -2, "out");
	lua_pushinteger (L, KANN_F_TRUTH);
	lua_setfield (L, -2, "truth");
	lua_settable (L, -3);

	/* Cost type */
	lua_pushstring (L, "cost");
	lua_newtable (L);
	/* binary cross-entropy cost, used with sigmoid */
	lua_pushinteger (L, KANN_C_CEB);
	lua_setfield (L, -2, "ceb");
	/* multi-class cross-entropy cost, used with softmax */
	lua_pushinteger (L, KANN_C_CEM);
	lua_setfield (L, -2, "cem");
	/* binary cross-entropy-like cost, used with tanh */
	lua_pushinteger (L, KANN_C_CEB_NEG);
	lua_setfield (L, -2, "ceb_neg");
	lua_pushinteger (L, KANN_C_MSE);
	lua_setfield (L, -2, "mse");
	lua_settable (L, -3);

	/* RNN flag */
	lua_pushstring (L, "rnn");
	lua_newtable (L);
	/* apply layer normalization */
	lua_pushinteger (L, KANN_RNN_NORM);
	lua_setfield (L, -2, "norm");
	/* take the initial hidden values as variables */
	lua_pushinteger (L, KANN_RNN_VAR_H0);
	lua_setfield (L, -2, "var_h0");
	lua_settable (L, -3);

	/* Layers */
	lua_pushstring (L, "layer");
	lua_newtable (L);
	luaL_register (L, NULL, rspamd_kann_layers_f);
	lua_settable (L, -3);

	/* Transforms */
	lua_pushstring (L, "transform");
	lua_newtable (L);
	luaL_register (L, NULL, rspamd_kann_transform_f);
	lua_settable (L, -3);

	/* Cost */
	lua_pushstring (L, "loss");
	lua_newtable (L);
	luaL_register (L, NULL, rspamd_kann_loss_f);
	lua_settable (L, -3);

	/* Create functions */
	lua_pushstring (L, "new");
	lua_newtable (L);
	luaL_register (L, NULL, rspamd_kann_new_f);
	lua_settable (L, -3);

	return 1;
}

static kad_node_t *
lua_check_kann_node (lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, KANN_NODE_CLASS);
	luaL_argcheck (L, ud != NULL, pos, "'kann_node' expected");
	return ud ? *((kad_node_t **)ud) : NULL;
}

void luaopen_kann (lua_State *L)
{
	/* Metatables */
	rspamd_lua_new_class (L, KANN_NODE_CLASS, NULL); /* TODO: add methods */
	lua_pop (L, 1); /* No need in metatable... */
	rspamd_lua_new_class (L, KANN_NETWORK_CLASS, NULL); /* TODO: add methods */
	lua_pop (L, 1); /* No need in metatable... */
	rspamd_lua_add_preload (L, "rspamd_kann", lua_load_kann);
	lua_settop (L, 0);
}

/* Layers implementation */
#define PUSH_KAD_NODE(n) do { \
	kad_node_t **pt; \
	pt = lua_newuserdata (L, sizeof (kad_node_t *)); \
	*pt = (n); \
	rspamd_lua_setclass (L, KANN_NODE_CLASS, -1); \
} while(0)

#define PUSH_KAN_NETWORK(n) do { \
	kann_t **pn; \
	pn = lua_newuserdata (L, sizeof (kann_t *)); \
	*pn = (n); \
	rspamd_lua_setclass (L, KANN_NETWORK_CLASS, -1); \
} while(0)

#define PROCESS_KAD_FLAGS(n, pos) do { \
	int fl = 0; \
	if (lua_type(L, (pos)) == LUA_TTABLE) { fl = rspamd_kann_table_to_flags (L, (pos)); } \
	else if (lua_type(L, (pos)) == LUA_TNUMBER) { fl = lua_tointeger (L, (pos)); } \
	(n)->ext_flag = fl; \
}while(0)

static int
lua_kann_layer_input (lua_State *L)
{
	gint nnodes = luaL_checkinteger (L, 1);

	if (nnodes > 0) {
		kad_node_t *t;

		t = kann_layer_input (nnodes);

		PROCESS_KAD_FLAGS (t, 2);
		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments, nnodes required");
	}

	return 1;
}

static int
lua_kann_layer_dense (lua_State *L)
{
	kad_node_t *in = lua_check_kann_node (L, 1);
	gint nnodes = luaL_checkinteger (L, 2);

	if (in != NULL && nnodes > 0) {
		kad_node_t *t;

		t = kann_layer_dense (in, nnodes);

		PROCESS_KAD_FLAGS (t, 3);
		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments, input + nnodes required");
	}

	return 1;
}

static int
lua_kann_layer_layerdropout (lua_State *L)
{
	kad_node_t *in = lua_check_kann_node (L, 1);
	double r = luaL_checknumber (L, 2);

	if (in != NULL) {
		kad_node_t *t;

		t = kann_layer_dropout (in, r);

		PROCESS_KAD_FLAGS (t, 3);
		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments, input + rate required");
	}

	return 1;
}

static int
lua_kann_layer_layernorm (lua_State *L)
{
	kad_node_t *in = lua_check_kann_node (L, 1);

	if (in != NULL) {
		kad_node_t *t;

		t = kann_layer_layernorm (in);

		PROCESS_KAD_FLAGS (t, 2);
		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments, input required");
	}

	return 1;
}

static int
lua_kann_layer_rnn (lua_State *L)
{
	kad_node_t *in = lua_check_kann_node (L, 1);
	gint nnodes = luaL_checkinteger (L, 2);
	gint rnnflags = 0;

	if (in != NULL && nnodes > 0) {
		kad_node_t *t;

		if (lua_type (L, 3) == LUA_TNUMBER) {
			rnnflags = lua_tointeger (L, 3);
		}

		t = kann_layer_rnn (in, nnodes, rnnflags);

		PROCESS_KAD_FLAGS (t, 4);
		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments, input + nnodes required");
	}

	return 1;
}

static int
lua_kann_layer_lstm (lua_State *L)
{
	kad_node_t *in = lua_check_kann_node (L, 1);
	gint nnodes = luaL_checkinteger (L, 2);
	gint rnnflags = 0;

	if (in != NULL && nnodes > 0) {
		kad_node_t *t;

		if (lua_type (L, 3) == LUA_TNUMBER) {
			rnnflags = lua_tointeger (L, 3);
		}

		t = kann_layer_lstm (in, nnodes, rnnflags);

		PROCESS_KAD_FLAGS (t, 4);
		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments, input + nnodes required");
	}

	return 1;
}

static int
lua_kann_layer_gru (lua_State *L)
{
	kad_node_t *in = lua_check_kann_node (L, 1);
	gint nnodes = luaL_checkinteger (L, 2);
	gint rnnflags = 0;

	if (in != NULL && nnodes > 0) {
		kad_node_t *t;

		if (lua_type (L, 3) == LUA_TNUMBER) {
			rnnflags = lua_tointeger (L, 3);
		}

		t = kann_layer_gru (in, nnodes, rnnflags);

		PROCESS_KAD_FLAGS (t, 4);
		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments, input + nnodes required");
	}

	return 1;
}

static int
lua_kann_layer_conv2d (lua_State *L)
{
	kad_node_t *in = lua_check_kann_node (L, 1);
	int n_flt = luaL_checkinteger (L, 2);
	int k_rows = luaL_checkinteger (L, 3);
	int k_cols =  luaL_checkinteger (L, 4);
	int stride_r = luaL_checkinteger (L, 5);
	int stride_c = luaL_checkinteger (L, 6);
	int pad_r = luaL_checkinteger (L, 7);
	int pad_c = luaL_checkinteger (L, 8);

	if (in != NULL) {
		kad_node_t *t;
		t = kann_layer_conv2d (in, n_flt, k_rows, k_cols, stride_r, stride_c,
				pad_r, pad_c);

		PROCESS_KAD_FLAGS (t, 9);
		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments, input, nflt, kx, ky, stridex, stridey, padx, pady are required");
	}

	return 1;
}

static int
lua_kann_layer_conv1d (lua_State *L)
{
	kad_node_t *in = lua_check_kann_node (L, 1);
	int n_flt = luaL_checkinteger (L, 2);
	int k_size = luaL_checkinteger (L, 3);
	int stride = luaL_checkinteger (L, 4);
	int pad = luaL_checkinteger (L, 5);

	if (in != NULL) {
		kad_node_t *t;
		t = kann_layer_conv1d (in, n_flt, k_size, stride, pad);

		PROCESS_KAD_FLAGS (t, 6);
		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments, input, nflt, k, stride, pad required");
	}

	return 1;
}

static int
lua_kann_layer_cost (lua_State *L)
{
	kad_node_t *in = lua_check_kann_node (L, 1);
	int nout = luaL_checkinteger (L, 2);
	int cost_type = luaL_checkinteger (L, 3);

	if (in != NULL && nout > 0) {
		kad_node_t *t;
		t = kann_layer_cost (in, nout, cost_type);

		PROCESS_KAD_FLAGS (t, 4);
		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments, input, nout and cost_type are required");
	}

	return 1;
}

/* Generic helpers */
static int
lua_kann_call_unary_function (lua_State *L, const char *name,
		kad_node_t *(*func)(kad_node_t *))
{
	kad_node_t *in = lua_check_kann_node (L, 1);

	if (in != NULL) {
		kad_node_t *t;
		t = func (in);

		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments for %s, input required", name);
	}

	return 1;
}
static int
lua_kann_call_binary_function (lua_State *L, const char *name,
							  kad_node_t *(*func)(kad_node_t *, kad_node_t *))
{
	kad_node_t *x = lua_check_kann_node (L, 1);
	kad_node_t *y = lua_check_kann_node (L, 2);

	if (x != NULL && y != NULL) {
		kad_node_t *t;
		t = func (x, y);

		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments for %s, 2 inputs required", name);
	}

	return 1;
}

#define LUA_UNARY_TRANSFORM_FUNC_IMPL(name)									\
static int lua_kann_transform_ ##name (lua_State *L)						\
{																			\
	return lua_kann_call_unary_function(L, #name, kad_##name);				\
}

#define LUA_BINARY_TRANSFORM_FUNC_IMPL(name)								\
static int lua_kann_transform_ ##name (lua_State *L)						\
{																			\
	return lua_kann_call_binary_function(L, #name, kad_##name);				\
}

#define LUA_LOSS_FUNC_IMPL(name)											\
static int lua_kann_loss_ ##name (lua_State *L)								\
{																			\
	return lua_kann_call_binary_function(L, #name, kad_##name);				\
}

/* Transform functions registered via macro helpers */
LUA_BINARY_TRANSFORM_FUNC_IMPL (add)
LUA_BINARY_TRANSFORM_FUNC_IMPL (sub)
LUA_BINARY_TRANSFORM_FUNC_IMPL (mul)
LUA_BINARY_TRANSFORM_FUNC_IMPL (cmul)
LUA_BINARY_TRANSFORM_FUNC_IMPL (matmul)

LUA_UNARY_TRANSFORM_FUNC_IMPL (square)
LUA_UNARY_TRANSFORM_FUNC_IMPL (sigm)
LUA_UNARY_TRANSFORM_FUNC_IMPL (tanh)
LUA_UNARY_TRANSFORM_FUNC_IMPL (relu)
LUA_UNARY_TRANSFORM_FUNC_IMPL (softmax)
LUA_UNARY_TRANSFORM_FUNC_IMPL (1minus)
LUA_UNARY_TRANSFORM_FUNC_IMPL (exp)
LUA_UNARY_TRANSFORM_FUNC_IMPL (log)
LUA_UNARY_TRANSFORM_FUNC_IMPL (sin)

/* Generic cost functions */
LUA_LOSS_FUNC_IMPL (mse)
LUA_LOSS_FUNC_IMPL (ce_multi)
LUA_LOSS_FUNC_IMPL (ce_bin)
LUA_LOSS_FUNC_IMPL (ce_bin_neg)

/* The only case of ternary weight function */
static int
lua_kann_loss_ce_multi_weighted (lua_State *L)
{
	kad_node_t *pred = lua_check_kann_node (L, 1);
	kad_node_t *truth = lua_check_kann_node (L, 2);
	kad_node_t *weight = lua_check_kann_node (L, 3);

	if (pred != NULL && truth != NULL && weight != NULL) {
		kad_node_t *t;
		t = kad_ce_multi_weighted (pred, truth, weight);

		PUSH_KAD_NODE (t);
	}
	else {
		return luaL_error (L, "invalid arguments for ce_multi_weighted, 3 inputs required");
	}

	return 1;
}

/* Creation functions */
static int
lua_kann_new_scalar (lua_State *L)
{
	gint flag = luaL_checkinteger (L, 1);
	double x = luaL_checknumber (L, 2);
	kad_node_t *t;

	t = kann_new_scalar (flag, x);

	PROCESS_KAD_FLAGS (t, 3);
	PUSH_KAD_NODE (t);

	return 1;
}

static int
lua_kann_new_weight (lua_State *L)
{
	gint nrow = luaL_checkinteger (L, 1);
	gint ncol = luaL_checkinteger (L, 2);
	kad_node_t *t;

	t = kann_new_weight (nrow, ncol);

	PROCESS_KAD_FLAGS (t, 3);
	PUSH_KAD_NODE (t);

	return 1;
}

static int
lua_kann_new_bias (lua_State *L)
{
	gint n = luaL_checkinteger (L, 1);
	kad_node_t *t;

	t = kann_new_bias (n);

	PROCESS_KAD_FLAGS (t, 2);
	PUSH_KAD_NODE (t);

	return 1;
}

static int
lua_kann_new_weight_conv2d (lua_State *L)
{
	gint nout = luaL_checkinteger (L, 1);
	gint nin = luaL_checkinteger (L, 2);
	gint krow = luaL_checkinteger (L, 3);
	gint kcol = luaL_checkinteger (L, 4);
	kad_node_t *t;

	t = kann_new_weight_conv2d (nout, nin, krow, kcol);

	PROCESS_KAD_FLAGS (t, 5);
	PUSH_KAD_NODE (t);

	return 1;
}

static int
lua_kann_new_weight_conv1d (lua_State *L)
{
	gint nout = luaL_checkinteger (L, 1);
	gint nin = luaL_checkinteger (L, 2);
	gint klen = luaL_checkinteger (L, 3);
	kad_node_t *t;

	t = kann_new_weight_conv1d (nout, nin, klen);

	PROCESS_KAD_FLAGS (t, 4);
	PUSH_KAD_NODE (t);

	return 1;
}

static int
lua_kann_new_leaf (lua_State *L)
{
	gint dim = luaL_checkinteger (L, 1), i, *ar;
	kad_node_t *t;

	if (dim >= 1 && dim < KAD_MAX_DIM && lua_istable (L, 2)) {
		ar = g_malloc0 (sizeof (ar) * dim);

		for (i = 0; i < dim; i ++) {
			lua_rawgeti (L, 2, i + 1);
			ar[i] = lua_tointeger (L, -1);
			lua_pop (L, 1);
		}

		t = kann_new_leaf_array (NULL, NULL, 0, 0.0, dim, ar);

		PROCESS_KAD_FLAGS (t, 3);
		PUSH_KAD_NODE (t);

		g_free (ar);
	}
	else {
		return luaL_error (L, "invalid arguments for new.leaf, "
						"dim and vector of elements are required");
	}

	return 1;
}

static int
lua_kann_new_kann (lua_State *L)
{
	kad_node_t *cost = lua_check_kann_node (L, 1);
	kann_t *k;

	if (cost) {
		k = kann_new (cost, 0);

		PUSH_KAN_NETWORK (k);
	}
	else {
		return luaL_error (L, "invalid arguments for new.kann, "
							  "cost node is required");
	}

	return 1;
}
