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
#include "lua_tensor.h"
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

LUA_FUNCTION_DEF (kann, load);
LUA_FUNCTION_DEF (kann, destroy);
LUA_FUNCTION_DEF (kann, save);
LUA_FUNCTION_DEF (kann, train1);
LUA_FUNCTION_DEF (kann, apply1);

static luaL_reg rspamd_kann_m[] = {
		LUA_INTERFACE_DEF (kann, save),
		LUA_INTERFACE_DEF (kann, train1),
		LUA_INTERFACE_DEF (kann, apply1),
		{"__gc", lua_kann_destroy},
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

	/* Load ann from memory or file */
	lua_pushstring (L, "load");
	lua_pushcfunction (L, lua_kann_load);
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

static kann_t *
lua_check_kann (lua_State *L, int pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, KANN_NETWORK_CLASS);
	luaL_argcheck (L, ud != NULL, pos, "'kann' expected");
	return ud ? *((kann_t **)ud) : NULL;
}

void luaopen_kann (lua_State *L)
{
	/* Metatables */
	rspamd_lua_new_class (L, KANN_NODE_CLASS, NULL); /* TODO: add methods */
	lua_pop (L, 1); /* No need in metatable... */
	rspamd_lua_new_class (L, KANN_NETWORK_CLASS, rspamd_kann_m);
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
	(n)->ext_flag |= fl; \
}while(0)

/***
 * @function kann.layer.input(ninputs[, flags])
 * Creates an input layer for ANN
 * @param {int} ninputs number of inputs
 * @param {table|int} flags optional flags
 * @return {kann_node} kann node object (should be used to combine ANN)
*/
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

/***
 * @function kann.layer.dense(in, ninputs[, flags])
 * Creates a dense layer (e.g. for hidden layer)
 * @param {kann_node} in kann node
 * @param {int} ninputs number of dense nodes
 * @param {table|int} flags optional flags
 * @return {kann_node} kann node object (should be used to combine ANN)
*/
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

/***
 * @function kann.layer.dropout(in, ratio[, flags])
 * Creates a dropout layer
 * @param {kann_node} in kann node
 * @param {float} ratio drop ratio
 * @param {table|int} flags optional flags
 * @return {kann_node} kann node object (should be used to combine ANN)
*/
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

/***
 * @function kann.layer.dropout(in [, flags])
 * Creates a normalisation layer
 * @param {kann_node} in kann node
 * @param {table|int} flags optional flags
 * @return {kann_node} kann node object (should be used to combine ANN)
*/
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

/***
 * @function kann.layer.rnn(in, nnodes[, rnn_flags, [, flags]])
 * Creates a recursive NN layer
 * @param {kann_node} in kann node
 * @param {int} nnodes number of cells
 * @param {int} rnnflags rnn flags
 * @param {table|int} flags optional flags
 * @return {kann_node} kann node object (should be used to combine ANN)
*/
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

/***
 * @function kann.layer.lstm(in, nnodes[, rnn_flags, [, flags]])
 * Creates a recursive NN layer using LSTM cells
 * @param {kann_node} in kann node
 * @param {int} nnodes number of cells
 * @param {int} rnnflags rnn flags
 * @param {table|int} flags optional flags
 * @return {kann_node} kann node object (should be used to combine ANN)
*/
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

/***
 * @function kann.layer.rnn(in, nnodes[, rnn_flags, [, flags]])
 * Creates a recursive NN layer using GRU cells
 * @param {kann_node} in kann node
 * @param {int} nnodes number of cells
 * @param {int} rnnflags rnn flags
 * @param {table|int} flags optional flags
 * @return {kann_node} kann node object (should be used to combine ANN)
*/
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

/***
 * @function kann.layer.conv2d(in, n_flt, k_rows, k_cols, stride_rows, stride_cols, pad_rows, pad_columns[, flags])
 * Creates a 2D convolution layer
 * @param {kann_node} in kann node
 * @param {int} n_flt number of filters
 * @param {int} k_rows kernel rows
 * @param {int} k_cols kernel columns
 * @param {int} stride_rows stride rows
 * @param {int} stride_cols stride columns
 * @param {int} pad_rows padding rows
 * @param {int} pad_columns padding columns
 * @param {table|int} flags optional flags
 * @return {kann_node} kann node object (should be used to combine ANN)
*/
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

/***
 * @function kann.layer.conv1d(in, n_flt, kern_size, stride_size, pad_size[, flags])
 * Creates 1D convolution layer
 * @param {kann_node} in kann node
 * @param {int} n_flt number of filters
 * @param {int} kern_size kernel rows
 * @param {int} stride_size stride rows
 * @param {int} pad_size padding rows
 * @param {table|int} flags optional flags
 * @return {kann_node} kann node object (should be used to combine ANN)
*/
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

/***
 * @function kann.layer.cost(in, nout, cost_type[, flags])
 * Creates 1D convolution layer
 * @param {kann_node} in kann node
 * @param {int} nout number of outputs
 * @param {int} cost_type see kann.cost table
 * @param {table|int} flags optional flags
 * @return {kann_node} kann node object (should be used to combine ANN)
*/
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
	int dim = luaL_checkinteger (L, 1), i, *ar;
	kad_node_t *t;

	if (dim >= 1 && dim < KAD_MAX_DIM && lua_istable (L, 2)) {
		ar = g_new0 (int, dim);

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

static int
lua_kann_destroy (lua_State *L)
{
	kann_t *k = lua_check_kann (L, 1);

	kann_delete (k);

	return 0;
}

static int
lua_kann_save (lua_State *L)
{
	kann_t *k = lua_check_kann (L, 1);

	if (k) {
		if (lua_istable (L, 2)) {
			lua_getfield (L, 2, "filename");

			if (lua_isstring (L, -1)) {
				const gchar *fname = lua_tostring (L, -1);
				FILE *f;

				f = fopen (fname, "w");

				if (!f) {
					lua_pop (L, 1);

					return luaL_error (L, "cannot open %s for writing: %s",
							fname, strerror (errno));
				}

				kann_save_fp (f, k);
				fclose (f);

				lua_pushboolean (L, true);
			}
			else {
				lua_pop (L, 1);

				return luaL_error (L, "invalid arguments: missing filename");
			}

			lua_pop (L, 1);
		}
		else {
			/* Save to Rspamd text */
#ifndef HAVE_OPENMEMSTREAM
			return luaL_error (L, "no support of saving to memory on your system");
#endif
			FILE *f;
			char *buf = NULL;
			size_t buflen;
			struct rspamd_lua_text *t;

			f = open_memstream (&buf, &buflen);
			g_assert (f != NULL);

			kann_save_fp (f, k);
			fclose (f);

			t = lua_newuserdata (L, sizeof (*t));
			rspamd_lua_setclass (L, "rspamd{text}", -1);
			t->flags = RSPAMD_TEXT_FLAG_OWN;
			t->start = (const gchar *)buf;
			t->len = buflen;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 1;
}

static int
lua_kann_load (lua_State *L)
{
	kann_t *k;
	FILE *f = NULL;

	if (lua_istable (L, 1)) {
		lua_getfield (L, 2, "filename");

		if (lua_isstring (L, -1)) {
			const gchar *fname = lua_tostring (L, -1);

			f = fopen (fname, "rb");
		}
		else {
			lua_pop (L, 1);

			return luaL_error (L, "invalid arguments: missing filename");
		}

		lua_pop (L, 1);
	}
	else if (lua_isstring (L, 1)) {
		gsize dlen;
		const gchar *data;

		data = lua_tolstring (L, 1, &dlen);

#ifndef HAVE_FMEMOPEN
		return luaL_error (L, "no support of loading from memory on your system");
#endif
		f = fmemopen ((void *)data, dlen, "rb");
	}
	else if (lua_isuserdata (L, 1)) {
		struct rspamd_lua_text *t;

		t = lua_check_text (L, 1);

		if (!t) {
			return luaL_error (L, "invalid arguments");
		}

#ifndef HAVE_FMEMOPEN
		return luaL_error (L, "no support of loading from memory on your system");
#endif
		f = fmemopen ((void *)t->start, t->len, "rb");
	}

	if (f == NULL) {
		return luaL_error (L, "invalid arguments or cannot open file");
	}

	k = kann_load_fp (f);
	fclose (f);

	if (k == NULL) {
		lua_pushnil (L);
	}
	else {
		PUSH_KAN_NETWORK (k);
	}

	return 1;
}

struct rspamd_kann_train_cbdata {
	lua_State *L;
	kann_t *k;
	gint cbref;
};

static void
lua_kann_train_cb (int iter, float train_cost, float val_cost, void *ud)
{
	struct rspamd_kann_train_cbdata *cbd = (struct rspamd_kann_train_cbdata *)ud;

	if (cbd->cbref != -1) {
		gint err_idx;
		lua_State *L = cbd->L;

		lua_pushcfunction (L, &rspamd_lua_traceback);
		err_idx = lua_gettop (L);

		lua_rawgeti (L, LUA_REGISTRYINDEX, cbd->cbref);
		lua_pushinteger (L, iter);
		lua_pushnumber (L, train_cost);
		lua_pushnumber (L, val_cost);

		if (lua_pcall (L, 3, 0, err_idx) != 0) {
			msg_err ("cannot run lua train callback: %s",
					lua_tostring (L, -1));
		}

		lua_settop (L, err_idx - 1);
	}
}

#define FREE_VEC(a, n) do { for(int i = 0; i < (n); i ++) g_free((a)[i]); g_free(a); } while(0)

static int
lua_kann_train1 (lua_State *L)
{
	kann_t *k = lua_check_kann (L, 1);
	struct rspamd_lua_tensor *pca = NULL;

	/* Default train params */
	double lr = 0.001;
	gint64 mini_size = 64;
	gint64 max_epoch = 25;
	gint64 max_drop_streak = 10;
	double frac_val = 0.1;
	gint cbref = -1;

	if (k && lua_istable (L, 2) && lua_istable (L, 3)) {
		int n = rspamd_lua_table_size (L, 2);
		int n_in = kann_dim_in (k);
		int n_out = kann_dim_out (k);

		if (n_in <= 0) {
			return luaL_error (L, "invalid inputs count: %d", n_in);
		}

		if (n_out <= 0) {
			return luaL_error (L, "invalid outputs count: %d", n_out);
		}

		if (n != rspamd_lua_table_size (L, 3) || n == 0) {
			return luaL_error (L, "invalid dimensions: outputs size must be "
						 "equal to inputs and non zero");
		}

		if (lua_istable (L, 4)) {
			GError *err = NULL;

			if (!rspamd_lua_parse_table_arguments (L, 4, &err,
					RSPAMD_LUA_PARSE_ARGUMENTS_IGNORE_MISSING,
					"lr=N;mini_size=I;max_epoch=I;max_drop_streak=I;frac_val=N;cb=F;pca=u{tensor}",
					&lr, &mini_size, &max_epoch, &max_drop_streak, &frac_val, &cbref, &pca)) {
				n = luaL_error (L, "invalid params: %s",
						err ? err->message : "unknown error");
				g_error_free (err);

				return n;
			}
		}

		if (pca) {
			/* Check pca matrix validity */
			if (pca->ndims != 2) {
				return luaL_error (L, "invalid pca tensor: matrix expected, got a row");
			}

			if (pca->dim[0] != n_in) {
				return luaL_error (L, "invalid pca tensor: "
						  "matrix must have %d rows and it has %d rows instead",
						  n_in, pca->dim[0]);
			}
		}

		float **x, **y, *tmp_row = NULL;

		/* Fill vectors row by row */
		x = (float **)g_malloc0 (sizeof (float *) * n);
		y = (float **)g_malloc0 (sizeof (float *) * n);

		if (pca) {
			tmp_row = g_malloc (sizeof (float) * pca->dim[1]);
		}

		for (int s = 0; s < n; s ++) {
			/* Inputs */
			lua_rawgeti (L, 2, s + 1);
			x[s] = (float *)g_malloc (sizeof (float) * n_in);

			if (pca == NULL) {
				if (rspamd_lua_table_size (L, -1) != n_in) {
					FREE_VEC (x, n);
					FREE_VEC (y, n);

					n = luaL_error (L, "invalid params at pos %d: "
									   "bad input dimension %d; %d expected",
							s + 1,
							(int) rspamd_lua_table_size (L, -1),
							n_in);
					lua_pop (L, 1);

					return n;
				}

				for (int i = 0; i < n_in; i++) {
					lua_rawgeti (L, -1, i + 1);
					x[s][i] = lua_tonumber (L, -1);

					lua_pop (L, 1);
				}
			}
			else {
				if (rspamd_lua_table_size (L, -1) != pca->dim[1]) {
					FREE_VEC (x, n);
					FREE_VEC (y, n);
					g_free (tmp_row);

					n = luaL_error (L, "(pca on) invalid params at pos %d: "
									   "bad input dimension %d; %d expected",
							s + 1,
							(int) rspamd_lua_table_size (L, -1),
							pca->dim[1]);
					lua_pop (L, 1);

					return n;
				}


				for (int i = 0; i < pca->dim[1]; i++) {
					lua_rawgeti (L, -1, i + 1);
					tmp_row[i] = lua_tonumber (L, -1);

					lua_pop (L, 1);
				}

				kad_sgemm_simple (0, 1, 1, n_in,
						pca->dim[1], tmp_row, pca->data,
						x[s]);
			}

			lua_pop (L, 1);

			/* Outputs */
			y[s] = (float *)g_malloc (sizeof (float) * n_out);
			lua_rawgeti (L, 3, s + 1);

			if (rspamd_lua_table_size (L, -1) != n_out) {
				FREE_VEC (x, n);
				FREE_VEC (y, n);
				g_free (tmp_row);

				n = luaL_error (L, "invalid params at pos %d: "
					   "bad output dimension %d; "
					   "%d expected",
						s + 1,
						(int)rspamd_lua_table_size (L, -1),
						n_out);
				lua_pop (L, 1);

				return n;
			}

			for (int i = 0; i < n_out; i ++) {
				lua_rawgeti (L, -1, i + 1);
				y[s][i] = lua_tonumber (L, -1);

				lua_pop (L, 1);
			}

			lua_pop (L, 1);
		}

		struct rspamd_kann_train_cbdata cbd;

		cbd.cbref = cbref;
		cbd.k = k;
		cbd.L = L;

		int niters = kann_train_fnn1 (k, lr,
				mini_size, max_epoch, max_drop_streak,
				frac_val, n, x, y, lua_kann_train_cb, &cbd);

		lua_pushinteger (L, niters);

		FREE_VEC (x, n);
		FREE_VEC (y, n);
		g_free (tmp_row);
	}
	else {
		return luaL_error (L, "invalid arguments: kann, inputs, outputs and"
							  " optional params are expected");
	}

	return 1;
}

static int
lua_kann_apply1 (lua_State *L)
{
	kann_t *k = lua_check_kann (L, 1);
	struct rspamd_lua_tensor *pca = NULL;

	if (k) {
		if (lua_istable (L, 2)) {
			gsize vec_len = rspamd_lua_table_size (L, 2);
			float *vec = (float *) g_malloc (sizeof (float) * vec_len),
				*pca_out = NULL;
			int i_out;
			int n_in = kann_dim_in (k);

			if (n_in <= 0) {
				g_free (vec);
				return luaL_error (L, "invalid inputs count: %d", n_in);
			}

			if (lua_isuserdata (L, 3)) {
				pca = lua_check_tensor (L, 3);

				if (pca) {
					if (pca->ndims != 2) {
						g_free (vec);
						return luaL_error (L, "invalid pca tensor: matrix expected, got a row");
					}

					if (pca->dim[0] != n_in) {
						g_free (vec);
						return luaL_error (L, "invalid pca tensor: "
											  "matrix must have %d rows and it has %d rows instead",
								n_in, pca->dim[0]);
					}
				}
				else {
					g_free (vec);
					return luaL_error (L, "invalid params: pca matrix expected");
				}
			}
			else {
				if (n_in != vec_len) {
					g_free (vec);
					return luaL_error (L, "invalid params: bad input dimension %d; %d expected",
							(int) vec_len, n_in);
				}
			}

			for (gsize i = 0; i < vec_len; i++) {
				lua_rawgeti (L, 2, i + 1);
				vec[i] = lua_tonumber (L, -1);
				lua_pop (L, 1);
			}

			i_out = kann_find (k, KANN_F_OUT, 0);

			if (i_out <= 0) {
				g_free (vec);
				return luaL_error (L, "invalid ANN: output layer is missing or is "
									  "at the input pos");
			}

			kann_set_batch_size (k, 1);
			if (pca) {
				pca_out = g_malloc (sizeof (float) * n_in);

				kad_sgemm_simple (0, 1, 1, n_in,
						vec_len, vec, pca->data,
						pca_out);

				kann_feed_bind (k, KANN_F_IN, 0, &pca_out);
			}
			else {
				kann_feed_bind (k, KANN_F_IN, 0, &vec);
			}

			kad_eval_at (k->n, k->v, i_out);

			gsize outlen = kad_len (k->v[i_out]);
			lua_createtable (L, outlen, 0);

			for (gsize i = 0; i < outlen; i++) {
				lua_pushnumber (L, k->v[i_out]->x[i]);
				lua_rawseti (L, -2, i + 1);
			}

			g_free (vec);
			g_free (pca_out);
		}
		else if (lua_isuserdata (L, 2)) {
			struct rspamd_lua_tensor *t = lua_check_tensor (L, 2);

			if (t && t->ndims == 1) {
				int i_out;
				int n_in = kann_dim_in (k);

				if (n_in != t->dim[0]) {
					return luaL_error (L, "invalid params: bad input dimension %d; %d expected",
							(int) t->dim[0], n_in);
				}

				i_out = kann_find (k, KANN_F_OUT, 0);

				if (i_out <= 0) {
					return luaL_error (L, "invalid ANN: output layer is missing or is "
										  "at the input pos");
				}

				kann_set_batch_size (k, 1);
				kann_feed_bind (k, KANN_F_IN, 0, &t->data);
				kad_eval_at (k->n, k->v, i_out);

				gint outlen = kad_len (k->v[i_out]);
				struct rspamd_lua_tensor *out;
				out = lua_newtensor (L, 1, &outlen, false, false);
				/* Ensure that kann and tensor have the same understanding of floats */
				G_STATIC_ASSERT (sizeof (float) == sizeof (rspamd_tensor_num_t));
				memcpy (out->data, k->v[i_out]->x, outlen * sizeof (float));
			}
			else {
				return luaL_error (L, "invalid arguments: 1D rspamd{tensor} expected");
			}
		}
		else {
			return luaL_error (L, "invalid arguments: 1D rspamd{tensor} expected");
		}
	}
	else {
		return luaL_error (L, "invalid arguments: rspamd{kann} expected");
	}

	return 1;
}