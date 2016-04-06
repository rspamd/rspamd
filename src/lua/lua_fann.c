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

#ifdef WITH_FANN
#include <fann.h>
#endif

/***
 * @module rspamd_fann
 * This module enables [fann](http://libfann.github.io) interaction in rspamd
 * Please note, that this module works merely if you have `ENABLE_FANN=ON` option
 * definition when building rspamd
 */

/*
 * Fann functions
 */
LUA_FUNCTION_DEF (fann, is_enabled);
LUA_FUNCTION_DEF (fann, create);
LUA_FUNCTION_DEF (fann, load);

/*
 * Fann methods
 */
LUA_FUNCTION_DEF (fann, train);
LUA_FUNCTION_DEF (fann, test);
LUA_FUNCTION_DEF (fann, save);
LUA_FUNCTION_DEF (fann, get_inputs);
LUA_FUNCTION_DEF (fann, get_outputs);
LUA_FUNCTION_DEF (fann, dtor);

static const struct luaL_reg fannlib_f[] = {
		LUA_INTERFACE_DEF (fann, is_enabled),
		LUA_INTERFACE_DEF (fann, create),
		LUA_INTERFACE_DEF (fann, load),
		{NULL, NULL}
};

static const struct luaL_reg fannlib_m[] = {
		LUA_INTERFACE_DEF (fann, train),
		LUA_INTERFACE_DEF (fann, test),
		LUA_INTERFACE_DEF (fann, save),
		LUA_INTERFACE_DEF (fann, get_inputs),
		LUA_INTERFACE_DEF (fann, get_outputs),
		{"__gc", lua_fann_dtor},
		{"__tostring", rspamd_lua_class_tostring},
		{NULL, NULL}
};

#ifdef WITH_FANN
struct fann *
rspamd_lua_check_fann (lua_State *L, gint pos)
{
	void *ud = luaL_checkudata (L, pos, "rspamd{fann}");
	luaL_argcheck (L, ud != NULL, pos, "'fann' expected");
	return ud ? *((struct fann **) ud) : NULL;
}
#endif

/***
 * @function rspamd_fann.is_enabled()
 * Checks if fann is enabled for this rspamd build
 * @return {boolean} true if fann is enabled
 */
static gint
lua_fann_is_enabled (lua_State *L)
{
#ifdef WITH_FANN
	lua_pushboolean (L, true);
#else
	lua_pushboolean (L, false);
#endif
	return 1;
}

/***
 * @function rspamd_fann.create(nlayers, [layer1, ... layern])
 * Creates new neural network with `nlayers` that contains `layer1`...`layern`
 * neurons in each layer
 * @param {number} nlayers number of layers
 * @param {number} layerI number of neurons in each layer
 * @return {fann} fann object
 */
static gint
lua_fann_create (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f, **pfann;
	guint nlayers, *layers, i;

	nlayers = luaL_checknumber (L, 1);

	if (nlayers > 0) {
		layers = g_malloc (nlayers * sizeof (layers[0]));

		for (i = 0; i < nlayers; i ++) {
			layers[i] = luaL_checknumber (L, i + 2);
		}

		f = fann_create_standard_array (nlayers, layers);

		if (f != NULL) {
			pfann = lua_newuserdata (L, sizeof (gpointer));
			*pfann = f;
			rspamd_lua_setclass (L, "rspamd{fann}", -1);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
#endif
}

/***
 * @function rspamd_fann.load(file)
 * Loads neural network from the file
 * @param {string} file filename where fann is stored
 * @return {fann} fann object
 */
static gint
lua_fann_load (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f, **pfann;
	const gchar *fname;

	fname = luaL_checkstring (L, 1);

	if (fname != NULL) {
		f = fann_create_from_file (fname);

		if (f != NULL) {
			pfann = lua_newuserdata (L, sizeof (gpointer));
			*pfann = f;
			rspamd_lua_setclass (L, "rspamd{fann}", -1);
		}
		else {
			lua_pushnil (L);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
#endif
}


/**
 * @method rspamd_fann:train(inputs, outputs)
 * Trains neural network with samples. Inputs and outputs should be tables of
 * equal size, each row in table should be N inputs and M outputs, e.g.
 *     {0, 1, 1} -> {0}
 * @param {table} inputs input samples
 * @param {table} outputs output samples
 * @return {number} number of samples learned
 */
static gint
lua_fann_train (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f = rspamd_lua_check_fann (L, 1);
	guint ninputs, noutputs, j;
	float *cur_input, *cur_output;
	gboolean ret = FALSE;

	if (f != NULL) {
		/* First check sanity, call for table.getn for that */
		ninputs = rspamd_lua_table_size (L, 2);
		noutputs = rspamd_lua_table_size (L, 3);

		if (ninputs != fann_get_num_input (f) ||
			noutputs != fann_get_num_output (f)) {
			msg_err ("bad number of inputs(%d, expected %d) and "
					"output(%d, expected %d) args for train",
					ninputs, fann_get_num_input (f),
					noutputs, fann_get_num_output (f));
		}
		else {
			cur_input = g_malloc (ninputs * sizeof (gint));

			for (j = 0; j < ninputs; j ++) {
				lua_rawgeti (L, 2, j + 1);
				cur_input[j] = lua_tonumber (L, -1);
				lua_pop (L, 1);
			}

			cur_output = g_malloc (noutputs * sizeof (gint));

			for (j = 0; j < noutputs; j++) {
				lua_rawgeti (L, 3, j + 1);
				cur_output[j] = lua_tonumber (L, -1);
				lua_pop (L, 1);
			}

			fann_train (f, cur_input, cur_output);
			g_free (cur_input);
			g_free (cur_output);

			ret = TRUE;
		}
	}

	lua_pushboolean (L, ret);

	return 1;
#endif
}

/**
 * @method rspamd_fann:test(inputs)
 * Tests neural network with samples. Inputs is a single sample of input data.
 * The function returns table of results, e.g.:
 *     {0, 1, 1} -> {0}
 * @param {table} inputs input sample
 * @return {table/number} outputs values
 */
static gint
lua_fann_test (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f = rspamd_lua_check_fann (L, 1);
	guint ninputs, noutputs, i, tbl_idx = 2;
	float *cur_input, *cur_output;

	if (f != NULL) {
		/* First check sanity, call for table.getn for that */
		if (lua_isnumber (L, 2)) {
			ninputs = lua_tonumber (L, 2);
			tbl_idx = 3;
		}
		else {
			ninputs = rspamd_lua_table_size (L, 2);

			if (ninputs == 0) {
				msg_err ("empty inputs number");
				lua_pushnil (L);

				return 1;
			}
		}

		cur_input = g_slice_alloc (ninputs * sizeof (gint));

		for (i = 0; i < ninputs; i++) {
			lua_rawgeti (L, tbl_idx, i + 1);
			cur_input[i] = lua_tonumber (L, -1);
			lua_pop (L, 1);
		}

		cur_output = fann_run (f, cur_input);
		noutputs = fann_get_num_output (f);
		lua_createtable (L, noutputs, 0);

		for (i = 0; i < noutputs; i ++) {
			lua_pushnumber (L, cur_output[i]);
			lua_rawseti (L, -2, i + 1);
		}

		g_slice_free1 (ninputs * sizeof (gint), cur_input);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
#endif
}

/***
 * @method rspamd_fann:get_inputs()
 * Returns number of inputs for neural network
 * @return {number} number of inputs
 */
static gint
lua_fann_get_inputs (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f = rspamd_lua_check_fann (L, 1);

	if (f != NULL) {
		lua_pushnumber (L, fann_get_num_input (f));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
#endif
}

/***
 * @method rspamd_fann:get_outputs()
 * Returns number of outputs for neural network
 * @return {number} number of outputs
 */
static gint
lua_fann_get_outputs (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f = rspamd_lua_check_fann (L, 1);

	if (f != NULL) {
		lua_pushnumber (L, fann_get_num_output (f));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
#endif
}

/***
 * @method rspamd_fann:save(fname)
 * Save fann to file named 'fname'
 * @param {string} fname filename to save fann into
 * @return {boolean} true if ann has been saved
 */
static gint
lua_fann_save (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f = rspamd_lua_check_fann (L, 1);
	const gchar *fname = luaL_checkstring (L, 2);

	if (f != NULL && fname != NULL) {
		if (fann_save (f, fname) == 0) {
			lua_pushboolean (L, true);
		}
		else {
			msg_err ("cannot save ANN to %s: %s", fname, strerror (errno));
			lua_pushboolean (L, false);
		}
	}
	else {
		lua_pushnil (L);
	}

	return 1;
#endif
}

static gint
lua_fann_dtor (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f = rspamd_lua_check_fann (L, 1);

	if (f) {
		fann_destroy (f);
	}

	return 0;
#endif
}

static gint
lua_load_fann (lua_State * L)
{
	lua_newtable (L);
	luaL_register (L, NULL, fannlib_f);

	return 1;
}

void
luaopen_fann (lua_State * L)
{
	rspamd_lua_new_class (L, "rspamd{fann}", fannlib_m);
	lua_pop (L, 1);

	rspamd_lua_add_preload (L, "rspamd_fann", lua_load_fann);
}
