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

#include "unix-std.h"

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
LUA_FUNCTION_DEF (fann, create_full);
LUA_FUNCTION_DEF (fann, load_file);
LUA_FUNCTION_DEF (fann, load_data);

/*
 * Fann methods
 */
LUA_FUNCTION_DEF (fann, train);
LUA_FUNCTION_DEF (fann, train_threaded);
LUA_FUNCTION_DEF (fann, test);
LUA_FUNCTION_DEF (fann, save);
LUA_FUNCTION_DEF (fann, data);
LUA_FUNCTION_DEF (fann, get_inputs);
LUA_FUNCTION_DEF (fann, get_outputs);
LUA_FUNCTION_DEF (fann, get_layers);
LUA_FUNCTION_DEF (fann, get_mse);
LUA_FUNCTION_DEF (fann, dtor);

static const struct luaL_reg fannlib_f[] = {
		LUA_INTERFACE_DEF (fann, is_enabled),
		LUA_INTERFACE_DEF (fann, create),
		LUA_INTERFACE_DEF (fann, create_full),
		LUA_INTERFACE_DEF (fann, load_file),
		{"load", lua_fann_load_file},
		LUA_INTERFACE_DEF (fann, load_data),
		{NULL, NULL}
};

static const struct luaL_reg fannlib_m[] = {
		LUA_INTERFACE_DEF (fann, train),
		LUA_INTERFACE_DEF (fann, train_threaded),
		LUA_INTERFACE_DEF (fann, test),
		LUA_INTERFACE_DEF (fann, save),
		LUA_INTERFACE_DEF (fann, data),
		LUA_INTERFACE_DEF (fann, get_inputs),
		LUA_INTERFACE_DEF (fann, get_outputs),
		LUA_INTERFACE_DEF (fann, get_layers),
		LUA_INTERFACE_DEF (fann, get_mse),
		{"__gc", lua_fann_dtor},
		{"__tostring", rspamd_lua_class_tostring},
		{NULL, NULL}
};

#ifdef WITH_FANN
struct fann *
rspamd_lua_check_fann (lua_State *L, gint pos)
{
	void *ud = rspamd_lua_check_udata (L, pos, "rspamd{fann}");
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

		if (lua_type (L, 2) == LUA_TNUMBER) {
			for (i = 0; i < nlayers; i ++) {
				layers[i] = luaL_checknumber (L, i + 2);
			}
		}
		else if (lua_type (L, 2) == LUA_TTABLE) {
			for (i = 0; i < nlayers; i ++) {
				lua_rawgeti (L, 2, i + 1);
				layers[i] = luaL_checknumber (L, -1);
				lua_pop (L, 1);
			}
		}

		f = fann_create_standard_array (nlayers, layers);
		fann_set_activation_function_hidden (f, FANN_SIGMOID_SYMMETRIC);
		fann_set_activation_function_output (f, FANN_SIGMOID_SYMMETRIC);
		fann_set_training_algorithm (f, FANN_TRAIN_INCREMENTAL);
		fann_randomize_weights (f, 0, 1);

		if (f != NULL) {
			pfann = lua_newuserdata (L, sizeof (gpointer));
			*pfann = f;
			rspamd_lua_setclass (L, "rspamd{fann}", -1);
		}
		else {
			lua_pushnil (L);
		}

		g_free (layers);
	}
	else {
		lua_pushnil (L);
	}

	return 1;
#endif
}

#ifdef WITH_FANN
static enum fann_activationfunc_enum
string_to_activation_func (const gchar *str)
{
	if (str == NULL) {
		return FANN_SIGMOID_SYMMETRIC;
	}
	if (strcmp (str, "sigmoid") == 0) {
		return FANN_SIGMOID;
	}
	else if (strcmp (str, "elliot") == 0) {
		return FANN_ELLIOT;
	}
	else if (strcmp (str, "elliot_symmetric") == 0) {
		return FANN_ELLIOT_SYMMETRIC;
	}
	else if (strcmp (str, "linear") == 0) {
		return FANN_LINEAR;
	}

	return FANN_SIGMOID_SYMMETRIC;
}

static enum fann_train_enum
string_to_learn_alg (const gchar *str)
{
	if (str == NULL) {
		return FANN_TRAIN_INCREMENTAL;
	}
	if (strcmp (str, "rprop") == 0) {
		return FANN_TRAIN_RPROP;
	}
	else if (strcmp (str, "qprop") == 0) {
		return FANN_TRAIN_QUICKPROP;
	}
	else if (strcmp (str, "batch") == 0) {
		return FANN_TRAIN_BATCH;
	}

	return FANN_TRAIN_INCREMENTAL;
}
/*
 * This is needed since libfann provides no versioning macros...
 */
static struct fann_train_data *
rspamd_fann_create_train (guint num_data, guint num_input, guint num_output)
{
	struct fann_train_data *t;
	fann_type *inp, *outp;
	guint i;

	g_assert (num_data > 0 && num_input > 0 && num_output > 0);

	t = calloc (1, sizeof (*t));
	g_assert (t != NULL);

	t->num_data = num_data;
	t->num_input = num_input;
	t->num_output = num_output;

	t->input = calloc (num_data, sizeof (fann_type *));
	g_assert (t->input != NULL);

	t->output = calloc (num_data, sizeof (fann_type *));
	g_assert (t->output != NULL);

	inp = calloc (num_data * num_input, sizeof (fann_type));
	g_assert (inp != NULL);

	outp = calloc (num_data * num_output, sizeof (fann_type));
	g_assert (outp != NULL);

	for (i = 0; i < num_data; i ++) {
		t->input[i] = inp;
		inp += num_input;
		t->output[i] = outp;
		outp += num_output;
	}

	return t;
}


#endif

/***
 * @function rspamd_fann.create_full(params)
 * Creates new neural network with parameters:
 * - `layers` {table/numbers}: table of layers in form: {N1, N2, N3 ... Nn} where N is number of neurons in a layer
 * - `activation_hidden` {string}: activation function type for hidden layers (`tanh` by default)
 * - `activation_output` {string}: activation function type for output layer (`tanh` by default)
 * - `sparsed` {float}: create sparsed ANN, where number is a coefficient for sparsing
 * - `learn` {string}: learning algorithm (quickprop, rprop or incremental)
 * - `randomize` {boolean}: randomize weights (true by default)
 * @return {fann} fann object
 */
static gint
lua_fann_create_full (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f, **pfann;
	guint nlayers, *layers, i;
	const gchar *activation_hidden = NULL, *activation_output, *learn_alg = NULL;
	gdouble sparsed = 0.0;
	gboolean randomize_ann = TRUE;
	GError *err = NULL;

	if (lua_type (L, 1) == LUA_TTABLE) {
		lua_pushstring (L, "layers");
		lua_gettable (L, 1);

		if (lua_type (L, -1) != LUA_TTABLE) {
			return luaL_error (L, "bad layers attribute");
		}

		nlayers = rspamd_lua_table_size (L, -1);
		if (nlayers < 2) {
			return luaL_error (L, "bad layers attribute");
		}

		layers = g_new0 (guint, nlayers);

		for (i = 0; i < nlayers; i ++) {
			lua_rawgeti (L, -1, i + 1);
			layers[i] = luaL_checknumber (L, -1);
			lua_pop (L, 1);
		}

		lua_pop (L, 1); /* Table */

		if (!rspamd_lua_parse_table_arguments (L, 1, &err,
				"sparsed=N;randomize=B;learn=S;activation_hidden=S;activation_output=S",
				&sparsed, &randomize_ann, &learn_alg, &activation_hidden, &activation_output)) {
			g_free (layers);

			if (err) {
				gint r;

				r = luaL_error (L, "invalid arguments: %s", err->message);
				g_error_free (err);
				return r;
			}
			else {
				return luaL_error (L, "invalid arguments");
			}
		}

		if (sparsed != 0.0) {
			f = fann_create_standard_array (nlayers, layers);
		}
		else {
			f = fann_create_sparse_array (sparsed, nlayers, layers);
		}

		if (f != NULL) {
			pfann = lua_newuserdata (L, sizeof (gpointer));
			*pfann = f;
			rspamd_lua_setclass (L, "rspamd{fann}", -1);
		}
		else {
			g_free (layers);
			return luaL_error (L, "cannot create fann");
		}

		fann_set_activation_function_hidden (f,
				string_to_activation_func (activation_hidden));
		fann_set_activation_function_output (f,
				string_to_activation_func (activation_output));
		fann_set_training_algorithm (f, string_to_learn_alg (learn_alg));

		if (randomize_ann) {
			fann_randomize_weights (f, 0, 1);
		}

		g_free (layers);
	}
	else {
		return luaL_error (L, "bad arguments");
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
lua_fann_load_file (lua_State *L)
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

/***
 * @function rspamd_fann.load_data(data)
 * Loads neural network from the data
 * @param {string} file filename where fann is stored
 * @return {fann} fann object
 */
static gint
lua_fann_load_data (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f, **pfann;
	gint fd;
	struct rspamd_lua_text *t;
	gchar fpath[PATH_MAX];

	if (lua_type (L, 1) == LUA_TUSERDATA) {
		t = lua_check_text (L, 1);

		if (!t) {
			return luaL_error (L, "text required");
		}
	}
	else {
		t = g_alloca (sizeof (*t));
		t->start = lua_tolstring (L, 1, (gsize *)&t->len);
		t->flags = 0;
	}

	/* We need to save data to file because of libfann stupidity */
	rspamd_strlcpy (fpath, "/tmp/rspamd-fannXXXXXXXXXX", sizeof (fpath));
	fd = mkstemp (fpath);

	if (fd == -1) {
		msg_warn ("cannot create tempfile: %s", strerror (errno));
		lua_pushnil (L);
	}
	else {
		if (write (fd, t->start, t->len) == -1) {
			msg_warn ("cannot write tempfile: %s", strerror (errno));
			lua_pushnil (L);
			unlink (fpath);
			close (fd);

			return 1;
		}

		f = fann_create_from_file (fpath);
		unlink (fpath);
		close (fd);

		if (f != NULL) {
			pfann = lua_newuserdata (L, sizeof (gpointer));
			*pfann = f;
			rspamd_lua_setclass (L, "rspamd{fann}", -1);
		}
		else {
			lua_pushnil (L);
		}
	}

	return 1;
#endif
}

/***
 * @function rspamd_fann:data()
 * Returns serialized neural network
 * @return {rspamd_text} fann data
 */
static gint
lua_fann_data (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f = rspamd_lua_check_fann (L, 1);
	gint fd;
	struct rspamd_lua_text *res;
	gchar fpath[PATH_MAX];
	gpointer map;
	gsize sz;

	if (f == NULL) {
		return luaL_error (L, "invalid arguments");
	}

	/* We need to save data to file because of libfann stupidity */
	rspamd_strlcpy (fpath, "/tmp/rspamd-fannXXXXXXXXXX", sizeof (fpath));
	fd = mkstemp (fpath);

	if (fd == -1) {
		msg_warn ("cannot create tempfile: %s", strerror (errno));
		lua_pushnil (L);
	}
	else {
		if (fann_save (f, fpath) == -1) {
			msg_warn ("cannot write tempfile: %s", strerror (errno));
			lua_pushnil (L);
			unlink (fpath);
			close (fd);

			return 1;
		}


		(void)lseek (fd, 0, SEEK_SET);
		map = rspamd_file_xmap (fpath, PROT_READ, &sz, TRUE);
		unlink (fpath);
		close (fd);

		if (map != NULL) {
			res = lua_newuserdata (L, sizeof (*res));
			res->len = sz;
			res->start = map;
			res->flags = RSPAMD_TEXT_FLAG_OWN|RSPAMD_TEXT_FLAG_MMAPED;
			rspamd_lua_setclass (L, "rspamd{text}", -1);
		}
		else {
			lua_pushnil (L);
		}

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
	fann_type *cur_input, *cur_output;
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
			cur_input = g_malloc (ninputs * sizeof (fann_type));

			for (j = 0; j < ninputs; j ++) {
				lua_rawgeti (L, 2, j + 1);
				cur_input[j] = lua_tonumber (L, -1);
				lua_pop (L, 1);
			}

			cur_output = g_malloc (noutputs * sizeof (fann_type));

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

#ifdef WITH_FANN
struct lua_fann_train_cbdata {
	lua_State *L;
	gint pair[2];
	struct fann_train_data *train;
	struct fann *f;
	gint cbref;
	gdouble desired_mse;
	guint max_epochs;
	GThread *t;
	struct event io;
};

struct lua_fann_train_reply {
	gint errcode;
	float mse;
	gchar errmsg[128];
};

static void
lua_fann_push_train_result (struct lua_fann_train_cbdata *cbdata,
		gint errcode, float mse, const gchar *errmsg)
{
	lua_rawgeti (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref);
	lua_pushnumber (cbdata->L, errcode);
	lua_pushstring (cbdata->L, errmsg);
	lua_pushnumber (cbdata->L, mse);

	if (lua_pcall (cbdata->L, 3, 0, 0) != 0) {
		msg_err ("call to train callback failed: %s", lua_tostring (cbdata->L, -1));
		lua_pop (cbdata->L, 1);
	}
}

static void
lua_fann_thread_notify (gint fd, short what, gpointer ud)
{
	struct lua_fann_train_cbdata *cbdata = ud;
	struct lua_fann_train_reply rep;

	if (read (cbdata->pair[0], &rep, sizeof (rep)) == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			event_add (&cbdata->io, NULL);
			return;
		}

		lua_fann_push_train_result (cbdata, errno, 0.0, strerror (errno));
	}
	else {
		lua_fann_push_train_result (cbdata, rep.errcode, rep.mse, rep.errmsg);
	}

	g_assert (write (cbdata->pair[0], "", 1) == 1);
	g_thread_join (cbdata->t);
	close (cbdata->pair[0]);
	close (cbdata->pair[1]);

	fann_destroy_train (cbdata->train);
	luaL_unref (cbdata->L, LUA_REGISTRYINDEX, cbdata->cbref);
	g_free (cbdata);
}

static void *
lua_fann_train_thread (void *ud)
{
	struct lua_fann_train_cbdata *cbdata = ud;
	struct lua_fann_train_reply rep;
	gchar repbuf[1];

	msg_info ("start learning ANN, %d epochs are possible",
			cbdata->max_epochs);
	rspamd_socket_blocking (cbdata->pair[1]);
	fann_train_on_data (cbdata->f, cbdata->train, cbdata->max_epochs, 0,
			cbdata->desired_mse);
	rep.errcode = 0;
	rspamd_strlcpy (rep.errmsg, "OK", sizeof (rep.errmsg));
	rep.mse = fann_get_MSE (cbdata->f);

	if (write (cbdata->pair[1], &rep, sizeof (rep)) == -1) {
		msg_err ("cannot write to socketpair: %s", strerror (errno));

		return NULL;
	}

	if (read (cbdata->pair[1], repbuf, sizeof (repbuf)) == -1) {
		msg_err ("cannot read from socketpair: %s", strerror (errno));

		return NULL;
	}

	return NULL;
}
#endif
/**
 * @method rspamd_fann:train_threaded(inputs, outputs, callback, event_base, {params})
 * Trains neural network with batch of samples. Inputs and outputs should be tables of
 * equal size, each row in table should be N inputs and M outputs, e.g.
 *     {{0, 1, 1}, ...} -> {{0}, {1} ...}
 * @param {table} inputs input samples
 * @param {table} outputs output samples
 * @param {callback} function that is called when train is completed
 */
static gint
lua_fann_train_threaded (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f = rspamd_lua_check_fann (L, 1);
	guint ninputs, noutputs, ndata, i, j;
	struct lua_fann_train_cbdata *cbdata;
	struct event_base *ev_base = lua_check_ev_base (L, 5);
	GError *err = NULL;
	const guint max_epochs_default = 1000;
	const gdouble desired_mse_default = 0.0001;

	if (f != NULL && lua_type (L, 2) == LUA_TTABLE &&
			lua_type (L, 3) == LUA_TTABLE && lua_type (L, 4) == LUA_TFUNCTION &&
			ev_base != NULL) {
		/* First check sanity, call for table.getn for that */
		ndata = rspamd_lua_table_size (L, 2);
		ninputs = fann_get_num_input (f);
		noutputs = fann_get_num_output (f);
		cbdata = g_malloc0 (sizeof (*cbdata));
		cbdata->L = L;
		cbdata->f = f;
		cbdata->train = rspamd_fann_create_train (ndata, ninputs, noutputs);
		lua_pushvalue (L, 4);
		cbdata->cbref = luaL_ref (L, LUA_REGISTRYINDEX);

		if (rspamd_socketpair (cbdata->pair, 0) == -1) {
			msg_err ("cannot open socketpair: %s", strerror (errno));
			cbdata->pair[0] = -1;
			cbdata->pair[1] = -1;
			goto err;
		}

		for (i = 0; i < ndata; i ++) {
			lua_rawgeti (L, 2, i + 1);

			if (rspamd_lua_table_size (L, -1) != ninputs) {
				msg_err ("invalid number of inputs: %d, %d expected",
						rspamd_lua_table_size (L, -1), ninputs);
				goto err;
			}

			for (j = 0; j < ninputs; j ++) {
				lua_rawgeti (L, -1, j + 1);
				cbdata->train->input[i][j] = lua_tonumber (L, -1);
				lua_pop (L, 1);
			}

			lua_pop (L, 1);
			lua_rawgeti (L, 3, i + 1);

			if (rspamd_lua_table_size (L, -1) != noutputs) {
				msg_err ("invalid number of outputs: %d, %d expected",
						rspamd_lua_table_size (L, -1), noutputs);
				goto err;
			}

			for (j = 0; j < noutputs; j++) {
				lua_rawgeti (L, -1, j + 1);
				cbdata->train->output[i][j] = lua_tonumber (L, -1);
				lua_pop (L, 1);
			}
		}

		cbdata->max_epochs = max_epochs_default;
		cbdata->desired_mse = desired_mse_default;

		if (lua_type (L, 5) == LUA_TTABLE) {
			rspamd_lua_parse_table_arguments (L, 5, NULL,
					"max_epochs=I;desired_mse=N",
					&cbdata->max_epochs, &cbdata->desired_mse);
		}

		/* Now we can call training in a separate thread */
		rspamd_socket_nonblocking (cbdata->pair[0]);
		event_set (&cbdata->io, cbdata->pair[0], EV_READ, lua_fann_thread_notify,
				cbdata);
		event_base_set (ev_base, &cbdata->io);
		/* TODO: add timeout */
		event_add (&cbdata->io, NULL);
		cbdata->t = rspamd_create_thread ("fann train", lua_fann_train_thread,
				cbdata, &err);

		if (cbdata->t == NULL) {
			msg_err ("cannot create training thread: %e", err);

			if (err) {
				g_error_free (err);
			}

			goto err;
		}
	}
	else {
		return luaL_error (L, "invalid arguments");
	}

	return 0;

err:
	if (cbdata->pair[0] != -1) {
		close (cbdata->pair[0]);
	}
	if (cbdata->pair[1] != -1) {
		close (cbdata->pair[1]);
	}

	fann_destroy_train (cbdata->train);
	luaL_unref (L, LUA_REGISTRYINDEX, cbdata->cbref);
	g_free (cbdata);
	return luaL_error (L, "invalid arguments");
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
	fann_type *cur_input, *cur_output;

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

		cur_input = g_malloc0 (ninputs * sizeof (fann_type));

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

		g_free (cur_input);
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
 * @method rspamd_fann:get_mse()
 * Returns mean square error for ANN
 * @return {number} MSE value
 */
static gint
lua_fann_get_mse (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f = rspamd_lua_check_fann (L, 1);

	if (f != NULL) {
		lua_pushnumber (L, fann_get_MSE (f));
	}
	else {
		lua_pushnil (L);
	}

	return 1;
#endif
}

/***
 * @method rspamd_fann:get_layers()
 * Returns array of neurons count for each layer
 * @return {table/number} table with number ofr neurons in each layer
 */
static gint
lua_fann_get_layers (lua_State *L)
{
#ifndef WITH_FANN
	return 0;
#else
	struct fann *f = rspamd_lua_check_fann (L, 1);
	guint nlayers, i, *layers;

	if (f != NULL) {
		nlayers = fann_get_num_layers (f);
		layers = g_new (guint, nlayers);
		fann_get_layer_array (f, layers);
		lua_createtable (L, nlayers, 0);

		for (i = 0; i < nlayers; i ++) {
			lua_pushnumber (L, layers[i]);
			lua_rawseti (L, -2, i + 1);
		}

		g_free (layers);
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
