/*
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lua_common.h"
#include "lua_classnames.h"

/***
 * @module rspamd_fasttext
 * This module provides access to FastText models for computing text embeddings.
 * It can load supervised or unsupervised FastText models and produce
 * sentence-level embedding vectors from word lists.
 *
 * @example
 * local rspamd_fasttext = require "rspamd_fasttext"
 * local model = rspamd_fasttext.load('/path/to/model.bin')
 * if model then
 *   local dim = model:get_dimension()
 *   -- words is a table of strings
 *   local vec = model:get_sentence_vector(words)
 *   -- vec is a table of dim floats
 * end
 */

#include "fasttext_shim.h"
#include <string>
#include <vector>
#include <cmath>
#include <unistd.h>

#define FASTTEXT_MODEL_CLASS rspamd_fasttext_classname

/* Forward declarations */
static int lua_fasttext_load(lua_State *L);
static int lua_fasttext_model_get_dimension(lua_State *L);
static int lua_fasttext_model_get_sentence_vector(lua_State *L);
static int lua_fasttext_model_get_word_vector(lua_State *L);
static int lua_fasttext_model_predict(lua_State *L);
static int lua_fasttext_model_get_word_frequency(lua_State *L);
static int lua_fasttext_model_dtor(lua_State *L);
static int lua_fasttext_model_is_loaded(lua_State *L);

/* Module functions */
static const struct luaL_reg fasttextlib_f[] = {
	{"load", lua_fasttext_load},
	{nullptr, nullptr},
};

/* Model methods */
static const struct luaL_reg fasttextlib_m[] = {
	{"get_dimension", lua_fasttext_model_get_dimension},
	{"get_sentence_vector", lua_fasttext_model_get_sentence_vector},
	{"get_word_vector", lua_fasttext_model_get_word_vector},
	{"get_word_frequency", lua_fasttext_model_get_word_frequency},
	{"predict", lua_fasttext_model_predict},
	{"is_loaded", lua_fasttext_model_is_loaded},
	{"__gc", lua_fasttext_model_dtor},
	{"__tostring", rspamd_lua_class_tostring},
	{nullptr, nullptr},
};

struct rspamd_lua_fasttext_model {
	rspamd::fasttext::fasttext_model *model;
	bool loaded;
};

static struct rspamd_lua_fasttext_model *
lua_check_fasttext_model(lua_State *L, int pos)
{
	auto *pmodel = static_cast<struct rspamd_lua_fasttext_model **>(
		rspamd_lua_check_udata(L, pos, FASTTEXT_MODEL_CLASS));
	luaL_argcheck(L, pmodel != nullptr && *pmodel != nullptr, pos, "'rspamd{fasttext}' expected");
	return *pmodel;
}

/***
 * @function rspamd_fasttext.load(path)
 * Load a FastText model from file
 * @param {string} path path to the .bin model file
 * @return {rspamd_fasttext} model object (check is_loaded())
 */
static int
lua_fasttext_load(lua_State *L)
{
	const char *path = luaL_checkstring(L, 1);

	auto *model = new rspamd_lua_fasttext_model();
	model->model = nullptr;
	model->loaded = false;

	/* Store pointer in userdata */
	auto **pmodel = static_cast<struct rspamd_lua_fasttext_model **>(
		lua_newuserdata(L, sizeof(struct rspamd_lua_fasttext_model *)));
	*pmodel = model;
	rspamd_lua_setclass(L, FASTTEXT_MODEL_CLASS, -1);

	/* Pre-validate: check file is readable */
	if (access(path, R_OK) != 0) {
		msg_err("fasttext model '%s' is not readable: %s", path, strerror(errno));
		return 1;
	}

	auto result = rspamd::fasttext::fasttext_model::load(path);
	if (result) {
		model->model = new rspamd::fasttext::fasttext_model(std::move(*result));
		model->loaded = true;
	}
	else {
		msg_err("fasttext model '%s' failed to load: %s", path,
				result.error().error_message.data());
	}

	return 1;
}

/***
 * @method model:is_loaded()
 * Check if the model was loaded successfully
 * @return {boolean} true if model is loaded
 */
static int
lua_fasttext_model_is_loaded(lua_State *L)
{
	auto *model = lua_check_fasttext_model(L, 1);
	lua_pushboolean(L, model && model->loaded);
	return 1;
}

/***
 * @method model:get_dimension()
 * Get the dimension of embedding vectors
 * @return {number} vector dimension
 */
static int
lua_fasttext_model_get_dimension(lua_State *L)
{
	auto *model = lua_check_fasttext_model(L, 1);

	if (!model || !model->loaded) {
		lua_pushinteger(L, 0);
		return 1;
	}

	lua_pushinteger(L, model->model->get_dimension());
	return 1;
}

/***
 * @method model:get_word_frequency(word)
 * Get word probability p(word) = count(word) / total_tokens.
 * Useful for SIF (Smooth Inverse Frequency) sentence weighting.
 * @param {string} word input word
 * @return {number} word probability (0..1), 0 for unknown words
 */
static int
lua_fasttext_model_get_word_frequency(lua_State *L)
{
	auto *model = lua_check_fasttext_model(L, 1);
	const char *word = luaL_checkstring(L, 2);

	if (!model || !model->loaded) {
		lua_pushnumber(L, 0.0);
		return 1;
	}

	auto freq = model->model->get_word_frequency(std::string_view{word});
	lua_pushnumber(L, freq);

	return 1;
}

/***
 * @method model:get_word_vector(word)
 * Get embedding vector for a single word
 * @param {string} word input word
 * @return {table} table of floats (dimension numbers)
 */
static int
lua_fasttext_model_get_word_vector(lua_State *L)
{
	auto *model = lua_check_fasttext_model(L, 1);
	const char *word = luaL_checkstring(L, 2);

	if (!model || !model->loaded) {
		lua_pushnil(L);
		return 1;
	}

	std::vector<float> vec;

	model->model->get_word_vector(vec, std::string_view{word});

	auto vec_size = static_cast<std::int32_t>(vec.size());
	lua_createtable(L, vec_size, 0);
	for (std::int32_t i = 0; i < vec_size; i++) {
		lua_pushnumber(L, static_cast<double>(vec[i]));
		lua_rawseti(L, -2, i + 1);
	}

	return 1;
}

/***
 * @method model:get_sentence_vector(words)
 * Compute a sentence embedding by averaging word vectors.
 * This is equivalent to fasttext's getSentenceVector but works
 * directly from a Lua table of word strings.
 * @param {table} words table of word strings
 * @return {table} table of floats (dimension numbers) or nil if empty
 */
static int
lua_fasttext_model_get_sentence_vector(lua_State *L)
{
	auto *model = lua_check_fasttext_model(L, 1);

	if (!model || !model->loaded) {
		lua_pushnil(L);
		return 1;
	}

	luaL_argcheck(L, lua_istable(L, 2), 2, "'table' of words expected");

	auto dim = model->model->get_dimension();
	if (dim <= 0 || dim > 4096) {
		lua_pushnil(L);
		return 1;
	}

	std::vector<float> sentence_vec(dim, 0.0f);
	std::vector<float> word_vec;
	int count = 0;

	auto nwords = rspamd_lua_table_size(L, 2);

	for (auto i = 1; i <= nwords; i++) {
		lua_rawgeti(L, 2, i);

		if (lua_isstring(L, -1)) {
			std::size_t len;
			const char *w = lua_tolstring(L, -1, &len);
			if (len > 0) {
				model->model->get_word_vector(word_vec, std::string_view{w, len});
				auto wv_size = std::min(dim, static_cast<std::int32_t>(word_vec.size()));
				for (std::int32_t d = 0; d < wv_size; d++) {
					sentence_vec[d] += word_vec[d];
				}
				count++;
			}
		}

		lua_pop(L, 1);
	}

	if (count == 0) {
		lua_pushnil(L);
		return 1;
	}

	/* Average */
	float inv = 1.0f / static_cast<float>(count);
	for (auto &v: sentence_vec) {
		v *= inv;
	}

	/* L2 normalize for consistent scale */
	float norm = 0.0f;
	for (auto v: sentence_vec) {
		norm += v * v;
	}
	norm = std::sqrt(norm);
	if (norm > 0) {
		for (auto &v: sentence_vec) {
			v /= norm;
		}
	}

	/* Return as Lua table */
	lua_createtable(L, dim, 0);
	for (std::int32_t i = 0; i < dim; i++) {
		lua_pushnumber(L, static_cast<double>(sentence_vec[i]));
		lua_rawseti(L, -2, i + 1);
	}

	return 1;
}

/***
 * @method model:predict(words, k)
 * Run supervised classification on a table of words.
 * Each word is converted to input matrix row IDs internally.
 * @param {table} words table of word strings
 * @param {number} k number of top predictions to return (default 1)
 * @return {table} array of {label=string, prob=number} tables, sorted by probability descending
 */
static int
lua_fasttext_model_predict(lua_State *L)
{
	auto *model = lua_check_fasttext_model(L, 1);

	if (!model || !model->loaded) {
		lua_pushnil(L);
		return 1;
	}

	luaL_argcheck(L, lua_istable(L, 2), 2, "'table' of words expected");
	int k = luaL_optinteger(L, 3, 1);

	/* Convert words to input matrix row IDs */
	std::vector<std::int32_t> word_ids;
	auto nwords = rspamd_lua_table_size(L, 2);

	for (auto i = 1; i <= nwords; i++) {
		lua_rawgeti(L, 2, i);
		if (lua_isstring(L, -1)) {
			std::size_t len;
			const char *w = lua_tolstring(L, -1, &len);
			if (len > 0) {
				model->model->word2vec(std::string_view{w, len}, word_ids);
			}
		}
		lua_pop(L, 1);
	}

	if (word_ids.empty()) {
		lua_newtable(L);
		return 1;
	}

	std::vector<rspamd::fasttext::prediction> preds;
	model->model->predict(k, word_ids, preds, 0.0f);

	lua_createtable(L, static_cast<int>(preds.size()), 0);
	for (std::size_t i = 0; i < preds.size(); i++) {
		lua_createtable(L, 0, 2);
		lua_pushstring(L, preds[i].label.c_str());
		lua_setfield(L, -2, "label");
		lua_pushnumber(L, static_cast<double>(preds[i].prob));
		lua_setfield(L, -2, "prob");
		lua_rawseti(L, -2, static_cast<int>(i + 1));
	}

	return 1;
}

static int
lua_fasttext_model_dtor(lua_State *L)
{
	auto *pmodel = static_cast<struct rspamd_lua_fasttext_model **>(
		rspamd_lua_check_udata(L, 1, FASTTEXT_MODEL_CLASS));

	if (pmodel && *pmodel) {
		delete (*pmodel)->model;
		delete *pmodel;
		*pmodel = nullptr;
	}

	return 0;
}

void luaopen_fasttext(lua_State *L)
{
	/* Register the model class */
	rspamd_lua_new_class(L, FASTTEXT_MODEL_CLASS, fasttextlib_m);
	lua_pop(L, 1);

	/* Register the module table */
	rspamd_lua_add_preload(L, "rspamd_fasttext", [](lua_State *LL) -> int {
		luaL_register(LL, "rspamd_fasttext", fasttextlib_f);
		return 1;
	});
}
