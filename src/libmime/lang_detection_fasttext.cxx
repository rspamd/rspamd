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

#include "lang_detection_fasttext.h"
#include "fasttext_shim.h"
#include "libserver/cfg_file.h"
#include "libserver/logger.h"
#include "libserver/maps/map.h"
#include "libserver/maps/map_private.h"
#include "contrib/fmt/include/fmt/base.h"
#include "stat_api.h"
#include "libserver/word.h"
#include <string_view>
#include <vector>
#include <optional>
#include <unistd.h>

EXTERN_LOG_MODULE_DEF(langdet);
#define msg_debug_lang_det(...) rspamd_conditional_debug_fast(nullptr, nullptr,                                           \
															  rspamd_langdet_log_id, "langdet", task->task_pool->tag.uid, \
															  __FUNCTION__,                                               \
															  __VA_ARGS__)

namespace rspamd::langdet {

/**
 * Map callback data for fasttext model loading.
 * Used by the maps infrastructure to atomically swap old/new models.
 */
struct fasttext_map_data {
	rspamd::fasttext::fasttext_model *model = nullptr;
};

class fasttext_langdet {
private:
	/* Owned model for direct file loading (non-map case) */
	std::optional<rspamd::fasttext::fasttext_model> owned_model_;
	/*
	 * For map-backed models: pointer to a mempool-allocated slot where the
	 * map infrastructure writes the current fasttext_map_data*.
	 * Allocated on cfg->cfg_pool so it outlives this object (maps are
	 * cleaned up after the lang detector during rspamd_config_free).
	 */
	void **map_target_ = nullptr;
	std::string model_fname;
	struct rspamd_config *cfg_;

	auto get_model() const -> rspamd::fasttext::fasttext_model *
	{
		if (owned_model_) {
			return const_cast<rspamd::fasttext::fasttext_model *>(&owned_model_.value());
		}
		if (map_target_ && *map_target_) {
			auto *fdata = static_cast<fasttext_map_data *>(*map_target_);
			return fdata->model;
		}
		return nullptr;
	}

	void load_model_direct(const char *model_path)
	{
		auto *cfg = cfg_;
		if (access(model_path, R_OK) != 0) {
			msg_err_config("fasttext model '%s' is not readable: %s",
						   model_path, strerror(errno));
			return;
		}

		auto result = rspamd::fasttext::fasttext_model::load(model_path);
		if (result) {
			owned_model_.emplace(std::move(*result));
			model_fname = std::string{model_path};
		}
		else {
			msg_err_config("cannot load fasttext model '%s': %s",
						   model_path, result.error().error_message.data());
		}
	}

	void load_model_map(const char *model_path)
	{
		auto *cfg = cfg_;
		model_fname = std::string{model_path};

		/* Allocate user_data target on config mempool so it survives until
		 * rspamd_map_remove_all (which runs after lang detector cleanup) */
		map_target_ = static_cast<void **>(
			rspamd_mempool_alloc0(cfg->cfg_pool, sizeof(void *)));

		auto *map = rspamd_map_add(cfg_, model_path,
								   "fasttext language model",
								   fasttext_map_read_cb,
								   fasttext_map_fin_cb,
								   fasttext_map_dtor_cb,
								   map_target_,
								   nullptr,
								   RSPAMD_MAP_FILE_NO_READ);

		if (!map) {
			msg_err_config("cannot add map for fasttext model '%s'", model_path);
		}
	}

	/* Map read callback: receives filename, loads model */
	static char *fasttext_map_read_cb(char *chunk, int len,
									  struct map_cb_data *data, gboolean final)
	{
		if (data->cur_data == nullptr) {
			data->cur_data = new fasttext_map_data();
		}

		if (!final) {
			return chunk + len;
		}

		auto *fdata = static_cast<fasttext_map_data *>(data->cur_data);
		auto *map = data->map;
		auto fname = std::string{chunk, static_cast<std::size_t>(len)};
		auto offset = static_cast<std::int64_t>(
			rspamd_map_get_no_file_read_offset(data->map));

		auto result = rspamd::fasttext::fasttext_model::load(fname, offset);
		if (result) {
			fdata->model = new rspamd::fasttext::fasttext_model(std::move(*result));
			msg_info_map("loaded fasttext model from %s (offset %z)",
						 fname.c_str(), (gsize) offset);
		}
		else {
			msg_err_map("cannot load fasttext model from %s (offset %z): %s",
						fname.c_str(), (gsize) offset,
						result.error().error_message.data());
		}

		return chunk + len;
	}

	/* Map fin callback: swap old model for new one */
	static void fasttext_map_fin_cb(struct map_cb_data *data, void **target)
	{
		auto *new_data = static_cast<fasttext_map_data *>(data->cur_data);
		auto *old_data = static_cast<fasttext_map_data *>(data->prev_data);

		if (data->errored) {
			/* Clean up new data on error */
			if (new_data) {
				delete new_data->model;
				delete new_data;
				data->cur_data = nullptr;
			}
			return;
		}

		/* Standard map pattern: publish cur_data (fasttext_map_data*) to target.
		 * rspamd_map_remove_all reads *target back as cbdata.cur_data for the dtor,
		 * so the type must match what the dtor expects. */
		if (target) {
			*target = data->cur_data;
		}

		/* Destroy old model and its wrapper */
		if (old_data) {
			delete old_data->model;
			delete old_data;
		}
	}

	/* Map destructor callback */
	static void fasttext_map_dtor_cb(struct map_cb_data *data)
	{
		auto *fdata = static_cast<fasttext_map_data *>(data->cur_data);
		if (fdata) {
			delete fdata->model;
			delete fdata;
		}
	}

public:
	explicit fasttext_langdet(struct rspamd_config *cfg)
		: cfg_(cfg)
	{
		const auto *ucl_obj = cfg->cfg_ucl_obj;
		const auto *opts_section = ucl_object_find_key(ucl_obj, "lang_detection");

		if (opts_section) {
			const auto *model = ucl_object_find_key(opts_section, "fasttext_model");

			if (model) {
				const char *model_path = ucl_object_tostring(model);

				if (rspamd_map_is_map(model_path)) {
					load_model_map(model_path);
				}
				else {
					load_model_direct(model_path);
				}
			}
		}
	}

	/* Disallow multiple initialisation */
	fasttext_langdet() = delete;
	fasttext_langdet(const fasttext_langdet &) = delete;
	fasttext_langdet(fasttext_langdet &&) = delete;

	~fasttext_langdet() = default;

	auto is_enabled() const -> bool
	{
		return get_model() != nullptr;
	}

	auto word2vec(const char *in, std::size_t len, std::vector<std::int32_t> &word_ngramms) const
	{
		auto *model = get_model();
		if (!model) {
			return;
		}

		model->word2vec(std::string_view{in, len}, word_ngramms);
	}

	auto detect_language(std::vector<std::int32_t> &words, int k)
		-> std::vector<std::pair<float, std::string>> *
	{
		auto *model = get_model();
		if (!model) {
			return nullptr;
		}

		std::vector<rspamd::fasttext::prediction> preds;
		model->predict(k, words, preds, 0.0f);

		auto *results = new std::vector<std::pair<float, std::string>>;
		results->reserve(preds.size());

		for (const auto &pred: preds) {
			results->push_back(std::make_pair(pred.prob, pred.label));
		}

		return results;
	}

	auto model_info(void) const -> const std::string
	{
		auto *model = get_model();
		if (!model) {
			static const auto not_loaded = std::string{"fasttext model is not loaded"};
			return not_loaded;
		}
		else {
			return fmt::format("fasttext model {}: {} languages, {} tokens", model_fname,
							   model->get_nlabels(), model->get_ntokens());
		}
	}
};
}// namespace rspamd::langdet

/* C API part */
G_BEGIN_DECLS

#define FASTTEXT_MODEL_TO_C_API(p) reinterpret_cast<rspamd::langdet::fasttext_langdet *>(p)
#define FASTTEXT_RESULT_TO_C_API(res) reinterpret_cast<std::vector<std::pair<float, std::string>> *>(res)

void *rspamd_lang_detection_fasttext_init(struct rspamd_config *cfg)
{
	return (void *) new rspamd::langdet::fasttext_langdet(cfg);
}

char *rspamd_lang_detection_fasttext_show_info(void *ud)
{
	auto model_info = FASTTEXT_MODEL_TO_C_API(ud)->model_info();

	return g_strdup(model_info.c_str());
}

bool rspamd_lang_detection_fasttext_is_enabled(void *ud)
{
	auto *real_model = FASTTEXT_MODEL_TO_C_API(ud);

	if (real_model) {
		return real_model->is_enabled();
	}

	return false;
}

rspamd_fasttext_predict_result_t rspamd_lang_detection_fasttext_detect(void *ud,
																	   struct rspamd_task *task,
																	   rspamd_words_t *utf_words,
																	   int k)
{
	/* Avoid too long inputs */
	static const size_t max_fasttext_input_len = 1024 * 1024;
	auto *real_model = FASTTEXT_MODEL_TO_C_API(ud);
	std::vector<std::int32_t> words_vec;

	if (!utf_words || !utf_words->a) {
		return nullptr;
	}

	auto words_count = kv_size(*utf_words);
	words_vec.reserve(words_count);

	for (auto i = 0; i < std::min(words_count, max_fasttext_input_len); i++) {
		const auto *w = &kv_A(*utf_words, i);
		if (w->original.len > 0) {
			real_model->word2vec(w->original.begin, w->original.len, words_vec);
		}
	}

	msg_debug_lang_det("fasttext: got %z word tokens from %z words", words_vec.size(), words_count);

	auto *res = real_model->detect_language(words_vec, k);

	return (rspamd_fasttext_predict_result_t) res;
}

void rspamd_lang_detection_fasttext_destroy(void *ud)
{
	delete FASTTEXT_MODEL_TO_C_API(ud);
}


unsigned int rspamd_lang_detection_fasttext_get_nlangs(rspamd_fasttext_predict_result_t res)
{
	auto *real_res = FASTTEXT_RESULT_TO_C_API(res);

	if (real_res) {
		return real_res->size();
	}
	return 0;
}

const char *
rspamd_lang_detection_fasttext_get_lang(rspamd_fasttext_predict_result_t res, unsigned int idx)
{
	auto *real_res = FASTTEXT_RESULT_TO_C_API(res);

	if (real_res && real_res->size() > idx) {
		/* Fasttext returns result in form __label__<lang>, so we need to remove __label__ prefix */
		auto lang = std::string_view{real_res->at(idx).second};
		if (lang.size() > sizeof("__label__") && lang.substr(0, sizeof("__label__") - 1) == "__label__") {
			lang.remove_prefix(sizeof("__label__") - 1);
		}
		return lang.data();
	}
	return nullptr;
}

float rspamd_lang_detection_fasttext_get_prob(rspamd_fasttext_predict_result_t res, unsigned int idx)
{
	auto *real_res = FASTTEXT_RESULT_TO_C_API(res);

	if (real_res && real_res->size() > idx) {
		return real_res->at(idx).first;
	}
	return 0.0f;
}

void rspamd_fasttext_predict_result_destroy(rspamd_fasttext_predict_result_t res)
{
	auto *real_res = FASTTEXT_RESULT_TO_C_API(res);

	delete real_res;
}

G_END_DECLS
