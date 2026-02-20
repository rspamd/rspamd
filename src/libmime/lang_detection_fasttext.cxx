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
class fasttext_langdet {
private:
	std::optional<rspamd::fasttext::fasttext_model> model_;
	std::string model_fname;

public:
	explicit fasttext_langdet(struct rspamd_config *cfg)
	{
		const auto *ucl_obj = cfg->cfg_ucl_obj;
		const auto *opts_section = ucl_object_find_key(ucl_obj, "lang_detection");

		if (opts_section) {
			const auto *model = ucl_object_find_key(opts_section, "fasttext_model");

			if (model) {
				const char *model_path = ucl_object_tostring(model);

				if (access(model_path, R_OK) != 0) {
					msg_err_config("fasttext model '%s' is not readable: %s",
								   model_path, strerror(errno));
					return;
				}

				auto result = rspamd::fasttext::fasttext_model::load(model_path);
				if (result) {
					model_.emplace(std::move(*result));
					model_fname = std::string{model_path};
				}
				else {
					msg_err_config("cannot load fasttext model '%s': %s",
								   model_path, result.error().error_message.data());
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
		return model_.has_value();
	}

	auto word2vec(const char *in, std::size_t len, std::vector<std::int32_t> &word_ngramms) const
	{
		if (!model_) {
			return;
		}

		model_->word2vec(std::string_view{in, len}, word_ngramms);
	}

	auto detect_language(std::vector<std::int32_t> &words, int k)
		-> std::vector<std::pair<float, std::string>> *
	{
		if (!model_) {
			return nullptr;
		}

		std::vector<rspamd::fasttext::prediction> preds;
		model_->predict(k, words, preds, 0.0f);

		auto *results = new std::vector<std::pair<float, std::string>>;
		results->reserve(preds.size());

		for (const auto &pred: preds) {
			results->push_back(std::make_pair(pred.prob, pred.label));
		}

		return results;
	}

	auto model_info(void) const -> const std::string
	{
		if (!model_) {
			static const auto not_loaded = std::string{"fasttext model is not loaded"};
			return not_loaded;
		}
		else {
			return fmt::format("fasttext model {}: {} languages, {} tokens", model_fname,
							   model_->get_nlabels(), model_->get_ntokens());
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
