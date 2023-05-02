/*-
 * Copyright 2023 Vsevolod Stakhov
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

#include "lang_detection_fasttext.h"

#ifdef WITH_FASTTEXT
#include "fasttext/fasttext.h"
#include "libserver/cfg_file.h"
#include "libserver/logger.h"
#include "fmt/core.h"
#include "stat_api.h"
#include <exception>
#include <string>
#include <string_view>
#include <vector>
#endif

#ifdef WITH_FASTTEXT
namespace rspamd::langdet {
class fasttext_langdet {
private:
	fasttext::FastText ft;
	std::string model_fname;
	bool loaded;

public:
	explicit fasttext_langdet(struct rspamd_config *cfg) {
		const auto *ucl_obj = cfg->rcl_obj;
		const auto *opts_section = ucl_object_find_key(ucl_obj, "lang_detection");

		if (opts_section) {
			const auto *model = ucl_object_find_key(opts_section, "fasttext_model");

			if (model) {
				try {
					ft.loadModel(ucl_object_tostring(model));
					loaded = true;
					model_fname = std::string{ucl_object_tostring(model)};
				}
				catch (std::exception &e) {
					auto err_message = fmt::format("cannot load fasttext model: {}", e.what());
					msg_err_config("%s", err_message.c_str());
					loaded = false;
				}
			}
		}
	}

	/* Disallow multiple initialisation */
	fasttext_langdet() = delete;
	fasttext_langdet(const fasttext_langdet &) = delete;
	fasttext_langdet(fasttext_langdet &&) = delete;

	~fasttext_langdet() = default;

	auto is_enabled() const -> bool { return loaded; }
	auto word2vec(const char *in, std::size_t len, std::vector<std::int32_t> &word_ngramms) const {
		if (!loaded) {
			return;
		}

		std::string tok{in, len};
		const auto &dic = ft.getDictionary();
		auto h = dic->hash(tok);
		auto wid = dic->getId(tok, h);
		auto type = wid < 0 ? dic->getType(tok) : dic->getType(wid);

		if (type == fasttext::entry_type::word) {
			if (wid < 0) {
				auto pipelined_word = fmt::format("{}{}{}", fasttext::Dictionary::BOW, tok, fasttext::Dictionary::EOW);
				dic->computeSubwords(pipelined_word, word_ngramms);
			}
			else {
				if (ft.getArgs().maxn <= 0) {
					word_ngramms.push_back(wid);
				}
				else {
					const auto ngrams = dic->getSubwords(wid);
					word_ngramms.insert(word_ngramms.end(), ngrams.cbegin(), ngrams.cend());
				}
			}
		}
	}
	auto detect_language(std::vector<std::int32_t> &words, int k)
		-> std::vector<std::pair<fasttext::real, std::string>> *
	{
		if (!loaded) {
			return nullptr;
		}

		auto predictions = new std::vector<std::pair<fasttext::real, std::string>>;
		predictions->reserve(k);
		fasttext::Predictions line_predictions;
		line_predictions.reserve(k);
		ft.predict(k, words, line_predictions, 0.0f);
		const auto *dict = ft.getDictionary().get();

		for (const auto &pred : line_predictions) {
			predictions->push_back(std::make_pair(std::exp(pred.first), dict->getLabel(pred.second)));
		}
		return predictions;
	}

	auto model_info(void) const -> std::string {
		if (!loaded) {
			return "fasttext model is not loaded";
		}
		else {
			return fmt::format("fasttext model {}: {} languages, {} tokens", model_fname,
				ft.getDictionary()->nlabels(), ft.getDictionary()->ntokens());
		}
	}
};
}
#endif

/* C API part */
G_BEGIN_DECLS

#define FASTTEXT_MODEL_TO_C_API(p) reinterpret_cast<rspamd::langdet::fasttext_langdet *>(p)
#define FASTTEXT_RESULT_TO_C_API(res) reinterpret_cast<std::vector<std::pair<fasttext::real, std::string>> *>(res)

void* rspamd_lang_detection_fasttext_init(struct rspamd_config *cfg)
{
#ifndef WITH_FASTTEXT
	return nullptr;
#else
	return (void *)new rspamd::langdet::fasttext_langdet(cfg);
#endif
}

char *rspamd_lang_detection_fasttext_show_info(void *ud)
{
#ifndef WITH_FASTTEXT
	return g_strdup("fasttext is not compiled in");
#else
	auto model_info = FASTTEXT_MODEL_TO_C_API(ud)->model_info();

	return g_strdup(model_info.c_str());
#endif
}

bool rspamd_lang_detection_fasttext_is_enabled(void *ud)
{
#ifdef WITH_FASTTEXT
	auto *real_model = FASTTEXT_MODEL_TO_C_API(ud);

	if (real_model) {
		return real_model->is_enabled();
	}
#endif

	return false;
}

rspamd_fasttext_predict_result_t rspamd_lang_detection_fasttext_detect(void *ud,
																	   GArray *utf_words,
																	   int k)
{
#ifndef WITH_FASTTEXT
	return nullptr;
#else
	/* Avoid too long inputs */
	static const guint max_fasttext_input_len = 1024 * 1024;
	auto *real_model = FASTTEXT_MODEL_TO_C_API(ud);
	std::vector<std::int32_t> words_vec;
	words_vec.reserve(utf_words->len);

	for (auto i = 0; i < std::min(utf_words->len, max_fasttext_input_len); i++) {
		const auto *w = &g_array_index (utf_words, rspamd_stat_token_t, i);
		if (w->original.len > 0) {
			real_model->word2vec(w->original.begin, w->original.len, words_vec);
		}
	}

	auto *res = real_model->detect_language(words_vec, k);

	return (rspamd_fasttext_predict_result_t)res;
#endif
}

void rspamd_lang_detection_fasttext_destroy(void *ud)
{
#ifdef WITH_FASTTEXT
	delete FASTTEXT_MODEL_TO_C_API(ud);
#endif
}


guint
rspamd_lang_detection_fasttext_get_nlangs(rspamd_fasttext_predict_result_t res)
{
#ifdef WITH_FASTTEXT
	auto *real_res = FASTTEXT_RESULT_TO_C_API(res);

	if (real_res) {
		return real_res->size();
	}
#endif
	return 0;
}

const char *
rspamd_lang_detection_fasttext_get_lang(rspamd_fasttext_predict_result_t res, unsigned int idx)
{
#ifdef WITH_FASTTEXT
	auto *real_res = FASTTEXT_RESULT_TO_C_API(res);

	if (real_res && real_res->size() > idx) {
		/* Fasttext returns result in form __label__<lang>, so we need to remove __label__ prefix */
		auto lang = std::string_view{real_res->at(idx).second};
		if (lang.size() > sizeof("__label__") && lang.substr(0, sizeof("__label__") - 1) == "__label__") {
			lang.remove_prefix(sizeof("__label__") - 1);
		}
		return lang.data();
	}
#endif
	return nullptr;
}

float
rspamd_lang_detection_fasttext_get_prob(rspamd_fasttext_predict_result_t res, unsigned int idx)
{
#ifdef WITH_FASTTEXT
	auto *real_res = FASTTEXT_RESULT_TO_C_API(res);

	if (real_res && real_res->size() > idx) {
		return real_res->at(idx).first;
	}
#endif
	return 0.0f;
}

void rspamd_fasttext_predict_result_destroy(rspamd_fasttext_predict_result_t res)
{
#ifdef WITH_FASTTEXT
	auto *real_res = FASTTEXT_RESULT_TO_C_API(res);

	delete real_res;
#endif
}

G_END_DECLS