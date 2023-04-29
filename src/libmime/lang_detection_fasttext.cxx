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
#include <exception>
#include <string>
#include <vector>
#include <sstream>
#include <streambuf>
#endif

#ifdef WITH_FASTTEXT
namespace rspamd::langdet {
class fasttext_langdet {
private:
	fasttext::FastText ft;
	std::string model_fname;
	bool loaded;

	struct one_shot_buf : public std::streambuf {
		explicit one_shot_buf(const char *in, std::size_t sz) {
			auto deconst_in = const_cast<char *>(in);
			setg(deconst_in, deconst_in, deconst_in + sz);
		}
	};
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
	auto detect_language(const char *in, size_t len, int k) const -> std::vector<std::pair<fasttext::real, std::string>> *
	{
		if (!loaded) {
			return nullptr;
		}

		/* Hack to deal with streams without copies */
		one_shot_buf buf{in, len};
		auto stream = std::istream{&buf};
		auto predictions = new std::vector<std::pair<fasttext::real, std::string>>;
		predictions->reserve(k);
		auto res = ft.predictLine(stream, *predictions, k, 0.0f);

		if (res) {
			return predictions;
		}
		else {
			delete predictions;
		}

		return nullptr;
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
											   const char *in, size_t len, int k)
{
#ifndef WITH_FASTTEXT
	return nullptr;
#else
	auto *real_model = FASTTEXT_MODEL_TO_C_API(ud);
	auto *res = real_model->detect_language(in, len, k);

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

	if (real_res && real_res->size() < idx) {
		return real_res->at(idx).second.c_str();
	}
#endif
	return nullptr;
}

float
rspamd_lang_detection_fasttext_get_prob(rspamd_fasttext_predict_result_t res, unsigned int idx)
{
#ifdef WITH_FASTTEXT
	auto *real_res = FASTTEXT_RESULT_TO_C_API(res);

	if (real_res && real_res->size() < idx) {
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