/*-
 * Copyright 2021 Vsevolod Stakhov
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

#pragma once

#ifndef RSPAMD_CSS_SELECTOR_HXX
#define RSPAMD_CSS_SELECTOR_HXX

#include <variant>
#include <string>
#include <optional>
#include <vector>
#include <functional>
#include <memory>
#include "parse_error.hxx"
#include "css_tokeniser.hxx"
#include "html_tags.h"

namespace rspamd::css {

/*
 * Holds a value for css selector, internal is handled by variant
 */
struct css_selector {
	enum class selector_type {
		SELECTOR_ELEMENT, /* e.g. .tr, for this value we use tag_id_t */
		SELECTOR_CLASS, /* generic class */
		SELECTOR_ID /* e.g. #id */
	};

	selector_type type;
	std::variant<tag_id_t, std::string> value;

	 auto to_tag(void) const -> std::optional<tag_id_t> {
		if (type == selector_type::SELECTOR_ELEMENT) {
			return std::get<tag_id_t>(value);
		}
		return std::nullopt;
	}

	auto to_string(void) const -> std::optional<const std::string_view> {
		if (type == selector_type::SELECTOR_ELEMENT) {
			return std::string_view(std::get<std::string>(value));
		}
		return std::nullopt;
	};
};

using selectors_vec = std::vector<std::unique_ptr<css_selector>>;

/*
 * Consume selectors token and split them to the list of selectors
 */
auto process_selector_tokens(rspamd_mempool_t *pool,
							 const tokeniser_gen_functor &next_token_functor)
	-> selectors_vec;

}

#endif //RSPAMD_CSS_SELECTOR_HXX
