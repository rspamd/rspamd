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
#include <memory>

#include "function2/function2.hpp"
#include "parse_error.hxx"
#include "css_parser.hxx"
#include "libserver/html/html_tags.h"
#include "libcryptobox/cryptobox.h"

namespace rspamd::css {

/*
 * Holds a value for css selector, internal is handled by variant
 */
struct css_selector {
	enum class selector_type {
		SELECTOR_TAG, /* e.g. tr, for this value we use tag_id_t */
		SELECTOR_CLASS, /* generic class, e.g. .class */
		SELECTOR_ID, /* e.g. #id */
		SELECTOR_ALL /* * selector */
	};

	selector_type type;
	std::variant<tag_id_t, std::string_view> value;

	/* Conditions for the css selector */
	/* Dependency on attributes */
	struct css_attribute_condition {
		std::string_view attribute;
		std::string_view op = "";
		std::string_view value = "";
	};

	/* General dependency chain */
	using css_selector_ptr = std::unique_ptr<css_selector>;
	using css_selector_dep = std::variant<css_attribute_condition, css_selector_ptr>;
	std::vector<css_selector_dep> dependencies;

	 auto to_tag(void) const -> std::optional<tag_id_t> {
		if (type == selector_type::SELECTOR_TAG) {
			return std::get<tag_id_t>(value);
		}
		return std::nullopt;
	}

	auto to_string(void) const -> std::optional<const std::string_view> {
		if (type != selector_type::SELECTOR_TAG) {
			return std::string_view(std::get<std::string_view>(value));
		}
		return std::nullopt;
	};

	explicit css_selector(selector_type t) : type(t) {}
	explicit css_selector(tag_id_t t) : type(selector_type::SELECTOR_TAG) {
		value = t;
	}
	explicit css_selector(const std::string_view &st, selector_type t = selector_type::SELECTOR_ID) : type(t) {
		value = st;
	}

	auto operator ==(const css_selector &other) const -> bool {
		return type == other.type && value == other.value;
	}

	auto debug_str(void) const -> std::string;
};


using selectors_vec = std::vector<std::unique_ptr<css_selector>>;

/*
 * Consume selectors token and split them to the list of selectors
 */
auto process_selector_tokens(rspamd_mempool_t *pool,
							 blocks_gen_functor &&next_token_functor)
	-> selectors_vec;

}

/* Selectors hashing */
namespace std {
template<>
class hash<rspamd::css::css_selector> {
public:
	auto operator() (const rspamd::css::css_selector &sel) const -> std::size_t {
		if (sel.type == rspamd::css::css_selector::selector_type::SELECTOR_TAG) {
			return static_cast<std::size_t>(std::get<tag_id_t>(sel.value));
		}
		else {
			const auto &sv = std::get<std::string_view>(sel.value);

			return rspamd_cryptobox_fast_hash(sv.data(), sv.size(), 0xdeadbabe);
		}
	}
};
}

#endif //RSPAMD_CSS_SELECTOR_HXX
