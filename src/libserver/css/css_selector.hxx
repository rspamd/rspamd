/*-
 * Copyright 2025 Vsevolod Stakhov
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
#include <cstdint>

#include "function2/function2.hpp"
#include "parse_error.hxx"
#include "css_parser.hxx"
#include "libserver/html/html_tags.h"
#include "libcryptobox/cryptobox.h"

namespace rspamd::html {
struct html_tag;
}

namespace rspamd::css {

/*
 * Shared by every selector and element of an HTML document. Work counts
 * selector/DOM steps and bytes scanned in attributes; exhaustion disables
 * further stylesheet matching, not HTML parsing or inline styles.
 */
struct css_match_budget {
	static constexpr std::size_t max_work = 4 * 1024 * 1024;
	std::size_t remaining = max_work;

	auto consume(std::size_t work = 1) -> bool
	{
		if (work > remaining) {
			remaining = 0;
			return false;
		}
		remaining -= work;
		return true;
	}
};

/*
 * A simple selector: a single tag name, class, id or the universal selector
 */
struct css_simple_selector {
	enum class selector_type : std::uint8_t {
		SELECTOR_TAG,   /* e.g. tr, for this value we use tag_id_t */
		SELECTOR_CLASS, /* generic class, e.g. .class */
		SELECTOR_ID,    /* e.g. #id */
		SELECTOR_ALL    /* * selector */
	};

	selector_type type;
	std::variant<tag_id_t, std::string_view> value;

	explicit css_simple_selector(selector_type t)
		: type(t)
	{
	}
	explicit css_simple_selector(tag_id_t t)
		: type(selector_type::SELECTOR_TAG)
	{
		value = t;
	}
	explicit css_simple_selector(const std::string_view &st,
								 selector_type t = selector_type::SELECTOR_ID)
		: type(t)
	{
		value = st;
	}

	auto to_tag() const -> std::optional<tag_id_t>
	{
		if (type == selector_type::SELECTOR_TAG) {
			return std::get<tag_id_t>(value);
		}
		return std::nullopt;
	}

	auto to_string() const -> std::optional<const std::string_view>
	{
		if (type != selector_type::SELECTOR_TAG) {
			return std::string_view(std::get<std::string_view>(value));
		}
		return std::nullopt;
	}

	/*
	 * Specificity weight of a single simple selector, following the CSS
	 * (id, class, type) triple flattened to one number
	 */
	auto specificity() const -> unsigned
	{
		switch (type) {
		case selector_type::SELECTOR_ID:
			return 100;
		case selector_type::SELECTOR_CLASS:
			return 10;
		case selector_type::SELECTOR_TAG:
			return 1;
		case selector_type::SELECTOR_ALL:
			break;
		}
		return 0;
	}

	auto operator==(const css_simple_selector &other) const -> bool
	{
		return type == other.type && value == other.value;
	}

	/* Check whether this simple selector matches the element itself */
	auto matches(const rspamd::html::html_tag *tag, css_match_budget &budget) const -> bool;

	auto debug_str() const -> std::string;
};

/*
 * A compound selector: simple selectors that must all match the same
 * element, e.g. `div.mainbox` or `*.spacer#top`
 */
struct css_compound_selector {
	static constexpr std::size_t max_parts = 64;
	std::vector<css_simple_selector> parts;

	auto specificity() const -> unsigned
	{
		unsigned ret = 0;

		for (const auto &p: parts) {
			ret += p.specificity();
		}

		return ret;
	}

	/*
	 * The most specific part; a style sheet indexes the selector by this
	 * part and evaluates the rest on lookup
	 */
	auto key() const -> const css_simple_selector &;

	auto operator==(const css_compound_selector &other) const -> bool
	{
		return parts == other.parts;
	}

	auto matches(const rspamd::html::html_tag *tag, css_match_budget &budget) const -> bool;
	auto debug_str() const -> std::string;
};

/*
 * A complex selector: the subject compound (the element the declarations
 * apply to) plus the chain of compounds that must match its ancestors or
 * preceding siblings.
 *
 * The chain is stored right to left, so `a > b c` has subject `c` and
 * chain [{descendant, b}, {child, a}]: each link relates the compound of
 * the previous link (or the subject for the first one) to its target.
 */
struct css_selector {
	using selector_type = css_simple_selector::selector_type;

	enum class combinator_type : std::uint8_t {
		descendant,         /* a b */
		child,              /* a > b */
		next_sibling,       /* a + b */
		subsequent_sibling, /* a ~ b */
	};

	struct link {
		combinator_type combinator;
		css_compound_selector target;

		auto operator==(const link &other) const -> bool
		{
			return combinator == other.combinator && target == other.target;
		}
	};

	/*
	 * Longer chains are dropped when parsing: matching recurses over the
	 * chain and nothing sane needs more levels than this
	 */
	static constexpr std::size_t max_chain_length = 16;
	/*
	 * Descendant and subsequent sibling links backtrack over their
	 * candidates, so a chain of them can revisit the same elements many
	 * times. The number of compound evaluations per match is bounded and
	 * a match that exhausts the budget fails
	 */
	static constexpr unsigned max_match_steps = 1024;

	css_compound_selector subject;
	std::vector<link> chain;

	css_selector() = default;
	explicit css_selector(css_simple_selector &&simple)
	{
		subject.parts.push_back(std::move(simple));
	}
	explicit css_selector(selector_type t)
		: css_selector(css_simple_selector{t})
	{
	}
	explicit css_selector(tag_id_t t)
		: css_selector(css_simple_selector{t})
	{
	}
	explicit css_selector(const std::string_view &st, selector_type t = selector_type::SELECTOR_ID)
		: css_selector(css_simple_selector{st, t})
	{
	}

	auto is_simple() const -> bool
	{
		return chain.empty() && subject.parts.size() == 1;
	}

	auto key() const -> const css_simple_selector &
	{
		return subject.key();
	}

	auto specificity() const -> unsigned
	{
		auto ret = subject.specificity();

		for (const auto &l: chain) {
			ret += l.target.specificity();
		}

		return ret;
	}

	auto operator==(const css_selector &other) const -> bool
	{
		return subject == other.subject && chain == other.chain;
	}

	/* Check whether the selector matches the element (walks the tag tree) */
	auto matches(const rspamd::html::html_tag *tag, css_match_budget &budget) const -> bool;

	auto debug_str() const -> std::string;
};


using selectors_vec = std::vector<std::unique_ptr<css_selector>>;

/*
 * Consume selectors token and split them to the list of selectors
 */
auto process_selector_tokens(rspamd_mempool_t *pool,
							 blocks_gen_functor &&next_token_functor)
	-> selectors_vec;

}// namespace rspamd::css

/* Selectors hashing */
namespace std {
template<>
class hash<rspamd::css::css_simple_selector> {
public:
	using is_avalanching = void;
	auto operator()(const rspamd::css::css_simple_selector &sel) const -> std::size_t
	{
		if (sel.type == rspamd::css::css_simple_selector::selector_type::SELECTOR_TAG) {
			return static_cast<std::size_t>(std::get<tag_id_t>(sel.value));
		}
		else {
			const auto &sv = std::get<std::string_view>(sel.value);

			return rspamd_cryptobox_fast_hash(sv.data(), sv.size(), 0xdeadbabe);
		}
	}
};
}// namespace std

#endif//RSPAMD_CSS_SELECTOR_HXX
