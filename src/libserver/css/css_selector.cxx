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

#include "css_selector.hxx"
#include "css.hxx"
#include "libserver/html/html.hxx"
#include "libserver/html/html_tag.hxx"
#include "contrib/fmt/include/fmt/base.h"
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

#include <algorithm>

namespace rspamd::css {

/*
 * Parsing
 *
 * The token stream is the preamble of a qualified rule: components (with
 * whitespace preserved, as it is the descendant combinator) and, for the
 * attribute selectors, nested blocks. We build compounds left to right,
 * remember the combinator between each pair, and turn the list into a
 * subject plus a right-to-left chain when the selector ends (comma or eof).
 *
 * Anything we cannot evaluate (pseudo classes, attributes, unknown tags,
 * dangling combinators) poisons the current selector: it is skipped up to
 * the next comma, as attaching a prefix of it would apply the declarations
 * to elements the author never targeted.
 */
auto process_selector_tokens(rspamd_mempool_t *pool,
							 blocks_gen_functor &&next_token_functor)
	-> selectors_vec
{
	selectors_vec ret;
	/* Compounds of the selector being parsed, left to right */
	std::vector<css_compound_selector> compounds;
	/* combinators[i] sits between compounds[i] and compounds[i + 1] */
	std::vector<css_selector::combinator_type> combinators;
	/* Compound being accumulated */
	css_compound_selector cur;
	/* Whitespace after the current compound: a descendant combinator unless an explicit one follows */
	bool ws_pending = false;
	/* After '.' or '#' we need an ident to complete the part */
	bool expect_ident = false;
	auto expect_type = css_simple_selector::selector_type::SELECTOR_CLASS;
	/* The selector cannot be evaluated: skip up to the next comma */
	bool broken = false;

	auto reset = [&]() {
		compounds.clear();
		combinators.clear();
		cur.parts.clear();
		ws_pending = false;
		expect_ident = false;
		broken = false;
	};

	auto add_part = [&](css_simple_selector &&part) {
		if (ws_pending && !cur.parts.empty()) {
			/* Whitespace between two compounds */
			compounds.push_back(std::move(cur));
			cur.parts.clear();
			combinators.push_back(css_selector::combinator_type::descendant);
		}

		ws_pending = false;
		cur.parts.push_back(std::move(part));
	};

	auto add_combinator = [&](css_selector::combinator_type comb) {
		if (cur.parts.empty()) {
			/* Leading or doubled combinator */
			msg_debug_css("combinator without a preceding compound, drop selector");
			broken = true;
			return;
		}

		compounds.push_back(std::move(cur));
		cur.parts.clear();
		combinators.push_back(comb);
		ws_pending = false;
	};

	auto finish = [&]() {
		if (!broken && !expect_ident && !cur.parts.empty()) {
			compounds.push_back(std::move(cur));
			cur.parts.clear();

			auto sel = std::make_unique<css_selector>();
			sel->subject = std::move(compounds.back());

			for (auto i = compounds.size() - 1; i > 0; i--) {
				sel->chain.push_back(css_selector::link{combinators[i - 1],
														std::move(compounds[i - 1])});
			}

			if (sel->chain.size() <= css_selector::max_chain_length) {
				msg_debug_css("attached selector: %s", sel->debug_str().c_str());
				ret.push_back(std::move(sel));
			}
			else {
				msg_debug_css("selector chain is too long: %d links, drop selector",
							  (int) sel->chain.size());
			}
		}
		else {
			msg_debug_css("not attached selector: broken=%d, expect_ident=%d, empty=%d",
						  (int) broken, (int) expect_ident, (int) cur.parts.empty());
		}

		reset();
	};

	for (;;) {
		const auto &next_tok = next_token_functor();

		if (next_tok.tag == css_consumed_block::parser_tag_type::css_eof_block) {
			finish();
			break;
		}

		if (next_tok.tag != css_consumed_block::parser_tag_type::css_component) {
			/*
			 * A nested block: an attribute selector `[...]` or a functional
			 * pseudo class argument; neither is evaluated
			 */
			msg_debug_css("cannot evaluate nested block %s in a selector, drop selector",
						  next_tok.token_type_str());
			broken = true;
			continue;
		}

		const auto &parser_tok = next_tok.get_token_or_empty();

		if (parser_tok.type == css_parser_token::token_type::comma_token) {
			finish();
			continue;
		}

		if (broken) {
			auto debug_str = parser_tok.get_string_or_default("");
			msg_debug_css("ignore token %*s", (int) debug_str.size(),
						  debug_str.data());
			continue;
		}

		if (expect_ident) {
			if (parser_tok.type == css_parser_token::token_type::ident_token) {
				add_part(css_simple_selector{parser_tok.get_string_or_default(""),
											 expect_type});
				expect_ident = false;
			}
			else {
				msg_debug_css("invalid parser token: %s; expected ident, drop selector",
							  next_tok.token_type_str());
				broken = true;
			}
			continue;
		}

		switch (parser_tok.type) {
		case css_parser_token::token_type::whitespace_token:
			if (!cur.parts.empty()) {
				ws_pending = true;
			}
			break;
		case css_parser_token::token_type::ident_token: {
			auto name = parser_tok.get_string_or_default("");
			auto tag_id = html::html_tag_by_name(name);

			if (tag_id) {
				add_part(css_simple_selector{tag_id.value()});
			}
			else {
				/* Such an element can never be matched */
				msg_debug_css("unknown tag %*s in a selector, drop selector",
							  (int) name.size(), name.data());
				broken = true;
			}
			break;
		}
		case css_parser_token::token_type::hash_token:
			add_part(css_simple_selector{parser_tok.get_string_or_default(""),
										 css_simple_selector::selector_type::SELECTOR_ID});
			break;
		case css_parser_token::token_type::delim_token: {
			auto delim_c = parser_tok.get_delim();

			switch (delim_c) {
			case '.':
				expect_ident = true;
				expect_type = css_simple_selector::selector_type::SELECTOR_CLASS;
				break;
			case '#':
				expect_ident = true;
				expect_type = css_simple_selector::selector_type::SELECTOR_ID;
				break;
			case '*':
				add_part(css_simple_selector{css_simple_selector::selector_type::SELECTOR_ALL});
				break;
			case '>':
				add_combinator(css_selector::combinator_type::child);
				break;
			case '+':
				add_combinator(css_selector::combinator_type::next_sibling);
				break;
			case '~':
				add_combinator(css_selector::combinator_type::subsequent_sibling);
				break;
			default:
				msg_debug_css("unexpected delimiter %c in a selector, drop selector", delim_c);
				broken = true;
				break;
			}
			break;
		}
		default:
			/* Pseudo classes and elements, numbers, strings and so on */
			msg_debug_css("cannot consume selector token: %s; drop selector",
						  next_tok.token_type_str());
			broken = true;
			break;
		}
	}

	return ret; /* copy elision */
}

/*
 * Matching
 */

static auto tag_has_class(const html::html_tag *tag, std::string_view cls) -> bool
{
	auto class_comp = tag->find_class();

	if (!class_comp) {
		return false;
	}

	auto strv = class_comp.value();
	std::size_t start = 0;

	while (start < strv.size()) {
		const auto last = strv.find_first_of(" \t\r\n", start);
		const auto elt = strv.substr(start, last - start);

		if (elt == cls) {
			return true;
		}

		if (last == std::string_view::npos) {
			break;
		}

		start = last + 1;
	}

	return false;
}

auto css_simple_selector::matches(const html::html_tag *tag) const -> bool
{
	switch (type) {
	case selector_type::SELECTOR_ALL:
		return true;
	case selector_type::SELECTOR_TAG:
		return static_cast<tag_id_t>(tag->id) == std::get<tag_id_t>(value);
	case selector_type::SELECTOR_ID: {
		auto id_comp = tag->find_id();
		return id_comp && id_comp.value() == std::get<std::string_view>(value);
	}
	case selector_type::SELECTOR_CLASS:
		return tag_has_class(tag, std::get<std::string_view>(value));
	}

	return false;
}

auto css_compound_selector::key() const -> const css_simple_selector &
{
	/* Parts are never empty for a parsed selector */
	return *std::max_element(parts.begin(), parts.end(),
							 [](const auto &a, const auto &b) {
								 return a.specificity() < b.specificity();
							 });
}

auto css_compound_selector::matches(const html::html_tag *tag) const -> bool
{
	return std::all_of(parts.begin(), parts.end(),
					   [tag](const auto &p) { return p.matches(tag); });
}

/*
 * Match the chain from the link `idx` on, starting from `elt` (the element
 * matched by the previous link or the subject). Descendant and subsequent
 * sibling combinators backtrack over all candidates, so `a b c` still
 * matches when the nearest `b` ancestor has no `a` above it but a farther
 * one has.
 */
static auto match_chain(const std::vector<css_selector::link> &chain,
						std::size_t idx,
						const html::html_tag *elt) -> bool
{
	if (idx == chain.size()) {
		return true;
	}

	const auto &lnk = chain[idx];

	switch (lnk.combinator) {
	case css_selector::combinator_type::child: {
		const auto *p = elt->parent;
		return p && lnk.target.matches(p) && match_chain(chain, idx + 1, p);
	}
	case css_selector::combinator_type::descendant:
		for (const auto *p = elt->parent; p != nullptr; p = p->parent) {
			if (lnk.target.matches(p) && match_chain(chain, idx + 1, p)) {
				return true;
			}
		}
		return false;
	case css_selector::combinator_type::next_sibling: {
		const auto *p = elt->parent;

		if (!p) {
			return false;
		}

		const html::html_tag *prev = nullptr;
		bool found = false;

		for (const auto *s: p->children) {
			if (s == elt) {
				found = true;
				break;
			}
			prev = s;
		}

		return found && prev && lnk.target.matches(prev) && match_chain(chain, idx + 1, prev);
	}
	case css_selector::combinator_type::subsequent_sibling: {
		const auto *p = elt->parent;

		if (!p) {
			return false;
		}

		for (const auto *s: p->children) {
			if (s == elt) {
				break;
			}
			if (lnk.target.matches(s) && match_chain(chain, idx + 1, s)) {
				return true;
			}
		}

		return false;
	}
	}

	return false;
}

auto css_selector::matches(const html::html_tag *tag) const -> bool
{
	if (!tag || !subject.matches(tag)) {
		return false;
	}

	return match_chain(chain, 0, tag);
}

/*
 * Debug output
 */

auto css_simple_selector::debug_str() const -> std::string
{
	std::string ret;

	if (type == selector_type::SELECTOR_ID) {
		ret += "#";
	}
	else if (type == selector_type::SELECTOR_CLASS) {
		ret += ".";
	}
	else if (type == selector_type::SELECTOR_ALL) {
		ret = "*";

		return ret;
	}

	std::visit([&](auto arg) -> void {
		using T = std::decay_t<decltype(arg)>;

		if constexpr (std::is_same_v<T, tag_id_t>) {
			ret += fmt::format("tag: {}", static_cast<int>(arg));
		}
		else {
			ret += arg;
		}
	},
			   value);

	return ret;
}

auto css_compound_selector::debug_str() const -> std::string
{
	std::string ret;

	for (const auto &p: parts) {
		ret += p.debug_str();
	}

	return ret;
}

auto css_selector::debug_str() const -> std::string
{
	/* Print left to right, as written */
	std::string ret;

	for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
		ret += it->target.debug_str();

		switch (it->combinator) {
		case combinator_type::descendant:
			ret += " ";
			break;
		case combinator_type::child:
			ret += " > ";
			break;
		case combinator_type::next_sibling:
			ret += " + ";
			break;
		case combinator_type::subsequent_sibling:
			ret += " ~ ";
			break;
		}
	}

	ret += subject.debug_str();

	return ret;
}

TEST_SUITE("css")
{
	TEST_CASE("simple css selectors")
	{
		using st = css_simple_selector::selector_type;
		const std::vector<std::pair<const char *, std::vector<st>>> cases{
			{"em", {st::SELECTOR_TAG}},
			{"*", {st::SELECTOR_ALL}},
			{".class", {st::SELECTOR_CLASS}},
			{"#id", {st::SELECTOR_ID}},
			{"em,.class,#id", {st::SELECTOR_TAG, st::SELECTOR_CLASS, st::SELECTOR_ID}},
			{"em , .class ,#id ", {st::SELECTOR_TAG, st::SELECTOR_CLASS, st::SELECTOR_ID}},
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		for (const auto &c: cases) {
			auto res = process_selector_tokens(pool,
											   get_selectors_parser_functor(pool, c.first));

			CHECK(c.second.size() == res.size());

			for (auto i = 0; i < c.second.size(); i++) {
				CHECK(res[i]->is_simple());
				CHECK(res[i]->key().type == c.second[i]);
			}
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("compound and complex css selectors")
	{
		using st = css_simple_selector::selector_type;
		using ct = css_selector::combinator_type;
		struct expected {
			std::vector<st> subject;
			std::vector<std::pair<ct, std::vector<st>>> chain; /* right to left */
			st key;
		};
		const std::vector<std::pair<const char *, expected>> cases{
			{"div.mainbox", {{st::SELECTOR_TAG, st::SELECTOR_CLASS}, {}, st::SELECTOR_CLASS}},
			{"*.spacer#top", {{st::SELECTOR_ALL, st::SELECTOR_CLASS, st::SELECTOR_ID}, {}, st::SELECTOR_ID}},
			{".a.b", {{st::SELECTOR_CLASS, st::SELECTOR_CLASS}, {}, st::SELECTOR_CLASS}},
			{"div p", {{st::SELECTOR_TAG}, {{ct::descendant, {st::SELECTOR_TAG}}}, st::SELECTOR_TAG}},
			{".a .b", {{st::SELECTOR_CLASS}, {{ct::descendant, {st::SELECTOR_CLASS}}}, st::SELECTOR_CLASS}},
			{"div > p", {{st::SELECTOR_TAG}, {{ct::child, {st::SELECTOR_TAG}}}, st::SELECTOR_TAG}},
			{"div>p", {{st::SELECTOR_TAG}, {{ct::child, {st::SELECTOR_TAG}}}, st::SELECTOR_TAG}},
			{"h1 + p", {{st::SELECTOR_TAG}, {{ct::next_sibling, {st::SELECTOR_TAG}}}, st::SELECTOR_TAG}},
			{"h1 ~ p", {{st::SELECTOR_TAG}, {{ct::subsequent_sibling, {st::SELECTOR_TAG}}}, st::SELECTOR_TAG}},
			{"div.mainbox ul li.spacer",
			 {{st::SELECTOR_TAG, st::SELECTOR_CLASS},
			  {{ct::descendant, {st::SELECTOR_TAG}}, {ct::descendant, {st::SELECTOR_TAG, st::SELECTOR_CLASS}}},
			  st::SELECTOR_CLASS}},
			{"#top > div span",
			 {{st::SELECTOR_TAG},
			  {{ct::descendant, {st::SELECTOR_TAG}}, {ct::child, {st::SELECTOR_ID}}},
			  st::SELECTOR_TAG}},
			{"div * ", {{st::SELECTOR_ALL}, {{ct::descendant, {st::SELECTOR_TAG}}}, st::SELECTOR_ALL}},
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		for (const auto &c: cases) {
			auto res = process_selector_tokens(pool,
											   get_selectors_parser_functor(pool, c.first));

			REQUIRE_MESSAGE(res.size() == 1, c.first);
			const auto &sel = *res[0];
			const auto &exp = c.second;

			REQUIRE_MESSAGE(sel.subject.parts.size() == exp.subject.size(), c.first);
			for (auto i = 0; i < exp.subject.size(); i++) {
				CHECK_MESSAGE(sel.subject.parts[i].type == exp.subject[i], c.first);
			}

			REQUIRE_MESSAGE(sel.chain.size() == exp.chain.size(), c.first);
			for (auto i = 0; i < exp.chain.size(); i++) {
				CHECK_MESSAGE(sel.chain[i].combinator == exp.chain[i].first, c.first);
				REQUIRE_MESSAGE(sel.chain[i].target.parts.size() == exp.chain[i].second.size(), c.first);
				for (auto j = 0; j < exp.chain[i].second.size(); j++) {
					CHECK_MESSAGE(sel.chain[i].target.parts[j].type == exp.chain[i].second[j], c.first);
				}
			}

			CHECK_MESSAGE(sel.key().type == exp.key, c.first);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("selectors that cannot be evaluated are dropped whole")
	{
		/*
		 * A selector we cannot evaluate must be dropped as a whole: keeping
		 * a prefix of it would apply the declarations to every element that
		 * prefix names. Other members of the list are kept
		 */
		const std::vector<std::pair<const char *, std::size_t>> cases{
			/* Pseudo classes and elements */
			{"a:hover", 0},
			{"p::first-line", 0},
			{"a:not(.x)", 0},
			{"a:hover, p", 1},
			{"p, a:hover", 1},
			{"a:not(.x), p", 1},
			/* Attribute selectors are tokenised as a nested block */
			{"a[href]", 0},
			{"a[href], p", 1},
			{"p, a[href]", 1},
			{"td[class=\"x\"] p", 0},
			/* Unknown element names never match */
			{"blink", 0},
			{"blink, p", 1},
			{"div blink", 0},
			/* Dangling and doubled combinators */
			{"> p", 0},
			{"div >", 0},
			{"div > > p", 0},
			{"div + , p", 1},
			{"div .", 0},
			{".class.", 0},
			/* Mixed lists */
			{"div.mainbox li.spacer, p", 2},
			{"p, div.mainbox li.spacer", 2},
			{"div.mainbox ul li.spacer, div.mainbox ol li.spacer", 2},
			{"em,.class,#id", 3},
			{"*", 1},
			{"", 0},
			{" , ", 0},
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		for (const auto &c: cases) {
			auto res = process_selector_tokens(pool,
											   get_selectors_parser_functor(pool, c.first));
			CHECK_MESSAGE(res.size() == c.second, c.first);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("selector chain length is bounded")
	{
		std::string too_long = "p";

		for (auto i = 0; i < css_selector::max_chain_length + 1; i++) {
			too_long += " > p";
		}

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);
		auto res = process_selector_tokens(pool,
										   get_selectors_parser_functor(pool, too_long));
		CHECK(res.empty());

		std::string just_fits = "p";

		for (auto i = 0; i < css_selector::max_chain_length; i++) {
			just_fits += " > p";
		}

		res = process_selector_tokens(pool,
									  get_selectors_parser_functor(pool, just_fits));
		REQUIRE(res.size() == 1);
		CHECK(res[0]->chain.size() == css_selector::max_chain_length);

		rspamd_mempool_delete(pool);
	}
}

}// namespace rspamd::css
