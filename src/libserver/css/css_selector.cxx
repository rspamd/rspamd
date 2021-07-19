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

#include "css_selector.hxx"
#include "css.hxx"
#include "libserver/html/html.hxx"
#include "fmt/core.h"
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

namespace rspamd::css {

auto process_selector_tokens(rspamd_mempool_t *pool,
							 blocks_gen_functor &&next_token_functor)
	-> selectors_vec
{
	selectors_vec ret;
	bool can_continue = true;
	enum class selector_process_state {
		selector_parse_start = 0,
		selector_expect_ident,
		selector_ident_consumed,
		selector_ignore_attribute,
		selector_ignore_function,
		selector_ignore_combination
	} state = selector_process_state::selector_parse_start;
	std::unique_ptr<css_selector> cur_selector;


	while (can_continue) {
		const auto &next_tok = next_token_functor();

		if (next_tok.tag == css_consumed_block::parser_tag_type::css_component) {
			const auto &parser_tok = next_tok.get_token_or_empty();

			if (state == selector_process_state::selector_parse_start) {
				/*
				 * At the beginning of the parsing we can expect either
				 * delim or an ident, everything else is discarded for now
				 */
				msg_debug_css("start consume selector");

				switch (parser_tok.type) {
				case css_parser_token::token_type::delim_token: {
					auto delim_c = parser_tok.get_delim();

					if (delim_c == '.') {
						cur_selector = std::make_unique<css_selector>(
								css_selector::selector_type::SELECTOR_CLASS);
						state = selector_process_state::selector_expect_ident;
					}
					else if (delim_c == '#') {
						cur_selector = std::make_unique<css_selector>(
								css_selector::selector_type::SELECTOR_ID);
						state = selector_process_state::selector_expect_ident;
					}
					else if (delim_c == '*') {
						cur_selector = std::make_unique<css_selector>(
								css_selector::selector_type::SELECTOR_ALL);
						state = selector_process_state::selector_ident_consumed;
					}
					break;
				}
				case css_parser_token::token_type::ident_token: {
					auto tag_id = html::html_tag_by_name(parser_tok.get_string_or_default(""));

					if (tag_id) {
						cur_selector = std::make_unique<css_selector>(tag_id.value());
					}
					state = selector_process_state::selector_ident_consumed;
					break;
				}
				case css_parser_token::token_type::hash_token:
					cur_selector = std::make_unique<css_selector>(
							css_selector::selector_type::SELECTOR_ID);
					cur_selector->value =
							parser_tok.get_string_or_default("");
					state = selector_process_state::selector_ident_consumed;
					break;
				default:
					msg_debug_css("cannot consume more of a selector, invalid parser token: %s; expected start",
							next_tok.token_type_str());
					can_continue = false;
					break;
				}
			}
			else if (state == selector_process_state::selector_expect_ident) {
				/*
				 * We got something like a selector start, so we expect
				 * a plain ident
				 */
				if (parser_tok.type == css_parser_token::token_type::ident_token && cur_selector) {
					cur_selector->value = parser_tok.get_string_or_default("");
					state = selector_process_state::selector_ident_consumed;
				}
				else {
					msg_debug_css("cannot consume more of a selector, invalid parser token: %s; expected ident",
							next_tok.token_type_str());
					can_continue = false;
				}
			}
			else if (state == selector_process_state::selector_ident_consumed) {
				if (parser_tok.type == css_parser_token::token_type::comma_token && cur_selector) {
					/* Got full selector, attach it to the vector and go further */
					msg_debug_css("attached selector: %s", cur_selector->debug_str().c_str());
					ret.push_back(std::move(cur_selector));
					state = selector_process_state::selector_parse_start;
				}
				else if (parser_tok.type == css_parser_token::token_type::semicolon_token) {
					/* TODO: implement adjustments */
					state = selector_process_state::selector_ignore_function;
				}
				else if (parser_tok.type == css_parser_token::token_type::osqbrace_token) {
					/* TODO: implement attributes checks */
					state = selector_process_state::selector_ignore_attribute;
				}
				else {
					/* TODO: implement selectors combinations */
					state = selector_process_state::selector_ignore_combination;
				}
			}
			else {
				/* Ignore state; ignore all till ',' token or eof token */
				if (parser_tok.type == css_parser_token::token_type::comma_token && cur_selector) {
					/* Got full selector, attach it to the vector and go further */
					ret.push_back(std::move(cur_selector));
					state = selector_process_state::selector_parse_start;
				}
				else {
					auto debug_str = parser_tok.get_string_or_default("");
					msg_debug_css("ignore token %*s", (int)debug_str.size(),
							debug_str.data());
				}
			}
		}
		else {
			/* End of parsing */
			if (state == selector_process_state::selector_ident_consumed && cur_selector) {
				msg_debug_css("attached selector: %s", cur_selector->debug_str().c_str());
				ret.push_back(std::move(cur_selector));
			}
			else {
				msg_debug_css("not attached selector, state: %d", static_cast<int>(state));
			}
			can_continue = false;
		}

	}

	return ret; /* copy elision */
}

auto
css_selector::debug_str() const -> std::string
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
	}, value);

	return ret;
}

TEST_SUITE("css") {
	TEST_CASE("simple css selectors") {
		const std::vector<std::pair<const char *, std::vector<css_selector::selector_type>>> cases{
				{"em", {css_selector::selector_type::SELECTOR_TAG}},
				{"*", {css_selector::selector_type::SELECTOR_ALL}},
				{".class", {css_selector::selector_type::SELECTOR_CLASS}},
				{"#id", {css_selector::selector_type::SELECTOR_ID}},
				{"em,.class,#id", {css_selector::selector_type::SELECTOR_TAG,
								   css_selector::selector_type::SELECTOR_CLASS,
								   css_selector::selector_type::SELECTOR_ID}},
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
			"css", 0);

		for (const auto &c : cases) {
			auto res = process_selector_tokens(pool,
					get_selectors_parser_functor(pool, c.first));

			CHECK(c.second.size() == res.size());

			for (auto i = 0; i < c.second.size(); i ++) {
				CHECK(res[i]->type == c.second[i]);
			}
		}

		rspamd_mempool_delete(pool);
	}
}

}

