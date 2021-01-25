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

#include "css_parser.hxx"
#include "css_tokeniser.hxx"
#include <unicode/utf8.h>


namespace rspamd::css {

class css_parser {
public:
	css_parser(void) = delete; /* Require mempool to be set for logging */
	explicit css_parser(rspamd_mempool_t *pool) : pool (pool) {}

	bool consume_input(const std::string_view &sv);

	auto get_object_maybe(void) -> tl::expected<std::unique_ptr<css_style_sheet>, css_parse_error> {
		if (state == parser_state::parse_done) {
			state = parser_state::initial_state;
			return std::move (style_object);
		}

		return tl::make_unexpected (error);
	}

private:
	enum class parser_state {
		initial_state,
		skip_spaces,
		parse_selector,
		ignore_selector, /* e.g. media or namespace */
		parse_done,
	};
	parser_state state = parser_state::initial_state;
	std::unique_ptr<css_style_sheet> style_object;

	css_parse_error error;
	rspamd_mempool_t *pool;

	/* Helper parser methods */
	bool need_unescape(const std::string_view &sv);
};

/*
 * Find if we need to unescape css
 */
bool
css_parser::need_unescape(const std::string_view &sv)
{
	bool in_quote = false;
	char quote_char, prev_c = 0;

	for (const auto c : sv) {
		if (!in_quote) {
			if (c == '"' || c == '\'') {
				in_quote = true;
				quote_char = c;
			}
			else if (c == '\\') {
				return true;
			}
		}
		else {
			if (c == quote_char) {
				if (prev_c != '\\') {
					in_quote = false;
				}
			}
			prev_c = c;
		}
	}

	return false;
}


bool css_parser::consume_input(const std::string_view &sv)
{
	bool eof = false;
	css_tokeniser css_tokeniser(pool, sv);

	while (!eof) {
		auto token_pair = css_tokeniser.next_token();

		/* Top level parser */
		switch (token_pair.first) {
		case css_parser_token::eof_token:
			eof = true;
			break;
		case css_parser_token::whitespace_token:
		case css_parser_token::cdc_token:
		case css_parser_token::cdo_token:
			/* Ignore tokens */
			break;
		}
	}

	return true;
}

/*
 * Wrapper for the parser
 */
auto parse_css(rspamd_mempool_t *pool, const std::string_view &st) ->
	tl::expected<std::unique_ptr<css_style_sheet>,css_parse_error>
{
	css_parser parser(pool);

	parser.consume_input(st);

	return parser.get_object_maybe();
}

}
