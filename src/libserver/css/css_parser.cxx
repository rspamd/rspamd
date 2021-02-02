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
#include <vector>
#include <unicode/utf8.h>


namespace rspamd::css {

/*
 * Represents a consumed token by a parser
 */
struct css_consumed_block {
	enum class parser_tag_type : std::uint8_t  {
		css_top_block,
		css_qualified_rule,
		css_at_rule,
		css_simple_block,
		css_function,
		css_component
	};

	using consumed_block_ptr = std::unique_ptr<css_consumed_block>;

	parser_tag_type tag;
	std::variant<std::monostate,
		std::vector<consumed_block_ptr>,
		css_parser_token> content;

	css_consumed_block() = delete;

	css_consumed_block(parser_tag_type tag) : tag(tag) {
		if (tag == parser_tag_type::css_top_block ||
			tag == parser_tag_type::css_qualified_rule ||
			tag == parser_tag_type::css_simple_block) {
			/* Pre-allocate content for known vector blocks */
			content = std::vector<consumed_block_ptr>(4);
		}
	}
	/* Construct a block from a single lexer token (for trivial blocks) */
	explicit css_consumed_block(parser_tag_type tag, css_parser_token &&tok) :
			tag(tag), content(std::move(tok)) {}

	/* Attach a new block to the compound block, consuming block inside */
	auto attach_block(consumed_block_ptr &&block) -> bool {
		if (content.index() == 0) {
			/* Switch from monostate */
			content = std::vector<consumed_block_ptr>(1);
		}
		else if (content.index() == 2) {
			/* A single component, cannot attach a block ! */
			return false;
		}

		std::get<std::vector<consumed_block_ptr>>(content)
		        .push_back(std::move(block));

		return true;
	}
};

class css_parser {
public:
	css_parser(void) = delete; /* Require mempool to be set for logging */
	explicit css_parser(rspamd_mempool_t *pool) : pool (pool) {}

	bool consume_input(const std::string_view &sv);

	auto get_object_maybe(void) -> tl::expected<std::unique_ptr<css_style_sheet>, css_parse_error> {
		if (state == parser_state::parse_done) {
			state = parser_state::initial_state;
			return std::move(style_object);
		}

		return tl::make_unexpected(error);
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

	auto consumed_blocks = std::make_unique<css_consumed_block>(
			css_consumed_block::parser_tag_type::css_top_block);
	auto rec_level = 0;
	const auto max_rec = 20;

	auto component_value_consumer = [&](std::unique_ptr<css_consumed_block> &top) -> bool {

		if (++rec_level > max_rec) {
			error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING);
			return false;
		}

		auto next_token = css_tokeniser.next_token();

		switch (next_token.type) {

		}

		--rec_level;

		return true;
	};

	auto qualified_rule_consumer = [&](std::unique_ptr<css_consumed_block> &top) -> bool {
		if (++rec_level > max_rec) {
			msg_err_css("max nesting reached, ignore style");
			error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING);
			return false;
		}

		auto ret = true;
		auto block = std::make_unique<css_consumed_block>(
				css_consumed_block::parser_tag_type::css_qualified_rule);

		while (ret && !eof) {
			auto &&next_token = css_tokeniser.next_token();
			switch (next_token.type) {
			case css_parser_token::token_type::eof_token:
				eof = true;
				break;
			case css_parser_token::token_type::ident_token:
			case css_parser_token::token_type::hash_token:
				/* Consume allowed complex tokens as a rule preamble */
				ret = component_value_consumer(block);
				break;
			case css_parser_token::token_type::cdo_token:
			case css_parser_token::token_type::cdc_token:
				if (top->tag == css_consumed_block::parser_tag_type::css_top_block) {
					/* Ignore */
					ret = true;
				}
				else {

				}
				break;
			};
		}

		if (ret) {
			if (top->tag == css_consumed_block::parser_tag_type::css_top_block) {
				top->attach_block(std::move(block));
			}
		}

		--rec_level;

		return ret;
	};

	auto get_parser_consumer = [&]() -> auto {
		switch (state) {
		case parser_state::initial_state:
			/* Top level qualified parser */
			return qualified_rule_consumer;
			break;
		}
	};

	while (!eof) {
		/* Get a token and a consumer lambda for the current parser state */

		auto consumer = get_parser_consumer();

		if (!consumer(consumed_blocks)) {
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
