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
		css_function_arg,
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
			std::vector<consumed_block_ptr> vec;
			vec.reserve(4);
			content = std::move(vec);
		}
	}
	/* Construct a block from a single lexer token (for trivial blocks) */
	explicit css_consumed_block(parser_tag_type tag, css_parser_token &&tok) :
			tag(tag), content(std::move(tok)) {}

	/* Attach a new block to the compound block, consuming block inside */
	auto attach_block(consumed_block_ptr &&block) -> bool {
		if (content.index() == 0) {
			/* Switch from monostate */
			content = std::vector<consumed_block_ptr>();
		}
		else if (content.index() == 2) {
			/* A single component, cannot attach a block ! */
			return false;
		}

		auto &value_vec = std::get<std::vector<consumed_block_ptr>>(content);
		value_vec.push_back(std::move(block));

		return true;
	}

	auto assign_token(css_parser_token &&tok) -> void
	{
		content = std::move(tok);
	}

	auto token_type_str(void) const -> const char *
	{
		const auto *ret = "";

		switch(tag) {
		case parser_tag_type::css_top_block:
			ret = "top";
			break;
		case parser_tag_type::css_qualified_rule:
			ret = "qualified rule";
			break;
		case parser_tag_type::css_at_rule:
			ret = "at rule";
			break;
		case parser_tag_type::css_simple_block:
			ret = "simple block";
			break;
		case parser_tag_type::css_function:
			ret = "function";
			break;
		case parser_tag_type::css_function_arg:
			ret = "function args";
			break;
		case parser_tag_type::css_component:
			ret = "component";
			break;
		}

		return ret;
	}

	auto size() const -> std::size_t {
		auto ret = 0;

		std::visit([&](auto& arg) {
			using T = std::decay_t<decltype(arg)>;

			if constexpr (std::is_same_v<T, std::vector<consumed_block_ptr>>) {
				/* Array of blocks */
				ret = arg.size();
			}
			else if constexpr (std::is_same_v<T, std::monostate>) {
				/* Empty block */
				ret = 0;
			}
			else {
				/* Single element block */
				ret = 1;
			}
		},
		content);

		return ret;
	}

	auto debug_str(void) -> std::string {
		std::string ret = std::string("\"type\": \"") + token_type_str() + "\"";

		ret += ", \"value\": ";

		std::visit([&](auto& arg) {
			using T = std::decay_t<decltype(arg)>;

			if constexpr (std::is_same_v<T, std::vector<consumed_block_ptr>>) {
				/* Array of blocks */
				ret += "[";
				for (const auto &block : arg) {
					ret += "{";
					ret += block->debug_str();
					ret += "}, ";
				}

				if (*(--ret.end()) == ' ') {
					ret.pop_back();
					ret.pop_back(); /* Last ',' */
				}
				ret += "]";
			}
			else if constexpr (std::is_same_v<T, std::monostate>) {
				/* Empty block */
				ret += "\"empty\"";
			}
			else {
				/* Single element block */
				ret += "\"" + arg.debug_token_str() + "\"";
			}
		},
		content);

		return ret;
	}
};

class css_parser {
public:
	css_parser(void) = delete; /* Require mempool to be set for logging */
	explicit css_parser(rspamd_mempool_t *pool) : pool (pool) {}

	bool consume_input(const std::string_view &sv);

	auto get_object_maybe(void) -> tl::expected<std::unique_ptr<css_style_sheet>, css_parse_error> {
		if (style_object) {
			return std::move(style_object);
		}

		return tl::make_unexpected(error);
	}

private:
	std::unique_ptr<css_style_sheet> style_object;
	std::unique_ptr<css_tokeniser> tokeniser;

	css_parse_error error;
	rspamd_mempool_t *pool;

	int rec_level = 0;
	const int max_rec = 20;
	bool eof = false;

	/* Helper parser methods */
	bool need_unescape(const std::string_view &sv);

	/* Consumers */
	auto component_value_consumer(std::unique_ptr<css_consumed_block> &top) -> bool;
	auto function_consumer(std::unique_ptr<css_consumed_block> &top) -> bool;
	auto simple_block_consumer(std::unique_ptr<css_consumed_block> &top,
							   css_parser_token::token_type expected_end,
							   bool consume_current) -> bool;
	auto qualified_rule_consumer(std::unique_ptr<css_consumed_block> &top) -> bool;
	auto at_rule_consumer(std::unique_ptr<css_consumed_block> &top) -> bool;
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

auto css_parser::function_consumer(std::unique_ptr<css_consumed_block> &top) -> bool
{
	auto ret = true, want_more = true;

	msg_debug_css("consume function block; top block: %s, recursion level %d",
			top->token_type_str(), rec_level);

	if (++rec_level > max_rec) {
		msg_err_css("max nesting reached, ignore style");
		error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING);
		return false;
	}

	while (ret && want_more && !eof) {
		auto next_token = tokeniser->next_token();

		switch (next_token.type) {
		case css_parser_token::token_type::eof_token:
			eof = true;
			break;
		case css_parser_token::token_type::whitespace_token:
			/* Ignore whitespaces */
			break;
		case css_parser_token::token_type::ebrace_token:
			ret = true;
			want_more = false;
			break;
		default:
			/* Attach everything to the function block */
			top->attach_block(std::make_unique<css_consumed_block>(
					css::css_consumed_block::parser_tag_type::css_function_arg,
					std::move(next_token)));
			break;
		}
	}

	--rec_level;

	return ret;
}

auto css_parser::simple_block_consumer(std::unique_ptr<css_consumed_block> &top,
									   css_parser_token::token_type expected_end,
									   bool consume_current) -> bool
{
	auto ret = true;
	std::unique_ptr<css_consumed_block> block;

	msg_debug_css("consume simple block; top block: %s, recursion level %d",
			top->token_type_str(), rec_level);

	if (!consume_current && ++rec_level > max_rec) {
		msg_err_css("max nesting reached, ignore style");
		error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING);
		return false;
	}

	if (!consume_current) {
		block = std::make_unique<css_consumed_block>(
				css_consumed_block::parser_tag_type::css_simple_block);
	}


	while (ret && !eof) {
		auto next_token = tokeniser->next_token();

		if (next_token.type == expected_end) {
			break;
		}

		switch (next_token.type) {
		case css_parser_token::token_type::eof_token:
			eof = true;
			break;
		case css_parser_token::token_type::whitespace_token:
			/* Ignore whitespaces */
			break;
		default:
			tokeniser->pushback_token(std::move(next_token));
			ret = component_value_consumer(consume_current ? top : block);
			break;
		}
	}

	if (!consume_current && ret) {
		msg_debug_css("attached node 'simple block' rule %s; length=%d",
				block->token_type_str(), (int)block->size());
		top->attach_block(std::move(block));
	}

	if (!consume_current) {
		--rec_level;
	}

	return ret;
}

auto css_parser::qualified_rule_consumer(std::unique_ptr<css_consumed_block> &top) -> bool
{
	msg_debug_css("consume qualified block; top block: %s, recursion level %d",
			top->token_type_str(), rec_level);

	if (++rec_level > max_rec) {
		msg_err_css("max nesting reached, ignore style");
		error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING);
		return false;
	}

	auto ret = true, want_more = true;
	auto block = std::make_unique<css_consumed_block>(
			css_consumed_block::parser_tag_type::css_qualified_rule);

	while (ret && want_more && !eof) {
		auto next_token = tokeniser->next_token();
		switch (next_token.type) {
		case css_parser_token::token_type::eof_token:
			eof = true;
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
		case css_parser_token::token_type::ocurlbrace_token:
			ret = simple_block_consumer(block,
					css_parser_token::token_type::ecurlbrace_token, false);
			want_more = false;
			break;
		case css_parser_token::token_type::whitespace_token:
			/* Ignore whitespaces */
			break;
		default:
			tokeniser->pushback_token(std::move(next_token));
			ret = component_value_consumer(block);
			break;
		};
	}

	if (ret) {
		if (top->tag == css_consumed_block::parser_tag_type::css_top_block) {
			msg_debug_css("attached node qualified rule %s; length=%d",
					block->token_type_str(), (int)block->size());
			top->attach_block(std::move(block));
		}
	}

	--rec_level;

	return ret;
}

auto css_parser::at_rule_consumer(std::unique_ptr<css_consumed_block> &top) -> bool
{
	msg_debug_css("consume at-rule block; top block: %s, recursion level %d",
			top->token_type_str(), rec_level);

	if (++rec_level > max_rec) {
		msg_err_css("max nesting reached, ignore style");
		error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING);
		return false;
	}

	auto ret = true, want_more = true;
	auto block = std::make_unique<css_consumed_block>(
			css_consumed_block::parser_tag_type::css_at_rule);

	while (ret && want_more && !eof) {
		auto next_token = tokeniser->next_token();
		switch (next_token.type) {
		case css_parser_token::token_type::eof_token:
			eof = true;
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
		case css_parser_token::token_type::ocurlbrace_token:
			ret = simple_block_consumer(block,
					css_parser_token::token_type::ecurlbrace_token, false);
			want_more = false;
			break;
		case css_parser_token::token_type::whitespace_token:
			/* Ignore whitespaces */
			break;
		case css_parser_token::token_type::semicolon_token:
			want_more = false;
			break;
		default:
			tokeniser->pushback_token(std::move(next_token));
			ret = component_value_consumer(block);
			break;
		};
	}

	if (ret) {
		if (top->tag == css_consumed_block::parser_tag_type::css_top_block) {
			msg_debug_css("attached node qualified rule %s; length=%d",
					block->token_type_str(), (int)block->size());
			top->attach_block(std::move(block));
		}
	}

	--rec_level;

	return ret;
}

auto css_parser::component_value_consumer(std::unique_ptr<css_consumed_block> &top) -> bool
{
	auto ret = true, need_more = true;
	std::unique_ptr<css_consumed_block> block;

	msg_debug_css("consume component block; top block: %s, recursion level %d",
			top->token_type_str(), rec_level);

	if (++rec_level > max_rec) {
		error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING);
		return false;
	}

	while (ret && need_more && !eof) {
		auto next_token = tokeniser->next_token();

		switch (next_token.type) {
		case css_parser_token::token_type::eof_token:
			eof = true;
			break;
		case css_parser_token::token_type::ocurlbrace_token:
			block = std::make_unique<css_consumed_block>(
					css_consumed_block::parser_tag_type::css_simple_block);
			ret = simple_block_consumer(block,
					css_parser_token::token_type::ecurlbrace_token,
					true);
			need_more = false;
			break;
		case css_parser_token::token_type::obrace_token:
			block = std::make_unique<css_consumed_block>(
					css_consumed_block::parser_tag_type::css_simple_block);
			ret = simple_block_consumer(block,
					css_parser_token::token_type::ebrace_token,
					true);
			need_more = false;
			break;
		case css_parser_token::token_type::osqbrace_token:
			block = std::make_unique<css_consumed_block>(
					css_consumed_block::parser_tag_type::css_simple_block);
			ret = simple_block_consumer(block,
					css_parser_token::token_type::esqbrace_token,
					true);
			need_more = false;
			break;
		case css_parser_token::token_type::whitespace_token:
			/* Ignore whitespaces */
			break;
		case css_parser_token::token_type::function_token: {
			need_more = false;
			block = std::make_unique<css_consumed_block>(
					css_consumed_block::parser_tag_type::css_function,
					std::move(next_token));

			/* Consume the rest */
			ret = function_consumer(block);
			break;
		}
		default:
			block = std::make_unique<css_consumed_block>(
					css_consumed_block::parser_tag_type::css_component,
					std::move(next_token));
			need_more = false;
			break;
		}
	}

	if (ret && block) {
		msg_debug_css("attached node component rule %s; length=%d",
				block->token_type_str(), (int)block->size());
		top->attach_block(std::move(block));
	}

	--rec_level;

	return ret;
}

bool css_parser::consume_input(const std::string_view &sv)
{
	tokeniser = std::make_unique<css_tokeniser>(pool, sv);
	auto ret = true;

	auto consumed_blocks =
			std::make_unique<css_consumed_block>(css_consumed_block::parser_tag_type::css_top_block);

	while (!eof && ret) {
		auto next_token = tokeniser->next_token();

		switch (next_token.type) {
		case css_parser_token::token_type::whitespace_token:
			/* Ignore whitespaces */
			break;
		case css_parser_token::token_type::eof_token:
			eof = true;
			break;
		case css_parser_token::token_type::at_keyword_token:
			tokeniser->pushback_token(std::move(next_token));
			ret = at_rule_consumer(consumed_blocks);
			break;
		default:
			tokeniser->pushback_token(std::move(next_token));
			ret = qualified_rule_consumer(consumed_blocks);
			break;
		}

	}

	auto debug_str = consumed_blocks->debug_str();
	msg_debug_css("consumed css: {%*s}", (int)debug_str.size(), debug_str.data());

	tokeniser.reset(nullptr); /* No longer needed */

	return ret;
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
