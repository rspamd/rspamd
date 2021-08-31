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
#include "css_selector.hxx"
#include "css_rule.hxx"
#include "css_util.hxx"
#include "css.hxx"
#include "fmt/core.h"

#include <vector>
#include <unicode/utf8.h>

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

namespace rspamd::css {

const css_consumed_block css_parser_eof_block{};

auto css_consumed_block::attach_block(consumed_block_ptr &&block) -> bool {
	if (std::holds_alternative<std::monostate>(content)) {
		/* Switch from monostate */
		content = std::vector<consumed_block_ptr>();
	}
	else if (!std::holds_alternative<std::vector<consumed_block_ptr>>(content)) {
		/* A single component, cannot attach a block ! */
		return false;
	}

	auto &value_vec = std::get<std::vector<consumed_block_ptr>>(content);
	value_vec.push_back(std::move(block));

	return true;
}

auto css_consumed_block::add_function_argument(consumed_block_ptr &&block)  -> bool {
	if (!std::holds_alternative<css_function_block>(content)) {
		return false;
	}

	auto &&func_bloc = std::get<css_function_block>(content);
	func_bloc.args.push_back(std::move(block));

	return true;
}

auto css_consumed_block::token_type_str(void) const -> const char *
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
		ret = "function arg";
		break;
	case parser_tag_type::css_component:
		ret = "component";
		break;
	case parser_tag_type::css_eof_block:
		ret = "eof";
		break;
	}

	return ret;
}

auto css_consumed_block::debug_str(void) -> std::string {
	std::string ret = fmt::format(R"("type": "{}", "value": )", token_type_str());

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
					ret += R"("empty")";
				}
				else if constexpr (std::is_same_v<T, css_function_block>) {
					ret += R"({ "content": {"token": )";
					ret += "\"" + arg.function.debug_token_str() + "\", ";
					ret += R"("arguments":  [)";

					for (const auto &block : arg.args) {
						ret += "{";
						ret += block->debug_str();
						ret += "}, ";
					}
					if (*(--ret.end()) == ' ') {
						ret.pop_back();
						ret.pop_back(); /* Last ',' */
					}
					ret += "]}}";
				}
				else {
					/* Single element block */
					ret += "\"" + arg.debug_token_str() + "\"";
				}
			},
			content);

	return ret;
}

class css_parser {
public:
	css_parser(void) = delete; /* Require mempool to be set for logging */
	explicit css_parser(rspamd_mempool_t *pool) : pool (pool) {
		style_object.reset();
		error.type = css_parse_error_type::PARSE_ERROR_NO_ERROR;
	}

	/*
	 * This constructor captures existing via unique_ptr, but it does not
	 * destruct it on errors (we assume that it is owned somewhere else)
	 */
	explicit css_parser(std::shared_ptr<css_style_sheet> &&existing, rspamd_mempool_t *pool) :
			style_object(existing), pool(pool) {
		error.type = css_parse_error_type::PARSE_ERROR_NO_ERROR;
	}

	/*
	 * Process input css blocks
	 */
	std::unique_ptr<css_consumed_block> consume_css_blocks(const std::string_view &sv);
	/*
	 * Process a single css rule
	 */
	std::unique_ptr<css_consumed_block> consume_css_rule(const std::string_view &sv);
	std::optional<css_parse_error> consume_input(const std::string_view &sv);

	auto get_object_maybe(void) -> tl::expected<std::shared_ptr<css_style_sheet>, css_parse_error> {
		if (style_object) {
			return style_object;
		}

		return tl::make_unexpected(error);
	}

	/* Helper parser methods */
	static bool need_unescape(const std::string_view &sv);

private:
	std::shared_ptr<css_style_sheet> style_object;
	std::unique_ptr<css_tokeniser> tokeniser;

	css_parse_error error;
	rspamd_mempool_t *pool;

	int rec_level = 0;
	const int max_rec = 20;
	bool eof = false;

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
		error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING,
				"maximum nesting has reached when parsing function value");
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
		case css_parser_token::token_type::comma_token:
		case css_parser_token::token_type::delim_token:
		case css_parser_token::token_type::obrace_token:
			break;
		default:
			/* Attach everything to the function block */
			top->add_function_argument(std::make_unique<css_consumed_block>(
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
		error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING,
				"maximum nesting has reached when parsing simple block value");
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
			tokeniser->pushback_token(next_token);
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
		error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING,
				"maximum nesting has reached when parsing qualified rule value");
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
			tokeniser->pushback_token(next_token);
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
		error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING,
				"maximum nesting has reached when parsing at keyword");
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
			tokeniser->pushback_token(next_token);
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
		error = css_parse_error(css_parse_error_type::PARSE_ERROR_BAD_NESTING,
				"maximum nesting has reached when parsing component value");
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

auto
css_parser::consume_css_blocks(const std::string_view &sv) -> std::unique_ptr<css_consumed_block>
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
			tokeniser->pushback_token(next_token);
			ret = at_rule_consumer(consumed_blocks);
			break;
		default:
			tokeniser->pushback_token(next_token);
			ret = qualified_rule_consumer(consumed_blocks);
			break;
		}

	}

	tokeniser.reset(nullptr); /* No longer needed */

	return consumed_blocks;
}

auto
css_parser::consume_css_rule(const std::string_view &sv) -> std::unique_ptr<css_consumed_block>
{
	tokeniser = std::make_unique<css_tokeniser>(pool, sv);
	auto ret = true;

	auto rule_block =
			std::make_unique<css_consumed_block>(css_consumed_block::parser_tag_type::css_simple_block);

	while (!eof && ret) {
		auto next_token = tokeniser->next_token();

		switch (next_token.type) {
		case css_parser_token::token_type::eof_token:
			eof = true;
			break;
		case css_parser_token::token_type::whitespace_token:
			/* Ignore whitespaces */
			break;
		default:
			tokeniser->pushback_token(next_token);
			ret = component_value_consumer(rule_block);
			break;
		}

	}

	tokeniser.reset(nullptr); /* No longer needed */

	return rule_block;
}

std::optional<css_parse_error>
css_parser::consume_input(const std::string_view &sv)
{
	auto &&consumed_blocks = consume_css_blocks(sv);
	const auto &rules = consumed_blocks->get_blocks_or_empty();

	if (rules.empty()) {
		if (error.type == css_parse_error_type::PARSE_ERROR_NO_ERROR) {
			return css_parse_error(css_parse_error_type::PARSE_ERROR_EMPTY,
					"no css rules consumed");
		}
		else {
			return error;
		}
	}

	if (!style_object) {
		style_object = std::make_shared<css_style_sheet>(pool);
	}

	for (auto &&rule : rules) {
		/*
		 * For now, we do not need any of the at rules, so we can safely ignore them
		 */
		auto &&children = rule->get_blocks_or_empty();

		if (children.size() > 1 &&
			children[0]->tag == css_consumed_block::parser_tag_type::css_component) {
			auto simple_block = std::find_if(children.begin(), children.end(),
					[](auto &bl) {
						return bl->tag == css_consumed_block::parser_tag_type::css_simple_block;
					});

			if (simple_block != children.end()) {
				/*
				 * We have a component and a simple block,
				 * so we can parse a selector and then extract
				 * declarations from a simple block
				 */

				/* First, tag all components as preamble */
				auto selector_it = children.cbegin();

				auto selector_token_functor = [&selector_it,&simple_block](void)
						-> const css_consumed_block & {
					for (;;) {
						if (selector_it == simple_block) {
							return css_parser_eof_block;
						}

						const auto &ret = (*selector_it);

						++selector_it;

						return *ret;
					}
				};

				auto selectors_vec = process_selector_tokens(pool, selector_token_functor);

				if (selectors_vec.size() > 0) {
					msg_debug_css("processed %d selectors", (int)selectors_vec.size());
					auto decls_it = (*simple_block)->get_blocks_or_empty().cbegin();
					auto decls_end = (*simple_block)->get_blocks_or_empty().cend();
					auto declaration_token_functor = [&decls_it, &decls_end](void)
							-> const css_consumed_block & {
						for (;;) {
							if (decls_it == decls_end) {
								return css_parser_eof_block;
							}

							const auto &ret = (*decls_it);

							++decls_it;

							return *ret;
						}
					};

					auto declarations_vec = process_declaration_tokens(pool,
							declaration_token_functor);

					if (declarations_vec && !declarations_vec->get_rules().empty()) {
						msg_debug_css("processed %d rules",
								(int)declarations_vec->get_rules().size());

						for (auto &&selector : selectors_vec) {
							style_object->add_selector_rule(std::move(selector),
									   declarations_vec);
						}
					}
				}
			}
		}
	}

	auto debug_str = consumed_blocks->debug_str();
	msg_debug_css("consumed css: {%*s}", (int)debug_str.size(), debug_str.data());

	return std::nullopt;
}

auto
get_selectors_parser_functor(rspamd_mempool_t *pool,
							 const std::string_view &st) -> blocks_gen_functor
{
	css_parser parser(pool);

	auto &&consumed_blocks = parser.consume_css_blocks(st);
	const auto &rules = consumed_blocks->get_blocks_or_empty();

	auto rules_it = rules.begin();
	auto &&children = (*rules_it)->get_blocks_or_empty();
	auto cur = children.begin();
	auto last = children.end();

	/*
	 * We use move only wrapper to state the fact that the cosumed blocks
	 * are moved into the closure, not copied.
	 * It prevents us from thinking about copies of the blocks and
	 * functors.
	 * Mutable lambda is required to copy iterators inside of the closure,
	 * as, again, it is C++ where lifetime of the objects must be explicitly
	 * transferred. On the other hand, we could move all stuff inside and remove
	 * mutable.
	 */
	return [cur, consumed_blocks = std::move(consumed_blocks), last](void) mutable
		-> const css_consumed_block & {
		if (cur != last) {
			const auto &ret = (*cur);

			++cur;

			return *ret;
		}

		return css_parser_eof_block;
	};
}

auto
get_rules_parser_functor(rspamd_mempool_t *pool,
							 const std::string_view &st) -> blocks_gen_functor
{
	css_parser parser(pool);

	auto &&consumed_blocks = parser.consume_css_rule(st);
	const auto &rules = consumed_blocks->get_blocks_or_empty();

	auto cur = rules.begin();
	auto last = rules.end();

	return [cur, consumed_blocks = std::move(consumed_blocks), last](void) mutable
			-> const css_consumed_block & {
		if (cur != last) {
			const auto &ret = (*cur);

			++cur;

			return *ret;
		}

		return css_parser_eof_block;
	};
}


/*
 * Wrapper for the parser
 */
auto parse_css(rspamd_mempool_t *pool, const std::string_view &st,
			   std::shared_ptr<css_style_sheet> &&other)
	-> tl::expected<std::shared_ptr<css_style_sheet>, css_parse_error>
{
	css_parser parser(std::forward<std::shared_ptr<css_style_sheet>>(other), pool);
	std::string_view processed_input;

	if (css_parser::need_unescape(st)) {
		processed_input = rspamd::css::unescape_css(pool, st);
	}
	else {
		/* Lowercase inplace */
		auto *nspace = rspamd_mempool_alloc_buffer(pool, st.size());
		rspamd_str_copy_lc(st.data(), nspace, st.size());
		processed_input = std::string_view{nspace, st.size()};
	}

	auto maybe_error = parser.consume_input(processed_input);
	if (!maybe_error) {
		return parser.get_object_maybe();
	}

	return tl::make_unexpected(maybe_error.value());
}

auto
parse_css_declaration(rspamd_mempool_t *pool, const std::string_view &st)
	-> rspamd::html::html_block *
{
	std::string_view processed_input;

	if (css_parser::need_unescape(st)) {
		processed_input = rspamd::css::unescape_css(pool, st);
	}
	else {
		auto *nspace = reinterpret_cast<char *>(rspamd_mempool_alloc(pool, st.size()));
		auto nlen = rspamd_str_copy_lc(st.data(), nspace, st.size());
		processed_input = std::string_view{nspace, nlen};
	}
	auto &&res = process_declaration_tokens(pool,
			get_rules_parser_functor(pool, processed_input));

	if (res) {
		return res->compile_to_block(pool);
	}

	return nullptr;
}

TEST_SUITE("css") {
	TEST_CASE("parse colors") {
		const std::vector<const char *> cases{
			"P { CoLoR: rgb(100%, 50%, 0%); opacity: -1; width: 1em; display: none; } /* very transparent solid orange тест */",
			"p { color: rgb(100%, 50%, 0%); opacity: 2; display: inline; } /* very transparent solid orange */",
			"p { color: rgb(100%, 50%, 0%); opacity: 0.5; } /* very transparent solid orange */\n",
			"p { color: rgb(100%, 50%, 0%); opacity: 1; width: 99%; } /* very transparent solid orange */\n",
			"p { color: rgb(100%, 50%, 0%); opacity: 10%; width: 99%; } /* very transparent solid orange */\n",
			"p { color: rgb(100%, 50%, 0%); opacity: 10%; width: 100px; } /* very transparent solid orange */\n",
			"p { color: rgb(100%, 50%, 0%); opacity: 10% } /* very transparent solid orange */\n",
			"* { color: hsl(0, 100%, 50%) !important }   /* red */\n",
			"* { color: hsl(120, 100%, 50%) important } /* lime */\n",
			"* { color: hsl(120, 100%, 25%) } /* dark green */\n",
			"* { color: hsl(120, 100%, 75%) } /* light green */\n",
			"* { color: hsl(120, 75%, 75%) }  /* pastel green, and so on */\n",
			"em { color: #f00 }              /* #rgb */\n",
			"em { color: #ff0000 }           /* #rrggbb */\n",
			"em { color: rgb(255,0,0) }\n",
			"em { color: rgb(100%, 0%, 0%) }\n",
			"body {color: black; background: white }\n",
			"h1 { color: maroon }\n",
			"h2 { color: olive }\n",
			"em { color: rgb(255,0,0) }       /* integer range 0 - 255 */\n",
			"em { color: rgb(300,0,0) }       /* clipped to rgb(255,0,0) */\n",
			"em { color: rgb(255,-10,0) }     /* clipped to rgb(255,0,0) */\n",
			"em { color: rgb(110%, 0%, 0%) }  /* clipped to rgb(100%,0%,0%) */\n",
			"em { color: rgb(255,0,0) }      /* integer range 0 - 255 */\n",
			"em { color: rgba(255,0,0,1)     /* the same, with explicit opacity of 1 */\n",
			"em { color: rgb(100%,0%,0%) }   /* float range 0.0% - 100.0% */\n",
			"em { color: rgba(100%,0%,0%,1) } /* the same, with explicit opacity of 1 */\n",
			"p { color: rgba(0,0,255,0.5) }        /* semi-transparent solid blue */\n",
			"p { color: rgba(100%, 50%, 0%, 0.1) } /* very transparent solid orange */",
			".chat-icon[_ng-cnj-c0]::before{content:url(group-2.63e87cd21fbf8c966dd.svg);width:60px;height:60px;display:block}",
			"tt{color:#1e3482}",
			"tt{unicode-range: u+0049-u+004a,u+0020;}",
			"@import url(https://fonts.googleapis.com/css?family=arial:300,400,7000;",
			"tt{color:black;\v}",
			"tt{color:black;\f}",
		};

		rspamd_mempool_t *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
				"css", 0);
		for (const auto &c : cases) {
			SUBCASE((std::string("parse css: ") + c).c_str()) {
				CHECK(parse_css(pool, c, nullptr).value().get() != nullptr);
			}
		}

		/* We now merge all styles together */
		SUBCASE("merged css parse") {
			std::shared_ptr<css_style_sheet> merged;
			for (const auto &c : cases) {
				auto ret = parse_css(pool, c, std::move(merged));
				merged.swap(ret.value());
			}

			CHECK(merged.get() != nullptr);
		}

		rspamd_mempool_delete(pool);
	}
}
}
