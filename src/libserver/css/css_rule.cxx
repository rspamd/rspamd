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

#include "css_rule.hxx"

namespace rspamd::css {

static auto
allowed_property_value(const css_property &prop, const css_consumed_block &parser_block)
	-> std::optional<css_value>
{
	if (prop.is_color()) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::hash_token) {
				return css_value::maybe_color_from_hex(tok.get_string_or_default(""));
			}
			else if (tok.type == css_parser_token::token_type::ident_token) {
				return css_value::maybe_color_from_string(tok.get_string_or_default(""));
			}
		}
		else if (parser_block.is_function()) {
			const auto &func = parser_block.get_function_or_invalid();

			return css_value::maybe_color_from_function(func);
		}
	}

	return std::nullopt;
}

auto process_declaration_tokens(rspamd_mempool_t *pool,
								const blocks_gen_functor &next_block_functor)
	-> declarations_vec
{
	declarations_vec ret;
	bool can_continue = true;
	css_property cur_property{css_property_type::PROPERTY_NYI};
	static const css_property bad_property{css_property_type::PROPERTY_NYI};
	std::unique_ptr<css_rule> cur_rule;

	enum {
		parse_property,
		parse_value,
		ignore_value, /* For unknown properties */
	} state = parse_property;

	while (can_continue) {
		const auto &next_tok = next_block_functor();

		switch (next_tok.tag) {
		case css_consumed_block::parser_tag_type::css_component:
			/* Component can be a property or a compound list of values */
			if (state == parse_property) {
				cur_property = css_property::from_token(next_tok.get_token_or_empty())
						.value_or(bad_property);

				if (cur_property.type == css_property_type::PROPERTY_NYI) {
					state = ignore_value;
					/* Ignore everything till ; */
					continue;
				}

				msg_debug_css("got css property: %s", cur_property.to_string());

				/* We now expect colon block */
				const auto &expect_colon_block = next_block_functor();

				if (expect_colon_block.tag != css_consumed_block::parser_tag_type::css_component) {
					state = ignore_value; /* Ignore up to the next rule */
				}
				else {
					const auto &expect_colon_tok = expect_colon_block.get_token_or_empty();

					if (expect_colon_tok.type != css_parser_token::token_type::colon_token) {
						msg_debug_css("invalid rule, no colon after property");
						state = ignore_value; /* Ignore up to the next rule */
					}
					else {
						state = parse_value;
						cur_rule = std::make_unique<css_rule>(cur_property);
					}
				}
			}
			else if (state == parse_value) {
				/* Check semicolon */
				if (next_tok.is_token()) {
					const auto &parser_tok = next_tok.get_token_or_empty();

					if (parser_tok.type == css_parser_token::token_type::semicolon_token) {
						ret.push_back(std::move(cur_rule));
						state = parse_property;
						continue;
					}
				}

				auto maybe_value = allowed_property_value(cur_property, next_tok);

				if (maybe_value) {
					msg_debug_css("added value %s to the property %s",
							maybe_value.value().debug_str().c_str(),
							cur_property.to_string());
					cur_rule->add_value(maybe_value.value());
				}
			}
			else {
				/* Ignore all till ; */
				if (next_tok.is_token()) {
					const auto &parser_tok = next_tok.get_token_or_empty();

					if (parser_tok.type == css_parser_token::token_type::semicolon_token) {
						state = parse_property;
					}
				}
			}
			break;
		case css_consumed_block::parser_tag_type::css_function:
			if (state == parse_value) {
				auto maybe_value = allowed_property_value(cur_property, next_tok);

				if (maybe_value) {
					msg_debug_css("added value %s to the property %s",
							maybe_value.value().debug_str().c_str(),
							cur_property.to_string());
					cur_rule->add_value(maybe_value.value());
				}
			}
			break;
		case css_consumed_block::parser_tag_type::css_eof_block:
			if (state == parse_value) {
				ret.push_back(std::move(cur_rule));
			}
			can_continue = false;
			break;
		default:
			can_continue = false;
			break;
		}
	}

	return ret; /* copy elision */
}

void css_rule::add_value(std::unique_ptr<css_value> &&value)
{
	values.emplace_back(std::forward<std::unique_ptr<css_value>>(value));
}

void css_rule::add_value(const css_value &value)
{
	values.emplace_back(std::make_unique<css_value>(css_value{value}));
}

}