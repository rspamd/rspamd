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
#include "css.hxx"
#include "libserver/html/html_block.hxx"
#include <limits>

#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#include "doctest/doctest.h"

namespace rspamd::css {

/* Class methods */
void css_rule::override_values(const css_rule &other)
{
	int bits = 0;
	/* Ensure that our bitset is large enough */
	static_assert(1 << std::variant_size_v<decltype(css_value::value)> <
				  std::numeric_limits<int>::max());

	for (const auto &v : values) {
		bits |= static_cast<int>(1 << v.value.index());
	}

	for (const auto &ov : other.values) {
		if (isset(&bits, static_cast<int>(1 << ov.value.index()))) {
			/* We need to override the existing value */
			/*
			 * The algorithm is not very efficient,
			 * so we need to sort the values first and have a O(N) algorithm
			 * On the other hand, values vectors are usually limited to the
			 * number of elements about less then 10, so this O(N^2) algorithm
			 * is probably ok here
			 */
			for (auto &v : values) {
				if (v.value.index() == ov.value.index()) {
					v = ov;
				}
			}
		}
	}

	/* Copy only not set values */
	std::copy_if(other.values.begin(), other.values.end(), std::back_inserter(values),
			[&bits](const auto &elt) -> bool {
				return (bits & (1 << static_cast<int>(elt.value.index()))) == 0;
			});
}

void css_rule::merge_values(const css_rule &other)
{
	unsigned int bits = 0;

	for (const auto &v : values) {
		bits |= 1 << v.value.index();
	}

	/* Copy only not set values */
	std::copy_if(other.values.begin(), other.values.end(), std::back_inserter(values),
			[&bits](const auto &elt) -> bool {
				return (bits & (1 << elt.value.index())) == 0;
			});
}

auto css_declarations_block::add_rule(rule_shared_ptr rule) -> bool
{
	auto it = rules.find(rule);
	auto &&remote_prop = rule->get_prop();
	auto ret = true;

	if (rule->get_values().size() == 0) {
		/* Ignore rules with no values */
		return false;
	}

	if (it != rules.end()) {
		auto &&local_rule = *it;
		auto &&local_prop = local_rule->get_prop();

		if (local_prop.flag == css_property_flag::FLAG_IMPORTANT) {
			if (remote_prop.flag == css_property_flag::FLAG_IMPORTANT) {
				local_rule->override_values(*rule);
			}
			else {
				/* Override remote not important over local important */
				local_rule->merge_values(*rule);
			}
		}
		else if (local_prop.flag == css_property_flag::FLAG_NOT_IMPORTANT) {
			if (remote_prop.flag == css_property_flag::FLAG_NOT_IMPORTANT) {
				local_rule->override_values(*rule);
			}
			else {
				/* Override local not important over important */
				local_rule->merge_values(*rule);
			}
		}
		else {
			if (remote_prop.flag == css_property_flag::FLAG_IMPORTANT) {
				/* Override with remote */
				local_rule->override_values(*rule);
			}
			else if (remote_prop.flag == css_property_flag::FLAG_NOT_IMPORTANT) {
				/* Ignore remote not important over local normal */
				ret = false;
			}
			else {
				/* Merge both */
				local_rule->merge_values(*rule);
			}
		}
	}
	else {
		rules.insert(std::move(rule));
	}

	return ret;
}

}

namespace rspamd::css {

/* Static functions */

static auto
allowed_property_value(const css_property &prop, const css_consumed_block &parser_block)
-> std::optional<css_value> {
	if (prop.is_color()) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::hash_token) {
				return css_value::maybe_color_from_hex(tok.get_string_or_default(""));
			}
			else if (tok.type == css_parser_token::token_type::ident_token) {
				auto &&ret = css_value::maybe_color_from_string(tok.get_string_or_default(""));

				return ret;
			}
		}
		else if (parser_block.is_function()) {
			const auto &func = parser_block.get_function_or_invalid();

			auto &&ret = css_value::maybe_color_from_function(func);
			return ret;
		}
	}
	if (prop.is_dimension()) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::number_token) {
				return css_value::maybe_dimension_from_number(tok);
			}
		}
	}
	if (prop.is_display()) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::ident_token) {
				return css_value::maybe_display_from_string(tok.get_string_or_default(""));
			}
		}
	}
	if (prop.is_visibility()) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::ident_token) {
				return css_value::maybe_display_from_string(tok.get_string_or_default(""));
			}
		}
	}
	if (prop.is_normal_number()) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::number_token) {
				return css_value{tok.get_normal_number_or_default(0)};
			}
		}
	}

	return std::nullopt;
}

auto process_declaration_tokens(rspamd_mempool_t *pool,
								blocks_gen_functor &&next_block_functor)
-> css_declarations_block_ptr {
	css_declarations_block_ptr ret;
	bool can_continue = true;
	css_property cur_property{css_property_type::PROPERTY_NYI,
							  css_property_flag::FLAG_NORMAL};
	static const css_property bad_property{css_property_type::PROPERTY_NYI,
										   css_property_flag::FLAG_NORMAL};
	std::shared_ptr<css_rule> cur_rule;

	enum {
		parse_property,
		parse_value,
		ignore_value, /* For unknown properties */
	} state = parse_property;

	auto seen_not = false;
	ret = std::make_shared<css_declarations_block>();

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
						cur_rule = std::make_shared<css_rule>(cur_property);
					}
				}
			}
			else if (state == parse_value) {
				/* Check semicolon */
				if (next_tok.is_token()) {
					const auto &parser_tok = next_tok.get_token_or_empty();

					if (parser_tok.type == css_parser_token::token_type::semicolon_token && cur_rule) {
						ret->add_rule(std::move(cur_rule));
						state = parse_property;
						seen_not = false;
						continue;
					}
					else if (parser_tok.type == css_parser_token::token_type::delim_token) {
						if (parser_tok.get_string_or_default("") == "!") {
							/* Probably something like !important */
							seen_not = true;
						}
					}
					else if (parser_tok.type == css_parser_token::token_type::ident_token) {
						if (parser_tok.get_string_or_default("") == "important") {
							if (seen_not) {
								msg_debug_css("add !important flag to property %s",
										cur_property.to_string());
								cur_property.flag = css_property_flag::FLAG_NOT_IMPORTANT;
							}
							else {
								msg_debug_css("add important flag to property %s",
										cur_property.to_string());
								cur_property.flag = css_property_flag::FLAG_IMPORTANT;
							}

							seen_not = false;

							continue;
						}
						else {
							seen_not = false;
						}
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

				if (maybe_value && cur_rule) {
					msg_debug_css("added value %s to the property %s",
							maybe_value.value().debug_str().c_str(),
							cur_property.to_string());
					cur_rule->add_value(maybe_value.value());
				}
			}
			break;
		case css_consumed_block::parser_tag_type::css_eof_block:
			if (state == parse_value) {
				ret->add_rule(std::move(cur_rule));
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

auto
css_declarations_block::merge_block(const css_declarations_block &other, merge_type how) -> void
{
	const auto &other_rules = other.get_rules();


	for (auto &rule : other_rules) {
		auto &&found_it = rules.find(rule);

		if (found_it != rules.end()) {
			/* Duplicate, need to merge */
			switch (how) {
			case merge_type::merge_override:
				/* Override */
				(*found_it)->override_values(*rule);
				break;
			case merge_type::merge_duplicate:
				/* Merge values */
				add_rule(rule);
				break;
			case merge_type::merge_parent:
				/* Do not merge parent rule if more specific local one is presented */
				break;
			}
		}
		else {
			/* New property, just insert */
			rules.insert(rule);
		}
	}
}

auto
css_declarations_block::compile_to_block(rspamd_mempool_t *pool) const -> rspamd::html::html_block *
{
	auto *block = rspamd_mempool_alloc0_type(pool, rspamd::html::html_block);
	auto opacity = -1;
	const css_rule *font_rule = nullptr, *background_rule = nullptr;

	for (const auto &rule : rules) {
		auto prop = rule->get_prop().type;
		const auto &vals = rule->get_values();

		if (vals.empty()) {
			continue;
		}

		switch (prop) {
		case css_property_type::PROPERTY_VISIBILITY:
		case css_property_type::PROPERTY_DISPLAY: {
			auto disp = vals.back().to_display().value_or(css_display_value::DISPLAY_INLINE);
			block->set_display(disp);
			break;
		}
		case css_property_type::PROPERTY_FONT_SIZE: {
			auto fs = vals.back().to_dimension();
			if (fs) {
				block->set_font_size(fs.value().dim, fs.value().is_percent);
			}
		}
		case css_property_type::PROPERTY_OPACITY: {
			opacity = vals.back().to_number().value_or(opacity);
			break;
		}
		case css_property_type::PROPERTY_FONT_COLOR:
		case css_property_type::PROPERTY_COLOR: {
			auto color = vals.back().to_color();
			if (color) {
				block->set_fgcolor(color.value());
			}
			break;
		}
		case css_property_type::PROPERTY_BGCOLOR: {
			auto color = vals.back().to_color();
			if (color) {
				block->set_bgcolor(color.value());
			}
			break;
		}
		case css_property_type::PROPERTY_HEIGHT: {
			auto w = vals.back().to_dimension();
			if (w) {
				block->set_width(w.value().dim, w.value().is_percent);
			}
			break;
		}
		case css_property_type::PROPERTY_WIDTH: {
			auto h = vals.back().to_dimension();
			if (h) {
				block->set_width(h.value().dim, h.value().is_percent);
			}
			break;
		}
		/* Optional attributes */
		case css_property_type::PROPERTY_FONT:
			font_rule = rule.get();
			break;
		case css_property_type::PROPERTY_BACKGROUND:
			background_rule = rule.get();
			break;
		default:
			/* Do nothing for now */
			break;
		}
	}

	/* Optional properties */
	if (!(block->fg_color_mask) && font_rule) {
		auto &vals = font_rule->get_values();

		for (const auto &val : vals) {
			auto maybe_color = val.to_color();

			if (maybe_color) {
				block->set_fgcolor(maybe_color.value());
			}
		}
	}

	if (!(block->font_mask) && font_rule) {
		auto &vals = font_rule->get_values();

		for (const auto &val : vals) {
			auto maybe_dim = val.to_dimension();

			if (maybe_dim) {
				block->set_font_size(maybe_dim.value().dim, maybe_dim.value().is_percent);
			}
		}
	}

	if (!(block->bg_color_mask) && background_rule) {
		auto &vals = background_rule->get_values();

		for (const auto &val : vals) {
			auto maybe_color = val.to_color();

			if (maybe_color) {
				block->set_bgcolor(maybe_color.value());
			}
		}
	}

	return block;
}

void css_rule::add_value(const css_value &value)
{
	values.push_back(value);
}


TEST_SUITE("css") {
	TEST_CASE("simple css rules") {
		const std::vector<std::pair<const char *, std::vector<css_property>>> cases{
				{
					"font-size:12.0pt;line-height:115%",
	 				{css_property(css_property_type::PROPERTY_FONT_SIZE)}
	 			},
				{
					"font-size:12.0pt;display:none",
				{css_property(css_property_type::PROPERTY_FONT_SIZE),
	 				css_property(css_property_type::PROPERTY_DISPLAY)}
				}
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
				"css", 0);

		for (const auto &c : cases) {
			auto res = process_declaration_tokens(pool,
					get_rules_parser_functor(pool, c.first));

			CHECK(res.get() != nullptr);

			for (auto i = 0; i < c.second.size(); i ++) {
				CHECK(res->has_property(c.second[i]));
			}
		}
	}
}

} // namespace rspamd::css