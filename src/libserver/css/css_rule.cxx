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
#include <algorithm>
#include <cmath>
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

	for (const auto &v: values) {
		bits |= static_cast<int>(1 << v.value.index());
	}

	for (const auto &ov: other.values) {
		if (bits & (1 << ov.value.index())) {
			/* We need to override the existing value */
			/*
			 * The algorithm is not very efficient,
			 * so we need to sort the values first and have a O(N) algorithm
			 * On the other hand, values vectors are usually limited to the
			 * number of elements about less then 10, so this O(N^2) algorithm
			 * is probably ok here
			 */
			for (auto &v: values) {
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

	for (const auto &v: values) {
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
				local_rule->mark_important(remote_prop.flag);
			}
			else {
				/* Override remote not important over local important */
				local_rule->merge_values(*rule);
			}
		}
		else if (local_prop.flag == css_property_flag::FLAG_NOT_IMPORTANT) {
			if (remote_prop.flag == css_property_flag::FLAG_NOT_IMPORTANT) {
				local_rule->override_values(*rule);
				local_rule->mark_important(remote_prop.flag);
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
				local_rule->mark_important(remote_prop.flag);
			}
			else if (remote_prop.flag == css_property_flag::FLAG_NOT_IMPORTANT) {
				/* Ignore remote not important over local normal */
				ret = false;
			}
			else {
				/* Override with remote - in CSS, later declarations win */
				local_rule->override_values(*rule);
				local_rule->mark_important(remote_prop.flag);
			}
		}
	}
	else {
		rules.insert(std::move(rule));
	}

	return ret;
}

}// namespace rspamd::css

namespace rspamd::css {

/* Static functions */

/*
 * Whether a clip / clip-path function collapses the element to a zero
 * area, fully hiding its content (a common way to hide text):
 *  - clip: rect(0,0,0,0) / rect(1px,1px,1px,1px)
 *  - clip-path: inset(100%) (or >= 50% on the first edge)
 *  - clip-path: circle(0) / ellipse(0)
 */
static auto
clip_function_hides(const css_consumed_block::css_function_block &func) -> bool
{
	auto get_num = [](const auto &arg, float &out, bool &is_percent) -> bool {
		const auto &tok = arg->get_token_or_empty();
		if (std::holds_alternative<float>(tok.value)) {
			out = std::get<float>(tok.value);
			is_percent = (tok.flags & css_parser_token::number_percent) != 0;
			return true;
		}
		return false;
	};

	auto name = func.as_string();

	if (name == "rect") {
		auto numeric_seen = false;
		for (const auto &arg: func.args) {
			float v = 0;
			bool pct = false;
			if (get_num(arg, v, pct)) {
				numeric_seen = true;
				if (std::fabs(v) > 1.0f) {
					return false;
				}
			}
		}
		return numeric_seen;
	}
	else if (name == "inset") {
		for (const auto &arg: func.args) {
			float v = 0;
			bool pct = false;
			if (get_num(arg, v, pct)) {
				return pct && v >= 50.0f;
			}
		}
	}
	else if (name == "circle" || name == "ellipse") {
		for (const auto &arg: func.args) {
			float v = 0;
			bool pct = false;
			if (get_num(arg, v, pct)) {
				return v <= 0.0f;
			}
		}
	}

	return false;
}

/*
 * Case-insensitive comparison of an identifier token with a word
 * given as a literal
 */
template<std::size_t N>
static auto
css_ident_equals(const css_parser_token &tok, const char (&word)[N]) -> bool
{
	auto str = tok.get_string_or_default("");

	return str.size() == N - 1 &&
		   g_ascii_strncasecmp(str.data(), word, N - 1) == 0;
}

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
				if (tok.flags & css_parser_token::flag_bad_dimension) {
					/*
					 * The unit is not one we know, while all the valid CSS
					 * length units are: this is invalid CSS, which a
					 * browser drops as well, leaving the earlier
					 * declaration of the property in effect
					 */
					return std::nullopt;
				}

				if (prop.type == css_property_type::PROPERTY_FONT &&
					!(tok.flags & (css_parser_token::number_dimension |
								   css_parser_token::number_percent))) {
					/*
					 * In the `font` shorthand a unitless number is the weight
					 * or the line-height, never the size. Zero is the
					 * exception: it is a valid length in every mode, cannot
					 * be a weight, and `font: 0 ...` renders text invisible
					 */
					auto is_zero = std::holds_alternative<float>(tok.value) &&
								   std::get<float>(tok.value) == 0.0f;

					if (!is_zero) {
						return std::nullopt;
					}
				}

				return css_value::maybe_dimension_from_number(tok);
			}
		}
		else if (parser_block.is_function() &&
				 (prop.type == css_property_type::PROPERTY_WIDTH ||
				  prop.type == css_property_type::PROPERTY_HEIGHT ||
				  prop.type == css_property_type::PROPERTY_MIN_WIDTH ||
				  prop.type == css_property_type::PROPERTY_MIN_HEIGHT ||
				  prop.type == css_property_type::PROPERTY_MAX_WIDTH ||
				  prop.type == css_property_type::PROPERTY_MAX_HEIGHT)) {
			/*
			 * A function value such as calc() or var() cannot be
			 * resolved to an absolute size. Width, height and the
			 * minimums are recorded as unknown ones, the same way as
			 * `auto`, and a maximum the `none` way, so that a bound
			 * declared earlier does not survive a declaration that
			 * replaced it with an unresolvable one
			 */
			if (prop.type == css_property_type::PROPERTY_MAX_HEIGHT ||
				prop.type == css_property_type::PROPERTY_MAX_WIDTH) {
				return css_value(css_dimension{-1.0f, false, false});
			}

			return css_value(css_dimension{-2.0f, false, false});
		}
	}
	if (prop.type == css_property_type::PROPERTY_MAX_HEIGHT ||
		prop.type == css_property_type::PROPERTY_MAX_WIDTH) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::ident_token &&
				(css_ident_equals(tok, "none") ||
				 css_ident_equals(tok, "inherit"))) {
				/* `none` removes the bound, and `inherit` resolves
				 * against the parent and cannot be resolved here; both
				 * are encoded as a negative length, which no valid CSS
				 * dimension can be */
				return css_value(css_dimension{-1.0f, false, false});
			}
		}
	}
	if (prop.type == css_property_type::PROPERTY_WIDTH ||
		prop.type == css_property_type::PROPERTY_HEIGHT) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::ident_token &&
				(css_ident_equals(tok, "auto") ||
				 css_ident_equals(tok, "inherit"))) {
				/* `auto` is the intrinsic size, and `inherit` resolves
				 * against the parent; both are unresolvable and encoded
				 * as a negative length distinct from the `none` one */
				return css_value(css_dimension{-2.0f, false, false});
			}
		}
	}
	if (prop.type == css_property_type::PROPERTY_MIN_HEIGHT ||
		prop.type == css_property_type::PROPERTY_MIN_WIDTH) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::ident_token &&
				css_ident_equals(tok, "inherit")) {
				/* An inherited minimum resolves against the parent and
				 * cannot raise the floor here */
				return css_value(css_dimension{-2.0f, false, false});
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
	if (prop.is_overflow()) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::ident_token) {
				auto sv = tok.get_string_or_default("");

				/* Distinguish only the clipping values, as they hide
				 * the content of a zero sized block entirely */
				if (sv == "hidden" || sv == "clip") {
					return css_value{css_display_value::DISPLAY_HIDDEN};
				}

				return css_value{css_display_value::DISPLAY_INLINE};
			}
		}
	}
	if (prop.is_position()) {
		if (parser_block.is_token()) {
			/* A single token */
			const auto &tok = parser_block.get_token_or_empty();

			if (tok.type == css_parser_token::token_type::ident_token) {
				auto sv = tok.get_string_or_default("");

				/* Only out-of-flow positioning can move content off-screen;
				 * encode it as a number flag for compile_to_block */
				return css_value{(sv == "absolute" || sv == "fixed") ? 1.0f : 0.0f};
			}
		}
	}
	if (prop.is_clip()) {
		if (parser_block.is_function()) {
			const auto &func = parser_block.get_function_or_invalid();

			return css_value{clip_function_hides(func) ? 1.0f : 0.0f};
		}
		else if (parser_block.is_token()) {
			/* idents such as auto / none do not hide anything */
			return css_value{0.0f};
		}
	}

	return std::nullopt;
}

auto process_declaration_tokens(rspamd_mempool_t *pool,
								blocks_gen_functor &&next_block_functor)
	-> css_declarations_block_ptr
{
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
							/*
							 * The rule already holds a copy of the property,
							 * so the flag has to be set on it as well; a bare
							 * `important` without `!` is not the important flag
							 */
							auto flag = seen_not
											? css_property_flag::FLAG_IMPORTANT
											: css_property_flag::FLAG_NOT_IMPORTANT;

							msg_debug_css("add important flag %d to property %s",
										  static_cast<int>(flag),
										  cur_property.to_string());
							cur_property.flag = flag;

							if (cur_rule) {
								cur_rule->mark_important(flag);
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

auto css_declarations_block::merge_block(const css_declarations_block &other, merge_type how) -> void
{
	const auto &other_rules = other.get_rules();


	for (auto &rule: other_rules) {
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

auto css_declarations_block::compile_to_block(rspamd_mempool_t *pool) const -> rspamd::html::html_block *
{
	auto *block = rspamd_mempool_alloc0_type(pool, rspamd::html::html_block);

	compile_into(*block);

	return block;
}

auto css_declarations_block::compile_into(rspamd::html::html_block &out) const -> void
{
	auto *block = &out;
	auto opacity = -1.0f;
	std::optional<css_dimension> height, width, max_height, max_width;
	std::optional<css_dimension> min_height, min_width;
	std::optional<css_dimension> left, top, text_indent;
	auto positioned = false, clip_hidden = false;
	auto height_important = false, width_important = false;
	auto min_height_important = false, min_width_important = false;
	auto max_height_important = false, max_width_important = false;
	const css_rule *font_rule = nullptr, *background_rule = nullptr;

	for (const auto &rule: rules) {
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
			break;
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
			height = vals.back().to_dimension();
			height_important = rule->get_prop().flag ==
							   css_property_flag::FLAG_IMPORTANT;
			break;
		}
		case css_property_type::PROPERTY_WIDTH: {
			width = vals.back().to_dimension();
			width_important = rule->get_prop().flag ==
							  css_property_flag::FLAG_IMPORTANT;
			break;
		}
		case css_property_type::PROPERTY_MAX_HEIGHT: {
			max_height = vals.back().to_dimension();
			max_height_important = rule->get_prop().flag ==
									css_property_flag::FLAG_IMPORTANT;
			break;
		}
		case css_property_type::PROPERTY_MAX_WIDTH: {
			max_width = vals.back().to_dimension();
			max_width_important = rule->get_prop().flag ==
								   css_property_flag::FLAG_IMPORTANT;
			break;
		}
		case css_property_type::PROPERTY_MIN_HEIGHT: {
			min_height = vals.back().to_dimension();
			min_height_important = rule->get_prop().flag ==
									css_property_flag::FLAG_IMPORTANT;
			break;
		}
		case css_property_type::PROPERTY_MIN_WIDTH: {
			min_width = vals.back().to_dimension();
			min_width_important = rule->get_prop().flag ==
								   css_property_flag::FLAG_IMPORTANT;
			break;
		}
		case css_property_type::PROPERTY_OVERFLOW: {
			auto disp = vals.back().to_display();
			if (disp) {
				block->set_overflow(disp.value() == css_display_value::DISPLAY_HIDDEN);
			}
			break;
		}
		case css_property_type::PROPERTY_POSITION: {
			positioned = vals.back().to_number().value_or(0.0f) > 0.5f;
			break;
		}
		case css_property_type::PROPERTY_LEFT: {
			left = vals.back().to_dimension();
			break;
		}
		case css_property_type::PROPERTY_TOP: {
			top = vals.back().to_dimension();
			break;
		}
		case css_property_type::PROPERTY_TEXT_INDENT: {
			text_indent = vals.back().to_dimension();
			break;
		}
		case css_property_type::PROPERTY_CLIP:
		case css_property_type::PROPERTY_CLIP_PATH: {
			if (vals.back().to_number().value_or(0.0f) > 0.5f) {
				clip_hidden = true;
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

	/*
	 * max-height/max-width clamp the corresponding dimension; mixed
	 * percent/absolute values cannot be compared, so prefer the zero
	 * limit in that case as it is the only value that matters for
	 * the visibility detection
	 */
	auto clamp_dim = [](std::optional<css_dimension> dim,
						std::optional<css_dimension> max_dim,
						bool *from_max) -> std::optional<css_dimension> {
		*from_max = false;

		if (dim && max_dim) {
			if (dim->is_percent == max_dim->is_percent) {
				return max_dim->dim < dim->dim ? max_dim : dim;
			}

			return max_dim->dim == 0 ? max_dim : dim;
		}

		if (dim) {
			return dim;
		}

		if (max_dim) {
			*from_max = true;

			return max_dim;
		}

		return std::nullopt;
	};

	/* A zero percent value, whether a size, a bound or a floor, is an
	 * absolute zero, so it is normalised to one before anything else */
	auto zero_percent = [](std::optional<css_dimension> &d) -> void {
		if (d && d->is_percent && d->dim == 0) {
			d->is_percent = false;
		}
	};
	zero_percent(width);
	zero_percent(height);
	zero_percent(max_width);
	zero_percent(max_height);
	zero_percent(min_width);
	zero_percent(min_height);

	/*
	 * The actual dimensions are recorded before the max bounds clamp
	 * the flattened values below, so that the image classification
	 * can apply the cascade result rather than a clamped one. A
	 * percent size or `auto` wins the cascade as well, but has no
	 * absolute value, so it is recorded as a negative sentinel
	 */
	if (width) {
		if (width->is_percent || width->is_relative_unit || width->dim < 0) {
			block->width_real = -1;
		}
		else {
			block->width_real = width->dim;
		}
		block->width_real_mask = 1;
		block->width_important = width_important;
	}
	if (height) {
		if (height->is_percent || height->is_relative_unit || height->dim < 0) {
			block->height_real = -1;
		}
		else {
			block->height_real = height->dim;
		}
		block->height_real_mask = 1;
		block->height_important = height_important;
	}

	/* A negative max dimension encodes `none`, and a percent one is
	 * unresolvable: both remove the bound rather than set it. The
	 * same applies to the minimums, which a percent value cannot
	 * raise either */
	if (max_width && (max_width->is_percent || max_width->is_relative_unit ||
					  max_width->dim < 0)) {
		block->width_max_mask = 2;
		block->max_width_important = max_width_important;
	}
	if (max_height && (max_height->is_percent || max_height->is_relative_unit ||
					   max_height->dim < 0)) {
		block->height_max_mask = 2;
		block->max_height_important = max_height_important;
	}
	if (min_width &&
		(min_width->is_percent || min_width->is_relative_unit || min_width->dim < 0)) {
		block->min_width_mask = 2;
		block->min_width_important = min_width_important;
	}
	if (min_height &&
		(min_height->is_percent || min_height->is_relative_unit || min_height->dim < 0)) {
		block->min_height_mask = 2;
		block->min_height_important = min_height_important;
	}

	/* `none` and percent maxima must not clamp the dimensions */
	auto no_bound = [](const std::optional<css_dimension> &d) -> std::optional<css_dimension> {
		if (d && (d->is_percent || d->dim < 0)) {
			return std::nullopt;
		}

		return d;
	};
	/* `auto` must not be flattened into the width/height fields
	 * either, as a negative value there encodes a percent */
	auto no_auto = [](const std::optional<css_dimension> &d) -> std::optional<css_dimension> {
		if (d && !d->is_percent && d->dim < 0) {
			return std::nullopt;
		}

		return d;
	};

	bool height_from_max = false, width_from_max = false;

	if (auto h = clamp_dim(no_auto(height), no_bound(max_height), &height_from_max); h) {
		block->set_height(h->dim, h->is_percent);
		block->height_from_max = height_from_max;
	}
	if (auto w = clamp_dim(no_auto(width), no_bound(max_width), &width_from_max); w) {
		block->set_width(w->dim, w->is_percent);
		block->width_from_max = width_from_max;
	}

	/*
	 * `auto` is excluded from the flattening above, but the size
	 * fields must still be set, so that a less specific absolute
	 * value does not fill in on merging and the size never looks
	 * like a zero one for the visibility detection. A max bound
	 * still flattens over it, capping the auto size
	 */
	if (height && !height->is_percent && height->dim < 0 &&
		block->height_mask != rspamd::html::html_block::set) {
		block->set_height((float) INT16_MAX);
		block->height_auto = true;
	}
	if (width && !width->is_percent && width->dim < 0 &&
		block->width_mask != rspamd::html::html_block::set) {
		block->set_width((float) INT16_MAX);
		block->width_auto = true;
	}

	/*
	 * Minimum dimensions and max bounds are needed for the image
	 * classification only, so absolute values are stored as is and
	 * percent ones are ignored
	 */
	if (min_height && !min_height->is_percent && !min_height->is_relative_unit &&
		min_height->dim >= 0) {
		block->min_height = min_height->dim;
		block->min_height_mask = 1;
		block->min_height_important = min_height_important;
	}
	if (min_width && !min_width->is_percent && !min_width->is_relative_unit &&
		min_width->dim >= 0) {
		block->min_width = min_width->dim;
		block->min_width_mask = 1;
		block->min_width_important = min_width_important;
	}
	if (max_height && !max_height->is_percent && !max_height->is_relative_unit &&
		max_height->dim >= 0) {
		block->height_max = max_height->dim;
		block->height_max_mask = 1;
		block->max_height_important = max_height_important;
	}
	if (max_width && !max_width->is_percent && !max_width->is_relative_unit &&
		max_width->dim >= 0) {
		block->width_max = max_width->dim;
		block->width_max_mask = 1;
		block->max_width_important = max_width_important;
	}

	if (opacity >= 0 && opacity < 0.1) {
		/*
		 * A (nearly) zero opacity makes the block invisible, and, unlike
		 * display, it cannot be reset by descendants; reuse the display
		 * value as it has the desired inheritance semantics
		 */
		block->set_display(css_display_value::DISPLAY_HIDDEN);
	}

	/*
	 * Off-screen positioning and clipping hide the content while keeping it
	 * in the document. As with opacity, descendants cannot bring it back, so
	 * model it as a hidden display, additionally flagging it for the
	 * offscreen feature counter:
	 *  - position:absolute|fixed with a large negative left/top
	 *  - a large negative text-indent (image-replacement trick)
	 *  - clip / clip-path collapsing the element to a zero area
	 */
	constexpr const auto offscreen_threshold = -1000.0f;
	auto is_offscreen = [&](const std::optional<css_dimension> &d) -> bool {
		return d && !d->is_percent && d->dim <= offscreen_threshold;
	};

	if ((positioned && (is_offscreen(left) || is_offscreen(top))) ||
		is_offscreen(text_indent) || clip_hidden) {
		block->set_display(css_display_value::DISPLAY_HIDDEN);
		block->offscreen = true;
	}

	/* Optional properties */
	if (!(block->fg_color_mask) && font_rule) {
		auto &vals = font_rule->get_values();

		for (const auto &val: vals) {
			auto maybe_color = val.to_color();

			if (maybe_color) {
				block->set_fgcolor(maybe_color.value());
			}
		}
	}

	if (!(block->font_mask) && font_rule) {
		auto &vals = font_rule->get_values();

		for (const auto &val: vals) {
			auto maybe_dim = val.to_dimension();

			if (maybe_dim) {
				/* The size is the first length of the shorthand */
				block->set_font_size(maybe_dim.value().dim, maybe_dim.value().is_percent);
				break;
			}
		}
	}

	if (!(block->bg_color_mask) && background_rule) {
		auto &vals = background_rule->get_values();

		for (const auto &val: vals) {
			auto maybe_color = val.to_color();

			if (maybe_color) {
				block->set_bgcolor(maybe_color.value());
			}
		}
	}
}

void css_rule::add_value(const css_value &value)
{
	values.push_back(value);
}


TEST_SUITE("css")
{
	TEST_CASE("simple css rules")
	{
		const std::vector<std::pair<const char *, std::vector<css_property>>> cases{
			{"font-size:12.0pt;line-height:115%",
			 {css_property(css_property_type::PROPERTY_FONT_SIZE)}},
			{"font-size:12.0pt;display:none",
			 {css_property(css_property_type::PROPERTY_FONT_SIZE),
			  css_property(css_property_type::PROPERTY_DISPLAY)}}};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		for (const auto &c: cases) {
			auto res = process_declaration_tokens(pool,
												  get_rules_parser_functor(pool, c.first));

			CHECK(res.get() != nullptr);

			for (auto i = 0; i < c.second.size(); i++) {
				CHECK(res->has_property(c.second[i]));
			}
		}
	}

	TEST_CASE("hidden blocks are compiled as invisible")
	{
		/* Real-world hiding techniques: text is removed from the rendered
		 * view to dilute the visible content (e.g. of a phishing message) */
		const std::vector<const char *> hidden_styles{
			"display:block; max-width:0; max-height:0; overflow:hidden",
			"opacity:0; height:0; line-height:0; overflow:hidden",
			"overflow:hidden; max-height:0",
			"height:0px; overflow:clip",
			"width:0; overflow:hidden",
			"opacity:0.01",
			"max-height:0; height:50px; overflow:hidden",
			/* Off-screen positioning */
			"position:absolute; left:-9999px",
			"position:absolute; top:-9999px; left:0",
			"position:fixed; left:-10000px",
			/* Image-replacement text-indent */
			"text-indent:-9999px",
			"text-indent:-100000px; white-space:nowrap",
			/* Clip / clip-path */
			"clip:rect(0,0,0,0); position:absolute",
			"clip:rect(1px,1px,1px,1px)",
			"clip-path:inset(100%)",
			"clip-path:inset(50%)",
			"clip-path:circle(0)",
			/* visibility:collapse */
			"visibility:collapse",
			/* unitless zero size in the font shorthand */
			"font:0 Arial",
			"font:400 0/1.5 Arial",
			/* Tiny font */
			"font-size:1px",
			"font-size:2px",
		};
		const std::vector<const char *> visible_styles{
			"max-width:600px; width:100%",
			/* Without overflow:hidden the content of a zero sized block
			 * is rendered outside of the block */
			"height:0",
			"max-height:0",
			"opacity:0.5",
			"overflow:hidden; max-height:10px",
			"overflow:hidden",
			"display:block",
			/* Absolute positioning on-screen is legitimate */
			"position:absolute; left:10px; top:20px",
			"position:absolute",
			/* A negative offset without out-of-flow positioning does not hide */
			"left:-9999px",
			/* Small or positive text-indent is normal */
			"text-indent:-20px",
			"text-indent:40px",
			/* Non-collapsing clip values */
			"clip:rect(auto,auto,auto,auto)",
			"clip-path:inset(10%)",
			"clip-path:none",
			/* Readable font */
			"font-size:10px",
		};

		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		for (const auto *css_text: hidden_styles) {
			auto res = process_declaration_tokens(pool,
												  get_rules_parser_functor(pool, css_text));
			CHECK(res.get() != nullptr);
			auto *block = res->compile_to_block(pool);
			CHECK(block != nullptr);
			block->compute_visibility();
			CHECK_MESSAGE(!block->is_visible(), css_text);
		}

		for (const auto *css_text: visible_styles) {
			auto res = process_declaration_tokens(pool,
												  get_rules_parser_functor(pool, css_text));
			CHECK(res.get() != nullptr);
			auto *block = res->compile_to_block(pool);
			CHECK(block != nullptr);
			block->compute_visibility();
			CHECK_MESSAGE(block->is_visible(), css_text);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("font shorthand takes the size and not the weight or line-height")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		/* Unitless numbers of the shorthand are the weight and the
		 * line-height, only the length in between is the size */
		const std::vector<std::pair<const char *, int>> cases{
			{"font:16px Arial", 16},
			{"font:400 1rem Arial", 16},
			{"font:400 1rem/1.5 Arial", 16},
			{"font:400 1rem / 1.5 Arial", 16},
			{"font:16px/24px Arial", 16},
			{"font:italic 400 12pt/2 Arial", 16},
			{"font:1px/1.5 Arial", 1},
			{"font:400 0px/1.5 Arial", 0},
			/* A unitless zero is the one unitless size the shorthand allows */
			{"font:0 Arial", 0},
			{"font:400 0/1.5 Arial", 0},
			{"font:bold 0/16px Arial", 0},
			{"font:16px/0 Arial", 16},
		};

		for (const auto &c: cases) {
			auto res = process_declaration_tokens(pool,
												  get_rules_parser_functor(pool, c.first));
			CHECK(res.get() != nullptr);
			auto *block = res->compile_to_block(pool);
			CHECK(block != nullptr);
			CHECK_MESSAGE(static_cast<int>(block->font_mask) != 0, c.first);
			CHECK_MESSAGE(block->font_size == c.second, c.first);
		}

		/* A shorthand without a length leaves the size unset */
		for (const auto *css_text: {"font:400 Arial", "font:bold Arial"}) {
			auto res = process_declaration_tokens(pool,
												  get_rules_parser_functor(pool, css_text));
			CHECK(res.get() != nullptr);
			auto *block = res->compile_to_block(pool);
			CHECK(block != nullptr);
			CHECK_MESSAGE(static_cast<int>(block->font_mask) == 0, css_text);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("an unknown unit does not become a bare pixel size")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		/* The tokeniser leaves the number behind when it cannot place the
		 * unit; taking it as pixels turns a responsive size into a hidden one */
		for (const auto *css_text: {"font-size:2nonsense", "height:0nonsense",
									"width:0nonsense"}) {
			auto res = process_declaration_tokens(pool,
												  get_rules_parser_functor(pool, css_text));
			CHECK(res.get() != nullptr);
			auto *block = res->compile_to_block(pool);
			CHECK(block != nullptr);
			block->compute_visibility();
			CHECK_MESSAGE(block->is_visible(), css_text);
		}

		/* Viewport units are known and keep working, and so do the units
		 * that used to be unknown: ch and lh are font-relative, and q is
		 * a quarter of a millimetre, small enough to hide the text */
		const std::vector<std::pair<const char *, int>> known{
			{"font-size:2vw", 16},
			{"font-size:2vh", 12},
			{"font-size:2vmin", 12},
			{"font-size:2vmax", 16},
			{"font-size:2ch", 16},
			{"font-size:2lh", 32},
			{"font-size:2q", 1},
		};

		for (const auto &c: known) {
			auto res = process_declaration_tokens(pool,
												  get_rules_parser_functor(pool, c.first));
			CHECK(res.get() != nullptr);
			auto *block = res->compile_to_block(pool);
			CHECK(block != nullptr);
			CHECK_MESSAGE(static_cast<int>(block->font_mask) != 0, c.first);
			CHECK_MESSAGE(block->font_size == c.second, c.first);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("percent font sizes survive above 100 percent")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		/* Percent sizes are stored negated, so the field has to be wide
		 * enough to hold them before they are resolved against a parent */
		const std::vector<std::pair<const char *, int>> cases{
			{"font-size:50%", -50},
			{"font-size:100%", -100},
			{"font-size:200%", -200},
			{"font-size:1000%", -1000},
		};

		for (const auto &c: cases) {
			auto res = process_declaration_tokens(pool,
												  get_rules_parser_functor(pool, c.first));
			CHECK(res.get() != nullptr);
			auto *block = res->compile_to_block(pool);
			CHECK(block != nullptr);
			CHECK_MESSAGE(block->font_size == c.second, c.first);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("offscreen flag is set only for offscreen tricks")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		const std::vector<std::pair<const char *, bool>> cases{
			{"position:absolute; left:-9999px", true},
			{"text-indent:-9999px", true},
			{"clip:rect(0,0,0,0)", true},
			{"clip-path:inset(100%)", true},
			/* Not offscreen, even if hidden by other means */
			{"display:none", false},
			{"opacity:0", false},
			{"position:absolute; left:10px", false},
			{"font-size:1px", false},
		};

		for (const auto &c: cases) {
			auto res = process_declaration_tokens(pool,
												  get_rules_parser_functor(pool, c.first));
			CHECK(res.get() != nullptr);
			auto *block = res->compile_to_block(pool);
			CHECK(block != nullptr);
			CHECK_MESSAGE(block->offscreen == c.second, c.first);
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("height and width are applied to the proper fields")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		auto res = process_declaration_tokens(pool,
											  get_rules_parser_functor(pool, "height:10px;width:20px"));
		CHECK(res.get() != nullptr);
		auto *block = res->compile_to_block(pool);
		CHECK(block != nullptr);
		CHECK(static_cast<int>(block->height_mask) != 0);
		CHECK(static_cast<int>(block->width_mask) != 0);
		CHECK(block->height == 10);
		CHECK(block->width == 20);

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("hidden parent cannot be reset by child display")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		auto parent_res = process_declaration_tokens(pool,
													 get_rules_parser_functor(pool, "display:none"));
		auto *parent = parent_res->compile_to_block(pool);
		parent->compute_visibility();
		CHECK(!parent->is_visible());

		auto child_res = process_declaration_tokens(pool,
													get_rules_parser_functor(pool, "display:block"));
		auto *child = child_res->compile_to_block(pool);
		child->propagate_block(*parent);
		child->compute_visibility();
		CHECK(!child->is_visible());

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("duplicate color properties - last wins")
	{
		/* Test case: duplicate color declarations should use the last value
		 * This is a common spam technique to hide text by declaring white color first,
		 * then overriding with visible color. CSS spec says last declaration wins.
		 */
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(),
										"css", 0);

		/* First color is white (#FFFFFF), second is dark (#232333) - last should win */
		const char *css_text = "color:#FFFFFF;font-weight:400;color:#232333";
		auto res = process_declaration_tokens(pool,
											  get_rules_parser_functor(pool, css_text));

		CHECK(res.get() != nullptr);
		CHECK(res->has_property(css_property(css_property_type::PROPERTY_COLOR)));

		auto *block = res->compile_to_block(pool);
		CHECK(block != nullptr);
		/* Check that fg_color is set (mask is non-zero) */
		auto fg_mask = block->fg_color_mask;
		CHECK(fg_mask != 0);
		/* The color should be #232333 (dark), not #FFFFFF (white) */
		CHECK(block->fg_color.r == 0x23);
		CHECK(block->fg_color.g == 0x23);
		CHECK(block->fg_color.b == 0x33);

		rspamd_mempool_delete(pool);
	}
}

}// namespace rspamd::css