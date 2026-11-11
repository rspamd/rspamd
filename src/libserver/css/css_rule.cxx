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
#include <array>
#include <algorithm>

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

	/*
	 * Each value we have takes the last value of its type in `other`: one pass
	 * over each list, as a declaration may carry any number of values
	 */
	std::array<const css_value *, std::variant_size_v<decltype(css_value::value)>> last{};

	for (const auto &ov: other.values) {
		last[ov.value.index()] = &ov;
	}

	for (auto &v: values) {
		if (const auto *ov = last[v.value.index()]; ov != nullptr) {
			v = *ov;
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

void css_rule::replace_with(const css_rule &other)
{
	values = other.values;
	prop.flag = other.prop.flag;
	order = other.order;
}

auto css_declarations_block::add_rule(rule_shared_ptr rule) -> bool
{
	if (rule->get_values().size() == 0) {
		/* Ignore rules with no values */
		return false;
	}

	if (rule->get_order() == 0) {
		rule->set_order(next_order++);
	}

	auto it = rules.find(rule);

	if (it == rules.end()) {
		rules.insert(std::move(rule));

		return true;
	}

	auto &&local_rule = *it;

	if (local_rule->get_prop().flag == css_property_flag::FLAG_IMPORTANT &&
		rule->get_prop().flag != css_property_flag::FLAG_IMPORTANT) {
		/* A normal declaration never overrides an important one */
		return false;
	}

	/*
	 * Otherwise the later declaration wins: it is either important itself or
	 * both are of the same importance
	 */
	local_rule->replace_with(*rule);

	return true;
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
					 * The unit is not one we know: the tokeniser leaves the
					 * bare number behind, and reading it as pixels turns a
					 * responsive size into a hidden one
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
				if (tok.get_string_or_default("") == "visible") {
					return css_value{css_display_value::DISPLAY_INLINE};
				}

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
		ignore_value, /* For unknown properties and invalid declarations */
	} state = parse_property;

	auto seen_not = false;
	ret = std::make_shared<css_declarations_block>();

	/* Drops the current declaration, the next one starts after the `;` */
	auto drop_declaration = [&]() {
		cur_rule.reset();
		seen_not = false;
		state = ignore_value;
	};

	while (can_continue) {
		const auto &next_tok = next_block_functor();

		switch (next_tok.tag) {
		case css_consumed_block::parser_tag_type::css_component:
			/* Component can be a property or a compound list of values */
			if (state == parse_property) {
				const auto &prop_tok = next_tok.get_token_or_empty();

				if (prop_tok.type == css_parser_token::token_type::semicolon_token) {
					/* An empty declaration */
					continue;
				}

				cur_property = css_property::from_token(prop_tok)
								   .value_or(bad_property);

				if (cur_property.type == css_property_type::PROPERTY_NYI) {
					state = ignore_value;
					/* Ignore everything till ; */
					continue;
				}

				msg_debug_css("got css property: %s", cur_property.to_string());

				/* We now expect colon block */
				const auto &expect_colon_block = next_block_functor();

				if (expect_colon_block.tag == css_consumed_block::parser_tag_type::css_eof_block) {
					can_continue = false;
				}
				else if (expect_colon_block.tag != css_consumed_block::parser_tag_type::css_component) {
					state = ignore_value; /* Ignore up to the next rule */
				}
				else {
					const auto &expect_colon_tok = expect_colon_block.get_token_or_empty();

					if (expect_colon_tok.type == css_parser_token::token_type::colon_token) {
						state = parse_value;
						seen_not = false;
						cur_rule = std::make_shared<css_rule>(cur_property);
					}
					else if (expect_colon_tok.type == css_parser_token::token_type::semicolon_token) {
						msg_debug_css("invalid rule, no colon after property");
						state = parse_property;
					}
					else {
						msg_debug_css("invalid rule, no colon after property");
						state = ignore_value; /* Ignore up to the next rule */
					}
				}
			}
			else if (state == parse_value) {
				const auto &parser_tok = next_tok.get_token_or_empty();

				if (parser_tok.type == css_parser_token::token_type::semicolon_token) {
					if (cur_rule) {
						ret->add_rule(std::move(cur_rule));
					}
					cur_rule.reset();
					state = parse_property;
					seen_not = false;
					continue;
				}
				else if (parser_tok.type == css_parser_token::token_type::delim_token &&
						 parser_tok.get_string_or_default("") == "!") {
					/* Probably something like !important */
					seen_not = true;
					continue;
				}
				else if (parser_tok.type == css_parser_token::token_type::string_token &&
						 (parser_tok.flags & css_parser_token::flag_bad_string)) {
					/* A string with a raw newline makes the declaration invalid */
					msg_debug_css("bad string in the property %s", cur_property.to_string());
					drop_declaration();
					continue;
				}
				else if (parser_tok.type == css_parser_token::token_type::ident_token &&
						 seen_not) {
					auto sv = parser_tok.get_string_or_default("");

					seen_not = false;

					if (sv.size() == 9 && g_ascii_strncasecmp(sv.data(), "important", 9) == 0) {
						msg_debug_css("add important flag to property %s",
									  cur_property.to_string());
						cur_rule->set_flag(css_property_flag::FLAG_IMPORTANT);
						continue;
					}
				}
				else {
					seen_not = false;
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
				const auto &parser_tok = next_tok.get_token_or_empty();

				if (parser_tok.type == css_parser_token::token_type::semicolon_token) {
					state = parse_property;
				}
			}
			break;
		case css_consumed_block::parser_tag_type::css_function:
			if (state == parse_value) {
				seen_not = false;
				auto maybe_value = allowed_property_value(cur_property, next_tok);

				if (maybe_value && cur_rule) {
					msg_debug_css("added value %s to the property %s",
								  maybe_value.value().debug_str().c_str(),
								  cur_property.to_string());
					cur_rule->add_value(maybe_value.value());
				}
			}
			else if (state == parse_property) {
				state = ignore_value;
			}
			break;
		case css_consumed_block::parser_tag_type::css_simple_block:
			/*
			 * A block in a value is something that the properties here do not
			 * take: the declaration is invalid, the next ones are not
			 */
			if (state == parse_value) {
				drop_declaration();
			}
			else if (state == parse_property) {
				state = ignore_value;
			}
			break;
		case css_consumed_block::parser_tag_type::css_eof_block:
			if (state == parse_value && cur_rule) {
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
	/*
	 * Normal declarations first, then the important ones over them: the
	 * fields they set are marked, so that a block merged later can tell them
	 */
	css_hiding normal_hiding, hiding;

	compile_layer(out, false, rspamd::html::html_block::set, normal_hiding);

	rspamd::html::html_block important{};
	compile_layer(important, true, rspamd::html::html_block::important, hiding);
	out.set_block(important);

	/*
	 * What hides a block without `display` is taken over both layers, each
	 * property from the important one if it is there: `opacity: 0` is not
	 * undone by an important `display`, and a position and its offset may
	 * stand in different layers
	 */
	if (hiding.opacity < 0) {
		hiding.opacity = normal_hiding.opacity;
	}
	if (!hiding.positioned) {
		hiding.positioned = normal_hiding.positioned;
	}
	if (!hiding.left) {
		hiding.left = normal_hiding.left;
	}
	if (!hiding.top) {
		hiding.top = normal_hiding.top;
	}
	if (!hiding.text_indent) {
		hiding.text_indent = normal_hiding.text_indent;
	}
	if (!hiding.clip) {
		hiding.clip = normal_hiding.clip;
	}

	if (hiding.opacity >= 0 && hiding.opacity < 0.1) {
		/* A (nearly) zero opacity makes the block invisible */
		out.forced_hidden = true;
	}

	/*
	 * Off-screen positioning and clipping hide the content while keeping it
	 * in the document, which is additionally flagged for the offscreen
	 * feature counter:
	 *  - position:absolute|fixed with a large negative left/top
	 *  - a large negative text-indent (image-replacement trick)
	 *  - clip / clip-path collapsing the element to a zero area
	 */
	constexpr const auto offscreen_threshold = -1000.0f;
	auto is_offscreen = [&](const std::optional<css_dimension> &d) -> bool {
		return d && !d->is_percent && d->dim <= offscreen_threshold;
	};

	if ((hiding.positioned.value_or(false) && (is_offscreen(hiding.left) || is_offscreen(hiding.top))) ||
		is_offscreen(hiding.text_indent) || hiding.clip.value_or(false)) {
		out.forced_hidden = true;
		out.offscreen = true;
	}
}

/* Compiles the declarations that are important, or the ones that are not */
auto css_declarations_block::compile_layer(rspamd::html::html_block &out, bool important, int how,
										   css_hiding &hiding) const -> void
{
	auto *block = &out;
	std::optional<css_dimension> height, width, max_height, max_width;
	auto &opacity = hiding.opacity;
	auto &left = hiding.left, &top = hiding.top, &text_indent = hiding.text_indent;
	auto &positioned = hiding.positioned, &clip_hidden = hiding.clip;
	std::optional<css_display_value> display, visibility;
	auto has_color = rules.find(css_rule{css_property{css_property_type::PROPERTY_COLOR}}) != rules.end() ||
					 rules.find(css_rule{css_property{css_property_type::PROPERTY_FONT_COLOR}}) != rules.end();

	/*
	 * Declarations are applied in the source order, so that a shorthand and a
	 * longhand override each other as they do in a browser
	 */
	std::vector<const css_rule *> ordered;
	ordered.reserve(rules.size());

	for (const auto &rule: rules) {
		if ((rule->get_prop().flag == css_property_flag::FLAG_IMPORTANT) == important) {
			ordered.push_back(rule.get());
		}
	}

	std::sort(ordered.begin(), ordered.end(), [](const css_rule *a, const css_rule *b) {
		return a->get_order() < b->get_order();
	});

	for (const auto *rule: ordered) {
		auto prop = rule->get_prop().type;
		const auto &vals = rule->get_values();

		if (vals.empty()) {
			continue;
		}

		switch (prop) {
		case css_property_type::PROPERTY_DISPLAY: {
			display = vals.back().to_display().value_or(css_display_value::DISPLAY_INLINE);
			break;
		}
		case css_property_type::PROPERTY_VISIBILITY: {
			visibility = vals.back().to_display().value_or(css_display_value::DISPLAY_INLINE);
			break;
		}
		case css_property_type::PROPERTY_FONT_SIZE: {
			auto fs = vals.back().to_dimension();
			if (fs) {
				block->set_font_size(fs.value().dim, fs.value().is_percent, how);
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
				block->set_fgcolor(color.value(), how);
			}
			break;
		}
		case css_property_type::PROPERTY_BGCOLOR: {
			auto color = vals.back().to_color();
			if (color) {
				block->set_bgcolor(color.value(), how);
			}
			break;
		}
		case css_property_type::PROPERTY_HEIGHT: {
			height = vals.back().to_dimension();
			break;
		}
		case css_property_type::PROPERTY_WIDTH: {
			width = vals.back().to_dimension();
			break;
		}
		case css_property_type::PROPERTY_MAX_HEIGHT: {
			max_height = vals.back().to_dimension();
			break;
		}
		case css_property_type::PROPERTY_MAX_WIDTH: {
			max_width = vals.back().to_dimension();
			break;
		}
		case css_property_type::PROPERTY_OVERFLOW: {
			auto disp = vals.back().to_display();
			if (disp) {
				block->set_overflow(disp.value() == css_display_value::DISPLAY_HIDDEN, how);
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
		case css_property_type::PROPERTY_FONT: {
			/* A color in the shorthand is taken only if there is no color property */
			if (!has_color) {
				for (const auto &val: vals) {
					auto maybe_color = val.to_color();

					if (maybe_color) {
						block->set_fgcolor(maybe_color.value(), how);
					}
				}
			}

			for (const auto &val: vals) {
				auto maybe_dim = val.to_dimension();

				if (maybe_dim) {
					/* The size is the first length of the shorthand */
					block->set_font_size(maybe_dim.value().dim, maybe_dim.value().is_percent, how);
					break;
				}
			}
			break;
		}
		case css_property_type::PROPERTY_BACKGROUND: {
			for (const auto &val: vals) {
				auto maybe_color = val.to_color();

				if (maybe_color) {
					block->set_bgcolor(maybe_color.value(), how);
				}
			}
			break;
		}
		default:
			/* Do nothing for now */
			break;
		}
	}

	/*
	 * Display and visibility are independent properties: a descendant cannot
	 * undo a hidden display, but it can reset an inherited visibility
	 */
	if (display) {
		block->set_display(*display, how);
	}

	if (visibility) {
		block->set_visibility(*visibility == css_display_value::DISPLAY_HIDDEN, how);
	}

	/*
	 * max-height/max-width clamp the corresponding dimension; mixed
	 * percent/absolute values cannot be compared, so prefer the zero
	 * limit in that case as it is the only value that matters for
	 * the visibility detection
	 */
	auto clamp_dim = [](std::optional<css_dimension> dim,
						std::optional<css_dimension> max_dim) -> std::optional<css_dimension> {
		if (dim && max_dim) {
			if (dim->is_percent == max_dim->is_percent) {
				return max_dim->dim < dim->dim ? max_dim : dim;
			}

			return max_dim->dim == 0 ? max_dim : dim;
		}

		return dim ? dim : max_dim;
	};

	if (auto h = clamp_dim(height, max_height); h) {
		block->set_height(h->dim, h->is_percent, how);
	}
	if (auto w = clamp_dim(width, max_width); w) {
		block->set_width(w->dim, w->is_percent, how);
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
		for (const auto *css_text: {"font-size:2ch", "font-size:2lh", "font-size:2q",
									"height:0nonsense", "width:0nonsense"}) {
			auto res = process_declaration_tokens(pool,
												  get_rules_parser_functor(pool, css_text));
			CHECK(res.get() != nullptr);
			auto *block = res->compile_to_block(pool);
			CHECK(block != nullptr);
			block->compute_visibility();
			CHECK_MESSAGE(block->is_visible(), css_text);
		}

		/* Viewport units are known and keep working */
		const std::vector<std::pair<const char *, int>> known{
			{"font-size:2vw", 16},
			{"font-size:2vh", 12},
			{"font-size:2vmin", 12},
			{"font-size:2vmax", 16},
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

	/* Compiles an inline style and tells if the block is hidden */
	static auto style_is_hidden(rspamd_mempool_t * pool, const std::string &style) -> bool
	{
		auto res = process_declaration_tokens(pool, get_rules_parser_functor(pool, style));
		auto *block = res->compile_to_block(pool);

		block->compute_visibility();

		return !block->is_visible();
	}

	static auto style_flag(rspamd_mempool_t * pool, const std::string &style,
						   css_property_type type) -> std::optional<css_property_flag>
	{
		auto res = process_declaration_tokens(pool, get_rules_parser_functor(pool, style));

		for (const auto &rule: res->get_rules()) {
			if (rule->get_prop().type == type) {
				return rule->get_prop().flag;
			}
		}

		return std::nullopt;
	}

	TEST_CASE("empty declarations are skipped")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		for (const auto *style: {";display:none", ";;display:none", "color:red;;display:none",
								 "color:red; ; ;display:none", "display:none;;", "display:;display:none",
								 "display;display:none", "color;;display:none", "; ;\n;display:none"}) {
			CHECK_MESSAGE(style_is_hidden(pool, style), std::string{style});
		}

		for (const auto *style: {";display:block", "color:red;;display:block", ";;", ";", "",
								 "display:block;;display:foo", "x;;display:block"}) {
			CHECK_MESSAGE(!style_is_hidden(pool, style), std::string{style});
		}

		/* The same inside of a rule body */
		auto sheet = parse_css(pool, ".h{;;display:none} .v{;;display:block}", nullptr);
		CHECK(sheet.has_value());

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("a declaration with an unusable value is dropped alone")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		for (const auto *style: {"x:[a];display:none", "y:(b);display:none", "z:{c};display:none",
								 "color:[a];display:none", "color:red [a];display:none",
								 "display:none;color:{c}", "color:{c};color:(d);display:none",
								 "x:[a;b];display:none", "x:{a;b};display:none",
								 "x:y(z);display:none", "x(y):z;display:none",
								 "[a]:b;display:none"}) {
			CHECK_MESSAGE(style_is_hidden(pool, style), std::string{style});
		}

		for (const auto *style: {"x:[a;display:none]", "x:{a;display:none}", "x:(a;display:none)",
								 "display:block;x:[a]", "color:{display:none}", "display:[a];display:block",
								 "display:block;display:[a]", "color:rgb(;display:none"}) {
			CHECK_MESSAGE(!style_is_hidden(pool, style), std::string{style});
		}

		/* A string with a raw newline makes only its own declaration invalid */
		CHECK(style_is_hidden(pool, "color:\"red\n;display:none"));
		CHECK(!style_is_hidden(pool, "color:\"red;display:none\""));
		CHECK(!style_is_hidden(pool, "color:'red;display:none'"));
		CHECK(style_is_hidden(pool, "color:\"a\\\"b\";display:none"));
		CHECK(!style_is_hidden(pool, "color:\"a\\\";display:none"));

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("a bad declaration with deep nesting does not drop the next ones")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);
		const auto deep = std::string(30, '[') + std::string(30, ']');

		CHECK(style_is_hidden(pool, "x:" + deep + ";display:none"));
		CHECK(style_is_hidden(pool, "color:red " + deep + ";display:none"));
		CHECK(style_is_hidden(pool, "display:none;x:" + deep));
		CHECK(!style_is_hidden(pool, "x:" + deep + std::string(2, ';') + "display:block"));
		/* The part of the declaration that was read does not apply */
		CHECK(!style_is_hidden(pool, "display:none " + deep + ";display:block"));
		CHECK(!style_is_hidden(pool, "display:none " + deep));

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("important flag reaches the stored rule")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		const std::vector<std::pair<const char *, css_property_flag>> cases{
			{"display:none !important", css_property_flag::FLAG_IMPORTANT},
			{"display:none!important", css_property_flag::FLAG_IMPORTANT},
			{"display:none ! important", css_property_flag::FLAG_IMPORTANT},
			{"display:none !IMPORTANT", css_property_flag::FLAG_IMPORTANT},
			{"display:none !Important;", css_property_flag::FLAG_IMPORTANT},
			{"display:none !/**/important", css_property_flag::FLAG_IMPORTANT},
			{"display:none;display:block !important", css_property_flag::FLAG_IMPORTANT},
			{"display:none", css_property_flag::FLAG_NORMAL},
			{"display:none important", css_property_flag::FLAG_NORMAL},
			{"display:none !importantx", css_property_flag::FLAG_NORMAL},
			{"display:none !imp", css_property_flag::FLAG_NORMAL},
			{"display:none !important;display:block", css_property_flag::FLAG_IMPORTANT},
			{"display:none;display:block", css_property_flag::FLAG_NORMAL},
		};

		for (const auto &c: cases) {
			auto flag = style_flag(pool, c.first, css_property_type::PROPERTY_DISPLAY);

			REQUIRE_MESSAGE(flag.has_value(), std::string{c.first});
			CHECK_MESSAGE(*flag == c.second, std::string{c.first});
		}

		/* The flag belongs to the declaration it follows */
		CHECK(*style_flag(pool, "color:red !important; display:none", css_property_type::PROPERTY_COLOR) ==
			  css_property_flag::FLAG_IMPORTANT);
		CHECK(*style_flag(pool, "color:red !important; display:none", css_property_type::PROPERTY_DISPLAY) ==
			  css_property_flag::FLAG_NORMAL);
		/* The color function and the flag */
		CHECK(*style_flag(pool, "color:rgb(1,2,3) !important", css_property_type::PROPERTY_COLOR) ==
			  css_property_flag::FLAG_IMPORTANT);

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("important wins within a block regardless of the order")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		const std::vector<std::pair<const char *, bool>> cases{
			{"display:none !important; display:block", true},
			{"display:block; display:none !important", true},
			{"display:none; display:block", false},
			{"display:block; display:none", true},
			{"display:none ! important; display:block", true},
			{"display:none !important; display:block !important", false},
			{"display:block !important; display:none !important", true},
			{"display:block !important; display:none", false},
			{"display:none; display:block !important", false},
			{"display:none; display:block !important; display:none", false},
			{"display:none !important; display:block; display:foo", true},
			/* An invalid later declaration does not override anything */
			{"display:none; display:foo", true},
			{"display:block; display:foo", false},
			{"display:block !important; display:none !important; display:block", true},
		};

		for (const auto &c: cases) {
			CHECK_MESSAGE(style_is_hidden(pool, c.first) == c.second, std::string{c.first});
		}

		rspamd_mempool_delete(pool);
	}

	TEST_CASE("shorthands and longhands apply in the source order")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);

		auto compile = [&](const std::string &style) {
			auto res = process_declaration_tokens(pool, get_rules_parser_functor(pool, style));

			return res->compile_to_block(pool);
		};

		const std::vector<std::pair<const char *, int>> sizes{
			{"font-size:12px; font:0 Arial", 0},
			{"font:0 Arial; font-size:12px", 12},
			{"font:12px Arial; font-size:0", 0},
			{"font-size:0; font:12px Arial", 12},
			{"font-size:12px !important; font:0 Arial", 12},
			{"font:0 Arial !important; font-size:12px", 0},
			{"font-size:12px; font:0 Arial; color:red", 0},
			{"font-size:0; color:red; font:10px Arial; font-size:14px", 14},
			{"font:10px Arial; font:0 Arial", 0},
		};

		for (const auto &c: sizes) {
			auto *block = compile(c.first);

			CHECK_MESSAGE(static_cast<int>(block->font_mask) != 0, std::string{c.first});
			CHECK_MESSAGE(block->font_size == c.second, std::string{c.first});
		}

		const std::vector<std::pair<const char *, int>> backgrounds{
			{"background:#ffffff; background-color:#000000", 0x00},
			{"background-color:#000000; background:#ffffff", 0xff},
			{"background-color:#000000 !important; background:#ffffff", 0x00},
			{"background:#ffffff !important; background-color:#000000", 0xff},
			{"background:#ffffff", 0xff},
		};

		for (const auto &c: backgrounds) {
			auto *block = compile(c.first);

			CHECK_MESSAGE(static_cast<int>(block->bg_color_mask) != 0, std::string{c.first});
			CHECK_MESSAGE(block->bg_color.r == c.second, std::string{c.first});
		}

		/* A color of the font shorthand is used only when there is no color property */
		CHECK(compile("font:12px red; color:#ffffff")->fg_color.g == 0xff);
		CHECK(compile("color:#ffffff; font:12px red")->fg_color.g == 0xff);

		/* Display and visibility are independent and both hide */
		for (const auto *style: {"display:none; visibility:visible", "visibility:hidden; display:block",
								 "display:block; visibility:hidden", "visibility:collapse; display:inline",
								 "display:none; display:block; visibility:hidden"}) {
			CHECK_MESSAGE(style_is_hidden(pool, style), std::string{style});
		}

		for (const auto *style: {"display:none; display:block", "visibility:hidden; visibility:visible",
								 "display:block; visibility:visible", "visibility:visible; display:block"}) {
			CHECK_MESSAGE(!style_is_hidden(pool, style), std::string{style});
		}

		/* Visibility is a property of its own, display is not touched by it */
		CHECK(compile("visibility:hidden")->visibility_hidden);
		CHECK(compile("visibility:collapse")->visibility_hidden);
		CHECK(!compile("visibility:visible")->visibility_hidden);
		CHECK(static_cast<int>(compile("visibility:hidden")->visibility_prop_mask) == rspamd::html::html_block::set);
		CHECK(static_cast<int>(compile("visibility:hidden")->display_mask) == rspamd::html::html_block::unset);
		CHECK(static_cast<int>(compile("visibility:hidden !important")->visibility_prop_mask) == rspamd::html::html_block::important);
		CHECK(static_cast<int>(compile("display:none")->visibility_prop_mask) == rspamd::html::html_block::unset);

		/* A child resets an inherited visibility */
		{
			auto *parent = compile("visibility:hidden; display:block");
			auto *child = compile("visibility:visible; display:block");
			auto *plain = compile("");
			child->propagate_block(*parent);
			plain->propagate_block(*parent);
			CHECK(!child->visibility_hidden);
			CHECK(plain->visibility_hidden);
			CHECK(static_cast<int>(plain->visibility_prop_mask) == rspamd::html::html_block::inherited);
		}

		/* An attribute hint is replaced by an author value and beats an inherited one */
		{
			auto *parent = compile("color:#333333");
			rspamd::html::html_block hinted{};
			hinted.set_fgcolor(css_color::white(), rspamd::html::html_block::hint);
			hinted.propagate_block(*parent);
			CHECK(hinted.fg_color.r == 0xff);
			CHECK(static_cast<int>(hinted.fg_color_mask) == rspamd::html::html_block::hint);
			hinted.set_block(*compile("color:#111111"));
			CHECK(hinted.fg_color.r == 0x11);
			CHECK(static_cast<int>(hinted.fg_color_mask) == rspamd::html::html_block::set);
		}

		rspamd_mempool_delete(pool);
	}
}

}// namespace rspamd::css