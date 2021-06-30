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

#include "css.hxx"
#include "contrib/robin-hood/robin_hood.h"
#include "css_parser.hxx"
#include "libserver/html/html_tag.hxx"
#include "libserver/html/html_block.hxx"

/* Keep unit tests implementation here (it'll possibly be moved outside one day) */
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"

namespace rspamd::css {

INIT_LOG_MODULE_PUBLIC(css);

class css_style_sheet::impl {
public:
	using sel_shared_hash = smart_ptr_hash<css_selector>;
	using sel_shared_eq = smart_ptr_equal<css_selector>;
	using selector_ptr = std::unique_ptr<css_selector>;
	using selectors_hash = robin_hood::unordered_flat_map<selector_ptr, css_declarations_block_ptr,
			sel_shared_hash, sel_shared_eq>;
	using universal_selector_t = std::pair<selector_ptr, css_declarations_block_ptr>;
	selectors_hash tags_selector;
	selectors_hash class_selectors;
	selectors_hash id_selectors;
	std::optional<universal_selector_t> universal_selector;
};

css_style_sheet::css_style_sheet(rspamd_mempool_t *pool)
		:  pool(pool), pimpl(new impl) {}
css_style_sheet::~css_style_sheet() {}

auto
css_style_sheet::add_selector_rule(std::unique_ptr<css_selector> &&selector,
									css_declarations_block_ptr decls) -> void
{
	impl::selectors_hash *target_hash = nullptr;

	switch(selector->type) {
	case css_selector::selector_type::SELECTOR_ALL:
		if (pimpl->universal_selector) {
			/* Another universal selector */
			msg_debug_css("redefined universal selector, merging rules");
			pimpl->universal_selector->second->merge_block(*decls);
		}
		else {
			msg_debug_css("added universal selector");
			pimpl->universal_selector = std::make_pair(std::move(selector),
					decls);
		}
		break;
	case css_selector::selector_type::SELECTOR_CLASS:
		target_hash = &pimpl->class_selectors;
		break;
	case css_selector::selector_type::SELECTOR_ID:
		target_hash = &pimpl->id_selectors;
		break;
	case css_selector::selector_type::SELECTOR_TAG:
		target_hash = &pimpl->tags_selector;
		break;
	}

	if (target_hash) {
		auto found_it = target_hash->find(selector);

		if (found_it == target_hash->end()) {
			/* Easy case, new element */
			target_hash->insert({std::move(selector), decls});
		}
		else {
			/* The problem with merging is actually in how to handle selectors chains
			 * For example, we have 2 selectors:
			 * 1. class id tag -> meaning that we first match class, then we ensure that
			 * id is also the same and finally we check the tag
			 * 2. tag class id -> it means that we check first tag, then class and then id
			 * So we have somehow equal path in the xpath terms.
			 * I suppose now, that we merely check parent stuff and handle duplicates
			 * merging when finally resolving paths.
			 */
			auto sel_str = selector->to_string().value_or("unknown");
			msg_debug_css("found duplicate selector: %*s", (int)sel_str.size(),
					sel_str.data());
			found_it->second->merge_block(*decls);
		}
	}
}

auto
css_style_sheet::check_tag_block(const rspamd::html::html_tag *tag) ->
		rspamd::html::html_block *
{
	std::optional<std::string_view> id_comp, class_comp;
	rspamd::html::html_block *res = nullptr;

	if (!tag) {
		return nullptr;
	}

	/* First, find id in a tag and a class */
	for (const auto &param : tag->components) {
		if (param.type == html::html_component_type::RSPAMD_HTML_COMPONENT_ID) {
			id_comp = param.value;
		}
		else if (param.type == html::html_component_type::RSPAMD_HTML_COMPONENT_CLASS) {
			class_comp = param.value;
		}
	}

	/* ID part */
	if (id_comp && !pimpl->id_selectors.empty()) {
		auto found_id_sel = pimpl->id_selectors.find(css_selector{id_comp.value()});

		if (found_id_sel != pimpl->id_selectors.end()) {
			const auto &decl = *(found_id_sel->second);
			res = decl.compile_to_block(pool);
		}
	}

	/* Class part */
	if (class_comp && !pimpl->class_selectors.empty()) {
		auto sv_split = [](auto strv, std::string_view delims = " ") -> std::vector<std::string_view> {
			std::vector<decltype(strv)> ret;
			std::size_t start = 0;

			while (start < strv.size()) {
				const auto last = strv.find_first_of(delims, start);
				if (start != last) {
					ret.emplace_back(strv.substr(start, last - start));
				}

				if (last == std::string_view::npos) {
					break;
				}

				start = last + 1;
			}

			return ret;
		};

		auto elts = sv_split(class_comp.value());

		for (const auto &e : elts) {
			auto found_class_sel = pimpl->class_selectors.find(
					css_selector{e, css_selector::selector_type::SELECTOR_CLASS});

			if (found_class_sel != pimpl->class_selectors.end()) {
				const auto &decl = *(found_class_sel->second);
				auto *tmp = decl.compile_to_block(pool);

				if (res == nullptr) {
					res = tmp;
				}
				else {
					res->propagate_block(*tmp);
				}
			}
		}
	}

	/* Tags part */
	if (!pimpl->tags_selector.empty()) {
		auto found_tag_sel = pimpl->tags_selector.find(
				css_selector{static_cast<tag_id_t>(tag->id)});

		if (found_tag_sel != pimpl->tags_selector.end()) {
			const auto &decl = *(found_tag_sel->second);
			auto *tmp = decl.compile_to_block(pool);

			if (res == nullptr) {
				res = tmp;
			}
			else {
				res->propagate_block(*tmp);
			}
		}
	}

	/* Finally, universal selector */
	if (pimpl->universal_selector) {
		auto *tmp = pimpl->universal_selector->second->compile_to_block(pool);

		if (res == nullptr) {
			res = tmp;
		}
		else {
			res->propagate_block(*tmp);
		}
	}

	return res;
}

auto
css_parse_style(rspamd_mempool_t *pool,
					 std::string_view input,
					 std::shared_ptr<css_style_sheet> &&existing)
					 -> css_return_pair
{
	auto parse_res = rspamd::css::parse_css(pool, input,
			std::forward<std::shared_ptr<css_style_sheet>>(existing));

	if (parse_res.has_value()) {
		return std::make_pair(parse_res.value(), css_parse_error());
	}

	return std::make_pair(nullptr, parse_res.error());
}

}