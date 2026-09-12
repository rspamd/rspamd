/*
 * Copyright 2025 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "css.hxx"
#include "contrib/ankerl/unordered_dense.h"
#include "css_parser.hxx"
#include "libserver/html/html_tag.hxx"
#include "libserver/html/html_block.hxx"

#include <algorithm>

/* Keep unit tests implementation here (it'll possibly be moved outside one day) */
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"

namespace rspamd::css {

INIT_LOG_MODULE_PUBLIC(css);

class css_style_sheet::impl {
public:
	struct selector_entry {
		std::unique_ptr<css_selector> selector;
		css_declarations_block_ptr decls;
		/* Source order: at equal specificity a later rule wins */
		unsigned order;
	};
	using selectors_bucket = std::vector<selector_entry>;
	/*
	 * Selectors are indexed by the most specific simple selector of their
	 * subject compound; the rest of the selector (other parts of the
	 * compound, ancestors and siblings) is evaluated against the tag tree
	 * on lookup
	 */
	using selectors_hash = ankerl::unordered_dense::map<css_simple_selector, selectors_bucket>;
	selectors_hash tags_selectors;
	selectors_hash class_selectors;
	selectors_hash id_selectors;
	selectors_bucket universal_selectors;
	unsigned next_order = 0;
	/* Scratch space for the lookup, kept to avoid an allocation per tag */
	std::vector<const selector_entry *> matched;
};

css_style_sheet::css_style_sheet(rspamd_mempool_t *pool)
	: pool(pool), pimpl(new impl)
{
}
css_style_sheet::~css_style_sheet()
{
}

auto css_style_sheet::add_selector_rule(std::unique_ptr<css_selector> &&selector,
										css_declarations_block_ptr decls) -> void
{
	const auto &key = selector->key();
	impl::selectors_bucket *bucket = nullptr;

	switch (key.type) {
	case css_simple_selector::selector_type::SELECTOR_ALL:
		bucket = &pimpl->universal_selectors;
		break;
	case css_simple_selector::selector_type::SELECTOR_CLASS:
		bucket = &pimpl->class_selectors[key];
		break;
	case css_simple_selector::selector_type::SELECTOR_ID:
		bucket = &pimpl->id_selectors[key];
		break;
	case css_simple_selector::selector_type::SELECTOR_TAG:
		bucket = &pimpl->tags_selectors[key];
		break;
	}

	for (auto &entry: *bucket) {
		if (*entry.selector == *selector) {
			/*
			 * The same selector again: merge the declarations, later ones
			 * override, and the rule moves to the end of the cascade
			 */
			msg_debug_css("found duplicate selector: %s, merging rules",
						  selector->debug_str().c_str());
			entry.decls->merge_block(*decls);
			entry.order = pimpl->next_order++;

			return;
		}
	}

	msg_debug_css("added selector: %s", selector->debug_str().c_str());
	bucket->push_back(impl::selector_entry{std::move(selector), std::move(decls),
										   pimpl->next_order++});
}

auto css_style_sheet::check_tag_block(const rspamd::html::html_tag *tag) -> rspamd::html::html_block *
{
	if (!tag) {
		return nullptr;
	}

	auto &matched = pimpl->matched;
	matched.clear();

	auto collect = [&](const impl::selectors_bucket &bucket) {
		for (const auto &entry: bucket) {
			if (entry.selector->matches(tag)) {
				matched.push_back(&entry);
			}
		}
	};
	auto collect_hash = [&](const impl::selectors_hash &hash, const css_simple_selector &key) {
		auto found = hash.find(key);

		if (found != hash.end()) {
			collect(found->second);
		}
	};

	/* ID part */
	if (!pimpl->id_selectors.empty()) {
		auto id_comp = tag->find_id();

		if (id_comp) {
			collect_hash(pimpl->id_selectors,
						 css_simple_selector{id_comp.value(),
											 css_simple_selector::selector_type::SELECTOR_ID});
		}
	}

	/* Class part */
	if (!pimpl->class_selectors.empty()) {
		auto class_comp = tag->find_class();

		if (class_comp) {
			auto strv = class_comp.value();
			std::size_t start = 0;

			while (start < strv.size()) {
				const auto last = strv.find_first_of(" \t\r\n", start);

				if (start != last) {
					collect_hash(pimpl->class_selectors,
								 css_simple_selector{strv.substr(start, last - start),
													 css_simple_selector::selector_type::SELECTOR_CLASS});
				}

				if (last == std::string_view::npos) {
					break;
				}

				start = last + 1;
			}
		}
	}

	/* Tags part */
	if (!pimpl->tags_selectors.empty()) {
		collect_hash(pimpl->tags_selectors,
					 css_simple_selector{static_cast<tag_id_t>(tag->id)});
	}

	/* Finally, universal selector */
	collect(pimpl->universal_selectors);

	if (matched.empty()) {
		return nullptr;
	}

	/*
	 * Cascade: the most specific selector wins, source order breaks ties.
	 * The winner is compiled first and the others only fill in what it
	 * leaves undefined
	 */
	std::stable_sort(matched.begin(), matched.end(),
					 [](const impl::selector_entry *a, const impl::selector_entry *b) {
						 auto sa = a->selector->specificity(), sb = b->selector->specificity();

						 if (sa != sb) {
							 return sa > sb;
						 }

						 return a->order > b->order;
					 });

	rspamd::html::html_block *res = nullptr;

	for (const auto *entry: matched) {
		auto *tmp = entry->decls->compile_to_block(pool);

		if (res == nullptr) {
			res = tmp;
		}
		else {
			res->propagate_block(*tmp);
		}
	}

	return res;
}

auto css_parse_style(rspamd_mempool_t *pool,
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

}// namespace rspamd::css
