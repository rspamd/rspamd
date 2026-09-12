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
		unsigned specificity;
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
	ankerl::unordered_dense::set<const selectors_bucket *> visited_classes;
	css_match_budget match_budget;

	/*
	 * Bound index storage and per-element cascade scratch space. The
	 * shared work budget separately bounds matching across all elements.
	 */
	static constexpr unsigned max_selectors = 4096;
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
	if (pimpl->next_order >= impl::max_selectors) {
		return;
	}

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

	/*
	 * A repeated selector is not merged with the earlier one: it is a new
	 * rule in the cascade, so only its own declarations move forward.
	 * Merging would also drag the earlier declarations past rules that
	 * were written in between
	 */
	msg_debug_css("added selector: %s", selector->debug_str().c_str());
	auto specificity = selector->specificity();
	bucket->push_back(impl::selector_entry{std::move(selector), std::move(decls),
										   pimpl->next_order++, specificity});
}

auto css_style_sheet::check_tag_block(const rspamd::html::html_tag *tag) -> rspamd::html::html_block *
{
	auto &budget = pimpl->match_budget;
	if (!tag || !budget.consume(1 + tag->components.size())) {
		return nullptr;
	}

	auto &matched = pimpl->matched;
	matched.clear();
	pimpl->visited_classes.clear();

	auto collect = [&](const impl::selectors_bucket &bucket) {
		for (const auto &entry: bucket) {
			if (!budget.consume()) {
				return;
			}
			if (entry.selector->matches(tag, budget)) {
				matched.push_back(&entry);
			}
		}
	};
	auto collect_hash = [&](const impl::selectors_hash &hash, const css_simple_selector &key,
							bool is_class = false) {
		auto found = hash.find(key);

		if (found != hash.end()) {
			if (is_class && !pimpl->visited_classes.insert(&found->second).second) {
				return;
			}
			collect(found->second);
		}
	};

	/* ID part */
	if (!pimpl->id_selectors.empty()) {
		auto id_comp = tag->find_id();

		if (id_comp) {
			if (!budget.consume(id_comp->size())) {
				return nullptr;
			}
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
			if (!budget.consume(strv.size())) {
				return nullptr;
			}
			std::size_t start = 0;

			while (start < strv.size()) {
				if (!budget.consume()) {
					return nullptr;
				}
				const auto last = strv.find_first_of(" \t\r\n", start);

				if (start != last) {
					collect_hash(pimpl->class_selectors,
								 css_simple_selector{strv.substr(start, last - start),
													 css_simple_selector::selector_type::SELECTOR_CLASS},
								 true);
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

	/* Do not apply a partial cascade when the document budget runs out. */
	if (budget.remaining == 0 || matched.empty()) {
		return nullptr;
	}

	/*
	 * Cascade: the most specific selector wins, source order breaks ties.
	 * The winner is compiled into the block returned to the caller; the
	 * others are compiled into a temporary and only fill in what the
	 * block leaves undefined, so a tag costs one pool allocation however
	 * many rules match it
	 */
	std::stable_sort(matched.begin(), matched.end(),
					 [](const impl::selector_entry *a, const impl::selector_entry *b) {
						 auto sa = a->specificity, sb = b->specificity;

						 if (sa != sb) {
							 return sa > sb;
						 }

						 return a->order > b->order;
					 });

	auto *res = matched.front()->decls->compile_to_block(pool);

	for (auto it = matched.begin() + 1; it != matched.end(); ++it) {
		rspamd::html::html_block tmp{};

		(*it)->decls->compile_into(tmp);
		res->set_block(tmp);
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

TEST_SUITE("css")
{
	TEST_CASE("budget exhaustion discards an incomplete cascade")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);
		{
			std::string css = ".x { font-size: 0 } ";
			for (auto i = 0; i < css_compound_selector::max_parts; i++) {
				css += ".x";
			}
			css += " { font-size: 14px }";
			auto parsed = css_parse_style(pool, css, nullptr);
			REQUIRE(parsed.first != nullptr);
			html::html_tag tag;
			tag.id = Tag_SPAN;
			std::string classes(65536, 'q');
			classes += " x";
			tag.components.emplace_back(html::html_component_class{classes});
			/* The first rule matches, but the overriding compound runs out. */
			CHECK(parsed.first->check_tag_block(&tag) == nullptr);
			auto control = css_parse_style(pool, ".x { font-size: 0 }", nullptr);
			REQUIRE(control.first != nullptr);
			CHECK(control.first->check_tag_block(&tag) != nullptr);
		}
		rspamd_mempool_delete(pool);
	}

	TEST_CASE("stylesheet matching budget persists across elements and style blocks")
	{
		auto *pool = rspamd_mempool_new(rspamd_mempool_suggest_size(), "css", 0);
		{
			auto parsed = css_parse_style(pool, ".x { color: red }", nullptr);
			REQUIRE(parsed.first != nullptr);
			html::html_tag tag;
			tag.id = Tag_SPAN;
			std::string classes(65536, ' ');
			classes += "x";
			tag.components.emplace_back(html::html_component_class{classes});
			CHECK(parsed.first->check_tag_block(&tag) != nullptr);
			/* Each lookup scans the attribute both for indexing and matching. */
			for (auto i = 0; i < css_match_budget::max_work / classes.size() + 1; i++) {
				parsed.first->check_tag_block(&tag);
			}
			tag.components.clear();
			tag.components.emplace_back(html::html_component_class{"x"});
			CHECK(parsed.first->check_tag_block(&tag) == nullptr);
			parsed = css_parse_style(pool, "span { color: blue }", std::move(parsed.first));
			REQUIRE(parsed.first != nullptr);
			CHECK(parsed.first->check_tag_block(&tag) == nullptr);
			auto fresh = css_parse_style(pool, ".x { color: red }", nullptr);
			REQUIRE(fresh.first != nullptr);
			CHECK(fresh.first->check_tag_block(&tag) != nullptr);
		}
		rspamd_mempool_delete(pool);
	}
}

}// namespace rspamd::css
