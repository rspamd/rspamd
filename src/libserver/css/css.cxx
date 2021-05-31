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

#include "css.h"
#include "css.hxx"
#include "contrib/robin-hood/robin_hood.h"
#include "css_parser.hxx"
/* Keep unit tests implementation here (it'll possibly be moved outside one day) */
#define DOCTEST_CONFIG_IMPLEMENTATION_IN_DLL
#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"

static void
rspamd_css_dtor(void *p)
{
	rspamd::css::css_style_sheet *style =
			reinterpret_cast<rspamd::css::css_style_sheet *>(p);

	delete style;
}

rspamd_css_ptr
rspamd_css_parse_style(rspamd_mempool_t *pool, const gchar *begin, gsize len,
					   rspamd_css_ptr existing_style,
					   GError **err)
{
	auto parse_res = rspamd::css::parse_css(pool, {(const char* )begin, len},
			reinterpret_cast<rspamd::css::css_style_sheet*>(existing_style));

	if (parse_res.has_value()) {
		/*
		 * Detach style pointer from the unique_ptr as it will be managed by
		 * C memory pool
		 */
		auto *detached_style = reinterpret_cast<rspamd_css_ptr>(parse_res.value().release());

		/* We attach dtor merely if the existing style is not null */
		if (!existing_style) {
			rspamd_mempool_add_destructor(pool, rspamd_css_dtor, (void *) detached_style);
		}

		return detached_style;
	}
	else {
		g_set_error(err, g_quark_from_static_string("css"),
				static_cast<int>(parse_res.error().type),
				"parse error");
		return nullptr;
	}
}

namespace rspamd::css {

INIT_LOG_MODULE_PUBLIC(css);

class css_style_sheet::impl {
public:
	using selector_ptr = std::unique_ptr<css_selector>;
	using selectors_hash = robin_hood::unordered_flat_map<selector_ptr, css_declarations_block_ptr>;
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
	case css_selector::selector_type::SELECTOR_ELEMENT:
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

}