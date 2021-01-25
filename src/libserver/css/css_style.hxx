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

#pragma once

#ifndef RSPAMD_CSS_STYLE_HXX
#define RSPAMD_CSS_STYLE_HXX

#include <memory>
#include <vector>
#include "css_rule.hxx"
#include "css_selector.hxx"

namespace rspamd::css {

/*
 * Full CSS style representation
 */
class css_style {
public:
	/* Make class trivial */
	css_style (const css_style &other) = default;

	css_style (const std::shared_ptr<css_style> &_parent) : parent(_parent) {
		propagate_from_parent ();
	}
	css_style (const std::shared_ptr<css_style> &_parent,
		   const std::vector<std::shared_ptr<css_selector> > &_selectors) : parent(_parent) {
		selectors.reserve (_selectors.size ());

		for (const auto &sel_ptr : _selectors) {
			selectors.emplace_back (sel_ptr);
		}

		propagate_from_parent ();
	}
private:
	std::vector<std::weak_ptr<css_selector> > selectors;
	std::weak_ptr<css_style> parent;
	std::vector<css_rule> rules;
private:
	void propagate_from_parent(void); /* Construct full style using parent */
};

}

#endif //RSPAMD_CSS_STYLE_HXX
