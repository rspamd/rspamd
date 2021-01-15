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

#ifndef RSPAMD_CSS_RULE_HXX
#define RSPAMD_CSS_RULE_HXX

#include "css_value.hxx"
#include "css_property.hxx"
#include <vector>
#include <memory>

namespace rspamd {

namespace css {

class css_rule {
	css_property prop;
	using css_values_vec = std::vector<std::unique_ptr<css_value> >;
	css_values_vec values;
public:
	/* We must create css rule explicitly from a property and values */
	css_rule() = delete;
	css_rule(const css_rule &other) = delete;
	/* Constructors */
	css_rule(css_rule &&other) = default;
	explicit css_rule(css_property &&prop, css_values_vec &&values) :
		prop(prop), values(values) {}
	explicit css_rule(css_property &&prop) : prop(prop), values{} {}
	/* Methods */
	void add_value(std::unique_ptr<css_value> &&value) {
		values.emplace_back(std::forward<std::unique_ptr<css_value>>(value));
	}
	void add_value(const css_value &value) {
		values.emplace_back(std::make_unique<css_value>(css_value{value}));
	}
	const css_values_vec& get_values(void) { return values; }
	const css_property& get_prop(void) { return prop; }
};

}

}

#endif //RSPAMD_CSS_RULE_HXX
