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

#ifndef RSPAMD_CSS_RULE_HXX
#define RSPAMD_CSS_RULE_HXX

#include "css_value.hxx"
#include "css_property.hxx"
#include "css_parser.hxx"
#include "contrib/robin-hood/robin_hood.h"
#include <vector>
#include <memory>

namespace rspamd::css {

class css_rule {
	css_property prop;
	using css_values_vec = std::vector<css_value>;
	css_values_vec values;

public:
	/* We must create css rule explicitly from a property and values */
	css_rule() = delete;

	css_rule(const css_rule &other) = delete;

	/* Constructors */
	css_rule(css_rule &&other) noexcept = default;

	explicit css_rule(css_property &&prop, css_values_vec &&values) noexcept :
			prop(prop), values(std::forward<css_values_vec>(values)) {}

	explicit css_rule(const css_property &prop) noexcept : prop(prop), values{} {}

	/* Methods */
	/* Comparison is special, as we care merely about property, not the values */
	auto operator==(const css_rule &other) const { return prop == other.prop; }

	constexpr const css_values_vec &get_values(void) const { return values; }
	constexpr const css_property &get_prop(void) const { return prop; }

	/* Import values from another rules according to the importance */
	void override_values(const css_rule &other);
	void merge_values(const css_rule &other);
	void add_value(const css_value &value);
};

}

/* Make rules hashable by property */
namespace std {
template<>
class hash<rspamd::css::css_rule> {
public:
	constexpr auto operator()(const rspamd::css::css_rule &rule) const -> auto {
		return hash<rspamd::css::css_property>()(rule.get_prop());
	}
};

}

namespace rspamd::css {

/*
 * We have to define transparent hash and compare methods
 *
 * TODO: move to some utility library
 */
template<typename T>
struct shared_ptr_equal {
	using is_transparent = void; /* We want to find values in a set of shared_ptr by reference */
	auto operator()(const std::shared_ptr<T> &a, const std::shared_ptr<T> &b) const {
		return (*a) == (*b);
	}
	auto operator()(const std::shared_ptr<T> &a, const T &b) const {
		return (*a) == b;
	}
	auto operator()(const T &a, const std::shared_ptr<T> &b) const {
		return a == (*b);
	}
};

template<typename T>
struct shared_ptr_hash {
	using is_transparent = void; /* We want to find values in a set of shared_ptr by reference */
	auto operator()(const std::shared_ptr<T> &a) const {
		return std::hash<T>()(*a);
	}
	auto operator()(const T &a) const {
		return std::hash<T>()(a);
	}
};

class css_declarations_block {
public:
	using rule_shared_ptr = std::shared_ptr<css_rule>;
	using rule_shared_hash = shared_ptr_hash<css_rule>;
	using rule_shared_eq = shared_ptr_equal<css_rule>;
	css_declarations_block() = default;
	auto add_rule(rule_shared_ptr &&rule) -> bool;
	auto get_rules(void) const -> const auto & {
		return rules;
	}

	auto has_rule(const css_rule &rule) const -> bool {
		return (rules.find(rule) != rules.end());
	}
private:
	robin_hood::unordered_flat_set<rule_shared_ptr, rule_shared_hash, rule_shared_eq> rules;
};

auto process_declaration_tokens(rspamd_mempool_t *pool,
							 const blocks_gen_functor &next_token_functor)
	-> css_declarations_block;

}

#endif //RSPAMD_CSS_RULE_HXX