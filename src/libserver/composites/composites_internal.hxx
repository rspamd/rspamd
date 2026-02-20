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

#ifndef RSPAMD_COMPOSITES_INTERNAL_HXX
#define RSPAMD_COMPOSITES_INTERNAL_HXX
#pragma once

#include <string>
#include "libutil/expression.h"
#include "libutil/util.h"
#include "libutil/cxx/hash_util.hxx"
#include "libserver/cfg_file.h"

namespace rspamd::composites {

/**
 * Subr for composite expressions
 */
extern const struct rspamd_atom_subr composite_expr_subr;

enum class rspamd_composite_policy {
	RSPAMD_COMPOSITE_POLICY_REMOVE_ALL = 0,
	RSPAMD_COMPOSITE_POLICY_REMOVE_SYMBOL,
	RSPAMD_COMPOSITE_POLICY_REMOVE_WEIGHT,
	RSPAMD_COMPOSITE_POLICY_LEAVE,
	RSPAMD_COMPOSITE_POLICY_UNKNOWN
};

/**
 * Static composites structure
 */
struct rspamd_composite {
	std::string str_expr;
	std::string sym;
	struct rspamd_expression *expr;
	int id;
	rspamd_composite_policy policy;
	bool second_pass;        /**< true if this composite needs second pass evaluation */
	bool has_positive_atoms; /**< true if composite has at least one non-negated atom */
};

#define COMPOSITE_MANAGER_FROM_PTR(ptr) (reinterpret_cast<rspamd::composites::composites_manager *>(ptr))

/**
 * Statistics for composite processing
 */
struct composites_stats {
	uint64_t checked_slow = 0;              /**< composites checked via slow path */
	uint64_t checked_fast = 0;              /**< composites checked via inverted index */
	uint64_t matched = 0;                   /**< composites that matched */
	struct rspamd_counter_data time_slow{}; /**< EMA timing for slow path */
	struct rspamd_counter_data time_fast{}; /**< EMA timing for fast path */
};

class composites_manager {
public:
	composites_manager(struct rspamd_config *_cfg)
		: cfg(_cfg), use_inverted_index(true)
	{
		rspamd_mempool_add_destructor(_cfg->cfg_pool, composites_manager_dtor, this);
	}

	auto size(void) const -> std::size_t
	{
		return all_composites.size();
	}

	auto find(std::string_view name) const -> const rspamd_composite *
	{
		auto found = composites.find(std::string(name));

		if (found != composites.end()) {
			return found->second.get();
		}

		return nullptr;
	}

	auto add_composite(std::string_view, const ucl_object_t *, bool silent_duplicate) -> rspamd_composite *;
	auto add_composite(std::string_view name, std::string_view expression, bool silent_duplicate, double score = NAN) -> rspamd_composite *;

private:
	~composites_manager() = default;
	static void composites_manager_dtor(void *ptr)
	{
		delete COMPOSITE_MANAGER_FROM_PTR(ptr);
	}

	auto new_composite(std::string_view composite_name, rspamd_expression *expr,
					   std::string_view composite_expression) -> auto
	{
		auto &composite = all_composites.emplace_back(std::make_shared<rspamd_composite>());
		composite->expr = expr;
		composite->id = all_composites.size() - 1;
		composite->str_expr = composite_expression;
		composite->sym = composite_name;
		composite->second_pass = false; /* Initially all composites are first pass */

		composites[composite->sym] = composite;

		return composite;
	}

	ankerl::unordered_dense::map<std::string,
								 std::shared_ptr<rspamd_composite>, rspamd::smart_str_hash, rspamd::smart_str_equal>
		composites;
	/* Store all composites here, even if we have duplicates */
	std::vector<std::shared_ptr<rspamd_composite>> all_composites;

	struct rspamd_config *cfg;

public:
	/* Two-phase evaluation: composites are split into first and second pass */
	std::vector<rspamd_composite *> first_pass_composites;  /* Evaluated during COMPOSITES stage */
	std::vector<rspamd_composite *> second_pass_composites; /* Evaluated during COMPOSITES_POST stage */

	/* Inverted index: symbol -> composites that contain this symbol as positive atom */
	ankerl::unordered_dense::map<std::string, std::vector<rspamd_composite *>,
								 rspamd::smart_str_hash, rspamd::smart_str_equal>
		symbol_to_composites;
	/* Composites that have only negated atoms (must always be checked) */
	std::vector<rspamd_composite *> not_only_composites;

	/* Configuration flags */
	bool use_inverted_index; /**< Use inverted index for fast composite lookup (default: true) */

	/* Statistics (updated probabilistically for performance) */
	composites_stats stats{};

	/* Analyze composite dependencies and split into first/second pass vectors */
	void process_dependencies();
	/* Build inverted index for fast composite lookup */
	void build_inverted_index();
	/* Mark symbols used in whitelist composites (negative score) as FINE */
	void mark_whitelist_dependencies();
};

/**
 * Precompute atom types (ATOM_COMPOSITE vs ATOM_PLAIN) for all composites.
 * This eliminates lazy lookups during expression evaluation.
 * Should be called after all composites are registered.
 */
void rspamd_composites_resolve_atom_types(composites_manager *cm);

}// namespace rspamd::composites

#endif//RSPAMD_COMPOSITES_INTERNAL_HXX
