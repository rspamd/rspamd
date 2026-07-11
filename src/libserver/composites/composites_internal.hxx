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

#include <memory>
#include <string>
#include <vector>
#include "contrib/ankerl/unordered_dense.h"
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
	bool disabled;           /**< true if composite is a placeholder stub (evaluates to false) */

	/* Per-symbol Lua conditions (registry refs owned by the config UCL tree),
	 * keyed by symbol name as written in the expression (no prefixes/brackets).
	 * A condition is ANDed with option filters of the matching atom. */
	ankerl::unordered_dense::map<std::string, int,
								 rspamd::smart_str_hash, rspamd::smart_str_equal>
		conditions;
	/* Symbols consulted by conditions beyond the expression atoms; feed
	 * first/second pass placement in process_dependencies() */
	std::vector<std::string> depends_on;

	auto find_condition(std::string_view sym_name) const -> int
	{
		if (conditions.empty()) {
			return -1;
		}

		auto it = conditions.find(sym_name);

		return it != conditions.end() ? it->second : -1;
	}
};

/**
 * A composites generation: an immutable-once-published snapshot of all
 * composites and their precomputed evaluation indices.
 *
 * The manager holds one current generation. On dynamic map reloads a new
 * generation is built off-line and atomically swapped in; in-flight tasks
 * keep using their snapshot (held via shared_ptr in composites_data).
 */
struct composites_generation {
	ankerl::unordered_dense::map<std::string,
								 std::shared_ptr<rspamd_composite>,
								 rspamd::smart_str_hash, rspamd::smart_str_equal>
		composites;
	/* Ownership of every composite belongs here (including duplicates) */
	std::vector<std::shared_ptr<rspamd_composite>> all_composites;

	/* Two-phase evaluation buckets */
	std::vector<rspamd_composite *> first_pass_composites;
	std::vector<rspamd_composite *> second_pass_composites;

	/* Inverted index: symbol -> composites that contain this symbol as positive atom */
	ankerl::unordered_dense::map<std::string, std::vector<rspamd_composite *>,
								 rspamd::smart_str_hash, rspamd::smart_str_equal>
		symbol_to_composites;
	/* Composites that have only negated atoms or group matchers (must always be checked) */
	std::vector<rspamd_composite *> not_only_composites;

	uint64_t generation_id = 0;

	auto find(std::string_view name) const -> const rspamd_composite *
	{
		auto found = composites.find(std::string(name));
		return found != composites.end() ? found->second.get() : nullptr;
	}
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
		: cfg(_cfg),
		  current_gen(std::make_shared<composites_generation>()),
		  use_inverted_index(true)
	{
		rspamd_mempool_add_destructor(_cfg->cfg_pool, composites_manager_dtor, this);
	}

	auto size(void) const -> std::size_t
	{
		return current_gen->all_composites.size();
	}

	auto find(std::string_view name) const -> const rspamd_composite *
	{
		return current_gen->find(name);
	}

	/**
	 * Snapshot the current generation. Callers (tasks) keep this shared_ptr
	 * alive for the duration of evaluation so a concurrent reload cannot
	 * pull the rug out from under them.
	 */
	auto snapshot_generation() const -> std::shared_ptr<composites_generation>
	{
		return current_gen;
	}

	auto add_composite(std::string_view, const ucl_object_t *, bool silent_duplicate) -> rspamd_composite *;
	auto add_composite(std::string_view name, std::string_view expression, bool silent_duplicate, double score = NAN) -> rspamd_composite *;

	/* Allocate a fresh monotonic composite id (stable across generations) */
	auto next_id() -> int
	{
		return next_composite_id++;
	}

	auto get_cfg() const -> struct rspamd_config *
	{
		return cfg;
	}

	auto current() const -> composites_generation *
	{
		return current_gen.get();
	}

	/**
	 * Snapshot current_gen as base_gen — every future staging generation
	 * starts from a clone of base_gen. Called once after static config has
	 * been loaded and the first round of process_dependencies /
	 * build_inverted_index / mark_whitelist_dependencies has completed.
	 */
	auto pin_base_generation() -> void
	{
		base_gen = current_gen;
	}

	auto get_base_generation() const -> std::shared_ptr<composites_generation>
	{
		return base_gen;
	}

	/**
	 * Build a fresh staging generation off the pinned base. Composites from
	 * base_gen are cloned (new shared_ptr, fresh id, flags reset) so the
	 * staging can run process_dependencies / build_inverted_index without
	 * mutating composites that in-flight tasks may still be observing.
	 *
	 * Callers (the dynamic-map fin callback) layer the map's composites on
	 * top, then call publish_generation().
	 */
	auto build_staging() -> std::shared_ptr<composites_generation>;

	/**
	 * Apply a single UCL composite definition to a staging generation.
	 * Parses the expression, creates a fresh composite struct, replaces any
	 * existing entry under this name, and updates cfg->symbols so scoring
	 * and FINE-flag propagation see the dynamic composite. Returns the new
	 * composite or nullptr on parse/validation failure.
	 */
	auto add_composite_to_staging(composites_generation &staging,
								  std::string_view name,
								  const ucl_object_t *obj) -> rspamd_composite *;

	/**
	 * Replace the composite under `name` in `staging` with a disabled stub
	 * (or insert one if the name was unknown). Returns true if a stub was
	 * (re)created.
	 */
	auto disable_in_staging(composites_generation &staging,
							const std::string &name) -> bool;

	/**
	 * Publish a staging generation as current:
	 *  - register new composite names with the symcache + cfg->symbols
	 *  - update ever_seen_names
	 *  - bump the resort generation on the symcache
	 *  - run process_dependencies / build_inverted_index / mark_whitelist
	 *  - atomically swap current_gen
	 *
	 * Single-threaded libev makes the swap a plain assignment; in-flight
	 * tasks keep their snapshot alive via shared_ptr.
	 */
	auto publish_generation(std::shared_ptr<composites_generation> staging) -> void;

	/**
	 * Capture current_gen as the static-config base. Subsequent
	 * build_staging() calls clone from this snapshot. Populates
	 * ever_seen_names from the static composites so they aren't
	 * re-registered with the symcache on first dynamic publish. Idempotent
	 * — calling more than once is a no-op.
	 */
	auto seal_static_load() -> void;

	/**
	 * Returns the set of composite names this manager has ever published.
	 * Map handlers consult this to materialise disabled stubs for names
	 * that previously existed and have now been removed.
	 */
	auto ever_seen() const -> const ankerl::unordered_dense::set<std::string> &
	{
		return ever_seen_names;
	}

	auto allocate_generation_id() -> uint64_t
	{
		return ++next_gen_id;
	}

private:
	~composites_manager() = default;
	static void composites_manager_dtor(void *ptr)
	{
		delete COMPOSITE_MANAGER_FROM_PTR(ptr);
	}

	auto new_composite(std::string_view composite_name, rspamd_expression *expr,
					   std::string_view composite_expression) -> auto
	{
		auto &gen = *current_gen;
		auto &composite = gen.all_composites.emplace_back(std::make_shared<rspamd_composite>());
		composite->expr = expr;
		composite->id = next_id();
		composite->str_expr = composite_expression;
		composite->sym = composite_name;
		composite->second_pass = false; /* Initially all composites are first pass */
		composite->disabled = false;

		gen.composites[composite->sym] = composite;

		return composite;
	}

	struct rspamd_config *cfg;
	int next_composite_id = 0;
	uint64_t next_gen_id = 0;

	/* The live generation. Replaced on dynamic-map reload via publish_generation(). */
	std::shared_ptr<composites_generation> current_gen;

	/* Snapshot of the static-config generation, taken after config-load.
	 * Every staging generation is cloned from this. */
	std::shared_ptr<composites_generation> base_gen;

	/* Names this manager has ever published (static or dynamic). Monotonic.
	 * Used to (a) gate one-time symcache + cfg->symbols registration and
	 * (b) help map handlers materialise disabled stubs for vanished names. */
	ankerl::unordered_dense::set<std::string> ever_seen_names;

	/* The composite shared_ptr each name was first registered with in the
	 * symcache. The symcache stores raw cbdata; pinning the shared_ptr here
	 * guarantees it never dangles even when later generations replace the
	 * composite under the same name. Static composites are already pinned
	 * via base_gen → all_composites so this map only fills in for
	 * dynamic-only names. */
	ankerl::unordered_dense::map<std::string, std::shared_ptr<rspamd_composite>>
		symcache_pinned;

public:
	/* Configuration flags */
	bool use_inverted_index; /**< Use inverted index for fast composite lookup (default: true) */

	/* Statistics (updated probabilistically for performance) */
	composites_stats stats{};

	/* Analyze composite dependencies and split a generation into first/second
	 * pass vectors. The no-arg form operates on current_gen for compatibility
	 * with config-load wiring. */
	void process_dependencies(composites_generation &gen);
	void process_dependencies()
	{
		process_dependencies(*current_gen);
	}

	/* Build inverted index for fast composite lookup in the given generation. */
	void build_inverted_index(composites_generation &gen);
	void build_inverted_index()
	{
		build_inverted_index(*current_gen);
	}

	/* Mark symbols used in whitelist composites (negative score) as FINE.
	 * Always operates against the manager's cfg symcache; the generation
	 * argument selects which whitelist composites contribute to the
	 * FINE-symbol set. */
	void mark_whitelist_dependencies(composites_generation &gen);
	void mark_whitelist_dependencies()
	{
		mark_whitelist_dependencies(*current_gen);
	}
};

}// namespace rspamd::composites

#endif//RSPAMD_COMPOSITES_INTERNAL_HXX
