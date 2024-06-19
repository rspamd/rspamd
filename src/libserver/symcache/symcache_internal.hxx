/*
 * Copyright 2024 Vsevolod Stakhov
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

/**
 * Internal C++ structures and classes for symcache
 */

#ifndef RSPAMD_SYMCACHE_INTERNAL_HXX
#define RSPAMD_SYMCACHE_INTERNAL_HXX
#pragma once

#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <utility>
#include <vector>
#include <string>
#include <string_view>
#include <memory>
#include <variant>

#include "rspamd_symcache.h"
#include "contrib/libev/ev.h"
#include "contrib/ankerl/unordered_dense.h"
#include "contrib/expected/expected.hpp"
#include "cfg_file.h"

#include "symcache_id_list.hxx"

#define msg_err_cache(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,  \
													   "symcache", log_tag(), \
													   RSPAMD_LOG_FUNC,       \
													   __VA_ARGS__)
#define msg_err_cache_lambda(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,  \
															  "symcache", log_tag(), \
															  log_func,              \
															  __VA_ARGS__)
#define msg_err_cache_task(...) rspamd_default_log_function(G_LOG_LEVEL_CRITICAL,                 \
															"symcache", task->task_pool->tag.uid, \
															RSPAMD_LOG_FUNC,                      \
															__VA_ARGS__)
#define msg_warn_cache(...) rspamd_default_log_function(G_LOG_LEVEL_WARNING,   \
														"symcache", log_tag(), \
														RSPAMD_LOG_FUNC,       \
														__VA_ARGS__)
#define msg_info_cache(...) rspamd_default_log_function(G_LOG_LEVEL_INFO,      \
														"symcache", log_tag(), \
														RSPAMD_LOG_FUNC,       \
														__VA_ARGS__)
#define msg_debug_cache(...) rspamd_conditional_debug_fast(NULL, NULL,                                                        \
														   ::rspamd::symcache::rspamd_symcache_log_id, "symcache", log_tag(), \
														   RSPAMD_LOG_FUNC,                                                   \
														   __VA_ARGS__)
#define msg_debug_cache_lambda(...) rspamd_conditional_debug_fast(NULL, NULL,                                                        \
																  ::rspamd::symcache::rspamd_symcache_log_id, "symcache", log_tag(), \
																  log_func,                                                          \
																  __VA_ARGS__)
#define msg_debug_cache_task(...) rspamd_conditional_debug_fast(NULL, NULL,                                                                       \
																::rspamd::symcache::rspamd_symcache_log_id, "symcache", task->task_pool->tag.uid, \
																RSPAMD_LOG_FUNC,                                                                  \
																__VA_ARGS__)
#define msg_debug_cache_task_lambda(...) rspamd_conditional_debug_fast(NULL, NULL,                                                                       \
																	   ::rspamd::symcache::rspamd_symcache_log_id, "symcache", task->task_pool->tag.uid, \
																	   log_func,                                                                         \
																	   __VA_ARGS__)

struct lua_State;

namespace rspamd::symcache {

/* Defined in symcache_impl.cxx */
extern int rspamd_symcache_log_id;

static const std::uint8_t symcache_magic[8] = {'r', 's', 'c', 2, 0, 0, 0, 0};

struct symcache_header {
	std::uint8_t magic[8];
	unsigned int nitems;
	std::uint8_t checksum[64];
	std::uint8_t unused[128];
};

struct cache_item;
using cache_item_ptr = std::shared_ptr<cache_item>;

/**
 * This structure is intended to keep the current ordering for all symbols
 * It is designed to be shared among all tasks and keep references to the real
 * symbols.
 * If some symbol has been added or removed to the symbol cache, it will not affect
 * the current order, and it will only be regenerated for the subsequent tasks.
 * This allows safe and no copy sharing and keeping track of all symbols in the
 * cache runtime.
 */
struct order_generation {
	/* All items ordered */
	std::vector<cache_item_ptr> d;
	/* Mapping from symbol name to the position in the order array */
	ankerl::unordered_dense::map<std::string_view, unsigned int> by_symbol;
	/* Mapping from symbol id to the position in the order array */
	ankerl::unordered_dense::map<unsigned int, unsigned int> by_cache_id;
	/* It matches cache->generation_id; if not, a fresh ordering is required */
	unsigned int generation_id;

	explicit order_generation(std::size_t nelts, unsigned id)
		: generation_id(id)
	{
		d.reserve(nelts);
		by_symbol.reserve(nelts);
		by_cache_id.reserve(nelts);
	}

	auto size() const -> auto
	{
		return d.size();
	}
};

using order_generation_ptr = std::shared_ptr<order_generation>;


struct delayed_cache_dependency {
	std::string from;
	std::string to;

	delayed_cache_dependency(std::string_view _from, std::string_view _to)
		: from(_from), to(_to)
	{
	}
};

struct delayed_cache_condition {
	std::string sym;
	int cbref;
	lua_State *L;

public:
	delayed_cache_condition(std::string_view sym, int cbref, lua_State *L)
		: sym(sym), cbref(cbref), L(L)
	{
	}
};

class delayed_symbol_elt {
private:
	std::variant<std::string, rspamd_regexp_t *> content;

public:
	/* Disable copy */
	delayed_symbol_elt() = delete;
	delayed_symbol_elt(const delayed_symbol_elt &) = delete;
	delayed_symbol_elt &operator=(const delayed_symbol_elt &) = delete;
	/* Enable move */
	delayed_symbol_elt(delayed_symbol_elt &&other) noexcept = default;
	delayed_symbol_elt &operator=(delayed_symbol_elt &&other) noexcept = default;

	explicit delayed_symbol_elt(std::string_view elt) noexcept
	{
		if (!elt.empty() && elt[0] == '/') {
			/* Possibly regexp */
			auto *re = rspamd_regexp_new_len(elt.data(), elt.size(), nullptr, nullptr);

			if (re != nullptr) {
				std::get<rspamd_regexp_t *>(content) = re;
			}
			else {
				std::get<std::string>(content) = elt;
			}
		}
		else {
			std::get<std::string>(content) = elt;
		}
	}

	~delayed_symbol_elt()
	{
		if (std::holds_alternative<rspamd_regexp_t *>(content)) {
			rspamd_regexp_unref(std::get<rspamd_regexp_t *>(content));
		}
	}

	auto matches(std::string_view what) const -> bool
	{
		return std::visit([&](auto &elt) {
			using T = typeof(elt);
			if constexpr (std::is_same_v<T, rspamd_regexp_t *>) {
				if (rspamd_regexp_match(elt, what.data(), what.size(), false)) {
					return true;
				}
			}
			else if constexpr (std::is_same_v<T, std::string>) {
				return elt == what;
			}

			return false;
		},
						  content);
	}

	auto to_string_view() const -> std::string_view
	{
		return std::visit([&](auto &elt) {
			using T = typeof(elt);
			if constexpr (std::is_same_v<T, rspamd_regexp_t *>) {
				return std::string_view{rspamd_regexp_get_pattern(elt)};
			}
			else if constexpr (std::is_same_v<T, std::string>) {
				return std::string_view{elt};
			}

			return std::string_view{};
		},
						  content);
	}
};

struct delayed_symbol_elt_equal {
	using is_transparent = void;
	auto operator()(const delayed_symbol_elt &a, const delayed_symbol_elt &b) const
	{
		return a.to_string_view() == b.to_string_view();
	}
	auto operator()(const delayed_symbol_elt &a, const std::string_view &b) const
	{
		return a.to_string_view() == b;
	}
	auto operator()(const std::string_view &a, const delayed_symbol_elt &b) const
	{
		return a == b.to_string_view();
	}
};

struct delayed_symbol_elt_hash {
	using is_transparent = void;
	auto operator()(const delayed_symbol_elt &a) const
	{
		return ankerl::unordered_dense::hash<std::string_view>()(a.to_string_view());
	}
	auto operator()(const std::string_view &a) const
	{
		return ankerl::unordered_dense::hash<std::string_view>()(a);
	}
};

class symcache {
private:
	using items_ptr_vec = std::vector<cache_item *>;
	/* Map indexed by symbol name: all symbols must have unique names, so this map holds ownership */
	ankerl::unordered_dense::map<std::string_view, cache_item *> items_by_symbol;
	ankerl::unordered_dense::map<int, cache_item_ptr> items_by_id;

	/* Items sorted into some order */
	order_generation_ptr items_by_order;
	unsigned int cur_order_gen;

	/* Specific vectors for execution/iteration */
	items_ptr_vec connfilters;
	items_ptr_vec prefilters;
	items_ptr_vec filters;
	items_ptr_vec postfilters;
	items_ptr_vec composites;
	items_ptr_vec idempotent;
	items_ptr_vec classifiers;
	items_ptr_vec virtual_symbols;

	/* These are stored within pointer to clean up after init */
	std::unique_ptr<std::vector<delayed_cache_dependency>> delayed_deps;
	std::unique_ptr<std::vector<delayed_cache_condition>> delayed_conditions;
	/* Delayed statically enabled or disabled symbols */
	using delayed_symbol_names = ankerl::unordered_dense::set<delayed_symbol_elt,
															  delayed_symbol_elt_hash, delayed_symbol_elt_equal>;
	std::unique_ptr<delayed_symbol_names> disabled_symbols;
	std::unique_ptr<delayed_symbol_names> enabled_symbols;

	rspamd_mempool_t *static_pool;
	std::uint64_t cksum;
	double total_weight;
	std::size_t stats_symbols_count;

private:
	std::uint64_t total_hits;

	struct rspamd_config *cfg;
	lua_State *L;
	double reload_time;
	double last_profile;

private:
	int peak_cb;
	int cache_id;

private:
	/* Internal methods */
	auto load_items() -> bool;
	auto resort() -> void;
	auto get_item_specific_vector(const cache_item &) -> items_ptr_vec &;
	/* Helper for g_hash_table_foreach */
	static auto metric_connect_cb(void *k, void *v, void *ud) -> void;

public:
	explicit symcache(struct rspamd_config *cfg)
		: cfg(cfg)
	{
		/* XXX: do we need a special pool for symcache? I don't think so */
		static_pool = cfg->cfg_pool;
		reload_time = cfg->cache_reload_time;
		total_hits = 1;
		total_weight = 1.0;
		cksum = 0xdeadbabe;
		peak_cb = -1;
		cache_id = rspamd_random_uint64_fast();
		L = (lua_State *) cfg->lua_state;
		delayed_conditions = std::make_unique<std::vector<delayed_cache_condition>>();
		delayed_deps = std::make_unique<std::vector<delayed_cache_dependency>>();
	}

	virtual ~symcache();

	/**
	 * Saves items on disk (if possible)
	 * @return
	 */
	auto save_items() const -> bool;

	/**
	 * Get an item by ID
	 * @param id
	 * @param resolve_parent
	 * @return
	 */
	auto get_item_by_id(int id, bool resolve_parent) const -> const cache_item *;
	auto get_item_by_id_mut(int id, bool resolve_parent) const -> cache_item *;
	/**
	 * Get an item by it's name
	 * @param name
	 * @param resolve_parent
	 * @return
	 */
	auto get_item_by_name(std::string_view name, bool resolve_parent) const -> const cache_item *;
	/**
	 * Get an item by it's name, mutable pointer
	 * @param name
	 * @param resolve_parent
	 * @return
	 */
	auto get_item_by_name_mut(std::string_view name, bool resolve_parent) const -> cache_item *;

	/**
	 * Add a direct dependency
	 * @param id_from
	 * @param to
	 * @param virtual_id_from
	 * @return
	 */
	auto add_dependency(int id_from, std::string_view to, int id_to, int virtual_id_from) -> void;

	/**
	 * Add a delayed dependency between symbols that will be resolved on the init stage
	 * @param from
	 * @param to
	 */
	auto add_delayed_dependency(std::string_view from, std::string_view to) -> void
	{
		if (!delayed_deps) {
			delayed_deps = std::make_unique<std::vector<delayed_cache_dependency>>();
		}

		delayed_deps->emplace_back(from, to);
	}

	/**
	 * Adds a symbol to the list of the disabled symbols
	 * @param sym
	 * @return
	 */
	auto disable_symbol_delayed(std::string_view sym) -> bool
	{
		if (!disabled_symbols) {
			disabled_symbols = std::make_unique<delayed_symbol_names>();
		}

		if (!disabled_symbols->contains(sym)) {
			disabled_symbols->emplace(sym);

			return true;
		}

		return false;
	}

	/**
	 * Adds a symbol to the list of the enabled symbols
	 * @param sym
	 * @return
	 */
	auto enable_symbol_delayed(std::string_view sym) -> bool
	{
		if (!enabled_symbols) {
			enabled_symbols = std::make_unique<delayed_symbol_names>();
		}

		if (!enabled_symbols->contains(sym)) {
			enabled_symbols->emplace(sym);

			return true;
		}

		return false;
	}

	/**
	 * Initialises the symbols cache, must be called after all symbols are added
	 * and the config file is loaded
	 */
	auto init() -> bool;

	/**
	 * Log helper that returns cfg checksum
	 * @return
	 */
	auto log_tag() const -> const char *
	{
		return cfg->checksum;
	}

	/**
	 * Helper to return a memory pool associated with the cache
	 * @return
	 */
	auto get_pool() const
	{
		return static_pool;
	}

	/**
	 * A method to add a generic symbol with a callback to couple with C API
	 * @param name name of the symbol, unlike C API it must be "" for callback only (compat) symbols, in this case an automatic name is generated
	 * @param priority
	 * @param func
	 * @param user_data
	 * @param flags_and_type mix of flags and type in a messy C enum
	 * @return id of a new symbol or -1 in case of failure
	 */
	auto add_symbol_with_callback(std::string_view name,
								  int priority,
								  symbol_func_t func,
								  void *user_data,
								  int flags_and_type) -> int;
	/**
	 * A method to add a generic virtual symbol with no function associated
	 * @param name must have some value, or a fatal error will strike you
	 * @param parent_id if this param is -1 then this symbol is associated with nothing
	 * @param flags_and_type mix of flags and type in a messy C enum
	 * @return id of a new symbol or -1 in case of failure
	 */
	auto add_virtual_symbol(std::string_view name, int parent_id,
							int flags_and_type) -> int;

	/**
	 * Sets a lua callback to be called on peaks in execution time
	 * @param cbref
	 */
	auto set_peak_cb(int cbref) -> void;

	/**
	 * Add a delayed condition for a symbol that might not be registered yet
	 * @param sym
	 * @param cbref
	 */
	auto add_delayed_condition(std::string_view sym, int cbref) -> void;

	/**
	 * Returns number of symbols that needs to be checked in statistical algorithm
	 * @return
	 */
	auto get_stats_symbols_count() const
	{
		return stats_symbols_count;
	}

	/**
	 * Returns a checksum for the cache
	 * @return
	 */
	auto get_cksum() const
	{
		return cksum;
	}

	/**
	 * Validate symbols in the cache
	 * @param strict
	 * @return
	 */
	auto validate(bool strict) -> bool;

	/**
	 * Returns counters for the cache
	 * @return
	 */
	auto counters() const -> ucl_object_t *;

	/**
	 * Adjusts stats of the cache for the periodic counter
	 */
	auto periodic_resort(struct ev_loop *ev_loop, double cur_time, double last_resort) -> void;

	/**
	 * A simple helper to get the reload time
	 * @return
	 */
	auto get_reload_time() const
	{
		return reload_time;
	};

	/**
	 * Iterate over all symbols using a specific functor
	 * @tparam Functor
	 * @param f
	 */
	template<typename Functor>
	auto symbols_foreach(Functor f) -> void
	{
		for (const auto &sym_it: items_by_symbol) {
			f(sym_it.second);
		}
	}

	/**
	 * Iterate over all composites using a specific functor
	 * @tparam Functor
	 * @param f
	 */
	template<typename Functor>
	auto composites_foreach(Functor f) -> void
	{
		for (const auto &sym_it: composites) {
			f(sym_it);
		}
	}

	/**
	 * Iterate over all composites using a specific functor
	 * @tparam Functor
	 * @param f
	 */
	template<typename Functor>
	auto connfilters_foreach(Functor f) -> bool
	{
		return std::all_of(std::begin(connfilters), std::end(connfilters),
						   [&](const auto &sym_it) {
							   return f(sym_it);
						   });
	}
	template<typename Functor>
	auto prefilters_foreach(Functor f) -> bool
	{
		return std::all_of(std::begin(prefilters), std::end(prefilters),
						   [&](const auto &sym_it) {
							   return f(sym_it);
						   });
	}
	template<typename Functor>
	auto postfilters_foreach(Functor f) -> bool
	{
		return std::all_of(std::begin(postfilters), std::end(postfilters),
						   [&](const auto &sym_it) {
							   return f(sym_it);
						   });
	}
	template<typename Functor>
	auto idempotent_foreach(Functor f) -> bool
	{
		return std::all_of(std::begin(idempotent), std::end(idempotent),
						   [&](const auto &sym_it) {
							   return f(sym_it);
						   });
	}
	template<typename Functor>
	auto filters_foreach(Functor f) -> bool
	{
		return std::all_of(std::begin(filters), std::end(filters),
						   [&](const auto &sym_it) {
							   return f(sym_it);
						   });
	}

	/**
	 * Resort cache if anything has been changed since last time
	 * @return
	 */
	auto maybe_resort() -> bool;

	/**
	 * Returns current set of items ordered for sharing ownership
	 * @return
	 */
	auto get_cache_order() const -> auto
	{
		return items_by_order;
	}

	/**
	 * Get last profile timestamp
	 * @return
	 */
	auto get_last_profile() const -> auto
	{
		return last_profile;
	}

	/**
	 * Sets last profile timestamp
	 * @param last_profile
	 * @return
	 */
	auto set_last_profile(double last_profile)
	{
		symcache::last_profile = last_profile;
	}

	/**
	 * Process settings elt identified by id
	 * @param elt
	 */
	auto process_settings_elt(struct rspamd_config_settings_elt *elt) -> void;

	/**
	 * Returns maximum timeout that is requested by all rules
	 * @return
	 */
	auto get_max_timeout(std::vector<std::pair<double, const cache_item *>> &elts) const -> double;
};


}// namespace rspamd::symcache

#endif//RSPAMD_SYMCACHE_INTERNAL_HXX
