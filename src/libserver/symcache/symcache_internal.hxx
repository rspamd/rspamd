/*-
 * Copyright 2022 Vsevolod Stakhov
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
#include "contrib/robin-hood/robin_hood.h"
#include "contrib/expected/expected.hpp"
#include "cfg_file.h"

#include "symcache_id_list.hxx"

#define msg_err_cache(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        "symcache", log_tag(), \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_warn_cache(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        "symcache", log_tag(), \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_info_cache(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        "symcache", log_tag(), \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug_cache(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        ::rspamd::symcache::rspamd_symcache_log_id, "symcache", log_tag(), \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug_cache_task(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        ::rspamd::symcache::rspamd_symcache_log_id, "symcache", task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
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
	robin_hood::unordered_flat_map<std::string_view, unsigned int> by_symbol;
	/* Mapping from symbol id to the position in the order array */
	robin_hood::unordered_flat_map<unsigned int, unsigned int> by_cache_id;
	/* It matches cache->generation_id; if not, a fresh ordering is required */
	unsigned int generation_id;

	explicit order_generation(std::size_t nelts, unsigned id) : generation_id(id) {
		d.reserve(nelts);
		by_symbol.reserve(nelts);
		by_cache_id.reserve(nelts);
	}

	auto size() const -> auto { return d.size(); }
};

using order_generation_ptr = std::shared_ptr<order_generation>;


struct delayed_cache_dependency {
	std::string from;
	std::string to;

	delayed_cache_dependency(std::string_view _from, std::string_view _to) : from(_from), to(_to) {}
};

struct delayed_cache_condition {
	std::string sym;
	int cbref;
	lua_State *L;
public:
	delayed_cache_condition(std::string_view _sym, int _cbref, lua_State *_L) :
		sym(_sym), cbref(_cbref), L(_L) {}
};

class symcache {
private:
	using items_ptr_vec = std::vector<cache_item_ptr>;
	/* Map indexed by symbol name: all symbols must have unique names, so this map holds ownership */
	robin_hood::unordered_flat_map<std::string_view, cache_item_ptr> items_by_symbol;
	items_ptr_vec items_by_id;

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
	auto get_item_specific_vector(const cache_item &) -> items_ptr_vec&;
	/* Helper for g_hash_table_foreach */
	static auto metric_connect_cb(void *k, void *v, void *ud) -> void;

public:
	explicit symcache(struct rspamd_config *cfg) : cfg(cfg) {
		/* XXX: do we need a special pool for symcache? I don't think so */
		static_pool = cfg->cfg_pool;
		reload_time = cfg->cache_reload_time;
		total_hits = 1;
		total_weight = 1.0;
		cksum = 0xdeadbabe;
		peak_cb = -1;
		cache_id = rspamd_random_uint64_fast();
		L = (lua_State *)cfg->lua_state;
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
	auto add_dependency(int id_from, std::string_view to, int virtual_id_from) -> void;

	/**
	 * Add a delayed dependency between symbols that will be resolved on the init stage
	 * @param from
	 * @param to
	 */
	auto add_delayed_dependency(std::string_view from, std::string_view to) -> void {
		if (!delayed_deps) {
			delayed_deps = std::make_unique<std::vector<delayed_cache_dependency>>();
		}

		delayed_deps->emplace_back(from, to);
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
	auto log_tag() const -> const char* {
		return cfg->checksum;
	}

	/**
	 * Helper to return a memory pool associated with the cache
	 * @return
	 */
	auto get_pool() const {
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
								  enum rspamd_symbol_type flags_and_type) -> int;
	/**
	 * A method to add a generic virtual symbol with no function associated
	 * @param name must have some value, or a fatal error will strike you
	 * @param parent_id if this param is -1 then this symbol is associated with nothing
	 * @param flags_and_type mix of flags and type in a messy C enum
	 * @return id of a new symbol or -1 in case of failure
	 */
	auto add_virtual_symbol(std::string_view name, int parent_id,
							enum rspamd_symbol_type flags_and_type) -> int;

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
	auto get_stats_symbols_count() const {
		return stats_symbols_count;
	}

	/**
	 * Returns a checksum for the cache
	 * @return
	 */
	auto get_cksum() const {
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
	auto get_reload_time() const { return reload_time; };

	/**
	 * Iterate over all symbols using a specific functor
	 * @tparam Functor
	 * @param f
	 */
	template<typename Functor>
	auto symbols_foreach(Functor f) -> void {
		for (const auto &sym_it : items_by_symbol) {
			f(sym_it.second.get());
		}
	}

	/**
	 * Iterate over all composites using a specific functor
	 * @tparam Functor
	 * @param f
	 */
	template<typename Functor>
	auto composites_foreach(Functor f) -> void {
		for (const auto &sym_it : composites) {
			f(sym_it.get());
		}
	}

	/**
	 * Resort cache if anything has been changed since last time
	 * @return
	 */
	auto maybe_resort() -> bool;

	/**
	 * Returns number of items with ids
	 * @return
	 */
	auto get_items_count()  const -> auto {
		return items_by_id.size();
	}

	/**
	 * Returns current set of items ordered for sharing ownership
	 * @return
	 */
	auto get_cache_order() const -> auto {
		return items_by_order;
	}

	/**
	 * Get last profile timestamp
	 * @return
	 */
	auto get_last_profile() const -> auto {
		return last_profile;
	}

	/**
	 * Sets last profile timestamp
	 * @param last_profile
	 * @return
	 */
	auto set_last_profile(double last_profile){
		symcache::last_profile = last_profile;
	}

	/**
	 * Process settings elt identified by id
	 * @param elt
	 */
	auto process_settings_elt(struct rspamd_config_settings_elt *elt) -> void;
};


} // namespace rspamd

#endif //RSPAMD_SYMCACHE_INTERNAL_HXX
