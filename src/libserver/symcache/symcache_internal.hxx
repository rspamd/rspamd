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
#include "contrib/robin-hood/robin_hood.h"
#include "contrib/expected/expected.hpp"
#include "cfg_file.h"
#include "lua/lua_common.h"

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
        rspamd_symcache_log_id, "symcache", log_tag(), \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug_cache_task(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_symcache_log_id, "symcache", task->task_pool->tag.uid, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)

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
using cache_item_weak_ptr = std::weak_ptr<cache_item>;

struct order_generation {
	std::vector<cache_item_ptr> d;
	unsigned int generation_id;

	explicit order_generation(std::size_t nelts, unsigned id) : generation_id(id) {
		d.reserve(nelts);
	}
};

using order_generation_ptr = std::shared_ptr<order_generation>;

class symcache;

enum class symcache_item_type {
	CONNFILTER, /* Executed on connection stage */
	PREFILTER, /* Executed before all filters */
	FILTER, /* Normal symbol with a callback */
	POSTFILTER, /* Executed after all filters */
	IDEMPOTENT, /* Executed after postfilters, cannot change results */
	CLASSIFIER, /* A virtual classifier symbol */
	COMPOSITE, /* A virtual composite symbol */
	VIRTUAL, /* A virtual symbol... */
};

/*
 * Compare item types: earlier stages symbols are > than later stages symbols
 * Order for virtual stuff is not defined.
 */
bool operator < (symcache_item_type lhs, symcache_item_type rhs);
/**
 * This is a public helper to convert a legacy C type to a more static type
 * @param type input type as a C enum
 * @return pair of type safe symcache_item_type + the remaining flags or an error
 */
auto item_type_from_c(enum rspamd_symbol_type type) -> tl::expected<std::pair<symcache_item_type, int>, std::string>;

struct item_condition {
private:
	lua_State *L;
	int cb;
public:
	item_condition(lua_State *_L, int _cb) : L(_L), cb(_cb) {}
	virtual ~item_condition() {
		if (cb != -1 && L != nullptr) {
			luaL_unref(L, LUA_REGISTRYINDEX, cb);
		}
	}
};

class normal_item {
private:
	symbol_func_t func;
	void *user_data;
	std::vector<item_condition> conditions;
public:
	explicit normal_item(symbol_func_t _func, void *_user_data) : func(_func), user_data(_user_data) {}
	auto add_condition(lua_State *L, int cbref) -> void {
		conditions.emplace_back(L, cbref);
	}
	auto call() -> void {
		// TODO
	}
};

class virtual_item {
private:
	int parent_id;
	cache_item_ptr parent;
public:
	explicit virtual_item(int _parent_id) : parent_id(_parent_id) {}

	auto get_parent(const symcache &cache) const -> const cache_item *;
	auto resolve_parent(const symcache &cache) -> bool;
};

struct cache_dependency {
	cache_item_ptr item; /* Real dependency */
	std::string sym; /* Symbolic dep name */
	int id; /* Real from */
	int vid; /* Virtual from */
public:
	/* Default piecewise constructor */
	cache_dependency(cache_item_ptr _item, std::string _sym, int _id, int _vid) :
		item(std::move(_item)), sym(std::move(_sym)), id(_id), vid(_vid) {}
};

struct cache_item : std::enable_shared_from_this<cache_item> {
	/* This block is likely shared */
	struct rspamd_symcache_item_stat *st = nullptr;
	struct rspamd_counter_data *cd = nullptr;

	/* Unique id - counter */
	int id;
	std::uint64_t last_count = 0;
	std::string symbol;
	symcache_item_type type;
	int flags;

	/* Condition of execution */
	bool enabled = true;

	/* Priority */
	int priority = 0;
	/* Topological order */
	unsigned int order = 0;
	int frequency_peaks = 0;

	/* Specific data for virtual and callback symbols */
	std::variant<normal_item, virtual_item> specific;

	/* Settings ids */
	id_list allowed_ids{};
	/* Allows execution but not symbols insertion */
	id_list exec_only_ids{};
	id_list forbidden_ids{};

	/* Dependencies */
	std::vector<cache_dependency> deps;
	/* Reverse dependencies */
	std::vector<cache_dependency> rdeps;

public:
	/**
	 * Create a normal item with a callback
	 * @param name
	 * @param priority
	 * @param func
	 * @param user_data
	 * @param type
	 * @param flags
	 * @return
	 */
	[[nodiscard]] static auto create_with_function(rspamd_mempool_t *pool,
												   int id,
												   std::string &&name,
												   int priority,
												   symbol_func_t func,
												   void *user_data,
												   symcache_item_type type,
												   int flags) -> cache_item_ptr {
		return std::shared_ptr<cache_item>(new cache_item(pool,
				id, std::move(name), priority,
				func, user_data,
				type, flags));
	}
	/**
	 * Create a virtual item
	 * @param name
	 * @param priority
	 * @param parent
	 * @param type
	 * @param flags
	 * @return
	 */
	[[nodiscard]] static auto create_with_virtual(rspamd_mempool_t *pool,
												  int id,
												  std::string &&name,
												  int parent,
												  symcache_item_type type,
												  int flags) -> cache_item_ptr {
		return std::shared_ptr<cache_item>(new cache_item(pool, id, std::move(name),
				parent, type, flags));
	}
	/**
	 * Share ownership on the item
	 * @return
	 */
	auto getptr() -> cache_item_ptr {
		return shared_from_this();
	}
	/**
	 * Process and resolve dependencies for the item
	 * @param cache
	 */
	auto process_deps(const symcache &cache) -> void;
	auto is_virtual() const -> bool { return std::holds_alternative<virtual_item>(specific); }
	auto is_filter() const -> bool {
		return std::holds_alternative<normal_item>(specific) &&
		        (type == symcache_item_type::FILTER);
	}
	auto is_ghost() const -> bool {
		return flags & SYMBOL_TYPE_GHOST;
	}
	auto get_parent(const symcache &cache) const -> const cache_item *;
	auto resolve_parent(const symcache &cache) -> bool;
	auto get_type() const -> auto {
		return type;
	}
	auto get_name() const -> const std::string & {
		return symbol;
	}
	auto add_condition(lua_State *L, int cbref) -> bool {
		if (!is_virtual()) {
			auto &normal = std::get<normal_item>(specific);
			normal.add_condition(L, cbref);

			return true;
		}

		return false;
	}

private:
	/**
	 * Constructor for a normal symbols with callback
	 * @param name
	 * @param _priority
	 * @param func
	 * @param user_data
	 * @param _type
	 * @param _flags
	 */
	cache_item(rspamd_mempool_t *pool,
			   int _id,
			   std::string &&name,
			   int _priority,
			   symbol_func_t func,
			   void *user_data,
			   symcache_item_type _type,
			   int _flags) : id(_id),
			   				 symbol(std::move(name)),
							 type(_type),
							 flags(_flags),
							 priority(_priority),
							 specific(normal_item{func, user_data})
	{
		forbidden_ids.reset();
		allowed_ids.reset();
		exec_only_ids.reset();
		st = rspamd_mempool_alloc0_shared_type(pool, std::remove_pointer_t<decltype(st)>);
		cd = rspamd_mempool_alloc0_shared_type(pool, std::remove_pointer_t<decltype(cd)>);
	}
	/**
	 * Constructor for a virtual symbol
	 * @param name
	 * @param _priority
	 * @param parent
	 * @param _type
	 * @param _flags
	 */
	cache_item(rspamd_mempool_t *pool,
			   int _id,
			   std::string &&name,
			   int parent,
			   symcache_item_type _type,
			   int _flags) : id(_id),
							 symbol(std::move(name)),
							 type(_type),
							 flags(_flags),
							 specific(virtual_item{parent})
	{
		forbidden_ids.reset();
		allowed_ids.reset();
		exec_only_ids.reset();
		st = rspamd_mempool_alloc0_shared_type(pool, std::remove_pointer_t<decltype(st)>);
		cd = rspamd_mempool_alloc0_shared_type(pool, std::remove_pointer_t<decltype(cd)>);
	}
};

struct delayed_cache_dependency {
	std::string from;
	std::string to;
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
	/* Map indexed by symbol name: all symbols must have unique names, so this map holds ownership */
	robin_hood::unordered_flat_map<std::string_view, cache_item_ptr> items_by_symbol;
	std::vector<cache_item_ptr> items_by_id;

	/* Items sorted into some order */
	order_generation_ptr items_by_order;
	unsigned int cur_order_gen;

	std::vector<cache_item_ptr> connfilters;
	std::vector<cache_item_ptr> prefilters;
	std::vector<cache_item_ptr> filters;
	std::vector<cache_item_ptr> postfilters;
	std::vector<cache_item_ptr> composites;
	std::vector<cache_item_ptr> idempotent;
	std::vector<cache_item_ptr> virtual_symbols;

	/* These are stored within pointer to clean up after init */
	std::unique_ptr<std::vector<delayed_cache_dependency>> delayed_deps;
	std::unique_ptr<std::vector<delayed_cache_condition>> delayed_conditions;

	rspamd_mempool_t *static_pool;
	std::uint64_t cksum;
	double total_weight;
	std::size_t used_items;
	std::size_t stats_symbols_count;

private:
	std::uint64_t total_hits;

	struct rspamd_config *cfg;
	lua_State *L;
	double reload_time;
	double last_profile;
	int peak_cb;
	int cache_id;

private:
	/* Internal methods */
	auto load_items() -> bool;
	auto resort() -> void;
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

	virtual ~symcache() {
		if (peak_cb != -1) {
			luaL_unref(L, LUA_REGISTRYINDEX, peak_cb);
		}
	}

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
};

/*
 * These items are saved within task structure and are used to track
 * symbols execution
 */
struct cache_dynamic_item {
	std::uint16_t start_msec; /* Relative to task time */
	unsigned started: 1;
	unsigned finished: 1;
	/* unsigned pad:14; */
	std::uint32_t async_events;
};

struct cache_savepoint {
	unsigned order_gen;
	unsigned items_inflight;
	bool profile;
	bool has_slow;

	double profile_start;
	double lim;

	struct rspamd_scan_result *rs;

	struct cache_item *cur_item;
	order_generation_ptr order;
	/* Dynamically expanded as needed */
	struct cache_dynamic_item dynamic_items[];
};

struct cache_refresh_cbdata {
	double last_resort;
	ev_timer resort_ev;
	symcache *cache;
	struct rspamd_worker *w;
	struct ev_loop *event_loop;
};

} // namespace rspamd

#endif //RSPAMD_SYMCACHE_INTERNAL_HXX
