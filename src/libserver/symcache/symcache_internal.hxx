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
#include <vector>
#include <string>
#include <string_view>
#include <memory>
#include <variant>
#include "contrib/robin-hood/robin_hood.h"

#include "cfg_file.h"
#include "lua/lua_common.h"

#define msg_err_cache(...) rspamd_default_log_function (G_LOG_LEVEL_CRITICAL, \
        static_pool->tag.tagname, cfg->checksum, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_warn_cache(...)   rspamd_default_log_function (G_LOG_LEVEL_WARNING, \
        static_pool->tag.tagname, cfg->checksum, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_info_cache(...)   rspamd_default_log_function (G_LOG_LEVEL_INFO, \
        static_pool->tag.tagname, cfg->checksum, \
        RSPAMD_LOG_FUNC, \
        __VA_ARGS__)
#define msg_debug_cache(...)  rspamd_conditional_debug_fast (NULL, NULL, \
        rspamd_symcache_log_id, "symcache", cfg->checksum, \
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
	std::vector<cache_item_weak_ptr> d;
	unsigned int generation_id;
};

using order_generation_ptr = std::shared_ptr<order_generation>;

/*
 * This structure is optimised to store ids list:
 * - If the first element is -1 then use dynamic part, else use static part
 * There is no std::variant to save space
 */
struct id_list {
	union {
		std::uint32_t st[4];
		struct {
			std::uint32_t e; /* First element */
			std::uint16_t len;
			std::uint16_t allocated;
			std::uint32_t *n;
		} dyn;
	} data;

	id_list() {
		std::memset((void *)&data, 0, sizeof(data));
	}
	/**
	 * Returns ids from a compressed list, accepting a mutable reference for number of elements
	 * @param nids output of the number of elements
	 * @return
	 */
	auto get_ids(std::size_t &nids) const -> const std::uint32_t * {
		if (data.dyn.e == -1) {
			/* Dynamic list */
			nids = data.dyn.len;

			return data.dyn.n;
		}
		else {
			auto cnt = 0;

			while (data.st[cnt] != 0 && cnt < G_N_ELEMENTS(data.st)) {
				cnt ++;
			}

			nids = cnt;

			return data.st;
		}
	}

	auto add_id(std::uint32_t id, rspamd_mempool_t *pool) -> void {
		if (data.st[0] == -1) {
			/* Dynamic array */
			if (data.dyn.len < data.dyn.allocated) {
				/* Trivial, append + sort */
				data.dyn.n[data.dyn.len++] = id;
			}
			else {
				/* Reallocate */
				g_assert (data.dyn.allocated <= G_MAXINT16);
				data.dyn.allocated *= 2;

				auto *new_array = rspamd_mempool_alloc_array_type(pool,
						data.dyn.allocated, std::uint32_t);
				memcpy(new_array, data.dyn.n, data.dyn.len * sizeof(std::uint32_t));
				data.dyn.n = new_array;
				data.dyn.n[data.dyn.len++] = id;
			}

			std::sort(data.dyn.n, data.dyn.n + data.dyn.len);
		}
		else {
			/* Static part */
			auto cnt = 0u;
			while (data.st[cnt] != 0 && cnt < G_N_ELEMENTS (data.st)) {
				cnt ++;
			}

			if (cnt < G_N_ELEMENTS (data.st)) {
				data.st[cnt] = id;
			}
			else {
				/* Switch to dynamic */
				data.dyn.allocated = G_N_ELEMENTS (data.st) * 2;
				auto *new_array = rspamd_mempool_alloc_array_type(pool,
						data.dyn.allocated, std::uint32_t);
				memcpy (new_array, data.st, sizeof(data.st));
				data.dyn.n = new_array;
				data.dyn.e = -1; /* Marker */
				data.dyn.len = G_N_ELEMENTS (data.st);

				/* Recursively jump to dynamic branch that will handle insertion + sorting */
				add_id(id, pool); // tail call
			}
		}
	}
};

class symcache;

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
	explicit normal_item() {
		// TODO
	}
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
	explicit virtual_item() {
		// TODO
	}

	auto get_parent(const symcache &cache) const -> const cache_item *;
};

struct cache_dependency {
	cache_item_ptr item; /* Real dependency */
	std::string sym; /* Symbolic dep name */
	int id; /* Real from */
	int vid; /* Virtual from */
};

struct cache_item {
	/* This block is likely shared */
	struct rspamd_symcache_item_stat *st;
	struct rspamd_counter_data *cd;

	std::uint64_t last_count;
	std::string symbol;
	std::string_view type_descr;
	int type;

	/* Callback data */
	std::variant<normal_item, virtual_item> specific;

	/* Condition of execution */
	bool enabled;

	/* Priority */
	int priority;
	/* Topological order */
	unsigned int order;
	/* Unique id - counter */
	int id;

	int frequency_peaks;
	/* Settings ids */
	id_list allowed_ids;
	/* Allows execution but not symbols insertion */
	id_list exec_only_ids;
	id_list forbidden_ids;

	/* Dependencies */
	std::vector<cache_dependency> deps;
	/* Reverse dependencies */
	std::vector<cache_item_ptr> rdeps;

	auto is_virtual() const -> bool { return std::holds_alternative<virtual_item>(specific); }
	auto get_parent(const symcache &cache) const -> const cache_item *;
	auto add_condition(lua_State *L, int cbref) -> bool {
		if (!is_virtual()) {
			auto &normal = std::get<normal_item>(specific);
			normal.add_condition(L, cbref);

			return true;
		}

		return false;
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
	auto save_items() const -> bool;

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

	/*
	 * Initialises the symbols cache, must be called after all symbols are added
	 * and the config file is loaded
	 */
	auto init() -> bool;
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


struct cache_dependency {
	cache_item_ptr item; /* Owning pointer to the real dep */
	std::string_view sym; /* Symbolic dep name */
	int id; /* Real from */
	int vid; /* Virtual from */
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
