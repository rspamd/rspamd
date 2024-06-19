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

#ifndef RSPAMD_SYMCACHE_ITEM_HXX
#define RSPAMD_SYMCACHE_ITEM_HXX

#pragma once

#include <utility>
#include <vector>
#include <string>
#include <string_view>
#include <memory>
#include <variant>
#include <algorithm>
#include <optional>

#include "rspamd_symcache.h"
#include "symcache_id_list.hxx"
#include "contrib/expected/expected.hpp"
#include "contrib/libev/ev.h"
#include "symcache_runtime.hxx"
#include "libutil/cxx/hash_util.hxx"

namespace rspamd::symcache {

class symcache;
struct cache_item;
using cache_item_ptr = std::shared_ptr<cache_item>;

enum class symcache_item_type {
	CONNFILTER, /* Executed on connection stage */
	PREFILTER,  /* Executed before all filters */
	FILTER,     /* Normal symbol with a callback */
	POSTFILTER, /* Executed after all filters */
	IDEMPOTENT, /* Executed after postfilters, cannot change results */
	CLASSIFIER, /* A virtual classifier symbol */
	COMPOSITE,  /* A virtual composite symbol */
	VIRTUAL,    /* A virtual symbol... */
};

/*
 * Compare item types: earlier stages symbols are > than later stages symbols
 * Order for virtual stuff is not defined.
 */
bool operator<(symcache_item_type lhs, symcache_item_type rhs);

constexpr static auto item_type_to_str(symcache_item_type t) -> const char *
{
	switch (t) {
	case symcache_item_type::CONNFILTER:
		return "connfilter";
	case symcache_item_type::PREFILTER:
		return "prefilter";
	case symcache_item_type::FILTER:
		return "filter";
	case symcache_item_type::POSTFILTER:
		return "postfilter";
	case symcache_item_type::IDEMPOTENT:
		return "idempotent";
	case symcache_item_type::CLASSIFIER:
		return "classifier";
	case symcache_item_type::COMPOSITE:
		return "composite";
	case symcache_item_type::VIRTUAL:
		return "virtual";
	}
}

/**
 * This is a public helper to convert a legacy C type to a more static type
 * @param type input type as a C enum
 * @return pair of type safe symcache_item_type + the remaining flags or an error
 */
auto item_type_from_c(int type) -> tl::expected<std::pair<symcache_item_type, int>, std::string>;

struct item_condition {
private:
	lua_State *L = nullptr;
	int cb = -1;

public:
	explicit item_condition(lua_State *L_, int cb_) noexcept
		: L(L_), cb(cb_)
	{
	}
	item_condition(item_condition &&other) noexcept
	{
		*this = std::move(other);
	}
	/* Make it move only */
	item_condition(const item_condition &) = delete;
	item_condition &operator=(item_condition &&other) noexcept
	{
		std::swap(other.L, L);
		std::swap(other.cb, cb);
		return *this;
	}
	~item_condition();

	auto check(std::string_view sym_name, struct rspamd_task *task) const -> bool;
};

class normal_item {
private:
	symbol_func_t func = nullptr;
	void *user_data = nullptr;
	std::vector<cache_item *> virtual_children;
	std::vector<item_condition> conditions;

public:
	explicit normal_item(symbol_func_t _func, void *_user_data)
		: func(_func), user_data(_user_data)
	{
	}

	auto add_condition(lua_State *L, int cbref) -> void
	{
		conditions.emplace_back(L, cbref);
	}

	auto call(struct rspamd_task *task, struct rspamd_symcache_dynamic_item *item) const -> void
	{
		func(task, item, user_data);
	}

	auto check_conditions(std::string_view sym_name, struct rspamd_task *task) const -> bool
	{
		return std::all_of(std::begin(conditions), std::end(conditions),
						   [&](const auto &cond) { return cond.check(sym_name, task); });
	}

	auto get_cbdata() const -> auto
	{
		return user_data;
	}

	auto add_child(cache_item *ptr) -> void
	{
		virtual_children.push_back(ptr);
	}

	auto get_childen() const -> const std::vector<cache_item *> &
	{
		return virtual_children;
	}
};

class virtual_item {
private:
	int parent_id = -1;
	cache_item *parent = nullptr;

public:
	explicit virtual_item(int _parent_id)
		: parent_id(_parent_id)
	{
	}

	auto get_parent(const symcache &cache) const -> const cache_item *;
	auto get_parent_mut(const symcache &cache) -> cache_item *;

	auto resolve_parent(const symcache &cache) -> bool;
};

struct cache_dependency {
	cache_item *item;      /* Real dependency */
	std::string sym;       /* Symbolic dep name */
	int virtual_source_id; /* Virtual source */
public:
	/* Default piecewise constructor */
	explicit cache_dependency(cache_item *_item, std::string _sym, int _vid)
		: item(_item), sym(std::move(_sym)), virtual_source_id(_vid)
	{
	}
};

/*
 * Used to store augmentation values
 */
struct item_augmentation {
	std::variant<std::monostate, std::string, double> value;
	int weight;

	explicit item_augmentation(int weight)
		: value(std::monostate{}), weight(weight)
	{
	}
	explicit item_augmentation(std::string str_value, int weight)
		: value(str_value), weight(weight)
	{
	}
	explicit item_augmentation(double double_value, int weight)
		: value(double_value), weight(weight)
	{
	}
};

struct cache_item : std::enable_shared_from_this<cache_item> {
	/* The following fields will live in shared memory */
	struct rspamd_symcache_item_stat *st = nullptr;
	struct rspamd_counter_data *cd = nullptr;

	std::string symbol;

	/* Unique id - counter */
	int id;
	std::uint64_t last_count = 0;
	symcache_item_type type;
	int flags;

	static constexpr const auto bit_enabled = 0b0001;
	static constexpr const auto bit_sync = 0b0010;
	static constexpr const auto bit_slow = 0b0100;
	int internal_flags = bit_enabled;

	/* Priority */
	int priority = 0;
	/* Topological order */
	unsigned int order = 0;
	int frequency_peaks = 0;

	/* Specific data for virtual and callback symbols */
	std::variant<normal_item, virtual_item> specific;

	/* Settings ids */
	id_list allowed_ids;
	/* Allows execution but not symbols insertion */
	id_list exec_only_ids;
	id_list forbidden_ids;

	/* Set of augmentations */
	ankerl::unordered_dense::map<std::string, item_augmentation,
								 rspamd::smart_str_hash, rspamd::smart_str_equal>
		augmentations;

	/* Dependencies */
	ankerl::unordered_dense::map<int, cache_dependency> deps;
	/* Reverse dependencies */
	ankerl::unordered_dense::map<int, cache_dependency> rdeps;

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
	template<typename T>
	static auto create_with_function(rspamd_mempool_t *pool,
									 int id,
									 T &&name,
									 int priority,
									 symbol_func_t func,
									 void *user_data,
									 symcache_item_type type,
									 int flags) -> cache_item_ptr
	{
		return std::shared_ptr<cache_item>(new cache_item(pool,
														  id, std::forward<T>(name), priority,
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
	template<typename T>
	static auto create_with_virtual(rspamd_mempool_t *pool,
									int id,
									T &&name,
									int parent,
									symcache_item_type type,
									int flags) -> cache_item_ptr
	{
		return std::shared_ptr<cache_item>(new cache_item(pool, id, std::forward<T>(name),
														  parent, type, flags));
	}

	/**
	 * Share ownership on the item
 	 * @return
 	 */
	auto getptr() -> cache_item_ptr
	{
		return shared_from_this();
	}

	/**
	 * Process and resolve dependencies for the item
	 * @param cache
	 */
	auto process_deps(const symcache &cache) -> void;

	auto is_virtual() const -> bool
	{
		return std::holds_alternative<virtual_item>(specific);
	}

	auto is_filter() const -> bool
	{
		return std::holds_alternative<normal_item>(specific) &&
			   (type == symcache_item_type::FILTER);
	}

	/**
	 * Returns true if a symbol should have some score defined
	 * @return
	 */
	auto is_scoreable() const -> bool
	{
		return !(flags & SYMBOL_TYPE_CALLBACK) &&
			   ((type == symcache_item_type::FILTER) ||
				is_virtual() ||
				(type == symcache_item_type::COMPOSITE) ||
				(type == symcache_item_type::CLASSIFIER));
	}

	auto is_ghost() const -> bool
	{
		return flags & SYMBOL_TYPE_GHOST;
	}

	auto get_parent(const symcache &cache) const -> const cache_item *;
	auto get_parent_mut(const symcache &cache) -> cache_item *;

	auto resolve_parent(const symcache &cache) -> bool;

	auto get_type() const -> auto
	{
		return type;
	}

	auto get_type_str() const -> const char *;

	auto get_name() const -> const std::string &
	{
		return symbol;
	}

	auto get_flags() const -> auto
	{
		return flags;
	};

	auto add_condition(lua_State *L, int cbref) -> bool
	{
		if (!is_virtual()) {
			auto &normal = std::get<normal_item>(specific);
			normal.add_condition(L, cbref);

			return true;
		}

		return false;
	}

	auto update_counters_check_peak(lua_State *L,
									struct ev_loop *ev_loop,
									double cur_time,
									double last_resort) -> bool;

	/**
	 * Increase frequency for a symbol
	 */
	auto inc_frequency(const char *sym_name, symcache &cache) -> void;

	/**
	 * Check if an item is allowed to be executed not checking item conditions
	 * @param task
	 * @param exec_only
	 * @return
	 */
	auto is_allowed(struct rspamd_task *task, bool exec_only) const -> bool;

	/**
	 * Returns callback data
	 * @return
	 */
	auto get_cbdata() const -> void *
	{
		if (std::holds_alternative<normal_item>(specific)) {
			const auto &filter_data = std::get<normal_item>(specific);

			return filter_data.get_cbdata();
		}

		return nullptr;
	}

	/**
	 * Check all conditions for an item
	 * @param task
	 * @return
	 */
	auto check_conditions(struct rspamd_task *task) const -> auto
	{
		if (std::holds_alternative<normal_item>(specific)) {
			const auto &filter_data = std::get<normal_item>(specific);

			return filter_data.check_conditions(symbol, task);
		}

		return false;
	}

	auto call(struct rspamd_task *task, cache_dynamic_item *dyn_item) const -> bool
	{
		if (std::holds_alternative<normal_item>(specific)) {
			const auto &filter_data = std::get<normal_item>(specific);

			filter_data.call(task, (struct rspamd_symcache_dynamic_item *) dyn_item);
			return true;
		}

		return false;
	}

	/**
	 * Add an augmentation to the item, returns `true` if augmentation is known and unique, false otherwise
	 * @param augmentation
	 * @return
	 */
	auto add_augmentation(const symcache &cache, std::string_view augmentation,
						  std::optional<std::string_view> value) -> bool;

	/**
	 * Return sum weight of all known augmentations
	 * @return
	 */
	auto get_augmentation_weight() const -> int;

	/**
	 * Returns numeric augmentation value
	 * @param name
	 * @return
	 */
	auto get_numeric_augmentation(std::string_view name) const -> std::optional<double>;

	/**
	 * Returns string augmentation value
	 * @param name
	 * @return
	 */
	auto get_string_augmentation(std::string_view name) const -> std::optional<std::string_view>;

	/**
	 * Add a virtual symbol as a child of some normal symbol
	 * @param ptr
	 */
	auto add_child(cache_item *ptr) -> void
	{
		if (std::holds_alternative<normal_item>(specific)) {
			auto &filter_data = std::get<normal_item>(specific);

			filter_data.add_child(ptr);
		}
		else {
			g_assert("add child is called for a virtual symbol!");
		}
	}

	/**
	 * Returns virtual children for a normal item
	 * @param ptr
	 * @return
	 */
	auto get_children() const -> const std::vector<cache_item *> *
	{
		if (std::holds_alternative<normal_item>(specific)) {
			const auto &filter_data = std::get<normal_item>(specific);

			return &filter_data.get_childen();
		}

		return nullptr;
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
			   int _flags)
		: symbol(std::move(name)),
		  id(_id),
		  type(_type),
		  flags(_flags),
		  priority(_priority),
		  specific(normal_item{func, user_data})
	{
		/* These structures are kept trivial, so they need to be explicitly reset */
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
			   int _flags)
		: symbol(std::move(name)),
		  id(_id),
		  type(_type),
		  flags(_flags),
		  specific(virtual_item{parent})
	{
		/* These structures are kept trivial, so they need to be explicitly reset */
		forbidden_ids.reset();
		allowed_ids.reset();
		exec_only_ids.reset();
		st = rspamd_mempool_alloc0_shared_type(pool, std::remove_pointer_t<decltype(st)>);
		cd = rspamd_mempool_alloc0_shared_type(pool, std::remove_pointer_t<decltype(cd)>);
	}
};

}// namespace rspamd::symcache

#endif//RSPAMD_SYMCACHE_ITEM_HXX
