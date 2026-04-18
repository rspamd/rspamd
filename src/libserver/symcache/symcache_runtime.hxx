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
 * Symcache runtime is produced for each task and it consists of symbols
 * being executed, being dynamically disabled/enabled and it also captures
 * the current order of the symbols (produced by resort periodic)
 */

#ifndef RSPAMD_SYMCACHE_RUNTIME_HXX
#define RSPAMD_SYMCACHE_RUNTIME_HXX
#pragma once

#include "symcache_internal.hxx"

struct rspamd_scan_result;

namespace rspamd::symcache {
enum class cache_item_status : std::uint16_t {
	not_started = 0,
	started = 1,
	pending = 2,
	finished = 3,
	disabled = 4, /* Disabled by settings; triggers cascade-disable for hard deps */
};

/* Check if an item status means "done" (finished or disabled) */
static inline auto is_item_done(cache_item_status status) -> bool
{
	return status == cache_item_status::finished || status == cache_item_status::disabled;
}
/**
 * These items are saved within task structure and are used to track
 * symbols execution.
 * Each symcache item occupies a single dynamic item, that currently has 8 bytes
 * length
 */
struct cache_dynamic_item {
	std::uint16_t start_msec; /* Relative to task time */
	cache_item_status status;
	std::uint32_t async_events;
};

static_assert(sizeof(cache_dynamic_item) == sizeof(std::uint64_t));
static_assert(std::is_trivial_v<cache_dynamic_item>);


class symcache_runtime {
	unsigned items_inflight;

	enum class slow_status : std::uint8_t {
		none = 0,
		enabled = 1,
		disabled = 2,
	} slow_status;
	enum class check_status {
		allow,
		limit_reached,
		passthrough,
	};
	bool profile;

	double profile_start;
	double lim;

	struct cache_dynamic_item *cur_item;
	order_generation_ptr order;
	/* Symbol IDs force-enabled by merged settings (overrides settings_elt forbidden_ids) */
	id_list *force_enabled_ids;
	/* Dynamically expanded as needed */
	mutable struct cache_dynamic_item dynamic_items[];
	/* We allocate this structure merely in memory pool, so destructor is absent */
	~symcache_runtime() = delete;

	auto process_symbol(struct rspamd_task *task, symcache &cache, cache_item *item,
						cache_dynamic_item *dyn_item) -> bool;
	/* Specific stages of the processing */
	auto process_pre_postfilters(struct rspamd_task *task, symcache &cache, int start_events, unsigned int stage) -> bool;
	auto process_filters(struct rspamd_task *task, symcache &cache, int start_events) -> bool;
	auto check_process_status(struct rspamd_task *task) -> check_status;
	auto check_item_deps(struct rspamd_task *task, symcache &cache, cache_item *item,
						 cache_dynamic_item *dyn_item, bool check_only) -> bool;

public:
	/* Dropper for a shared ownership */
	auto savepoint_dtor(struct rspamd_task *task) -> void;
	/**
	 * Creates a cache runtime using task mempool
	 * @param task
	 * @param cache
	 * @return
	 */
	static auto create(struct rspamd_task *task, symcache &cache) -> symcache_runtime *;
	/**
	 * Process task settings
	 * @param task
	 * @return
	 */
	auto process_settings(struct rspamd_task *task, const symcache &cache) -> bool;

	/**
	 * Disable all symbols but not touching ones that are in the specific mask
	 * @param skip_mask
	 */
	auto disable_all_symbols(int skip_mask) -> void;

	/**
	 * Disable a symbol (or it's parent)
	 * @param name
	 * @return
	 */
	auto disable_symbol(struct rspamd_task *task, const symcache &cache, std::string_view name) -> bool;

	/**
	 * Enable a symbol (or it's parent)
	 * @param name
	 * @return
	 */
	auto enable_symbol(struct rspamd_task *task, const symcache &cache, std::string_view name) -> bool;

	/**
	 * Mark a symbol as force-enabled (overrides settings_elt forbidden_ids)
	 * @param id symbol cache id
	 */
	auto add_force_enabled(int id) -> void;

	/**
	 * Check if a symbol is force-enabled
	 * @param id symbol cache id
	 * @return true if force-enabled
	 */
	auto is_force_enabled(int id) const -> bool;

	/**
	 * Checks if an item has been checked/disabled
	 * @param cache
	 * @param name
	 * @return
	 */
	auto is_symbol_checked(const symcache &cache, std::string_view name) -> bool;

	/**
	 * Checks if a symbol is enabled for execution, checking all pending conditions
	 * @param task
	 * @param cache
	 * @param name
	 * @return
	 */
	auto is_symbol_enabled(struct rspamd_task *task, const symcache &cache, std::string_view name) -> bool;

	/**
	 * Get the current processed item
	 * @return
	 */
	auto get_cur_item() const -> auto
	{
		return cur_item;
	}

	/**
	 * Set the current processed item
	 * @param item
	 * @return
	 */
	auto set_cur_item(cache_dynamic_item *item) -> auto
	{
		std::swap(item, cur_item);
		return item;
	}

	/**
	 * Set profile mode for the runtime
	 * @param enable
	 * @return
	 */
	auto set_profile_mode(bool enable) -> auto
	{
		std::swap(profile, enable);
		return enable;
	}

	/**
	 * Returns the dynamic item by static item id
	 * @param id
	 * @return
	 */
	auto get_dynamic_item(int id) const -> cache_dynamic_item *;

	/**
	 * Returns static cache item by dynamic cache item
	 * @return
	 */
	auto get_item_by_dynamic_item(cache_dynamic_item *) const -> cache_item *;

	/**
	 * Process symbols in the cache
	 * @param task
	 * @param cache
	 * @param stage
	 * @return
	 */
	auto process_symbols(struct rspamd_task *task, symcache &cache, unsigned int stage) -> bool;

	/**
	 * Finalize execution of some item in the cache
	 * @param task
	 * @param item
	 */
	auto finalize_item(struct rspamd_task *task, cache_dynamic_item *item) -> void;

	/**
	 * Process unblocked reverse dependencies of the specific item
	 * @param task
	 * @param item
	 */
	auto process_item_rdeps(struct rspamd_task *task, cache_item *item) -> void;

	/* XXX: a helper to allow hiding internal implementation of the slow timer structure */
	auto unset_slow() -> void
	{
		if (slow_status == slow_status::enabled) {
			slow_status = slow_status::disabled;
		}
	}

	/**
	 * Builds a human-readable description of symbols that have been started but
	 * have not yet finished (i.e. are waiting on async events: DNS, Redis, HTTP,
	 * etc.). Intended to be used from timeout handlers to surface which rules
	 * stalled the task.
	 * @return newly allocated GString (caller must g_string_free) or nullptr if
	 *         no inflight symbols
	 */
	auto describe_inflight_symbols() const -> GString *;
};


}// namespace rspamd::symcache

#endif//RSPAMD_SYMCACHE_RUNTIME_HXX
