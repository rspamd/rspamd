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
	disabled = 4,   /* Disabled by settings; triggers cascade-disable for hard deps */
	suppressed = 5, /* Not enabled (symbols_enabled, disable_all_symbols, pre-result): no cascade, can be re-enabled */
	skipped = 6,    /* Skipped by the scheduler (passthrough, score limit, stage passed): cascades to hard deps */
};

/* Check if an item status means "done": it will not run (anymore) */
static inline auto is_item_done(cache_item_status status) -> bool
{
	return status == cache_item_status::finished ||
		   status == cache_item_status::disabled ||
		   status == cache_item_status::suppressed ||
		   status == cache_item_status::skipped;
}

static inline auto item_status_to_str(cache_item_status status) -> const char *
{
	switch (status) {
	case cache_item_status::not_started:
		return "not started";
	case cache_item_status::started:
		return "started";
	case cache_item_status::pending:
		return "pending";
	case cache_item_status::finished:
		return "finished";
	case cache_item_status::disabled:
		return "disabled";
	case cache_item_status::suppressed:
		return "suppressed";
	case cache_item_status::skipped:
		return "skipped";
	}

	return "unknown";
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
	/* The stage being processed (exec_stage::none before the first stage) */
	exec_stage cur_stage;
	/*
	 * Number of items that are not done yet for each bucket of the order;
	 * allocated right after `dynamic_items` in the same memory block
	 */
	std::uint32_t *bucket_pending;
	/* Dynamically expanded as needed */
	mutable struct cache_dynamic_item dynamic_items[];
	/* We allocate this structure merely in memory pool, so destructor is absent */
	~symcache_runtime() = delete;

	auto process_symbol(struct rspamd_task *task, symcache &cache, cache_item *item,
						cache_dynamic_item *dyn_item) -> bool;
	/* Processes all buckets of a stage in their order */
	auto process_stage(struct rspamd_task *task, symcache &cache, exec_stage stage) -> bool;
	auto check_process_status(struct rspamd_task *task) -> check_status;
	auto check_item_deps(struct rspamd_task *task, symcache &cache, cache_item *item,
						 cache_dynamic_item *dyn_item, bool check_only) -> bool;
	/* True if the item is subject to skipping for the current passthrough/limit status */
	static auto should_skip(const cache_item *item, check_status status) -> bool;
	/* Marks every not started item of the stages before `stage` as skipped */
	auto sweep_earlier_stages(struct rspamd_task *task, exec_stage stage) -> void;

public:
	/**
	 * The only way to change an item status: keeps the buckets accounting consistent
	 * @param dyn_item
	 * @param status
	 */
	auto set_status(cache_dynamic_item *dyn_item, cache_item_status status) -> void
	{
		auto was_done = is_item_done(dyn_item->status);
		auto now_done = is_item_done(status);

		if (was_done != now_done) {
			auto idx = dyn_item - dynamic_items;
			auto bucket = order->item_bucket[idx];

			if (bucket != order_generation::no_bucket) {
				if (now_done) {
					g_assert(bucket_pending[bucket] > 0);
					bucket_pending[bucket]--;
				}
				else {
					bucket_pending[bucket]++;
				}
			}
		}

		dyn_item->status = status;
	}

	/**
	 * A bucket is open when all buckets before it at the same stage are drained,
	 * or when nothing can drain them anymore (the session has no events left)
	 * @param task
	 * @param bucket
	 * @return
	 */
	auto is_bucket_open(struct rspamd_task *task, unsigned int bucket) const -> bool;

	/**
	 * Checks if an item may be started now: its stage is the current one and its
	 * level is open
	 * @param task
	 * @param item
	 * @param dyn_item
	 * @return
	 */
	auto may_start(struct rspamd_task *task, const cache_item *item, const cache_dynamic_item *dyn_item) const -> bool;

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
