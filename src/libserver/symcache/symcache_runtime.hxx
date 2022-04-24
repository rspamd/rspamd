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
 * Symcache runtime is produced for each task and it consists of symbols
 * being executed, being dynamically disabled/enabled and it also captures
 * the current order of the symbols (produced by resort periodic)
 */

#ifndef RSPAMD_SYMCACHE_RUNTIME_HXX
#define RSPAMD_SYMCACHE_RUNTIME_HXX
#pragma once

#include "symcache_internal.hxx"

namespace rspamd::symcache {
/**
 * These items are saved within task structure and are used to track
 * symbols execution.
 * Each symcache item occupies a single dynamic item, that currently has 8 bytes
 * length
 */
struct cache_dynamic_item {
	std::uint16_t start_msec; /* Relative to task time */
	bool started;
	bool finished;
	std::uint32_t async_events;
};

static_assert(sizeof(cache_dynamic_item) == sizeof(std::uint64_t));
static_assert(std::is_trivial_v<cache_dynamic_item>);

class symcache_runtime {
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
	/* We allocate this structure merely in memory pool, so destructor is absent */
	~symcache_runtime() = delete;
	/* Dropper for a shared ownership */
	static auto savepoint_dtor(void *ptr) -> void {
		auto *real_savepoint = (symcache_runtime *)ptr;

		/* Drop shared ownership */
		real_savepoint->order.reset();
	}
public:
	/**
	 * Creates a cache runtime using task mempool
	 * @param task
	 * @param cache
	 * @return
	 */
	static auto create_savepoint(struct rspamd_task *task, symcache &cache) -> symcache_runtime *;
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

	auto get_cur_item() const -> auto {
		return cur_item;
	}

	auto set_cur_item(cache_item *item) -> auto {
		std::swap(item, cur_item);
		return item;
	}
};


}

#endif //RSPAMD_SYMCACHE_RUNTIME_HXX
