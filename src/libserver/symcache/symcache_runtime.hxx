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

}

#endif //RSPAMD_SYMCACHE_RUNTIME_HXX
