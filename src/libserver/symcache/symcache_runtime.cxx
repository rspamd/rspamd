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

#include "symcache_internal.hxx"
#include "symcache_item.hxx"
#include "symcache_runtime.hxx"

namespace rspamd::symcache {

/* At least once per minute */
constexpr static const auto PROFILE_MAX_TIME = 60.0;
/* For messages larger than 2Mb enable profiling */
constexpr static const auto PROFILE_MESSAGE_SIZE_THRESHOLD = 1024ul * 1024 * 2;
/* Enable profile at least once per this amount of messages processed */
constexpr static const auto PROFILE_PROBABILITY = 0.01;

auto
cache_savepoint::create_savepoint(struct rspamd_task *task, symcache &cache) -> cache_savepoint *
{
	struct cache_savepoint *checkpoint;

	cache.maybe_resort();

	checkpoint = (struct cache_savepoint *) rspamd_mempool_alloc0 (task->task_pool,
			sizeof(*checkpoint) +
			sizeof(struct cache_dynamic_item) * cache.get_items_count());

	checkpoint->order = cache.get_cache_order();
	rspamd_mempool_add_destructor(task->task_pool,
			cache_savepoint::savepoint_dtor, checkpoint);

	/* Calculate profile probability */
	ev_now_update_if_cheap(task->event_loop);
	ev_tstamp now = ev_now(task->event_loop);
	checkpoint->profile_start = now;

	if ((cache.get_last_profile() == 0.0 || now > cache.get_last_profile() + PROFILE_MAX_TIME) ||
		(task->msg.len >= PROFILE_MESSAGE_SIZE_THRESHOLD) ||
		(rspamd_random_double_fast() >= (1 - PROFILE_PROBABILITY))) {
		msg_debug_cache_task("enable profiling of symbols for task");
		checkpoint->profile = true;
		cache.set_last_profile(now);
	}

	task->checkpoint = (void *)checkpoint;

	return checkpoint;
}

}

