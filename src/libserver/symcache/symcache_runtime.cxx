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
#include "libutil/cxx/util.hxx"
#include "libserver/task.h"

namespace rspamd::symcache {

/* At least once per minute */
constexpr static const auto PROFILE_MAX_TIME = 60.0;
/* For messages larger than 2Mb enable profiling */
constexpr static const auto PROFILE_MESSAGE_SIZE_THRESHOLD = 1024ul * 1024 * 2;
/* Enable profile at least once per this amount of messages processed */
constexpr static const auto PROFILE_PROBABILITY = 0.01;

auto
symcache_runtime::create_savepoint(struct rspamd_task *task, symcache &cache) -> symcache_runtime *
{
	cache.maybe_resort();

	auto &&cur_order = cache.get_cache_order();
	auto *checkpoint = (symcache_runtime *) rspamd_mempool_alloc0 (task->task_pool,
			sizeof(symcache_runtime) +
			sizeof(struct cache_dynamic_item) * cur_order->size());

	checkpoint->order = cache.get_cache_order();
	rspamd_mempool_add_destructor(task->task_pool,
			symcache_runtime::savepoint_dtor, checkpoint);

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

	task->symcache_runtime = (void *) checkpoint;

	return checkpoint;
}

auto
symcache_runtime::process_settings(struct rspamd_task *task, const symcache &cache) -> bool
{
	if (!task->settings) {
		msg_err_task("`process_settings` is called with no settings");
		return false;
	}

	const auto *wl = ucl_object_lookup(task->settings, "whitelist");

	if (wl != nullptr) {
		msg_info_task("task is whitelisted");
		task->flags |= RSPAMD_TASK_FLAG_SKIP;
		return true;
	}

	auto already_disabled = false;

	auto process_group = [&](const ucl_object_t *gr_obj, auto functor) -> void {
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *cur;

		if (gr_obj) {
			while ((cur = ucl_iterate_object(gr_obj, &it, true)) != nullptr) {
				if (ucl_object_type(cur) == UCL_STRING) {
					auto *gr = (struct rspamd_symbols_group *)
							g_hash_table_lookup(task->cfg->groups,
									ucl_object_tostring(cur));

					if (gr) {
						GHashTableIter gr_it;
						void *k, *v;
						g_hash_table_iter_init(&gr_it, gr->symbols);

						while (g_hash_table_iter_next(&gr_it, &k, &v)) {
							functor((const char *) k);
						}
					}
				}
			}
		}
	};

	ucl_object_iter_t it = nullptr;
	const ucl_object_t *cur;

	const auto *enabled = ucl_object_lookup(task->settings, "symbols_enabled");

	if (enabled) {
		/* Disable all symbols but selected */
		disable_all_symbols(SYMBOL_TYPE_EXPLICIT_DISABLE);
		already_disabled = true;
		it = nullptr;

		while ((cur = ucl_iterate_object(enabled, &it, true)) != nullptr) {
			enable_symbol(task, cache, ucl_object_tostring(cur));
		}
	}


	/* Enable groups of symbols */
	enabled = ucl_object_lookup(task->settings, "groups_enabled");
	if (enabled && !already_disabled) {
		disable_all_symbols(SYMBOL_TYPE_EXPLICIT_DISABLE);
	}
	process_group(enabled, [&](const char *sym) {
		enable_symbol(task, cache, sym);
	});

	const auto *disabled = ucl_object_lookup(task->settings, "symbols_disabled");


	if (disabled) {
		it = nullptr;

		while ((cur = ucl_iterate_object (disabled, &it, true)) != nullptr) {
			disable_symbol(task, cache, ucl_object_tostring(cur));
		}
	}

	/* Disable groups of symbols */
	disabled = ucl_object_lookup(task->settings, "groups_disabled");
	process_group(disabled, [&](const char *sym) {
		disable_symbol(task, cache, sym);
	});

	return false;
}

auto symcache_runtime::disable_all_symbols(int skip_mask) -> void
{
	for (auto i = 0; i < order->size(); i++) {
		auto *dyn_item = &dynamic_items[i];
		const auto &item = order->d[i];

		if (!(item->get_flags() & skip_mask)) {
			dyn_item->finished = true;
			dyn_item->started = true;
		}
	}
}

auto
symcache_runtime::disable_symbol(struct rspamd_task *task, const symcache &cache, std::string_view name) -> bool
{
	const auto *item = cache.get_item_by_name(name, true);

	if (item != nullptr) {

		auto our_id_maybe = rspamd::find_map(order->by_cache_id, item->id);

		if (our_id_maybe) {
			auto *dyn_item = &dynamic_items[our_id_maybe.value()];
			dyn_item->finished = true;
			dyn_item->started = true;
			msg_debug_cache_task("disable execution of %s", name.data());

			return true;
		}
		else {
			msg_debug_cache_task("cannot disable %s: id not found %d", name.data(), item->id);
		}
	}
	else {
		msg_debug_cache_task("cannot disable %s: symbol not found", name.data());
	}

	return false;
}

auto
symcache_runtime::enable_symbol(struct rspamd_task *task, const symcache &cache, std::string_view name) -> bool
{
	const auto *item = cache.get_item_by_name(name, true);

	if (item != nullptr) {

		auto our_id_maybe = rspamd::find_map(order->by_cache_id, item->id);

		if (our_id_maybe) {
			auto *dyn_item = &dynamic_items[our_id_maybe.value()];
			dyn_item->finished = false;
			dyn_item->started = false;
			msg_debug_cache_task("enable execution of %s", name.data());

			return true;
		}
		else {
			msg_debug_cache_task("cannot enable %s: id not found %d", name.data(), item->id);
		}
	}
	else {
		msg_debug_cache_task("cannot enable %s: symbol not found", name.data());
	}

	return false;
}

auto
symcache_runtime::is_symbol_checked(const symcache &cache, std::string_view name) -> bool
{
	const auto *item = cache.get_item_by_name(name, true);

	if (item != nullptr) {

		auto our_id_maybe = rspamd::find_map(order->by_cache_id, item->id);

		if (our_id_maybe) {
			auto *dyn_item = &dynamic_items[our_id_maybe.value()];
			return dyn_item->started;
		}
	}

	return false;
}

auto
symcache_runtime::is_symbol_enabled(struct rspamd_task *task, const symcache &cache, std::string_view name) -> bool
{

	const auto *item = cache.get_item_by_name(name, true);
	if (item) {

		if (!item->is_allowed(task, true)) {
			return false;
		}
		else {
			auto our_id_maybe = rspamd::find_map(order->by_cache_id, item->id);

			if (our_id_maybe) {
				auto *dyn_item = &dynamic_items[our_id_maybe.value()];
				if (dyn_item->started) {
					/* Already started */
					return false;
				}

				if (!item->is_virtual()) {
					return std::get<normal_item>(item->specific).check_conditions(item->symbol, task);
				}
			}
			else {
				/* Unknown item */
				msg_debug_cache_task("cannot enable %s: symbol not found", name.data());
			}
		}
	}

	return true;
}

}

